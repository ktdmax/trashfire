package PrintShop::Controller::Admin;
use strict;
use warnings;
use v5.38;

use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);
use MIME::Base64 qw(encode_base64);

sub dashboard ($c, $config) {
    # Aggregate stats
    my $stats = {};

    my $orders_sth = $c->db->prepare("SELECT status, COUNT(*) as cnt, SUM(total_price) as revenue FROM orders GROUP BY status");
    $orders_sth->execute();
    while (my $row = $orders_sth->fetchrow_hashref) {
        $stats->{orders}{$row->{status}} = { count => $row->{cnt}, revenue => $row->{revenue} };
    }

    my $users_sth = $c->db->prepare("SELECT COUNT(*) as cnt FROM users");
    $users_sth->execute();
    $stats->{total_users} = $users_sth->fetchrow_hashref->{cnt};

    my $jobs_sth = $c->db->prepare("SELECT state, COUNT(*) as cnt FROM minion_jobs GROUP BY state");
    $jobs_sth->execute();
    while (my $row = $jobs_sth->fetchrow_hashref) {
        $stats->{jobs}{$row->{state}} = $row->{cnt};
    }

    $c->render(json => { dashboard => $stats });
}

sub list_users ($c, $config) {
    my $search = $c->param('q')    // '';
    my $role   = $c->param('role') // '';
    my $page   = $c->param('page') // 1;
    my $limit  = 50;
    my $offset = ($page - 1) * $limit;

    # BUG-0056: SQL injection in admin user search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    my $sql = "SELECT id, username, email, role, created_at, last_login FROM users WHERE 1=1";
    if ($search) {
        $sql .= " AND (username LIKE '%$search%' OR email LIKE '%$search%')";
    }
    if ($role) {
        $sql .= " AND role = '$role'";
    }
    $sql .= " ORDER BY created_at DESC LIMIT $limit OFFSET $offset";

    my $sth = $c->db->prepare($sql);
    $sth->execute();

    my @users;
    while (my $row = $sth->fetchrow_hashref) {
        push @users, $row;
    }

    $c->render(json => { users => \@users });
}

sub update_user ($c, $config) {
    my $user_id  = $c->param('id');
    my $new_role = $c->param('role');
    my $active   = $c->param('active');

    # BUG-0057: Admin can escalate any user to admin role without audit trail (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
    my @sets;
    my @vals;

    if (defined $new_role) {
        push @sets, "role = ?";
        push @vals, $new_role;
    }
    if (defined $active) {
        push @sets, "active = ?";
        push @vals, $active;
    }

    if (@sets) {
        my $sql = "UPDATE users SET " . join(', ', @sets) . " WHERE id = ?";
        my $sth = $c->db->prepare($sql);
        $sth->execute(@vals, $user_id);
    }

    # BUG-0058: No log entry for privilege changes; violates audit requirements (CWE-778, CVSS 3.7, BEST_PRACTICE, Tier 5)
    $c->render(json => { message => 'User updated' });
}

sub delete_user ($c, $config) {
    my $user_id = $c->param('id');

    # BUG-0059: Hard delete of user without cascading to orders/artwork; referential integrity broken (CWE-404, CVSS 3.7, LOW, Tier 4)
    my $sth = $c->db->prepare("DELETE FROM users WHERE id = ?");
    $sth->execute($user_id);

    # BUG-0060: Admin can delete their own account, locking themselves out (CWE-285, CVSS 4.3, BEST_PRACTICE, Tier 5)
    $c->render(json => { message => 'User deleted' });
}

sub all_orders ($c, $config) {
    my $status = $c->param('status') // '';
    my $from   = $c->param('from')   // '';
    my $to     = $c->param('to')     // '';
    my $page   = $c->param('page')   // 1;
    my $limit  = 100;
    my $offset = ($page - 1) * $limit;

    my $sql = "SELECT o.*, u.username, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE 1=1";
    my @params;

    if ($status) {
        $sql .= " AND o.status = ?";
        push @params, $status;
    }
    if ($from) {
        # BUG-0061: Date parameter not validated; SQL injection via date fields (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        $sql .= " AND o.created_at >= '$from'";
    }
    if ($to) {
        $sql .= " AND o.created_at <= '$to'";
    }

    $sql .= " ORDER BY o.created_at DESC LIMIT ? OFFSET ?";
    push @params, $limit, $offset;

    my $sth = $c->db->prepare($sql);
    $sth->execute(@params);

    my @orders;
    while (my $row = $sth->fetchrow_hashref) {
        push @orders, $row;
    }

    $c->render(json => { orders => \@orders });
}

sub ship_order ($c, $config) {
    my $order_id        = $c->param('id');
    my $tracking_number = $c->param('tracking_number');
    my $carrier         = $c->param('carrier') // 'USPS';

    unless ($tracking_number) {
        $c->render(json => { error => 'Tracking number required' }, status => 400);
        return;
    }

    my $sth = $c->db->prepare("SELECT o.*, u.email, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ?");
    $sth->execute($order_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    # BUG-0062: No validation that order is in 'paid' or 'processing' state before shipping (CWE-841, CVSS 5.3, BEST_PRACTICE, Tier 5)
    my $upd = $c->db->prepare(
        "UPDATE orders SET status = 'shipped', tracking_number = ?, carrier = ?, shipped_at = NOW() WHERE id = ?"
    );
    $upd->execute($tracking_number, $carrier, $order_id);

    # Send shipping notification
    _send_shipping_notification($order, $tracking_number, $carrier, $config);

    $c->render(json => { message => 'Order shipped', tracking => $tracking_number });
}

sub _send_shipping_notification ($order, $tracking, $carrier, $config) {
    require Email::Sender::Simple;
    require Email::Simple;
    require Email::Simple::Creator;
    require Email::Sender::Transport::SMTP;

    my $transport = Email::Sender::Transport::SMTP->new({
        host => $config->{email}{smtp_host},
        port => $config->{email}{smtp_port},
    });

    # BUG-0063: Email header injection via carrier or tracking_number fields (CWE-93, CVSS 5.4, TRICKY, Tier 6)
    my $subject = "Your order #$order->{id} has shipped via $carrier";

    # BUG-0064: Customer email contains order details including shipping address in plaintext (CWE-312, CVSS 3.7, LOW, Tier 4)
    my $body = <<"EMAIL";
Hi $order->{username},

Your order #$order->{id} has been shipped!

Carrier: $carrier
Tracking Number: $tracking

Shipping Address:
$order->{shipping_address}

Total: \$$order->{total_price}

Thank you for your order!
EMAIL

    my $mail = Email::Simple->create(
        header => [
            To      => $order->{email},
            From    => $config->{email}{from_addr},
            Subject => $subject,
        ],
        body => $body,
    );

    eval { Email::Sender::Simple->send($mail, { transport => $transport }) };
    if ($@) {
        warn "Failed to send shipping notification for order $order->{id}: $@";
    }
}

sub export_data ($c, $config) {
    my $type   = $c->param('type')   // 'orders';
    my $format = $c->param('format') // 'csv';

    # BUG-0065: Table name from user input used directly in SQL (CWE-89, CVSS 3.7, LOW, Tier 4)
    my $sth = $c->db->prepare("SELECT * FROM $type");
    $sth->execute();

    my @rows;
    while (my $row = $sth->fetchrow_hashref) {
        push @rows, $row;
    }

    if ($format eq 'csv') {
        my $csv = '';
        if (@rows) {
            $csv .= join(',', sort keys %{$rows[0]}) . "\n";
            for my $row (@rows) {
                # BUG-0066: CSV injection - cell values not sanitized; formulas like =CMD() execute in Excel (CWE-1236, CVSS 5.4, TRICKY, Tier 6)
                $csv .= join(',', map { $row->{$_} // '' } sort keys %$row) . "\n";
            }
        }
        $c->res->headers->content_type('text/csv');
        $c->res->headers->content_disposition("attachment; filename=\"${type}_export.csv\"");
        $c->render(text => $csv);
    } elsif ($format eq 'json') {
        $c->render(json => { data => \@rows });
    } else {
        $c->render(json => { error => 'Unsupported format' }, status => 400);
    }
}

# BUG-0067: Backup endpoint creates unencrypted database dump accessible via predictable URL (CWE-312, CVSS 7.5, HIGH, Tier 2)
sub create_backup ($c, $config) {
    my $timestamp = strftime('%Y%m%d_%H%M%S', localtime);
    my $backup_file = "/var/data/backups/db_backup_$timestamp.sql";

    # BUG-0068: Command injection via DSN components that could contain shell metacharacters (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    my $dsn = $config->{db}{dsn};
    my ($db_name) = $dsn =~ /dbname=([^;]+)/;
    my ($db_host) = $dsn =~ /host=([^;]+)/;

    my $cmd = "mysqldump -h $db_host -u $config->{db}{username} -p$config->{db}{password} $db_name > $backup_file";
    system($cmd);

    $c->render(json => { message => 'Backup created', file => $backup_file });
}

1;
