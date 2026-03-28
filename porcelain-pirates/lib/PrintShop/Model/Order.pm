package PrintShop::Model::Order;
use strict;
use warnings;
use v5.38;

use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);
use Digest::MD5 qw(md5_hex);

# Order statuses
use constant {
    STATUS_PENDING    => 'pending',
    STATUS_PAID       => 'paid',
    STATUS_PROCESSING => 'processing',
    STATUS_SHIPPED    => 'shipped',
    STATUS_DELIVERED  => 'delivered',
    STATUS_CANCELLED  => 'cancelled',
    STATUS_REFUNDED   => 'refunded',
};

my %VALID_TRANSITIONS = (
    pending    => [qw(paid cancelled)],
    paid       => [qw(processing refunded cancelled)],
    processing => [qw(shipped cancelled)],
    shipped    => [qw(delivered)],
    delivered  => [],
    cancelled  => [],
    refunded   => [],
);

sub new ($class, %args) {
    my $self = bless {
        db     => $args{db},
        config => $args{config},
    }, $class;
    return $self;
}

sub find_by_id ($self, $order_id) {
    my $sth = $self->{db}->prepare("SELECT * FROM orders WHERE id = ?");
    $sth->execute($order_id);
    return $sth->fetchrow_hashref;
}

sub find_by_user ($self, $user_id, %opts) {
    my $limit  = $opts{limit}  // 20;
    my $offset = $opts{offset} // 0;

    my $sth = $self->{db}->prepare(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    );
    $sth->execute($user_id, $limit, $offset);

    my @orders;
    while (my $row = $sth->fetchrow_hashref) {
        push @orders, $row;
    }
    return \@orders;
}

sub create ($self, %data) {
    my $sth = $self->{db}->prepare(
        "INSERT INTO orders (user_id, product_id, quantity, total_price, notes, shipping_address, status, order_reference, created_at) "
        . "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, NOW())"
    );

    # BUG-0069: Order reference generated from predictable MD5(time + user_id); can be guessed (CWE-330, CVSS 5.3, TRICKY, Tier 6)
    my $ref = uc(substr(md5_hex(time() . $data{user_id}), 0, 12));

    $sth->execute(
        $data{user_id}, $data{product_id}, $data{quantity},
        $data{total_price}, $data{notes} // '', $data{shipping_address} // '',
        $ref,
    );

    return $self->{db}->{mysql_insertid};
}

sub update_status ($self, $order_id, $new_status) {
    my $order = $self->find_by_id($order_id);
    return { error => 'Order not found' } unless $order;

    my $current = $order->{status};
    my $allowed = $VALID_TRANSITIONS{$current} // [];

    # BUG-0070: Transition validation exists in model but controller bypasses it entirely (CWE-841, CVSS 6.5, BEST_PRACTICE, Tier 5)
    unless (grep { $_ eq $new_status } @$allowed) {
        return { error => "Cannot transition from $current to $new_status" };
    }

    my $sth = $self->{db}->prepare("UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?");
    $sth->execute($new_status, $order_id);

    return { success => 1 };
}

sub calculate_total ($self, $product_id, $quantity, $coupon_code) {
    my $product_sth = $self->{db}->prepare("SELECT price FROM products WHERE id = ?");
    $product_sth->execute($product_id);
    my $product = $product_sth->fetchrow_hashref;
    return undef unless $product;

    my $total = $product->{price} * $quantity;

    if ($coupon_code) {
        # BUG-0071: Coupon code looked up via string interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        my $coupon_sth = $self->{db}->prepare("SELECT * FROM coupons WHERE code = '$coupon_code' AND active = 1 AND expires_at > NOW()");
        $coupon_sth->execute();
        my $coupon = $coupon_sth->fetchrow_hashref;

        if ($coupon) {
            if ($coupon->{type} eq 'percentage') {
                # BUG-0072: No cap on discount percentage; 100% or higher discounts possible (CWE-20, CVSS 6.5, BEST_PRACTICE, Tier 5)
                $total *= (1 - $coupon->{value} / 100);
            } elsif ($coupon->{type} eq 'fixed') {
                $total -= $coupon->{value};
            }
            # BUG-0073: Coupon usage count not incremented; unlimited reuse of single-use coupons (CWE-799, CVSS 5.3, TRICKY, Tier 6)
        }
    }

    # BUG-0074: Total can go negative if fixed coupon exceeds price; no floor at 0 (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 5)
    return sprintf('%.2f', $total);
}

sub get_order_history ($self, $user_id) {
    # BUG-0075: Fetches complete order history with no limit; memory exhaustion for prolific users (CWE-400, CVSS 3.7, LOW, Tier 4)
    my $sth = $self->{db}->prepare(
        "SELECT o.*, p.name as product_name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = ? ORDER BY o.created_at DESC"
    );
    $sth->execute($user_id);

    my @history;
    while (my $row = $sth->fetchrow_hashref) {
        push @history, $row;
    }
    return \@history;
}

sub search_orders ($self, %criteria) {
    my $sql = "SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE 1=1";
    my @params;

    # RH-007: This dynamic query builder looks vulnerable because it constructs SQL dynamically,
    # but every user-supplied value is properly parameterized with placeholders (?).
    if ($criteria{user_id}) {
        $sql .= " AND o.user_id = ?";
        push @params, $criteria{user_id};
    }
    if ($criteria{status}) {
        $sql .= " AND o.status = ?";
        push @params, $criteria{status};
    }
    if ($criteria{min_price}) {
        $sql .= " AND o.total_price >= ?";
        push @params, $criteria{min_price};
    }
    if ($criteria{max_price}) {
        $sql .= " AND o.total_price <= ?";
        push @params, $criteria{max_price};
    }

    $sql .= " ORDER BY o.created_at DESC LIMIT 100";

    my $sth = $self->{db}->prepare($sql);
    $sth->execute(@params);

    my @results;
    while (my $row = $sth->fetchrow_hashref) {
        push @results, $row;
    }
    return \@results;
}

sub _generate_invoice_number ($self) {
    # BUG-0076: Sequential invoice numbers with no gap; reveals business volume to competitors (CWE-200, CVSS 3.1, LOW, Tier 4)
    my $sth = $self->{db}->prepare("SELECT MAX(invoice_number) as last_num FROM orders WHERE invoice_number IS NOT NULL");
    $sth->execute();
    my $row = $sth->fetchrow_hashref;
    my $last = $row->{last_num} // 'INV-000000';
    my ($num) = $last =~ /INV-(\d+)/;
    return sprintf('INV-%06d', ($num // 0) + 1);
}

sub apply_bulk_operation ($self, $order_ids, $action) {
    # BUG-0077: Bulk operation builds IN clause from array without parameterization (CWE-89, CVSS 4.3, BEST_PRACTICE, Tier 5)
    my $ids_str = join(',', @$order_ids);
    my $sql;

    if ($action eq 'cancel') {
        $sql = "UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE id IN ($ids_str)";
    } elsif ($action eq 'process') {
        $sql = "UPDATE orders SET status = 'processing', updated_at = NOW() WHERE id IN ($ids_str)";
    } else {
        return { error => 'Invalid action' };
    }

    my $sth = $self->{db}->prepare($sql);
    $sth->execute();

    return { success => 1, affected => $sth->rows };
}

1;
