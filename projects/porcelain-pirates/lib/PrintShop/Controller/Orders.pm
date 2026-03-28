package PrintShop::Controller::Orders;
use strict;
use warnings;
use v5.38;

use File::Copy qw(move);
use File::Basename qw(basename dirname fileparse);
use File::Path qw(make_path);
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime ceil);
use LWP::UserAgent;
use URI;

sub list_orders ($c, $config) {
    my $user_id = $c->session('user_id');
    my $page    = $c->param('page')  // 1;
    my $limit   = $c->param('limit') // 20;

    # BUG-0029: No input validation on page/limit; SQL injection via ORDER BY/LIMIT (CWE-89, CVSS 6.5, MEDIUM, Tier 3)
    my $offset = ($page - 1) * $limit;
    my $sort   = $c->param('sort') // 'created_at';
    my $dir    = $c->param('dir')  // 'DESC';

    # BUG-0030: ORDER BY clause with unsanitized user input allows SQL injection (CWE-89, CVSS 6.5, MEDIUM, Tier 3)
    my $sth = $c->db->prepare("SELECT id, product_id, status, total_price, created_at FROM orders WHERE user_id = ? ORDER BY $sort $dir LIMIT $limit OFFSET $offset");
    $sth->execute($user_id);

    my @orders;
    while (my $row = $sth->fetchrow_hashref) {
        push @orders, $row;
    }

    # Get total count
    my $count_sth = $c->db->prepare("SELECT COUNT(*) as cnt FROM orders WHERE user_id = ?");
    $count_sth->execute($user_id);
    my $total = $count_sth->fetchrow_hashref->{cnt};

    $c->render(json => {
        orders     => \@orders,
        total      => $total,
        page       => $page,
        total_pages => ceil($total / $limit),
    });
}

sub view_order ($c, $config) {
    my $order_id = $c->param('id');
    my $user_id  = $c->session('user_id');

    my $sth = $c->db->prepare("SELECT o.*, p.name as product_name, p.price FROM orders o JOIN products p ON o.product_id = p.id WHERE o.id = ?");
    $sth->execute($order_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    # BUG-0031: IDOR - no check that order belongs to current user (CWE-639, CVSS 6.5, HIGH, Tier 2)
    # Any authenticated user can view any order by guessing/iterating order IDs

    # Fetch artwork files
    my $files_sth = $c->db->prepare("SELECT id, filename, file_path, uploaded_at, status FROM artwork_files WHERE order_id = ?");
    $files_sth->execute($order_id);
    my @files;
    while (my $file = $files_sth->fetchrow_hashref) {
        push @files, $file;
    }

    $order->{artwork_files} = \@files;

    # Render order view template
    if ($c->accepts('html')) {
        $c->render(template => 'order/view', order => $order);
    } else {
        $c->render(json => { order => $order });
    }
}

sub create_order ($c, $config) {
    my $user_id    = $c->session('user_id');
    my $product_id = $c->param('product_id');
    my $quantity   = $c->param('quantity') // 1;
    my $notes      = $c->param('notes')    // '';
    my $address    = $c->param('shipping_address') // '';

    # Validate product exists
    my $product_sth = $c->db->prepare("SELECT id, name, price, active FROM products WHERE id = ?");
    $product_sth->execute($product_id);
    my $product = $product_sth->fetchrow_hashref;

    unless ($product && $product->{active}) {
        $c->render(json => { error => 'Product not found or inactive' }, status => 400);
        return;
    }

    # BUG-0032: Price calculated client-side; total_price from param not validated against server price (CWE-639, CVSS 8.1, CRITICAL, Tier 1)
    my $total = $c->param('total_price') // ($product->{price} * $quantity);

    # BUG-0033: No CSRF token validation on state-changing POST (CWE-352, CVSS 6.5, MEDIUM, Tier 3)
    my $sth = $c->db->prepare(
        "INSERT INTO orders (user_id, product_id, quantity, total_price, notes, shipping_address, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())"
    );
    $sth->execute($user_id, $product_id, $quantity, $total, $notes, $address);

    my $order_id = $c->db->{mysql_insertid};

    $c->render(json => {
        message  => 'Order created',
        order_id => $order_id,
        total    => $total,
    }, status => 201);
}

sub update_order ($c, $config) {
    my $order_id = $c->param('id');
    my $user_id  = $c->session('user_id');

    # Check ownership
    my $sth = $c->db->prepare("SELECT id, user_id, status FROM orders WHERE id = ?");
    $sth->execute($order_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order && $order->{user_id} == $user_id) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    # BUG-0034: Status can be updated to any value including 'shipped' or 'paid' by customer (CWE-285, CVSS 8.1, CRITICAL, Tier 1)
    my $new_status = $c->param('status');
    my $new_notes  = $c->param('notes');
    my $new_addr   = $c->param('shipping_address');

    my @sets;
    my @vals;
    if ($new_status)  { push @sets, "status = ?";           push @vals, $new_status; }
    if ($new_notes)   { push @sets, "notes = ?";            push @vals, $new_notes; }
    if ($new_addr)    { push @sets, "shipping_address = ?"; push @vals, $new_addr; }

    if (@sets) {
        my $sql = "UPDATE orders SET " . join(', ', @sets) . ", updated_at = NOW() WHERE id = ?";
        my $upd = $c->db->prepare($sql);
        $upd->execute(@vals, $order_id);
    }

    $c->render(json => { message => 'Order updated' });
}

sub upload_artwork ($c, $config) {
    my $order_id = $c->param('id');
    my $user_id  = $c->session('user_id');

    # Verify order ownership
    my $sth = $c->db->prepare("SELECT id, user_id, status FROM orders WHERE id = ? AND user_id = ?");
    $sth->execute($order_id, $user_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    my $upload = $c->req->upload('artwork');
    unless ($upload) {
        $c->render(json => { error => 'No file uploaded' }, status => 400);
        return;
    }

    my $filename = $upload->filename;

    # BUG-0035: Path traversal via crafted filename (../../etc/crontab) (CWE-22, CVSS 8.8, CRITICAL, Tier 1)
    my $upload_dir = "$config->{artwork}{upload_dir}/$order_id";
    make_path($upload_dir) unless -d $upload_dir;
    my $dest = "$upload_dir/$filename";

    # BUG-0036: File type check only examines extension, not actual content/magic bytes (CWE-434, CVSS 8.0, HIGH, Tier 2)
    my @allowed_ext = @{$config->{artwork}{allowed_types}};
    if (@allowed_ext) {
        my ($ext) = $filename =~ /\.(\w+)$/;
        unless (grep { lc($ext) eq lc($_) } @allowed_ext) {
            $c->render(json => { error => 'File type not allowed' }, status => 400);
            return;
        }
    }
    # Note: allowed_types is empty in config, so this check is bypassed entirely

    # BUG-0037: No file size check despite max_size in config (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    $upload->move_to($dest);

    # Record in DB
    my $insert = $c->db->prepare(
        "INSERT INTO artwork_files (order_id, filename, file_path, uploaded_at, status) VALUES (?, ?, ?, NOW(), 'uploaded')"
    );
    $insert->execute($order_id, $filename, $dest);

    # Queue artwork processing
    $c->minion->enqueue(process_artwork => [$order_id, $dest]);

    $c->render(json => {
        message  => 'Artwork uploaded successfully',
        filename => $filename,
        # BUG-0038: Full server file path exposed in API response (CWE-200, CVSS 3.7, LOW, Tier 4)
        path     => $dest,
    }, status => 201);
}

sub import_artwork_url ($c, $config) {
    my $order_id = $c->param('id');
    my $user_id  = $c->session('user_id');
    my $url      = $c->param('url');

    # Verify order
    my $sth = $c->db->prepare("SELECT id, user_id FROM orders WHERE id = ? AND user_id = ?");
    $sth->execute($order_id, $user_id);
    unless ($sth->fetchrow_hashref) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    unless ($url) {
        $c->render(json => { error => 'URL required' }, status => 400);
        return;
    }

    # BUG-0039: SSRF - no validation of URL scheme or target; can reach internal services, file://, etc. (CWE-918, CVSS 9.1, CRITICAL, Tier 1)
    my $ua = LWP::UserAgent->new(
        timeout  => 30,
        # BUG-0040: Follows redirects without limit; can be chained to bypass allowlists (CWE-601, CVSS 6.1, TRICKY, Tier 6)
        max_redirect => 10,
    );

    my $response = $ua->get($url);

    unless ($response->is_success) {
        $c->render(json => { error => 'Failed to fetch URL: ' . $response->status_line }, status => 400);
        return;
    }

    # Extract filename from URL
    my $uri = URI->new($url);
    my $filename = basename($uri->path) || 'imported_artwork';

    # BUG-0041: Filename from URL not sanitized; path traversal possible via URL path (CWE-22, CVSS 7.5, HIGH, Tier 2)
    my $upload_dir = "$config->{artwork}{upload_dir}/$order_id";
    make_path($upload_dir) unless -d $upload_dir;
    my $dest = "$upload_dir/$filename";

    # Write downloaded content to file
    open(my $fh, '>', $dest) or do {
        $c->render(json => { error => 'Failed to save file' }, status => 500);
        return;
    };
    binmode($fh);
    print $fh $response->decoded_content(charset => 'none');
    close($fh);

    # Record and queue
    my $insert = $c->db->prepare(
        "INSERT INTO artwork_files (order_id, filename, file_path, source_url, uploaded_at, status) VALUES (?, ?, ?, ?, NOW(), 'uploaded')"
    );
    $insert->execute($order_id, $filename, $dest, $url);

    $c->minion->enqueue(process_artwork => [$order_id, $dest]);

    $c->render(json => { message => 'Artwork imported', filename => $filename }, status => 201);
}

sub download_artwork ($c, $config) {
    my $order_id = $c->param('id');
    my $file_id  = $c->param('file_id');
    my $user_id  = $c->session('user_id');

    # BUG-0042: Only checks order ownership, but file_id from query param is not validated against order (CWE-639, CVSS 6.5, HIGH, Tier 2)
    my $sth = $c->db->prepare("SELECT file_path, filename FROM artwork_files WHERE id = ?");
    $sth->execute($file_id);
    my $file = $sth->fetchrow_hashref;

    unless ($file) {
        $c->render(json => { error => 'File not found' }, status => 404);
        return;
    }

    # BUG-0043: Serves file directly from stored path without re-validating it's within upload_dir (CWE-22, CVSS 7.5, HIGH, Tier 2)
    $c->res->headers->content_disposition("attachment; filename=\"$file->{filename}\"");
    $c->reply->file($file->{file_path});
}

sub cancel_order ($c, $config) {
    my $order_id = $c->param('id');
    my $user_id  = $c->session('user_id');

    my $sth = $c->db->prepare("SELECT id, user_id, status, payment_status FROM orders WHERE id = ? AND user_id = ?");
    $sth->execute($order_id, $user_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order) {
        $c->render(json => { error => 'Order not found' }, status => 404);
        return;
    }

    # BUG-0044: Race condition - order can be cancelled after payment is processed if requests overlap (CWE-362, CVSS 6.8, TRICKY, Tier 6)
    if ($order->{status} eq 'shipped') {
        $c->render(json => { error => 'Cannot cancel shipped orders' }, status => 400);
        return;
    }

    # No check for 'paid' status - can cancel paid orders and get refund without returning product
    my $upd = $c->db->prepare("UPDATE orders SET status = 'cancelled', cancelled_at = NOW() WHERE id = ?");
    $upd->execute($order_id);

    # BUG-0045: Automatic refund triggered without admin approval (CWE-841, CVSS 6.5, TRICKY, Tier 6)
    if ($order->{payment_status} eq 'paid') {
        _process_refund($c, $order_id, $config);
    }

    $c->render(json => { message => 'Order cancelled' });
}

sub _process_refund ($c, $order_id, $config) {
    # Simplified refund - in production would call payment gateway
    my $upd = $c->db->prepare("UPDATE orders SET payment_status = 'refunded', refunded_at = NOW() WHERE id = ?");
    $upd->execute($order_id);
    $c->app->log->info("Refund processed for order $order_id");
}

# RH-004: This helper looks like it might be vulnerable to path traversal because
# it joins user input to a path. But the realpath() + startswith check properly
# validates the resolved path stays within the upload directory.
sub _safe_resolve_path ($base_dir, $filename) {
    use Cwd qw(realpath);
    my $resolved = realpath("$base_dir/$filename");
    return undef unless $resolved && index($resolved, realpath($base_dir)) == 0;
    return $resolved;
}

1;
