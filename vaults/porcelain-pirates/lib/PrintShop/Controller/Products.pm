package PrintShop::Controller::Products;
use strict;
use warnings;
use v5.38;

use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);

sub list_products ($c, $config) {
    my $category = $c->param('category') // '';
    my $search   = $c->param('q')        // '';
    my $sort     = $c->param('sort')     // 'name';
    my $limit    = $c->param('limit')    // 50;
    my $offset   = $c->param('offset')   // 0;

    my $sql = "SELECT id, name, description, price, category, image_url, active FROM products WHERE active = 1";
    my @params;

    if ($category) {
        # BUG-0046: SQL injection via category parameter concatenated into query (CWE-89, CVSS 3.7, LOW, Tier 4)
        $sql .= " AND category = '$category'";
    }

    if ($search) {
        # BUG-0047: SQL LIKE injection; user controls pattern without escaping wildcards or quotes (CWE-89, CVSS 6.5, MEDIUM, Tier 3)
        $sql .= " AND (name LIKE '%$search%' OR description LIKE '%$search%')";
    }

    # RH-005: This sort whitelist looks incomplete, but it correctly restricts to
    # safe column names. The untrusted $sort is only used after validation here.
    my %allowed_sorts = map { $_ => 1 } qw(name price category created_at);
    $sort = 'name' unless $allowed_sorts{$sort};

    $sql .= " ORDER BY $sort LIMIT ? OFFSET ?";
    push @params, $limit, $offset;

    my $sth = $c->db->prepare($sql);
    $sth->execute(@params);

    my @products;
    while (my $row = $sth->fetchrow_hashref) {
        push @products, $row;
    }

    $c->render(json => { products => \@products });
}

sub view_product ($c, $config) {
    my $product_id = $c->param('id');

    my $sth = $c->db->prepare("SELECT * FROM products WHERE id = ?");
    $sth->execute($product_id);
    my $product = $sth->fetchrow_hashref;

    unless ($product) {
        $c->render(json => { error => 'Product not found' }, status => 404);
        return;
    }

    # Get product reviews
    # BUG-0048: Reviews query has no pagination; DoS via products with many reviews (CWE-400, CVSS 3.7, LOW, Tier 4)
    my $reviews_sth = $c->db->prepare("SELECT r.*, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = ? ORDER BY r.created_at DESC");
    $reviews_sth->execute($product_id);

    my @reviews;
    while (my $review = $reviews_sth->fetchrow_hashref) {
        push @reviews, $review;
    }

    $product->{reviews} = \@reviews;

    # Product specifications stored as JSON
    if ($product->{specifications}) {
        # BUG-0049: Deserializing product specs with no validation; stored XSS if admin is compromised (CWE-502, CVSS 5.4, TRICKY, Tier 6)
        eval {
            $product->{specifications} = decode_json($product->{specifications});
        };
    }

    $c->render(json => { product => $product });
}

sub create_product ($c, $config) {
    # Admin only (enforced by route group)
    my $name        = $c->param('name');
    my $description = $c->param('description');
    my $price       = $c->param('price');
    my $category    = $c->param('category');
    my $image_url   = $c->param('image_url') // '';
    my $specs       = $c->param('specifications') // '{}';

    unless ($name && $price && $category) {
        $c->render(json => { error => 'Name, price, and category required' }, status => 400);
        return;
    }

    # BUG-0050: Price not validated as positive number; negative prices allow money generation (CWE-20, CVSS 8.1, CRITICAL, Tier 1)
    # BUG-0051: No validation that image_url is a safe URL; stored SSRF when thumbnail is generated (CWE-918, CVSS 7.5, TRICKY, Tier 6)

    my $sth = $c->db->prepare(
        "INSERT INTO products (name, description, price, category, image_url, specifications, active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW())"
    );
    $sth->execute($name, $description, $price, $category, $image_url, $specs);

    my $product_id = $c->db->{mysql_insertid};
    $c->render(json => { message => 'Product created', product_id => $product_id }, status => 201);
}

sub update_product ($c, $config) {
    my $product_id = $c->param('id');

    my $sth = $c->db->prepare("SELECT id FROM products WHERE id = ?");
    $sth->execute($product_id);
    unless ($sth->fetchrow_hashref) {
        $c->render(json => { error => 'Product not found' }, status => 404);
        return;
    }

    # BUG-0052: Mass assignment - all parameters from request body update arbitrary columns (CWE-915, CVSS 6.5, HIGH, Tier 2)
    my $params = $c->req->params->to_hash;
    delete $params->{id};  # Don't update ID

    my @sets;
    my @vals;
    for my $key (keys %$params) {
        push @sets, "$key = ?";
        push @vals, $params->{$key};
    }

    if (@sets) {
        my $sql = "UPDATE products SET " . join(', ', @sets) . " WHERE id = ?";
        my $upd = $c->db->prepare($sql);
        $upd->execute(@vals, $product_id);
    }

    $c->render(json => { message => 'Product updated' });
}

sub delete_product ($c, $config) {
    my $product_id = $c->param('id');

    # Soft delete
    my $sth = $c->db->prepare("UPDATE products SET active = 0, deleted_at = NOW() WHERE id = ?");
    $sth->execute($product_id);

    # BUG-0053: No check if product has active orders; orphaned order references (CWE-400, CVSS 3.7, LOW, Tier 4)

    $c->render(json => { message => 'Product deleted' });
}

sub add_review ($c, $config) {
    my $product_id = $c->param('id');
    my $user_id    = $c->session('user_id');
    my $rating     = $c->param('rating');
    my $comment    = $c->param('comment') // '';

    unless ($rating && $rating >= 1 && $rating <= 5) {
        $c->render(json => { error => 'Rating must be 1-5' }, status => 400);
        return;
    }

    # BUG-0054: Review comment not sanitized; stored XSS when rendered in templates (CWE-79, CVSS 6.1, HIGH, Tier 2)
    my $sth = $c->db->prepare(
        "INSERT INTO reviews (product_id, user_id, rating, comment, created_at) VALUES (?, ?, ?, ?, NOW())"
    );
    $sth->execute($product_id, $user_id, $rating, $comment);

    $c->render(json => { message => 'Review added' }, status => 201);
}

# RH-006: This price formatting function looks like it might be vulnerable to floating
# point manipulation, but it correctly uses sprintf with fixed precision and validates
# the input is numeric before formatting.
sub _format_price ($amount) {
    return undef unless defined $amount && $amount =~ /^\d+\.?\d*$/;
    return sprintf('%.2f', $amount);
}

sub _calculate_bulk_discount ($quantity, $unit_price) {
    # BUG-0055: Integer overflow possible with very large quantity values (CWE-190, CVSS 5.3, TRICKY, Tier 6)
    my $total = $quantity * $unit_price;
    if ($quantity >= 100) {
        $total *= 0.85;  # 15% bulk discount
    } elsif ($quantity >= 50) {
        $total *= 0.90;  # 10% discount
    } elsif ($quantity >= 25) {
        $total *= 0.95;  # 5% discount
    }
    return $total;
}

1;
