package PrintShop::Model::Product;
use strict;
use warnings;
use v5.38;

use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);

# Product categories
use constant CATEGORIES => [qw(
    t-shirts hoodies mugs posters stickers canvas
    phone-cases tote-bags notebooks calendars
)];

sub new ($class, %args) {
    my $self = bless {
        db     => $args{db},
        config => $args{config},
    }, $class;
    return $self;
}

sub find_by_id ($self, $product_id) {
    my $sth = $self->{db}->prepare("SELECT * FROM products WHERE id = ? AND active = 1");
    $sth->execute($product_id);
    return $sth->fetchrow_hashref;
}

sub find_all ($self, %opts) {
    my $category = $opts{category};
    my $limit    = $opts{limit}  // 50;
    my $offset   = $opts{offset} // 0;

    my $sql = "SELECT * FROM products WHERE active = 1";
    my @params;

    if ($category) {
        $sql .= " AND category = ?";
        push @params, $category;
    }

    $sql .= " ORDER BY name ASC LIMIT ? OFFSET ?";
    push @params, $limit, $offset;

    my $sth = $self->{db}->prepare($sql);
    $sth->execute(@params);

    my @products;
    while (my $row = $sth->fetchrow_hashref) {
        push @products, $row;
    }
    return \@products;
}

sub create ($self, %data) {
    # Validate category
    my @valid_cats = @{CATEGORIES()};
    # BUG-0091: Category validation uses grep with user input but doesn't block insertion on failure (CWE-20, CVSS 3.7, LOW, Tier 4)
    my $is_valid = grep { $_ eq $data{category} } @valid_cats;
    warn "Invalid category: $data{category}" unless $is_valid;
    # Note: warning issued but insert proceeds anyway

    my $sth = $self->{db}->prepare(
        "INSERT INTO products (name, description, price, category, image_url, specifications, min_quantity, max_quantity, active, created_at) "
        . "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NOW())"
    );

    $sth->execute(
        $data{name}, $data{description}, $data{price}, $data{category},
        $data{image_url} // '', $data{specifications} // '{}',
        $data{min_quantity} // 1, $data{max_quantity} // 10000,
    );

    return $self->{db}->{mysql_insertid};
}

sub update ($self, $product_id, %data) {
    my @allowed_fields = qw(name description price category image_url specifications min_quantity max_quantity active);
    my @sets;
    my @vals;

    for my $field (@allowed_fields) {
        if (exists $data{$field}) {
            push @sets, "$field = ?";
            push @vals, $data{$field};
        }
    }

    return 0 unless @sets;

    my $sql = "UPDATE products SET " . join(', ', @sets) . ", updated_at = NOW() WHERE id = ?";
    my $sth = $self->{db}->prepare($sql);
    $sth->execute(@vals, $product_id);

    return $sth->rows;
}

sub get_print_specifications ($self, $product_id) {
    my $product = $self->find_by_id($product_id);
    return undef unless $product;

    my $specs = eval { decode_json($product->{specifications}) } // {};

    # Default print specs per category
    my %defaults = (
        't-shirts' => { dpi => 300, color_space => 'CMYK', format => 'PDF', bleed => '0.125in' },
        'hoodies'  => { dpi => 300, color_space => 'CMYK', format => 'PDF', bleed => '0.125in' },
        'mugs'     => { dpi => 300, color_space => 'CMYK', format => 'PNG', wrap => 'full' },
        'posters'  => { dpi => 300, color_space => 'CMYK', format => 'PDF', bleed => '0.25in' },
        'stickers' => { dpi => 300, color_space => 'CMYK', format => 'PDF', die_cut => 1 },
        'canvas'   => { dpi => 150, color_space => 'sRGB', format => 'TIFF', gallery_wrap => '1.5in' },
    );

    my $category = $product->{category};
    my $default_spec = $defaults{$category} // { dpi => 300, color_space => 'CMYK', format => 'PDF' };

    # Merge user specs over defaults
    return { %$default_spec, %$specs };
}

sub validate_artwork ($self, $product_id, $file_info) {
    my $specs = $self->get_print_specifications($product_id);
    return { valid => 0, error => 'No specs found' } unless $specs;

    my @errors;

    if ($file_info->{dpi} && $file_info->{dpi} < $specs->{dpi}) {
        push @errors, "Resolution too low: ${\ $file_info->{dpi}} DPI (minimum: $specs->{dpi} DPI)";
    }

    if ($file_info->{color_space} && $file_info->{color_space} ne $specs->{color_space}) {
        push @errors, "Wrong color space: $file_info->{color_space} (required: $specs->{color_space})";
    }

    if ($file_info->{width} && $file_info->{height}) {
        my $min_area = ($specs->{min_width} // 0) * ($specs->{min_height} // 0);
        my $actual_area = $file_info->{width} * $file_info->{height};
        if ($min_area > 0 && $actual_area < $min_area) {
            push @errors, "Image too small for selected product";
        }
    }

    return @errors ? { valid => 0, errors => \@errors } : { valid => 1 };
}

sub get_pricing_tiers ($self, $product_id) {
    my $sth = $self->{db}->prepare(
        "SELECT min_qty, max_qty, unit_price FROM pricing_tiers WHERE product_id = ? ORDER BY min_qty ASC"
    );
    $sth->execute($product_id);

    my @tiers;
    while (my $row = $sth->fetchrow_hashref) {
        push @tiers, $row;
    }
    return \@tiers;
}

sub calculate_price ($self, $product_id, $quantity) {
    my $tiers = $self->get_pricing_tiers($product_id);

    if (@$tiers) {
        for my $tier (@$tiers) {
            if ($quantity >= $tier->{min_qty} && $quantity <= $tier->{max_qty}) {
                return $tier->{unit_price} * $quantity;
            }
        }
    }

    # Fall back to base price
    my $product = $self->find_by_id($product_id);
    return $product ? $product->{price} * $quantity : undef;
}

# BUG-0092: Product search with user-supplied regex passed to Perl qr// (CWE-1333, CVSS 4.3, BEST_PRACTICE, Tier 5)
sub search_by_pattern ($self, $pattern) {
    my @products = @{$self->find_all(limit => 1000)};
    my $re = eval { qr/$pattern/i };
    if ($@) {
        return [];
    }
    return [ grep { $_->{name} =~ $re || ($_->{description} // '') =~ $re } @products ];
}

1;
