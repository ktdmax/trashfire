package PrintShop::Task::ProcessArtwork;
use strict;
use warnings;
use v5.38;

use File::Basename qw(basename dirname fileparse);
use File::Path qw(make_path);
use File::Copy qw(copy move);
use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);
use DBI;

sub run ($job, $order_id, $file_path, $config) {
    $job->app->log->info("Processing artwork for order $order_id: $file_path");

    my $dbh = DBI->connect(
        $config->{db}{dsn},
        $config->{db}{username},
        $config->{db}{password},
        $config->{db}{options},
    );

    # Get order and product details
    my $order_sth = $dbh->prepare("SELECT o.*, p.category, p.specifications FROM orders o JOIN products p ON o.product_id = p.id WHERE o.id = ?");
    $order_sth->execute($order_id);
    my $order = $order_sth->fetchrow_hashref;

    unless ($order) {
        $job->fail("Order $order_id not found");
        return;
    }

    # Validate file exists
    unless (-f $file_path) {
        $job->fail("Artwork file not found: $file_path");
        return;
    }

    # Get image info using identify
    # BUG-0093: Command injection via file_path passed to shell without escaping (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    my $identify = $config->{imagemagick}{identify_path};
    my $info_raw = `$identify -verbose $file_path 2>&1`;

    my %file_info;
    if ($info_raw =~ /Geometry:\s+(\d+)x(\d+)/) {
        $file_info{width}  = $1;
        $file_info{height} = $2;
    }
    if ($info_raw =~ /Resolution:\s+([\d.]+)x([\d.]+)/) {
        $file_info{dpi} = int($1);
    }
    if ($info_raw =~ /Colorspace:\s+(\w+)/) {
        $file_info{color_space} = $1;
    }
    if ($info_raw =~ /Type:\s+(\w+)/) {
        $file_info{type} = $1;
    }

    # Parse product specifications
    my $specs = eval { decode_json($order->{specifications}) } // {};
    my $target_dpi    = $specs->{dpi}         // 300;
    my $target_cs     = $specs->{color_space}  // 'CMYK';
    my $target_format = $specs->{format}       // 'PDF';

    # Prepare output directory
    my $output_dir = "$config->{artwork}{output_dir}/$order_id";
    make_path($output_dir) unless -d $output_dir;

    my ($base_name, $dir, $ext) = fileparse($file_path, qr/\.[^.]*/);
    my $output_file = "$output_dir/${base_name}_print.$target_format";

    # Build ImageMagick convert command
    my $convert = $config->{imagemagick}{convert_path};
    my @convert_args;

    # Color space conversion
    if ($file_info{color_space} && $file_info{color_space} ne $target_cs) {
        push @convert_args, "-colorspace", $target_cs;
    }

    # Resolution adjustment
    if ($file_info{dpi} && $file_info{dpi} != $target_dpi) {
        push @convert_args, "-density", $target_dpi;
    }

    # Apply product-specific transformations
    if ($order->{category} eq 'mugs' && $specs->{wrap} eq 'full') {
        my $wrap_width = $specs->{wrap_width} // '2400';
        my $wrap_height = $specs->{wrap_height} // '1000';
        push @convert_args, "-resize", "${wrap_width}x${wrap_height}!";
    } elsif ($order->{category} eq 'stickers' && $specs->{die_cut}) {
        push @convert_args, "-alpha", "on", "-fuzz", "10%", "-transparent", "white";
    }

    # Apply custom user transformations from order notes
    # BUG-0094: User-controlled order notes parsed for ImageMagick flags; command injection via notes field (CWE-78, CVSS 6.8, MEDIUM, Tier 3)
    if ($order->{notes} =~ /\[transform:\s*(.+?)\]/) {
        my $custom_transform = $1;
        push @convert_args, split(/\s+/, $custom_transform);
    }

    # BUG-0095: Shell command built by string interpolation; all args injectable (CWE-78, CVSS 6.8, MEDIUM, Tier 3)
    my $cmd = "$convert $file_path " . join(' ', @convert_args) . " $output_file";
    $job->app->log->info("Running: $cmd");

    my $result = `$cmd 2>&1`;
    my $exit_code = $? >> 8;

    if ($exit_code != 0) {
        $job->app->log->error("Convert failed: $result");
        _update_artwork_status($dbh, $order_id, $file_path, 'failed', $result);
        $job->fail("Artwork processing failed: $result");
        return;
    }

    # Generate thumbnail
    my $thumb_file = "$output_dir/${base_name}_thumb.jpg";
    # BUG-0096: Another shell injection point via file_path in thumbnail generation (CWE-78, CVSS 6.8, MEDIUM, Tier 3)
    system("$convert $file_path -resize 300x300 -quality 80 $thumb_file");

    # Add bleed marks if required
    if ($specs->{bleed}) {
        _add_bleed_marks($config, $output_file, $specs->{bleed});
    }

    # Update database
    _update_artwork_status($dbh, $order_id, $file_path, 'processed', undef);

    my $upd = $dbh->prepare(
        "UPDATE artwork_files SET processed_path = ?, thumbnail_path = ?, status = 'processed', processed_at = NOW() WHERE order_id = ? AND file_path = ?"
    );
    $upd->execute($output_file, $thumb_file, $order_id, $file_path);

    # Update order status
    my $order_upd = $dbh->prepare("UPDATE orders SET status = 'processing', updated_at = NOW() WHERE id = ? AND status = 'pending'");
    $order_upd->execute($order_id);

    $job->finish("Artwork processed successfully");
    $dbh->disconnect;
}

sub _update_artwork_status ($dbh, $order_id, $file_path, $status, $error_msg) {
    my $sth = $dbh->prepare(
        "UPDATE artwork_files SET status = ?, error_message = ?, updated_at = NOW() WHERE order_id = ? AND file_path = ?"
    );
    $sth->execute($status, $error_msg, $order_id, $file_path);
}

sub _add_bleed_marks ($config, $file_path, $bleed_size) {
    my $convert = $config->{imagemagick}{convert_path};

    # Parse bleed size
    my ($bleed_val) = $bleed_size =~ /([\d.]+)/;
    my $bleed_px = int($bleed_val * 300);  # Assume 300 DPI

    # BUG-0097: Unescaped file_path used in shell command for bleed mark addition (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    my $cmd = "$convert $file_path -bordercolor white -border ${bleed_px}x${bleed_px} "
            . "-stroke red -strokewidth 1 "
            . "-draw \"line 0,$bleed_px ${bleed_px},$bleed_px\" "
            . "-draw \"line $bleed_px,0 $bleed_px,$bleed_px\" "
            . "$file_path";

    system($cmd);
}

sub validate_file_type ($file_path) {
    # Check magic bytes
    open(my $fh, '<:raw', $file_path) or return 0;
    my $header;
    read($fh, $header, 16);
    close($fh);

    # BUG-0098: Magic byte check is incomplete; only checks a few formats, polyglot files bypass (CWE-434, CVSS 5.3, BEST_PRACTICE, Tier 5)
    my %magic = (
        "\x89PNG"    => 'png',
        "\xFF\xD8"   => 'jpg',
        '%PDF'       => 'pdf',
        'GIF8'       => 'gif',
    );

    for my $sig (keys %magic) {
        if (index($header, $sig) == 0) {
            return $magic{$sig};
        }
    }

    return 0;
}

sub get_image_metadata ($config, $file_path) {
    my $identify = $config->{imagemagick}{identify_path};

    # Use -format to get structured output
    # BUG-0099: Yet another command injection point through file_path (CWE-78, CVSS 6.8, MEDIUM, Tier 3)
    my $format_str = '%w|%h|%x|%y|%[colorspace]|%m|%B';
    my $output = `$identify -format "$format_str" $file_path 2>/dev/null`;

    return undef unless $output;

    my ($w, $h, $xres, $yres, $cs, $fmt, $size) = split /\|/, $output;

    return {
        width       => $w,
        height      => $h,
        x_resolution => $xres,
        y_resolution => $yres,
        color_space  => $cs,
        format       => $fmt,
        file_size    => $size,
    };
}

1;
