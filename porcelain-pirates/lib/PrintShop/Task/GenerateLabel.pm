package PrintShop::Task::GenerateLabel;
use strict;
use warnings;
use v5.38;

use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);
use File::Path qw(make_path);
use LWP::UserAgent;
use URI;
use DBI;
use MIME::Base64 qw(encode_base64 decode_base64);

# Shipping carrier configurations
my %CARRIERS = (
    USPS => {
        api_url => 'https://secure.shippingapis.com/ShippingAPI.dll',
        api_key => 'USPS_API_KEY_PLACEHOLDER',
    },
    UPS => {
        api_url => 'https://onlinetools.ups.com/api/shipments/v1/ship',
        api_key => 'UPS_API_KEY_PLACEHOLDER',
    },
    FedEx => {
        api_url => 'https://apis.fedex.com/rate/v1/rates/quotes',
        api_key => 'FEDEX_API_KEY_PLACEHOLDER',
    },
);

sub run ($job, $order_id, $config) {
    $job->app->log->info("Generating shipping label for order $order_id");

    my $dbh = DBI->connect(
        $config->{db}{dsn},
        $config->{db}{username},
        $config->{db}{password},
        $config->{db}{options},
    );

    # Get order with shipping details
    my $sth = $dbh->prepare(
        "SELECT o.*, u.username, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ?"
    );
    $sth->execute($order_id);
    my $order = $sth->fetchrow_hashref;

    unless ($order) {
        $job->fail("Order $order_id not found");
        return;
    }

    unless ($order->{shipping_address}) {
        $job->fail("No shipping address for order $order_id");
        return;
    }

    my $carrier = $order->{carrier} // 'USPS';
    my $carrier_config = $CARRIERS{$carrier};

    unless ($carrier_config) {
        $job->fail("Unknown carrier: $carrier");
        return;
    }

    # Parse shipping address
    my $address = _parse_address($order->{shipping_address});

    # Generate label via carrier API
    my $label_data = _request_label($carrier, $carrier_config, $order, $address, $config);

    unless ($label_data) {
        $job->fail("Failed to generate label for order $order_id");
        return;
    }

    # Save label PDF
    my $label_dir = "$config->{artwork}{output_dir}/$order_id/labels";
    make_path($label_dir) unless -d $label_dir;
    my $label_file = "$label_dir/shipping_label_${order_id}.pdf";

    open(my $fh, '>', $label_file) or do {
        $job->fail("Cannot write label file: $!");
        return;
    };
    binmode($fh);
    print $fh decode_base64($label_data->{label_pdf});
    close($fh);

    # Update order with tracking info
    my $upd = $dbh->prepare(
        "UPDATE orders SET tracking_number = ?, carrier = ?, label_path = ?, updated_at = NOW() WHERE id = ?"
    );
    $upd->execute($label_data->{tracking_number}, $carrier, $label_file, $order_id);

    # Send notification
    _notify_customer($order, $label_data, $config);

    $job->finish("Label generated: $label_data->{tracking_number}");
    $dbh->disconnect;
}

sub _parse_address ($address_string) {
    # Simple address parser: expects "Name\nStreet\nCity, State ZIP\nCountry"
    my @lines = split /\n/, $address_string;

    return {
        name    => $lines[0] // '',
        street  => $lines[1] // '',
        city    => '',
        state   => '',
        zip     => '',
        country => $lines[3] // 'US',
    } unless @lines >= 3;

    my $city_line = $lines[2];
    my ($city, $state_zip) = split /,\s*/, $city_line, 2;
    my ($state, $zip) = split /\s+/, ($state_zip // ''), 2;

    return {
        name    => $lines[0],
        street  => $lines[1],
        city    => $city // '',
        state   => $state // '',
        zip     => $zip // '',
        country => $lines[3] // 'US',
    };
}

sub _request_label ($carrier, $carrier_config, $order, $address, $config) {
    my $ua = LWP::UserAgent->new(
        timeout => 30,
        # BUG-0100: SSL certificate verification disabled for carrier API calls (CWE-295, CVSS 4.3, BEST_PRACTICE, Tier 5)
        ssl_opts => { verify_hostname => 0, SSL_verify_mode => 0 },
    );

    my $payload;
    if ($carrier eq 'USPS') {
        $payload = _build_usps_request($order, $address, $carrier_config);
    } elsif ($carrier eq 'UPS') {
        $payload = _build_ups_request($order, $address, $carrier_config);
    } elsif ($carrier eq 'FedEx') {
        $payload = _build_fedex_request($order, $address, $carrier_config);
    }

    my $response = $ua->post(
        $carrier_config->{api_url},
        Content_Type => 'application/json',
        Content      => encode_json($payload),
        Authorization => "Bearer $carrier_config->{api_key}",
    );

    unless ($response->is_success) {
        warn "Carrier API error ($carrier): " . $response->status_line . " - " . $response->decoded_content;
        return undef;
    }

    my $result = eval { decode_json($response->decoded_content) };
    if ($@) {
        warn "Failed to parse carrier response: $@";
        return undef;
    }

    return {
        tracking_number => $result->{tracking_number} // $result->{TrackingNumber} // 'UNKNOWN',
        label_pdf       => $result->{label_image}     // $result->{LabelImage} // '',
        rate            => $result->{rate}             // $result->{TotalCharge} // 0,
    };
}

sub _build_usps_request ($order, $address, $carrier_config) {
    return {
        API          => 'DelivConfirmCertifyV4.0',
        Revision     => '2',
        ImageType    => 'PDF',
        FromName     => 'PrintShop Fulfillment',
        FromAddress  => '123 Print Lane',
        FromCity     => 'San Francisco',
        FromState    => 'CA',
        FromZip      => '94102',
        ToName       => $address->{name},
        ToAddress    => $address->{street},
        ToCity       => $address->{city},
        ToState      => $address->{state},
        ToZip        => $address->{zip},
        WeightOunces => _estimate_weight($order),
    };
}

sub _build_ups_request ($order, $address, $carrier_config) {
    return {
        ShipmentRequest => {
            Shipment => {
                Shipper => {
                    Name    => 'PrintShop Fulfillment',
                    Address => { AddressLine => '123 Print Lane', City => 'San Francisco', StateProvinceCode => 'CA', PostalCode => '94102', CountryCode => 'US' },
                },
                ShipTo => {
                    Name    => $address->{name},
                    Address => { AddressLine => $address->{street}, City => $address->{city}, StateProvinceCode => $address->{state}, PostalCode => $address->{zip}, CountryCode => $address->{country} },
                },
                Package => {
                    PackagingType => { Code => '02' },
                    Dimensions    => { UnitOfMeasurement => { Code => 'IN' }, Length => '12', Width => '12', Height => '4' },
                    PackageWeight => { UnitOfMeasurement => { Code => 'LBS' }, Weight => _estimate_weight($order) / 16 },
                },
            },
            LabelSpecification => { LabelImageFormat => { Code => 'PDF' } },
        },
    };
}

sub _build_fedex_request ($order, $address, $carrier_config) {
    return {
        accountNumber => { value => 'FEDEX_ACCT_PLACEHOLDER' },
        requestedShipment => {
            shipper  => { address => { streetLines => ['123 Print Lane'], city => 'San Francisco', stateOrProvinceCode => 'CA', postalCode => '94102', countryCode => 'US' } },
            recipient => { address => { streetLines => [$address->{street}], city => $address->{city}, stateOrProvinceCode => $address->{state}, postalCode => $address->{zip}, countryCode => $address->{country} } },
            pickupType => 'DROPOFF_AT_FEDEX_LOCATION',
            serviceType => 'FEDEX_GROUND',
            requestedPackageLineItems => [{
                weight => { units => 'LB', value => _estimate_weight($order) / 16 },
            }],
        },
    };
}

sub _estimate_weight ($order) {
    # Estimate weight in ounces based on product category and quantity
    my %base_weights = (
        't-shirts'    => 6,
        'hoodies'     => 16,
        'mugs'        => 12,
        'posters'     => 4,
        'stickers'    => 1,
        'canvas'      => 24,
        'phone-cases' => 3,
        'tote-bags'   => 8,
        'notebooks'   => 10,
        'calendars'   => 12,
    );

    my $category = $order->{category} // 't-shirts';
    my $base = $base_weights{$category} // 8;
    return $base * ($order->{quantity} // 1) + 4;  # +4 oz for packaging
}

sub _notify_customer ($order, $label_data, $config) {
    require Email::Sender::Simple;
    require Email::Simple;
    require Email::Simple::Creator;
    require Email::Sender::Transport::SMTP;

    my $transport = Email::Sender::Transport::SMTP->new({
        host => $config->{email}{smtp_host},
        port => $config->{email}{smtp_port},
    });

    my $tracking = $label_data->{tracking_number};
    my $carrier  = $order->{carrier} // 'USPS';

    my $tracking_url;
    if ($carrier eq 'USPS') {
        $tracking_url = "https://tools.usps.com/go/TrackConfirmAction?qtc_tLabels1=$tracking";
    } elsif ($carrier eq 'UPS') {
        $tracking_url = "https://www.ups.com/track?tracknum=$tracking";
    } elsif ($carrier eq 'FedEx') {
        $tracking_url = "https://www.fedex.com/fedextrack/?trknbr=$tracking";
    }

    my $body = <<"EMAIL";
Hi $order->{username},

Great news! Your order #$order->{id} is on its way!

Carrier: $carrier
Tracking Number: $tracking
Track your package: $tracking_url

Estimated delivery: 5-7 business days

Thank you for shopping with PrintShop!
EMAIL

    my $mail = Email::Simple->create(
        header => [
            To      => $order->{email},
            From    => $config->{email}{from_addr},
            Subject => "Your PrintShop order #$order->{id} has shipped!",
        ],
        body => $body,
    );

    eval { Email::Sender::Simple->send($mail, { transport => $transport }) };
    if ($@) {
        warn "Failed to send shipping notification for order $order->{id}: $@";
    }
}

1;
