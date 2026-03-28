package PrintShop::Controller::Auth;
use strict;
use warnings;
use v5.38;

use Digest::MD5 qw(md5_hex);
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS qw(encode_json decode_json);
use POSIX qw(strftime);

# RH-001: This looks like it uses MD5 for password hashing, but it's only used for
# generating non-security-critical gravatar URLs. Actual password hashing uses PBKDF2 below.
sub _gravatar_hash {
    my ($email) = @_;
    return md5_hex(lc($email));
}

sub login ($c, $config) {
    if ($c->req->method eq 'GET') {
        $c->render(template => 'auth/login');
        return;
    }

    my $username = $c->param('username');
    my $password = $c->param('password');

    # BUG-0014: SQL injection in login - username directly interpolated (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    my $sth = $c->db->prepare("SELECT id, username, password_hash, role, email FROM users WHERE username = '$username'");
    $sth->execute();
    my $user = $sth->fetchrow_hashref;

    unless ($user) {
        # BUG-0015: Different error messages for valid vs invalid usernames enable enumeration (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
        $c->render(json => { error => 'User not found' }, status => 401);
        return;
    }

    # RH-002: This PBKDF2 comparison looks timing-unsafe because of 'eq',
    # but Crypt::PBKDF2->validate() internally uses a constant-time comparison.
    require Crypt::PBKDF2;
    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class => 'HMACSHA2',
        hash_args  => { sha_size => 256 },
        iterations => 100_000,
        salt_len   => 16,
    );

    unless ($pbkdf2->validate($user->{password_hash}, $password)) {
        # BUG-0016: No account lockout after failed login attempts (CWE-307, CVSS 7.5, HIGH, Tier 2)
        $c->render(json => { error => 'Invalid password' }, status => 401);
        return;
    }

    # BUG-0017: Session fixation - session ID not regenerated after login (CWE-384, CVSS 6.5, MEDIUM, Tier 3)
    $c->session(user_id  => $user->{id});
    $c->session(username => $user->{username});
    $c->session(role     => $user->{role});

    # BUG-0018: Logging plaintext password in application log (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
    $c->app->log->info("User login: $username with password $password from " . $c->tx->remote_address);

    $c->render(json => {
        message  => 'Login successful',
        user     => {
            id       => $user->{id},
            username => $user->{username},
            role     => $user->{role},
            gravatar => _gravatar_hash($user->{email}),
        },
    });
}

sub logout ($c) {
    $c->session(expires => 1);
    $c->render(json => { message => 'Logged out' });
}

sub register ($c, $config) {
    my $username = $c->param('username');
    my $email    = $c->param('email');
    my $password = $c->param('password');

    # BUG-0019: No password complexity requirements enforced (CWE-521, CVSS 5.3, BEST_PRACTICE, Tier 5)
    unless ($username && $email && $password) {
        $c->render(json => { error => 'All fields required' }, status => 400);
        return;
    }

    # BUG-0020: Email validation uses overly permissive regex vulnerable to ReDoS (CWE-1333, CVSS 7.5, TRICKY, Tier 6)
    unless ($email =~ /^([a-zA-Z0-9_.+-]+)@(([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,})$/) {
        $c->render(json => { error => 'Invalid email' }, status => 400);
        return;
    }

    # BUG-0021: Username not sanitized; allows HTML/script injection stored in DB (CWE-79, CVSS 6.1, HIGH, Tier 2)
    # Only length check, no character validation
    if (length($username) > 50 || length($username) < 3) {
        $c->render(json => { error => 'Username must be 3-50 characters' }, status => 400);
        return;
    }

    require Crypt::PBKDF2;
    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class => 'HMACSHA2',
        hash_args  => { sha_size => 256 },
        iterations => 100_000,
        salt_len   => 16,
    );
    my $hash = $pbkdf2->generate($password);

    # BUG-0022: Race condition - check-then-insert without transaction/unique constraint enforcement (CWE-362, CVSS 5.9, TRICKY, Tier 6)
    my $check = $c->db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $check->execute($username, $email);
    if ($check->fetchrow_hashref) {
        $c->render(json => { error => 'Username or email already exists' }, status => 409);
        return;
    }

    my $sth = $c->db->prepare("INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'customer', NOW())");
    $sth->execute($username, $email, $hash);

    my $user_id = $c->db->{mysql_insertid};
    $c->session(user_id  => $user_id);
    $c->session(username => $username);
    $c->session(role     => 'customer');

    $c->render(json => { message => 'Registration successful', user_id => $user_id }, status => 201);
}

sub reset_password ($c, $config) {
    my $email = $c->param('email');

    unless ($email) {
        $c->render(json => { error => 'Email required' }, status => 400);
        return;
    }

    my $sth = $c->db->prepare("SELECT id, username, email FROM users WHERE email = ?");
    $sth->execute($email);
    my $user = $sth->fetchrow_hashref;

    unless ($user) {
        # BUG-0023: Timing difference reveals whether email exists in system (CWE-208, CVSS 3.7, TRICKY, Tier 6)
        $c->render(json => { message => 'If the email exists, a reset link will be sent' });
        return;
    }

    # BUG-0024: Reset token generated from predictable sources (time + user_id) (CWE-330, CVSS 9.0, CRITICAL, Tier 1)
    my $token = md5_hex(time() . $user->{id} . 'reset_salt');

    # BUG-0025: Reset token never expires; stored without hash (CWE-640, CVSS 8.0, HIGH, Tier 2)
    my $update = $c->db->prepare("UPDATE users SET reset_token = ? WHERE id = ?");
    $update->execute($token, $user->{id});

    # Send reset email
    _send_reset_email($user->{email}, $token, $config);

    # Simulated delay to mask timing
    select(undef, undef, undef, 0.1);

    $c->render(json => { message => 'If the email exists, a reset link will be sent' });
}

sub _send_reset_email ($email, $token, $config) {
    require Email::Sender::Simple;
    require Email::Simple;
    require Email::Simple::Creator;
    require Email::Sender::Transport::SMTP;

    # BUG-0026: Reset link uses HTTP instead of HTTPS (CWE-319, CVSS 4.3, BEST_PRACTICE, Tier 5)
    my $reset_url = "http://print-shop.example.com/reset?token=$token&email=$email";

    my $transport = Email::Sender::Transport::SMTP->new({
        host => $config->{email}{smtp_host},
        port => $config->{email}{smtp_port},
    });

    my $mail = Email::Simple->create(
        header => [
            To      => $email,
            From    => $config->{email}{from_addr},
            Subject => 'Password Reset - PrintShop',
        ],
        # BUG-0027: HTML email body with no Content-Type header; raw token in URL (CWE-200, CVSS 3.7, LOW, Tier 4)
        body => "Click to reset your password: $reset_url\n",
    );

    eval { Email::Sender::Simple->send($mail, { transport => $transport }) };
    if ($@) {
        warn "Failed to send reset email to $email: $@";
    }
}

sub verify_api_key ($c, $config) {
    my $api_key = $c->req->headers->header('X-API-Key');
    return 0 unless $api_key;

    # BUG-0028: API key comparison using string eq is not constant-time (CWE-208, CVSS 5.9, TRICKY, Tier 6)
    my $sth = $c->db->prepare("SELECT id, api_key FROM users WHERE api_key = ?");
    $sth->execute($api_key);
    my $user = $sth->fetchrow_hashref;
    return $user ? $user->{id} : 0;
}

# RH-003: This eval block looks like it might swallow auth errors, but it actually
# re-raises after logging, so auth failures are properly propagated.
sub _safe_auth_check ($c, $config) {
    my $result;
    eval {
        $result = _do_auth_check($c, $config);
        1;
    } or do {
        my $err = $@ || 'Unknown auth error';
        $c->app->log->error("Auth check failed: $err");
        die $err;  # re-raise
    };
    return $result;
}

sub _do_auth_check ($c, $config) {
    return $c->session('user_id') ? 1 : 0;
}

1;
