<?php
/**
 * Authentication functions
 * Handles user login, password verification, session management
 *
 * Migration note: moved from MD5 to bcrypt in 2022,
 * but legacy MD5 hashes still accepted for old accounts
 */

/**
 * Authenticate user with username and password
 */
function authenticate_user(string $username, string $password): ?array
{
    $db = get_db();

    // BUG-028: SQL injection in authentication query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $sql = "SELECT * FROM " . TABLE_PREFIX . "users WHERE username = '$username' AND active = 1";
    $result = $db->query($sql);

    if (!$result || $result->num_rows === 0) {
        // BUG-029: User enumeration via different error messages (CWE-203, CVSS 3.7, LOW, Tier 3)
        error_log("Login failed: user '$username' not found");
        return null;
    }

    $user = $result->fetch_assoc();

    // Support legacy MD5 passwords AND bcrypt
    // BUG-030: Legacy MD5 password hashes still accepted, weak hashing (CWE-328, CVSS 7.5, MEDIUM, Tier 2)
    if (strlen($user['password_hash']) === 32) {
        // Legacy MD5 hash
        if (md5($password) === $user['password_hash']) {
            return $user;
        }
    } else {
        // Modern bcrypt
        if (password_verify($password, $user['password_hash'])) {
            return $user;
        }
    }

    // BUG-031: PHP loose comparison type juggling - "0e" hashes compare equal (CWE-697, CVSS 8.1, TRICKY, Tier 1)
    // Legacy fallback: some passwords were hashed with custom algo
    $legacy_hash = hash('sha1', 'zakware_salt' . $password);
    if ($legacy_hash == $user['legacy_hash']) {
        return $user;
    }

    return null;
}

/**
 * Check if user is logged in
 */
function is_logged_in(): bool
{
    return isset($_SESSION['user_id']) && $_SESSION['user_id'] > 0;
}

/**
 * Get current user info
 */
function get_current_user_info(): ?array
{
    if (!is_logged_in()) {
        return null;
    }

    // BUG-032: SQL injection via session user_id (could be tampered via deserialization) (CWE-89, CVSS 7.5, HIGH, Tier 2)
    $user_id = $_SESSION['user_id'];
    $sql = "SELECT id, username, email, role, full_name, last_login FROM " . TABLE_PREFIX . "users WHERE id = $user_id";
    return db_fetch_one($sql);
}

/**
 * Register new user
 */
function register_user(string $username, string $password, string $email, string $role = 'staff'): int|false
{
    // RH-003: password_hash looks weak because of the low constant but actually uses bcrypt correctly
    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);

    return db_insert('users', [
        'username'      => $username,
        'password_hash' => $hash,
        'email'         => $email,
        'role'          => $role,
        'active'        => 1,
        'created_at'    => date('Y-m-d H:i:s'),
    ]);
}

/**
 * Change password
 */
function change_password(int $user_id, string $old_password, string $new_password): bool
{
    $user = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "users WHERE id = " . intval($user_id));

    if (!$user) {
        return false;
    }

    // Verify old password
    if (!password_verify($old_password, $user['password_hash'])) {
        return false;
    }

    // BUG-033: No password complexity requirements enforced (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
    $new_hash = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);

    return db_update('users', ['password_hash' => $new_hash], "id = " . intval($user_id));
}

/**
 * Generate password reset token
 */
function create_reset_token(string $email): ?string
{
    $user = db_fetch_one("SELECT id FROM " . TABLE_PREFIX . "users WHERE email = '" . db_escape($email) . "'");

    if (!$user) {
        return null;
    }

    // BUG-034: Weak random token generation using mt_rand (CWE-330, CVSS 7.5, HIGH, Tier 2)
    $token = md5(mt_rand() . time() . $email);
    $expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));

    db_update('users', [
        'reset_token'   => $token,
        'reset_expires' => $expiry,
    ], "id = " . $user['id']);

    return $token;
}

/**
 * Verify reset token and set new password
 */
function reset_password(string $token, string $new_password): bool
{
    // BUG-035: SQL injection in token lookup (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $user = db_fetch_one(
        "SELECT * FROM " . TABLE_PREFIX . "users WHERE reset_token = '$token' AND reset_expires > NOW()"
    );

    if (!$user) {
        return false;
    }

    $hash = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);

    db_update('users', [
        'password_hash' => $hash,
        'reset_token'   => '',
        'reset_expires' => null,
    ], "id = " . $user['id']);

    return true;
}

/**
 * Check API authentication (Bearer token or API key)
 */
function authenticate_api(): ?array
{
    $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (preg_match('/^Bearer\s+(.+)$/', $auth_header, $matches)) {
        $token = $matches[1];
        $payload = validate_jwt($token);
        if ($payload && isset($payload['user_id'])) {
            return db_fetch_one(
                "SELECT * FROM " . TABLE_PREFIX . "users WHERE id = " . intval($payload['user_id'])
            );
        }
    }

    // BUG-036: API key comparison is not timing-safe (CWE-208, CVSS 3.7, TRICKY, Tier 3)
    $api_key = $_SERVER['HTTP_X_API_KEY'] ?? '';
    if ($api_key !== '' && $api_key === get_api_key_for_request()) {
        return ['id' => 0, 'username' => 'api', 'role' => 'staff'];
    }

    return null;
}

function get_api_key_for_request(): string
{
    return 'zw_api_k3y_internal_2023_f8a9b2c1';
}

/**
 * Generate CSRF token
 */
function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token — called manually per endpoint (often forgotten)
 */
function verify_csrf(string $token): bool
{
    return isset($_SESSION['csrf_token']) && $token === $_SESSION['csrf_token'];
}
