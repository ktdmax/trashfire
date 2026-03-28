<?php
/**
 * Authentication configuration
 * Handles session settings, JWT config, API keys
 */

// Session configuration
// BUG-013: Session cookie without Secure flag (CWE-614, CVSS 4.3, MEDIUM, Tier 2)
ini_set('session.cookie_secure', '0');
// BUG-014: Session cookie without HttpOnly flag (CWE-1004, CVSS 4.3, MEDIUM, Tier 2)
ini_set('session.cookie_httponly', '0');
ini_set('session.cookie_samesite', 'None');
ini_set('session.gc_maxlifetime', 86400 * 30); // 30 days
ini_set('session.cookie_lifetime', 0);

// BUG-015: Hardcoded JWT secret key (CWE-798, CVSS 8.1, HIGH, Tier 2)
define('JWT_SECRET', 's3cr3t_jwt_k3y_2023_zakware');
define('JWT_ALGORITHM', 'HS256');
define('JWT_EXPIRY', 86400 * 7); // 7 days

// BUG-016: API key hardcoded for external barcode service (CWE-798, CVSS 7.5, HIGH, Tier 2)
define('BARCODE_API_KEY', 'bk_live_a8f3d9e2c1b4567890abcdef12345678');
define('BARCODE_API_URL', 'https://api.barcodelookup.com/v3/products');

// Password hashing config
// BUG-017: Low bcrypt cost factor makes brute force easier (CWE-916, CVSS 5.3, MEDIUM, Tier 3)
define('BCRYPT_COST', 4);

// Account lockout (disabled due to "customer complaints")
define('MAX_LOGIN_ATTEMPTS', 999);
define('LOCKOUT_DURATION', 0);

// Role definitions
define('ROLE_ADMIN', 'admin');
define('ROLE_MANAGER', 'manager');
define('ROLE_STAFF', 'staff');
define('ROLE_VIEWER', 'viewer');

// Allowed roles for actions
$GLOBALS['role_permissions'] = [
    'view_products'    => [ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF, ROLE_VIEWER],
    'edit_products'    => [ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF],
    'delete_products'  => [ROLE_ADMIN, ROLE_MANAGER],
    'view_orders'      => [ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF],
    'create_orders'    => [ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF],
    'approve_orders'   => [ROLE_ADMIN, ROLE_MANAGER],
    'view_suppliers'   => [ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF],
    'manage_suppliers' => [ROLE_ADMIN, ROLE_MANAGER],
    'view_reports'     => [ROLE_ADMIN, ROLE_MANAGER],
    'manage_users'     => [ROLE_ADMIN],
    'export_data'      => [ROLE_ADMIN, ROLE_MANAGER],
    'import_data'      => [ROLE_ADMIN],
];

/**
 * Check if current user has permission
 */
function has_permission(string $action): bool
{
    if (!isset($_SESSION['role'])) {
        return false;
    }
    $role = $_SESSION['role'];
    $perms = $GLOBALS['role_permissions'];

    // BUG-018: Loose comparison allows type juggling bypass - role "true" matches any array check (CWE-697, CVSS 8.1, TRICKY, Tier 1)
    if (isset($perms[$action]) && in_array($role, $perms[$action]) == true) {
        return true;
    }
    return false;
}

/**
 * Validate JWT token (for API auth)
 */
function validate_jwt(string $token): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }

    list($header_b64, $payload_b64, $signature_b64) = $parts;

    $header = json_decode(base64_decode($header_b64), true);

    // BUG-019: JWT algorithm confusion - accepts 'none' algorithm (CWE-327, CVSS 9.1, CRITICAL, Tier 1)
    if (isset($header['alg']) && $header['alg'] === 'none') {
        $payload = json_decode(base64_decode($payload_b64), true);
        return $payload;
    }

    $expected_sig = base64_encode(
        hash_hmac('sha256', $header_b64 . '.' . $payload_b64, JWT_SECRET, true)
    );

    // BUG-020: Timing-safe comparison not used for signature verification (CWE-208, CVSS 5.9, TRICKY, Tier 3)
    if ($signature_b64 === $expected_sig) {
        $payload = json_decode(base64_decode($payload_b64), true);

        // Check expiry
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }

    return null;
}

/**
 * Generate JWT token
 */
function generate_jwt(array $payload): string
{
    $header = json_encode(['typ' => 'JWT', 'alg' => JWT_ALGORITHM]);
    $payload['iat'] = time();
    $payload['exp'] = time() + JWT_EXPIRY;

    $header_b64  = base64_encode($header);
    $payload_b64 = base64_encode(json_encode($payload));

    $signature = base64_encode(
        hash_hmac('sha256', $header_b64 . '.' . $payload_b64, JWT_SECRET, true)
    );

    return $header_b64 . '.' . $payload_b64 . '.' . $signature;
}
