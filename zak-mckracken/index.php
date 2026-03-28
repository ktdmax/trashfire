<?php
/**
 * ZakWare Inventory Management System
 * Main entry point and router
 *
 * Originally written for PHP 5.6, upgraded to 7.4, now running on 8.3
 * @author Various (legacy codebase)
 */

// BUG-001: error_reporting exposes detailed errors to users (CWE-209, CVSS 5.3, MEDIUM, Tier 2)
error_reporting(E_ALL);
ini_set('display_errors', '1');

// BUG-002: Debug mode enabled in production via GET parameter (CWE-489, CVSS 5.3, MEDIUM, Tier 2)
if (isset($_GET['debug'])) {
    define('DEBUG_MODE', true);
    ini_set('display_errors', '1');
} else {
    define('DEBUG_MODE', false);
}

session_start();

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// BUG-003: Open redirect via unvalidated 'redirect' parameter (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
$redirect_after_login = isset($_GET['redirect']) ? $_GET['redirect'] : '/dashboard';

$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$base_path = dirname($_SERVER['SCRIPT_NAME']);
$route = str_replace($base_path, '', $request_uri);
$route = trim($route, '/');

// Simple router
$routes = [
    ''           => 'views/dashboard.php',
    'dashboard'  => 'views/dashboard.php',
    'products'   => 'views/products.php',
    'orders'     => 'views/orders.php',
    'suppliers'  => 'views/suppliers.php',
    'reports'    => 'views/reports.php',
    'users'      => 'views/users.php',
    'login'      => 'views/login.php',
    'logout'     => 'views/logout.php',
    'barcode'    => 'views/barcode.php',
];

// API routing
if (strpos($route, 'api/') === 0) {
    $api_file = __DIR__ . '/' . $route . '.php';
    // BUG-004: Path traversal in API routing - dots not filtered (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
    if (file_exists($api_file)) {
        require $api_file;
        exit;
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'API endpoint not found: ' . $route]);
        exit;
    }
}

// BUG-005: phpinfo() accessible via query parameter (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
if (isset($_GET['phpinfo'])) {
    phpinfo();
    exit;
}

// Handle login POST
if ($route === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $user = authenticate_user($username, $password);
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        // BUG-006: Session not regenerated after login, session fixation (CWE-384, CVSS 8.1, HIGH, Tier 1)
        header('Location: ' . $redirect_after_login);
        exit;
    } else {
        $login_error = 'Invalid username or password';
    }
}

// Check authentication for non-public routes
$public_routes = ['login', 'api/products'];
if (!in_array($route, $public_routes) && !is_logged_in()) {
    header('Location: /login?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

// BUG-007: Page inclusion allows arbitrary file read via route manipulation (CWE-98, CVSS 9.8, CRITICAL, Tier 1)
if (isset($routes[$route])) {
    $page = $routes[$route];
} elseif (isset($_GET['page'])) {
    // Legacy support for old URL format
    $page = $_GET['page'] . '.php';
} else {
    $page = 'views/404.php';
}

// Template
$page_title = ucfirst($route ?: 'Dashboard') . ' - ZakWare Inventory';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?></title>
    <link rel="stylesheet" href="/public/css/style.css">
</head>
<body>
<?php if (is_logged_in()): ?>
<nav class="main-nav">
    <div class="nav-brand">ZakWare Inventory v3.2.1</div>
    <ul>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/products">Products</a></li>
        <li><a href="/orders">Orders</a></li>
        <li><a href="/suppliers">Suppliers</a></li>
        <li><a href="/reports">Reports</a></li>
        <?php if ($_SESSION['role'] === 'admin'): ?>
        <li><a href="/users">Users</a></li>
        <?php endif; ?>
        <li><a href="/logout">Logout (<?php
            // BUG-008: XSS via session username displayed without encoding (CWE-79, CVSS 6.1, HIGH, Tier 2)
            echo $_SESSION['username'];
        ?>)</a></li>
    </ul>
</nav>
<?php endif; ?>

<main class="content">
<?php
    if (file_exists(__DIR__ . '/' . $page)) {
        include __DIR__ . '/' . $page;
    } else {
        echo '<h1>Page Not Found</h1>';
        echo '<p>The requested page could not be found.</p>';
    }
?>
</main>

<footer>
    <p>&copy; <?php echo date('Y'); ?> ZakWare Industries.</p>
</footer>

<script src="/public/js/inventory.js"></script>
<script src="/public/js/dashboard.js"></script>
</body>
</html>
