<?php
/**
 * Reporting API
 * Generates various inventory and business reports
 */

header('Content-Type: application/json');

if (!is_logged_in() && !authenticate_api()) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

if (!has_permission('view_reports')) {
    http_response_code(403);
    echo json_encode(['error' => 'Insufficient permissions']);
    exit;
}

$action = $_GET['action'] ?? 'summary';

switch ($action) {
    case 'summary':
        handle_summary_report();
        break;
    case 'inventory':
        handle_inventory_report();
        break;
    case 'sales':
        handle_sales_report();
        break;
    case 'low_stock':
        handle_low_stock_report();
        break;
    case 'custom':
        handle_custom_report();
        break;
    case 'export':
        handle_report_export();
        break;
    case 'scheduled':
        handle_scheduled_report();
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown report type']);
}

function handle_summary_report(): void
{
    $period = $_GET['period'] ?? 'month';

    $stats = [
        'total_products' => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "products")['cnt'],
        'total_value'    => db_fetch_one("SELECT SUM(price * quantity) as total FROM " . TABLE_PREFIX . "products")['total'],
        'low_stock'      => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "products WHERE quantity < 10")['cnt'],
        'out_of_stock'   => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "products WHERE quantity = 0")['cnt'],
        'total_orders'   => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "orders")['cnt'],
        'pending_orders' => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "orders WHERE status = 'pending'")['cnt'],
        'total_suppliers' => db_fetch_one("SELECT COUNT(*) as cnt FROM " . TABLE_PREFIX . "suppliers WHERE active = 1")['cnt'],
    ];

    echo json_encode(['summary' => $stats, 'period' => $period]);
}

function handle_inventory_report(): void
{
    $category = $_GET['category'] ?? '';
    $location = $_GET['location'] ?? '';

    $where = "WHERE 1=1";
    if ($category) {
        $where .= " AND p.category_id = " . intval($category);
    }
    if ($location) {
        // BUG-067: SQL injection in location filter (CWE-89, CVSS 8.6, HIGH, Tier 2)
        $where .= " AND p.location = '$location'";
    }

    $sql = "SELECT p.id, p.name, p.sku, p.quantity, p.price,
                   (p.price * p.quantity) as total_value,
                   p.location, c.name as category_name
            FROM " . TABLE_PREFIX . "products p
            LEFT JOIN " . TABLE_PREFIX . "categories c ON p.category_id = c.id
            $where
            ORDER BY p.name";

    echo json_encode(['inventory' => db_fetch_all($sql)]);
}

function handle_sales_report(): void
{
    $date_from = $_GET['date_from'] ?? date('Y-m-01');
    $date_to = $_GET['date_to'] ?? date('Y-m-d');

    $sql = "SELECT DATE(o.created_at) as date,
                   COUNT(o.id) as order_count,
                   SUM(o.total_amount) as total_amount
            FROM " . TABLE_PREFIX . "orders o
            WHERE o.status != 'cancelled'
              AND o.created_at BETWEEN '" . db_escape($date_from) . "' AND '" . db_escape($date_to) . " 23:59:59'
            GROUP BY DATE(o.created_at)
            ORDER BY date";

    $data = db_fetch_all($sql);

    // Top products
    $top_sql = "SELECT p.name, p.sku, SUM(oi.quantity) as total_qty,
                       SUM(oi.total_price) as total_revenue
                FROM " . TABLE_PREFIX . "order_items oi
                JOIN " . TABLE_PREFIX . "products p ON oi.product_id = p.id
                JOIN " . TABLE_PREFIX . "orders o ON oi.order_id = o.id
                WHERE o.status != 'cancelled'
                  AND o.created_at BETWEEN '" . db_escape($date_from) . "' AND '" . db_escape($date_to) . " 23:59:59'
                GROUP BY p.id
                ORDER BY total_revenue DESC
                LIMIT 10";

    echo json_encode([
        'daily_totals'  => $data,
        'top_products'  => db_fetch_all($top_sql),
        'date_from'     => $date_from,
        'date_to'       => $date_to,
    ]);
}

function handle_low_stock_report(): void
{
    $threshold = intval($_GET['threshold'] ?? 10);

    $sql = "SELECT p.*, s.name as supplier_name, s.contact_email as supplier_email
            FROM " . TABLE_PREFIX . "products p
            LEFT JOIN " . TABLE_PREFIX . "suppliers s ON p.supplier_id = s.id
            WHERE p.quantity <= $threshold
            ORDER BY p.quantity ASC";

    echo json_encode(['low_stock' => db_fetch_all($sql), 'threshold' => $threshold]);
}

function handle_custom_report(): void
{
    // BUG-068: Arbitrary SQL execution via custom report query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $custom_query = $_POST['query'] ?? $_GET['query'] ?? '';

    if (empty($custom_query)) {
        http_response_code(400);
        echo json_encode(['error' => 'Query parameter required']);
        return;
    }

    // "Safety" check: only allow SELECT statements
    $normalized = strtolower(trim($custom_query));
    // BUG-069: Bypassable SQL filter - only checks first word, UNION/subquery still works (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    if (strpos($normalized, 'select') !== 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Only SELECT queries are allowed']);
        return;
    }

    try {
        $results = db_fetch_all($custom_query);
        echo json_encode(['results' => $results, 'row_count' => count($results)]);
    } catch (Exception $e) {
        http_response_code(500);
        // BUG-070: SQL error message exposed to user (CWE-209, CVSS 4.3, LOW, Tier 3)
        echo json_encode(['error' => 'Query failed: ' . $e->getMessage()]);
    }
}

function handle_report_export(): void
{
    $report_type = $_GET['type'] ?? 'inventory';
    $format = $_GET['format'] ?? 'csv';

    // BUG-071: Command injection via report type parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    $cmd = "python3 " . __DIR__ . "/../scripts/generate_report.py --type " . $report_type;

    if ($format === 'pdf') {
        $output_file = '/tmp/report_' . time() . '.pdf';
        $cmd .= " --format pdf --output " . $output_file;
    } else {
        $output_file = '/tmp/report_' . time() . '.csv';
        $cmd .= " --format csv --output " . $output_file;
    }

    // BUG-072: Command injection via format parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    $output = [];
    exec($cmd . ' 2>&1', $output, $return_code);

    if ($return_code === 0 && file_exists($output_file)) {
        $mime = $format === 'pdf' ? 'application/pdf' : 'text/csv';
        header('Content-Type: ' . $mime);
        header('Content-Disposition: attachment; filename="report.' . $format . '"');
        readfile($output_file);
        unlink($output_file);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Report generation failed', 'output' => $output]);
    }
}

function handle_scheduled_report(): void
{
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input) {
        // List existing scheduled reports
        $schedules = db_fetch_all(
            "SELECT * FROM " . TABLE_PREFIX . "report_schedules WHERE user_id = " . intval($_SESSION['user_id'] ?? 0)
        );
        echo json_encode(['schedules' => $schedules]);
        return;
    }

    $cron_expr = $input['cron'] ?? '0 8 * * 1';

    db_insert('report_schedules', [
        'user_id'     => $_SESSION['user_id'] ?? 0,
        'report_type' => $input['report_type'] ?? 'summary',
        'format'      => $input['format'] ?? 'csv',
        'cron_expr'   => $cron_expr,
        'email_to'    => $input['email'] ?? '',
        'active'      => 1,
        'created_at'  => date('Y-m-d H:i:s'),
    ]);

    echo json_encode(['success' => true, 'message' => 'Report scheduled']);
}
