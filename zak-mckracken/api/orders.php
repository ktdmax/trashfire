<?php
/**
 * Purchase Order API
 * Handles: create, update, approve, list, receive
 */

header('Content-Type: application/json');

$api_user = authenticate_api();
if (!$api_user && !is_logged_in()) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? 'list';

switch ($action) {
    case 'list':
        handle_list_orders();
        break;
    case 'get':
        handle_get_order();
        break;
    case 'create':
        handle_create_order();
        break;
    case 'update':
        handle_update_order();
        break;
    case 'approve':
        handle_approve_order();
        break;
    case 'receive':
        handle_receive_order();
        break;
    case 'cancel':
        handle_cancel_order();
        break;
    case 'template':
        handle_order_template();
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action']);
}

function handle_list_orders(): void
{
    $status = $_GET['status'] ?? '';
    $supplier_id = $_GET['supplier_id'] ?? '';
    $date_from = $_GET['date_from'] ?? '';
    $date_to = $_GET['date_to'] ?? '';

    $where = "WHERE 1=1";

    // BUG-055: SQL injection in status filter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    if ($status) {
        $where .= " AND o.status = '$status'";
    }
    if ($supplier_id) {
        $where .= " AND o.supplier_id = " . intval($supplier_id);
    }
    if ($date_from) {
        $where .= " AND o.created_at >= '" . db_escape($date_from) . "'";
    }
    if ($date_to) {
        $where .= " AND o.created_at <= '" . db_escape($date_to) . " 23:59:59'";
    }

    $sql = "SELECT o.*, s.name as supplier_name, u.username as created_by_name
            FROM " . TABLE_PREFIX . "orders o
            LEFT JOIN " . TABLE_PREFIX . "suppliers s ON o.supplier_id = s.id
            LEFT JOIN " . TABLE_PREFIX . "users u ON o.created_by = u.id
            $where
            ORDER BY o.created_at DESC
            LIMIT 100";

    echo json_encode(['orders' => db_fetch_all($sql)]);
}

function handle_get_order(): void
{
    // BUG-056: IDOR - no check that user has access to this order (CWE-639, CVSS 6.5, HIGH, Tier 2)
    $id = intval($_GET['id'] ?? 0);

    $order = db_fetch_one(
        "SELECT o.*, s.name as supplier_name, s.email as supplier_email
         FROM " . TABLE_PREFIX . "orders o
         LEFT JOIN " . TABLE_PREFIX . "suppliers s ON o.supplier_id = s.id
         WHERE o.id = $id"
    );

    if (!$order) {
        http_response_code(404);
        echo json_encode(['error' => 'Order not found']);
        return;
    }

    // Get order items
    $items = db_fetch_all(
        "SELECT oi.*, p.name as product_name, p.sku
         FROM " . TABLE_PREFIX . "order_items oi
         LEFT JOIN " . TABLE_PREFIX . "products p ON oi.product_id = p.id
         WHERE oi.order_id = $id"
    );

    $order['items'] = $items;
    echo json_encode($order);
}

function handle_create_order(): void
{
    if (!has_permission('create_orders')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }

    $supplier_id = intval($input['supplier_id'] ?? 0);
    $items = $input['items'] ?? [];
    $notes = $input['notes'] ?? '';

    if (!$supplier_id || empty($items)) {
        http_response_code(400);
        echo json_encode(['error' => 'Supplier and items required']);
        return;
    }

    // Generate order number
    $order_number = 'PO-' . date('Ymd') . '-' . str_pad(mt_rand(1, 9999), 4, '0', STR_PAD_LEFT);

    $total = 0;
    foreach ($items as $item) {
        $total += floatval($item['quantity'] ?? 0) * floatval($item['unit_price'] ?? 0);
    }

    $user_id = $_SESSION['user_id'] ?? ($api_user['id'] ?? 0);

    $order_id = db_insert('orders', [
        'order_number' => $order_number,
        'supplier_id'  => $supplier_id,
        'total_amount' => $total,
        'status'       => 'draft',
        'notes'        => $notes,
        'created_by'   => $user_id,
        'created_at'   => date('Y-m-d H:i:s'),
        'updated_at'   => date('Y-m-d H:i:s'),
    ]);

    if (!$order_id) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create order']);
        return;
    }

    // Insert order items
    foreach ($items as $item) {
        db_insert('order_items', [
            'order_id'   => $order_id,
            'product_id' => intval($item['product_id']),
            'quantity'    => intval($item['quantity']),
            'unit_price'  => floatval($item['unit_price']),
            'total_price' => floatval($item['quantity']) * floatval($item['unit_price']),
        ]);
    }

    db_log('create', 'orders', $order_id);

    echo json_encode([
        'success'      => true,
        'id'           => $order_id,
        'order_number' => $order_number,
    ]);
}

function handle_update_order(): void
{
    $id = intval($_GET['id'] ?? 0);
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$id || !$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Order ID and data required']);
        return;
    }

    $order = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "orders WHERE id = $id");

    if (!$order) {
        http_response_code(404);
        echo json_encode(['error' => 'Order not found']);
        return;
    }

    // BUG-057: Status can be changed to 'approved' bypassing approval workflow (CWE-284, CVSS 6.5, MEDIUM, Tier 2)
    $allowed = ['supplier_id', 'notes', 'status', 'total_amount'];
    $update_data = [];
    foreach ($allowed as $field) {
        if (isset($input[$field])) {
            $update_data[$field] = $input[$field];
        }
    }
    $update_data['updated_at'] = date('Y-m-d H:i:s');

    if (db_update('orders', $update_data, "id = $id")) {
        db_log('update', 'orders', $id);
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update order']);
    }
}

function handle_approve_order(): void
{
    if (!has_permission('approve_orders')) {
        http_response_code(403);
        echo json_encode(['error' => 'Only managers can approve orders']);
        return;
    }

    $id = intval($_GET['id'] ?? 0);
    $order = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "orders WHERE id = $id");

    if (!$order) {
        http_response_code(404);
        echo json_encode(['error' => 'Order not found']);
        return;
    }

    // BUG-058: Race condition - order can be approved multiple times concurrently (CWE-362, CVSS 5.9, TRICKY, Tier 3)
    if ($order['status'] !== 'pending') {
        http_response_code(400);
        echo json_encode(['error' => 'Order must be in pending status']);
        return;
    }

    $approver_id = $_SESSION['user_id'] ?? 0;

    db_update('orders', [
        'status'      => 'approved',
        'approved_by' => $approver_id,
        'approved_at' => date('Y-m-d H:i:s'),
        'updated_at'  => date('Y-m-d H:i:s'),
    ], "id = $id");

    db_log('approve', 'orders', $id);
    echo json_encode(['success' => true, 'message' => 'Order approved']);
}

function handle_receive_order(): void
{
    if (!has_permission('create_orders')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $id = intval($_GET['id'] ?? 0);
    $input = json_decode(file_get_contents('php://input'), true);

    $order = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "orders WHERE id = $id");
    if (!$order || $order['status'] !== 'approved') {
        http_response_code(400);
        echo json_encode(['error' => 'Order not found or not approved']);
        return;
    }

    $received_items = $input['items'] ?? [];

    foreach ($received_items as $item) {
        $product_id = intval($item['product_id']);
        $qty_received = intval($item['quantity_received']);

        // BUG-059: Race condition on inventory update, no locking (CWE-362, CVSS 5.9, TRICKY, Tier 3)
        $product = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "products WHERE id = $product_id");
        if ($product) {
            $new_qty = $product['quantity'] + $qty_received;
            db_update('products', ['quantity' => $new_qty], "id = $product_id");
        }

        // Update order item
        db_update('order_items', [
            'quantity_received' => $qty_received,
            'received_at'      => date('Y-m-d H:i:s'),
        ], "order_id = $id AND product_id = $product_id");
    }

    db_update('orders', [
        'status'     => 'received',
        'updated_at' => date('Y-m-d H:i:s'),
    ], "id = $id");

    db_log('receive', 'orders', $id);
    echo json_encode(['success' => true, 'message' => 'Order received']);
}

function handle_cancel_order(): void
{
    $id = intval($_GET['id'] ?? 0);

    // BUG-060: Any authenticated user can cancel any order (CWE-862, CVSS 6.5, HIGH, Tier 2)
    db_update('orders', [
        'status'     => 'cancelled',
        'updated_at' => date('Y-m-d H:i:s'),
    ], "id = $id");

    db_log('cancel', 'orders', $id);
    echo json_encode(['success' => true]);
}

function handle_order_template(): void
{
    // BUG-061: PHP object deserialization from user input (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    $template_data = $_POST['template'] ?? $_GET['template'] ?? '';

    if ($template_data) {
        $template = unserialize(base64_decode($template_data));
        if (is_array($template)) {
            echo json_encode(['template' => $template]);
            return;
        }
    }

    // Default template
    echo json_encode([
        'template' => [
            'supplier_id' => 0,
            'items'       => [],
            'notes'       => '',
        ]
    ]);
}
