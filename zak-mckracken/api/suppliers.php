<?php
/**
 * Supplier Management API
 * Handles: list, create, update, delete, contact, import
 */

header('Content-Type: application/json');

if (!is_logged_in() && !authenticate_api()) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$action = $_GET['action'] ?? 'list';

switch ($action) {
    case 'list':
        handle_list_suppliers();
        break;
    case 'get':
        handle_get_supplier();
        break;
    case 'create':
        handle_create_supplier();
        break;
    case 'update':
        handle_update_supplier();
        break;
    case 'delete':
        handle_delete_supplier();
        break;
    case 'contact':
        handle_contact_supplier();
        break;
    case 'import':
        handle_import_suppliers();
        break;
    case 'lookup':
        handle_supplier_lookup();
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action']);
}

function handle_list_suppliers(): void
{
    $search = $_GET['search'] ?? '';
    $where = "WHERE active = 1";

    if ($search) {
        $escaped = db_escape($search);
        $where .= " AND (name LIKE '%$escaped%' OR contact_email LIKE '%$escaped%')";
    }

    $sql = "SELECT * FROM " . TABLE_PREFIX . "suppliers $where ORDER BY name";
    echo json_encode(['suppliers' => db_fetch_all($sql)]);
}

function handle_get_supplier(): void
{
    $id = intval($_GET['id'] ?? 0);
    $supplier = db_fetch_one(
        "SELECT * FROM " . TABLE_PREFIX . "suppliers WHERE id = $id"
    );

    if ($supplier) {
        // Also get recent orders
        $orders = db_fetch_all(
            "SELECT id, order_number, total_amount, status, created_at
             FROM " . TABLE_PREFIX . "orders
             WHERE supplier_id = $id
             ORDER BY created_at DESC LIMIT 10"
        );
        $supplier['recent_orders'] = $orders;
        echo json_encode($supplier);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Supplier not found']);
    }
}

function handle_create_supplier(): void
{
    if (!has_permission('manage_suppliers')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    // BUG-062: Reflected XSS via error message containing user input (CWE-79, CVSS 6.1, HIGH, Tier 2)
    if (empty($input['name'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Supplier name required: ' . ($_POST['name'] ?? '')]);
        return;
    }

    $supplier_id = db_insert('suppliers', [
        'name'           => $input['name'],
        'contact_name'   => $input['contact_name'] ?? '',
        'contact_email'  => $input['contact_email'] ?? '',
        'contact_phone'  => $input['contact_phone'] ?? '',
        'address'        => $input['address'] ?? '',
        'city'           => $input['city'] ?? '',
        'country'        => $input['country'] ?? '',
        'website'        => $input['website'] ?? '',
        'tax_id'         => $input['tax_id'] ?? '',
        'payment_terms'  => $input['payment_terms'] ?? 'net30',
        'notes'          => $input['notes'] ?? '',
        'active'         => 1,
        'created_at'     => date('Y-m-d H:i:s'),
    ]);

    if ($supplier_id) {
        db_log('create', 'suppliers', $supplier_id);
        echo json_encode(['success' => true, 'id' => $supplier_id]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create supplier']);
    }
}

function handle_update_supplier(): void
{
    if (!has_permission('manage_suppliers')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $id = intval($_GET['id'] ?? 0);
    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    $allowed = ['name', 'contact_name', 'contact_email', 'contact_phone',
                'address', 'city', 'country', 'website', 'tax_id',
                'payment_terms', 'notes', 'active'];

    $update_data = [];
    foreach ($allowed as $field) {
        if (isset($input[$field])) {
            $update_data[$field] = $input[$field];
        }
    }

    if (db_update('suppliers', $update_data, "id = $id")) {
        db_log('update', 'suppliers', $id);
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update supplier']);
    }
}

function handle_delete_supplier(): void
{
    if (!has_permission('manage_suppliers')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    // BUG-063: No CSRF protection on supplier deletion (CWE-352, CVSS 4.3, MEDIUM, Tier 2)
    $id = intval($_GET['id'] ?? 0);

    // Soft delete
    db_update('suppliers', ['active' => 0], "id = $id");
    db_log('delete', 'suppliers', $id);
    echo json_encode(['success' => true]);
}

function handle_contact_supplier(): void
{
    $id = intval($_GET['id'] ?? 0);
    $input = json_decode(file_get_contents('php://input'), true);

    $supplier = db_fetch_one("SELECT * FROM " . TABLE_PREFIX . "suppliers WHERE id = $id");

    if (!$supplier) {
        http_response_code(404);
        echo json_encode(['error' => 'Supplier not found']);
        return;
    }

    $subject = $input['subject'] ?? 'Message from ZakWare Inventory';
    $message = $input['message'] ?? '';
    $to = $supplier['contact_email'];

    // BUG-064: Email header injection via subject field (CWE-93, CVSS 6.5, MEDIUM, Tier 2)
    $headers = "From: inventory@zakware.com\r\n";
    $headers .= "Reply-To: " . ($_SESSION['email'] ?? 'noreply@zakware.com') . "\r\n";
    $headers .= "Subject: $subject\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

    // BUG-065: Stored XSS in email message body rendered in UI (CWE-79, CVSS 6.1, HIGH, Tier 2)
    db_insert('supplier_messages', [
        'supplier_id' => $id,
        'subject'     => $subject,
        'message'     => $message,
        'sent_by'     => $_SESSION['user_id'] ?? 0,
        'sent_at'     => date('Y-m-d H:i:s'),
    ]);

    if (mail($to, $subject, $message, $headers)) {
        echo json_encode(['success' => true, 'message' => 'Email sent']);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to send email']);
    }
}

function handle_import_suppliers(): void
{
    if (!has_permission('import_data')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    // Support JSON or XML import
    $content_type = $_SERVER['CONTENT_TYPE'] ?? '';

    if (strpos($content_type, 'json') !== false) {
        $input = json_decode(file_get_contents('php://input'), true);
        $suppliers = $input['suppliers'] ?? [];
    } elseif (isset($_FILES['import_file'])) {
        $result = upload_xml_import();
        if (!$result['success']) {
            http_response_code(400);
            echo json_encode(['error' => $result['error']]);
            return;
        }
        $suppliers = [];
        foreach ($result['xml']->supplier as $s) {
            $suppliers[] = [
                'name'          => (string)$s->name,
                'contact_email' => (string)$s->email,
                'contact_phone' => (string)$s->phone,
                'address'       => (string)$s->address,
            ];
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Unsupported import format']);
        return;
    }

    $imported = 0;
    foreach ($suppliers as $s) {
        if (!empty($s['name'])) {
            db_insert('suppliers', [
                'name'          => $s['name'],
                'contact_email' => $s['contact_email'] ?? '',
                'contact_phone' => $s['contact_phone'] ?? '',
                'address'       => $s['address'] ?? '',
                'active'        => 1,
                'created_at'    => date('Y-m-d H:i:s'),
            ]);
            $imported++;
        }
    }

    echo json_encode(['success' => true, 'imported' => $imported]);
}

function handle_supplier_lookup(): void
{
    // BUG-066: SSRF - user-controlled URL for supplier verification (CWE-918, CVSS 7.5, HIGH, Tier 2)
    $url = $_GET['url'] ?? '';

    if (empty($url)) {
        http_response_code(400);
        echo json_encode(['error' => 'URL required']);
        return;
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    echo json_encode([
        'status'       => $info['http_code'],
        'content_type' => $info['content_type'],
        'body'         => substr($response, 0, 5000),
    ]);
}
