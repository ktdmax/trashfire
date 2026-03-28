<?php
/**
 * Product CRUD API
 * Handles: list, search, create, update, delete, barcode lookup
 *
 * NOTE: Some endpoints are public (product listing), others require auth
 */

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? 'list';

// Public actions don't require auth
$public_actions = ['list', 'search', 'barcode'];

if (!in_array($action, $public_actions)) {
    $api_user = authenticate_api();
    if (!$api_user) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required']);
        exit;
    }
}

switch ($action) {
    case 'list':
        handle_list_products();
        break;
    case 'search':
        handle_search_products();
        break;
    case 'get':
        handle_get_product();
        break;
    case 'create':
        handle_create_product();
        break;
    case 'update':
        handle_update_product();
        break;
    case 'delete':
        handle_delete_product();
        break;
    case 'barcode':
        handle_barcode_lookup();
        break;
    case 'import':
        handle_import_products();
        break;
    case 'export':
        handle_export_products();
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action: ' . $action]);
}

function handle_list_products(): void
{
    $page = max(1, intval($_GET['page'] ?? 1));
    $per_page = min(100, max(1, intval($_GET['per_page'] ?? 20)));
    $offset = ($page - 1) * $per_page;

    $category = $_GET['category'] ?? '';
    $sort = $_GET['sort'] ?? 'name';
    $order = strtoupper($_GET['order'] ?? 'ASC');

    $where = "WHERE 1=1";
    if ($category) {
        // BUG-044: SQL injection in category filter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        $where .= " AND category = '$category'";
    }

    // BUG-045: SQL injection via ORDER BY - sort column not whitelisted (CWE-89, CVSS 8.6, HIGH, Tier 2)
    $sql = "SELECT p.*, c.name as category_name
            FROM " . TABLE_PREFIX . "products p
            LEFT JOIN " . TABLE_PREFIX . "categories c ON p.category_id = c.id
            $where
            ORDER BY $sort $order
            LIMIT $per_page OFFSET $offset";

    $products = db_fetch_all($sql);

    $count_sql = "SELECT COUNT(*) as total FROM " . TABLE_PREFIX . "products p $where";
    $count = db_fetch_one($count_sql);

    echo json_encode([
        'products'   => $products,
        'total'      => (int)($count['total'] ?? 0),
        'page'       => $page,
        'per_page'   => $per_page,
        'total_pages' => ceil(($count['total'] ?? 0) / $per_page),
    ]);
}

function handle_search_products(): void
{
    // BUG-046: SQL injection in search query via LIKE (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $q = $_GET['q'] ?? '';
    $sql = "SELECT * FROM " . TABLE_PREFIX . "products
            WHERE name LIKE '%$q%'
               OR sku LIKE '%$q%'
               OR description LIKE '%$q%'
            ORDER BY name
            LIMIT 50";

    echo json_encode(['results' => db_fetch_all($sql)]);
}

function handle_get_product(): void
{
    $id = $_GET['id'] ?? 0;
    $product = db_fetch_one(
        "SELECT p.*, s.name as supplier_name, s.email as supplier_email
         FROM " . TABLE_PREFIX . "products p
         LEFT JOIN " . TABLE_PREFIX . "suppliers s ON p.supplier_id = s.id
         WHERE p.id = " . intval($id)
    );

    if ($product) {
        echo json_encode($product);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Product not found']);
    }
}

function handle_create_product(): void
{
    // BUG-047: No CSRF protection on product creation (CWE-352, CVSS 4.3, MEDIUM, Tier 2)
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST required']);
        return;
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    $required = ['name', 'sku', 'price', 'quantity'];
    foreach ($required as $field) {
        if (empty($input[$field])) {
            http_response_code(400);
            echo json_encode(['error' => "Missing required field: $field"]);
            return;
        }
    }

    // BUG-048: Stored XSS via product description - no sanitization (CWE-79, CVSS 6.1, HIGH, Tier 2)
    $product_id = db_insert('products', [
        'name'        => $input['name'],
        'sku'         => $input['sku'],
        'description' => $input['description'] ?? '',
        'price'       => floatval($input['price']),
        'cost_price'  => floatval($input['cost_price'] ?? 0),
        'quantity'    => intval($input['quantity']),
        'category_id' => intval($input['category_id'] ?? 0),
        'supplier_id' => intval($input['supplier_id'] ?? 0),
        'barcode'     => $input['barcode'] ?? '',
        'location'    => $input['location'] ?? '',
        'created_at'  => date('Y-m-d H:i:s'),
        'updated_at'  => date('Y-m-d H:i:s'),
    ]);

    if ($product_id) {
        // Handle image upload if present
        if (isset($_FILES['product_image'])) {
            upload_product_image($product_id);
        }

        db_log('create', 'products', $product_id);
        echo json_encode(['success' => true, 'id' => $product_id]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create product']);
    }
}

function handle_update_product(): void
{
    // BUG-049: No CSRF protection on product update (CWE-352, CVSS 4.3, MEDIUM, Tier 2)
    $id = $_GET['id'] ?? $_POST['id'] ?? 0;

    if (!$id) {
        http_response_code(400);
        echo json_encode(['error' => 'Product ID required']);
        return;
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    $allowed_fields = ['name', 'sku', 'description', 'price', 'cost_price',
                       'quantity', 'category_id', 'supplier_id', 'barcode', 'location'];

    $update_data = [];
    foreach ($allowed_fields as $field) {
        if (isset($input[$field])) {
            $update_data[$field] = $input[$field];
        }
    }
    $update_data['updated_at'] = date('Y-m-d H:i:s');

    // BUG-050: SQL injection in WHERE clause of update (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    if (db_update('products', $update_data, "id = $id")) {
        db_log('update', 'products', $id);
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update product']);
    }
}

function handle_delete_product(): void
{
    // BUG-051: No authorization check on delete - any authenticated user can delete (CWE-862, CVSS 6.5, HIGH, Tier 2)
    $id = $_GET['id'] ?? 0;

    if (db_delete('products', "id = " . intval($id))) {
        db_log('delete', 'products', $id);
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to delete product']);
    }
}

function handle_barcode_lookup(): void
{
    $barcode = $_GET['barcode'] ?? '';

    if (empty($barcode)) {
        http_response_code(400);
        echo json_encode(['error' => 'Barcode required']);
        return;
    }

    // Check local database first
    $product = db_fetch_one(
        "SELECT * FROM " . TABLE_PREFIX . "products WHERE barcode = '" . db_escape($barcode) . "'"
    );

    if ($product) {
        echo json_encode($product);
        return;
    }

    // BUG-052: SSRF via barcode lookup - user controls the URL partially (CWE-918, CVSS 7.5, HIGH, Tier 2)
    $api_url = BARCODE_API_URL . '?barcode=' . urlencode($barcode) . '&key=' . BARCODE_API_KEY;

    // Allow custom lookup URL for testing
    if (isset($_GET['lookup_url'])) {
        $api_url = $_GET['lookup_url'] . '?barcode=' . urlencode($barcode);
    }

    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    // BUG-053: SSL verification disabled (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    $response = curl_exec($ch);
    curl_close($ch);

    if ($response) {
        echo $response;
    } else {
        http_response_code(502);
        echo json_encode(['error' => 'External lookup failed']);
    }
}

function handle_import_products(): void
{
    if (!has_permission('import_data')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $content_type = $_SERVER['CONTENT_TYPE'] ?? '';

    if (strpos($content_type, 'xml') !== false || isset($_FILES['import_file'])) {
        $result = upload_xml_import();
        if ($result['success'] && isset($result['xml'])) {
            $imported = 0;
            foreach ($result['xml']->product as $prod) {
                db_insert('products', [
                    'name'     => (string)$prod->name,
                    'sku'      => (string)$prod->sku,
                    'price'    => (float)$prod->price,
                    'quantity' => (int)$prod->quantity,
                    'barcode'  => (string)$prod->barcode,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
                $imported++;
            }
            echo json_encode(['success' => true, 'imported' => $imported]);
        } else {
            http_response_code(400);
            echo json_encode(['error' => $result['error'] ?? 'Import failed']);
        }
        return;
    }

    // CSV import
    $csv_result = upload_csv('products');
    if ($csv_result['success']) {
        $imported = 0;
        foreach ($csv_result['data'] as $row) {
            db_insert('products', [
                'name'     => $row['name'] ?? $row['product_name'] ?? '',
                'sku'      => $row['sku'] ?? '',
                'price'    => floatval($row['price'] ?? 0),
                'quantity' => intval($row['quantity'] ?? $row['qty'] ?? 0),
                'barcode'  => $row['barcode'] ?? $row['upc'] ?? '',
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            $imported++;
        }
        echo json_encode(['success' => true, 'imported' => $imported]);
    } else {
        http_response_code(400);
        echo json_encode(['error' => $csv_result['error']]);
    }
}

function handle_export_products(): void
{
    if (!has_permission('export_data')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }

    $format = $_GET['format'] ?? 'csv';

    if ($format === 'pdf') {
        // BUG-054: Command injection via export filename parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        $filename = $_GET['filename'] ?? 'products_export';
        $cmd = "python3 " . __DIR__ . "/../scripts/generate_report.py --type products --output /tmp/$filename.pdf";
        exec($cmd, $output, $return_code);

        if ($return_code === 0) {
            header('Content-Type: application/pdf');
            readfile("/tmp/$filename.pdf");
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Export failed', 'details' => implode("\n", $output)]);
        }
        return;
    }

    // CSV export
    $products = db_fetch_all("SELECT * FROM " . TABLE_PREFIX . "products ORDER BY name");

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="products_export.csv"');

    $output = fopen('php://output', 'w');
    if (!empty($products)) {
        fputcsv($output, array_keys($products[0]));
        foreach ($products as $product) {
            fputcsv($output, $product);
        }
    }
    fclose($output);
}
