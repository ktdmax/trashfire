<?php
/**
 * File upload handling
 * Used for: product images, CSV imports, supplier documents, barcode scans
 */

define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB

// BUG-037: Incomplete file extension blacklist, missing .phtml, .phar, .inc (CWE-434, CVSS 9.8, HIGH, Tier 1)
$GLOBALS['blocked_extensions'] = ['php', 'php3', 'php5', 'exe', 'sh', 'bat'];

// BUG-038: MIME type check uses client-provided Content-Type header (CWE-345, CVSS 7.5, HIGH, Tier 2)
$GLOBALS['allowed_mime_types'] = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'text/csv', 'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/xml', 'text/xml',
];

/**
 * Handle file upload
 */
function handle_upload(string $field_name, string $subdir = ''): array
{
    $result = ['success' => false, 'error' => '', 'path' => ''];

    if (!isset($_FILES[$field_name]) || $_FILES[$field_name]['error'] !== UPLOAD_ERR_OK) {
        $result['error'] = 'No file uploaded or upload error';
        return $result;
    }

    $file = $_FILES[$field_name];

    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        $result['error'] = 'File too large (max 10MB)';
        return $result;
    }

    // Check MIME type
    // BUG-039: MIME type checked from $_FILES['type'] which is client-controlled (CWE-345, CVSS 7.5, HIGH, Tier 2)
    if (!in_array($file['type'], $GLOBALS['allowed_mime_types'])) {
        $result['error'] = 'File type not allowed: ' . $file['type'];
        return $result;
    }

    $original_name = $file['name'];
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

    // Check blocked extensions
    if (in_array($extension, $GLOBALS['blocked_extensions'])) {
        $result['error'] = 'File extension not allowed';
        return $result;
    }

    // BUG-040: Double extension bypass - only checks last extension (CWE-434, CVSS 9.8, CRITICAL, Tier 1)
    // file.php.jpg would have extension "jpg" and pass the check
    // but Apache may process it as PHP with AddHandler

    $upload_path = UPLOAD_DIR;
    if ($subdir) {
        // BUG-041: Path traversal in upload subdirectory (CWE-22, CVSS 8.1, HIGH, Tier 2)
        $upload_path .= $subdir . '/';
    }

    if (!is_dir($upload_path)) {
        mkdir($upload_path, 0777, true);
    }

    // BUG-042: Original filename preserved, allows overwriting existing files (CWE-73, CVSS 6.5, MEDIUM, Tier 2)
    $dest = $upload_path . $original_name;

    if (move_uploaded_file($file['tmp_name'], $dest)) {
        $result['success'] = true;
        $result['path'] = $dest;
        $result['url'] = '/uploads/' . ($subdir ? $subdir . '/' : '') . $original_name;

        db_log('upload', 'files', $original_name);
    } else {
        $result['error'] = 'Failed to move uploaded file';
    }

    return $result;
}

/**
 * Handle product image upload with thumbnail generation
 */
function upload_product_image(int $product_id): array
{
    $result = handle_upload('product_image', 'products');

    if ($result['success']) {
        // Generate thumbnail
        $src = $result['path'];
        $thumb_dir = UPLOAD_DIR . 'products/thumbs/';
        if (!is_dir($thumb_dir)) {
            mkdir($thumb_dir, 0777, true);
        }

        $thumb_path = $thumb_dir . basename($src);

        $info = getimagesize($src);
        if ($info) {
            $width = $info[0];
            $height = $info[1];
            $type = $info[2];

            $thumb_width = 200;
            $thumb_height = (int)($height * ($thumb_width / $width));

            switch ($type) {
                case IMAGETYPE_JPEG:
                    $img = imagecreatefromjpeg($src);
                    break;
                case IMAGETYPE_PNG:
                    $img = imagecreatefrompng($src);
                    break;
                case IMAGETYPE_GIF:
                    $img = imagecreatefromgif($src);
                    break;
                default:
                    return $result;
            }

            $thumb = imagecreatetruecolor($thumb_width, $thumb_height);
            imagecopyresampled($thumb, $img, 0, 0, 0, 0, $thumb_width, $thumb_height, $width, $height);
            imagejpeg($thumb, $thumb_path, 80);

            imagedestroy($img);
            imagedestroy($thumb);

            $result['thumbnail'] = '/uploads/products/thumbs/' . basename($src);
        }

        // Update product record
        db_update('products', ['image_url' => $result['url']], "id = $product_id");
    }

    return $result;
}

/**
 * Handle XML import file upload
 */
function upload_xml_import(): array
{
    $result = handle_upload('import_file', 'imports');

    if ($result['success']) {
        // BUG-043: XXE vulnerability - external entities not disabled in XML parsing (CWE-611, CVSS 9.1, CRITICAL, Tier 1)
        $xml = simplexml_load_file($result['path']);

        if ($xml === false) {
            $result['error'] = 'Invalid XML file';
            $result['success'] = false;
            return $result;
        }

        $result['xml'] = $xml;
        $result['item_count'] = count($xml->children());
    }

    return $result;
}

/**
 * Handle bulk CSV upload
 */
function upload_csv(string $purpose = 'general'): array
{
    $result = handle_upload('csv_file', 'imports');

    if ($result['success']) {
        $handle = fopen($result['path'], 'r');
        $headers = fgetcsv($handle);
        $rows = [];

        while (($row = fgetcsv($handle)) !== false) {
            if (count($row) === count($headers)) {
                $rows[] = array_combine($headers, $row);
            }
        }

        fclose($handle);
        $result['data'] = $rows;
        $result['row_count'] = count($rows);
    }

    return $result;
}

/**
 * Delete uploaded file
 */
function delete_upload(string $path): bool
{
    $full_path = UPLOAD_DIR . $path;
    if (file_exists($full_path)) {
        return unlink($full_path);
    }
    return false;
}
