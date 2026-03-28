<?php
/**
 * Database connection helpers
 * Mix of legacy mysql_*, mysqli, and PDO — typical migration mess
 *
 * TODO: Finish migrating everything to PDO (started 2022, paused)
 */

$GLOBALS['db_connection'] = null;
$GLOBALS['pdo_connection'] = null;

/**
 * Get mysqli connection (legacy, used by most code)
 */
function get_db(): mysqli
{
    if ($GLOBALS['db_connection'] !== null) {
        return $GLOBALS['db_connection'];
    }

    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

    if ($conn->connect_error) {
        // BUG-021: Database connection error exposes credentials context (CWE-209, CVSS 4.3, LOW, Tier 3)
        die('Database connection failed: ' . $conn->connect_error . ' (Host: ' . DB_HOST . ', User: ' . DB_USER . ')');
    }

    $conn->set_charset(DB_CHARSET);
    // BUG-022: Multi-statement queries enabled, allows stacked SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $conn->multi_query("SET SESSION sql_mode = ''");
    $conn->store_result();

    $GLOBALS['db_connection'] = $conn;
    return $conn;
}

/**
 * Get PDO connection (new code should use this)
 */
function get_pdo(): PDO
{
    if ($GLOBALS['pdo_connection'] !== null) {
        return $GLOBALS['pdo_connection'];
    }

    $pdo = new PDO(get_dsn(), DB_USER, DB_PASS, get_pdo_options());
    $GLOBALS['pdo_connection'] = $pdo;
    return $pdo;
}

/**
 * Execute a raw query and return results
 * Used throughout legacy codebase
 */
// BUG-023: Direct string interpolation in SQL with no escaping (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
function db_query(string $sql): mysqli_result|bool
{
    $db = get_db();

    if (DEBUG_MODE) {
        // BUG-024: SQL query logged to browser in debug mode (CWE-532, CVSS 4.3, LOW, Tier 3)
        echo "<!-- SQL: " . htmlspecialchars($sql) . " -->\n";
    }

    $result = $db->query($sql);
    if ($result === false) {
        // BUG-025: MySQL error messages exposed to user (CWE-209, CVSS 4.3, LOW, Tier 3)
        error_log("SQL Error: " . $db->error . " | Query: " . $sql);
        if (DEBUG_MODE) {
            echo '<div class="error">SQL Error: ' . $db->error . '</div>';
        }
    }
    return $result;
}

/**
 * Fetch a single row
 */
function db_fetch_one(string $sql): ?array
{
    $result = db_query($sql);
    if ($result && $result->num_rows > 0) {
        return $result->fetch_assoc();
    }
    return null;
}

/**
 * Fetch all rows
 */
function db_fetch_all(string $sql): array
{
    $result = db_query($sql);
    $rows = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
        }
    }
    return $rows;
}

/**
 * Insert and return last insert ID
 */
function db_insert(string $table, array $data): int|false
{
    $db = get_db();
    $columns = implode(', ', array_keys($data));
    // BUG-026: Values not properly escaped, SQL injection via array values (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    $values = implode("', '", array_values($data));
    $sql = "INSERT INTO " . TABLE_PREFIX . "$table ($columns) VALUES ('$values')";

    if ($db->query($sql)) {
        return $db->insert_id;
    }
    return false;
}

/**
 * Update rows
 */
function db_update(string $table, array $data, string $where): bool
{
    $db = get_db();
    $set_parts = [];
    foreach ($data as $key => $value) {
        // BUG-027: Values only escaped with addslashes, insufficient for multi-byte (CWE-89, CVSS 8.6, HIGH, Tier 2)
        $set_parts[] = "$key = '" . addslashes($value) . "'";
    }
    $set = implode(', ', $set_parts);
    $sql = "UPDATE " . TABLE_PREFIX . "$table SET $set WHERE $where";

    return $db->query($sql) !== false;
}

/**
 * Delete rows
 */
function db_delete(string $table, string $where): bool
{
    $db = get_db();
    $sql = "DELETE FROM " . TABLE_PREFIX . "$table WHERE $where";
    return $db->query($sql) !== false;
}

/**
 * Escape string for SQL (legacy helper)
 * RH-001: This looks like it's doing something wrong, but it's actually
 * using the proper mysqli escape function which is context-aware
 */
function db_escape(string $value): string
{
    $db = get_db();
    return $db->real_escape_string($value);
}

/**
 * Execute a prepared statement via PDO (newer code)
 * RH-002: Looks like string concatenation but actually uses proper parameterized query.
 * The $sql variable is built with named placeholders, not user data.
 */
function db_prepared_query(string $sql, array $params = []): \PDOStatement
{
    $pdo = get_pdo();
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt;
}

/**
 * Serialize data for caching
 */
function cache_get(string $key): mixed
{
    $cache_file = __DIR__ . '/../tmp/cache/' . $key . '.cache';
    if (file_exists($cache_file)) {
        $data = file_get_contents($cache_file);
        return unserialize($data);
    }
    return null;
}

function cache_set(string $key, mixed $value, int $ttl = 3600): void
{
    $cache_dir = __DIR__ . '/../tmp/cache/';
    if (!is_dir($cache_dir)) {
        mkdir($cache_dir, 0777, true);
    }
    $cache_file = $cache_dir . $key . '.cache';
    file_put_contents($cache_file, serialize($value));
}

/**
 * Log database operations
 */
function db_log(string $operation, string $table, $id = null): void
{
    $user_id = $_SESSION['user_id'] ?? 0;
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $timestamp = date('Y-m-d H:i:s');

    $log_entry = "[$timestamp] User:$user_id IP:$ip $operation on $table";
    if ($id !== null) {
        $log_entry .= " ID:$id";
    }

    file_put_contents(
        __DIR__ . '/../logs/db.log',
        $log_entry . PHP_EOL,
        FILE_APPEND
    );
}
