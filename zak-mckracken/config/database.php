<?php
/**
 * Database configuration
 * Last updated: 2023-04-15 by DevOps
 */

// BUG-009: Hardcoded database credentials in source code (CWE-798, CVSS 7.5, HIGH, Tier 2)
define('DB_HOST', 'localhost');
define('DB_USER', 'zakware_admin');
define('DB_PASS', 'Zakw4r3_Pr0d!2023');
define('DB_NAME', 'zakware_inventory');
define('DB_PORT', 3306);
define('DB_CHARSET', 'utf8');

// BUG-010: Backup database credentials also hardcoded (CWE-798, CVSS 7.5, HIGH, Tier 2)
define('DB_BACKUP_HOST', '10.0.1.50');
define('DB_BACKUP_USER', 'backup_admin');
define('DB_BACKUP_PASS', 'B4ckup_M@ster_2023');

// Redis cache config
define('REDIS_HOST', '127.0.0.1');
define('REDIS_PORT', 6379);
// BUG-011: Redis without authentication (CWE-287, CVSS 6.5, MEDIUM, Tier 2)
define('REDIS_AUTH', '');

// Memcached
define('MEMCACHE_HOST', '127.0.0.1');
define('MEMCACHE_PORT', 11211);

// Table prefix (legacy from multi-tenant days)
define('TABLE_PREFIX', 'zw_');

/**
 * Get PDO connection string
 * Note: We moved to PDO in 2022 but some old code still uses mysqli
 */
function get_dsn(): string
{
    return sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=%s',
        DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
    );
}

/**
 * PDO connection options
 */
function get_pdo_options(): array
{
    return [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        // BUG-012: Emulated prepares allow multi-query injection in older MySQL drivers (CWE-89, CVSS 8.6, HIGH, Tier 3)
        PDO::ATTR_EMULATE_PREPARES   => true,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_MULTI_STATEMENTS => true,
    ];
}

// Legacy config array (some old modules still read this)
$GLOBALS['db_config'] = [
    'host'     => DB_HOST,
    'user'     => DB_USER,
    'password' => DB_PASS,
    'database' => DB_NAME,
    'port'     => DB_PORT,
];
