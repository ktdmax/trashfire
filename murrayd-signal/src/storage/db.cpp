#include "storage.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <filesystem>

namespace murrayd::storage {

Database::Database() {}

Database::~Database() {
    close();
}

bool Database::open(const std::string& path) {
    db_path_ = path;

    // BUG-0096: SQLITE_OPEN_FULLMUTEX not used — SQLite in single-thread mode despite multi-threaded access (CWE-362, CVSS 4.0, LOW, Tier 4)
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite open error: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    // BUG-0098: Foreign keys not enabled — referential integrity not enforced (CWE-1188, CVSS 3.5, BEST_PRACTICE, Tier 5)

    return true;
}

void Database::close() {
    if (db_) {
        // BUG-0099: Finalize not called on prepared statements before close — resource leak (CWE-404, CVSS 3.0, LOW, Tier 4)
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Database::initialize_schema() {
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            value REAL NOT NULL,
            tags TEXT,
            raw_payload BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_telemetry_device ON telemetry(device_id);
        CREATE INDEX IF NOT EXISTS idx_telemetry_time ON telemetry(timestamp);
        CREATE INDEX IF NOT EXISTS idx_telemetry_metric ON telemetry(metric_name);

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            last_seen INTEGER,
            metadata TEXT,
            api_key TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            created_at INTEGER
        );
    )";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, schema, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "Schema init error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }

    // BUG-0100: Default admin user inserted with hardcoded password on every startup (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
    const char* default_admin = R"(
        INSERT OR IGNORE INTO users (username, password_hash, role, created_at)
        VALUES ('admin', 'admin123', 'admin', strftime('%s', 'now'));
    )";
    sqlite3_exec(db_, default_admin, nullptr, nullptr, nullptr);

    return true;
}

// BUG-0027 (impl): SQL injection via string concatenation
bool Database::insert_point(const TimeseriesPoint& point) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    // BUG-0027: Direct string interpolation of device_id and metric_name into SQL
    std::string sql = "INSERT INTO telemetry (timestamp, device_id, metric_name, value, tags, raw_payload) "
                      "VALUES (" + std::to_string(point.timestamp) + ", "
                      "'" + point.device_id + "', "
                      "'" + point.metric_name + "', "
                      + std::to_string(point.value) + ", "
                      "'" + point.tags + "', "
                      "NULL);";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "Insert error: " << err_msg << " | Query: " << sql << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

// BUG-0028 (impl): SQL injection via filter_expr
std::vector<TimeseriesPoint> Database::query(const QueryParams& params) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<TimeseriesPoint> results;

    // BUG-0028: filter_expr injected directly into WHERE clause
    std::string sql = "SELECT timestamp, device_id, metric_name, value, tags FROM telemetry WHERE 1=1";

    if (!params.device_id.empty()) {
        sql += " AND device_id = '" + params.device_id + "'";
    }
    if (!params.metric_name.empty()) {
        sql += " AND metric_name = '" + params.metric_name + "'";
    }
    if (params.start_time > 0) {
        sql += " AND timestamp >= " + std::to_string(params.start_time);
    }
    if (params.end_time > 0) {
        sql += " AND timestamp <= " + std::to_string(params.end_time);
    }
    if (!params.filter_expr.empty()) {
        // Direct injection of user-provided filter expression
        sql += " AND (" + params.filter_expr + ")";
    }
    if (!params.order_by.empty()) {
        sql += " ORDER BY " + params.order_by;
    }
    if (params.limit > 0) {
        sql += " LIMIT " + std::to_string(params.limit);
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Query error: " << sqlite3_errmsg(db_) << std::endl;
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TimeseriesPoint point;
        point.timestamp = sqlite3_column_int64(stmt, 0);

        // BUG-0103: Null check missing on sqlite3_column_text — undefined behavior if column is NULL (CWE-476, CVSS 5.5, MEDIUM, Tier 2)
        point.device_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        point.metric_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        point.value = sqlite3_column_double(stmt, 3);

        const char* tags = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        point.tags = tags ? tags : "";

        point.raw_payload = nullptr;
        point.raw_payload_len = 0;

        results.push_back(point);
        // BUG-0026 (ref): raw_payload copied as null but struct has raw pointer semantics
    }

    sqlite3_finalize(stmt);
    return results;
}

bool Database::delete_old_data(int64_t before_timestamp) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::string sql = "DELETE FROM telemetry WHERE timestamp < " + std::to_string(before_timestamp);
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

int64_t Database::get_row_count(const std::string& table_name) {
    std::string sql = "SELECT COUNT(*) FROM " + table_name;
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

// BUG-0030 (impl): Command injection via dest_path
bool Database::backup_database(const std::string& dest_path) {
    // BUG-0030: Shell command constructed from user-provided dest_path — command injection
    std::string cmd = "cp " + db_path_ + " " + dest_path;
    // BUG-0105: system() call with unsanitized input — RCE via semicolon injection (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        std::cerr << "Backup failed with exit code: " << rc << std::endl;
        return false;
    }

    // Verify backup
    // BUG-0106: TOCTOU — file could be modified between copy and verification (CWE-367, CVSS 4.5, TRICKY, Tier 3)
    if (!std::filesystem::exists(dest_path)) {
        std::cerr << "Backup file not found after copy" << std::endl;
        return false;
    }
    auto src_size = std::filesystem::file_size(db_path_);
    auto dst_size = std::filesystem::file_size(dest_path);
    if (src_size != dst_size) {
        std::cerr << "Backup size mismatch: " << src_size << " vs " << dst_size << std::endl;
        return false;
    }

    return true;
}

// BUG-0031 (impl): Path traversal in export_csv
bool Database::export_csv(const std::string& query_str, const std::string& output_path) {
    // BUG-0031: output_path not sanitized — can write to any location (e.g., ../../etc/cron.d/evil)
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "Cannot open output file: " << output_path << std::endl;
        return false;
    }

    // BUG-0107: query_str is user-provided SQL executed directly — arbitrary SQL execution (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, query_str.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "CSV export query error: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    int cols = sqlite3_column_count(stmt);
    // Write header
    for (int i = 0; i < cols; i++) {
        if (i > 0) out << ",";
        out << sqlite3_column_name(stmt, i);
    }
    out << "\n";

    // Write rows
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        for (int i = 0; i < cols; i++) {
            if (i > 0) out << ",";
            const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            // BUG-0108: CSV injection — cell values not escaped, can contain =cmd() formulas (CWE-1236, CVSS 5.5, MEDIUM, Tier 2)
            out << (val ? val : "");
        }
        out << "\n";
    }

    sqlite3_finalize(stmt);
    out.close();
    return true;
}

} // namespace murrayd::storage
