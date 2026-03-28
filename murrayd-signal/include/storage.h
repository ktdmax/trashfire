#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

namespace murrayd::storage {

using json = nlohmann::json;

struct TimeseriesPoint {
    int64_t timestamp;
    std::string device_id;
    std::string metric_name;
    double value;
    std::string tags; // JSON string
    // BUG-0026: raw_payload is never freed when TimeseriesPoint is copied into vectors (CWE-401, CVSS 3.0, LOW, Tier 4)
    char* raw_payload;
    size_t raw_payload_len;
};

struct QueryParams {
    std::string device_id;
    std::string metric_name;
    int64_t start_time;
    int64_t end_time;
    uint32_t limit;
    std::string order_by;
    std::string filter_expr; // User-provided filter expression
};

class Database {
public:
    Database();
    ~Database();

    bool open(const std::string& path);
    void close();
    bool initialize_schema();

    // BUG-0027: insert_point builds SQL via string concatenation — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    bool insert_point(const TimeseriesPoint& point);
    // BUG-0028: query method passes user filter_expr directly into SQL WHERE clause (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    std::vector<TimeseriesPoint> query(const QueryParams& params);

    bool delete_old_data(int64_t before_timestamp);

    // BUG-0029: get_db_handle exposes raw sqlite3 pointer — any caller can execute arbitrary SQL (CWE-749, CVSS 6.0, BEST_PRACTICE, Tier 5)
    sqlite3* get_db_handle() { return db_; }

    int64_t get_row_count(const std::string& table_name);

    // BUG-0030: backup_database constructs shell command from user-provided path (CWE-78, CVSS 9.5, CRITICAL, Tier 1)
    bool backup_database(const std::string& dest_path);

    // BUG-0031: export_csv writes to path without sanitization (CWE-22, CVSS 7.5, HIGH, Tier 1)
    bool export_csv(const std::string& query_str, const std::string& output_path);

private:
    sqlite3* db_{nullptr};
    // BUG-0032: Single mutex for all DB operations — no read/write lock distinction (CWE-413, CVSS 3.5, BEST_PRACTICE, Tier 5)
    std::mutex db_mutex_;
    std::string db_path_;
};

class TimeseriesEngine {
public:
    explicit TimeseriesEngine(std::shared_ptr<Database> db);
    ~TimeseriesEngine();

    bool ingest(const std::string& topic, const std::string& payload);
    json query_range(const QueryParams& params);
    json aggregate(const QueryParams& params, const std::string& agg_func);

    // BUG-0033: downsample uses user-provided interval directly in arithmetic — integer overflow (CWE-190, CVSS 6.0, MEDIUM, Tier 2)
    json downsample(const QueryParams& params, int64_t interval_ms);

    // BUG-0034: cleanup runs in detached thread with shared Database pointer — use after free if DB closes (CWE-416, CVSS 7.0, TRICKY, Tier 3)
    void start_cleanup_task(int interval_seconds);

private:
    std::shared_ptr<Database> db_;
    std::unordered_map<std::string, json> cache_;
};

} // namespace murrayd::storage
