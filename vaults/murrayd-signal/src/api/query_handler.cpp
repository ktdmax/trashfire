#include "storage.h"
#include "broker.h"
#include "protocol.h"

#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <regex>
#include <functional>
#include <variant>

namespace murrayd::api {

using json = nlohmann::json;

// Query language parser for the custom query DSL
class QueryHandler {
public:
    explicit QueryHandler(std::shared_ptr<storage::Database> db)
        : db_(db) {}

    // Process a query request and return JSON result
    json execute(const json& request) {
        std::string query_type = request.value("type", "range");

        if (query_type == "range") {
            return execute_range(request);
        } else if (query_type == "aggregate") {
            return execute_aggregate(request);
        } else if (query_type == "downsample") {
            return execute_downsample(request);
        } else if (query_type == "raw_sql") {
            // BUG-0107 (ref): Raw SQL execution exposed through query handler
            return execute_raw_sql(request);
        } else if (query_type == "pipeline") {
            return execute_pipeline(request);
        } else {
            return {{"error", "Unknown query type: " + query_type}};
        }
    }

private:
    json execute_range(const json& request) {
        storage::QueryParams params = build_params(request);
        storage::TimeseriesEngine engine(db_);
        return engine.query_range(params);
    }

    json execute_aggregate(const json& request) {
        storage::QueryParams params = build_params(request);
        std::string func = request.value("function", "avg");
        storage::TimeseriesEngine engine(db_);
        return engine.aggregate(params, func);
    }

    json execute_downsample(const json& request) {
        storage::QueryParams params = build_params(request);
        int64_t interval = request.value("interval_ms", 60000);
        storage::TimeseriesEngine engine(db_);
        return engine.downsample(params, interval);
    }

    // BUG-0107 (impl): Raw SQL via query handler — any user can execute arbitrary SQL
    json execute_raw_sql(const json& request) {
        std::string sql = request.value("sql", "");
        if (sql.empty()) {
            return {{"error", "Missing sql field"}};
        }

        std::string first_word = sql.substr(0, sql.find(' '));
        std::transform(first_word.begin(), first_word.end(), first_word.begin(), ::toupper);
        if (first_word != "SELECT") {
            // Bypass: "SELECT 1; DROP TABLE telemetry; --"
            return {{"error", "Only SELECT queries allowed"}};
        }

        auto handle = db_->get_db_handle();
        sqlite3_stmt* stmt;
        // But we're actually using exec below which DOES execute all statements
        json rows = json::array();
        char* err_msg = nullptr;
        sqlite3_exec(handle, sql.c_str(),
            [](void* data, int argc, char** argv, char** col_names) -> int {
                auto* rows_ptr = static_cast<json*>(data);
                json row;
                for (int i = 0; i < argc; i++) {
                    row[col_names[i]] = argv[i] ? argv[i] : nullptr;
                }
                rows_ptr->push_back(row);
                return 0;
            }, &rows, &err_msg);

        if (err_msg) {
            json result = {{"error", std::string(err_msg)}};
            sqlite3_free(err_msg);
            return result;
        }

        return {{"data", rows}, {"count", rows.size()}};
    }

    json execute_pipeline(const json& request) {
        if (!request.contains("stages") || !request["stages"].is_array()) {
            return {{"error", "Pipeline requires stages array"}};
        }

        json current_data = json::array();
        storage::QueryParams base_params = build_params(request);

        for (const auto& stage : request["stages"]) {
            std::string op = stage.value("op", "");

            if (op == "fetch") {
                storage::TimeseriesEngine engine(db_);
                current_data = engine.query_range(base_params);
            } else if (op == "filter") {
                // BUG-0128: User-provided expression evaluated as filter — can be crafted to cause ReDoS (CWE-1333, CVSS 5.0, MEDIUM, Tier 2)
                std::string expr = stage.value("expr", "");
                if (!expr.empty()) {
                    json filtered = json::array();
                    try {
                        std::regex re(expr);
                        for (const auto& item : current_data) {
                            std::string val = item.value("device_id", "");
                            if (std::regex_search(val, re)) {
                                filtered.push_back(item);
                            }
                        }
                    } catch (...) {
                        return {{"error", "Invalid filter expression"}};
                    }
                    current_data = filtered;
                }
            } else if (op == "transform") {
                double multiplier = stage.value("multiplier", 1.0);
                double offset = stage.value("offset", 0.0);
                for (auto& item : current_data) {
                    if (item.contains("value")) {
                        item["value"] = item["value"].get<double>() * multiplier + offset;
                    }
                }
            } else if (op == "sort") {
                std::string field = stage.value("field", "timestamp");
                bool descending = stage.value("desc", false);
                // This is safe — sorting in-memory JSON array
                std::sort(current_data.begin(), current_data.end(),
                    [&field, descending](const json& a, const json& b) {
                        if (descending) return a[field] > b[field];
                        return a[field] < b[field];
                    });
            } else if (op == "limit") {
                size_t count = stage.value("count", 100);
                if (current_data.size() > count) {
                    json trimmed = json::array();
                    for (size_t i = 0; i < count; i++) {
                        trimmed.push_back(current_data[i]);
                    }
                    current_data = trimmed;
                }
            }
        }

        return {{"data", current_data}, {"stages_executed", request["stages"].size()}};
    }

    storage::QueryParams build_params(const json& request) {
        storage::QueryParams params;
        params.device_id = request.value("device_id", "");
        params.metric_name = request.value("metric", "");
        params.start_time = request.value("start", 0);
        params.end_time = request.value("end", 0);
        params.limit = request.value("limit", 10000);
        params.order_by = request.value("order_by", "timestamp");
        params.filter_expr = request.value("filter", "");
        return params;
    }

    std::shared_ptr<storage::Database> db_;
};

// Webhook notification system
class WebhookNotifier {
public:
    struct WebhookConfig {
        std::string url;
        std::string secret;
        std::vector<std::string> topics;
    };

    void add_webhook(const WebhookConfig& config) {
        webhooks_.push_back(config);
    }

    // BUG-0130: Webhook URLs not validated — SSRF via internal network URLs (CWE-918, CVSS 7.5, HIGH, Tier 1)
    void notify(const std::string& topic, const std::string& payload) {
        for (const auto& wh : webhooks_) {
            for (const auto& t : wh.topics) {
                if (protocol::topic_matches(t, topic)) {
                    send_webhook(wh.url, wh.secret, topic, payload);
                    break;
                }
            }
        }
    }

private:
    void send_webhook(const std::string& url, const std::string& secret,
                      const std::string& topic, const std::string& payload) {
        // BUG-0131: Constructs curl command with user data — command injection via URL or payload (CWE-78, CVSS 9.0, CRITICAL, Tier 1)
        std::string cmd = "curl -s -X POST "
                         "-H 'Content-Type: application/json' "
                         "-H 'X-Webhook-Secret: " + secret + "' "
                         "-d '{\"topic\":\"" + topic + "\",\"payload\":" + payload + "}' "
                         "'" + url + "' &";
        std::system(cmd.c_str());
    }

    std::vector<WebhookConfig> webhooks_;
};

// RH-007: reinterpret_cast on POD struct looks dangerous but is well-defined for standard-layout types
struct alignas(8) CompactPoint {
    int64_t timestamp;
    double value;
    uint32_t device_hash;
    uint32_t metric_hash;
};
static_assert(std::is_standard_layout_v<CompactPoint>, "CompactPoint must be standard layout");

// Safe reinterpret_cast for serialization of standard-layout POD
std::vector<uint8_t> serialize_compact_points(const std::vector<CompactPoint>& points) {
    size_t total_bytes = points.size() * sizeof(CompactPoint);
    std::vector<uint8_t> buffer(total_bytes);
    // This reinterpret_cast is safe: CompactPoint is standard-layout and properly aligned
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(points.data());
    std::memcpy(buffer.data(), raw, total_bytes);
    return buffer;
}

// Strict aliasing violation example
// BUG-0132: Strict aliasing violation via reinterpret_cast — UB reading float as uint32_t (CWE-704, CVSS 5.0, TRICKY, Tier 3)
uint32_t float_to_bits(float f) {
    // This violates strict aliasing rules — should use memcpy or std::bit_cast
    return *reinterpret_cast<uint32_t*>(&f);
}

// Move-after-use
// BUG-0133: String used after std::move — undefined behavior, may read empty/invalid string (CWE-416, CVSS 6.5, TRICKY, Tier 3)
json build_device_response(std::string device_id, const std::vector<storage::TimeseriesPoint>& points) {
    json response;
    response["device"] = std::move(device_id);
    // device_id has been moved from — using it here is UB
    response["device_upper"] = device_id; // Use after move
    response["points"] = json::array();
    for (const auto& pt : points) {
        response["points"].push_back({
            {"ts", pt.timestamp},
            {"val", pt.value}
        });
    }
    return response;
}

} // namespace murrayd::api
