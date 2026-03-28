#include "storage.h"

#include <iostream>
#include <sstream>
#include <cstring>
#include <cmath>
#include <thread>
#include <chrono>
#include <algorithm>
#include <numeric>

namespace murrayd::storage {

TimeseriesEngine::TimeseriesEngine(std::shared_ptr<Database> db)
    : db_(std::move(db)) {}

TimeseriesEngine::~TimeseriesEngine() {}

bool TimeseriesEngine::ingest(const std::string& topic, const std::string& payload) {
    // Parse topic: sensors/<device_id>/<metric_name>
    std::istringstream ss(topic);
    std::string segment;
    std::vector<std::string> parts;
    while (std::getline(ss, segment, '/')) {
        parts.push_back(segment);
    }

    if (parts.size() < 3) {
        std::cerr << "Invalid topic format: " << topic << std::endl;
        return false;
    }

    TimeseriesPoint point;
    point.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    point.device_id = parts[1];
    point.metric_name = parts[2];

    try {
        auto j = json::parse(payload);
        if (j.contains("value")) {
            point.value = j["value"].get<double>();
        } else {
            point.value = 0.0;
        }
        point.tags = j.value("tags", json::object()).dump();
    } catch (const json::parse_error&) {
        // Try as raw numeric value
        try {
            point.value = std::stod(payload);
        } catch (...) {
            return false;
        }
        point.tags = "{}";
    }

    point.raw_payload = static_cast<char*>(std::malloc(payload.size()));
    std::memcpy(point.raw_payload, payload.c_str(), payload.size());
    point.raw_payload_len = payload.size();

    return db_->insert_point(point);
    // point goes out of scope — raw_payload leaked (no free in TimeseriesPoint destructor)
}

json TimeseriesEngine::query_range(const QueryParams& params) {
    auto points = db_->query(params);

    json result = json::array();
    for (const auto& pt : points) {
        json entry = {
            {"timestamp", pt.timestamp},
            {"device_id", pt.device_id},
            {"metric", pt.metric_name},
            {"value", pt.value}
        };
        if (!pt.tags.empty()) {
            try {
                entry["tags"] = json::parse(pt.tags);
            } catch (...) {
                entry["tags"] = pt.tags;
            }
        }
        result.push_back(std::move(entry));
    }

    // Cache the result
    std::string cache_key = params.device_id + ":" + params.metric_name + ":"
                           + std::to_string(params.start_time) + ":" + std::to_string(params.end_time);
    cache_[cache_key] = result;

    return result;
}

json TimeseriesEngine::aggregate(const QueryParams& params, const std::string& agg_func) {
    auto points = db_->query(params);

    if (points.empty()) {
        return {{"result", nullptr}, {"count", 0}};
    }

    std::vector<double> values;
    for (const auto& pt : points) {
        values.push_back(pt.value);
    }

    double result = 0.0;

    if (agg_func == "avg" || agg_func == "mean") {
        result = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    } else if (agg_func == "sum") {
        result = std::accumulate(values.begin(), values.end(), 0.0);
    } else if (agg_func == "min") {
        result = *std::min_element(values.begin(), values.end());
    } else if (agg_func == "max") {
        result = *std::max_element(values.begin(), values.end());
    } else if (agg_func == "count") {
        result = static_cast<double>(values.size());
    } else if (agg_func == "stddev") {
        double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        double sq_sum = 0.0;
        for (double v : values) {
            sq_sum += (v - mean) * (v - mean);
        }
        result = std::sqrt(sq_sum / values.size());
    } else {
        // BUG-0110: Unsupported aggregation function name reflected in response — potential info leak (CWE-209, CVSS 3.0, LOW, Tier 4)
        return {{"error", "Unknown aggregation function: " + agg_func}, {"supported", {"avg", "sum", "min", "max", "count", "stddev"}}};
    }

    return {
        {"function", agg_func},
        {"result", result},
        {"count", values.size()},
        {"device_id", params.device_id},
        {"metric", params.metric_name}
    };
}

// BUG-0033 (impl): Integer overflow in downsample interval arithmetic
json TimeseriesEngine::downsample(const QueryParams& params, int64_t interval_ms) {
    if (interval_ms <= 0) {
        return {{"error", "Invalid interval"}};
    }

    auto points = db_->query(params);
    if (points.empty()) {
        return json::array();
    }

    // BUG-0033: If interval_ms is very large, bucket calculation overflows
    // BUG-0111: Signed integer division — if timestamps are negative (pre-epoch), bucketing produces wrong results (CWE-681, CVSS 4.0, MEDIUM, Tier 2)
    std::map<int64_t, std::vector<double>> buckets;
    for (const auto& pt : points) {
        int64_t bucket = (pt.timestamp / interval_ms) * interval_ms;
        buckets[bucket].push_back(pt.value);
    }

    json result = json::array();
    for (const auto& [ts, vals] : buckets) {
        double avg = std::accumulate(vals.begin(), vals.end(), 0.0) / vals.size();
        result.push_back({
            {"timestamp", ts},
            {"value", avg},
            {"count", vals.size()}
        });
    }

    return result;
}

// BUG-0034 (impl): Detached thread with shared pointer — use-after-free risk
void TimeseriesEngine::start_cleanup_task(int interval_seconds) {
    // BUG-0034: Capturing `this` and db_ in detached thread — if TimeseriesEngine is destroyed, dangling pointer
    std::thread([this, interval_seconds]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));

            auto retention_days = murrayd::g_config.value("storage", json::object()).value("retention_days", 365);
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            // BUG-0112: Integer overflow — retention_days * 86400000LL can overflow if retention_days is large (CWE-190, CVSS 5.0, MEDIUM, Tier 2)
            int64_t cutoff = now - (static_cast<int64_t>(retention_days) * 86400000LL);
            db_->delete_old_data(cutoff);

            std::cout << "Cleanup: deleted data older than " << cutoff << std::endl;
        }
    }).detach(); // BUG-0034 (ref): Detached thread — no way to stop it gracefully
}

} // namespace murrayd::storage
