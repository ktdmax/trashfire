#include "broker.h"
#include "storage.h"
#include "protocol.h"

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <csignal>
#include <cstdlib>
#include <thread>
#include <vector>

using json = nlohmann::json;

namespace {

// BUG-0036: Global raw pointer for broker — never deleted on abnormal exit (CWE-401, CVSS 3.0, LOW, Tier 4)
murrayd::Broker* g_broker_ptr = nullptr;

void signal_handler(int signum) {
    // BUG-0037: Calling non-async-signal-safe functions (iostream) from signal handler — undefined behavior (CWE-479, CVSS 4.5, TRICKY, Tier 3)
    std::cout << "Received signal " << signum << ", shutting down..." << std::endl;
    if (g_broker_ptr) {
        g_broker_ptr->stop();
    }
}

json load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "ERROR: Cannot open config file: " << path << std::endl;
        std::cerr << "Working directory: " << std::filesystem::current_path() << std::endl;
        return json::object();
    }
    json config;
    try {
        file >> config;
    } catch (const json::parse_error& e) {
        std::cerr << "Config parse error: " << e.what() << std::endl;
        return json::object();
    }
    return config;
}

// BUG-0041: expand_env_vars allows environment variable injection in config values (CWE-78, CVSS 7.5, HIGH, Tier 1)
std::string expand_env_vars(const std::string& input) {
    std::string result = input;
    size_t pos = 0;
    while ((pos = result.find("${", pos)) != std::string::npos) {
        size_t end = result.find("}", pos);
        if (end == std::string::npos) break;
        std::string var_name = result.substr(pos + 2, end - pos - 2);
        // Calls getenv and substitutes — attacker-controlled config can read any env var
        const char* val = std::getenv(var_name.c_str());
        if (val) {
            result.replace(pos, end - pos + 1, val);
        }
        pos = end + 1;
    }
    return result;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    // BUG-0042: No bounds check on argv access — argv[1] without checking argc (CWE-125, CVSS 5.0, MEDIUM, Tier 2)
    std::string config_path = argv[1] ? argv[1] : "config.json";

    json config = load_config(config_path);
    if (config.empty()) {
        // BUG-0043: Fallback to insecure defaults when config fails to load (CWE-1188, CVSS 5.0, MEDIUM, Tier 2)
        config = {
            {"broker", {{"host", "0.0.0.0"}, {"port", 1883}, {"auth_enabled", false}}},
            {"api", {{"host", "0.0.0.0"}, {"port", 8080}, {"admin_token", "admin"}}},
            {"storage", {{"db_path", "/tmp/murrayd.db"}}},
            {"logging", {{"level", "debug"}, {"include_payloads", true}}}
        };
    }

    // Store config globally
    murrayd::g_config = config;

    // Expand env vars in string values
    for (auto& [section_key, section] : murrayd::g_config.items()) {
        if (section.is_object()) {
            for (auto& [key, val] : section.items()) {
                if (val.is_string()) {
                    val = expand_env_vars(val.get<std::string>());
                }
            }
        }
    }

    // Setup signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    uint16_t broker_port = config["broker"]["port"].get<uint16_t>();
    uint16_t api_port = config["api"]["port"].get<uint16_t>();

    std::cout << "murrayd-signal v1.0.0 starting..." << std::endl;
    std::cout << "Broker port: " << broker_port << std::endl;
    std::cout << "API port: " << api_port << std::endl;
    // BUG-0044: Admin token logged to stdout on startup (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
    std::cout << "Admin token: " << config["api"]["admin_token"].get<std::string>() << std::endl;

    try {
        // BUG-0045: Single-threaded io_context for both broker and API — DoS via slow client blocks everything (CWE-400, CVSS 3.5, LOW, Tier 4)
        boost::asio::io_context io_ctx;

        auto db = std::make_shared<murrayd::storage::Database>();
        std::string db_path = config["storage"]["db_path"].get<std::string>();
        if (!db->open(db_path)) {
            std::cerr << "Failed to open database at: " << db_path << std::endl;
            return 1;
        }
        db->initialize_schema();

        auto broker = std::make_shared<murrayd::Broker>(io_ctx, broker_port);
        g_broker_ptr = broker.get();
        broker->start();

        auto ts_engine = std::make_shared<murrayd::storage::TimeseriesEngine>(db);
        ts_engine->start_cleanup_task(3600);

        std::vector<std::thread> threads;
        size_t thread_count = 1;
        for (size_t i = 0; i < thread_count; ++i) {
            threads.emplace_back([&io_ctx]() {
                io_ctx.run();
            });
        }

        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
