#include "broker.h"
#include "storage.h"
#include "protocol.h"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <cstring>
#include <functional>
#include <regex>
#include <fstream>
#include <filesystem>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;

namespace murrayd::api {

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket socket, std::shared_ptr<storage::Database> db,
                std::shared_ptr<Broker> broker)
        : socket_(std::move(socket)), db_(db), broker_(broker) {}

    void start() {
        do_read();
    }

private:
    void do_read() {
        auto self = shared_from_this();
        // BUG-0113: No timeout on HTTP read — slow loris attack can hold connection indefinitely (CWE-400, CVSS 7.0, HIGH, Tier 1)
        http::async_read(socket_, buffer_, request_,
            [self](beast::error_code ec, size_t) {
                if (!ec) {
                    self->handle_request();
                }
            });
    }

    void handle_request() {
        auto target = std::string(request_.target());
        auto method = request_.method();

        // BUG-0114: No CORS preflight handling — CORS header set to * in config but OPTIONS not handled (CWE-942, CVSS 5.0, MEDIUM, Tier 2)


        // Route dispatch
        if (target.starts_with("/api/v1/query")) {
            handle_query(target);
        } else if (target.starts_with("/api/v1/devices")) {
            handle_devices(target);
        } else if (target.starts_with("/api/v1/ingest")) {
            handle_ingest();
        } else if (target.starts_with("/api/v1/admin")) {
            handle_admin(target);
        } else if (target.starts_with("/api/v1/export")) {
            handle_export(target);
        } else if (target.starts_with("/api/v1/backup")) {
            handle_backup();
        } else if (target == "/debug" || target == "/api/v1/debug") {
            // BUG-0116: Debug endpoint accessible without authentication — exposes internal state (CWE-489, CVSS 7.0, HIGH, Tier 1)
            handle_debug();
        } else if (target == "/health") {
            send_json_response(200, {{"status", "ok"}, {"version", "1.0.0"}});
        } else {
            send_json_response(404, {{"error", "Not found"}, {"path", target}});
        }
    }

    // BUG-0117: Admin endpoints use token from query string — token visible in logs/history (CWE-598, CVSS 6.5, MEDIUM, Tier 2)
    bool check_admin_auth() {
        auto target = std::string(request_.target());
        auto token_pos = target.find("token=");
        if (token_pos == std::string::npos) {
            // Also check Authorization header
            auto auth = request_[http::field::authorization];
            if (auth.empty()) {
                send_json_response(401, {{"error", "Authentication required"}});
                return false;
            }
            std::string auth_str(auth);
            // BUG-0118: Timing-safe comparison not used — token comparison vulnerable to timing attack (CWE-208, CVSS 5.5, TRICKY, Tier 3)
            if (auth_str != "Bearer " + murrayd::g_config["api"]["admin_token"].get<std::string>()) {
                send_json_response(403, {{"error", "Invalid token"}});
                return false;
            }
            return true;
        }
        std::string provided_token = target.substr(token_pos + 6);
        auto amp = provided_token.find('&');
        if (amp != std::string::npos) provided_token = provided_token.substr(0, amp);

        return provided_token == murrayd::g_config["api"]["admin_token"].get<std::string>();
    }

    void handle_query(const std::string& target) {
        // Parse query parameters from URL
        storage::QueryParams params;
        auto qpos = target.find('?');
        if (qpos != std::string::npos) {
            std::string query_str = target.substr(qpos + 1);
            parse_query_params(query_str, params);
        }

        // Also accept POST body
        if (request_.method() == http::verb::post) {
            try {
                auto body = json::parse(request_.body());
                if (body.contains("device_id")) params.device_id = body["device_id"];
                if (body.contains("metric")) params.metric_name = body["metric"];
                if (body.contains("start")) params.start_time = body["start"];
                if (body.contains("end")) params.end_time = body["end"];
                if (body.contains("limit")) params.limit = body["limit"];
                if (body.contains("order_by")) params.order_by = body["order_by"];
                // BUG-0028 (ref): filter_expr from user body passed directly to SQL query
                if (body.contains("filter")) params.filter_expr = body["filter"];
            } catch (...) {
                send_json_response(400, {{"error", "Invalid JSON body"}});
                return;
            }
        }

        auto results = db_->query(params);
        json response = json::array();
        for (const auto& pt : results) {
            response.push_back({
                {"timestamp", pt.timestamp},
                {"device_id", pt.device_id},
                {"metric", pt.metric_name},
                {"value", pt.value},
                {"tags", pt.tags}
            });
        }

        send_json_response(200, {{"data", response}, {"count", results.size()}});
    }

    void handle_devices(const std::string& target) {
        auto results = db_->query(storage::QueryParams{});
        std::set<std::string> device_ids;
        for (const auto& pt : results) {
            device_ids.insert(pt.device_id);
        }

        json devices = json::array();
        for (const auto& id : device_ids) {
            devices.push_back(id);
        }
        send_json_response(200, {{"devices", devices}});
    }

    void handle_ingest() {
        if (request_.method() != http::verb::post) {
            send_json_response(405, {{"error", "Method not allowed"}});
            return;
        }

        try {
            auto body = json::parse(request_.body());
            std::string topic = body.value("topic", "");
            std::string payload = body.value("payload", "");

            if (topic.empty()) {
                send_json_response(400, {{"error", "Missing topic"}});
                return;
            }

            // BUG-0120: No payload size validation — can ingest arbitrarily large payloads via HTTP (CWE-770, CVSS 6.0, MEDIUM, Tier 2)
            storage::TimeseriesEngine engine(db_);
            if (engine.ingest(topic, payload)) {
                // Also publish to MQTT subscribers
                broker_->publish(topic, payload, 0);
                send_json_response(200, {{"status", "ok"}});
            } else {
                send_json_response(500, {{"error", "Ingest failed"}});
            }
        } catch (const json::parse_error& e) {
            send_json_response(400, {{"error", "Invalid JSON"}, {"detail", e.what()}});
        }
    }

    void handle_admin(const std::string& target) {
        if (!check_admin_auth()) return;

        if (target.find("/admin/stats") != std::string::npos) {
            auto& stats = broker_->stats();
            send_json_response(200, {
                {"active_connections", stats.active_connections.load()},
                {"total_connections", stats.total_connections},
                {"messages_received", stats.messages_received.load()},
                {"messages_sent", stats.messages_sent.load()},
                {"telemetry_rows", db_->get_row_count("telemetry")}
            });
        } else if (target.find("/admin/config") != std::string::npos) {
            // BUG-0121: Returns full config including admin_token and TLS key path (CWE-200, CVSS 8.0, HIGH, Tier 1)
            send_json_response(200, murrayd::g_config);
        } else if (target.find("/admin/sql") != std::string::npos) {
            // BUG-0122: Arbitrary SQL execution endpoint — even authenticated, this is extremely dangerous (CWE-89, CVSS 9.5, CRITICAL, Tier 1)
            if (request_.method() == http::verb::post) {
                auto body = json::parse(request_.body());
                std::string sql = body.value("query", "");
                auto handle = db_->get_db_handle();

                char* err_msg = nullptr;
                json rows = json::array();
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
                    send_json_response(500, {{"error", err_msg}});
                    sqlite3_free(err_msg);
                } else {
                    send_json_response(200, {{"rows", rows}});
                }
            }
        } else {
            send_json_response(404, {{"error", "Unknown admin endpoint"}});
        }
    }

    void handle_export(const std::string& target) {
        if (!check_admin_auth()) return;

        try {
            auto body = json::parse(request_.body());
            std::string query = body.value("query", "SELECT * FROM telemetry LIMIT 1000");
            // BUG-0031 (ref): output_path from user request — path traversal
            std::string output_path = body.value("path", "/tmp/export.csv");

            if (db_->export_csv(query, output_path)) {
                // BUG-0123: Reads exported file and sends it in response — SSRF-like file read (CWE-22, CVSS 7.0, HIGH, Tier 1)
                std::ifstream file(output_path);
                std::string content((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
                send_text_response(200, content, "text/csv");
            } else {
                send_json_response(500, {{"error", "Export failed"}});
            }
        } catch (...) {
            send_json_response(400, {{"error", "Invalid request"}});
        }
    }

    void handle_backup() {
        if (!check_admin_auth()) return;

        try {
            auto body = json::parse(request_.body());
            // BUG-0030 (ref): dest_path from user request — command injection via backup_database
            std::string dest = body.value("destination", "/tmp/backup.db");

            if (db_->backup_database(dest)) {
                send_json_response(200, {{"status", "ok"}, {"path", dest}});
            } else {
                send_json_response(500, {{"error", "Backup failed"}});
            }
        } catch (...) {
            send_json_response(400, {{"error", "Invalid request"}});
        }
    }

    void handle_debug() {
        // BUG-0116 (impl): Debug endpoint leaks environment variables and internal state
        json debug_info;
        debug_info["config"] = murrayd::g_config;
        debug_info["pid"] = getpid();
        debug_info["cwd"] = std::filesystem::current_path().string();

        // BUG-0124: Dumps all environment variables — credential leakage (CWE-200, CVSS 8.5, HIGH, Tier 1)
        json env_vars;
        extern char** environ;
        for (char** env = environ; *env; ++env) {
            std::string entry(*env);
            auto eq = entry.find('=');
            if (eq != std::string::npos) {
                env_vars[entry.substr(0, eq)] = entry.substr(eq + 1);
            }
        }
        debug_info["environment"] = env_vars;

        // Active sessions
        json sessions = json::array();
        for (const auto& [id, session] : broker_->get_sessions()) {
            sessions.push_back({
                {"client_id", id},
                {"connected", session->is_connected()},
                {"address", session->get_remote_address()}
            });
        }
        debug_info["sessions"] = sessions;

        send_json_response(200, debug_info);
    }

    void parse_query_params(const std::string& query_str, storage::QueryParams& params) {
        std::istringstream ss(query_str);
        std::string param;
        while (std::getline(ss, param, '&')) {
            auto eq = param.find('=');
            if (eq == std::string::npos) continue;
            std::string key = param.substr(0, eq);
            std::string value = param.substr(eq + 1);
            if (key == "device_id") params.device_id = value;
            else if (key == "metric") params.metric_name = value;
            else if (key == "start") params.start_time = std::stoll(value);
            else if (key == "end") params.end_time = std::stoll(value);
            else if (key == "limit") params.limit = std::stoul(value);
            else if (key == "order_by") params.order_by = value;
            else if (key == "filter") params.filter_expr = value;
        }
    }

    void send_json_response(unsigned status, const json& body) {
        http::response<http::string_body> response;
        response.result(status);
        response.set(http::field::content_type, "application/json");
        // BUG-0114 (ref): CORS wildcard allows any origin
        response.set(http::field::access_control_allow_origin, "*");
        response.body() = body.dump();
        response.prepare_payload();
        // RH-006: Looks like response might dangle, but shared_from_this() in lambda keeps HttpSession alive
        auto self = shared_from_this();
        http::async_write(socket_, response,
            [self](beast::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "HTTP write error: " << ec.message() << std::endl;
                }
                self->socket_.shutdown(tcp::socket::shutdown_send, ec);
            });
    }

    void send_text_response(unsigned status, const std::string& body, const std::string& content_type) {
        http::response<http::string_body> response;
        response.result(status);
        response.set(http::field::content_type, content_type);
        response.set(http::field::access_control_allow_origin, "*");
        response.body() = body;
        response.prepare_payload();
        auto self = shared_from_this();
        http::async_write(socket_, response,
            [self](beast::error_code ec, size_t) {
                self->socket_.shutdown(tcp::socket::shutdown_send, ec);
            });
    }

    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> request_;
    std::shared_ptr<storage::Database> db_;
    std::shared_ptr<Broker> broker_;
};

// HTTP Server listener
class HttpServer {
public:
    HttpServer(net::io_context& io_ctx, uint16_t port,
               std::shared_ptr<storage::Database> db,
               std::shared_ptr<Broker> broker)
        : acceptor_(io_ctx, tcp::endpoint(tcp::v4(), port)),
          db_(db), broker_(broker) {
        acceptor_.set_option(net::socket_base::reuse_address(true));
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    auto session = std::make_shared<HttpSession>(
                        std::move(socket), db_, broker_);
                    session->start();
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
    std::shared_ptr<storage::Database> db_;
    std::shared_ptr<Broker> broker_;
};

} // namespace murrayd::api
