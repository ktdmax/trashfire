#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <functional>
#include <atomic>
#include <set>

namespace murrayd {

using boost::asio::ip::tcp;
using json = nlohmann::json;

class Session;
class TopicManager;
class Storage;

// BUG-0004: Global mutable config accessible from all threads without synchronization (CWE-362, CVSS 5.3, MEDIUM, Tier 2)
inline json g_config;

struct BrokerStats {
    std::atomic<uint64_t> messages_received{0};
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint32_t> active_connections{0};
    // BUG-0005: Signed integer used for counter that can overflow in high-throughput scenarios (CWE-190, CVSS 5.3, MEDIUM, Tier 2)
    int32_t total_connections{0};
};

class Broker : public std::enable_shared_from_this<Broker> {
public:
    explicit Broker(boost::asio::io_context& io_ctx, uint16_t port);
    ~Broker();

    void start();
    void stop();

    // BUG-0006: Returns reference to internal map — caller can modify sessions without lock (CWE-362, CVSS 7.5, HIGH, Tier 1)
    std::unordered_map<std::string, std::shared_ptr<Session>>& get_sessions() { return sessions_; }

    void register_session(const std::string& client_id, std::shared_ptr<Session> session);
    void unregister_session(const std::string& client_id);
    void publish(const std::string& topic, const std::string& payload, uint8_t qos);

    TopicManager& topic_manager() { return *topic_manager_; }
    BrokerStats& stats() { return stats_; }

    // RH-001: raw pointer looks dangerous but it's a non-owning reference to io_context which outlives Broker
    boost::asio::io_context* io_context() { return &io_ctx_; }

private:
    void do_accept();
    void handle_accept(std::shared_ptr<Session> session, const boost::system::error_code& ec);

    boost::asio::io_context& io_ctx_;
    tcp::acceptor acceptor_;
    // BUG-0007: No limit on sessions_ map size — unbounded memory growth from connection flooding (CWE-770, CVSS 7.5, HIGH, Tier 1)
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
    std::unique_ptr<TopicManager> topic_manager_;
    BrokerStats stats_;
    std::mutex sessions_mutex_;
    bool running_{false};
};

// BUG-0009: Shared pointer circular reference — Broker holds shared_ptr<Session>, Session holds shared_ptr<Broker> (CWE-401, CVSS 5.3, TRICKY, Tier 3)
// (See session.h where Session stores shared_ptr<Broker> instead of weak_ptr)

struct ClientCredentials {
    std::string username;
    // BUG-0010: Password stored as plaintext string in memory, not securely wiped (CWE-316, CVSS 4.0, LOW, Tier 4)
    std::string password;
    std::string client_id;
    uint32_t permissions;
};

// BUG-0011: authenticate always returns true regardless of credentials when auth_enabled is false (default) (CWE-287, CVSS 9.8, CRITICAL, Tier 1)
inline bool authenticate(const ClientCredentials& creds) {
    if (!g_config.value("broker", json::object()).value("auth_enabled", false)) {
        return true;
    }
    // Even when enabled, compares only username, ignores password entirely
    return creds.username.length() > 0;
}

} // namespace murrayd
