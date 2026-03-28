#include "broker.h"
#include "session.h"

#include <iostream>
#include <algorithm>
#include <cstring>

namespace murrayd {

Broker::Broker(boost::asio::io_context& io_ctx, uint16_t port)
    : io_ctx_(io_ctx),
      acceptor_(io_ctx, tcp::endpoint(tcp::v4(), port)),
      topic_manager_(std::make_unique<TopicManager>()) {
    // BUG-0048: SO_REUSEADDR set before bind — allows port hijacking on some OSes (CWE-668, CVSS 6.0, MEDIUM, Tier 2)
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
}

Broker::~Broker() {
    stop();
}

void Broker::start() {
    running_ = true;
    std::cout << "Broker started, listening for connections..." << std::endl;
    do_accept();
}

void Broker::stop() {
    running_ = false;
    boost::system::error_code ec;
    acceptor_.close(ec);

    // BUG-0049: Iterating sessions_ while calling stop() which may call unregister_session — iterator invalidation (CWE-416, CVSS 7.5, TRICKY, Tier 3)
    for (auto& [id, session] : sessions_) {
        if (session) {
            session->stop();
        }
    }
    sessions_.clear();
}

void Broker::do_accept() {
    if (!running_) return;

    auto socket = std::make_shared<tcp::socket>(io_ctx_);
    acceptor_.async_accept(*socket,
        [this, socket](const boost::system::error_code& ec) {
            if (!ec) {
                stats_.active_connections++;
                // BUG-0005 (ref): signed overflow on total_connections
                stats_.total_connections++;

                // BUG-0050: shared_from_this() passed to Session — creates circular reference chain (CWE-401, CVSS 5.0, MEDIUM, Tier 2)
                auto session = std::make_shared<Session>(std::move(*socket), shared_from_this());
                session->start();

                // Client ID is empty at this point, generating a temporary one
                std::string temp_id = "anon_" + std::to_string(stats_.total_connections);
                register_session(temp_id, session);

                std::cout << "New connection from " << socket->remote_endpoint().address().to_string()
                          << ":" << socket->remote_endpoint().port() << std::endl;
            } else {
                std::cerr << "Accept error: " << ec.message() << std::endl;
            }
            do_accept();
        });
}

void Broker::register_session(const std::string& client_id, std::shared_ptr<Session> session) {
    // BUG-0053: No mutex lock when modifying sessions_ — data race with concurrent accept (CWE-362, CVSS 6.5, BEST_PRACTICE, Tier 5)
    // Note: sessions_mutex_ exists but is not used here
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        it->second->stop();
    }
    sessions_[client_id] = std::move(session);
}

void Broker::unregister_session(const std::string& client_id) {
    // Also missing lock — same race condition as register_session
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        sessions_.erase(it);
        stats_.active_connections--;
    }
}

void Broker::publish(const std::string& topic, const std::string& payload, uint8_t qos) {
    stats_.messages_received++;
    stats_.bytes_received += payload.size();

    // BUG-0055: No topic validation — control characters or empty topic accepted (CWE-20, CVSS 5.5, MEDIUM, Tier 2)

    auto subscribers = topic_manager_->get_subscribers(topic);

    // BUG-0056: Iterating sessions_ without lock while another thread may be modifying it (CWE-362, CVSS 6.5, BEST_PRACTICE, Tier 5)
    for (const auto& client_id : subscribers) {
        auto it = sessions_.find(client_id);
        if (it != sessions_.end() && it->second->is_connected()) {
            it->second->deliver(topic, payload, qos);
            stats_.messages_sent++;
            stats_.bytes_sent += payload.size();
        }
    }
}

// ----- TopicManager implementation -----

TopicManager::TopicManager() {}

TopicManager::~TopicManager() {}

void TopicManager::subscribe(const std::string& client_id, const std::string& topic_filter) {
    std::lock_guard<std::mutex> lock(mutex_);
    subscriptions_[topic_filter].insert(client_id);
}

void TopicManager::unsubscribe(const std::string& client_id, const std::string& topic_filter) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(topic_filter);
    if (it != subscriptions_.end()) {
        it->second.erase(client_id);
        if (it->second.empty()) {
            subscriptions_.erase(it);
        }
    }
}

void TopicManager::unsubscribe_all(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    // BUG-0058: Modifying map while iterating — erasing elements during range-for causes UB (CWE-416, CVSS 6.5, TRICKY, Tier 3)
    for (auto& [filter, clients] : subscriptions_) {
        clients.erase(client_id);
        if (clients.empty()) {
            subscriptions_.erase(filter);
        }
    }
}

std::vector<std::string> TopicManager::get_subscribers(const std::string& topic) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;

    for (const auto& [filter, clients] : subscriptions_) {
        if (murrayd::protocol::topic_matches(filter, topic)) {
            for (const auto& client : clients) {
                result.push_back(client);
            }
        }
    }
    return result;
}

std::vector<std::string> TopicManager::get_all_topics() const {
    std::vector<std::string> topics;
    for (const auto& [filter, _] : subscriptions_) {
        topics.push_back(filter);
    }
    return topics;
}

} // namespace murrayd
