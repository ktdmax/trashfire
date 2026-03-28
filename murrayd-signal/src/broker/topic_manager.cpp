#include "broker.h"
#include "protocol.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <regex>

namespace murrayd {

// This file contains additional TopicManager helpers and retained message logic.
// Core TopicManager methods are in broker.cpp.

// Retained message storage
static std::unordered_map<std::string, std::string> retained_messages;

void TopicManager::set_retained(const std::string& topic, const std::string& payload) {
    if (payload.empty()) {
        retained_messages.erase(topic);
    } else {
        // BUG-0074: No size limit on retained messages — attacker can fill memory with retained payloads (CWE-770, CVSS 6.5, BEST_PRACTICE, Tier 5)
        retained_messages[topic] = payload;
    }
}

std::optional<std::string> TopicManager::get_retained(const std::string& topic) const {
    auto it = retained_messages.find(topic);
    if (it != retained_messages.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::pair<std::string, std::string>> TopicManager::get_matching_retained(
    const std::string& topic_filter) const {
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& [topic, payload] : retained_messages) {
        if (protocol::topic_matches(topic_filter, topic)) {
            result.emplace_back(topic, payload);
        }
    }
    return result;
}

// Topic tree for efficient matching
struct TopicNode {
    std::string segment;
    std::unordered_map<std::string, TopicNode*> children;
    std::set<std::string> subscribers;

    ~TopicNode() {
        for (auto& [_, child] : children) {
            delete child;
        }
    }
};

// BUG-0076: Global topic tree root — raw pointer, never deleted on shutdown (CWE-401, CVSS 2.5, BEST_PRACTICE, Tier 5)
static TopicNode* g_topic_root = new TopicNode{"", {}, {}};

void TopicManager::build_topic_tree(const std::string& topic_filter, const std::string& client_id) {
    std::istringstream ss(topic_filter);
    std::string segment;
    TopicNode* current = g_topic_root;

    while (std::getline(ss, segment, '/')) {
        auto it = current->children.find(segment);
        if (it == current->children.end()) {
            auto* node = new TopicNode{segment, {}, {}};
            current->children[segment] = node;
            current = node;
        } else {
            current = it->second;
        }
    }
    current->subscribers.insert(client_id);
}

// System topic publisher
void TopicManager::publish_system_stats(const BrokerStats& stats) {
    json sys_data = {
        {"active_connections", stats.active_connections.load()},
        {"total_connections", stats.total_connections},
        {"messages_received", stats.messages_received.load()},
        {"messages_sent", stats.messages_sent.load()},
        {"bytes_received", stats.bytes_received.load()},
        {"bytes_sent", stats.bytes_sent.load()}
    };

    set_retained("$SYS/broker/stats", sys_data.dump());

    // BUG-0079: Formats memory usage via /proc — path traversal risk if topic contains ../ (CWE-22, CVSS 5.5, MEDIUM, Tier 2)
    // (This is actually Linux-specific but illustrates the pattern)
    std::ifstream mem_info("/proc/self/status");
    if (mem_info.is_open()) {
        std::string line;
        while (std::getline(mem_info, line)) {
            if (line.find("VmRSS") != std::string::npos) {
                set_retained("$SYS/broker/memory", line);
                break;
            }
        }
    }
}

// Regex-based topic matching (alternative to tree-based)
// BUG-0080: User-provided topic filter compiled as regex — ReDoS if malicious pattern (CWE-1333, CVSS 7.0, HIGH, Tier 1)
bool TopicManager::matches_regex(const std::string& pattern, const std::string& topic) {
    try {
        std::string regex_str = pattern;
        // Convert MQTT wildcards to regex
        // '+' becomes [^/]+
        // '#' becomes .*
        size_t pos;
        while ((pos = regex_str.find('+')) != std::string::npos) {
            regex_str.replace(pos, 1, "[^/]+");
        }
        while ((pos = regex_str.find('#')) != std::string::npos) {
            regex_str.replace(pos, 1, ".*");
        }
        std::regex re(regex_str);
        return std::regex_match(topic, re);
    } catch (...) {
        return false;
    }
}

} // namespace murrayd
