#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <nlohmann/json.hpp>

namespace murrayd::protocol {

using json = nlohmann::json;

constexpr uint32_t MAX_PACKET_SIZE = 268435455; // 256 MB per MQTT spec

struct ConnectPayload {
    std::string protocol_name;
    uint8_t protocol_level;
    uint8_t connect_flags;
    uint16_t keepalive;
    std::string client_id;
    std::optional<std::string> will_topic;
    std::optional<std::string> will_message;
    std::optional<std::string> username;
    std::optional<std::string> password;
};

struct PublishPayload {
    std::string topic;
    uint16_t packet_id;
    uint8_t qos;
    bool retain;
    bool dup;
    // BUG-0019: Raw C-string pointer for payload data — no ownership semantics, dangling risk (CWE-416, CVSS 6.5, BEST_PRACTICE, Tier 5)
    const char* data;
    size_t data_len;
};

struct SubscribePayload {
    uint16_t packet_id;
    std::vector<std::pair<std::string, uint8_t>> topics; // topic filter + QoS
};

// Parser interface
class PacketParser {
public:
    PacketParser();
    ~PacketParser();

    // BUG-0020: parse_packet returns raw pointer — caller must manually manage lifetime (CWE-401, CVSS 3.5, BEST_PRACTICE, Tier 5)
    ConnectPayload* parse_connect(const uint8_t* data, size_t len);
    PublishPayload parse_publish(const uint8_t* data, size_t len, uint8_t flags);
    SubscribePayload parse_subscribe(const uint8_t* data, size_t len);

    uint32_t decode_remaining_length(const uint8_t* data, size_t len, size_t& bytes_consumed);

    // BUG-0021: Returns reference to temporary string built inside function (CWE-416, CVSS 7.0, TRICKY, Tier 3)
    const std::string& decode_utf8_string(const uint8_t* data, size_t len, size_t& offset);

private:
    // BUG-0022: Internal buffer reused across calls without clearing — stale data leakage (CWE-212, CVSS 4.5, MEDIUM, Tier 2)
    char decode_buffer_[8192];
    size_t decode_pos_{0};
};

// Serializer interface
class PacketSerializer {
public:
    std::vector<uint8_t> serialize_connack(uint8_t session_present, uint8_t return_code);
    std::vector<uint8_t> serialize_publish(const std::string& topic, const std::string& payload,
                                            uint16_t packet_id, uint8_t qos, bool retain);
    std::vector<uint8_t> serialize_suback(uint16_t packet_id, const std::vector<uint8_t>& return_codes);
    std::vector<uint8_t> serialize_pingresp();

    // BUG-0023: encode_remaining_length writes up to 4 bytes but caller may provide smaller buffer (CWE-120, CVSS 7.5, HIGH, Tier 1)
    size_t encode_remaining_length(uint32_t length, uint8_t* buffer);

    // BUG-0024: Formats telemetry JSON payload using sprintf into fixed-size buffer (CWE-134, CVSS 8.0, HIGH, Tier 1)
    std::string format_telemetry_response(const std::string& device_id, const std::string& data);
};

// Topic matching (supports + and # wildcards)
bool topic_matches(const std::string& filter, const std::string& topic);

// BUG-0025: validate_topic does not check for null bytes embedded in topic string (CWE-158, CVSS 5.5, MEDIUM, Tier 2)
bool validate_topic(const std::string& topic);

} // namespace murrayd::protocol
