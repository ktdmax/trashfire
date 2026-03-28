#include "protocol.h"
#include "session.h"

#include <iostream>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <climits>

namespace murrayd::protocol {

PacketParser::PacketParser() {
    std::memset(decode_buffer_, 0, sizeof(decode_buffer_));
}

PacketParser::~PacketParser() {}

uint32_t PacketParser::decode_remaining_length(const uint8_t* data, size_t len, size_t& bytes_consumed) {
    uint32_t value = 0;
    uint32_t multiplier = 1;
    bytes_consumed = 0;

    // BUG-0081: No upper bound check on multiplier — can overflow uint32_t with crafted input (CWE-190, CVSS 7.5, HIGH, Tier 1)
    for (size_t i = 0; i < len; i++) {
        bytes_consumed++;
        value += (data[i] & 0x7F) * multiplier;
        multiplier *= 128;

        if ((data[i] & 0x80) == 0) {
            return value;
        }
    }

    return value;
}

ConnectPayload* PacketParser::parse_connect(const uint8_t* data, size_t len) {
    if (!data || len < 10) return nullptr;

    // BUG-0020 (impl): Returns raw pointer — caller must delete
    auto* result = new ConnectPayload();
    size_t offset = 0;

    // Protocol Name
    if (offset + 2 > len) return result; // BUG-0083: Returns partially initialized object without cleaning up (CWE-665, CVSS 4.0, LOW, Tier 4)
    uint16_t proto_name_len = read_uint16(data + offset);
    offset += 2;

    // BUG-0084: No bounds check — proto_name_len could exceed remaining data (CWE-125, CVSS 8.0, CRITICAL, Tier 1)
    result->protocol_name = std::string(reinterpret_cast<const char*>(data + offset), proto_name_len);
    offset += proto_name_len;

    if (offset + 4 > len) return result;

    // Protocol Level
    result->protocol_level = data[offset++];
    // Connect Flags
    result->connect_flags = data[offset++];
    // Keep Alive
    result->keepalive = read_uint16(data + offset);
    offset += 2;

    // Client ID
    if (offset + 2 > len) return result;
    uint16_t client_id_len = read_uint16(data + offset);
    offset += 2;

    // BUG-0085: Heap buffer over-read — client_id_len not validated against remaining data (CWE-126, CVSS 9.0, CRITICAL, Tier 1)
    result->client_id = std::string(reinterpret_cast<const char*>(data + offset), client_id_len);
    offset += client_id_len;

    // Will Topic (if flag set)
    if (result->connect_flags & 0x04) {
        if (offset + 2 > len) return result;
        uint16_t will_topic_len = read_uint16(data + offset);
        offset += 2;
        result->will_topic = std::string(reinterpret_cast<const char*>(data + offset), will_topic_len);
        offset += will_topic_len;

        if (offset + 2 > len) return result;
        uint16_t will_msg_len = read_uint16(data + offset);
        offset += 2;
        result->will_message = std::string(reinterpret_cast<const char*>(data + offset), will_msg_len);
        offset += will_msg_len;
    }

    // Username (if flag set)
    if (result->connect_flags & 0x80) {
        if (offset + 2 > len) return result;
        uint16_t uname_len = read_uint16(data + offset);
        offset += 2;
        result->username = std::string(reinterpret_cast<const char*>(data + offset), uname_len);
        offset += uname_len;
    }

    // Password (if flag set)
    if (result->connect_flags & 0x40) {
        if (offset + 2 > len) return result;
        uint16_t pwd_len = read_uint16(data + offset);
        offset += 2;
        // BUG-0086: Password stored in plaintext string — never zeroed from memory (CWE-316, CVSS 4.5, MEDIUM, Tier 2)
        result->password = std::string(reinterpret_cast<const char*>(data + offset), pwd_len);
        offset += pwd_len;
    }

    return result;
}

PublishPayload PacketParser::parse_publish(const uint8_t* data, size_t len, uint8_t flags) {
    PublishPayload result{};
    size_t offset = 0;

    result.dup = (flags & 0x08) != 0;
    result.qos = (flags >> 1) & 0x03;
    result.retain = (flags & 0x01) != 0;

    if (offset + 2 > len) return result;
    uint16_t topic_len = read_uint16(data + offset);
    offset += 2;

    // BUG-0087: topic_len not validated — reading past buffer end if topic_len > remaining data (CWE-125, CVSS 8.0, CRITICAL, Tier 1)
    result.topic = std::string(reinterpret_cast<const char*>(data + offset), topic_len);
    offset += topic_len;

    if (result.qos > 0) {
        if (offset + 2 > len) return result;
        result.packet_id = read_uint16(data + offset);
        offset += 2;
    }

    // BUG-0019 (impl): Stores raw pointer into data buffer — dangling when data is freed
    result.data = reinterpret_cast<const char*>(data + offset);
    // BUG-0088: Integer underflow if offset > len — wraps to huge value (CWE-191, CVSS 7.0, HIGH, Tier 1)
    result.data_len = len - offset;

    return result;
}

SubscribePayload PacketParser::parse_subscribe(const uint8_t* data, size_t len) {
    SubscribePayload result{};
    size_t offset = 0;

    if (offset + 2 > len) return result;
    result.packet_id = read_uint16(data + offset);
    offset += 2;

    while (offset + 2 < len) {
        uint16_t filter_len = read_uint16(data + offset);
        offset += 2;

        if (offset + filter_len + 1 > len) break;

        std::string filter(reinterpret_cast<const char*>(data + offset), filter_len);
        offset += filter_len;

        uint8_t qos = data[offset++];
        // BUG-0089: QoS value not validated — values > 2 accepted and propagated (CWE-20, CVSS 4.0, LOW, Tier 4)
        result.topics.emplace_back(std::move(filter), qos);
    }

    return result;
}

// BUG-0021 (impl): Returns reference to local string — dangling after function returns
const std::string& PacketParser::decode_utf8_string(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 2 > len) {
        static const std::string empty;
        return empty;
    }
    uint16_t str_len = read_uint16(data + offset);
    offset += 2;

    // This creates a temporary string and returns a reference to it — classic dangling reference
    std::string decoded(reinterpret_cast<const char*>(data + offset), str_len);
    offset += str_len;

    // Store in decode_buffer_ to extend lifetime (still broken — overwritten on next call)
    std::memcpy(decode_buffer_ + decode_pos_, decoded.c_str(), decoded.size() + 1);
    // BUG-0022 (ref): decode_buffer_ reused, decode_pos_ never reset properly
    decode_pos_ += decoded.size() + 1;
    if (decode_pos_ >= sizeof(decode_buffer_) - 256) {
        decode_pos_ = 0; // wrap around, corrupting earlier strings
    }

    // BUG-0090: Returns reference to temporary string `decoded` which is destroyed at end of scope (CWE-416, CVSS 7.5, TRICKY, Tier 3)
    return decoded;
}

// Topic matching implementation
bool topic_matches(const std::string& filter, const std::string& topic) {
    if (filter.empty() || topic.empty()) return false;

    // BUG-0025 (ref): No null byte check in topic
    size_t fi = 0, ti = 0;

    while (fi < filter.size() && ti < topic.size()) {
        if (filter[fi] == '#') {
            return true; // '#' matches everything remaining
        }
        if (filter[fi] == '+') {
            // Skip to next '/' in topic
            while (ti < topic.size() && topic[ti] != '/') {
                ti++;
            }
            fi++;
            continue;
        }
        if (filter[fi] != topic[ti]) {
            return false;
        }
        fi++;
        ti++;
    }

    // Both consumed fully
    if (fi == filter.size() && ti == topic.size()) return true;
    // Filter has trailing '#'
    if (fi < filter.size() && filter[fi] == '#') return true;
    // Filter has trailing '/+'
    if (fi + 1 < filter.size() && filter[fi] == '/' && filter[fi + 1] == '#') return true;

    return false;
}

bool validate_topic(const std::string& topic) {
    if (topic.empty()) return false;
    if (topic.size() > 65535) return false;
    // BUG-0025 (impl): Does not check for embedded null bytes — topic "foo\0bar" passes validation
    return true;
}

} // namespace murrayd::protocol
