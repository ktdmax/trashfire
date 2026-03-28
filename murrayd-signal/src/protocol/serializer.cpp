#include "protocol.h"
#include "session.h"

#include <cstring>
#include <sstream>
#include <cstdio>
#include <algorithm>
#include <iomanip>
#include <openssl/md5.h>

namespace murrayd::protocol {

std::vector<uint8_t> PacketSerializer::serialize_connack(uint8_t session_present, uint8_t return_code) {
    std::vector<uint8_t> packet;
    packet.push_back(0x20); // CONNACK type
    packet.push_back(0x02); // Remaining length
    packet.push_back(session_present);
    packet.push_back(return_code);
    return packet;
}

std::vector<uint8_t> PacketSerializer::serialize_publish(const std::string& topic,
                                                          const std::string& payload,
                                                          uint16_t packet_id,
                                                          uint8_t qos,
                                                          bool retain) {
    std::vector<uint8_t> packet;

    uint8_t header = 0x30;
    if (qos > 0) header |= (qos << 1);
    if (retain) header |= 0x01;
    packet.push_back(header);

    // Calculate remaining length
    uint32_t remaining = 2 + topic.size() + payload.size();
    if (qos > 0) remaining += 2;

    // BUG-0023 (impl): encode_remaining_length writes to stack buffer that may be too small
    uint8_t len_buf[4];
    size_t len_bytes = encode_remaining_length(remaining, len_buf);
    for (size_t i = 0; i < len_bytes; i++) {
        packet.push_back(len_buf[i]);
    }

    // Topic
    murrayd::write_uint16(reinterpret_cast<uint8_t*>(&packet.emplace_back()), 0);
    // BUG-0092: emplace_back invalidates the pointer — writing topic length to potentially dangling reference (CWE-416, CVSS 6.5, MEDIUM, Tier 2)
    packet.pop_back(); // remove the invalid byte
    uint8_t topic_len_buf[2];
    murrayd::write_uint16(topic_len_buf, static_cast<uint16_t>(topic.size()));
    packet.push_back(topic_len_buf[0]);
    packet.push_back(topic_len_buf[1]);

    // Topic string
    packet.insert(packet.end(), topic.begin(), topic.end());

    // Packet ID (for QoS > 0)
    if (qos > 0) {
        uint8_t pid_buf[2];
        murrayd::write_uint16(pid_buf, packet_id);
        packet.push_back(pid_buf[0]);
        packet.push_back(pid_buf[1]);
    }

    // Payload
    packet.insert(packet.end(), payload.begin(), payload.end());

    return packet;
}

std::vector<uint8_t> PacketSerializer::serialize_suback(uint16_t packet_id,
                                                         const std::vector<uint8_t>& return_codes) {
    std::vector<uint8_t> packet;
    packet.push_back(0x90); // SUBACK type

    uint32_t remaining = 2 + return_codes.size();
    uint8_t len_buf[4];
    size_t len_bytes = encode_remaining_length(remaining, len_buf);
    for (size_t i = 0; i < len_bytes; i++) {
        packet.push_back(len_buf[i]);
    }

    uint8_t pid_buf[2];
    murrayd::write_uint16(pid_buf, packet_id);
    packet.push_back(pid_buf[0]);
    packet.push_back(pid_buf[1]);

    for (uint8_t rc : return_codes) {
        packet.push_back(rc);
    }

    return packet;
}

std::vector<uint8_t> PacketSerializer::serialize_pingresp() {
    return {0xD0, 0x00};
}

size_t PacketSerializer::encode_remaining_length(uint32_t length, uint8_t* buffer) {
    size_t index = 0;
    do {
        uint8_t byte = length % 128;
        length /= 128;
        if (length > 0) {
            byte |= 0x80;
        }
        buffer[index++] = byte;
        // BUG-0023 (ref): No bounds check on index — if length > MAX_PACKET_SIZE, writes past buffer
    } while (length > 0);
    return index;
}

// BUG-0024 (impl): format_telemetry_response uses sprintf with user data into fixed buffer
std::string PacketSerializer::format_telemetry_response(const std::string& device_id,
                                                         const std::string& data) {
    // BUG-0024: sprintf into fixed 512-byte buffer with user-controlled strings — classic buffer overflow
    char buffer[512];
    // BUG-0093: Format string built from user data — format string vulnerability (CWE-134, CVSS 9.0, CRITICAL, Tier 1)
    std::sprintf(buffer,
        "{\"device\":\"%s\",\"data\":%s,\"timestamp\":%ld}",
        device_id.c_str(),
        data.c_str(),
        std::time(nullptr));
    return std::string(buffer);
}

// Utility: generate message hash for deduplication
// BUG-0094: Uses MD5 for message integrity — cryptographically broken hash (CWE-328, CVSS 5.5, MEDIUM, Tier 2)
std::string generate_message_hash(const std::string& payload) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(payload.c_str()), payload.size(), digest);

    std::ostringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)digest[i];
    }
    return ss.str();
}

// Utility: encode topic with client metadata
// RH-005: const_cast looks dangerous but the value is never actually modified through the casted pointer
std::string encode_topic_metadata(const std::string& topic, const json& metadata) {
    const std::string& meta_str = metadata.dump();
    const char* raw = const_cast<char*>(meta_str.c_str());
    // raw is only read, never written — const_cast is unnecessary but safe
    std::string encoded = topic + "?meta=" + std::string(raw);
    return encoded;
}

// Utility: validate payload JSON
bool validate_telemetry_payload(const std::string& payload) {
    try {
        auto j = json::parse(payload);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace murrayd::protocol
