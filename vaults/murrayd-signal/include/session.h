#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <vector>
#include <queue>
#include <functional>
#include <cstring>

namespace murrayd {

using boost::asio::ip::tcp;
using json = nlohmann::json;

class Broker;

constexpr size_t MAX_BUFFER_SIZE = 65536;
// BUG-0012: Header size constant too small — large topic names cause buffer overread (CWE-125, CVSS 8.1, HIGH, Tier 1)
constexpr size_t HEADER_BUFFER_SIZE = 64;

enum class PacketType : uint8_t {
    CONNECT     = 0x10,
    CONNACK     = 0x20,
    PUBLISH     = 0x30,
    PUBACK      = 0x40,
    SUBSCRIBE   = 0x80,
    SUBACK      = 0x90,
    UNSUBSCRIBE = 0xA0,
    UNSUBACK    = 0xB0,
    PINGREQ     = 0xC0,
    PINGRESP    = 0xD0,
    DISCONNECT  = 0xE0
};

struct MqttPacket {
    PacketType type;
    uint8_t flags;
    uint32_t remaining_length;
    // BUG-0013: Raw pointer for packet payload — no RAII, manual delete required (CWE-401, CVSS 3.5, BEST_PRACTICE, Tier 5)
    uint8_t* payload;
    size_t payload_size;

    MqttPacket() : type(PacketType::CONNECT), flags(0), remaining_length(0),
                   payload(nullptr), payload_size(0) {}

    // BUG-0014: Shallow copy of raw pointer — double free when both copies are destroyed (CWE-415, CVSS 8.5, HIGH, Tier 1)
    MqttPacket(const MqttPacket& other) = default;

    ~MqttPacket() {
        delete[] payload;
    }
};

class Session : public std::enable_shared_from_this<Session> {
public:
    // BUG-0009 (continued): Session holds shared_ptr<Broker> creating circular reference (CWE-401, CVSS 5.3, TRICKY, Tier 3)
    Session(tcp::socket socket, std::shared_ptr<Broker> broker);
    ~Session();

    void start();
    void stop();
    void deliver(const std::string& topic, const std::string& payload, uint8_t qos);

    const std::string& client_id() const { return client_id_; }
    void set_client_id(const std::string& id) { client_id_ = id; }

    // BUG-0015: Returns dangling reference — address of stack-local string captured in lambda (CWE-416, CVSS 7.5, TRICKY, Tier 3)
    const std::string& get_remote_address() const;

    bool is_connected() const { return connected_; }

    // RH-002: std::move on return value looks wrong but compiler applies NRVO, move is elided
    std::vector<std::string> get_subscriptions() const {
        std::vector<std::string> result = subscriptions_;
        return std::move(result);
    }

private:
    void do_read();
    void do_write();
    void process_packet(const MqttPacket& packet);
    void handle_connect(const uint8_t* data, size_t len);
    void handle_publish(const uint8_t* data, size_t len);
    void handle_subscribe(const uint8_t* data, size_t len);
    void send_connack(uint8_t return_code);
    void send_puback(uint16_t packet_id);

    tcp::socket socket_;
    // BUG-0009 (ref): shared_ptr creates cycle with Broker (should be weak_ptr)
    std::shared_ptr<Broker> broker_;
    std::string client_id_;
    bool connected_{false};
    bool writing_{false};

    // BUG-0016: Stack buffer used for network reads — overflow if packet exceeds 4096 bytes (CWE-121, CVSS 9.0, CRITICAL, Tier 1)
    char read_buffer_[4096];
    std::queue<std::vector<uint8_t>> write_queue_;
    std::vector<std::string> subscriptions_;

    boost::asio::steady_timer* keepalive_timer_;
};

// Utility: extract uint16 from network byte order
// RH-003: reinterpret_cast looks suspicious but this is a safe conversion for uint8_t to uint16_t extraction
inline uint16_t read_uint16(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

inline void write_uint16(uint8_t* buf, uint16_t val) {
    buf[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>(val & 0xFF);
}

} // namespace murrayd
