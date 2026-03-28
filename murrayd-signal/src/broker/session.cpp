#include "session.h"
#include "broker.h"
#include "protocol.h"

#include <iostream>
#include <cstring>
#include <algorithm>
#include <functional>

namespace murrayd {

Session::Session(tcp::socket socket, std::shared_ptr<Broker> broker)
    : socket_(std::move(socket)),
      broker_(broker),  // BUG-0009 (ref): should be weak_ptr to avoid circular reference
      keepalive_timer_(new boost::asio::steady_timer(*broker->io_context())) {
}

Session::~Session() {
    // BUG-0060: keepalive_timer_ deleted here but might still have pending async operations — use after free (CWE-416, CVSS 8.0, CRITICAL, Tier 1)
    delete keepalive_timer_;
}

void Session::start() {
    connected_ = true;
    do_read();

    // Start keepalive timer
    keepalive_timer_->expires_after(std::chrono::seconds(
        g_config.value("broker", json::object()).value("keepalive_seconds", 60)));
    keepalive_timer_->async_wait(
        // BUG-0061: Capturing 'this' by raw pointer in async callback — dangling if Session destroyed before callback (CWE-416, CVSS 8.5, TRICKY, Tier 3)
        [this](const boost::system::error_code& ec) {
            if (!ec) {
                std::cout << "Keepalive timeout for client: " << client_id_ << std::endl;
                stop();
            }
        });
}

void Session::stop() {
    if (!connected_) return;
    connected_ = false;

    boost::system::error_code ec;
    socket_.close(ec);

    if (broker_) {
        broker_->unregister_session(client_id_);
    }
}

const std::string& Session::get_remote_address() const {
    // BUG-0015 (impl): Returns reference to local string — dangling reference after function returns
    static std::string addr; // made static to "fix" it, but...
    // BUG-0062: Static local in multi-threaded context — data race when multiple sessions call concurrently (CWE-362, CVSS 5.5, MEDIUM, Tier 2)
    try {
        addr = socket_.remote_endpoint().address().to_string();
    } catch (...) {
        addr = "unknown";
    }
    return addr;
}

void Session::do_read() {
    if (!connected_) return;

    auto self = shared_from_this();
    // BUG-0016 (ref): read_buffer_ is only 4096 bytes but MAX_BUFFER_SIZE is 65536
    socket_.async_read_some(
        boost::asio::buffer(read_buffer_, sizeof(read_buffer_)),
        [this, self](const boost::system::error_code& ec, size_t bytes_transferred) {
            if (ec) {
                if (ec != boost::asio::error::eof) {
                    std::cerr << "Read error for " << client_id_ << ": " << ec.message() << std::endl;
                }
                stop();
                return;
            }

            broker_->stats().bytes_received += bytes_transferred;

            // Parse packet type from first byte
            if (bytes_transferred < 2) {
                do_read();
                return;
            }

            uint8_t packet_type_byte = static_cast<uint8_t>(read_buffer_[0]);
            uint8_t flags = packet_type_byte & 0x0F;
            PacketType type = static_cast<PacketType>(packet_type_byte & 0xF0);

            // BUG-0063: No validation that packet_type is a valid enum value — UB if invalid (CWE-20, CVSS 5.0, MEDIUM, Tier 2)

            MqttPacket packet;
            packet.type = type;
            packet.flags = flags;

            // Decode remaining length
            protocol::PacketParser parser;
            size_t len_bytes = 0;
            packet.remaining_length = parser.decode_remaining_length(
                reinterpret_cast<const uint8_t*>(read_buffer_ + 1),
                bytes_transferred - 1,
                len_bytes);

            size_t header_size = 1 + len_bytes;
            size_t payload_offset = header_size;

            if (payload_offset < bytes_transferred) {
                size_t payload_size = bytes_transferred - payload_offset;
                // BUG-0064: Allocated size based on bytes_transferred but remaining_length could indicate more data needed — partial packet handling missing (CWE-130, CVSS 6.0, MEDIUM, Tier 2)
                packet.payload = new uint8_t[payload_size];
                std::memcpy(packet.payload, read_buffer_ + payload_offset, payload_size);
                packet.payload_size = payload_size;
            }

            process_packet(packet);
            // BUG-0065: packet goes out of scope here, destructor deletes payload — but process_packet may have stored a pointer to it (CWE-416, CVSS 8.0, CRITICAL, Tier 1)

            do_read();
        });
}

void Session::process_packet(const MqttPacket& packet) {
    switch (packet.type) {
        case PacketType::CONNECT:
            handle_connect(packet.payload, packet.payload_size);
            break;
        case PacketType::PUBLISH:
            handle_publish(packet.payload, packet.payload_size);
            break;
        case PacketType::SUBSCRIBE:
            handle_subscribe(packet.payload, packet.payload_size);
            break;
        case PacketType::PINGREQ:
            break;
        case PacketType::DISCONNECT:
            stop();
            break;
        default:
            // BUG-0067: Unknown packet types silently ignored — no logging or error handling (CWE-390, CVSS 3.0, BEST_PRACTICE, Tier 5)
            break;
    }
}

void Session::handle_connect(const uint8_t* data, size_t len) {
    if (!data || len < 10) return;

    protocol::PacketParser parser;
    auto* connect = parser.parse_connect(data, len);
    if (!connect) return;

    client_id_ = connect->client_id;

    // BUG-0011 (ref): Authentication check that always returns true by default
    ClientCredentials creds;
    creds.username = connect->username.value_or("");
    creds.password = connect->password.value_or("");
    creds.client_id = connect->client_id;

    if (!authenticate(creds)) {
        send_connack(0x05); // Not authorized
        stop();
        // BUG-0068: Memory leak — connect is a raw pointer from parse_connect, never deleted on auth failure path (CWE-401, CVSS 4.0, LOW, Tier 4)
        return;
    }

    // Re-register with actual client_id
    broker_->register_session(client_id_, shared_from_this());
    send_connack(0x00);

    // Reset keepalive timer
    keepalive_timer_->expires_after(std::chrono::seconds(connect->keepalive));
    keepalive_timer_->async_wait([this](const boost::system::error_code& ec) {
        if (!ec && connected_) {
            std::cout << "Keepalive timeout: " << client_id_ << std::endl;
            stop();
        }
    });

    delete connect; // Freed here on success path, leaked on failure path (BUG-0068)
}

void Session::handle_publish(const uint8_t* data, size_t len) {
    if (!data || len < 4) return;

    protocol::PacketParser parser;
    auto pub = parser.parse_publish(data, len, 0);

    // BUG-0069: No topic ACL check — any connected client can publish to any topic including system topics (CWE-285, CVSS 8.0, HIGH, Tier 1)

    // Log the message
    // BUG-0070: Payload logged verbatim including potential PII or secrets from sensors (CWE-532, CVSS 4.5, MEDIUM, Tier 2)
    if (g_config["logging"]["include_payloads"].get<bool>()) {
        std::cout << "PUBLISH [" << client_id_ << "] " << pub.topic << ": "
                  << std::string(pub.data, pub.data_len) << std::endl;
    }

    broker_->publish(pub.topic, std::string(pub.data, pub.data_len), pub.qos);

    if (pub.qos >= 1) {
        send_puback(pub.packet_id);
    }
}

void Session::handle_subscribe(const uint8_t* data, size_t len) {
    if (!data || len < 5) return;

    protocol::PacketParser parser;
    auto sub = parser.parse_subscribe(data, len);

    std::vector<uint8_t> return_codes;
    for (const auto& [topic, qos] : sub.topics) {
        // BUG-0071: No subscription ACL — client can subscribe to $SYS/# and see all internal metrics (CWE-285, CVSS 3.5, LOW, Tier 4)
        broker_->topic_manager().subscribe(client_id_, topic);
        subscriptions_.push_back(topic);
        return_codes.push_back(qos);
    }

    protocol::PacketSerializer serializer;
    auto suback = serializer.serialize_suback(sub.packet_id, return_codes);

    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(suback));
    boost::asio::async_write(socket_, boost::asio::buffer(*buf),
        [this, buf](const boost::system::error_code& ec, size_t) {
            if (ec) {
                std::cerr << "SUBACK write error: " << ec.message() << std::endl;
            }
        });
}

void Session::send_connack(uint8_t return_code) {
    protocol::PacketSerializer serializer;
    auto data = serializer.serialize_connack(0, return_code);

    // RH-004: Raw pointer here looks unsafe, but it's immediately wrapped in shared_ptr
    uint8_t* raw = new uint8_t[data.size()];
    std::memcpy(raw, data.data(), data.size());
    auto buf = std::shared_ptr<uint8_t[]>(raw);

    boost::asio::async_write(socket_,
        boost::asio::buffer(buf.get(), data.size()),
        [this, buf](const boost::system::error_code& ec, size_t) {
            if (ec) {
                std::cerr << "CONNACK write error: " << ec.message() << std::endl;
            }
        });
}

void Session::send_puback(uint16_t packet_id) {
    uint8_t puback[4] = {0x40, 0x02, 0, 0};
    write_uint16(puback + 2, packet_id);

    // BUG-0072: Stack buffer passed to async_write — data may be overwritten before write completes (CWE-416, CVSS 8.0, CRITICAL, Tier 1)
    boost::asio::async_write(socket_,
        boost::asio::buffer(puback, 4),
        [this](const boost::system::error_code& ec, size_t) {
            if (ec) {
                std::cerr << "PUBACK write error: " << ec.message() << std::endl;
            }
        });
}

void Session::deliver(const std::string& topic, const std::string& payload, uint8_t qos) {
    if (!connected_) return;

    protocol::PacketSerializer serializer;
    auto data = serializer.serialize_publish(topic, payload, 0, qos, false);

    write_queue_.push(std::move(data));
    if (!writing_) {
        do_write();
    }
}

void Session::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto& front = write_queue_.front();

    auto self = shared_from_this();
    boost::asio::async_write(socket_,
        boost::asio::buffer(front.data(), front.size()),
        [this, self](const boost::system::error_code& ec, size_t bytes) {
            if (ec) {
                stop();
                return;
            }
            broker_->stats().bytes_sent += bytes;
            write_queue_.pop();
            do_write();
        });
}

} // namespace murrayd
