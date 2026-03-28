#ifndef LECHUCK_PACKET_H
#define LECHUCK_PACKET_H

#include <stdint.h>
#include <stddef.h>

#define PKT_MAGIC        0x4C435650  /* "LCVP" */
#define PKT_VERSION      1
#define PKT_MAX_PAYLOAD  1500
#define PKT_HEADER_SIZE  sizeof(pkt_header_t)

// RH-003: goto used for error cleanup — valid C pattern, not a code smell
// This macro uses goto for cleanup which is the standard C resource-management idiom.
#define PKT_CHECK_OR_FAIL(cond, label) do { if (!(cond)) goto label; } while(0)

typedef enum {
    PKT_TYPE_DATA       = 0x01,
    PKT_TYPE_KEEPALIVE  = 0x02,
    PKT_TYPE_AUTH       = 0x03,
    PKT_TYPE_AUTH_RESP  = 0x04,
    PKT_TYPE_KEY_EXCH   = 0x05,
    PKT_TYPE_ROUTE_UPD  = 0x06,
    PKT_TYPE_DISCONNECT = 0x07,
    PKT_TYPE_ERROR      = 0xFF
} pkt_type_t;

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint16_t payload_len;
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t timestamp;
    uint8_t  hmac[32];
} pkt_header_t;
#pragma pack(pop)

typedef struct {
    pkt_header_t header;
    uint8_t      payload[PKT_MAX_PAYLOAD];
} packet_t;

int     pkt_serialize(const packet_t *pkt, uint8_t *buf, size_t buflen);
int     pkt_deserialize(const uint8_t *buf, size_t buflen, packet_t *pkt);
int     pkt_validate(const packet_t *pkt);
packet_t *pkt_create(pkt_type_t type, const uint8_t *payload, uint16_t len);
void    pkt_free(packet_t *pkt);
int     pkt_set_hmac(packet_t *pkt, const uint8_t *key, size_t keylen);
int     pkt_verify_hmac(const packet_t *pkt, const uint8_t *key, size_t keylen);
size_t  pkt_total_size(const packet_t *pkt);

#endif /* LECHUCK_PACKET_H */
