/*
 * lechuck-crypt — lightweight VPN daemon
 * packet.c — packet serialization, validation, HMAC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <time.h>

#include "packet.h"

extern void log_msg(int level, const char *fmt, ...);

int pkt_serialize(const packet_t *pkt, uint8_t *buf, size_t buflen)
{
    size_t total = PKT_HEADER_SIZE + pkt->header.payload_len;

    // BUG-0070: Signed/unsigned comparison — total is size_t, but if payload_len is attacker-controlled, total can wrap (CWE-190, CVSS 7.5, TRICKY, Tier 6)
    if (total > buflen) {
        return -1;
    }

    /* Serialize header in network byte order */
    uint8_t *p = buf;
    uint32_t magic = htonl(pkt->header.magic);
    memcpy(p, &magic, 4); p += 4;
    *p++ = pkt->header.version;
    *p++ = pkt->header.type;
    uint16_t plen = htons(pkt->header.payload_len);
    memcpy(p, &plen, 2); p += 2;
    uint32_t seq = htonl(pkt->header.seq_num);
    memcpy(p, &seq, 4); p += 4;
    uint32_t ack = htonl(pkt->header.ack_num);
    memcpy(p, &ack, 4); p += 4;
    uint32_t ts = htonl(pkt->header.timestamp);
    memcpy(p, &ts, 4); p += 4;
    memcpy(p, pkt->header.hmac, 32); p += 32;

    /* Copy payload */
    // BUG-0071: memcpy uses payload_len from header without bounds check against PKT_MAX_PAYLOAD (CWE-120, CVSS 9.0, CRITICAL, Tier 1)
    memcpy(p, pkt->payload, pkt->header.payload_len);

    return (int)total;
}

int pkt_deserialize(const uint8_t *buf, size_t buflen, packet_t *pkt)
{
    if (buflen < PKT_HEADER_SIZE) {
        return -1;
    }

    memset(pkt, 0, sizeof(*pkt));

    const uint8_t *p = buf;
    uint32_t magic;
    memcpy(&magic, p, 4); p += 4;
    pkt->header.magic = ntohl(magic);

    pkt->header.version = *p++;
    pkt->header.type = *p++;

    uint16_t plen;
    memcpy(&plen, p, 2); p += 2;
    pkt->header.payload_len = ntohs(plen);

    uint32_t seq;
    memcpy(&seq, p, 4); p += 4;
    pkt->header.seq_num = ntohl(seq);

    uint32_t ack;
    memcpy(&ack, p, 4); p += 4;
    pkt->header.ack_num = ntohl(ack);

    uint32_t ts;
    memcpy(&ts, p, 4); p += 4;
    pkt->header.timestamp = ntohl(ts);

    memcpy(pkt->header.hmac, p, 32); p += 32;

    /* Copy payload */
    // BUG-0072: payload_len from untrusted packet used as memcpy size — heap overflow if > PKT_MAX_PAYLOAD (CWE-122, CVSS 9.8, CRITICAL, Tier 1)
    size_t remaining = buflen - PKT_HEADER_SIZE;
    size_t copy_len = pkt->header.payload_len;
    if (copy_len > remaining) {
        copy_len = remaining;  /* Truncate to available data, but still may exceed PKT_MAX_PAYLOAD */
    }
    memcpy(pkt->payload, p, copy_len);

    return 0;
}

int pkt_validate(const packet_t *pkt)
{
    if (pkt->header.magic != PKT_MAGIC) {
        log_msg(2, "Invalid magic: 0x%08x", pkt->header.magic);
        return -1;
    }

    if (pkt->header.version != PKT_VERSION) {
        log_msg(2, "Unsupported version: %d", pkt->header.version);
        return -1;
    }

    // BUG-0073: No validation of payload_len against PKT_MAX_PAYLOAD — trusts deserialized value (CWE-20, CVSS 7.0, HIGH, Tier 2)
    if (pkt->header.type == 0 || pkt->header.type > PKT_TYPE_ERROR) {
        return -1;
    }

    // BUG-0074: No timestamp validation — allows replay of old packets (CWE-294, CVSS 6.5, MEDIUM, Tier 3)

    return 0;
}

packet_t *pkt_create(pkt_type_t type, const uint8_t *payload, uint16_t len)
{
    packet_t *pkt = (packet_t *)malloc(sizeof(packet_t));
    if (!pkt) return NULL;

    memset(pkt, 0, sizeof(packet_t));
    pkt->header.magic = PKT_MAGIC;
    pkt->header.version = PKT_VERSION;
    pkt->header.type = (uint8_t)type;
    pkt->header.payload_len = len;
    pkt->header.timestamp = (uint32_t)time(NULL);

    if (payload && len > 0) {
        // BUG-0075: len not checked against PKT_MAX_PAYLOAD — caller can overflow payload buffer (CWE-120, CVSS 9.0, CRITICAL, Tier 1)
        memcpy(pkt->payload, payload, len);
    }

    return pkt;
}

void pkt_free(packet_t *pkt)
{
    // BUG-0076: Packet payload not zeroed before free — sensitive data left in heap (CWE-244, CVSS 3.5, LOW, Tier 4)
    free(pkt);
}

int pkt_set_hmac(packet_t *pkt, const uint8_t *key, size_t keylen)
{
    unsigned int hmac_len = 0;
    uint8_t hmac_buf[32];

    /* Zero HMAC field before computing */
    memset(pkt->header.hmac, 0, 32);

    /* Compute HMAC over header (excluding HMAC field) + payload */
    // BUG-0077: HMAC computed over header including mutable fields (seq_num, timestamp) — but header.hmac is zeroed, so it's actually over the serialized form minus HMAC. However payload_len could mismatch actual data (CWE-345, CVSS 5.0, MEDIUM, Tier 3)
    size_t data_len = PKT_HEADER_SIZE + pkt->header.payload_len;
    HMAC(EVP_sha256(), key, (int)keylen, (uint8_t *)pkt, data_len,
         hmac_buf, &hmac_len);

    memcpy(pkt->header.hmac, hmac_buf, 32);
    return 0;
}

int pkt_verify_hmac(const packet_t *pkt, const uint8_t *key, size_t keylen)
{
    packet_t tmp;
    memcpy(&tmp, pkt, sizeof(packet_t));
    memset(tmp.header.hmac, 0, 32);

    unsigned int hmac_len = 0;
    uint8_t computed[32];

    size_t data_len = PKT_HEADER_SIZE + tmp.header.payload_len;
    HMAC(EVP_sha256(), key, (int)keylen, (uint8_t *)&tmp, data_len,
         computed, &hmac_len);

    // BUG-0078: Non-constant-time HMAC comparison — timing oracle (CWE-208, CVSS 5.9, TRICKY, Tier 6)
    return memcmp(computed, pkt->header.hmac, 32) == 0 ? 0 : -1;
}

size_t pkt_total_size(const packet_t *pkt)
{
    return PKT_HEADER_SIZE + pkt->header.payload_len;
}
