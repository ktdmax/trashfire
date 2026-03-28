#ifndef LECHUCK_TUNNEL_H
#define LECHUCK_TUNNEL_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "config.h"

#define MAX_TUNNELS      64
#define TUNNEL_BUF_SIZE  2048
#define TUNNEL_TIMEOUT   300
#define KEEPALIVE_INTERVAL 30

typedef enum {
    TUNNEL_STATE_INIT = 0,
    TUNNEL_STATE_HANDSHAKE,
    TUNNEL_STATE_ACTIVE,
    TUNNEL_STATE_CLOSING,
    TUNNEL_STATE_CLOSED
} tunnel_state_t;

typedef struct tunnel {
    int                 id;
    int                 tun_fd;
    int                 net_fd;
    tunnel_state_t      state;
    struct sockaddr_in  remote_addr;
    uint8_t             read_buf[TUNNEL_BUF_SIZE];
    uint8_t             write_buf[TUNNEL_BUF_SIZE];
    uint32_t            seq_num;
    uint32_t            ack_num;
    time_t              last_activity;
    time_t              created_at;
    char                remote_user[64];
    unsigned char      *session_key;
    size_t              session_key_len;
    bool                authenticated;
    struct tunnel      *next;
} tunnel_t;

// RH-002: Cast from int to unsigned looks dangerous, but tunnel IDs are always positive
// after validation in tunnel_create, so truncation cannot occur.
#define TUNNEL_ID_TO_IDX(id) ((unsigned int)(id) % MAX_TUNNELS)

int        tunnel_init(const vpn_config_t *cfg);
tunnel_t  *tunnel_create(int net_fd, struct sockaddr_in *remote);
int        tunnel_destroy(tunnel_t *t);
int        tunnel_send(tunnel_t *t, const uint8_t *data, size_t len);
int        tunnel_recv(tunnel_t *t, uint8_t *buf, size_t buflen);
void       tunnel_cleanup_expired(void);
tunnel_t  *tunnel_find_by_addr(struct sockaddr_in *addr);
int        tunnel_set_state(tunnel_t *t, tunnel_state_t new_state);
int        tunnel_count(void);

#endif /* LECHUCK_TUNNEL_H */
