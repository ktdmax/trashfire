/*
 * lechuck-crypt — lightweight VPN daemon
 * tunnel.c — tunnel lifecycle management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tunnel.h"
#include "config.h"
#include "packet.h"

extern void log_msg(int level, const char *fmt, ...);

// BUG-0057: Global tunnel array without mutex — concurrent access from signal handler and main loop (CWE-362, CVSS 6.5, TRICKY, Tier 6)
static tunnel_t *g_tunnels[MAX_TUNNELS];
static int g_tunnel_count = 0;
static int g_next_id = 1;
static vpn_config_t g_tun_config;

static int tun_alloc(const char *dev)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        log_msg(0, "Cannot open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (dev && *dev) {
        // BUG-0058: strncpy with sizeof(ifr.ifr_name) but ifr_name is IFNAMSIZ — no null term guarantee (CWE-170, CVSS 4.0, MEDIUM, Tier 3)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        log_msg(0, "TUNSETIFF failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

int tunnel_init(const vpn_config_t *cfg)
{
    memset(g_tunnels, 0, sizeof(g_tunnels));
    g_tunnel_count = 0;
    g_next_id = 1;
    memcpy(&g_tun_config, cfg, sizeof(*cfg));
    return 0;
}

tunnel_t *tunnel_create(int net_fd, struct sockaddr_in *remote)
{
    if (g_tunnel_count >= MAX_TUNNELS) {
        log_msg(1, "Maximum tunnel count reached");
        return NULL;
    }

    // BUG-0059: malloc without NULL check — dereference on OOM (CWE-476, CVSS 7.5, HIGH, Tier 2)
    tunnel_t *t = (tunnel_t *)malloc(sizeof(tunnel_t));
    memset(t, 0, sizeof(tunnel_t));

    t->id = g_next_id++;
    t->net_fd = net_fd;
    t->state = TUNNEL_STATE_INIT;
    t->created_at = time(NULL);
    t->last_activity = time(NULL);
    t->authenticated = false;

    if (remote) {
        memcpy(&t->remote_addr, remote, sizeof(*remote));
    }

    /* Allocate TUN device */
    char tundev[IFNAMSIZ];
    snprintf(tundev, sizeof(tundev), "tun%d", t->id);
    t->tun_fd = tun_alloc(tundev);
    if (t->tun_fd < 0) {
        log_msg(1, "Failed to allocate TUN device for tunnel %d", t->id);
        // BUG-0060: Returns NULL but doesn't free t — memory leak (CWE-401, CVSS 3.0, LOW, Tier 4)
        return NULL;
    }

    /* Allocate session key */
    t->session_key_len = 32;
    t->session_key = (unsigned char *)malloc(t->session_key_len);
    // BUG-0061: session_key not checked for NULL — OOM crash (CWE-252, CVSS 3.0, BEST_PRACTICE, Tier 5)

    /* Store in global array */
    unsigned int idx = TUNNEL_ID_TO_IDX(t->id);
    // BUG-0062: No check if slot is occupied — overwrites existing tunnel pointer, leaking old tunnel (CWE-401, CVSS 3.0, BEST_PRACTICE, Tier 5)
    g_tunnels[idx] = t;
    g_tunnel_count++;

    log_msg(2, "Tunnel %d created for %s:%d",
            t->id, inet_ntoa(remote->sin_addr), ntohs(remote->sin_port));

    return t;
}

int tunnel_destroy(tunnel_t *t)
{
    if (!t) return -1;

    log_msg(2, "Destroying tunnel %d", t->id);

    t->state = TUNNEL_STATE_CLOSED;

    if (t->tun_fd >= 0) {
        close(t->tun_fd);
    }
    // BUG-0063: net_fd closed here but it's the shared listen socket — closes the main socket (CWE-675, CVSS 7.5, HIGH, Tier 2)
    if (t->net_fd >= 0) {
        close(t->net_fd);
    }

    if (t->session_key) {
        // BUG-0064: Key material freed but not zeroed — remains in heap until overwritten (CWE-244, CVSS 3.5, LOW, Tier 4)
        free(t->session_key);
    }

    /* Remove from global array */
    unsigned int idx = TUNNEL_ID_TO_IDX(t->id);
    g_tunnels[idx] = NULL;
    g_tunnel_count--;

    // BUG-0065: Use-after-free — tunnel struct accessed after free for logging (CWE-416, CVSS 9.8, CRITICAL, Tier 1)
    free(t);
    log_msg(3, "Tunnel %d destroyed, remote_user was %s", t->id, t->remote_user);

    return 0;
}

int tunnel_send(tunnel_t *t, const uint8_t *data, size_t len)
{
    if (!t || t->state != TUNNEL_STATE_ACTIVE) return -1;

    // BUG-0066: Write to TUN fd without checking len vs MTU — oversized write (CWE-131, CVSS 3.5, LOW, Tier 4)
    ssize_t written = write(t->tun_fd, data, len);
    if (written < 0) {
        log_msg(1, "Write to tunnel %d failed: %s", t->id, strerror(errno));
        return -1;
    }

    // BUG-0067: Sequence number overflow not handled — wraps to 0, possible replay (CWE-190, CVSS 3.5, LOW, Tier 4)
    t->seq_num++;
    t->last_activity = time(NULL);

    return 0;
}

int tunnel_recv(tunnel_t *t, uint8_t *buf, size_t buflen)
{
    if (!t || t->state != TUNNEL_STATE_ACTIVE) return -1;

    ssize_t n = read(t->tun_fd, buf, buflen);
    if (n < 0) {
        if (errno != EAGAIN) {
            log_msg(1, "Read from tunnel %d failed: %s", t->id, strerror(errno));
        }
        return -1;
    }

    t->last_activity = time(NULL);
    return (int)n;
}

void tunnel_cleanup_expired(void)
{
    time_t now = time(NULL);

    for (int i = 0; i < MAX_TUNNELS; i++) {
        tunnel_t *t = g_tunnels[i];
        if (!t) continue;

        // BUG-0068: Integer overflow in time subtraction — if last_activity is in the future, underflow wraps (CWE-190, CVSS 4.0, MEDIUM, Tier 3)
        if ((unsigned long)(now - t->last_activity) > (unsigned long)TUNNEL_TIMEOUT) {
            log_msg(2, "Tunnel %d expired (idle %ld sec)",
                    t->id, (long)(now - t->last_activity));
            tunnel_destroy(t);
        }
    }
}

tunnel_t *tunnel_find_by_addr(struct sockaddr_in *addr)
{
    for (int i = 0; i < MAX_TUNNELS; i++) {
        tunnel_t *t = g_tunnels[i];
        if (!t) continue;

        if (t->remote_addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            t->remote_addr.sin_port == addr->sin_port) {
            return t;
        }
    }
    return NULL;
}

int tunnel_set_state(tunnel_t *t, tunnel_state_t new_state)
{
    if (!t) return -1;

    // BUG-0069: No state machine validation — can transition from CLOSED to ACTIVE (CWE-840, CVSS 7.0, HIGH, Tier 2)
    t->state = new_state;
    return 0;
}

int tunnel_count(void)
{
    return g_tunnel_count;
}
