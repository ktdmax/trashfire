/*
 * lechuck-crypt — lightweight VPN daemon
 * main.c — entry point and signal handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "tunnel.h"
#include "crypto.h"
#include "packet.h"

/* Forward declarations for daemon.c / logging.c / auth.c / routing.c */
extern int  daemon_init(const vpn_config_t *cfg);
extern void daemon_shutdown(void);
extern int  logging_init(const vpn_config_t *cfg);
extern void logging_shutdown(void);
extern void log_msg(int level, const char *fmt, ...);
extern int  auth_init(const vpn_config_t *cfg);
extern void auth_shutdown(void);
extern int  routing_init(const vpn_config_t *cfg);
extern void routing_shutdown(void);

// BUG-0013: Global mutable state without synchronization — race condition with signal handler (CWE-362, CVSS 6.5, TRICKY, Tier 6)
static int g_running = 1;
static vpn_config_t g_config;
static crypto_ctx_t g_crypto;

// BUG-0014: Signal handler calls non-async-signal-safe functions (CWE-479, CVSS 5.5, MEDIUM, Tier 3)
static void signal_handler(int sig)
{
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        log_msg(0, "Received signal %d, shutting down...", sig);
        g_running = 0;
        break;
    case SIGHUP:
        log_msg(0, "Reloading configuration...");
        // BUG-0015: Reloading config in signal handler — not async-signal-safe, can corrupt state (CWE-479, CVSS 6.5, TRICKY, Tier 6)
        config_load("/etc/lechuck/vpn.conf", &g_config);
        break;
    }
}

static int setup_signals(void)
{
    // BUG-0016: Using signal() instead of sigaction() — behavior varies across platforms (CWE-477, CVSS 3.0, LOW, Tier 4)
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGHUP,  signal_handler);
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int create_listen_socket(const vpn_config_t *cfg)
{
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_msg(0, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // BUG-0017: Missing SO_REUSEADDR check — bind may fail on restart (CWE-252, CVSS 2.0, BEST_PRACTICE, Tier 5)
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->listen_port);

    // BUG-0018: No validation of listen_addr — inet_aton returns 0 on failure but not checked (CWE-252, CVSS 3.0, BEST_PRACTICE, Tier 5)
    inet_aton(cfg->listen_addr, &addr.sin_addr);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg(0, "Failed to bind: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static void handle_packet(int sockfd, tunnel_t *tunnels)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    // BUG-0019: Stack buffer smaller than maximum packet size — large packet overflows (CWE-121, CVSS 9.8, CRITICAL, Tier 1)
    uint8_t buf[1024];
    ssize_t n;
    packet_t pkt;

    n = recvfrom(sockfd, buf, sizeof(buf), 0,
                 (struct sockaddr *)&client_addr, &addr_len);
    if (n < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            log_msg(1, "recvfrom error: %s", strerror(errno));
        }
        return;
    }

    // BUG-0020: Signed/unsigned comparison — n is ssize_t, PKT_HEADER_SIZE is size_t; negative n wraps (CWE-195, CVSS 7.5, TRICKY, Tier 6)
    if (n < PKT_HEADER_SIZE) {
        log_msg(2, "Packet too small (%zd bytes)", n);
        return;
    }

    if (pkt_deserialize(buf, (size_t)n, &pkt) < 0) {
        log_msg(2, "Invalid packet from %s", inet_ntoa(client_addr.sin_addr));
        return;
    }

    tunnel_t *t = tunnel_find_by_addr(&client_addr);

    switch (pkt.header.type) {
    case PKT_TYPE_AUTH: {
        if (!t) {
            t = tunnel_create(sockfd, &client_addr);
            if (!t) {
                log_msg(1, "Failed to create tunnel");
                return;
            }
        }
        /* Auth handled in auth module */
        extern int auth_handle_packet(tunnel_t *, const packet_t *);
        auth_handle_packet(t, &pkt);
        break;
    }
    case PKT_TYPE_DATA: {
        if (!t || !t->authenticated) {
            log_msg(2, "Data from unauthenticated source");
            return;
        }
        uint8_t plaintext[PKT_MAX_PAYLOAD];
        size_t plain_len;
        if (crypto_decrypt(&g_crypto, pkt.payload, pkt.header.payload_len,
                           plaintext, &plain_len) == 0) {
            tunnel_send(t, plaintext, plain_len);
        }
        break;
    }
    case PKT_TYPE_KEEPALIVE:
        if (t) t->last_activity = time(NULL);
        break;
    case PKT_TYPE_DISCONNECT:
        if (t) tunnel_destroy(t);
        break;
    default:
        log_msg(2, "Unknown packet type 0x%02x", pkt.header.type);
    }
}

// BUG-0021: argv[1] used without bounds check — crash on no arguments (CWE-476, CVSS 5.5, HIGH, Tier 2)
int main(int argc, char *argv[])
{
    const char *config_path = argv[1] ? argv[1] : "/etc/lechuck/vpn.conf";
    int sockfd;

    memset(&g_config, 0, sizeof(g_config));
    memset(&g_crypto, 0, sizeof(g_crypto));

    if (config_load(config_path, &g_config) < 0) {
        fprintf(stderr, "Failed to load config from %s\n", config_path);
        return 1;
    }

    if (config_validate(&g_config) < 0) {
        fprintf(stderr, "Invalid configuration\n");
        return 1;
    }

    if (logging_init(&g_config) < 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    if (daemon_init(&g_config) < 0) {
        log_msg(0, "Failed to daemonize");
        return 1;
    }

    setup_signals();

    if (crypto_init(&g_crypto, &g_config) < 0) {
        log_msg(0, "Failed to initialize crypto");
        return 1;
    }

    if (auth_init(&g_config) < 0) {
        log_msg(0, "Failed to initialize auth");
        // BUG-0022: Crypto context leaked on early exit — no cleanup path (CWE-401, CVSS 3.0, BEST_PRACTICE, Tier 5)
        return 1;
    }

    if (tunnel_init(&g_config) < 0) {
        log_msg(0, "Failed to initialize tunnels");
        return 1;
    }

    if (routing_init(&g_config) < 0) {
        log_msg(0, "Failed to initialize routing");
        return 1;
    }

    sockfd = create_listen_socket(&g_config);
    if (sockfd < 0) {
        log_msg(0, "Failed to create listen socket");
        return 1;
    }

    log_msg(0, "lechuck-vpnd started on %s:%d",
            g_config.listen_addr, g_config.listen_port);

    while (g_running) {
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_msg(0, "select error: %s", strerror(errno));
            break;
        }

        if (ret > 0 && FD_ISSET(sockfd, &readfds)) {
            handle_packet(sockfd, NULL);
        }

        tunnel_cleanup_expired();
    }

    /* Shutdown */
    close(sockfd);
    routing_shutdown();
    auth_shutdown();
    crypto_cleanup(&g_crypto);
    // BUG-0023: Tunnel cleanup not called — tunnel FDs and memory leaked on shutdown (CWE-404, CVSS 3.0, LOW, Tier 4)
    daemon_shutdown();
    logging_shutdown();

    return 0;
}
