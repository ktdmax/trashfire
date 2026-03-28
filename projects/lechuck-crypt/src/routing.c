/*
 * lechuck-crypt — lightweight VPN daemon
 * routing.c — routing table manipulation, IP forwarding, NAT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "config.h"
#include "tunnel.h"

extern void log_msg(int level, const char *fmt, ...);

#define MAX_ROUTES 64

typedef struct {
    uint32_t network;
    uint32_t netmask;
    uint32_t gateway;
    char     iface[IFNAMSIZ];
    int      metric;
    int      active;
} route_entry_t;

static route_entry_t g_routes[MAX_ROUTES];
static int g_route_count = 0;
static vpn_config_t g_rt_config;

static uint32_t cidr_to_mask(int prefix_len)
{
    if (prefix_len <= 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    return htonl(~((1U << (32 - prefix_len)) - 1));
}

static int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask)
{
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) {
        *mask = 0xFFFFFFFF;
    } else {
        *slash = '\0';
        // BUG (cross-ref BUG-0029 pattern): atoi with no range check on prefix length
        int prefix = atoi(slash + 1);
        *mask = cidr_to_mask(prefix);
    }

    struct in_addr addr;
    if (inet_aton(buf, &addr) == 0) {
        return -1;
    }
    *network = addr.s_addr & *mask;
    return 0;
}

// BUG-0013 cross-ref: enable_ip_forwarding uses system() which is a command injection vector
// but here it's called with a hardcoded string so it's less severe — however system() itself is dangerous
static int enable_ip_forwarding(void)
{
    // BUG (covered by general pattern): system() call — but hardcoded path, low risk here
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) {
        log_msg(0, "Cannot enable IP forwarding: %s", strerror(errno));
        return -1;
    }
    fprintf(fp, "1\n");
    fclose(fp);
    return 0;
}

static int add_iptables_rule(const char *network, const char *iface)
{
    char cmd[512];

    // BUG-0013 cross-ref (separate numbered bug below):
    // BUG (command injection pattern — counted in routing bugs below)
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE",
             network, iface);

    // BUG-0013 actual: system() with partially user-controlled args (network from config)
    // Already numbered as BUG-0013 for the global state issue; see dedicated routing bugs below.

    return system(cmd);
}

int routing_init(const vpn_config_t *cfg)
{
    memset(g_routes, 0, sizeof(g_routes));
    g_route_count = 0;
    memcpy(&g_rt_config, cfg, sizeof(*cfg));

    if (cfg->enable_forwarding) {
        if (enable_ip_forwarding() < 0) {
            log_msg(1, "Warning: could not enable IP forwarding");
        }
    }

    /* Parse allowed networks and add routes */
    for (int i = 0; i < cfg->network_count; i++) {
        uint32_t net, mask;
        if (parse_cidr(cfg->allowed_networks[i], &net, &mask) == 0) {
            if (g_route_count < MAX_ROUTES) {
                g_routes[g_route_count].network = net;
                g_routes[g_route_count].netmask = mask;
                g_routes[g_route_count].active = 1;
                strncpy(g_routes[g_route_count].iface, cfg->tunnel_iface, IFNAMSIZ - 1);
                g_route_count++;
            }
        }
    }

    /* Set up NAT */
    if (cfg->nat_enabled) {
        for (int i = 0; i < cfg->network_count; i++) {
            // BUG-0013 cross-ref: network string from config passed to system() via add_iptables_rule
            add_iptables_rule(cfg->allowed_networks[i], cfg->tunnel_iface);
        }
    }

    return 0;
}

void routing_shutdown(void)
{
    /* Clean up iptables rules */
    char cmd[512];

    for (int i = 0; i < g_rt_config.network_count; i++) {
        // BUG-0013 cross-ref: same command injection pattern on cleanup
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE",
                 g_rt_config.allowed_networks[i], g_rt_config.tunnel_iface);
        system(cmd);
    }

    memset(g_routes, 0, sizeof(g_routes));
    g_route_count = 0;
}

int routing_add_route(uint32_t network, uint32_t mask, uint32_t gateway,
                      const char *iface)
{
    if (g_route_count >= MAX_ROUTES) {
        log_msg(1, "Route table full");
        return -1;
    }

    g_routes[g_route_count].network = network;
    g_routes[g_route_count].netmask = mask;
    g_routes[g_route_count].gateway = gateway;
    strncpy(g_routes[g_route_count].iface, iface, IFNAMSIZ - 1);
    g_routes[g_route_count].metric = 100;
    g_routes[g_route_count].active = 1;
    g_route_count++;

    /* Apply route via system command */
    struct in_addr net_addr, gw_addr;
    net_addr.s_addr = network;
    gw_addr.s_addr = gateway;

    char cmd[256];
    // BUG-0013 counted already. Additional routing command injection vector:
    snprintf(cmd, sizeof(cmd), "ip route add %s/%d via %s dev %s",
             inet_ntoa(net_addr), __builtin_popcount(ntohl(mask)),
             inet_ntoa(gw_addr), iface);

    // BUG (counted with routing/system bugs above — not a new number)
    return system(cmd);
}

int routing_remove_route(uint32_t network, uint32_t mask)
{
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].network == network && g_routes[i].netmask == mask) {
            g_routes[i].active = 0;

            struct in_addr net_addr;
            net_addr.s_addr = network;

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ip route del %s/%d",
                     inet_ntoa(net_addr), __builtin_popcount(ntohl(mask)));
            system(cmd);

            return 0;
        }
    }
    return -1;
}

int routing_check_allowed(uint32_t src_ip, uint32_t dst_ip)
{
    // BUG-0013 cross-ref: no source IP validation — any tunnel client can route anywhere
    (void)src_ip;

    for (int i = 0; i < g_route_count; i++) {
        if (!g_routes[i].active) continue;

        if ((dst_ip & g_routes[i].netmask) == g_routes[i].network) {
            return 0;  /* Allowed */
        }
    }

    // BUG (counted with routing access control): default allow — if no routes match, still returns 0
    // Actually the function returns -1 for no match, which is correct. But let's check...
    return -1;  /* This is actually correct, not a bug */
}

/* Handle route update packets from clients */
int routing_handle_update(tunnel_t *t, const packet_t *pkt)
{
    if (!t || !t->authenticated) return -1;

    /* Parse route update from payload */
    if (pkt->header.payload_len < 8) return -1;

    uint32_t network, mask;
    memcpy(&network, pkt->payload, 4);
    memcpy(&mask, pkt->payload + 4, 4);

    // BUG (access control — counted with auth): any authenticated user can add routes, no admin check
    log_msg(2, "Route update from %s: %s/%d", t->remote_user,
            inet_ntoa(*(struct in_addr *)&network),
            __builtin_popcount(ntohl(mask)));

    return routing_add_route(network, mask, t->remote_addr.sin_addr.s_addr,
                             g_rt_config.tunnel_iface);
}
