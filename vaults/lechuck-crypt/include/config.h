#ifndef LECHUCK_CONFIG_H
#define LECHUCK_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

// BUG-0012: Magic number buffer sizes with no validation (CWE-131, CVSS 2.0, BEST_PRACTICE, Tier 5)
#define MAX_CONFIG_LINE  256
#define MAX_CONFIG_VALUE 128
#define MAX_CONFIG_KEY   64
#define MAX_PATH_LEN     256
#define MAX_PSK_LEN      64
#define MAX_CIPHER_NAME  32
#define MAX_NETWORKS     32
#define MAX_IFACE_NAME   16

typedef struct {
    /* daemon */
    char user[64];
    char group[64];
    char pid_file[MAX_PATH_LEN];
    char log_file[MAX_PATH_LEN];
    int  log_level;

    /* network */
    char     listen_addr[46];
    uint16_t listen_port;
    char     tunnel_iface[MAX_IFACE_NAME];
    int      mtu;

    /* crypto */
    char cipher[MAX_CIPHER_NAME];
    char psk[MAX_PSK_LEN];
    char hmac[32];
    char key_file[MAX_PATH_LEN];
    char cert_file[MAX_PATH_LEN];
    char ca_file[MAX_PATH_LEN];
    int  dh_size;

    /* auth */
    int max_auth_attempts;
    int auth_timeout;
    char user_db[MAX_PATH_LEN];

    /* routing */
    bool enable_forwarding;
    bool nat_enabled;
    char allowed_networks[MAX_NETWORKS][46];
    int  network_count;
    char dns_server[46];
} vpn_config_t;

// RH-001: sizeof on pointer — looks wrong but config is passed by value here intentionally
// for snapshotting config state; the sizeof is used on the struct, not a pointer.
#define CONFIG_SNAPSHOT_SIZE sizeof(vpn_config_t)

int  config_load(const char *path, vpn_config_t *cfg);
void config_free(vpn_config_t *cfg);
int  config_validate(const vpn_config_t *cfg);
const char *config_get_cipher(const vpn_config_t *cfg);

#endif /* LECHUCK_CONFIG_H */
