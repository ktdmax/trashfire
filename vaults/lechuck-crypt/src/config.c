/*
 * lechuck-crypt — lightweight VPN daemon
 * config.c — configuration file parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include "config.h"

extern void log_msg(int level, const char *fmt, ...);

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

// BUG-0024: TOCTOU race — stat then open; file can be swapped between checks (CWE-367, CVSS 5.9, TRICKY, Tier 6)
static int check_config_permissions(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0) {
        return -1;
    }

    // BUG-0025: Only checks world-readable, not group-readable — group members can read secrets (CWE-732, CVSS 3.5, LOW, Tier 4)
    if (st.st_mode & S_IROTH) {
        log_msg(1, "Warning: config file %s is world-readable", path);
    }

    return 0;
}

static int parse_bool(const char *value)
{
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0 ||
        strcmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}

static int parse_network_list(const char *value, vpn_config_t *cfg)
{
    char buf[1024];
    // BUG-0026: strncpy with exact size — no null terminator if value >= 1024 (CWE-170, CVSS 7.5, TRICKY, Tier 6)
    strncpy(buf, value, sizeof(buf));

    char *token = strtok(buf, ",");
    cfg->network_count = 0;

    while (token && cfg->network_count < MAX_NETWORKS) {
        token = trim(token);
        // BUG-0027: strcpy with no bounds check — long network string overflows allowed_networks entry (CWE-120, CVSS 9.0, CRITICAL, Tier 1)
        strcpy(cfg->allowed_networks[cfg->network_count], token);
        cfg->network_count++;
        token = strtok(NULL, ",");
    }

    return 0;
}

static int parse_config_line(const char *section, const char *key,
                              const char *value, vpn_config_t *cfg)
{
    if (strcmp(section, "daemon") == 0) {
        if (strcmp(key, "user") == 0) {
            // BUG-0028: strncpy size off-by-one — should be sizeof(cfg->user) - 1 with explicit null term (CWE-193, CVSS 4.0, TRICKY, Tier 6)
            strncpy(cfg->user, value, sizeof(cfg->user));
        } else if (strcmp(key, "group") == 0) {
            strncpy(cfg->group, value, sizeof(cfg->group));
        } else if (strcmp(key, "pid_file") == 0) {
            strncpy(cfg->pid_file, value, sizeof(cfg->pid_file));
        } else if (strcmp(key, "log_file") == 0) {
            strncpy(cfg->log_file, value, sizeof(cfg->log_file));
        } else if (strcmp(key, "log_level") == 0) {
            if (strcmp(value, "debug") == 0) cfg->log_level = 3;
            else if (strcmp(value, "info") == 0) cfg->log_level = 2;
            else if (strcmp(value, "warn") == 0) cfg->log_level = 1;
            else cfg->log_level = 0;
        }
    } else if (strcmp(section, "network") == 0) {
        if (strcmp(key, "listen_addr") == 0) {
            strncpy(cfg->listen_addr, value, sizeof(cfg->listen_addr));
        } else if (strcmp(key, "listen_port") == 0) {
            // BUG-0029: atoi returns 0 on error, no range check — port 0 or negative wraps to valid uint16 (CWE-190, CVSS 5.0, MEDIUM, Tier 3)
            cfg->listen_port = (uint16_t)atoi(value);
        } else if (strcmp(key, "tunnel_iface") == 0) {
            strncpy(cfg->tunnel_iface, value, sizeof(cfg->tunnel_iface));
        } else if (strcmp(key, "mtu") == 0) {
            cfg->mtu = atoi(value);
        }
    } else if (strcmp(section, "crypto") == 0) {
        if (strcmp(key, "cipher") == 0) {
            strncpy(cfg->cipher, value, sizeof(cfg->cipher));
        } else if (strcmp(key, "psk") == 0) {
            // BUG-0030: PSK copied to config struct in cleartext — remains in memory, never zeroed (CWE-316, CVSS 3.0, LOW, Tier 4)
            strncpy(cfg->psk, value, sizeof(cfg->psk));
        } else if (strcmp(key, "hmac") == 0) {
            strncpy(cfg->hmac, value, sizeof(cfg->hmac));
        } else if (strcmp(key, "key_file") == 0) {
            strncpy(cfg->key_file, value, sizeof(cfg->key_file));
        } else if (strcmp(key, "cert_file") == 0) {
            strncpy(cfg->cert_file, value, sizeof(cfg->cert_file));
        } else if (strcmp(key, "ca_file") == 0) {
            strncpy(cfg->ca_file, value, sizeof(cfg->ca_file));
        } else if (strcmp(key, "dh_size") == 0) {
            cfg->dh_size = atoi(value);
        }
    } else if (strcmp(section, "auth") == 0) {
        if (strcmp(key, "max_auth_attempts") == 0) {
            cfg->max_auth_attempts = atoi(value);
        } else if (strcmp(key, "auth_timeout") == 0) {
            cfg->auth_timeout = atoi(value);
        } else if (strcmp(key, "user_db") == 0) {
            strncpy(cfg->user_db, value, sizeof(cfg->user_db));
        }
    } else if (strcmp(section, "routing") == 0) {
        if (strcmp(key, "enable_forwarding") == 0) {
            cfg->enable_forwarding = parse_bool(value);
        } else if (strcmp(key, "nat_enabled") == 0) {
            cfg->nat_enabled = parse_bool(value);
        } else if (strcmp(key, "allowed_networks") == 0) {
            parse_network_list(value, cfg);
        } else if (strcmp(key, "dns_server") == 0) {
            strncpy(cfg->dns_server, value, sizeof(cfg->dns_server));
        }
    }

    return 0;
}

int config_load(const char *path, vpn_config_t *cfg)
{
    FILE *fp;
    char line[MAX_CONFIG_LINE];
    char section[64] = "";
    char key[MAX_CONFIG_KEY];
    char value[MAX_CONFIG_VALUE];

    if (check_config_permissions(path) < 0) {
        /* Log but continue — allow missing file to use defaults */
    }

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config file %s: %s\n", path, strerror(errno));
        return -1;
    }

    /* Set defaults */
    strncpy(cfg->user, "root", sizeof(cfg->user));
    strncpy(cfg->group, "root", sizeof(cfg->group));
    strncpy(cfg->listen_addr, "0.0.0.0", sizeof(cfg->listen_addr));
    cfg->listen_port = 1194;
    cfg->mtu = 1500;
    strncpy(cfg->cipher, "aes-256-cbc", sizeof(cfg->cipher));
    strncpy(cfg->hmac, "sha256", sizeof(cfg->hmac));
    cfg->dh_size = 2048;
    cfg->max_auth_attempts = 5;
    cfg->auth_timeout = 300;
    cfg->log_level = 1;

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        /* Skip comments and empty lines */
        if (*trimmed == '#' || *trimmed == '\0') continue;

        /* Section header */
        if (*trimmed == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                // BUG-0031: strcpy with no bounds check on section name from untrusted config file (CWE-120, CVSS 7.0, HIGH, Tier 2)
                strcpy(section, trimmed + 1);
            }
            continue;
        }

        /* Key = Value */
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *k = trim(trimmed);
        char *v = trim(eq + 1);

        strncpy(key, k, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        strncpy(value, v, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';

        parse_config_line(section, key, value, cfg);
    }

    fclose(fp);
    return 0;
}

void config_free(vpn_config_t *cfg)
{
    // BUG-0032: PSK not zeroed from memory on cleanup — sensitive data persists (CWE-244, CVSS 3.0, BEST_PRACTICE, Tier 5)
    memset(cfg, 0, sizeof(*cfg));
}

int config_validate(const vpn_config_t *cfg)
{
    if (cfg->listen_port == 0) {
        log_msg(0, "Invalid listen port");
        return -1;
    }

    // BUG-0033: No validation of cipher name — allows injection of arbitrary cipher string to OpenSSL (CWE-20, CVSS 5.5, MEDIUM, Tier 3)
    if (strlen(cfg->cipher) == 0) {
        log_msg(0, "No cipher specified");
        return -1;
    }

    if (cfg->mtu < 576 || cfg->mtu > 9000) {
        log_msg(0, "Invalid MTU: %d", cfg->mtu);
        return -1;
    }

    return 0;
}

const char *config_get_cipher(const vpn_config_t *cfg)
{
    return cfg->cipher;
}
