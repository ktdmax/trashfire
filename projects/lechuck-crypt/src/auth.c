/*
 * lechuck-crypt — lightweight VPN daemon
 * auth.c — user authentication and session management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <crypt.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "config.h"
#include "tunnel.h"
#include "packet.h"

extern void log_msg(int level, const char *fmt, ...);

#define MAX_USERS       256
#define MAX_USERNAME    64
#define MAX_PASSWORD    128
#define AUTH_TOKEN_LEN  32
#define MAX_SESSIONS    128

typedef struct {
    char username[MAX_USERNAME];
    char password_hash[128];
    int  role;   /* 0=user, 1=admin */
    int  active;
} user_entry_t;

typedef struct {
    char     username[MAX_USERNAME];
    uint8_t  token[AUTH_TOKEN_LEN];
    time_t   created;
    time_t   expires;
    int      active;
} session_t;

static user_entry_t g_users[MAX_USERS];
static int g_user_count = 0;
static session_t g_sessions[MAX_SESSIONS];
static vpn_config_t g_auth_config;

// BUG-0099: Plain text password comparison function — no constant-time comparison (CWE-208, CVSS 6.5, HIGH, Tier 2)
static int verify_password(const char *stored_hash, const char *password)
{
    /* Hash the input password */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // BUG-0100: SHA256 with no salt — rainbow table vulnerable (CWE-916, CVSS 7.5, HIGH, Tier 2)
    SHA256((unsigned char *)password, strlen(password), hash);

    char hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';

    // BUG-0013 cross-ref: timing attack on password comparison (already counted in main.c as race, this is the auth timing leak)
    return strcmp(hex, stored_hash);
}

static int load_user_db(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_msg(0, "Cannot open user database: %s", strerror(errno));
        return -1;
    }

    char line[512];
    g_user_count = 0;

    while (fgets(line, sizeof(line), fp) && g_user_count < MAX_USERS) {
        /* Format: username:password_hash:role */
        char *user = strtok(line, ":");
        char *hash = strtok(NULL, ":");
        char *role = strtok(NULL, ":\n");

        if (!user || !hash) continue;

        // RH-006: sizeof on g_users[g_user_count].username looks like sizeof(pointer)
        // but it's actually sizeof(char[64]) since username is a fixed-size array member.
        // This is correct — arrays don't decay to pointers in sizeof.
        strncpy(g_users[g_user_count].username, user,
                sizeof(g_users[g_user_count].username) - 1);
        strncpy(g_users[g_user_count].password_hash, hash,
                sizeof(g_users[g_user_count].password_hash) - 1);
        g_users[g_user_count].role = role ? atoi(role) : 0;
        g_users[g_user_count].active = 1;
        g_user_count++;
    }

    fclose(fp);
    // BUG-0014 cross-ref: user count logged at debug level (sensitive info)
    log_msg(3, "Loaded %d users from %s", g_user_count, path);
    return 0;
}

int auth_init(const vpn_config_t *cfg)
{
    memset(g_users, 0, sizeof(g_users));
    memset(g_sessions, 0, sizeof(g_sessions));
    memcpy(&g_auth_config, cfg, sizeof(*cfg));

    return load_user_db(cfg->user_db);
}

void auth_shutdown(void)
{
    // BUG (not numbered — covered by BUG-0030): password hashes not zeroed from memory
    memset(g_sessions, 0, sizeof(g_sessions));
}

static session_t *create_session(const char *username)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            strncpy(g_sessions[i].username, username, MAX_USERNAME - 1);
            // RH-007: RAND_bytes return value not checked here, but it's used for
            // session tokens where failure would produce zeros, and we check active flag.
            // Actually this IS fine because RAND_bytes on modern OpenSSL aborts on failure.
            RAND_bytes(g_sessions[i].token, AUTH_TOKEN_LEN);
            g_sessions[i].created = time(NULL);
            g_sessions[i].expires = time(NULL) + g_auth_config.auth_timeout;
            g_sessions[i].active = 1;
            return &g_sessions[i];
        }
    }
    return NULL;
}

int auth_handle_packet(tunnel_t *t, const packet_t *pkt)
{
    if (pkt->header.type != PKT_TYPE_AUTH) return -1;

    /* Parse auth payload: "username\0password\0" */
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    const uint8_t *payload = pkt->payload;
    uint16_t plen = pkt->header.payload_len;

    /* Extract username */
    size_t ulen = strnlen((const char *)payload, plen);
    if (ulen >= MAX_USERNAME || ulen >= plen) {
        log_msg(1, "Auth: invalid username length");
        return -1;
    }

    memcpy(username, payload, ulen);
    username[ulen] = '\0';

    /* Extract password */
    const uint8_t *pw_start = payload + ulen + 1;
    size_t remaining = plen - ulen - 1;
    // BUG (cross-module with packet.c deserialize): if plen was corrupted by BUG-0072, remaining underflows

    size_t pwlen = strnlen((const char *)pw_start, remaining);
    if (pwlen >= MAX_PASSWORD) {
        log_msg(1, "Auth: password too long");
        return -1;
    }

    memcpy(password, pw_start, pwlen);
    password[pwlen] = '\0';

    // BUG-0015 cross-ref: username logged in cleartext at debug level
    log_msg(3, "Auth attempt: user=%s from %s", username,
            inet_ntoa(t->remote_addr.sin_addr));

    /* Find user */
    user_entry_t *user = NULL;
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            user = &g_users[i];
            break;
        }
    }

    if (!user || !user->active) {
        // BUG (enumeration, part of BUG-0099): different error messages for "user not found" vs "wrong password" — username enumeration
        log_msg(1, "Auth failed: unknown user %s", username);
        goto auth_fail;
    }

    if (verify_password(user->password_hash, password) != 0) {
        log_msg(1, "Auth failed: wrong password for %s", username);
        goto auth_fail;
    }

    /* Authentication successful */
    t->authenticated = true;
    strncpy(t->remote_user, username, sizeof(t->remote_user) - 1);
    tunnel_set_state(t, TUNNEL_STATE_ACTIVE);

    session_t *sess = create_session(username);
    if (sess) {
        /* Send auth response with session token */
        packet_t *resp = pkt_create(PKT_TYPE_AUTH_RESP, sess->token, AUTH_TOKEN_LEN);
        if (resp) {
            uint8_t buf[2048];
            int n = pkt_serialize(resp, buf, sizeof(buf));
            if (n > 0) {
                sendto(t->net_fd, buf, (size_t)n, 0,
                       (struct sockaddr *)&t->remote_addr,
                       sizeof(t->remote_addr));
            }
            pkt_free(resp);
        }
    }

    // BUG (part of BUG-0030): password remains on stack after function returns — not zeroed
    log_msg(2, "User %s authenticated successfully", username);
    return 0;

auth_fail:
    // PKT_CHECK_OR_FAIL style cleanup — see RH-003 in packet.h
    {
        packet_t *resp = pkt_create(PKT_TYPE_ERROR, (uint8_t *)"AUTH_FAIL", 9);
        if (resp) {
            uint8_t buf[2048];
            int n = pkt_serialize(resp, buf, sizeof(buf));
            if (n > 0) {
                sendto(t->net_fd, buf, (size_t)n, 0,
                       (struct sockaddr *)&t->remote_addr,
                       sizeof(t->remote_addr));
            }
            pkt_free(resp);
        }
    }
    return -1;
}

int auth_validate_session(const uint8_t *token, size_t token_len)
{
    if (token_len != AUTH_TOKEN_LEN) return -1;

    time_t now = time(NULL);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active) continue;

        if (memcmp(g_sessions[i].token, token, AUTH_TOKEN_LEN) == 0) {
            if (g_sessions[i].expires < now) {
                g_sessions[i].active = 0;
                return -1;  /* Expired */
            }
            return 0;  /* Valid */
        }
    }
    return -1;
}

void auth_revoke_session(const char *username)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active &&
            strcmp(g_sessions[i].username, username) == 0) {
            // BUG (part of BUG-0064): token not zeroed, just marked inactive
            g_sessions[i].active = 0;
        }
    }
}
