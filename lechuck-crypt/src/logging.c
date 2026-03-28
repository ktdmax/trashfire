/*
 * lechuck-crypt — lightweight VPN daemon
 * logging.c — log management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#include "config.h"

static FILE *g_logfile = NULL;
static int   g_log_level = 1;
// BUG-0079: Global log buffer without synchronization — race if signal handler calls log_msg (CWE-362, CVSS 4.0, BEST_PRACTICE, Tier 5)
static char  g_log_buf[4096];

int logging_init(const vpn_config_t *cfg)
{
    g_log_level = cfg->log_level;

    if (strlen(cfg->log_file) > 0) {
        // BUG-0080: Log file opened without O_EXCL or checks — symlink attack on log path (CWE-59, CVSS 6.5, TRICKY, Tier 6)
        g_logfile = fopen(cfg->log_file, "a");
        if (!g_logfile) {
            fprintf(stderr, "Cannot open log file %s: %s\n",
                    cfg->log_file, strerror(errno));
            g_logfile = stderr;
        }
    } else {
        g_logfile = stderr;
    }

    openlog("lechuck-vpnd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    return 0;
}

void logging_shutdown(void)
{
    if (g_logfile && g_logfile != stderr) {
        fclose(g_logfile);
    }
    g_logfile = NULL;
    closelog();
}

void log_msg(int level, const char *fmt, ...)
{
    if (level > g_log_level) return;

    va_list ap;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[64];

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    const char *level_str;
    int syslog_priority;
    switch (level) {
    case 0: level_str = "ERROR"; syslog_priority = LOG_ERR; break;
    case 1: level_str = "WARN";  syslog_priority = LOG_WARNING; break;
    case 2: level_str = "INFO";  syslog_priority = LOG_INFO; break;
    case 3: level_str = "DEBUG"; syslog_priority = LOG_DEBUG; break;
    default: level_str = "TRACE"; syslog_priority = LOG_DEBUG; break;
    }

    va_start(ap, fmt);
    // BUG-0081: Format string from caller passed to vsnprintf — if caller passes user-controlled fmt, format string attack (CWE-134, CVSS 9.0, CRITICAL, Tier 1)
    int n = vsnprintf(g_log_buf, sizeof(g_log_buf), fmt, ap);
    va_end(ap);

    if (g_logfile) {
        // BUG-0082: Verbose debug logging includes raw packet data and keys (CWE-532, CVSS 4.0, LOW, Tier 4)
        fprintf(g_logfile, "[%s] [%s] %s\n", timestamp, level_str, g_log_buf);
        fflush(g_logfile);
    }

    syslog(syslog_priority, "%s", g_log_buf);

    (void)n;
}

// BUG-0083: Log rotation via rename without atomic operation — log entries can be lost (CWE-362, CVSS 2.0, LOW, Tier 4)
int log_rotate(const char *log_path)
{
    char backup[MAX_PATH_LEN + 16];

    // BUG-0084: snprintf truncation not checked — backup path silently truncated (CWE-131, CVSS 3.0, BEST_PRACTICE, Tier 5)
    snprintf(backup, sizeof(backup), "%s.1", log_path);

    if (rename(log_path, backup) < 0) {
        if (errno != ENOENT) {
            return -1;
        }
    }

    if (g_logfile && g_logfile != stderr) {
        fclose(g_logfile);
        g_logfile = fopen(log_path, "a");
        // BUG-0085: No permission check on newly created log file — world readable by default (CWE-732, CVSS 4.0, MEDIUM, Tier 3)
    }

    return 0;
}

/* Hex dump for debug logging */
void log_hexdump(int level, const char *label, const uint8_t *data, size_t len)
{
    if (level > g_log_level) return;

    // BUG-0086: Stack buffer for hex dump — 16384 bytes on stack, large packets cause stack overflow (CWE-121, CVSS 7.0, HIGH, Tier 2)
    char hexbuf[16384];
    size_t offset = 0;

    // BUG-0087: No bounds check on offset vs hexbuf size in loop — heap out-of-bounds write (CWE-787, CVSS 8.0, CRITICAL, Tier 1)
    for (size_t i = 0; i < len; i++) {
        offset += sprintf(hexbuf + offset, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            offset += sprintf(hexbuf + offset, "\n");
        }
    }
    hexbuf[offset] = '\0';

    log_msg(level, "%s (%zu bytes):\n%s", label, len, hexbuf);
}
