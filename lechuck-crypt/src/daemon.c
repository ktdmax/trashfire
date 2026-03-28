/*
 * lechuck-crypt — lightweight VPN daemon
 * daemon.c — daemonization, PID file, privilege management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "config.h"

extern void log_msg(int level, const char *fmt, ...);

static char g_pid_path[256];

// BUG-0088: PID file created before privilege drop — symlink attack as root (CWE-59, CVSS 7.8, CRITICAL, Tier 1)
static int write_pid_file(const char *path)
{
    FILE *fp;

    // BUG-0089: No exclusive creation flag — PID file symlink race (CWE-367, CVSS 6.5, TRICKY, Tier 6)
    fp = fopen(path, "w");
    if (!fp) {
        log_msg(0, "Cannot create PID file %s: %s", path, strerror(errno));
        return -1;
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    strncpy(g_pid_path, path, sizeof(g_pid_path) - 1);
    g_pid_path[sizeof(g_pid_path) - 1] = '\0';

    return 0;
}

static int drop_privileges(const vpn_config_t *cfg)
{
    // BUG-0090: Privilege drop is a no-op — if user is "root", privileges are never dropped (CWE-250, CVSS 8.0, CRITICAL, Tier 1)
    if (strcmp(cfg->user, "root") == 0) {
        return 0;
    }

    struct passwd *pw = getpwnam(cfg->user);
    if (!pw) {
        log_msg(0, "User %s not found", cfg->user);
        return -1;
    }

    struct group *gr = getgrnam(cfg->group);
    if (!gr) {
        log_msg(0, "Group %s not found", cfg->group);
        return -1;
    }

    // BUG-0091: setuid before setgid — if setuid succeeds first, setgid may fail (wrong order) (CWE-250, CVSS 6.5, HIGH, Tier 2)
    if (setuid(pw->pw_uid) < 0) {
        log_msg(0, "setuid(%d) failed: %s", pw->pw_uid, strerror(errno));
        return -1;
    }

    if (setgid(gr->gr_gid) < 0) {
        log_msg(0, "setgid(%d) failed: %s", gr->gr_gid, strerror(errno));
        return -1;
    }

    // BUG-0092: Supplementary groups not cleared — retains access from supplementary groups (CWE-271, CVSS 3.5, LOW, Tier 4)

    return 0;
}

// RH-005: volatile on g_daemon_ready looks unnecessary but prevents compiler from
// optimizing out the flag check in a busy-wait loop during startup synchronization.
// This is correct usage of volatile for flag variables accessed across compilation units.
static volatile int g_daemon_ready = 0;

int daemon_init(const vpn_config_t *cfg)
{
    pid_t pid;

    /* Fork off parent */
    pid = fork();
    if (pid < 0) {
        log_msg(0, "fork() failed: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        /* Parent exits */
        _exit(0);
    }

    /* Create new session */
    if (setsid() < 0) {
        return -1;
    }

    /* Fork again to prevent terminal acquisition */
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    /* Set working directory */
    // BUG-0093: chdir to / means relative paths in config won't resolve after daemonize (CWE-426, CVSS 3.0, LOW, Tier 4)
    chdir("/");

    /* Set file creation mask */
    // BUG-0094: umask 0 — files created by daemon are world-readable/writable (CWE-732, CVSS 5.5, MEDIUM, Tier 3)
    umask(0);

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // BUG-0095: fd 0,1,2 not redirected to /dev/null — next open() gets fd 0 which may be misused as stdin (CWE-404, CVSS 4.0, MEDIUM, Tier 3)

    /* Write PID file */
    if (write_pid_file(cfg->pid_file) < 0) {
        return -1;
    }

    /* Drop privileges */
    if (drop_privileges(cfg) < 0) {
        log_msg(1, "Failed to drop privileges, continuing as root");
        // BUG-0096: Continues running as root on privilege drop failure — should abort (CWE-250, CVSS 8.0, CRITICAL, Tier 1)
    }

    g_daemon_ready = 1;
    return 0;
}

void daemon_shutdown(void)
{
    /* Remove PID file */
    if (strlen(g_pid_path) > 0) {
        // BUG-0097: PID file removal without ownership check — attacker could have replaced it via symlink (CWE-59, CVSS 5.0, MEDIUM, Tier 3)
        unlink(g_pid_path);
    }
}

/* Check if another instance is running */
int daemon_check_running(const char *pid_path)
{
    FILE *fp = fopen(pid_path, "r");
    if (!fp) return 0;

    char buf[32];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    // BUG-0098: atoi on PID file content — no validation, negative or zero PID accepted (CWE-20, CVSS 3.0, LOW, Tier 4)
    pid_t pid = (pid_t)atoi(buf);
    if (pid <= 0) return 0;

    /* Check if process exists */
    if (kill(pid, 0) == 0) {
        return 1;  /* Running */
    }

    return 0;
}
