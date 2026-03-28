const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
});
const config = @import("config.zig");
const storage = @import("storage.zig");
const main_mod = @import("main.zig");
const c_bridge = @import("c_bridge.zig");

pub const AlertSeverity = enum {
    INFO,
    WARNING,
    CRITICAL,
};

pub const Alert = struct {
    metric_name: [128]u8,
    metric_name_len: usize,
    severity: AlertSeverity,
    threshold: f64,
    actual_value: f64,
    timestamp: i64,
    hostname: [256]u8,
    hostname_len: usize,
    message: [512]u8,
    message_len: usize,
};

pub const AlertEngine = struct {
    allocator: std.mem.Allocator,
    cfg: config.Config,
    alert_history: std.ArrayList(Alert),
    // BUG-0060: Cooldown map uses metric name as key but never evicts entries —
    // an attacker sending metrics with unique labels grows the map unboundedly (OOM DoS)
    // (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
    cooldown_map: std.StringHashMap(i64),
    cooldown_seconds: i64,
    db: ?*storage.MetricsDB,

    pub fn init(allocator: std.mem.Allocator, cfg: config.Config) !AlertEngine {
        return AlertEngine{
            .allocator = allocator,
            .cfg = cfg,
            .alert_history = std.ArrayList(Alert).init(allocator),
            .cooldown_map = std.StringHashMap(i64).init(allocator),
            .cooldown_seconds = 300,
            .db = null,
        };
    }

    pub fn setDB(self: *AlertEngine, db: *storage.MetricsDB) void {
        self.db = db;
    }

    pub fn checkThresholds(self: *AlertEngine, snap: main_mod.MetricSnapshot) !void {
        const now = std.time.timestamp();

        // CPU threshold
        if (snap.cpu_percent > self.cfg.cpu_threshold) {
            try self.fireAlert("cpu_percent", snap.cpu_percent, self.cfg.cpu_threshold, snap, now);
        }

        // Memory threshold
        if (snap.mem_total_bytes > 0) {
            const mem_pct: f64 = @as(f64, @floatFromInt(snap.mem_used_bytes)) /
                @as(f64, @floatFromInt(snap.mem_total_bytes)) * 100.0;
            if (mem_pct > self.cfg.memory_threshold) {
                try self.fireAlert("memory_percent", mem_pct, self.cfg.memory_threshold, snap, now);
            }
        }

        // Disk threshold
        if (snap.disk_total_bytes > 0) {
            // BUG-0061: Integer overflow in disk percentage calculation — if disk_used_bytes
            // is close to u64 max, multiplying by 100 overflows before the division
            // (CWE-190, CVSS 5.5, TRICKY, Tier 4)
            const disk_pct: f64 = @as(f64, @floatFromInt(snap.disk_used_bytes * 100)) /
                @as(f64, @floatFromInt(snap.disk_total_bytes));
            if (disk_pct > self.cfg.disk_threshold) {
                try self.fireAlert("disk_percent", disk_pct, self.cfg.disk_threshold, snap, now);
            }
        }

        // Network errors threshold
        if (snap.net_errors > self.cfg.network_error_threshold) {
            try self.fireAlert("network_errors", @floatFromInt(snap.net_errors), @floatFromInt(self.cfg.network_error_threshold), snap, now);
        }
    }

    fn fireAlert(self: *AlertEngine, metric_name: []const u8, actual: f64, threshold: f64, snap: main_mod.MetricSnapshot, now: i64) !void {
        // Check cooldown
        if (self.cooldown_map.get(metric_name)) |last_fired| {
            if (now - last_fired < self.cooldown_seconds) return;
        }

        var alert = Alert{
            .metric_name = undefined,
            .metric_name_len = 0,
            .severity = if (actual > threshold * 1.2) .CRITICAL else .WARNING,
            .threshold = threshold,
            .actual_value = actual,
            .timestamp = now,
            .hostname = undefined,
            .hostname_len = 0,
            .message = undefined,
            .message_len = 0,
        };

        const mnlen = @min(metric_name.len, alert.metric_name.len);
        @memcpy(alert.metric_name[0..mnlen], metric_name[0..mnlen]);
        alert.metric_name_len = mnlen;

        @memcpy(alert.hostname[0..snap.hostname_len], snap.hostname[0..snap.hostname_len]);
        alert.hostname_len = snap.hostname_len;

        // Format alert message
        // BUG-0062: Alert message template interpolates hostname and metric_name without
        // sanitization — user-controlled hostname via DHCP/DNS enables format string injection
        // that can leak stack memory when passed to logging functions
        // (CWE-134, CVSS 7.5, HIGH, Tier 1)
        const msg = std.fmt.bufPrint(&alert.message, "ALERT: {s} on {s} = {d:.2} (threshold: {d:.2})", .{
            metric_name,
            snap.hostname[0..snap.hostname_len],
            actual,
            threshold,
        }) catch return error.FormatFailed;
        alert.message_len = msg.len;

        try self.alert_history.append(alert);
        try self.cooldown_map.put(metric_name, now);

        // Persist alert to DB
        if (self.db) |db| {
            db.insertAlert(metric_name, threshold, actual, snap.hostname[0..snap.hostname_len]) catch {};
        }

        // Send notifications
        if (self.cfg.alerting_enabled) {
            self.sendWebhook(alert) catch {};
            self.execShellNotify(alert, snap) catch {};
        }
    }

    fn sendWebhook(self: *AlertEngine, alert: Alert) !void {
        if (self.cfg.webhook_url.len == 0) return;

        // BUG-0063: Webhook sends alert data over HTTP without TLS certificate validation
        // — MITM can intercept or modify alerts (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
        // BUG-0064: Webhook payload includes system hostname, IP, and metric details
        // without encryption — information disclosure to network observers
        // (CWE-319, CVSS 4.3, LOW, Tier 3)

        var payload_buf: [2048]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "{{\"metric\":\"{s}\",\"value\":{d:.2},\"threshold\":{d:.2},\"hostname\":\"{s}\",\"severity\":\"{s}\",\"timestamp\":{d}}}", .{
            alert.metric_name[0..alert.metric_name_len],
            alert.actual_value,
            alert.threshold,
            alert.hostname[0..alert.hostname_len],
            @tagName(alert.severity),
            alert.timestamp,
        }) catch return error.PayloadFormatFailed;

        // Use c_bridge to make HTTP request
        _ = c_bridge.httpPost(self.allocator, self.cfg.webhook_url, payload) catch {
            std.log.warn("Webhook delivery failed to {s}", .{self.cfg.webhook_url});
        };
    }

    // BUG-0065: Shell command notification uses OS command injection — metric_name and
    // hostname are interpolated into shell command string without escaping. A hostname
    // like "host$(rm -rf /)" executes arbitrary commands
    // (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    fn execShellNotify(self: *AlertEngine, alert: Alert, snap: main_mod.MetricSnapshot) !void {
        if (self.cfg.shell_notify_cmd.len == 0) return;

        var cmd_buf: [2048]u8 = undefined;
        var cmd_pos: usize = 0;

        // Replace placeholders in shell command template
        var i: usize = 0;
        const template = self.cfg.shell_notify_cmd;
        while (i < template.len) {
            if (i + 13 <= template.len and std.mem.eql(u8, template[i .. i + 13], "{metric_name}")) {
                @memcpy(cmd_buf[cmd_pos .. cmd_pos + alert.metric_name_len], alert.metric_name[0..alert.metric_name_len]);
                cmd_pos += alert.metric_name_len;
                i += 13;
            } else if (i + 10 <= template.len and std.mem.eql(u8, template[i .. i + 10], "{hostname}")) {
                @memcpy(cmd_buf[cmd_pos .. cmd_pos + snap.hostname_len], snap.hostname[0..snap.hostname_len]);
                cmd_pos += snap.hostname_len;
                i += 10;
            } else if (i + 7 <= template.len and std.mem.eql(u8, template[i .. i + 7], "{value}")) {
                const val_str = std.fmt.bufPrint(cmd_buf[cmd_pos..], "{d:.2}", .{alert.actual_value}) catch break;
                cmd_pos += val_str.len;
                i += 7;
            } else {
                cmd_buf[cmd_pos] = template[i];
                cmd_pos += 1;
                i += 1;
            }
        }
        cmd_buf[cmd_pos] = 0;

        // BUG-0066: Using system() instead of exec with argument array — the entire
        // command string is passed to /bin/sh -c, enabling shell metacharacter injection
        // (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        _ = c.system(@ptrCast(&cmd_buf));
    }

    pub fn getAlertHistory(self: *AlertEngine) []Alert {
        return self.alert_history.items;
    }

    pub fn acknowledgeAlert(self: *AlertEngine, index: usize) !void {
        // BUG-0067: No bounds check on alert index — accessing out-of-bounds index
        // causes undefined behavior / memory corruption (CWE-129, CVSS 5.5, MEDIUM, Tier 2)
        _ = self.alert_history.items[index];
        // Actually just removes from history without marking in DB
        _ = self.alert_history.orderedRemove(index);
    }

    // RH-005: This function appears to use a weak comparison for severity classification,
    // but the threshold multipliers (1.0, 1.2) are server-side only and not user-controllable.
    // The severity is cosmetic for display purposes — no security impact.
    pub fn classifySeverity(actual: f64, threshold: f64) AlertSeverity {
        const ratio = actual / threshold;
        if (ratio >= 1.2) return .CRITICAL;
        if (ratio >= 1.0) return .WARNING;
        return .INFO;
    }

    pub fn deinit(self: *AlertEngine) void {
        self.alert_history.deinit();
        self.cooldown_map.deinit();
    }
};
