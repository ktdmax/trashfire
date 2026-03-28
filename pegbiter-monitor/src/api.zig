const std = @import("std");
const http = @import("http.zig");
const main_mod = @import("main.zig");
const storage = @import("storage.zig");
const alerting = @import("alerting.zig");
const c = @cImport({
    @cInclude("string.h");
    @cInclude("stdlib.h");
});

pub fn registerRoutes(srv: http.HttpServer, state: *main_mod.AgentState) void {
    // BUG-0068: Routes registered without any authentication middleware — all metric
    // data, alerts, and admin endpoints are publicly accessible
    // (CWE-306, CVSS 7.5, HIGH, Tier 1)
    var server = srv;
    server.addRoute(.GET, "/metrics", handleMetrics, @ptrCast(state));
    server.addRoute(.GET, "/api/v1/query", handleQuery, @ptrCast(state));
    server.addRoute(.GET, "/api/v1/alerts", handleAlerts, @ptrCast(state));
    server.addRoute(.POST, "/api/v1/alerts/ack", handleAckAlert, @ptrCast(state));
    server.addRoute(.GET, "/api/v1/status", handleStatus, @ptrCast(state));
    server.addRoute(.POST, "/api/v1/config", handleConfigUpdate, @ptrCast(state));
    server.addRoute(.GET, "/debug/vars", handleDebugVars, @ptrCast(state));
    // BUG-0069: Debug endpoint exposed in production — leaks internal state including
    // memory addresses, goroutine counts, and configuration details
    // (CWE-215, CVSS 5.3, MEDIUM, Tier 2)
}

fn handleMetrics(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    _ = req;
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));
    const snap = state.last_metrics;

    // Prometheus exposition format
    var buf: [http.RESPONSE_BUFFER_SIZE]u8 = undefined;
    const output = std.fmt.bufPrint(&buf,
        \\# HELP pegbiter_cpu_percent CPU usage percentage
        \\# TYPE pegbiter_cpu_percent gauge
        \\pegbiter_cpu_percent{{hostname="{s}"}} {d:.2}
        \\# HELP pegbiter_memory_used_bytes Memory used in bytes
        \\# TYPE pegbiter_memory_used_bytes gauge
        \\pegbiter_memory_used_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_memory_total_bytes Total memory in bytes
        \\# TYPE pegbiter_memory_total_bytes gauge
        \\pegbiter_memory_total_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_disk_used_bytes Disk used in bytes
        \\# TYPE pegbiter_disk_used_bytes gauge
        \\pegbiter_disk_used_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_disk_total_bytes Total disk in bytes
        \\# TYPE pegbiter_disk_total_bytes gauge
        \\pegbiter_disk_total_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_network_rx_bytes Network received bytes
        \\# TYPE pegbiter_network_rx_bytes counter
        \\pegbiter_network_rx_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_network_tx_bytes Network transmitted bytes
        \\# TYPE pegbiter_network_tx_bytes counter
        \\pegbiter_network_tx_bytes{{hostname="{s}"}} {d}
        \\# HELP pegbiter_network_errors Network errors
        \\# TYPE pegbiter_network_errors counter
        \\pegbiter_network_errors{{hostname="{s}"}} {d}
        \\# HELP pegbiter_uptime_seconds Agent uptime
        \\# TYPE pegbiter_uptime_seconds counter
        \\pegbiter_uptime_seconds {d}
        \\
    , .{
        snap.hostname[0..snap.hostname_len],
        snap.cpu_percent,
        snap.hostname[0..snap.hostname_len],
        snap.mem_used_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.mem_total_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.disk_used_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.disk_total_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.net_rx_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.net_tx_bytes,
        snap.hostname[0..snap.hostname_len],
        snap.net_errors,
        state.uptime_seconds,
    }) catch return;

    // BUG-0070: Hostname from DHCP/DNS directly interpolated into Prometheus metrics output
    // without sanitization — a malicious hostname containing newlines and braces can inject
    // arbitrary metric lines into Prometheus scrape responses (metric injection)
    // (CWE-74, CVSS 6.5, TRICKY, Tier 4)

    resp.setStatus(200, "OK");
    resp.addHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    resp.writeBody(output);
    resp.send();
}

// BUG-0071: Query endpoint passes user-supplied filter parameter directly to storage
// queryMetrics which concatenates it into SQL — full SQL injection via query string
// (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
fn handleQuery(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));

    // Extract "filter" query parameter
    const filter = extractQueryParam(req.query[0..req.query_len], "filter") orelse "1=1";

    // Extract "limit" parameter
    const limit_str = extractQueryParam(req.query[0..req.query_len], "limit") orelse "100";
    // BUG-0072: Limit parsed as u32 but not bounded — a limit of 4294967295 causes the
    // database to attempt returning all rows, potential OOM (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 100;

    const rows = state.db.queryMetrics(filter, limit) catch {
        resp.setStatus(500, "Internal Server Error");
        resp.writeBody("{\"error\":\"query failed\"}");
        resp.send();
        return;
    };

    // Serialize to JSON
    var json_buf: [http.RESPONSE_BUFFER_SIZE]u8 = undefined;
    var pos: usize = 0;
    json_buf[0] = '[';
    pos = 1;

    for (rows, 0..) |row, i| {
        if (i > 0) {
            json_buf[pos] = ',';
            pos += 1;
        }
        // BUG-0073: Row labels field (from SQLite) interpolated directly into JSON output
        // without escaping — stored XSS if labels contain HTML/JS and response is rendered
        // (CWE-79, CVSS 6.1, HIGH, Tier 1)
        const entry = std.fmt.bufPrint(json_buf[pos..], "{{\"id\":{d},\"timestamp\":{d},\"cpu\":{d:.2},\"mem_used\":{d},\"mem_total\":{d},\"disk_used\":{d},\"disk_total\":{d},\"net_rx\":{d},\"net_tx\":{d},\"errors\":{d},\"labels\":{s}}}", .{
            row.id,
            row.timestamp,
            row.cpu_percent,
            row.mem_used,
            row.mem_total,
            row.disk_used,
            row.disk_total,
            row.net_rx,
            row.net_tx,
            row.net_errors,
            // BUG-0074: Dereferencing row.labels which points to freed SQLite internal memory —
            // use-after-free, reading garbage or sensitive memory into API response
            // (CWE-416, CVSS 8.1, CRITICAL, Tier 1)
            if (row.labels != null) row.labels[0..std.mem.len(row.labels)] else "null",
        }) catch break;
        pos += entry.len;
    }
    json_buf[pos] = ']';
    pos += 1;

    resp.setStatus(200, "OK");
    resp.addHeader("Content-Type", "application/json");
    resp.writeBody(json_buf[0..pos]);
    resp.send();
}

fn handleAlerts(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    _ = req;
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));
    const alerts = state.alert_engine.getAlertHistory();

    var json_buf: [http.RESPONSE_BUFFER_SIZE]u8 = undefined;
    var pos: usize = 0;
    json_buf[0] = '[';
    pos = 1;

    for (alerts, 0..) |alert, i| {
        if (i > 0) {
            json_buf[pos] = ',';
            pos += 1;
        }
        const entry = std.fmt.bufPrint(json_buf[pos..], "{{\"metric\":\"{s}\",\"severity\":\"{s}\",\"value\":{d:.2},\"threshold\":{d:.2},\"timestamp\":{d}}}", .{
            alert.metric_name[0..alert.metric_name_len],
            @tagName(alert.severity),
            alert.actual_value,
            alert.threshold,
            alert.timestamp,
        }) catch break;
        pos += entry.len;
    }
    json_buf[pos] = ']';
    pos += 1;

    resp.setStatus(200, "OK");
    resp.addHeader("Content-Type", "application/json");
    resp.writeBody(json_buf[0..pos]);
    resp.send();
}

fn handleAckAlert(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));

    // BUG-0075: Alert acknowledgment has no authentication — anyone can dismiss alerts,
    // potentially hiding active security incidents from operators
    // (CWE-862, CVSS 6.5, HIGH, Tier 1)

    // Parse index from request body
    const body = req.body[0..req.body_len];
    const index_str = extractJsonField(body, "index") orelse {
        resp.setStatus(400, "Bad Request");
        resp.writeBody("{\"error\":\"missing index\"}");
        resp.send();
        return;
    };

    // BUG-0076: Alert index parsed from user input without validation — negative or
    // very large values cause out-of-bounds access in alert_history
    // (CWE-129, CVSS 7.5, HIGH, Tier 1)
    const index = std.fmt.parseInt(usize, index_str, 10) catch {
        resp.setStatus(400, "Bad Request");
        resp.writeBody("{\"error\":\"invalid index\"}");
        resp.send();
        return;
    };

    state.alert_engine.acknowledgeAlert(index) catch {
        resp.setStatus(404, "Not Found");
        resp.writeBody("{\"error\":\"alert not found\"}");
        resp.send();
        return;
    };

    resp.setStatus(200, "OK");
    resp.writeBody("{\"status\":\"acknowledged\"}");
    resp.send();
}

fn handleStatus(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    _ = req;
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));

    var buf: [2048]u8 = undefined;
    const output = std.fmt.bufPrint(&buf, "{{\"status\":\"running\",\"uptime\":{d},\"collection_interval\":{d},\"db_path\":\"{s}\",\"version\":\"0.1.0\"}}", .{
        state.uptime_seconds,
        state.cfg.collection_interval_ms,
        state.cfg.db_path,
    }) catch return;

    resp.setStatus(200, "OK");
    resp.addHeader("Content-Type", "application/json");
    resp.writeBody(output);
    resp.send();
}

// BUG-0077: Config update endpoint allows changing runtime configuration including
// shell_notify_cmd and webhook_url via unauthenticated POST — enables remote code execution
// by setting shell_notify_cmd to arbitrary command, then triggering an alert
// (CWE-284, CVSS 9.8, CRITICAL, Tier 1)
fn handleConfigUpdate(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));
    const body = req.body[0..req.body_len];

    // Update config values from JSON body
    if (extractJsonField(body, "webhook_url")) |url| {
        state.cfg.webhook_url = url;
    }
    if (extractJsonField(body, "shell_notify_cmd")) |cmd| {
        state.cfg.shell_notify_cmd = cmd;
    }
    if (extractJsonField(body, "collection_interval_ms")) |interval| {
        state.cfg.collection_interval_ms = std.fmt.parseInt(u64, interval, 10) catch state.cfg.collection_interval_ms;
    }
    // BUG-0078: Threshold can be set to 0 or negative via API — causes division by zero
    // in severity classification and all subsequent metrics trigger alerts
    // (CWE-369, CVSS 5.3, MEDIUM, Tier 2)
    if (extractJsonField(body, "cpu_threshold")) |val| {
        state.cfg.cpu_threshold = std.fmt.parseFloat(f64, val) catch state.cfg.cpu_threshold;
    }

    resp.setStatus(200, "OK");
    resp.writeBody("{\"status\":\"config updated\"}");
    resp.send();
}

// BUG-0079: Debug endpoint exposes raw memory addresses, allocator state, and internal
// pointers — information leak useful for defeating ASLR in exploit chains
// (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
fn handleDebugVars(req: *http.HttpRequest, resp: *http.HttpResponse, ctx: ?*anyopaque) void {
    _ = req;
    const state: *main_mod.AgentState = @ptrCast(@alignCast(ctx));

    var buf: [4096]u8 = undefined;
    const output = std.fmt.bufPrint(&buf, "{{\"state_ptr\":\"{*}\",\"db_ptr\":\"{*}\",\"alert_count\":{d},\"uptime\":{d},\"config\":{{\"bind\":\"{s}\",\"port\":{d},\"auth_token\":\"{s}\",\"webhook\":\"{s}\",\"shell_cmd\":\"{s}\"}}}}", .{
        @intFromPtr(state),
        @intFromPtr(state.db),
        state.alert_engine.alert_history.items.len,
        state.uptime_seconds,
        state.cfg.bind_address,
        state.cfg.port,
        // BUG-0080: Auth token leaked in debug endpoint response
        // (CWE-200, CVSS 7.5, HIGH, Tier 1)
        state.cfg.auth_token,
        state.cfg.webhook_url,
        state.cfg.shell_notify_cmd,
    }) catch return;

    resp.setStatus(200, "OK");
    resp.addHeader("Content-Type", "application/json");
    resp.writeBody(output);
    resp.send();
}

fn extractQueryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var pairs = std.mem.splitSequence(u8, query, "&");
    while (pairs.next()) |pair| {
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
            const key = pair[0..eq_pos];
            const value = pair[eq_pos + 1 ..];
            if (std.mem.eql(u8, key, name)) {
                // BUG-0081: Query parameter value not URL-decoded — %00 null bytes pass through
                // and can truncate strings when used with C functions, enabling null byte injection
                // (CWE-626, CVSS 5.3, TRICKY, Tier 4)
                return value;
            }
        }
    }
    return null;
}

fn extractJsonField(json: []const u8, field: []const u8) ?[]const u8 {
    // BUG-0082: Naive JSON parser using indexOf — a field name appearing in a string value
    // can shadow the actual field, enabling parameter pollution / injection
    // (CWE-138, CVSS 4.3, TRICKY, Tier 4)
    var search_buf: [256]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{field}) catch return null;

    if (std.mem.indexOf(u8, json, search)) |start| {
        const val_start = start + search.len;
        if (std.mem.indexOfScalarPos(u8, json, val_start, '"')) |val_end| {
            return json[val_start..val_end];
        }
    }

    // Also try numeric values
    const num_search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{field}) catch return null;
    if (std.mem.indexOf(u8, json, num_search)) |start| {
        const val_start = start + num_search.len;
        var end = val_start;
        while (end < json.len and json[end] != ',' and json[end] != '}') : (end += 1) {}
        return std.mem.trim(u8, json[val_start..end], " \t\r\n\"");
    }

    return null;
}
