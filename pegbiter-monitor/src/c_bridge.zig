const std = @import("std");
const c = @cImport({
    @cInclude("uv.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("netdb.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
});

// BUG-0083: Global mutable buffer for hostname resolution — concurrent calls from
// timer callback and API handler race on this buffer (CWE-362, CVSS 6.8, TRICKY, Tier 4)
var hostname_buf: [256]u8 = undefined;
var resolved_hostname: [256]u8 = undefined;
var resolve_depth: u32 = 0;

pub fn resolveHostname(allocator: std.mem.Allocator) ![]const u8 {
    _ = allocator;

    // BUG-0084: gethostname writes into global buffer without mutex — data race if
    // called from multiple threads (timer callback + API handler simultaneously)
    // (CWE-362, CVSS 5.5, TRICKY, Tier 4)
    const rc = c.gethostname(&hostname_buf, hostname_buf.len);
    if (rc != 0) return error.HostnameFailed;

    // Resolve hostname to FQDN via DNS
    // BUG-0085: getaddrinfo with no timeout — if DNS is slow or unresponsive, this blocks
    // the entire event loop, stalling all metric collection and API responses
    // (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_UNSPEC;
    hints.ai_flags = c.AI_CANONNAME;

    var result: ?*c.struct_addrinfo = null;
    const gai_rc = c.getaddrinfo(@ptrCast(&hostname_buf), null, &hints, &result);
    if (gai_rc != 0) {
        // Fall back to raw hostname
        const len = std.mem.len(@as([*:0]u8, @ptrCast(&hostname_buf)));
        return hostname_buf[0..len];
    }
    defer c.freeaddrinfo(result);

    if (result) |res| {
        if (res.ai_canonname) |canon| {
            const canon_len = std.mem.len(canon);
            // BUG-0086: Canonical hostname from DNS is trusted without length validation —
            // a malicious DNS response with a >256 byte canonical name overflows resolved_hostname
            // (CWE-120, CVSS 8.1, CRITICAL, Tier 1)
            @memcpy(resolved_hostname[0..canon_len], canon[0..canon_len]);
            return resolved_hostname[0..canon_len];
        }
    }

    const len = std.mem.len(@as([*:0]u8, @ptrCast(&hostname_buf)));
    return hostname_buf[0..len];
}

// BUG-0087: resolveHostnameCNAME follows CNAME chains recursively with no depth limit —
// a DNS CNAME loop causes stack overflow (CWE-674, CVSS 7.5, TRICKY, Tier 4)
pub fn resolveHostnameCNAME(hostname: []const u8, depth: u32) ![]const u8 {
    // No maximum depth check
    _ = depth;

    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_UNSPEC;
    hints.ai_flags = c.AI_CANONNAME;

    var result: ?*c.struct_addrinfo = null;
    var host_z: [256]u8 = undefined;
    @memcpy(host_z[0..hostname.len], hostname);
    host_z[hostname.len] = 0;

    const rc = c.getaddrinfo(@ptrCast(&host_z), null, &hints, &result);
    if (rc != 0) return error.ResolveFailed;
    defer c.freeaddrinfo(result);

    if (result) |res| {
        if (res.ai_canonname) |canon| {
            const canon_slice = canon[0..std.mem.len(canon)];
            if (!std.mem.eql(u8, canon_slice, hostname)) {
                // CNAME detected, follow it recursively
                return resolveHostnameCNAME(canon_slice, depth + 1);
            }
            return canon_slice;
        }
    }

    return hostname;
}

pub const HttpResult = struct {
    status_code: u16,
    body: []const u8,
    body_len: usize,
};

// BUG-0088: HTTP client does not validate TLS certificates — accepts any certificate
// including self-signed, enabling MITM attacks on webhook delivery
// (CWE-295, CVSS 7.4, HIGH, Tier 1)
pub fn httpPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8) !HttpResult {
    // Parse URL
    const host_start = if (std.mem.indexOf(u8, url, "://")) |pos| pos + 3 else 0;
    const path_start = std.mem.indexOfScalarPos(u8, url, host_start, '/') orelse url.len;
    const host = url[host_start..path_start];
    const path = if (path_start < url.len) url[path_start..] else "/";

    var port: u16 = 80;
    if (std.mem.indexOfScalar(u8, host, ':')) |colon| {
        port = std.fmt.parseInt(u16, host[colon + 1 ..], 10) catch 80;
    }

    // Create socket
    const sock = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (sock < 0) return error.SocketFailed;
    var addr: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(port);

    // Resolve host
    const host_z = try allocator.dupeZ(u8, host);
    defer allocator.free(host_z);

    const hostent = c.gethostbyname(host_z);
    if (hostent == null) {
        _ = c.close(sock);
        return error.HostResolveFailed;
    }

    // BUG-0091: gethostbyname result used without null checks on h_addr_list —
    // null pointer dereference if DNS returns empty result
    // (CWE-476, CVSS 5.5, MEDIUM, Tier 2)
    _ = c.memcpy(&addr.sin_addr, hostent.*.h_addr_list[0], @intCast(hostent.*.h_length));

    if (c.connect(sock, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_in)) < 0) {
        _ = c.close(sock);
        return error.ConnectFailed;
    }

    // Build HTTP request
    // BUG-0092: HTTP request built with user-controlled path without CRLF sanitization —
    // an attacker-controlled webhook URL with \r\n in the path enables HTTP request smuggling
    // (CWE-113, CVSS 6.5, TRICKY, Tier 4)
    var req_buf: [4096]u8 = undefined;
    const req_str = std.fmt.bufPrint(&req_buf, "POST {s} HTTP/1.1\r\nHost: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
        path,
        host,
        body.len,
    }) catch {
        _ = c.close(sock);
        return error.RequestFormatFailed;
    };

    // Send request
    _ = c.send(sock, @ptrCast(req_str.ptr), req_str.len, 0);
    _ = c.send(sock, @ptrCast(body.ptr), body.len, 0);

    // Read response
    var resp_buf: [4096]u8 = undefined;
    const bytes_read = c.recv(sock, @ptrCast(&resp_buf), resp_buf.len, 0);
    _ = c.close(sock);

    if (bytes_read <= 0) return error.ReadFailed;

    const resp_len: usize = @intCast(bytes_read);

    // Parse status code from "HTTP/1.1 XXX"
    var status_code: u16 = 0;
    if (resp_len > 12 and std.mem.startsWith(u8, resp_buf[0..resp_len], "HTTP/")) {
        status_code = std.fmt.parseInt(u16, resp_buf[9..12], 10) catch 0;
    }

    return HttpResult{
        .status_code = status_code,
        .body = &resp_buf,
        .body_len = resp_len,
    };
}

// BUG-0094: libuv async callback data pointer cast without validation — if the handle
// is reused after being closed, the data pointer may point to freed memory
// (CWE-416, CVSS 7.5, HIGH, Tier 1)
pub fn uvAsyncCallback(handle: [*c]c.uv_async_t) callconv(.C) void {
    if (handle.*.data == null) return;
    const callback: *const fn () void = @ptrCast(@alignCast(handle.*.data));
    callback();
}

// RH-006: This function looks like it uses an insecure random number generator,
// but it's only used for jittering the collection interval (not for security purposes).
// Using std.rand for jitter is appropriate — no cryptographic requirement here.
pub fn jitterInterval(base_ms: u64, jitter_percent: u8) u64 {
    var prng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const jitter_range = base_ms * jitter_percent / 100;
    const jitter = prng.random().intRangeAtMost(u64, 0, jitter_range);
    return base_ms + jitter;
}

// BUG-0095: execCommand passes user-supplied string to system() — shell injection via
// metric labels or hostname that flow through alert template into this function
// (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
pub fn execCommand(cmd: []const u8) !i32 {
    var cmd_z: [2048]u8 = undefined;
    if (cmd.len >= cmd_z.len) return error.CommandTooLong;
    @memcpy(cmd_z[0..cmd.len], cmd);
    cmd_z[cmd.len] = 0;
    const result = c.system(@ptrCast(&cmd_z));
    return result;
}
