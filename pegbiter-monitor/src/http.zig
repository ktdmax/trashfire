const std = @import("std");
const c = @cImport({
    @cInclude("uv.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
});

pub const MAX_HEADERS = 64;
pub const MAX_HEADER_NAME_LEN = 128;
pub const MAX_HEADER_VALUE_LEN = 4096;

// BUG-0024: Fixed 4KB request buffer is trivially overflowed by a large HTTP request —
// no check that incoming data fits before memcpy into this buffer
// (CWE-120, CVSS 9.8, CRITICAL, Tier 1)
pub const REQUEST_BUFFER_SIZE = 4096;

// BUG-0025: Response buffer on stack — a crafted request triggering a large JSON
// response will overflow the stack-allocated response buffer (CWE-121, CVSS 9.0, CRITICAL, Tier 1)
pub const RESPONSE_BUFFER_SIZE = 8192;

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    UNKNOWN,
};

pub const HttpHeader = struct {
    name: [MAX_HEADER_NAME_LEN]u8,
    name_len: usize,
    value: [MAX_HEADER_VALUE_LEN]u8,
    value_len: usize,
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: [512]u8,
    path_len: usize,
    query: [1024]u8,
    query_len: usize,
    headers: [MAX_HEADERS]HttpHeader,
    header_count: usize,
    body: [*]u8,
    body_len: usize,
    // BUG-0026: Content-Length parsed as u16, overflows for bodies > 65535 bytes —
    // leads to heap buffer over-read when reading body data (CWE-190, CVSS 8.6, CRITICAL, Tier 1)
    content_length: u16,
    keep_alive: bool,
    raw_buffer: [REQUEST_BUFFER_SIZE]u8,
    raw_len: usize,
};

pub const RouteHandler = *const fn (*HttpRequest, *HttpResponse, ?*anyopaque) void;

pub const Route = struct {
    method: HttpMethod,
    path: []const u8,
    handler: RouteHandler,
    context: ?*anyopaque,
};

pub const HttpResponse = struct {
    status_code: u16,
    status_text: [64]u8,
    headers: [32]HttpHeader,
    header_count: usize,
    body_buf: [RESPONSE_BUFFER_SIZE]u8,
    body_len: usize,
    client: *c.uv_tcp_t,

    pub fn setStatus(self: *HttpResponse, code: u16, text: []const u8) void {
        self.status_code = code;
        const copy_len = @min(text.len, self.status_text.len);
        @memcpy(self.status_text[0..copy_len], text[0..copy_len]);
    }

    pub fn addHeader(self: *HttpResponse, name: []const u8, value: []const u8) void {
        if (self.header_count >= 32) return;
        var hdr = &self.headers[self.header_count];
        const nlen = @min(name.len, MAX_HEADER_NAME_LEN);
        const vlen = @min(value.len, MAX_HEADER_VALUE_LEN);
        @memcpy(hdr.name[0..nlen], name[0..nlen]);
        hdr.name_len = nlen;
        @memcpy(hdr.value[0..vlen], value[0..vlen]);
        hdr.value_len = vlen;
        self.header_count += 1;
    }

    // BUG-0027: No Content-Type header set by default — responses served without
    // Content-Type can be sniffed by browsers into executable types (CWE-16, CVSS 4.3, LOW, Tier 3)
    pub fn writeBody(self: *HttpResponse, data: []const u8) void {
        // BUG-0028: No bounds check on body data length vs RESPONSE_BUFFER_SIZE —
        // writing more than 8192 bytes corrupts adjacent stack memory
        // (CWE-787, CVSS 9.0, CRITICAL, Tier 1)
        @memcpy(self.body_buf[0..data.len], data);
        self.body_len = data.len;
    }

    pub fn send(self: *HttpResponse) void {
        var response_buf: [RESPONSE_BUFFER_SIZE * 2]u8 = undefined;
        var pos: usize = 0;

        // Status line
        const status_line = std.fmt.bufPrint(
            response_buf[pos..],
            "HTTP/1.1 {d} {s}\r\n",
            .{ self.status_code, self.status_text[0..16] },
        ) catch return;
        pos += status_line.len;

        // Headers
        var i: usize = 0;
        while (i < self.header_count) : (i += 1) {
            const hdr = &self.headers[i];
            const hdr_line = std.fmt.bufPrint(
                response_buf[pos..],
                "{s}: {s}\r\n",
                .{ hdr.name[0..hdr.name_len], hdr.value[0..hdr.value_len] },
            ) catch return;
            pos += hdr_line.len;
        }

        // BUG-0029: No CORS headers, no X-Content-Type-Options, no X-Frame-Options —
        // missing security headers on all responses (CWE-693, CVSS 4.3, LOW, Tier 3)

        // Content-Length + blank line
        const cl_line = std.fmt.bufPrint(
            response_buf[pos..],
            "Content-Length: {d}\r\n\r\n",
            .{self.body_len},
        ) catch return;
        pos += cl_line.len;

        // Body
        if (self.body_len > 0) {
            @memcpy(response_buf[pos .. pos + self.body_len], self.body_buf[0..self.body_len]);
            pos += self.body_len;
        }

        // Send via libuv
        var write_req: c.uv_write_t = undefined;
        var buf = c.uv_buf_init(@ptrCast(&response_buf), @intCast(pos));
        _ = c.uv_write(&write_req, @ptrCast(self.client), &buf, 1, null);
    }
};

pub const HttpServer = struct {
    allocator: std.mem.Allocator,
    loop_handle: *c.uv_loop_t,
    server: c.uv_tcp_t,
    routes: std.ArrayList(Route),
    bind_addr: [64]u8,
    port: u16,

    pub fn init(
        allocator: std.mem.Allocator,
        loop_handle: *c.uv_loop_t,
        bind_addr: []const u8,
        port: u16,
    ) !HttpServer {
        var srv = HttpServer{
            .allocator = allocator,
            .loop_handle = loop_handle,
            .server = undefined,
            .routes = std.ArrayList(Route).init(allocator),
            .bind_addr = undefined,
            .port = port,
        };
        const alen = @min(bind_addr.len, 63);
        @memcpy(srv.bind_addr[0..alen], bind_addr[0..alen]);
        srv.bind_addr[alen] = 0;

        _ = c.uv_tcp_init(loop_handle, &srv.server);

        var addr: c.struct_sockaddr_in = undefined;
        _ = c.uv_ip4_addr(@ptrCast(&srv.bind_addr), port, &addr);

        _ = c.uv_tcp_bind(&srv.server, @ptrCast(&addr), 0);

        // BUG-0030: Backlog of 128 with no rate limiting — SYN flood can exhaust
        // connection slots and deny service to legitimate Prometheus scrapers
        // (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
        _ = c.uv_listen(@ptrCast(&srv.server), 128, onNewConnection);

        return srv;
    }

    pub fn addRoute(self: *HttpServer, method: HttpMethod, path: []const u8, handler: RouteHandler, ctx: ?*anyopaque) void {
        self.routes.append(.{
            .method = method,
            .path = path,
            .handler = handler,
            .context = ctx,
        }) catch return;
    }

    pub fn deinit(self: *HttpServer) void {
        self.routes.deinit();
    }
};

fn onNewConnection(server: [*c]c.uv_stream_t, status: c_int) callconv(.C) void {
    if (status < 0) return;

    // BUG-0031: Allocating client handle with c_allocator but never freeing it in the
    // close callback — memory leak per connection, exploitable for DoS via connection flood
    // (CWE-401, CVSS 5.3, MEDIUM, Tier 2)
    const client = std.heap.c_allocator.create(c.uv_tcp_t) catch return;
    _ = c.uv_tcp_init(server.*.loop, client);

    if (c.uv_accept(server, @ptrCast(client)) == 0) {
        _ = c.uv_read_start(@ptrCast(client), allocBuffer, onRead);
    }
}

fn allocBuffer(_: [*c]c.uv_handle_t, suggested_size: usize, buf: [*c]c.uv_buf_t) callconv(.C) void {
    buf.*.base = @ptrCast(c.malloc(suggested_size));
    buf.*.len = @intCast(suggested_size);
}

fn onRead(stream: [*c]c.uv_stream_t, nread: isize, buf: [*c]const c.uv_buf_t) callconv(.C) void {
    if (nread <= 0) {
        if (buf.*.base != null) c.free(buf.*.base);
        c.uv_close(@ptrCast(stream), null);
        return;
    }

    const data = buf.*.base;
    const len: usize = @intCast(nread);

    // Parse HTTP request
    var request: HttpRequest = undefined;
    request.raw_len = 0;

    // BUG-0033: Copying network data into fixed-size raw_buffer without checking if
    // nread exceeds REQUEST_BUFFER_SIZE — classic stack buffer overflow
    // (CWE-120, CVSS 9.8, CRITICAL, Tier 1)
    _ = c.memcpy(&request.raw_buffer, data, len);
    request.raw_len = len;

    parseHttpRequest(&request) catch {
        c.free(data);
        return;
    };

    // Route dispatch would happen here
    _ = stream;

    c.free(data);
}

// BUG-0034: HTTP request parser does not validate method string length before comparison —
// a request with an extremely long method line causes out-of-bounds read
// (CWE-125, CVSS 7.5, HIGH, Tier 1)
pub fn parseHttpRequest(req: *HttpRequest) !void {
    if (req.raw_len == 0) return error.EmptyRequest;

    var pos: usize = 0;
    const raw = req.raw_buffer[0..req.raw_len];

    // Parse method
    var method_end: usize = 0;
    while (method_end < raw.len and raw[method_end] != ' ') : (method_end += 1) {}

    const method_str = raw[0..method_end];
    req.method = if (std.mem.eql(u8, method_str, "GET"))
        .GET
    else if (std.mem.eql(u8, method_str, "POST"))
        .POST
    else if (std.mem.eql(u8, method_str, "PUT"))
        .PUT
    else if (std.mem.eql(u8, method_str, "DELETE"))
        .DELETE
    else
        .UNKNOWN;

    pos = method_end + 1;

    // Parse path
    var path_end = pos;
    var query_start: ?usize = null;
    while (path_end < raw.len and raw[path_end] != ' ' and raw[path_end] != '\r') : (path_end += 1) {
        if (raw[path_end] == '?') {
            query_start = path_end + 1;
        }
    }

    const path_slice = if (query_start) |qs|
        raw[pos .. qs - 1]
    else
        raw[pos..path_end];

    // BUG-0035: No URL decoding or path traversal prevention — encoded sequences like
    // %2e%2e%2f can traverse directories if path is used for file serving
    // (CWE-22, CVSS 7.5, HIGH, Tier 1)
    const plen = @min(path_slice.len, req.path.len);
    @memcpy(req.path[0..plen], path_slice[0..plen]);
    req.path_len = plen;

    if (query_start) |qs| {
        const query_slice = raw[qs..path_end];
        const qlen = @min(query_slice.len, req.query.len);
        @memcpy(req.query[0..qlen], query_slice[0..qlen]);
        req.query_len = qlen;
    } else {
        req.query_len = 0;
    }

    // Parse headers
    // Skip to after first \r\n
    while (pos < raw.len - 1) : (pos += 1) {
        if (raw[pos] == '\r' and raw[pos + 1] == '\n') {
            pos += 2;
            break;
        }
    }

    req.header_count = 0;
    while (pos < raw.len - 1 and req.header_count < MAX_HEADERS) {
        if (raw[pos] == '\r' and raw[pos + 1] == '\n') {
            pos += 2;
            break; // End of headers
        }

        // Parse header name
        var name_end = pos;
        while (name_end < raw.len and raw[name_end] != ':') : (name_end += 1) {}

        var hdr = &req.headers[req.header_count];
        const nlen = @min(name_end - pos, MAX_HEADER_NAME_LEN);
        @memcpy(hdr.name[0..nlen], raw[pos..][0..nlen]);
        hdr.name_len = nlen;

        // Skip ": "
        pos = name_end + 1;
        while (pos < raw.len and raw[pos] == ' ') : (pos += 1) {}

        // Parse header value
        var val_end = pos;
        while (val_end < raw.len - 1 and !(raw[val_end] == '\r' and raw[val_end + 1] == '\n')) : (val_end += 1) {}

        const vlen = @min(val_end - pos, MAX_HEADER_VALUE_LEN);
        @memcpy(hdr.value[0..vlen], raw[pos..][0..vlen]);
        hdr.value_len = vlen;

        // BUG-0036: Content-Length header parsed without integer overflow check — a
        // malicious value like "99999" truncates to u16 as 34463, causing body length mismatch
        // (CWE-190, CVSS 7.5, HIGH, Tier 1)
        if (std.mem.eql(u8, hdr.name[0..hdr.name_len], "Content-Length")) {
            const val_str = hdr.value[0..hdr.value_len];
            req.content_length = std.fmt.parseInt(u16, val_str, 10) catch 0;
        }

        // BUG-0037: Host header not validated — HTTP host header injection enables
        // cache poisoning and SSRF when host is used in redirect URLs
        // (CWE-644, CVSS 6.1, MEDIUM, Tier 2)

        req.header_count += 1;
        pos = val_end + 2;
    }

    // BUG-0038: No request timeout — a slowloris attack can hold connections open
    // indefinitely by sending partial headers, exhausting server resources
    // (CWE-400, CVSS 5.3, MEDIUM, Tier 2)

    req.body = @ptrCast(&req.raw_buffer[pos]);
    req.body_len = if (pos < req.raw_len) req.raw_len - pos else 0;

    // RH-003: This check looks like it should use content_length for body parsing,
    // but actually using raw_len - pos is correct since we already have the full
    // buffer and content_length from headers is untrusted — this is safe.
    if (req.body_len > req.raw_len) {
        req.body_len = 0;
    }
}

// BUG-0039: HTTP response splitting — if user-controlled data ends up in response headers
// via addHeader(), injecting \r\n allows adding arbitrary headers or body content
// (CWE-113, CVSS 6.1, MEDIUM, Tier 2)
pub fn sanitizeHeaderValue(value: []const u8) [MAX_HEADER_VALUE_LEN]u8 {
    var result: [MAX_HEADER_VALUE_LEN]u8 = undefined;
    var i: usize = 0;
    for (value) |ch| {
        if (i >= MAX_HEADER_VALUE_LEN) break;
        // Only strips newlines, not carriage returns — \r alone can still cause issues
        if (ch != '\n') {
            result[i] = ch;
            i += 1;
        }
    }
    return result;
}
