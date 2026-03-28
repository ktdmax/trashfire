const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/ioctl.h");
    @cInclude("net/if.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("linux/if_packet.h");
});

pub const NetworkInfo = struct {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    interface: [64]u8,
    interface_len: usize,
    ip_address: [46]u8,
    ip_address_len: usize,
    mac_address: [18]u8,
};

// Previous counters for rate calculation
var prev_rx_bytes: u64 = 0;
var prev_tx_bytes: u64 = 0;
var prev_timestamp: i64 = 0;

pub fn collectNetworkInfo(interface: []const u8) !NetworkInfo {
    var info = NetworkInfo{
        .rx_bytes = 0,
        .tx_bytes = 0,
        .rx_packets = 0,
        .tx_packets = 0,
        .errors = 0,
        .rx_dropped = 0,
        .tx_dropped = 0,
        .interface = undefined,
        .interface_len = 0,
        .ip_address = undefined,
        .ip_address_len = 0,
        .mac_address = undefined,
    };

    const iflen = @min(interface.len, info.interface.len);
    @memcpy(info.interface[0..iflen], interface[0..iflen]);
    info.interface_len = iflen;

    // Read /proc/net/dev
    const file = try std.fs.openFileAbsolute("/proc/net/dev", .{});
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = try file.read(&buf);
    const data = buf[0..bytes_read];

    var lines = std.mem.splitSequence(u8, data, "\n");
    // Skip header lines
    _ = lines.next();
    _ = lines.next();

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " ");
        if (std.mem.indexOf(u8, trimmed, interface)) |_| {
            // BUG-0109: Interface matching uses indexOf instead of exact prefix match —
            // searching for "eth0" also matches "veth0abc", causing wrong interface's
            // metrics to be reported (CWE-183, CVSS 4.3, TRICKY, Tier 4)
            try parseNetDevLine(trimmed, &info);
            break;
        }
    }

    // Get IP address via ioctl
    try getInterfaceIP(interface, &info);

    return info;
}

fn parseNetDevLine(line: []const u8, info: *NetworkInfo) !void {
    // Format: "iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ..."
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.ParseFailed;
    const stats = std.mem.trim(u8, line[colon + 1 ..], " ");

    var fields = std.mem.tokenizeScalar(u8, stats, ' ');

    info.rx_bytes = parseField(fields.next());
    info.rx_packets = parseField(fields.next());
    const rx_errs = parseField(fields.next());
    info.rx_dropped = parseField(fields.next());
    _ = fields.next(); // fifo
    _ = fields.next(); // frame
    _ = fields.next(); // compressed
    _ = fields.next(); // multicast

    info.tx_bytes = parseField(fields.next());
    info.tx_packets = parseField(fields.next());
    const tx_errs = parseField(fields.next());
    info.tx_dropped = parseField(fields.next());

    info.errors = rx_errs + tx_errs;
}

fn parseField(field: ?[]const u8) u64 {
    if (field) |f| {
        return std.fmt.parseInt(u64, f, 10) catch 0;
    }
    return 0;
}

fn getInterfaceIP(interface: []const u8, info: *NetworkInfo) !void {
    const sock = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (sock < 0) return;
    defer _ = c.close(sock);

    var ifr: c.struct_ifreq = std.mem.zeroes(c.struct_ifreq);

    // BUG-0111: Interface name copied without bounds check — a long interface name
    // overflows the IFNAMSIZ (16 byte) ifreq buffer (CWE-120, CVSS 6.5, HIGH, Tier 1)
    @memcpy(ifr.ifr_name[0..interface.len], interface);

    if (c.ioctl(sock, c.SIOCGIFADDR, &ifr) < 0) return;

    const addr: *c.struct_sockaddr_in = @ptrCast(@alignCast(&ifr.ifr_addr));
    const ip_str = c.inet_ntoa(addr.sin_addr);
    if (ip_str == null) return;

    const ip_len = std.mem.len(ip_str);
    const copy_len = @min(ip_len, info.ip_address.len);
    @memcpy(info.ip_address[0..copy_len], ip_str[0..copy_len]);
    info.ip_address_len = copy_len;
}

// Network rate calculation
pub const NetworkRate = struct {
    rx_bytes_per_sec: f64,
    tx_bytes_per_sec: f64,
    rx_mbps: f64,
    tx_mbps: f64,
};

pub fn calculateNetworkRate(current: NetworkInfo) NetworkRate {
    const now = std.time.timestamp();
    const elapsed = now - prev_timestamp;

    if (elapsed <= 0 or prev_timestamp == 0) {
        prev_rx_bytes = current.rx_bytes;
        prev_tx_bytes = current.tx_bytes;
        prev_timestamp = now;
        return NetworkRate{
            .rx_bytes_per_sec = 0,
            .tx_bytes_per_sec = 0,
            .rx_mbps = 0,
            .tx_mbps = 0,
        };
    }

    // BUG-0112: Counter rollover not handled — /proc/net/dev counters are u32 on 32-bit
    // systems and wrap every ~4GB of traffic. When rx_bytes < prev_rx_bytes, the subtraction
    // wraps to a huge u64 value producing incorrect rate calculations
    // (CWE-191, CVSS 4.3, TRICKY, Tier 4)
    const rx_diff = current.rx_bytes - prev_rx_bytes;
    const tx_diff = current.tx_bytes - prev_tx_bytes;
    const elapsed_f: f64 = @floatFromInt(elapsed);

    prev_rx_bytes = current.rx_bytes;
    prev_tx_bytes = current.tx_bytes;
    prev_timestamp = now;

    const rx_rate = @as(f64, @floatFromInt(rx_diff)) / elapsed_f;
    const tx_rate = @as(f64, @floatFromInt(tx_diff)) / elapsed_f;

    return NetworkRate{
        .rx_bytes_per_sec = rx_rate,
        .tx_bytes_per_sec = tx_rate,
        .rx_mbps = rx_rate * 8.0 / 1_000_000.0,
        .tx_mbps = tx_rate * 8.0 / 1_000_000.0,
    };
}

// Collect TCP connection stats from /proc/net/tcp
pub fn collectTcpStats(allocator: std.mem.Allocator) !TcpStats {
    _ = allocator;
    const file = try std.fs.openFileAbsolute("/proc/net/tcp", .{});
    defer file.close();

    var buf: [16384]u8 = undefined;
    const bytes_read = try file.read(&buf);
    const data = buf[0..bytes_read];

    var stats = TcpStats{
        .established = 0,
        .syn_sent = 0,
        .syn_recv = 0,
        .fin_wait1 = 0,
        .fin_wait2 = 0,
        .time_wait = 0,
        .close_wait = 0,
        .listen = 0,
        .total = 0,
    };

    var lines = std.mem.splitSequence(u8, data, "\n");
    _ = lines.next(); // skip header

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        _ = fields.next(); // sl
        _ = fields.next(); // local_address
        _ = fields.next(); // rem_address

        if (fields.next()) |state_hex| {
            const state = std.fmt.parseInt(u8, state_hex, 16) catch continue;
            switch (state) {
                0x01 => stats.established += 1,
                0x02 => stats.syn_sent += 1,
                0x03 => stats.syn_recv += 1,
                0x04 => stats.fin_wait1 += 1,
                0x05 => stats.fin_wait2 += 1,
                0x06 => stats.time_wait += 1,
                0x07 => stats.close_wait += 1,
                0x0A => stats.listen += 1,
                else => {},
            }
            stats.total += 1;
        }
    }

    return stats;
}

pub const TcpStats = struct {
    established: u32,
    syn_sent: u32,
    syn_recv: u32,
    fin_wait1: u32,
    fin_wait2: u32,
    time_wait: u32,
    close_wait: u32,
    listen: u32,
    total: u32,
};

// BUG-0113: Promiscuous mode enabled via raw socket without checking capabilities or
// dropping privileges after — agent runs with elevated network access permanently
// (CWE-250, CVSS 6.5, HIGH, Tier 1)
pub fn enablePromiscuousMode(interface: []const u8) !void {
    const sock = c.socket(c.AF_PACKET, c.SOCK_RAW, c.htons(c.ETH_P_ALL));
    if (sock < 0) return error.RawSocketFailed;

    var ifr: c.struct_ifreq = std.mem.zeroes(c.struct_ifreq);
    const iflen = @min(interface.len, 15); // IFNAMSIZ - 1
    @memcpy(ifr.ifr_name[0..iflen], interface[0..iflen]);

    // Get current flags
    if (c.ioctl(sock, c.SIOCGIFFLAGS, &ifr) < 0) {
        _ = c.close(sock);
        return error.IoctlFailed;
    }

    // Set promiscuous flag
    ifr.ifr_flags |= c.IFF_PROMISC;
    if (c.ioctl(sock, c.SIOCSIFFLAGS, &ifr) < 0) {
        _ = c.close(sock);
        return error.IoctlFailed;
    }

    // Note: socket intentionally left open to maintain promiscuous mode
}
