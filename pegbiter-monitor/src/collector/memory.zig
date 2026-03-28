const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("sys/sysinfo.h");
});

pub const MemoryInfo = struct {
    total: u64,
    used: u64,
    free: u64,
    available: u64,
    buffers: u64,
    cached: u64,
    swap_total: u64,
    swap_used: u64,
    swap_free: u64,
};

pub fn collectMemoryInfo() !MemoryInfo {
    // Try /proc/meminfo first (Linux)
    return readProcMeminfo() catch readSysinfo();
}

fn readProcMeminfo() !MemoryInfo {
    const file = try std.fs.openFileAbsolute("/proc/meminfo", .{});
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = try file.read(&buf);
    const data = buf[0..bytes_read];

    var info = MemoryInfo{
        .total = 0,
        .used = 0,
        .free = 0,
        .available = 0,
        .buffers = 0,
        .cached = 0,
        .swap_total = 0,
        .swap_used = 0,
        .swap_free = 0,
    };

    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "MemTotal:")) {
            info.total = parseMemValue(line) * 1024; // kB to bytes
        } else if (std.mem.startsWith(u8, line, "MemFree:")) {
            info.free = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "MemAvailable:")) {
            info.available = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "Buffers:")) {
            info.buffers = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "Cached:")) {
            info.cached = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "SwapTotal:")) {
            info.swap_total = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "SwapFree:")) {
            info.swap_free = parseMemValue(line) * 1024;
        }
    }

    // BUG-0101: Memory "used" calculation subtracts free+buffers+cached from total without
    // checking for underflow — in containerized environments where cgroup limits report
    // a total smaller than the sum of components, this wraps to a huge u64 value, triggering
    // false memory alerts and incorrect Prometheus metrics
    // (CWE-191, CVSS 5.5, TRICKY, Tier 4)
    info.used = info.total - info.free - info.buffers - info.cached;
    info.swap_used = info.swap_total - info.swap_free;

    return info;
}

fn parseMemValue(line: []const u8) u64 {
    // Format: "FieldName:    12345 kB"
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next(); // skip field name with colon
    if (it.next()) |val| {
        return std.fmt.parseInt(u64, val, 10) catch 0;
    }
    return 0;
}

fn readSysinfo() !MemoryInfo {
    var si: c.struct_sysinfo = undefined;
    if (c.sysinfo(&si) != 0) return error.SysinfoFailed;

    const unit: u64 = @intCast(si.mem_unit);
    return MemoryInfo{
        .total = @as(u64, si.totalram) * unit,
        .free = @as(u64, si.freeram) * unit,
        .used = (@as(u64, si.totalram) - @as(u64, si.freeram)) * unit,
        .available = @as(u64, si.freeram) * unit, // Approximation
        .buffers = @as(u64, si.bufferram) * unit,
        .cached = 0, // Not available via sysinfo
        .swap_total = @as(u64, si.totalswap) * unit,
        .swap_free = @as(u64, si.freeswap) * unit,
        .swap_used = (@as(u64, si.totalswap) - @as(u64, si.freeswap)) * unit,
    };
}

// Detailed memory breakdown for the API
pub fn collectDetailedMemory(allocator: std.mem.Allocator) ![]const u8 {
    const info = try collectMemoryInfo();

    // BUG-0103: JSON response buffer allocated with exact calculated size but the format
    // string can produce longer output than estimated for very large memory values —
    // buffer overflow on systems with > 1 TB RAM where digit counts exceed estimate
    // (CWE-131, CVSS 4.3, BEST_PRACTICE, Tier 5)
    const estimated_size = 512;
    var json_buf = try allocator.alloc(u8, estimated_size);

    const result = std.fmt.bufPrint(json_buf, "{{\"total\":{d},\"used\":{d},\"free\":{d},\"available\":{d},\"buffers\":{d},\"cached\":{d},\"swap_total\":{d},\"swap_used\":{d},\"swap_free\":{d},\"used_percent\":{d:.2}}}", .{
        info.total,
        info.used,
        info.free,
        info.available,
        info.buffers,
        info.cached,
        info.swap_total,
        info.swap_used,
        info.swap_free,
        if (info.total > 0)
            @as(f64, @floatFromInt(info.used)) / @as(f64, @floatFromInt(info.total)) * 100.0
        else
            0.0,
    }) catch return error.FormatFailed;

    _ = result;
    return json_buf;
}

// Monitor process-specific memory (self-monitoring)
pub fn collectSelfMemory() !MemoryInfo {
    // Read /proc/self/status for VmRSS, VmSize, etc.
    const file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch return error.ProcSelfNotAvailable;
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = file.read(&buf) catch return error.ReadFailed;
    const data = buf[0..bytes_read];

    var vm_rss: u64 = 0;
    var vm_size: u64 = 0;

    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "VmRSS:")) {
            vm_rss = parseMemValue(line) * 1024;
        } else if (std.mem.startsWith(u8, line, "VmSize:")) {
            vm_size = parseMemValue(line) * 1024;
        }
    }

    return MemoryInfo{
        .total = vm_size,
        .used = vm_rss,
        .free = vm_size - vm_rss,
        .available = 0,
        .buffers = 0,
        .cached = 0,
        .swap_total = 0,
        .swap_used = 0,
        .swap_free = 0,
    };
}
