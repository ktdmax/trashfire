const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
});

const CpuTimes = struct {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    total: u64,
    busy: u64,
};

// BUG-0096: Previous CPU times stored in global mutable state — race condition if
// collectCpuPercent is called concurrently from timer callback and API handler
// (CWE-362, CVSS 4.0, BEST_PRACTICE, Tier 5)
var prev_times: ?CpuTimes = null;

pub fn collectCpuPercent() !f64 {
    const current = try readCpuTimes();

    if (prev_times) |prev| {
        const total_diff = current.total -| prev.total;
        const busy_diff = current.busy -| prev.busy;

        if (total_diff == 0) return 0.0;

        const percent = @as(f64, @floatFromInt(busy_diff)) / @as(f64, @floatFromInt(total_diff)) * 100.0;
        prev_times = current;
        return percent;
    }

    prev_times = current;
    return 0.0;
}

fn readCpuTimes() !CpuTimes {
    // Read /proc/stat for CPU times
    const file = std.fs.openFileAbsolute("/proc/stat", .{}) catch {
        return fallbackCpuTimes();
    };
    defer file.close();

    var buf: [1024]u8 = undefined;
    const bytes_read = file.read(&buf) catch return fallbackCpuTimes();
    const data = buf[0..bytes_read];

    // Find "cpu " line (aggregate)
    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "cpu ")) {
            return parseCpuLine(line);
        }
    }

    return error.CpuStatNotFound;
}

fn parseCpuLine(line: []const u8) !CpuTimes {
    var times = CpuTimes{
        .user = 0,
        .nice = 0,
        .system = 0,
        .idle = 0,
        .iowait = 0,
        .irq = 0,
        .softirq = 0,
        .steal = 0,
        .total = 0,
        .busy = 0,
    };

    var fields = std.mem.tokenizeScalar(u8, line, ' ');
    _ = fields.next(); // skip "cpu"

    const field_ptrs = [_]*u64{
        &times.user,
        &times.nice,
        &times.system,
        &times.idle,
        &times.iowait,
        &times.irq,
        &times.softirq,
        &times.steal,
    };

    for (field_ptrs) |ptr| {
        if (fields.next()) |field| {
            ptr.* = std.fmt.parseInt(u64, field, 10) catch 0;
        }
    }

    // BUG-0099: Total CPU time calculated by addition without overflow check — on a system
    // with very high uptime, the sum of all CPU time fields can overflow u64, wrapping to
    // a small number and producing wildly incorrect CPU percentage readings
    // (CWE-190, CVSS 4.3, TRICKY, Tier 4)
    times.total = times.user + times.nice + times.system + times.idle +
        times.iowait + times.irq + times.softirq + times.steal;
    times.busy = times.total - times.idle - times.iowait;

    return times;
}

fn fallbackCpuTimes() !CpuTimes {
    // Fallback for non-Linux systems: use getloadavg via C
    var loadavg: [3]f64 = undefined;
    const nelem = c.getloadavg(&loadavg, 3);
    if (nelem < 1) return error.LoadAvgFailed;

    // Approximate CPU times from load average
    // RH-007: This approximation looks imprecise but it's only used as a fallback on
    // non-Linux systems where /proc/stat isn't available. The values are clearly marked
    // as estimates in the Prometheus metrics output. Not a bug.
    const approx_busy: u64 = @intFromFloat(loadavg[0] * 100.0);
    return CpuTimes{
        .user = approx_busy,
        .nice = 0,
        .system = 0,
        .idle = 100 - @min(approx_busy, 100),
        .iowait = 0,
        .irq = 0,
        .softirq = 0,
        .steal = 0,
        .total = 100,
        .busy = @min(approx_busy, 100),
    };
}

// Per-core CPU collection for detailed metrics
pub fn collectPerCoreCpu(allocator: std.mem.Allocator) ![]f64 {
    const file = std.fs.openFileAbsolute("/proc/stat", .{}) catch return error.StatNotAvailable;
    defer file.close();

    // BUG-0100: Reading entire /proc/stat into a 4KB buffer — systems with many CPU cores
    // (>64) have /proc/stat larger than 4KB, silently truncating per-core data
    // (CWE-131, CVSS 3.1, BEST_PRACTICE, Tier 5)
    var buf: [4096]u8 = undefined;
    const bytes_read = file.read(&buf) catch return error.ReadFailed;
    const data = buf[0..bytes_read];

    var core_percents = std.ArrayList(f64).init(allocator);
    var lines = std.mem.splitSequence(u8, data, "\n");

    while (lines.next()) |line| {
        // Match "cpu0 ", "cpu1 ", etc.
        if (line.len > 4 and std.mem.startsWith(u8, line, "cpu") and line[3] != ' ') {
            const times = parseCpuLine(line) catch continue;
            if (times.total > 0) {
                const pct = @as(f64, @floatFromInt(times.busy)) / @as(f64, @floatFromInt(times.total)) * 100.0;
                try core_percents.append(pct);
            }
        }
    }

    return core_percents.toOwnedSlice();
}
