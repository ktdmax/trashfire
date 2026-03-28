const std = @import("std");
const c = @cImport({
    @cInclude("sys/statvfs.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("stdio.h");
    @cInclude("dirent.h");
    @cInclude("sys/stat.h");
});

pub const DiskInfo = struct {
    total: u64,
    used: u64,
    free: u64,
    available: u64,
    inodes_total: u64,
    inodes_used: u64,
    inodes_free: u64,
    mount_point: [256]u8,
    mount_point_len: usize,
    fs_type: [64]u8,
    fs_type_len: usize,
};

pub fn collectDiskInfo(path: []const u8) !DiskInfo {
    var info = DiskInfo{
        .total = 0,
        .used = 0,
        .free = 0,
        .available = 0,
        .inodes_total = 0,
        .inodes_used = 0,
        .inodes_free = 0,
        .mount_point = undefined,
        .mount_point_len = 0,
        .fs_type = undefined,
        .fs_type_len = 0,
    };

    // BUG-0104: Path not null-terminated before passing to C statvfs — reads past buffer
    // end to find null byte, potentially accessing unmapped memory
    // (CWE-170, CVSS 5.5, MEDIUM, Tier 2)
    var stat: c.struct_statvfs = undefined;
    const rc = c.statvfs(@ptrCast(path.ptr), &stat);
    if (rc != 0) return error.StatvfsFailed;

    const block_size: u64 = @intCast(stat.f_frsize);

    // BUG-0105: Block size multiplied with block counts without overflow check — on ZFS
    // or other filesystems with very large block sizes and counts, this overflows u64
    // (CWE-190, CVSS 4.3, BEST_PRACTICE, Tier 5)
    info.total = @as(u64, stat.f_blocks) * block_size;
    info.free = @as(u64, stat.f_bfree) * block_size;
    info.available = @as(u64, stat.f_bavail) * block_size;
    info.used = info.total - info.free;

    info.inodes_total = @intCast(stat.f_files);
    info.inodes_free = @intCast(stat.f_ffree);
    info.inodes_used = info.inodes_total - info.inodes_free;

    const plen = @min(path.len, info.mount_point.len);
    @memcpy(info.mount_point[0..plen], path[0..plen]);
    info.mount_point_len = plen;

    return info;
}

// Collect all mount points
pub fn collectAllDisks(allocator: std.mem.Allocator) ![]DiskInfo {
    var disks = std.ArrayList(DiskInfo).init(allocator);

    // Read /proc/mounts for mount points
    const file = std.fs.openFileAbsolute("/proc/mounts", .{}) catch {
        // Fallback: just report root filesystem
        const root = try collectDiskInfo("/");
        try disks.append(root);
        return disks.toOwnedSlice();
    };
    defer file.close();

    // BUG-0106: /proc/mounts read into 8KB buffer — systems with many mounts (e.g., Kubernetes
    // pods with many ConfigMaps/Secrets) can exceed this, silently truncating mount list and
    // missing monitoring of critical filesystems
    // (CWE-131, CVSS 3.1, BEST_PRACTICE, Tier 5)
    var buf: [8192]u8 = undefined;
    const bytes_read = file.read(&buf) catch return disks.toOwnedSlice();
    const data = buf[0..bytes_read];

    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const device = fields.next() orelse continue;
        const mount_point = fields.next() orelse continue;
        const fs_type = fields.next() orelse continue;

        // Skip pseudo-filesystems
        if (std.mem.startsWith(u8, device, "none") or
            std.mem.startsWith(u8, device, "proc") or
            std.mem.startsWith(u8, device, "sys") or
            std.mem.startsWith(u8, device, "dev") or
            std.mem.startsWith(u8, device, "tmpfs") or
            std.mem.startsWith(u8, device, "cgroup"))
        {
            continue;
        }

        var disk = collectDiskInfo(mount_point) catch continue;

        const ftlen = @min(fs_type.len, disk.fs_type.len);
        @memcpy(disk.fs_type[0..ftlen], fs_type[0..ftlen]);
        disk.fs_type_len = ftlen;

        try disks.append(disk);
    }

    return disks.toOwnedSlice();
}

// BUG-0107: Directory size calculation follows symlinks — a symlink to / causes infinite
// recursion and stack overflow; a symlink to a large directory causes excessive disk I/O
// (CWE-61, CVSS 5.5, TRICKY, Tier 4)
pub fn calculateDirSize(dir_path: []const u8) !u64 {
    var total_size: u64 = 0;

    // Null-terminate path for C API
    var path_z: [4096]u8 = undefined;
    if (dir_path.len >= path_z.len) return error.PathTooLong;
    @memcpy(path_z[0..dir_path.len], dir_path);
    path_z[dir_path.len] = 0;

    const dir = c.opendir(@ptrCast(&path_z));
    if (dir == null) return error.OpenDirFailed;
    defer _ = c.closedir(dir);

    while (c.readdir(dir)) |entry| {
        const name_ptr: [*:0]const u8 = @ptrCast(&entry.*.d_name);
        const name = std.mem.span(name_ptr);

        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var child_path: [4096]u8 = undefined;
        const cp = std.fmt.bufPrint(&child_path, "{s}/{s}", .{ dir_path, name }) catch continue;

        // BUG-0108: Using stat instead of lstat — follows symlinks, can lead to infinite
        // loops if directory contains a symlink cycle (CWE-61, CVSS 4.0, LOW, Tier 3)
        var stat_buf: c.struct_stat = undefined;
        var cp_z: [4096]u8 = undefined;
        @memcpy(cp_z[0..cp.len], cp);
        cp_z[cp.len] = 0;

        if (c.stat(@ptrCast(&cp_z), &stat_buf) != 0) continue;

        if (stat_buf.st_mode & c.S_IFMT == c.S_IFDIR) {
            total_size += calculateDirSize(cp) catch 0;
        } else {
            total_size += @intCast(stat_buf.st_size);
        }
    }

    return total_size;
}

// Disk I/O stats from /proc/diskstats
pub const DiskIOStats = struct {
    reads_completed: u64,
    writes_completed: u64,
    read_bytes: u64,
    write_bytes: u64,
    io_in_progress: u64,
};

pub fn collectDiskIO(device_name: []const u8) !DiskIOStats {
    const file = try std.fs.openFileAbsolute("/proc/diskstats", .{});
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = try file.read(&buf);
    const data = buf[0..bytes_read];

    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        _ = fields.next(); // major
        _ = fields.next(); // minor
        const dev = fields.next() orelse continue;

        if (!std.mem.eql(u8, dev, device_name)) continue;

        return DiskIOStats{
            .reads_completed = parseFieldU64(fields.next()),
            .writes_completed = blk: {
                _ = fields.next(); // reads merged
                _ = fields.next(); // sectors read
                _ = fields.next(); // ms reading
                break :blk parseFieldU64(fields.next());
            },
            .read_bytes = 0, // Would need sector size
            .write_bytes = 0,
            .io_in_progress = blk: {
                _ = fields.next(); // writes merged
                _ = fields.next(); // sectors written
                _ = fields.next(); // ms writing
                break :blk parseFieldU64(fields.next());
            },
        };
    }

    return error.DeviceNotFound;
}

fn parseFieldU64(field: ?[]const u8) u64 {
    if (field) |f| {
        return std.fmt.parseInt(u64, f, 10) catch 0;
    }
    return 0;
}
