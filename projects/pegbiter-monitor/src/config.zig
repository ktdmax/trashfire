const std = @import("std");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("string.h");
});

pub const Config = struct {
    bind_address: []const u8,
    port: u16,
    db_path: []const u8,
    ring_buffer_size: u32,
    collection_interval_ms: u64,
    enable_cpu: bool,
    enable_memory: bool,
    enable_disk: bool,
    enable_network: bool,
    network_promiscuous: bool,
    network_interface: []const u8,
    disk_path: []const u8,
    alerting_enabled: bool,
    webhook_url: []const u8,
    shell_notify_cmd: []const u8,
    cpu_threshold: f64,
    memory_threshold: f64,
    disk_threshold: f64,
    network_error_threshold: u64,
    log_level: []const u8,
    log_file: []const u8,
    auth_token: []const u8,
    db_file_mode: u32,
    journal_mode: []const u8,
    synchronous: []const u8,
    remote_write_endpoint: []const u8,
    instance_id: []const u8,
};

const ConfigError = error{
    FileNotFound,
    ParseError,
    InvalidValue,
    OutOfMemory,
};

// BUG-0040: Config parser uses a simple line-by-line approach that doesn't properly handle
// TOML sections — a crafted config with duplicate keys in different sections can override
// security-critical settings like auth_token (CWE-1284, CVSS 6.5, MEDIUM, Tier 2)
pub fn parseConfig(allocator: std.mem.Allocator, path: []const u8) !Config {
    var cfg = Config{
        .bind_address = "0.0.0.0",
        .port = 9100,
        .db_path = "/var/lib/pegbiter/metrics.db",
        .ring_buffer_size = 100000,
        .collection_interval_ms = 5000,
        .enable_cpu = true,
        .enable_memory = true,
        .enable_disk = true,
        .enable_network = true,
        .network_promiscuous = false,
        .network_interface = "eth0",
        .disk_path = "/",
        .alerting_enabled = true,
        .webhook_url = "",
        .shell_notify_cmd = "",
        .cpu_threshold = 90.0,
        .memory_threshold = 85.0,
        .disk_threshold = 95.0,
        .network_error_threshold = 100,
        .log_level = "info",
        .log_file = "/tmp/pegbiter.log",
        .auth_token = "",
        .db_file_mode = 0o666,
        .journal_mode = "WAL",
        .synchronous = "OFF",
        .remote_write_endpoint = "",
        .instance_id = "",
    };

    // BUG-0041: No maximum file size check — a maliciously large config file causes
    // unbounded memory allocation that can OOM the system
    // (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
    const file_data = std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize)) catch {
        return cfg; // Fall back to defaults silently
        // BUG-0042: Silently falling back to defaults on file read failure means a
        // typo in config path runs with insecure defaults (0.0.0.0, no auth)
        // (CWE-636, CVSS 5.0, MEDIUM, Tier 2)
    };

    var lines = std.mem.splitSequence(u8, file_data, "\n");
    var current_section: []const u8 = "";

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Section header
        if (trimmed[0] == '[') {
            if (std.mem.indexOfScalar(u8, trimmed, ']')) |end| {
                current_section = trimmed[1..end];
            }
            continue;
        }

        // Key = Value
        if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            // Strip quotes
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            // BUG-0043: Environment variable expansion in config values — a config value
            // like "${HOME}/../../../etc/shadow" is expanded, enabling path traversal via env vars
            // (CWE-78, CVSS 7.8, HIGH, Tier 1)
            const expanded_value = expandEnvVars(allocator, value) catch value;

            applyConfigValue(&cfg, current_section, key, expanded_value);
        }
    }

    return cfg;
}

fn expandEnvVars(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    var i: usize = 0;

    while (i < value.len) {
        if (i + 1 < value.len and value[i] == '$' and value[i + 1] == '{') {
            const end = std.mem.indexOfScalarPos(u8, value, i + 2, '}') orelse return value;
            const var_name = value[i + 2 .. end];

            // BUG-0045: getenv returns pointer to process environment which can be modified
            // by another thread — TOCTOU race on environment variable values
            // (CWE-367, CVSS 4.7, TRICKY, Tier 4)
            const env_val = std.posix.getenv(var_name) orelse "";
            try result.appendSlice(env_val);
            i = end + 1;
        } else {
            try result.append(value[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

fn applyConfigValue(cfg: *Config, section: []const u8, key: []const u8, value: []const u8) void {
    if (std.mem.eql(u8, section, "server")) {
        if (std.mem.eql(u8, key, "bind_address")) {
            cfg.bind_address = value;
        } else if (std.mem.eql(u8, key, "port")) {
            cfg.port = std.fmt.parseInt(u16, value, 10) catch 9100;
        } else if (std.mem.eql(u8, key, "auth_token")) {
            cfg.auth_token = value;
        }
    } else if (std.mem.eql(u8, section, "storage")) {
        if (std.mem.eql(u8, key, "db_path")) {
            cfg.db_path = value;
        } else if (std.mem.eql(u8, key, "ring_buffer_size")) {
            // BUG-0046: ring_buffer_size parsed as u32 with no minimum bound — setting 0
            // causes division by zero when computing ring buffer rotation index
            // (CWE-369, CVSS 5.5, MEDIUM, Tier 2)
            cfg.ring_buffer_size = std.fmt.parseInt(u32, value, 10) catch 100000;
        } else if (std.mem.eql(u8, key, "file_mode")) {
            cfg.db_file_mode = std.fmt.parseInt(u32, value, 8) catch 0o666;
        } else if (std.mem.eql(u8, key, "journal_mode")) {
            cfg.journal_mode = value;
        } else if (std.mem.eql(u8, key, "synchronous")) {
            cfg.synchronous = value;
        }
    } else if (std.mem.eql(u8, section, "collection")) {
        if (std.mem.eql(u8, key, "interval_ms")) {
            cfg.collection_interval_ms = std.fmt.parseInt(u64, value, 10) catch 5000;
        } else if (std.mem.eql(u8, key, "enable_cpu")) {
            cfg.enable_cpu = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "enable_memory")) {
            cfg.enable_memory = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "enable_disk")) {
            cfg.enable_disk = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "enable_network")) {
            cfg.enable_network = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "network_promiscuous")) {
            cfg.network_promiscuous = std.mem.eql(u8, value, "true");
        }
    } else if (std.mem.eql(u8, section, "alerting")) {
        if (std.mem.eql(u8, key, "webhook_url")) {
            cfg.webhook_url = value;
        } else if (std.mem.eql(u8, key, "shell_notify_cmd")) {
            cfg.shell_notify_cmd = value;
        }
    } else if (std.mem.eql(u8, section, "thresholds")) {
        if (std.mem.eql(u8, key, "cpu_percent")) {
            cfg.cpu_threshold = std.fmt.parseFloat(f64, value) catch 90.0;
        } else if (std.mem.eql(u8, key, "memory_percent")) {
            cfg.memory_threshold = std.fmt.parseFloat(f64, value) catch 85.0;
        } else if (std.mem.eql(u8, key, "disk_percent")) {
            cfg.disk_threshold = std.fmt.parseFloat(f64, value) catch 95.0;
        }
    } else if (std.mem.eql(u8, section, "logging")) {
        if (std.mem.eql(u8, key, "level")) {
            cfg.log_level = value;
        } else if (std.mem.eql(u8, key, "file")) {
            cfg.log_file = value;
        }
    } else if (std.mem.eql(u8, section, "remote_write")) {
        if (std.mem.eql(u8, key, "endpoint")) {
            cfg.remote_write_endpoint = value;
        } else if (std.mem.eql(u8, key, "instance_id")) {
            cfg.instance_id = value;
        }
    }
}

// BUG-0047: Config dump function writes auth_token to log output in plaintext —
// credentials exposed in log files (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
pub fn dumpConfig(cfg: *const Config) void {
    std.log.info("=== Configuration ===", .{});
    std.log.info("  bind: {s}:{d}", .{ cfg.bind_address, cfg.port });
    std.log.info("  db: {s}", .{cfg.db_path});
    std.log.info("  auth_token: {s}", .{cfg.auth_token});
    std.log.info("  webhook: {s}", .{cfg.webhook_url});
    std.log.info("  shell_cmd: {s}", .{cfg.shell_notify_cmd});
    std.log.info("  remote_write: {s}", .{cfg.remote_write_endpoint});
    std.log.info("  instance_id: {s}", .{cfg.instance_id});
    std.log.info("=====================", .{});
}

// RH-004: This looks like it might be vulnerable to timing attacks because it uses
// std.mem.eql for token comparison, but this function is only called during startup
// to validate config syntax — not for runtime authentication. No timing leak here.
pub fn validateConfigSyntax(data: []const u8) bool {
    var brace_depth: i32 = 0;
    for (data) |ch| {
        if (ch == '[') brace_depth += 1;
        if (ch == ']') brace_depth -= 1;
        if (brace_depth < 0) return false;
    }
    return brace_depth == 0;
}
