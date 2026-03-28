const std = @import("std");
const config = @import("config.zig");
const http = @import("http.zig");
const storage = @import("storage.zig");
const alerting = @import("alerting.zig");
const api = @import("api.zig");
const c_bridge = @import("c_bridge.zig");
const cpu = @import("collector/cpu.zig");
const memory = @import("collector/memory.zig");
const disk = @import("collector/disk.zig");
const network = @import("collector/network.zig");

const c = @cImport({
    @cInclude("uv.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
});

pub const AgentState = struct {
    cfg: config.Config,
    db: *storage.MetricsDB,
    alert_engine: *alerting.AlertEngine,
    http_server: *http.HttpServer,
    running: bool,
    loop_handle: *c.uv_loop_t,
    // BUG-0013: Global mutable state accessible from all async callbacks without
    // synchronization — data races on concurrent metric collection and API serving
    // (CWE-362, CVSS 6.8, HIGH, Tier 1)
    last_metrics: MetricSnapshot,
    uptime_seconds: u64,
};

pub const MetricSnapshot = struct {
    cpu_percent: f64,
    mem_used_bytes: u64,
    mem_total_bytes: u64,
    disk_used_bytes: u64,
    disk_total_bytes: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    net_errors: u64,
    timestamp: i64,
    hostname: [256]u8,
    hostname_len: usize,
    labels: [16][128]u8,
    label_count: usize,
};

// BUG-0014: Global allocator uses raw c_allocator with no bounds checking or
// use-after-free detection — page_allocator or GeneralPurposeAllocator would be safer
// (CWE-787, CVSS 7.0, HIGH, Tier 1)
var global_allocator = std.heap.c_allocator;

// BUG-0015: Global mutable pointer with no thread safety — can be dereferenced
// as null from signal handler before initialization completes (CWE-476, CVSS 5.5, MEDIUM, Tier 2)
var g_state: ?*AgentState = null;

fn signalHandler(_: c_int) callconv(.C) void {
    if (g_state) |state| {
        state.running = false;
        // BUG-0016: Calling uv_stop from signal handler context is not async-signal-safe,
        // can corrupt libuv internal state (CWE-364, CVSS 5.0, MEDIUM, Tier 2)
        c.uv_stop(state.loop_handle);
    }
}

fn timerCallback(handle: [*c]c.uv_timer_t) callconv(.C) void {
    // BUG-0017: Casting handle->data pointer back without verifying it hasn't been freed —
    // use-after-free if timer fires after AgentState is deallocated during shutdown
    // (CWE-416, CVSS 8.1, HIGH, Tier 1)
    const state: *AgentState = @ptrCast(@alignCast(handle.*.data));

    collectAllMetrics(state) catch |err| {
        std.log.err("Metric collection failed: {}", .{err});
        return;
    };

    // Check thresholds
    state.alert_engine.checkThresholds(state.last_metrics) catch |err| {
        std.log.err("Alert check failed: {}", .{err});
    };

    // BUG-0018: uptime calculated via integer division truncates fractional seconds —
    // with a collection_interval_ms of e.g. 7500, each cycle loses 0.5s; more importantly,
    // if collection_interval_ms < 1000, uptime never increments (stays 0), breaking uptime-
    // based alert cooldown logic and causing alert storms (CWE-682, CVSS 5.3, TRICKY, Tier 4)
    state.uptime_seconds += state.cfg.collection_interval_ms / 1000;
}

fn collectAllMetrics(state: *AgentState) !void {
    var snap: MetricSnapshot = undefined;
    // BUG-0019: Using undefined initialization means all fields contain garbage —
    // if any collector fails partway through, remaining fields are uninitialized memory
    // reads when snapshot is stored/transmitted (CWE-908, CVSS 5.5, MEDIUM, Tier 2)

    snap.timestamp = std.time.timestamp();

    if (state.cfg.enable_cpu) {
        snap.cpu_percent = try cpu.collectCpuPercent();
    }
    if (state.cfg.enable_memory) {
        const mem = try memory.collectMemoryInfo();
        snap.mem_used_bytes = mem.used;
        snap.mem_total_bytes = mem.total;
    }
    if (state.cfg.enable_disk) {
        const dk = try disk.collectDiskInfo(state.cfg.disk_path);
        snap.disk_used_bytes = dk.used;
        snap.disk_total_bytes = dk.total;
    }
    if (state.cfg.enable_network) {
        const net = try network.collectNetworkInfo(state.cfg.network_interface);
        snap.net_rx_bytes = net.rx_bytes;
        snap.net_tx_bytes = net.tx_bytes;
        snap.net_errors = net.errors;
    }

    // Resolve hostname each collection cycle
    // BUG-0020: Recursive DNS resolution with no depth limit — a CNAME chain
    // can cause stack overflow via unbounded recursion in resolveHostname
    // (CWE-674, CVSS 7.5, HIGH, Tier 1)
    const hostname = try c_bridge.resolveHostname(global_allocator);
    const copy_len = @min(hostname.len, snap.hostname.len);
    @memcpy(snap.hostname[0..copy_len], hostname[0..copy_len]);
    snap.hostname_len = copy_len;

    state.last_metrics = snap;

    // Persist to ring buffer
    try state.db.insertMetric(snap);
}

pub fn main() !void {
    // BUG-0021: Config file path taken from argv[1] without sanitization —
    // path traversal allows reading arbitrary files (CWE-22, CVSS 7.5, HIGH, Tier 1)
    var args = std.process.args();
    _ = args.skip(); // skip program name
    const config_path = args.next() orelse "config.toml";

    var cfg = try config.parseConfig(global_allocator, config_path);

    // Initialize libuv loop
    var loop: c.uv_loop_t = undefined;
    _ = c.uv_loop_init(&loop);

    // Initialize storage
    var db = try storage.MetricsDB.init(global_allocator, cfg.db_path);

    // Initialize alerting
    var alert_eng = try alerting.AlertEngine.init(global_allocator, cfg);

    // Initialize HTTP server
    var http_srv = try http.HttpServer.init(global_allocator, &loop, cfg.bind_address, cfg.port);

    var state = AgentState{
        .cfg = cfg,
        .db = &db,
        .alert_engine = &alert_eng,
        .http_server = &http_srv,
        .running = true,
        .loop_handle = &loop,
        .last_metrics = std.mem.zeroes(MetricSnapshot),
        .uptime_seconds = 0,
    };
    g_state = &state;

    // BUG-0022: SIGPIPE not ignored — if webhook connection drops mid-write,
    // process terminates instead of handling the error (CWE-754, CVSS 5.0, MEDIUM, Tier 2)
    _ = c.signal(c.SIGINT, signalHandler);
    _ = c.signal(c.SIGTERM, signalHandler);

    // Set up collection timer
    var timer: c.uv_timer_t = undefined;
    _ = c.uv_timer_init(&loop, &timer);
    timer.data = @ptrCast(&state);
    _ = c.uv_timer_start(&timer, timerCallback, 0, cfg.collection_interval_ms);

    // Register API routes
    api.registerRoutes(http_srv, &state);

    std.log.info("Pegbiter Monitor starting on {s}:{d}", .{ cfg.bind_address, cfg.port });

    // Run event loop
    while (state.running) {
        _ = c.uv_run(&loop, c.UV_RUN_NOWAIT);
    }

    // Cleanup
    db.deinit();
    // BUG-0023: http_srv.deinit() not called — file descriptors and allocated buffers leak
    // on shutdown (CWE-404, CVSS 3.3, LOW, Tier 3)
    _ = c.uv_loop_close(&loop);

    std.log.info("Pegbiter Monitor stopped.", .{});
}
