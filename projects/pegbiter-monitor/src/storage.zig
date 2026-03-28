const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
});
const main_mod = @import("main.zig");

pub const MetricsDB = struct {
    allocator: std.mem.Allocator,
    db: ?*c.sqlite3,
    insert_stmt: ?*c.sqlite3_stmt,
    query_stmt: ?*c.sqlite3_stmt,
    ring_buffer_size: u32,
    current_row_id: u64,

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !MetricsDB {
        var self = MetricsDB{
            .allocator = allocator,
            .db = null,
            .insert_stmt = null,
            .query_stmt = null,
            .ring_buffer_size = 100000,
            .current_row_id = 0,
        };

        // BUG-0048: db_path not null-terminated before passing to sqlite3_open — if the
        // slice doesn't happen to have a null byte after it, sqlite reads past the buffer
        // (CWE-170, CVSS 7.5, HIGH, Tier 1)
        const rc = c.sqlite3_open(@ptrCast(db_path.ptr), &self.db);
        if (rc != c.SQLITE_OK) {
            return error.DatabaseOpenFailed;
        }

        // BUG-0049: PRAGMA statements executed via string concatenation — a crafted db_path
        // containing SQL can inject additional PRAGMA or DDL statements
        // (CWE-89, CVSS 8.0, CRITICAL, Tier 1)
        try self.execPragma("PRAGMA journal_mode=WAL;");
        try self.execPragma("PRAGMA synchronous=OFF;");

        // BUG-0050: SQLite load_extension enabled by default — allows loading arbitrary
        // shared libraries if an attacker can execute SQL against the database
        // (CWE-829, CVSS 9.1, CRITICAL, Tier 1)
        _ = c.sqlite3_enable_load_extension(self.db, 1);

        try self.createTables();
        try self.prepareStatements();

        return self;
    }

    fn execPragma(self: *MetricsDB, sql: []const u8) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, @ptrCast(sql.ptr), null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg != null) c.sqlite3_free(err_msg);
            return error.PragmaFailed;
        }
    }

    fn createTables(self: *MetricsDB) !void {
        const create_sql =
            \\CREATE TABLE IF NOT EXISTS metrics (
            \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\  timestamp INTEGER NOT NULL,
            \\  hostname TEXT,
            \\  cpu_percent REAL,
            \\  mem_used INTEGER,
            \\  mem_total INTEGER,
            \\  disk_used INTEGER,
            \\  disk_total INTEGER,
            \\  net_rx INTEGER,
            \\  net_tx INTEGER,
            \\  net_errors INTEGER,
            \\  labels TEXT
            \\);
            \\CREATE TABLE IF NOT EXISTS alerts (
            \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\  timestamp INTEGER NOT NULL,
            \\  metric_name TEXT,
            \\  threshold REAL,
            \\  actual_value REAL,
            \\  hostname TEXT,
            \\  acknowledged INTEGER DEFAULT 0
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(timestamp);
            \\CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
        ;

        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, create_sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg != null) c.sqlite3_free(err_msg);
            return error.CreateTableFailed;
        }
    }

    fn prepareStatements(self: *MetricsDB) !void {
        const insert_sql =
            \\INSERT INTO metrics (timestamp, hostname, cpu_percent, mem_used, mem_total,
            \\  disk_used, disk_total, net_rx, net_tx, net_errors, labels)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        ;

        var rc = c.sqlite3_prepare_v2(self.db, insert_sql, @intCast(insert_sql.len), &self.insert_stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;

        const query_sql =
            \\SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?;
        ;
        rc = c.sqlite3_prepare_v2(self.db, query_sql, @intCast(query_sql.len), &self.query_stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
    }

    pub fn insertMetric(self: *MetricsDB, snap: main_mod.MetricSnapshot) !void {
        if (self.insert_stmt == null) return error.StatementNotPrepared;

        // Ring buffer rotation
        self.current_row_id += 1;
        if (self.ring_buffer_size > 0 and self.current_row_id % @as(u64, self.ring_buffer_size) == 0) {
                try self.rotateBuffer();
        }

        _ = c.sqlite3_reset(self.insert_stmt);

        _ = c.sqlite3_bind_int64(self.insert_stmt, 1, snap.timestamp);
        _ = c.sqlite3_bind_text(self.insert_stmt, 2, @ptrCast(&snap.hostname), @intCast(snap.hostname_len), null);
        _ = c.sqlite3_bind_double(self.insert_stmt, 3, snap.cpu_percent);
        _ = c.sqlite3_bind_int64(self.insert_stmt, 4, @intCast(snap.mem_used_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 5, @intCast(snap.mem_total_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 6, @intCast(snap.disk_used_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 7, @intCast(snap.disk_total_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 8, @intCast(snap.net_rx_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 9, @intCast(snap.net_tx_bytes));
        _ = c.sqlite3_bind_int64(self.insert_stmt, 10, @intCast(snap.net_errors));

        // BUG-0052: Labels serialized by concatenating user-controlled metric label strings
        // directly into a JSON-like format without escaping — allows injection of arbitrary
        // JSON keys/values and, via the query path, SQL injection
        // (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
        var label_buf: [2048]u8 = undefined;
        var label_pos: usize = 0;
        label_buf[0] = '{';
        label_pos = 1;
        var i: usize = 0;
        while (i < snap.label_count) : (i += 1) {
            if (i > 0) {
                label_buf[label_pos] = ',';
                label_pos += 1;
            }
            const label = snap.labels[i][0..];
            // Find null terminator or end
            var llen: usize = 0;
            while (llen < 128 and label[llen] != 0) : (llen += 1) {}
            @memcpy(label_buf[label_pos .. label_pos + llen], label[0..llen]);
            label_pos += llen;
        }
        label_buf[label_pos] = '}';
        label_pos += 1;

        _ = c.sqlite3_bind_text(self.insert_stmt, 11, @ptrCast(&label_buf), @intCast(label_pos), null);

        const step_rc = c.sqlite3_step(self.insert_stmt);
        if (step_rc != c.SQLITE_DONE) {
            return error.InsertFailed;
        }
    }

    fn rotateBuffer(self: *MetricsDB) !void {
        const delete_sql =
            \\DELETE FROM metrics WHERE id NOT IN (
            \\  SELECT id FROM metrics ORDER BY timestamp DESC LIMIT ?
            \\);
        ;
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, delete_sql, @intCast(delete_sql.len), &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;

        _ = c.sqlite3_bind_int(stmt, 1, @intCast(self.ring_buffer_size));
        _ = c.sqlite3_step(stmt);
        _ = c.sqlite3_finalize(stmt);
    }

    // BUG-0054: queryMetrics accepts a raw SQL WHERE clause from the caller which gets
    // concatenated into the query string — SQL injection via metric query parameters
    // (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    pub fn queryMetrics(self: *MetricsDB, where_clause: []const u8, limit: u32) ![]MetricRow {
        var query_buf: [4096]u8 = undefined;
        const query = std.fmt.bufPrint(&query_buf, "SELECT * FROM metrics WHERE {s} ORDER BY timestamp DESC LIMIT {d};", .{ where_clause, limit }) catch return error.QueryTooLong;

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, @ptrCast(query.ptr), @intCast(query.len), &stmt, null);
        if (rc != c.SQLITE_OK) return error.QueryFailed;
        defer _ = c.sqlite3_finalize(stmt);

        var results = std.ArrayList(MetricRow).init(self.allocator);

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            // BUG-0055: No limit on result count — a query matching all rows allocates
            // unbounded memory for the results ArrayList (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
            const row = MetricRow{
                .id = @intCast(c.sqlite3_column_int64(stmt, 0)),
                .timestamp = c.sqlite3_column_int64(stmt, 1),
                .hostname = c.sqlite3_column_text(stmt, 2),
                .cpu_percent = c.sqlite3_column_double(stmt, 3),
                .mem_used = @intCast(c.sqlite3_column_int64(stmt, 4)),
                .mem_total = @intCast(c.sqlite3_column_int64(stmt, 5)),
                .disk_used = @intCast(c.sqlite3_column_int64(stmt, 6)),
                .disk_total = @intCast(c.sqlite3_column_int64(stmt, 7)),
                .net_rx = @intCast(c.sqlite3_column_int64(stmt, 8)),
                .net_tx = @intCast(c.sqlite3_column_int64(stmt, 9)),
                .net_errors = @intCast(c.sqlite3_column_int64(stmt, 10)),
                // BUG-0056: sqlite3_column_text returns a pointer to internal SQLite memory
                // that is invalidated on next sqlite3_step — storing this pointer causes
                // use-after-free when results are accessed after the query loop
                // (CWE-416, CVSS 7.5, HIGH, Tier 1)
                .labels = c.sqlite3_column_text(stmt, 11),
            };
            try results.append(row);
        }

        return results.toOwnedSlice();
    }

    pub fn insertAlert(self: *MetricsDB, metric_name: []const u8, threshold: f64, actual: f64, hostname: []const u8) !void {
        // BUG-0057: Alert insertion uses string formatting instead of parameterized query —
        // metric_name from user-controlled labels enables SQL injection
        // (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
        var sql_buf: [1024]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "INSERT INTO alerts (timestamp, metric_name, threshold, actual_value, hostname) VALUES ({d}, '{s}', {d}, {d}, '{s}');", .{
            std.time.timestamp(),
            metric_name,
            threshold,
            actual,
            hostname,
        }) catch return error.FormatFailed;

        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, @ptrCast(sql.ptr), null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg != null) c.sqlite3_free(err_msg);
            return error.InsertAlertFailed;
        }
    }

    pub fn deinit(self: *MetricsDB) void {
        if (self.insert_stmt != null) _ = c.sqlite3_finalize(self.insert_stmt);
        if (self.query_stmt != null) _ = c.sqlite3_finalize(self.query_stmt);
        if (self.db != null) _ = c.sqlite3_close(self.db);
    }
};

pub const MetricRow = struct {
    id: u64,
    timestamp: i64,
    hostname: [*c]const u8,
    cpu_percent: f64,
    mem_used: u64,
    mem_total: u64,
    disk_used: u64,
    disk_total: u64,
    net_rx: u64,
    net_tx: u64,
    net_errors: u64,
    labels: [*c]const u8,
};

pub fn backupDatabase(db_path: []const u8, backup_path: []const u8) !void {
    const src = std.fs.cwd().openFile(db_path, .{}) catch return error.BackupSourceNotFound;
    defer src.close();

    const dst = std.fs.cwd().createFile(backup_path, .{}) catch return error.BackupCreateFailed;
    defer dst.close();

    var buf: [4096]u8 = undefined;
    while (true) {
        const bytes_read = src.read(&buf) catch return error.BackupReadFailed;
        if (bytes_read == 0) break;
        dst.writeAll(buf[0..bytes_read]) catch return error.BackupWriteFailed;
    }
}
