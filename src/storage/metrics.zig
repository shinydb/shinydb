const std = @import("std");
const Allocator = std.mem.Allocator;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;

/// Database-wide metrics snapshot
pub const MetricsSnapshot = struct {
    timestamp: i64,

    // Storage metrics
    storage: StorageMetrics,

    // GC metrics
    gc: GcMetricsSnapshot,

    // Performance metrics
    performance: PerformanceMetrics,

    // Vlog metrics
    vlogs: []VlogMetrics,

    pub fn deinit(self: *MetricsSnapshot, allocator: Allocator) void {
        allocator.free(self.vlogs);
    }
};

pub const StorageMetrics = struct {
    total_entries: u64,
    total_vlogs: u16,
    total_size_bytes: u64,
    memtable_size_bytes: u64,
    index_size_bytes: u64,
    vlog_size_bytes: u64,
};

pub const GcMetricsSnapshot = struct {
    enabled: bool,
    total_runs: u64,
    total_bytes_reclaimed: u64,
    last_run_duration_ms: u64,
    last_run_timestamp: i64,
    next_run_estimate_ms: i64,
};


pub const PerformanceMetrics = struct {
    ops_per_second: f64,
    avg_read_latency_us: f64,
    avg_write_latency_us: f64,
    p99_read_latency_us: f64,
    p99_write_latency_us: f64,
};

pub const VlogMetrics = struct {
    vlog_id: u16,
    total_bytes: u64,
    live_bytes: u64,
    dead_bytes: u64,
    dead_ratio: f64,
    entry_count: u64,
    deleted_count: u64,
    last_gc_timestamp: i64,
};

/// Metrics collector and exporter
pub const MetricsCollector = struct {
    allocator: Allocator,

    // Cumulative counters
    total_reads: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_writes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_deletes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Transaction counters
    total_txn_commits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_txn_aborts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_txn_conflicts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Latency tracking (simple moving average)
    read_latency_sum_us: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    write_latency_sum_us: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    read_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    write_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Start time for ops/sec calculation
    start_time: i64,

    pub fn init(allocator: Allocator) !*MetricsCollector {
        const collector = try allocator.create(MetricsCollector);
        collector.* = MetricsCollector{
            .allocator = allocator,
            .start_time = milliTimestamp(),
        };
        return collector;
    }

    pub fn deinit(self: *MetricsCollector) void {
        self.allocator.destroy(self);
    }

    /// Record a read operation
    pub fn recordRead(self: *MetricsCollector, latency_us: u64) void {
        _ = self.total_reads.fetchAdd(1, .monotonic);
        _ = self.read_latency_sum_us.fetchAdd(latency_us, .monotonic);
        _ = self.read_count.fetchAdd(1, .monotonic);
    }

    /// Record a write operation
    pub fn recordWrite(self: *MetricsCollector, latency_us: u64) void {
        _ = self.total_writes.fetchAdd(1, .monotonic);
        _ = self.write_latency_sum_us.fetchAdd(latency_us, .monotonic);
        _ = self.write_count.fetchAdd(1, .monotonic);
    }

    /// Record a delete operation
    pub fn recordDelete(self: *MetricsCollector) void {
        _ = self.total_deletes.fetchAdd(1, .monotonic);
    }

    /// Record a transaction commit
    pub fn recordTxnCommit(self: *MetricsCollector) void {
        _ = self.total_txn_commits.fetchAdd(1, .monotonic);
    }

    /// Record a transaction abort
    pub fn recordTxnAbort(self: *MetricsCollector) void {
        _ = self.total_txn_aborts.fetchAdd(1, .monotonic);
    }

    /// Record a transaction conflict
    pub fn recordTxnConflict(self: *MetricsCollector) void {
        _ = self.total_txn_conflicts.fetchAdd(1, .monotonic);
    }

    /// Get current performance metrics
    pub fn getPerformanceMetrics(self: *MetricsCollector) PerformanceMetrics {
        const elapsed_ms = milliTimestamp() - self.start_time;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;

        const total_ops = self.total_reads.load(.monotonic) +
                         self.total_writes.load(.monotonic) +
                         self.total_deletes.load(.monotonic);

        const ops_per_sec = if (elapsed_s > 0)
            @as(f64, @floatFromInt(total_ops)) / elapsed_s
        else
            0.0;

        const read_count = self.read_count.load(.monotonic);
        const write_count = self.write_count.load(.monotonic);

        const avg_read_latency = if (read_count > 0)
            @as(f64, @floatFromInt(self.read_latency_sum_us.load(.monotonic))) / @as(f64, @floatFromInt(read_count))
        else
            0.0;

        const avg_write_latency = if (write_count > 0)
            @as(f64, @floatFromInt(self.write_latency_sum_us.load(.monotonic))) / @as(f64, @floatFromInt(write_count))
        else
            0.0;

        return PerformanceMetrics{
            .ops_per_second = ops_per_sec,
            .avg_read_latency_us = avg_read_latency,
            .avg_write_latency_us = avg_write_latency,
            .p99_read_latency_us = avg_read_latency * 2.0, // Simplified estimate
            .p99_write_latency_us = avg_write_latency * 2.0, // Simplified estimate
        };
    }

    /// Export metrics as JSON string
    pub fn exportJson(self: *MetricsCollector, snapshot: MetricsSnapshot) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        var writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"timestamp\":{d},", .{snapshot.timestamp});

        // Storage metrics
        try writer.writeAll("\"storage\":{");
        try writer.print("\"total_entries\":{d},", .{snapshot.storage.total_entries});
        try writer.print("\"total_vlogs\":{d},", .{snapshot.storage.total_vlogs});
        try writer.print("\"total_size_bytes\":{d},", .{snapshot.storage.total_size_bytes});
        try writer.print("\"memtable_size_bytes\":{d},", .{snapshot.storage.memtable_size_bytes});
        try writer.print("\"index_size_bytes\":{d},", .{snapshot.storage.index_size_bytes});
        try writer.print("\"vlog_size_bytes\":{d}", .{snapshot.storage.vlog_size_bytes});
        try writer.writeAll("},");

        // GC metrics
        try writer.writeAll("\"gc\":{");
        try writer.print("\"enabled\":{},", .{snapshot.gc.enabled});
        try writer.print("\"total_runs\":{d},", .{snapshot.gc.total_runs});
        try writer.print("\"total_bytes_reclaimed\":{d},", .{snapshot.gc.total_bytes_reclaimed});
        try writer.print("\"last_run_duration_ms\":{d},", .{snapshot.gc.last_run_duration_ms});
        try writer.print("\"last_run_timestamp\":{d}", .{snapshot.gc.last_run_timestamp});
        try writer.writeAll("},");

        // Transaction metrics
        try writer.writeAll("\"transactions\":{");
        try writer.print("\"active\":{d},", .{snapshot.transactions.active_transactions});
        try writer.print("\"total_committed\":{d},", .{snapshot.transactions.total_committed});
        try writer.print("\"total_aborted\":{d},", .{snapshot.transactions.total_aborted});
        try writer.print("\"total_conflicts\":{d}", .{snapshot.transactions.total_conflicts});
        try writer.writeAll("},");

        // Performance metrics
        try writer.writeAll("\"performance\":{");
        try writer.print("\"ops_per_second\":{d:.2},", .{snapshot.performance.ops_per_second});
        try writer.print("\"avg_read_latency_us\":{d:.2},", .{snapshot.performance.avg_read_latency_us});
        try writer.print("\"avg_write_latency_us\":{d:.2},", .{snapshot.performance.avg_write_latency_us});
        try writer.print("\"p99_read_latency_us\":{d:.2},", .{snapshot.performance.p99_read_latency_us});
        try writer.print("\"p99_write_latency_us\":{d:.2}", .{snapshot.performance.p99_write_latency_us});
        try writer.writeAll("},");

        // Vlog metrics
        try writer.writeAll("\"vlogs\":[");
        for (snapshot.vlogs, 0..) |vlog, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"id\":{d},", .{vlog.vlog_id});
            try writer.print("\"total_bytes\":{d},", .{vlog.total_bytes});
            try writer.print("\"live_bytes\":{d},", .{vlog.live_bytes});
            try writer.print("\"dead_bytes\":{d},", .{vlog.dead_bytes});
            try writer.print("\"dead_ratio\":{d:.2},", .{vlog.dead_ratio});
            try writer.print("\"entry_count\":{d},", .{vlog.entry_count});
            try writer.print("\"deleted_count\":{d}", .{vlog.deleted_count});
            try writer.writeAll("}");
        }
        try writer.writeAll("]");

        try writer.writeAll("}");

        return try self.allocator.dupe(u8, buffer.items);
    }
};
