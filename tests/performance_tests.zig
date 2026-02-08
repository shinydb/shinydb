const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const Dir = Io.Dir;
const Db = @import("../src/storage/db.zig").Db;
const Config = @import("../src/common/config.zig").Config;
const Index = @import("../src/storage/bptree.zig").Index;
const milliTimestamp = @import("../src/common/common.zig").milliTimestamp;

/// Performance test configuration
pub const PerfConfig = struct {
    num_operations: usize = 100_000,
    value_size: usize = 1024, // 1KB values
    num_threads: usize = 1,
    report_interval: usize = 10_000,
};

/// Performance metrics
pub const PerfMetrics = struct {
    total_operations: usize,
    duration_ms: i64,
    throughput_ops_per_sec: f64,
    avg_latency_us: f64,
    min_latency_us: i64,
    max_latency_us: i64,
    p50_latency_us: i64,
    p95_latency_us: i64,
    p99_latency_us: i64,

    pub fn print(self: PerfMetrics) void {
        std.debug.print("\n=== Performance Metrics ===\n", .{});
        std.debug.print("Total Operations:  {d}\n", .{self.total_operations});
        std.debug.print("Duration:          {d} ms\n", .{self.duration_ms});
        std.debug.print("Throughput:        {d:.2} ops/sec\n", .{self.throughput_ops_per_sec});
        std.debug.print("Average Latency:   {d:.2} μs\n", .{self.avg_latency_us});
        std.debug.print("Min Latency:       {d} μs\n", .{self.min_latency_us});
        std.debug.print("Max Latency:       {d} μs\n", .{self.max_latency_us});
        std.debug.print("P50 Latency:       {d} μs\n", .{self.p50_latency_us});
        std.debug.print("P95 Latency:       {d} μs\n", .{self.p95_latency_us});
        std.debug.print("P99 Latency:       {d} μs\n", .{self.p99_latency_us});
        std.debug.print("===========================\n\n", .{});
    }
};

/// Latency tracker
pub const LatencyTracker = struct {
    allocator: std.mem.Allocator,
    samples: std.ArrayList(i64),

    pub fn init(allocator: std.mem.Allocator) LatencyTracker {
        return LatencyTracker{
            .allocator = allocator,
            .samples = std.ArrayList(i64).init(allocator),
        };
    }

    pub fn deinit(self: *LatencyTracker) void {
        self.samples.deinit();
    }

    pub fn record(self: *LatencyTracker, latency_us: i64) !void {
        try self.samples.append(latency_us);
    }

    pub fn percentile(self: *LatencyTracker, p: f64) i64 {
        if (self.samples.items.len == 0) return 0;

        // Sort samples
        std.mem.sort(i64, self.samples.items, {}, comptime std.sort.asc(i64));

        const index = @as(usize, @intFromFloat(@as(f64, @floatFromInt(self.samples.items.len)) * p));
        const clamped = @min(index, self.samples.items.len - 1);
        return self.samples.items[clamped];
    }

    pub fn min(self: *LatencyTracker) i64 {
        if (self.samples.items.len == 0) return 0;
        var min_val = self.samples.items[0];
        for (self.samples.items) |sample| {
            if (sample < min_val) min_val = sample;
        }
        return min_val;
    }

    pub fn max(self: *LatencyTracker) i64 {
        if (self.samples.items.len == 0) return 0;
        var max_val = self.samples.items[0];
        for (self.samples.items) |sample| {
            if (sample > max_val) max_val = sample;
        }
        return max_val;
    }

    pub fn average(self: *LatencyTracker) f64 {
        if (self.samples.items.len == 0) return 0.0;
        var sum: i64 = 0;
        for (self.samples.items) |sample| {
            sum += sample;
        }
        return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(self.samples.items.len));
    }
};

/// Helper functions
fn createTestIo(allocator: std.mem.Allocator) Io.Threaded {
    return Io.Threaded.init(allocator, .{});
}

fn deleteTestDir(io: Io, path: []const u8) void {
    Dir.deleteTree(.cwd(), io, path) catch {};
}

fn createTestConfig(allocator: std.mem.Allocator, base_path: []const u8) !*Config {
    const config = try allocator.create(Config);

    var buf: [256]u8 = undefined;
    const vlog_path = try std.fmt.bufPrint(&buf, "{s}/vlog", .{base_path});
    var buf2: [256]u8 = undefined;
    const wal_path = try std.fmt.bufPrint(&buf2, "{s}/wal", .{base_path});

    config.* = Config{
        .paths = .{
            .vlog = try allocator.dupe(u8, vlog_path),
            .wal = try allocator.dupe(u8, wal_path),
        },
        .buffers = .{
            .memtable = 4 * 1024 * 1024, // 4MB
            .vlog = 100 * 1024 * 1024, // 100MB
        },
    };

    return config;
}

// Benchmark: Sequential writes
test "perf: sequential write throughput" {
    const allocator = testing.allocator;
    const test_dir = "test_perf_seq_write";
    var threaded = createTestIo(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    deleteTestDir(io, test_dir);
    defer deleteTestDir(io, test_dir);

    Dir.createDirPath(.cwd(), io, test_dir) catch {};

    const config = try createTestConfig(allocator, test_dir);
    defer {
        allocator.free(config.paths.vlog);
        allocator.free(config.paths.wal);
        allocator.destroy(config);
    }

    Dir.createDirPath(.cwd(), io, config.paths.vlog) catch {};
    Dir.createDirPath(.cwd(), io, config.paths.wal) catch {};

    const primary_index = try Index(u128, u64).init(allocator, io, 1000);
    defer primary_index.deinit();

    var db = try Db.init(allocator, config, io, primary_index);
    defer db.deinit();

    const perf_config = PerfConfig{
        .num_operations = 100_000,
        .value_size = 1024,
    };

    // Prepare value
    const value_buf = try allocator.alloc(u8, perf_config.value_size);
    defer allocator.free(value_buf);
    @memset(value_buf, 'X');

    var latency_tracker = LatencyTracker.init(allocator);
    defer latency_tracker.deinit();

    const start_time = milliTimestamp();

    var i: i128 = 0;
    while (i < perf_config.num_operations) : (i += 1) {
        const op_start = std.time.microTimestamp();

        try db.put(i, value_buf, milliTimestamp());

        const op_end = std.time.microTimestamp();
        const latency = op_end - op_start;
        try latency_tracker.record(latency);

        if (i % perf_config.report_interval == 0) {
            std.debug.print("Progress: {d}/{d}\n", .{ i, perf_config.num_operations });
        }
    }

    const end_time = milliTimestamp();
    const duration_ms = end_time - start_time;
    const throughput = (@as(f64, @floatFromInt(perf_config.num_operations)) * 1000.0) / @as(f64, @floatFromInt(duration_ms));

    const metrics = PerfMetrics{
        .total_operations = perf_config.num_operations,
        .duration_ms = duration_ms,
        .throughput_ops_per_sec = throughput,
        .avg_latency_us = latency_tracker.average(),
        .min_latency_us = latency_tracker.min(),
        .max_latency_us = latency_tracker.max(),
        .p50_latency_us = latency_tracker.percentile(0.50),
        .p95_latency_us = latency_tracker.percentile(0.95),
        .p99_latency_us = latency_tracker.percentile(0.99),
    };

    metrics.print();
}

// Benchmark: Random reads
test "perf: random read throughput" {
    const allocator = testing.allocator;
    const test_dir = "test_perf_rand_read";
    var threaded = createTestIo(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    deleteTestDir(io, test_dir);
    defer deleteTestDir(io, test_dir);

    Dir.createDirPath(.cwd(), io, test_dir) catch {};

    const config = try createTestConfig(allocator, test_dir);
    defer {
        allocator.free(config.paths.vlog);
        allocator.free(config.paths.wal);
        allocator.destroy(config);
    }

    Dir.createDirPath(.cwd(), io, config.paths.vlog) catch {};
    Dir.createDirPath(.cwd(), io, config.paths.wal) catch {};

    const primary_index = try Index(u128, u64).init(allocator, io, 1000);
    defer primary_index.deinit();

    var db = try Db.init(allocator, config, io, primary_index);
    defer db.deinit();

    const perf_config = PerfConfig{
        .num_operations = 50_000,
        .value_size = 1024,
    };

    // Pre-populate database
    std.debug.print("Pre-populating database with {d} entries...\n", .{perf_config.num_operations});
    const value_buf = try allocator.alloc(u8, perf_config.value_size);
    defer allocator.free(value_buf);
    @memset(value_buf, 'X');

    var i: i128 = 0;
    while (i < perf_config.num_operations) : (i += 1) {
        try db.put(i, value_buf, milliTimestamp());
    }

    try db.flush(); // Ensure all data is flushed

    std.debug.print("Starting read benchmark...\n", .{});

    var latency_tracker = LatencyTracker.init(allocator);
    defer latency_tracker.deinit();

    const start_time = milliTimestamp();

    var read_count: usize = 0;
    i = 0;
    while (read_count < perf_config.num_operations) : ({
        read_count += 1;
        i = (i + 1) % @as(i128, @intCast(perf_config.num_operations));
    }) {
        const op_start = std.time.microTimestamp();

        _ = db.get(i) catch |err| {
            if (err != error.NotFound) {
                return err;
            }
            continue;
        };

        const op_end = std.time.microTimestamp();
        const latency = op_end - op_start;
        try latency_tracker.record(latency);

        if (read_count % perf_config.report_interval == 0) {
            std.debug.print("Progress: {d}/{d}\n", .{ read_count, perf_config.num_operations });
        }
    }

    const end_time = milliTimestamp();
    const duration_ms = end_time - start_time;
    const throughput = (@as(f64, @floatFromInt(perf_config.num_operations)) * 1000.0) / @as(f64, @floatFromInt(duration_ms));

    const metrics = PerfMetrics{
        .total_operations = perf_config.num_operations,
        .duration_ms = duration_ms,
        .throughput_ops_per_sec = throughput,
        .avg_latency_us = latency_tracker.average(),
        .min_latency_us = latency_tracker.min(),
        .max_latency_us = latency_tracker.max(),
        .p50_latency_us = latency_tracker.percentile(0.50),
        .p95_latency_us = latency_tracker.percentile(0.95),
        .p99_latency_us = latency_tracker.percentile(0.99),
    };

    metrics.print();
}

// Benchmark: Mixed workload (70% reads, 30% writes)
test "perf: mixed workload (70% read, 30% write)" {
    const allocator = testing.allocator;
    const test_dir = "test_perf_mixed";
    var threaded = createTestIo(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    deleteTestDir(io, test_dir);
    defer deleteTestDir(io, test_dir);

    Dir.createDirPath(.cwd(), io, test_dir) catch {};

    const config = try createTestConfig(allocator, test_dir);
    defer {
        allocator.free(config.paths.vlog);
        allocator.free(config.paths.wal);
        allocator.destroy(config);
    }

    Dir.createDirPath(.cwd(), io, config.paths.vlog) catch {};
    Dir.createDirPath(.cwd(), io, config.paths.wal) catch {};

    const primary_index = try Index(u128, u64).init(allocator, io, 1000);
    defer primary_index.deinit();

    var db = try Db.init(allocator, config, io, primary_index);
    defer db.deinit();

    const perf_config = PerfConfig{
        .num_operations = 50_000,
        .value_size = 512,
    };

    const value_buf = try allocator.alloc(u8, perf_config.value_size);
    defer allocator.free(value_buf);
    @memset(value_buf, 'M');

    var latency_tracker = LatencyTracker.init(allocator);
    defer latency_tracker.deinit();

    const start_time = milliTimestamp();

    var i: usize = 0;
    while (i < perf_config.num_operations) : (i += 1) {
        const op_start = std.time.microTimestamp();

        // 70% reads, 30% writes
        if (i % 10 < 7) {
            // Read
            _ = db.get(@intCast(i % 1000)) catch {};
        } else {
            // Write
            try db.put(@intCast(i), value_buf, milliTimestamp());
        }

        const op_end = std.time.microTimestamp();
        const latency = op_end - op_start;
        try latency_tracker.record(latency);

        if (i % perf_config.report_interval == 0) {
            std.debug.print("Progress: {d}/{d}\n", .{ i, perf_config.num_operations });
        }
    }

    const end_time = milliTimestamp();
    const duration_ms = end_time - start_time;
    const throughput = (@as(f64, @floatFromInt(perf_config.num_operations)) * 1000.0) / @as(f64, @floatFromInt(duration_ms));

    const metrics = PerfMetrics{
        .total_operations = perf_config.num_operations,
        .duration_ms = duration_ms,
        .throughput_ops_per_sec = throughput,
        .avg_latency_us = latency_tracker.average(),
        .min_latency_us = latency_tracker.min(),
        .max_latency_us = latency_tracker.max(),
        .p50_latency_us = latency_tracker.percentile(0.50),
        .p95_latency_us = latency_tracker.percentile(0.95),
        .p99_latency_us = latency_tracker.percentile(0.99),
    };

    metrics.print();
}

// Benchmark: Large values (10KB)
test "perf: large value writes (10KB)" {
    const allocator = testing.allocator;
    const test_dir = "test_perf_large_values";
    var threaded = createTestIo(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    deleteTestDir(io, test_dir);
    defer deleteTestDir(io, test_dir);

    Dir.createDirPath(.cwd(), io, test_dir) catch {};

    const config = try createTestConfig(allocator, test_dir);
    defer {
        allocator.free(config.paths.vlog);
        allocator.free(config.paths.wal);
        allocator.destroy(config);
    }

    Dir.createDirPath(.cwd(), io, config.paths.vlog) catch {};
    Dir.createDirPath(.cwd(), io, config.paths.wal) catch {};

    const primary_index = try Index(u128, u64).init(allocator, io, 1000);
    defer primary_index.deinit();

    var db = try Db.init(allocator, config, io, primary_index);
    defer db.deinit();

    const perf_config = PerfConfig{
        .num_operations = 10_000,
        .value_size = 10 * 1024, // 10KB
    };

    const value_buf = try allocator.alloc(u8, perf_config.value_size);
    defer allocator.free(value_buf);
    @memset(value_buf, 'L');

    var latency_tracker = LatencyTracker.init(allocator);
    defer latency_tracker.deinit();

    const start_time = milliTimestamp();

    var i: i128 = 0;
    while (i < perf_config.num_operations) : (i += 1) {
        const op_start = std.time.microTimestamp();

        try db.put(i, value_buf, milliTimestamp());

        const op_end = std.time.microTimestamp();
        const latency = op_end - op_start;
        try latency_tracker.record(latency);

        if (i % (perf_config.report_interval / 10) == 0) {
            std.debug.print("Progress: {d}/{d}\n", .{ i, perf_config.num_operations });
        }
    }

    const end_time = milliTimestamp();
    const duration_ms = end_time - start_time;
    const throughput = (@as(f64, @floatFromInt(perf_config.num_operations)) * 1000.0) / @as(f64, @floatFromInt(duration_ms));

    const metrics = PerfMetrics{
        .total_operations = perf_config.num_operations,
        .duration_ms = duration_ms,
        .throughput_ops_per_sec = throughput,
        .avg_latency_us = latency_tracker.average(),
        .min_latency_us = latency_tracker.min(),
        .max_latency_us = latency_tracker.max(),
        .p50_latency_us = latency_tracker.percentile(0.50),
        .p95_latency_us = latency_tracker.percentile(0.95),
        .p99_latency_us = latency_tracker.percentile(0.99),
    };

    metrics.print();
}
