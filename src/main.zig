const std = @import("std");
const Io = std.Io;

const Config = @import("common/config.zig").Config;
const Engine = @import("engine/engine.zig").Engine;
const Server = @import("tcp/server.zig").Server;
const SecurityManager = @import("storage/security.zig").SecurityManager;
const common = @import("common/common.zig");

const log = std.log.scoped(.main);

/// Direct engine benchmark - bypasses TCP layer
fn benchmarkEngine(allocator: std.mem.Allocator, config: *Config, io: Io) !void {
    std.debug.print("\n============================================================\n", .{});
    std.debug.print("Direct Engine Write Benchmark\n", .{});
    std.debug.print("============================================================\n", .{});
    std.debug.print("Bypassing TCP layer - measuring pure engine performance\n", .{});
    std.debug.print("Operations: 1,000,000\n", .{});
    std.debug.print("Document Size: 1024 bytes\n", .{});
    std.debug.print("============================================================\n\n", .{});

    // Initialize engine
    const engine = try Engine.init(allocator, config, io);
    defer engine.deinit();

    // Create a test space and store for benchmarking
    const store_ns = "benchmark.docs";
    {
        engine.catalog_mutex.lock();
        defer engine.catalog_mutex.unlock();
        // Create space if it doesn't exist
        _ = engine.catalog.createSpace("benchmark", "Benchmark space") catch {};
        // Create store if it doesn't exist
        _ = engine.catalog.createStore(store_ns, "Benchmark store") catch {};
    }

    const operation_count: usize = 1_000_000;

    // Generate a sample document (1KB)
    const document = "{{\"id\":0,\"name\":\"benchmark\",\"email\":\"test@example.com\",\"data\":\"" ++ "x" ** 900 ++ "\"}}";

    // Warmup
    std.debug.print("Warmup: 10,000 operations...\n", .{});
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        _ = try engine.post(store_ns, document);
    }
    std.debug.print("Warmup complete\n\n", .{});

    // Actual benchmark
    std.debug.print("Starting benchmark...\n", .{});
    const start_time = common.milliTimestamp();

    var completed: usize = 0;
    var next_progress: usize = 100_000;

    while (completed < operation_count) : (completed += 1) {
        _ = try engine.post(store_ns, document);

        if (completed >= next_progress) {
            const elapsed = common.milliTimestamp() - start_time;
            const ops_per_sec = (@as(f64, @floatFromInt(completed)) * 1000.0) / @as(f64, @floatFromInt(elapsed));
            std.debug.print("Progress: {d}/{d} ops ({d:.0} ops/sec)\n", .{
                completed,
                operation_count,
                ops_per_sec,
            });
            next_progress += 100_000;
        }
    }

    const total_time = common.milliTimestamp() - start_time;
    const ops_per_sec = (@as(f64, @floatFromInt(operation_count)) * 1000.0) / @as(f64, @floatFromInt(total_time));

    std.debug.print("\n============================================================\n", .{});
    std.debug.print("Benchmark Results\n", .{});
    std.debug.print("============================================================\n\n", .{});
    std.debug.print("Total Operations:  {d}\n", .{operation_count});
    std.debug.print("Duration:          {d}ms ({d:.2}s)\n", .{ total_time, @as(f64, @floatFromInt(total_time)) / 1000.0 });
    std.debug.print("Throughput:        {d:.2} ops/sec\n", .{ops_per_sec});
    std.debug.print("Avg Latency:       {d:.2} µs/op\n", .{(@as(f64, @floatFromInt(total_time)) * 1000.0) / @as(f64, @floatFromInt(operation_count))});
    std.debug.print("\n============================================================\n\n", .{});
}

pub fn main() !void {
    // Initialize allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize std.Io.Threaded for concurrent I/O
    // Disable async thread pool completely to avoid busy-polling
    var threaded: std.Io.Threaded = .init(allocator, .{
        .async_limit = .nothing, // No async worker threads
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Load configuration
    var config = Config.load(allocator) catch |err| {
        log.err("Failed to load config: {}", .{err});
        return err;
    };
    defer config.deinit(allocator);
    // Config ownership is transferred to db — db.deinit() frees it
    // Check for benchmark flag
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1 and std.mem.eql(u8, args[1], "--benchmark")) {
        try benchmarkEngine(allocator, config, io);
        return;
    }

    log.info("Starting ShinyDb....", .{});

    // TODO: Make security_enabled configurable via config file
    const security_enabled = true; // Enable security by default

    log.info("Using std.Io.Threaded server", .{});

    // Initialize the database engine
    const engine = Engine.init(allocator, config, io) catch |err| {
        log.err("Failed to initialize engine: {}", .{err});
        return err;
    };
    defer engine.deinit();

    // Initialize and run the TCP server
    var server = Server.init(allocator, config, io, engine, security_enabled) catch |err| {
        log.err("Failed to initialize server: {}", .{err});
        return err;
    };
    defer server.deinit();

    // Run the server (blocking - returns when shutdown is requested)
    server.run() catch |err| {
        log.err("Server error: {}", .{err});
        return err;
    };

    // Graceful engine shutdown after server has stopped
    log.info("Shutting down engine...", .{});
    engine.shutdown() catch |err| {
        log.err("Engine shutdown error: {}", .{err});
    };
}
