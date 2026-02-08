const std = @import("std");
const Io = std.Io;
const Yaml = @import("yaml").Yaml;

pub const Config = struct {
    address: []const u8,
    port: u16,
    max_sessions: u31,
    worker_count: u32,
    base_dir: []const u8,
    max_cores: u8,
    connection_pool: struct {
        max_queue_size: u32,
        batch_accept_size: u32,
        connection_timeout_ms: u64,
        read_timeout_ms: u64,
        write_timeout_ms: u64,
        idle_timeout_ms: u64,
        graceful_shutdown_timeout_ms: u64,
    },
    datafiles: struct {
        pool_size: u32,
        flush_interval_in_ms: u64,
    },
    buffers: struct {
        memtable: usize,
        vlog: usize,
        wal: usize,
    },
    durability: struct {
        enabled: bool,
        flush_interval_in_ms: u64,
        /// Number of writes to batch before forcing fsync (0 = sync every write)
        group_commit_count: u32 = 0,
        /// Max milliseconds to wait before forcing fsync (0 = sync every write)
        group_commit_interval_ms: u64 = 0,
    },
    file_sizes: struct {
        vlog: usize,
        wal: usize,
    },
    paths: struct {
        vlog: []const u8,
        wal: []const u8,
        index: []const u8,
    },
    index: struct {
        primary: struct {
            pool_size: u32,
        },
        secondary: struct {
            pool_size: u32,
            max_key_size: usize,
        },
    },
    cache: struct {
        enabled: bool = true,
        capacity: usize = 10000,
    } = .{},

    pub fn load(allocator: std.mem.Allocator) !*Config {
        // Use std.Io for file operations in Zig 0.16
        var threaded: Io.Threaded = .init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Read entire file content
        const content = try Io.Dir.readFileAlloc(.cwd(), io, "config.yaml", allocator, .unlimited);
        defer allocator.free(content);

        var yaml: Yaml = .{ .source = content };
        const cfg = try allocator.create(Config);
        try yaml.load(allocator);
        cfg.* = try yaml.parse(allocator, Config);
        return cfg;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "Config - cache defaults" {
    // Test that cache struct has correct defaults
    const cache: @TypeOf(@as(Config, undefined).cache) = .{};
    try std.testing.expect(cache.enabled);
    try std.testing.expectEqual(@as(usize, 10000), cache.capacity);
}

test "Config - durability group commit defaults" {
    // Test that durability has correct defaults for group commit fields
    const durability: @TypeOf(@as(Config, undefined).durability) = .{
        .enabled = true,
        .flush_interval_in_ms = 1000,
    };
    try std.testing.expectEqual(@as(u32, 0), durability.group_commit_count);
    try std.testing.expectEqual(@as(u64, 0), durability.group_commit_interval_ms);
}

test "Config - struct field types" {
    // Verify key field types for documentation purposes
    try std.testing.expectEqual(@as(usize, @sizeOf(u16)), @sizeOf(@TypeOf(@as(Config, undefined).port)));
    try std.testing.expectEqual(@as(usize, @sizeOf(u31)), @sizeOf(@TypeOf(@as(Config, undefined).max_sessions)));
    try std.testing.expectEqual(@as(usize, @sizeOf(u32)), @sizeOf(@TypeOf(@as(Config, undefined).worker_count)));
    try std.testing.expectEqual(@as(usize, @sizeOf(u8)), @sizeOf(@TypeOf(@as(Config, undefined).max_cores)));
}

test "Config - nested struct access" {
    // Verify nested struct fields are accessible
    const cfg = Config{
        .address = "127.0.0.1",
        .port = 23469,
        .max_sessions = 1000,
        .worker_count = 4,
        .base_dir = "/tmp/shinydb",
        .max_cores = 8,
        .connection_pool = .{
            .max_queue_size = 100,
            .batch_accept_size = 10,
            .connection_timeout_ms = 5000,
            .read_timeout_ms = 30000,
            .write_timeout_ms = 30000,
            .idle_timeout_ms = 60000,
            .graceful_shutdown_timeout_ms = 10000,
        },
        .datafiles = .{
            .pool_size = 16,
            .flush_interval_in_ms = 1000,
        },
        .buffers = .{
            .memtable = 64 * 1024 * 1024,
            .vlog = 32 * 1024 * 1024,
            .wal = 16 * 1024 * 1024,
        },
        .durability = .{
            .enabled = true,
            .flush_interval_in_ms = 1000,
        },
        .file_sizes = .{
            .vlog = 256 * 1024 * 1024,
            .wal = 64 * 1024 * 1024,
        },
        .paths = .{
            .vlog = "data/vlog",
            .wal = "data/wal",
            .index = "data/index",
        },
        .index = .{
            .primary = .{ .pool_size = 32 },
            .secondary = .{ .pool_size = 16, .max_key_size = 256 },
        },
    };

    try std.testing.expectEqual(@as(u16, 23469), cfg.port);
    try std.testing.expectEqual(@as(u32, 100), cfg.connection_pool.max_queue_size);
    try std.testing.expectEqual(@as(u32, 16), cfg.datafiles.pool_size);
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), cfg.buffers.memtable);
    try std.testing.expect(cfg.durability.enabled);
    try std.testing.expectEqual(@as(u32, 32), cfg.index.primary.pool_size);
    try std.testing.expect(cfg.cache.enabled); // Default value
}
