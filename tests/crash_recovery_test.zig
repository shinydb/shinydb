const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const Dir = Io.Dir;

const Db = @import("../src/storage/db.zig").Db;
const Config = @import("../src/common/config.zig").Config;
const Index = @import("../src/storage/bptree.zig").Index;
const milliTimestamp = @import("../src/common/common.zig").milliTimestamp;

fn createTestIo(allocator: std.mem.Allocator) Io.Threaded {
    return Io.Threaded.init(allocator, .{});
}

fn deleteTestDir(io: Io, path: []const u8) void {
    Dir.deleteTree(.cwd(), io, path) catch {};
}

fn createTestConfig(allocator: std.mem.Allocator, base_path: []const u8) !*Config {
    const config = try allocator.create(Config);

    // Create test directories
    var buf: [256]u8 = undefined;
    const vlog_path = try std.fmt.bufPrint(&buf, "{s}/vlog", .{base_path});
    const wal_path = try std.fmt.bufPrint(&buf, "{s}/wal", .{base_path});

    config.* = Config{
        .paths = .{
            .vlog = try allocator.dupe(u8, vlog_path),
            .wal = try allocator.dupe(u8, wal_path),
        },
        .buffers = .{
            .memtable = 1024 * 1024, // 1MB
            .vlog = 10 * 1024 * 1024, // 10MB
        },
    };

    return config;
}

test "crash recovery - basic put operations" {
    const allocator = testing.allocator;
    const test_dir = "test_crash_recovery_basic";
    var threaded = createTestIo(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    deleteTestDir(io, test_dir);
    defer deleteTestDir(io, test_dir);

    // Create directories
    Dir.createDirPath(.cwd(), io, test_dir) catch {};

    const config = try createTestConfig(allocator, test_dir);
    defer {
        allocator.free(config.paths.vlog);
        allocator.free(config.paths.wal);
        allocator.destroy(config);
    }

    Dir.createDirPath(.cwd(), io, config.paths.vlog) catch {};
    Dir.createDirPath(.cwd(), io, config.paths.wal) catch {};

    // Phase 1: Write data
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Write some data
        try db.put(1, "value1", milliTimestamp());
        try db.put(2, "value2", milliTimestamp());
        try db.put(3, "value3", milliTimestamp());

        // Flush to ensure WAL is written
        try db.wal.flush();

        // Simulate crash by not calling shutdown
        // (db.deinit() will clean up but WAL should persist)
    }

    // Phase 2: Recover from crash
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        // Create new DB instance - this should replay WAL
        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Verify data was recovered
        const val1 = try db.get(1);
        try testing.expectEqualStrings("value1", val1);

        const val2 = try db.get(2);
        try testing.expectEqualStrings("value2", val2);

        const val3 = try db.get(3);
        try testing.expectEqualStrings("value3", val3);
    }
}

test "crash recovery - delete operations" {
    const allocator = testing.allocator;
    const test_dir = "test_crash_recovery_delete";
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

    // Phase 1: Write and delete data
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Write data
        try db.put(1, "value1", milliTimestamp());
        try db.put(2, "value2", milliTimestamp());
        try db.put(3, "value3", milliTimestamp());

        // Delete some data
        try db.del(2, milliTimestamp());

        try db.wal.flush();
    }

    // Phase 2: Recover and verify deletion
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Key 1 and 3 should exist
        _ = try db.get(1);
        _ = try db.get(3);

        // Key 2 should be deleted
        try testing.expectError(error.NotFound, db.get(2));
    }
}

test "crash recovery - checkpoint and truncate" {
    const allocator = testing.allocator;
    const test_dir = "test_crash_recovery_checkpoint";
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

    const primary_index = try Index(u128, u64).init(allocator, io, 100);
    defer primary_index.deinit();

    var db = try Db.init(allocator, config, io, primary_index);
    defer db.deinit();

    // Write some data
    try db.put(1, "checkpoint_test_1", milliTimestamp());
    try db.put(2, "checkpoint_test_2", milliTimestamp());

    // Checkpoint - this should mark the current state as safe
    try db.wal.checkpoint();

    // Write more data after checkpoint
    try db.put(3, "after_checkpoint", milliTimestamp());

    // Truncate old WAL files
    try db.wal.truncate();

    try db.wal.flush();
}

test "crash recovery - multiple operations" {
    const allocator = testing.allocator;
    const test_dir = "test_crash_recovery_multiple";
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

    // Phase 1: Write mixed operations
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Series of operations
        try db.put(1, "initial_value", milliTimestamp());
        try db.put(2, "second_value", milliTimestamp());
        try db.put(1, "updated_value", milliTimestamp()); // Update
        try db.del(2, milliTimestamp()); // Delete
        try db.put(3, "third_value", milliTimestamp());
        try db.put(4, "fourth_value", milliTimestamp());
        try db.del(4, milliTimestamp()); // Delete

        try db.wal.flush();
    }

    // Phase 2: Recover and verify final state
    {
        const primary_index = try Index(u128, u64).init(allocator, io, 100);
        defer primary_index.deinit();

        var db = try Db.init(allocator, config, io, primary_index);
        defer db.deinit();

        // Key 1 should have updated value
        const val1 = try db.get(1);
        try testing.expectEqualStrings("updated_value", val1);

        // Key 2 and 4 should be deleted
        try testing.expectError(error.NotFound, db.get(2));
        try testing.expectError(error.NotFound, db.get(4));

        // Key 3 should exist
        const val3 = try db.get(3);
        try testing.expectEqualStrings("third_value", val3);
    }
}
