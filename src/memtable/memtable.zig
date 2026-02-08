const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const SkipList = @import("skiplist.zig").SkipList;
const SkipLists = @import("skiplists.zig").SkipLists;
const MemoryPool = @import("memory_pool.zig").MemoryPool;
const MemoryPoolConfig = @import("memory_pool.zig").MemoryPoolConfig;
const common = @import("../common/common.zig");
const Entry = common.Entry;
const milliTimestamp = common.milliTimestamp;

const log = std.log.scoped(.memtable);

pub const MemTable = struct {
    allocator: Allocator,
    active: *SkipList, // Pointer to the active SkipList
    lists: *SkipLists,
    size_threshold: u64,

    pub fn init(allocator: Allocator, size_threshold: u64) !*MemTable {
        const memtable = try allocator.create(MemTable);

        memtable.allocator = allocator;
        memtable.size_threshold = size_threshold;
        memtable.active = try SkipList.init(allocator, 64, @intCast(milliTimestamp()));
        memtable.lists = try SkipLists.init(allocator);
        return memtable;
    }

    pub fn deinit(self: *MemTable) void {
        // Free the active skiplist
        self.active.deinit();
        // Free inactive skiplists and the lists container
        self.lists.deinit();
        self.allocator.destroy(self);
    }

    /// post: fast ingestion, always inserts a new node
    pub fn post(self: *MemTable, entry: Entry) !bool {
        var switched: bool = false;
        if (self.active.size >= self.size_threshold) {
            // Push the current active tree to the list
            self.lists.push(self.active) catch |err| {
                log.err("Failed to push SkipList: {s}", .{@errorName(err)});
                return err;
            };
            // Switch to a new SkipList
            self.active = try SkipList.init(self.allocator, 64, @intCast(milliTimestamp()));
            switched = true;
        }
        const was_new = self.active.post(entry) catch |err| {
            log.err("Failed to post key in MemTable: {s}", .{@errorName(err)});
            return err;
        };
        _ = was_new;

        return switched;
    }

    pub fn put(self: *MemTable, key: i128, value: []const u8, timestamp: i64) !bool {
        const entry = Entry{
            .key = @bitCast(key),
            .ns = "",
            .value = value,
            .timestamp = timestamp,
            .kind = .update,
        };
        if (self.active.get(@bitCast(key))) |old_entry| {
            // Free old value since we're replacing it
            _ = old_entry;
            // Delete and reinsert with updated value
            try self.del(key);
            return try self.post(entry);
        } else {
            // Insert new node if not found
            return try self.post(entry);
        }
    }

    pub fn get(self: *MemTable, key: i128) ![]const u8 {
        // First check active skiplist
        if (self.active.get(@bitCast(key))) |node| {
            if (node.kind == .delete) {
                return error.NotFound;
            }
            return node.value;
        }

        // Then check inactive skiplists (most recent first)
        var i: usize = self.lists.len;
        while (i > 0) {
            i -= 1;
            if (try self.lists.get(i)) |skl| {
                if (skl.get(@bitCast(key))) |node| {
                    if (node.kind == .delete) {
                        return error.NotFound;
                    }
                    return node.value;
                }
            }
        }

        return error.NotFound;
    }

    pub fn del(self: *MemTable, key: i128) !void {
        _ = self.active.del(@bitCast(key));
    }

    /// Get current size of active skiplist
    pub fn activeSize(self: *const MemTable) u64 {
        return self.active.size;
    }

    /// Get number of inactive skiplists pending flush
    pub fn pendingFlushCount(self: *const MemTable) usize {
        return self.lists.len;
    }

    /// Force switch active skiplist to inactive for on-demand flush
    /// This allows flushing data even when threshold isn't reached
    pub fn switchActive(self: *MemTable) !void {
        if (self.active.count > 0) {
            // Push current active to inactive list
            try self.lists.push(self.active);
            // Create new empty active skiplist
            self.active = try SkipList.init(self.allocator, 64, @intCast(milliTimestamp()));
        }
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "MemTable - init and deinit" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    try testing.expectEqual(@as(u64, 1000), mt.size_threshold);
    try testing.expectEqual(@as(u64, 0), mt.activeSize());
    try testing.expectEqual(@as(usize, 0), mt.pendingFlushCount());
}

test "MemTable - put and get" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    const value = "test_value";
    _ = try mt.put(42, value, 1000);

    const retrieved = try mt.get(42);
    try testing.expectEqualStrings(value, retrieved);
}

test "MemTable - get nonexistent key returns NotFound" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    const result = mt.get(999);
    try testing.expectError(error.NotFound, result);
}

test "MemTable - put updates existing key" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(42, "first_value", 1000);
    _ = try mt.put(42, "second_value", 2000);

    const retrieved = try mt.get(42);
    try testing.expectEqualStrings("second_value", retrieved);
}

test "MemTable - del marks key as deleted" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(42, "value", 1000);
    try mt.del(42);

    const result = mt.get(42);
    try testing.expectError(error.NotFound, result);
}

test "MemTable - multiple keys" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(1, "one", 1000);
    _ = try mt.put(2, "two", 1001);
    _ = try mt.put(3, "three", 1002);

    try testing.expectEqualStrings("one", try mt.get(1));
    try testing.expectEqualStrings("two", try mt.get(2));
    try testing.expectEqualStrings("three", try mt.get(3));
}

test "MemTable - activeSize increases with puts" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    const initial_size = mt.activeSize();
    _ = try mt.put(1, "value", 1000);

    try testing.expect(mt.activeSize() > initial_size);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "MemTable - empty value" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(1, "", 1000); // Empty value
    const retrieved = try mt.get(1);
    try testing.expectEqualStrings("", retrieved);
}

test "MemTable - large value" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 100000);
    defer mt.deinit();

    // Create a large value (1KB)
    var large_value: [1024]u8 = undefined;
    @memset(&large_value, 'X');

    _ = try mt.put(1, &large_value, 1000);
    const retrieved = try mt.get(1);
    try testing.expectEqual(@as(usize, 1024), retrieved.len);
}

test "MemTable - negative key" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(-1, "negative", 1000);
    const retrieved = try mt.get(-1);
    try testing.expectEqualStrings("negative", retrieved);
}

test "MemTable - zero key" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(0, "zero", 1000);
    const retrieved = try mt.get(0);
    try testing.expectEqualStrings("zero", retrieved);
}

test "MemTable - max i128 key" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    const max_key: i128 = std.math.maxInt(i128);
    _ = try mt.put(max_key, "max", 1000);
    const retrieved = try mt.get(max_key);
    try testing.expectEqualStrings("max", retrieved);
}

test "MemTable - min i128 key" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    const min_key: i128 = std.math.minInt(i128);
    _ = try mt.put(min_key, "min", 1000);
    const retrieved = try mt.get(min_key);
    try testing.expectEqualStrings("min", retrieved);
}

test "MemTable - delete nonexistent key does not error" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    // Deleting a key that doesn't exist should not panic
    try mt.del(999);
}

test "MemTable - put same key multiple times" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(1, "first", 1000);
    _ = try mt.put(1, "second", 2000);
    _ = try mt.put(1, "third", 3000);

    const retrieved = try mt.get(1);
    try testing.expectEqualStrings("third", retrieved);
}

test "MemTable - delete then reinsert" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    _ = try mt.put(1, "original", 1000);
    try mt.del(1);
    try testing.expectError(error.NotFound, mt.get(1));

    _ = try mt.put(1, "reinserted", 2000);
    const retrieved = try mt.get(1);
    try testing.expectEqualStrings("reinserted", retrieved);
}

test "MemTable - minimum size threshold" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1); // Minimum threshold
    defer mt.deinit();

    try testing.expectEqual(@as(u64, 1), mt.size_threshold);
}

test "MemTable - pendingFlushCount starts at zero" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    try testing.expectEqual(@as(usize, 0), mt.pendingFlushCount());
}
