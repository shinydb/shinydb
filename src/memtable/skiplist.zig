const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;
const Order = std.math.Order;
const MemoryPool = @import("memory_pool.zig").MemoryPool;
const MemoryPoolConfig = @import("memory_pool.zig").MemoryPoolConfig;
const common = @import("../common/common.zig");
const OpKind = common.OpKind;
const Entry = common.Entry;
const milliTimestamp = common.milliTimestamp;

// pub const OpKind = enum(u8) {
//     insert,
//     update,
//     delete,
//     read,
// };

// pub const Entry = struct {
//     key: u128,
//     ns: []const u8,
//     value: []const u8,
//     timestamp: i64,
//     kind: OpKind,

//     pub fn size(self: Entry) usize {
//         return @sizeOf(u128) + @sizeOf(u64) + self.ns.len + @sizeOf(u64) + self.value.len + @sizeOf(i64) + 1;
//     }
// };

const Node = struct {
    key: u128,
    entry: Entry,
    level: usize,
    forward: []?*Node,

    fn init(pool: *MemoryPool, key: u128, entry: Entry, level: usize) !*Node {
        const node = try pool.create(Node);
        const forward_ptrs = try pool.alloc(?*Node, level + 1);

        node.* = Node{
            .key = key,
            .entry = entry,
            .level = level,
            .forward = forward_ptrs,
        };

        // Initialize forward pointers to null
        @memset(node.forward, null);

        return node;
    }
};

pub const SkipList = struct {
    pool: *MemoryPool,
    arena: *std.heap.ArenaAllocator,
    allocator: Allocator,
    header: ?*Node,
    max_level: usize,
    current_level: isize,
    rng: std.Random.DefaultPrng,
    count: usize,
    size: usize,

    pub fn init(allocator: std.mem.Allocator, max_level: usize, seed: u64) !*SkipList {
        var arena_state = try allocator.create(std.heap.ArenaAllocator);
      
        arena_state.* = std.heap.ArenaAllocator.init(allocator);
        const arena = arena_state.allocator();

        var self = try arena.create(SkipList);
        self.* = SkipList{
            .pool = try MemoryPool.init(arena, MemoryPoolConfig{}),
            .allocator = arena,
            .arena = arena_state,
            .header = null,
            .max_level = max_level,
            .current_level = -1,
            .rng = std.Random.DefaultPrng.init(seed),
            .count = 0,
            .size = 0,
        };
        // Create header node
        try self.createHeader();

        return self;
    }

    pub fn deinit(self: *SkipList) void {
        // Save references before arena.deinit() invalidates self
        const parent_allocator = self.arena.child_allocator;
        const arena_state = self.arena;

        // Deinit the pool (arena-allocated, but may have cleanup logic)
        self.pool.deinit();

        // Deinit the arena - frees all arena-allocated memory (including self, pool, nodes)
        arena_state.deinit();

        // Free the arena_state itself using the parent allocator
        parent_allocator.destroy(arena_state);
    }

    fn createHeader(self: *SkipList) !void {
        // Use a sentinel key - this assumes K can be undefined
        // For production, you might want to pass in a minimum key value
        const header = try Node.init(self.pool, undefined, undefined, self.max_level);
        self.header = header;
    }

    fn randomLevel(self: *SkipList) usize {
        var lvl: usize = 0;
        while (lvl < self.max_level and self.rng.random().boolean()) {
            lvl += 1;
        }
        return lvl;
    }

    fn compare(_: *SkipList, a: u128, b: u128) Order {
        return std.math.order(a, b);
    }

    pub fn post(self: *SkipList, entry: Entry) !bool {
        if (self.header == null) try self.createHeader();

        // Copy the value and namespace data using the arena allocator
        // The arena owns all data and frees it when destroyed
        const value_copy = self.allocator.dupe(u8, entry.value) catch |err| {
            std.log.err("SkipList: Failed to allocate {} bytes for value: {}", .{ entry.value.len, err });
            return err;
        };
        const ns_copy = try self.allocator.dupe(u8, entry.ns);

        var entry_copy = entry;
        entry_copy.value = value_copy;
        entry_copy.ns = ns_copy;

        var update = try self.pool.alloc(?*Node, self.max_level + 1);
        @memset(update, null);

        var current = self.header.?;

        // Find insertion point
        var i: isize = if (self.current_level >= 0) self.current_level else @as(isize, @intCast(self.max_level));
        while (i >= 0) : (i -= 1) {
            const ui = @as(usize, @intCast(i));

            // Extra safety: check current.forward is valid and ui in bounds
            if (current.forward.len == 0 or ui >= current.forward.len) {
                continue;
            }

            while (current.forward[ui] != null) {
                const next_node = current.forward[ui].?;
                const cmp = self.compare(next_node.key, entry_copy.key);
                if (cmp != .lt) break;
                current = next_node;
            }
            update[ui] = current;
        }

        const next_node = if (current.forward.len > 0) current.forward[0] else null;

        // If key already exists, update value
        if (next_node != null and self.compare(next_node.?.key, entry_copy.key) == .eq) {
            next_node.?.entry = entry_copy;
            return false; // Not a new insertion
        }

        // Create new node
        const new_level = self.randomLevel();
        if (new_level > self.current_level) {
            var j = @as(usize, @intCast(self.current_level + 1));
            while (j <= new_level and j < self.max_level + 1) : (j += 1) {
                update[j] = self.header.?;
            }
            self.current_level = @as(isize, @intCast(new_level));
        }

        const new_node = try Node.init(self.pool, entry_copy.key, entry_copy, new_level);

        // Update forward pointers
        var j: usize = 0;
        while (j <= new_level and j < self.max_level + 1) : (j += 1) {
            if (update[j] != null and update[j].?.forward.len != 0 and j < update[j].?.forward.len) {
                new_node.forward[j] = update[j].?.forward[j];
                update[j].?.forward[j] = new_node;
            }
        }

        self.count += 1;
        self.size += @sizeOf(Node) + entry_copy.size();
        return true;
    }

    pub fn get(self: *SkipList, key: u128) ?Entry {
        if (self.header == null) return null;

        var current = self.header.?;
        var i: isize = self.current_level;

        while (i >= 0) : (i -= 1) {
            const ui = @as(usize, @intCast(i));

            // Safety check: ensure we don't access out of bounds
            if (ui >= current.forward.len) {
                i -= 1;
                continue;
            }

            while (current.forward[ui] != null) {
                const next_node = current.forward[ui].?;
                const cmp = self.compare(next_node.key, key);
                if (cmp != .lt) break;
                current = next_node;
            }
        }

        const next_node = if (current.forward.len > 0) current.forward[0] else null;

        if (next_node != null and self.compare(next_node.?.key, key) == .eq) {
            if (next_node) |nxt| {
                return nxt.entry;
            }
        }

        return null;
    }

    pub fn put(self: *SkipList, key: u128, entry: Entry) !bool {
        if (self.active.get(key)) |node| {
            // Update node in place
            node.entry = entry;
            return false; // No switch
        } else {
            // Insert new node if not found
            return try self.post(key, entry, milliTimestamp(), false);
        }
    }

    pub fn del(self: *SkipList, key: u128) !void {
        if (self.header == null) return error.NotFound;

        var update = self.pool.alloc(?*Node, self.max_level + 1) catch return error.OutOfMemory;
        @memset(update, null);

        var current = self.header.?;

        // Find deletion point
        var i: isize = self.current_level;
        while (i >= 0) : (i -= 1) {
            const ui = @as(usize, @intCast(i));

            // Safety check: ensure we don't access out of bounds
            if (ui >= current.forward.len) {
                i -= 1;
                continue;
            }

            while (current.forward[ui] != null) {
                const next_node = current.forward[ui].?;
                const cmp = self.compare(next_node.key, key);
                if (cmp != .lt) break;
                current = next_node;
            }
            update[ui] = current;
        }

        const target_node = if (current.forward.len > 0) current.forward[0] else null;

        if (target_node == null or self.compare(target_node.?.key, key) != .eq) {
            return error.NotFound; // Key not found
        }

        // Update forward pointers
        var j: usize = 0;
        while (j <= @as(usize, @intCast(self.current_level)) and j < self.max_level + 1) : (j += 1) {
            if (update[j] != null and j < update[j].?.forward.len and update[j].?.forward[j] == target_node) {
                update[j].?.forward[j] = target_node.?.forward[j];
            }
        }

        // Note: In a pool allocator, we can't free individual nodes
        // The memory will be reclaimed when the pool is reset/released

        // Decrease level if necessary
        while (self.current_level > 0 and self.header.?.forward[@as(usize, @intCast(self.current_level))] == null) {
            self.current_level -= 1;
        }

        self.count -= 1;
    }

    pub fn len(self: *const SkipList) usize {
        return self.count;
    }

    pub fn isEmpty(self: *const SkipList) bool {
        return self.count == 0;
    }

    const KeyVal = struct { key: u128, value: u64 };

    /// Iterator for traversing the skiplist
    pub const Iterator = struct {
        current: ?*Node,

        pub fn next(self: *Iterator) ?Entry {
            if (self.current) |node| {
                self.current = node.forward[0];
                return node.entry;
            }
            return null;
        }
    };

    pub fn iterator(self: *SkipList) Iterator {
        const start = if (self.header) |h| h.forward[0] else null;
        return Iterator{ .current = start };
    }
};

test "basic operations" {
    const allocator = std.heap.page_allocator;
    var memtable = try SkipList.init(allocator, 16, @intCast(milliTimestamp()));
    defer memtable.deinit();

    // Test posting a new entry
    _ = try memtable.post(Entry{
        .key = 1,
        .kind = .insert,
        .ns = "namespace1",
        .value = "value1",
        .timestamp = 1,
    });
    _ = try memtable.post(Entry{
        .key = 2,
        .kind = .insert,
        .ns = "namespace2",
        .value = "value2",
        .timestamp = 2,
    });

    // Test getting an entry
    const value = memtable.get(1);
    try std.testing.expect(value != null);

    // Test deleting an entry
    try memtable.del(1);

    // Test getting an entry after delete
    const delval = memtable.get(1);
    _ = delval;
}
