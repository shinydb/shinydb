const std = @import("std");
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;

/// LRU (Least Recently Used) cache for hot key-value pairs
/// Thread-safe with configurable capacity
pub fn LruCache(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        /// Doubly-linked list node for LRU ordering
        const Node = struct {
            key: K,
            value: V,
            prev: ?*Node,
            next: ?*Node,
        };

        allocator: Allocator,
        capacity: usize,
        map: std.AutoHashMap(K, *Node),

        // LRU list: head = most recent, tail = least recent
        head: ?*Node,
        tail: ?*Node,

        // Stats
        hits: u64,
        misses: u64,

        // Thread safety
        mutex: Mutex,

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .capacity = capacity,
                .map = std.AutoHashMap(K, *Node).init(allocator),
                .head = null,
                .tail = null,
                .hits = 0,
                .misses = 0,
                .mutex = .{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Free all nodes
            var node = self.head;
            while (node) |n| {
                const next = n.next;
                // Free the value if it's a slice
                if (@typeInfo(V) == .pointer) {
                    if (@typeInfo(V).pointer.size == .slice) {
                        self.allocator.free(n.value);
                    }
                }
                self.allocator.destroy(n);
                node = next;
            }
            self.map.deinit();
        }

        /// Get a value from cache (returns null on miss)
        pub fn get(self: *Self, key: K) ?V {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.map.get(key)) |node| {
                self.hits += 1;
                self.moveToFront(node);
                return node.value;
            }
            self.misses += 1;
            return null;
        }

        /// Put a value into cache (evicts LRU if at capacity)
        pub fn put(self: *Self, key: K, value: V) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check if key already exists
            if (self.map.get(key)) |node| {
                // Update existing node
                // Free old value if it's a slice
                if (@typeInfo(V) == .pointer) {
                    if (@typeInfo(V).pointer.size == .slice) {
                        self.allocator.free(node.value);
                    }
                }
                node.value = value;
                self.moveToFront(node);
                return;
            }

            // Evict if at capacity
            if (self.map.count() >= self.capacity) {
                try self.evictLru();
            }

            // Create new node
            const node = try self.allocator.create(Node);
            node.* = .{
                .key = key,
                .value = value,
                .prev = null,
                .next = null,
            };

            // Add to map and front of list
            try self.map.put(key, node);
            self.addToFront(node);
        }

        /// Remove a key from cache (for invalidation)
        pub fn remove(self: *Self, key: K) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.map.fetchRemove(key)) |kv| {
                const node = kv.value;
                self.unlinkNode(node);
                // Free value if it's a slice
                if (@typeInfo(V) == .pointer) {
                    if (@typeInfo(V).pointer.size == .slice) {
                        self.allocator.free(node.value);
                    }
                }
                self.allocator.destroy(node);
            }
        }

        /// Clear all entries
        pub fn clear(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var node = self.head;
            while (node) |n| {
                const next = n.next;
                // Free value if it's a slice
                if (@typeInfo(V) == .pointer) {
                    if (@typeInfo(V).pointer.size == .slice) {
                        self.allocator.free(n.value);
                    }
                }
                self.allocator.destroy(n);
                node = next;
            }
            self.map.clearRetainingCapacity();
            self.head = null;
            self.tail = null;
        }

        /// Get cache statistics
        pub fn getStats(self: *Self) struct { hits: u64, misses: u64, size: usize, capacity: usize } {
            self.mutex.lock();
            defer self.mutex.unlock();
            return .{
                .hits = self.hits,
                .misses = self.misses,
                .size = self.map.count(),
                .capacity = self.capacity,
            };
        }

        /// Get hit rate (0.0 to 1.0)
        pub fn getHitRate(self: *Self) f64 {
            self.mutex.lock();
            defer self.mutex.unlock();
            const total = self.hits + self.misses;
            if (total == 0) return 0.0;
            return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
        }

        // Internal: Move node to front of LRU list
        fn moveToFront(self: *Self, node: *Node) void {
            if (self.head == node) return; // Already at front

            self.unlinkNode(node);
            self.addToFront(node);
        }

        // Internal: Add node to front of list
        fn addToFront(self: *Self, node: *Node) void {
            node.prev = null;
            node.next = self.head;

            if (self.head) |h| {
                h.prev = node;
            }
            self.head = node;

            if (self.tail == null) {
                self.tail = node;
            }
        }

        // Internal: Unlink node from list
        fn unlinkNode(self: *Self, node: *Node) void {
            if (node.prev) |p| {
                p.next = node.next;
            } else {
                self.head = node.next;
            }

            if (node.next) |n| {
                n.prev = node.prev;
            } else {
                self.tail = node.prev;
            }

            node.prev = null;
            node.next = null;
        }

        // Internal: Evict least recently used entry
        fn evictLru(self: *Self) !void {
            if (self.tail) |tail| {
                _ = self.map.remove(tail.key);
                self.unlinkNode(tail);
                // Free value if it's a slice
                if (@typeInfo(V) == .pointer) {
                    if (@typeInfo(V).pointer.size == .slice) {
                        self.allocator.free(tail.value);
                    }
                }
                self.allocator.destroy(tail);
            }
        }
    };
}

// Tests
test "LruCache basic operations" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 3);
    defer cache.deinit();

    // Put and get
    try cache.put(1, 100);
    try cache.put(2, 200);
    try cache.put(3, 300);

    try std.testing.expectEqual(@as(?u32, 100), cache.get(1));
    try std.testing.expectEqual(@as(?u32, 200), cache.get(2));
    try std.testing.expectEqual(@as(?u32, 300), cache.get(3));

    // Miss
    try std.testing.expectEqual(@as(?u32, null), cache.get(4));
}

test "LruCache eviction" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 2);
    defer cache.deinit();

    try cache.put(1, 100);
    try cache.put(2, 200);
    // Should evict key 1
    try cache.put(3, 300);

    try std.testing.expectEqual(@as(?u32, null), cache.get(1));
    try std.testing.expectEqual(@as(?u32, 200), cache.get(2));
    try std.testing.expectEqual(@as(?u32, 300), cache.get(3));
}

test "LruCache LRU ordering" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 2);
    defer cache.deinit();

    try cache.put(1, 100);
    try cache.put(2, 200);
    // Access key 1 to make it most recent
    _ = cache.get(1);
    // Should evict key 2 (least recent)
    try cache.put(3, 300);

    try std.testing.expectEqual(@as(?u32, 100), cache.get(1));
    try std.testing.expectEqual(@as(?u32, null), cache.get(2));
    try std.testing.expectEqual(@as(?u32, 300), cache.get(3));
}

test "LruCache remove" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 3);
    defer cache.deinit();

    try cache.put(1, 100);
    try cache.put(2, 200);

    cache.remove(1);

    try std.testing.expectEqual(@as(?u32, null), cache.get(1));
    try std.testing.expectEqual(@as(?u32, 200), cache.get(2));
}

test "LruCache stats" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 3);
    defer cache.deinit();

    try cache.put(1, 100);
    _ = cache.get(1); // hit
    _ = cache.get(2); // miss

    const stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);
    try std.testing.expectEqual(@as(usize, 1), stats.size);
}

// ============================================================================
// Concurrency Tests
// ============================================================================

test "LruCache concurrent reads" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 100);
    defer cache.deinit();

    // Pre-populate cache
    for (0..50) |i| {
        try cache.put(@intCast(i), @intCast(i * 100));
    }

    // Spawn multiple reader threads
    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(c: *LruCache(u32, u32)) void {
                for (0..100) |j| {
                    _ = c.get(@intCast(j % 50));
                }
            }
        }.run, .{&cache});
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // Cache should still be consistent
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(usize, 50), stats.size);
}

test "LruCache concurrent writes" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 1000);
    defer cache.deinit();

    // Spawn multiple writer threads
    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(c: *LruCache(u32, u32), thread_id: usize) void {
                const base = @as(u32, @intCast(thread_id * 100));
                for (0..50) |j| {
                    c.put(base + @as(u32, @intCast(j)), @as(u32, @intCast(j))) catch {};
                }
            }
        }.run, .{ &cache, i });
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // Verify cache is consistent (no crashes, proper size)
    const stats = cache.getStats();
    try std.testing.expect(stats.size <= 1000);
}

test "LruCache concurrent read-write" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 100);
    defer cache.deinit();

    // Pre-populate
    for (0..50) |i| {
        try cache.put(@intCast(i), @intCast(i));
    }

    // Spawn mixed reader/writer threads
    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        if (i % 2 == 0) {
            // Reader
            threads[i] = try std.Thread.spawn(.{}, struct {
                fn run(c: *LruCache(u32, u32)) void {
                    for (0..100) |j| {
                        _ = c.get(@intCast(j % 100));
                    }
                }
            }.run, .{&cache});
        } else {
            // Writer
            threads[i] = try std.Thread.spawn(.{}, struct {
                fn run(c: *LruCache(u32, u32)) void {
                    for (0..50) |j| {
                        c.put(@intCast(j + 50), @intCast(j)) catch {};
                    }
                }
            }.run, .{&cache});
        }
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // Cache should be consistent
    const stats = cache.getStats();
    try std.testing.expect(stats.size <= 100);
}

test "LruCache concurrent remove" {
    const allocator = std.testing.allocator;
    var cache = LruCache(u32, u32).init(allocator, 100);
    defer cache.deinit();

    // Pre-populate
    for (0..100) |i| {
        try cache.put(@intCast(i), @intCast(i));
    }

    // Spawn threads that remove items
    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(c: *LruCache(u32, u32), thread_id: usize) void {
                const start = @as(u32, @intCast(thread_id * 25));
                for (0..25) |j| {
                    c.remove(start + @as(u32, @intCast(j)));
                }
            }
        }.run, .{ &cache, i });
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // All items should be removed
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.size);
}
