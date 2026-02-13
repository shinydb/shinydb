const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const Engine = @import("../engine/engine.zig").Engine;
const Session = @import("server.zig").Session;
const milliTimestamp = common.milliTimestamp;
const SecurityManager = @import("../storage/security.zig").SecurityManager;
const common = @import("../common/common.zig");
const MetricsSnapshot = @import("metrics_snapshot.zig").MetricsSnapshot;    


const log = std.log.scoped(.message_buffer_pool);

/// Pool of reusable message buffers to avoid per-message allocations
pub const MessageBufferPool = struct {
    allocator: Allocator,
    pool: std.ArrayList([]u8),
    mutex: Mutex,
    buffer_size: usize,
    max_size: usize,

    const Self = @This();

    pub fn init(allocator: Allocator, buffer_size: usize, pool_size: usize) !Self {
        var pool: std.ArrayList([]u8) = .empty;
        errdefer pool.deinit(allocator);

        try pool.ensureTotalCapacity(allocator, pool_size);

        return Self{
            .allocator = allocator,
            .pool = pool,
            .mutex = .{},
            .buffer_size = buffer_size,
            .max_size = pool_size,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Free all buffers in the pool
        for (self.pool.items) |buffer| {
            self.allocator.free(buffer);
        }
        self.pool.deinit(self.allocator);
    }

    /// Acquire a buffer from the pool (creates new if pool is empty)
    /// Returns a buffer that's AT LEAST needed_size bytes. Caller should only use
    /// the first needed_size bytes, but must pass back the full buffer to release().
    pub fn acquire(self: *Self, needed_size: usize) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to reuse existing buffer - prefer buffers close to the needed size
        if (self.pool.items.len > 0) {
            const buffer = self.pool.pop().?; // Force unwrap since we checked length
            // If buffer is large enough but not excessively large, reuse it
            // Allow up to 2x overhead to balance reuse vs memory waste
            if (buffer.len >= needed_size and buffer.len <= needed_size * 2) {
                // Return the full buffer, not a slice - the caller will only use
                // the first needed_size bytes but must return the full buffer
                return buffer;
            }
            // Buffer wrong size, free it and allocate new one
            self.allocator.free(buffer);
        }

        // Allocate new buffer at the needed size
        return try self.allocator.alloc(u8, needed_size);
    }

    /// Return a buffer to the pool
    pub fn release(self: *Self, buffer: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Only keep up to max_size buffers in the pool
        if (self.pool.items.len < self.max_size) {
            // Keep buffer at its current size to avoid memory bloat
            self.pool.append(self.allocator, buffer) catch {
                // If append fails, just free the buffer
                self.allocator.free(buffer);
            };
        } else {
            // Pool is full, free the buffer
            self.allocator.free(buffer);
        }
    }
};

test "MetricsSnapshot - struct layout" {
    const snapshot = MetricsSnapshot{
        .active_connections = 1,
        .queued_connections = 2,
        .total_processed = 3,
        .total_rejected = 4,
        .total_timeouts = 5,
        .total_errors = 6,
    };

    try std.testing.expectEqual(@as(u64, 1), snapshot.active_connections);
    try std.testing.expectEqual(@as(u64, 2), snapshot.queued_connections);
    try std.testing.expectEqual(@as(u64, 3), snapshot.total_processed);
    try std.testing.expectEqual(@as(u64, 4), snapshot.total_rejected);
    try std.testing.expectEqual(@as(u64, 5), snapshot.total_timeouts);
    try std.testing.expectEqual(@as(u64, 6), snapshot.total_errors);
}

test "MessageBufferPool - init and deinit" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 1024), pool.buffer_size);
    try std.testing.expectEqual(@as(usize, 10), pool.max_size);
}

test "MessageBufferPool - acquire and release" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    // Acquire a buffer
    const buf = try pool.acquire(512);
    try std.testing.expect(buf.len >= 512);

    // Release it back
    pool.release(buf);
}

test "MessageBufferPool - reuse buffers" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    // Acquire and release
    const buf1 = try pool.acquire(512);
    pool.release(buf1);

    // Acquire again - should reuse if size is appropriate
    const buf2 = try pool.acquire(256);
    defer pool.release(buf2);

    // Buffer should be reused if it fits the 2x overhead criteria
    try std.testing.expect(buf2.len >= 256);
}

test "MessageBufferPool - pool size limit" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 2);
    defer pool.deinit();

    // Acquire 3 buffers
    const buf1 = try pool.acquire(512);
    const buf2 = try pool.acquire(512);
    const buf3 = try pool.acquire(512);

    // Release all 3 - only 2 should be kept
    pool.release(buf1);
    pool.release(buf2);
    pool.release(buf3); // This one should be freed, not pooled

    // Pool should have max 2 buffers
    pool.mutex.lock();
    const pool_size = pool.pool.items.len;
    pool.mutex.unlock();
    try std.testing.expect(pool_size <= 2);
}

test "MessageBufferPool - variable size allocations" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    // Request various sizes
    const small = try pool.acquire(64);
    defer pool.release(small);
    try std.testing.expect(small.len >= 64);

    const medium = try pool.acquire(512);
    defer pool.release(medium);
    try std.testing.expect(medium.len >= 512);

    const large = try pool.acquire(4096);
    defer pool.release(large);
    try std.testing.expect(large.len >= 4096);
}

test "MessageBufferPool - concurrent access" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 100);
    defer pool.deinit();

    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(p: *MessageBufferPool) void {
                for (0..10) |_| {
                    const buf = p.acquire(256) catch continue;
                    // Simulate some work
                    @memset(buf[0..256], 0xAB);
                    p.release(buf);
                }
            }
        }.run, .{&pool});
    }

    for (&threads) |*t| {
        t.join();
    }

    // Pool should still be in valid state
    pool.mutex.lock();
    const pool_size = pool.pool.items.len;
    pool.mutex.unlock();
    try std.testing.expect(pool_size <= 100);
}

test "MessageBufferPool - zero size request" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    // Request zero size
    const buf = try pool.acquire(0);
    defer pool.release(buf);
    try std.testing.expect(buf.len == 0);
}

test "MessageBufferPool - exact size match" {
    const allocator = std.testing.allocator;
    var pool = try MessageBufferPool.init(allocator, 1024, 10);
    defer pool.deinit();

    // Request exact buffer size
    const buf = try pool.acquire(1024);
    defer pool.release(buf);
    try std.testing.expect(buf.len >= 1024);
}
