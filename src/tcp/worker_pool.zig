const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const Engine = @import("../engine/engine.zig").Engine;
const Session = @import("server.zig").Session;
const SecurityManager = @import("../storage/security.zig").SecurityManager;
const common = @import("../common/common.zig");
const milliTimestamp = common.milliTimestamp;

const log = std.log.scoped(.worker_pool);

/// Metrics for monitoring pool health and performance
pub const PoolMetrics = struct {
    active_connections: std.atomic.Value(u64),
    queued_connections: std.atomic.Value(u64),
    total_processed: std.atomic.Value(u64),
    total_rejected: std.atomic.Value(u64),
    total_timeouts: std.atomic.Value(u64),
    total_errors: std.atomic.Value(u64),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .active_connections = std.atomic.Value(u64).init(0),
            .queued_connections = std.atomic.Value(u64).init(0),
            .total_processed = std.atomic.Value(u64).init(0),
            .total_rejected = std.atomic.Value(u64).init(0),
            .total_timeouts = std.atomic.Value(u64).init(0),
            .total_errors = std.atomic.Value(u64).init(0),
        };
    }

    pub fn snapshot(self: *const Self) MetricsSnapshot {
        return MetricsSnapshot{
            .active_connections = self.active_connections.load(.monotonic),
            .queued_connections = self.queued_connections.load(.monotonic),
            .total_processed = self.total_processed.load(.monotonic),
            .total_rejected = self.total_rejected.load(.monotonic),
            .total_timeouts = self.total_timeouts.load(.monotonic),
            .total_errors = self.total_errors.load(.monotonic),
        };
    }
};

pub const MetricsSnapshot = struct {
    active_connections: u64,
    queued_connections: u64,
    total_processed: u64,
    total_rejected: u64,
    total_timeouts: u64,
    total_errors: u64,
};

/// Thread-safe queue for pending connections
// pub const ConnectionQueue = struct {
//     allocator: Allocator,
//     queue: std.ArrayList(net.Stream),
//     mutex: Mutex,
//     condition: Condition,
//     shutdown: bool,
//     max_size: u32,
//     io: Io,
//     metrics: *PoolMetrics,

//     const Self = @This();

//     pub fn init(allocator: Allocator, io: Io, max_size: u32, metrics: *PoolMetrics) Self {
//         return Self{
//             .allocator = allocator,
//             .queue = .empty,
//             .mutex = .{},
//             .condition = .{},
//             .shutdown = false,
//             .max_size = max_size,
//             .io = io,
//             .metrics = metrics,
//         };
//     }

//     pub fn deinit(self: *Self) void {
//         self.mutex.lock();
//         defer self.mutex.unlock();

//         // Close all remaining connections in the queue
//         for (self.queue.items) |connection| {
//             connection.close(self.io);
//         }
//         self.queue.deinit(self.allocator);
//     }

//     /// Push a connection to the queue (rejects if full)
//     pub fn push(self: *Self, connection: net.Stream) !void {
//         // Add item to queue under lock
//         {
//             self.mutex.lock();
//             defer self.mutex.unlock();

//             if (self.shutdown) {
//                 return error.QueueShutdown;
//             }

//             // Check queue size limit
//             if (self.queue.items.len >= self.max_size) {
//                 _ = self.metrics.total_rejected.fetchAdd(1, .monotonic);
//                 return error.QueueFull;
//             }

//             try self.queue.append(self.allocator, connection);
//             _ = self.metrics.queued_connections.fetchAdd(1, .monotonic);
//         }

//         // Signal AFTER releasing the mutex - try signal() first (wakes one thread)
//         self.condition.signal();
//     }

//     /// Pop a connection from the queue (blocks if empty)
//     /// NOTE: Using polling approach as workaround for condition variable issues
//     pub fn pop(self: *Self) ?net.Stream {
//         while (!self.shutdown) {
//             {
//                 self.mutex.lock();
//                 defer self.mutex.unlock();

//                 // Check if queue has items
//                 if (self.queue.items.len > 0) {
//                     // Use swapRemove for O(1) instead of orderedRemove O(n)
//                     const connection = self.queue.swapRemove(0);
//                     _ = self.metrics.queued_connections.fetchSub(1, .monotonic);
//                     return connection;
//                 }
//             }

//             // Yield to other threads and sleep briefly to avoid busy-waiting
//             std.Thread.yield() catch {};
//             std.time.sleep(1 * std.time.ns_per_ms); // 1ms sleep
//         }

//         return null;
//     }

//     /// Get current queue size (for monitoring)
//     pub fn size(self: *Self) usize {
//         self.mutex.lock();
//         defer self.mutex.unlock();
//         return self.queue.items.len;
//     }

//     /// Signal shutdown to all waiting workers
//     pub fn shutdownQueue(self: *Self) void {
//         self.mutex.lock();
//         defer self.mutex.unlock();
//         self.shutdown = true;
//         self.condition.broadcast();
//     }
// };

/// Pool of reusable Session objects
pub const SessionPool = struct {
    allocator: Allocator,
    pool: std.ArrayList(*Session),
    mutex: Mutex,
    io: Io,
    engine: *Engine,
    max_size: usize,
    idle_timeout_ms: u64,
    security_manager: *SecurityManager,

    const Self = @This();

    pub fn init(allocator: Allocator, io: Io, engine: *Engine, pool_size: usize, idle_timeout_ms: u64, security_manager: *SecurityManager) !Self {
        var pool: std.ArrayList(*Session) = .empty;
        errdefer pool.deinit(allocator);

        // Pre-allocate sessions
        try pool.ensureTotalCapacity(allocator, pool_size);

        return Self{
            .allocator = allocator,
            .pool = pool,
            .mutex = .{},
            .io = io,
            .engine = engine,
            .max_size = pool_size,
            .idle_timeout_ms = idle_timeout_ms,
            .security_manager = security_manager,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Free all sessions in the pool
        for (self.pool.items) |session| {
            session.deinit();
            self.allocator.destroy(session);
        }
        self.pool.deinit(self.allocator);
    }

    /// Acquire a session from the pool (creates new if pool is empty)
    pub fn acquire(self: *Self, connection: net.Stream, message_buffer_pool: *MessageBufferPool, server: anytype) !*Session {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pool.items.len > 0) {
            const session = self.pool.pop().?; // Force unwrap since we checked length
            // Reuse existing session with new connection
            session.reset(connection, server);
            return session;
        }

        // Create new session if pool is empty
        const session = try self.allocator.create(Session);
        session.* = Session.init(self.allocator, self.io, connection, self.engine, server, self.idle_timeout_ms, message_buffer_pool, self.security_manager);
        return session;
    }

    /// Return a session to the pool
    pub fn release(self: *Self, session: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Only keep up to max_size sessions in the pool
        if (self.pool.items.len < self.max_size) {
            self.pool.append(self.allocator, session) catch {
                // If append fails, just destroy the session
                session.deinit();
                self.allocator.destroy(session);
            };
        } else {
            // Pool is full, destroy the session
            session.deinit();
            self.allocator.destroy(session);
        }
    }
};

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

// pub const WorkerPool = struct {
//     allocator: Allocator,
//     io: Io,
//     engine: *Engine,
//     connection_queue: ConnectionQueue,
//     session_pool: SessionPool,
//     message_buffer_pool: MessageBufferPool,
//     workers: []std.Thread,
//     worker_count: usize,
//     shutdown: bool,
//     metrics: PoolMetrics,
//     max_sessions: u32,
//     graceful_shutdown_timeout_ms: u64,

//     const Self = @This();

//     pub fn init(allocator: Allocator, io: Io, engine: *Engine, worker_count: usize, max_queue_size: u32, max_sessions: u32, graceful_shutdown_timeout_ms: u64, idle_timeout_ms: u64) !Self {
//         // Create metrics first (needs to be on heap since ConnectionQueue stores a pointer)
//         const metrics_ptr = try allocator.create(PoolMetrics);
//         metrics_ptr.* = PoolMetrics.init();
//         errdefer allocator.destroy(metrics_ptr);

//         const connection_queue = ConnectionQueue.init(allocator, io, max_queue_size, metrics_ptr);

//         // Initialize message buffer pool (64KB default size, pool size = worker_count)
//         // Must be created before session_pool since it needs a pointer to it
//         const message_buffer_pool_ptr = try allocator.create(MessageBufferPool);
//         message_buffer_pool_ptr.* = try MessageBufferPool.init(allocator, 64 * 1024, worker_count);
//         errdefer {
//             message_buffer_pool_ptr.deinit();
//             allocator.destroy(message_buffer_pool_ptr);
//         }

//         var session_pool = try SessionPool.init(allocator, io, engine, worker_count, idle_timeout_ms, message_buffer_pool_ptr);
//         errdefer session_pool.deinit();

//         const workers = try allocator.alloc(std.Thread, worker_count);
//         errdefer allocator.free(workers);

//         return Self{
//             .allocator = allocator,
//             .io = io,
//             .engine = engine,
//             .connection_queue = connection_queue,
//             .session_pool = session_pool,
//             .message_buffer_pool = message_buffer_pool_ptr.*,
//             .workers = workers,
//             .worker_count = worker_count,
//             .shutdown = false,
//             .metrics = metrics_ptr.*,
//             .max_sessions = max_sessions,
//             .graceful_shutdown_timeout_ms = graceful_shutdown_timeout_ms,
//         };
//     }

//     /// Start the worker threads (must be called after init)
//     pub fn start(self: *Self) !void {
//         // Spawn worker threads
//         for (self.workers, 0..) |*worker, i| {
//             worker.* = try std.Thread.spawn(.{}, workerLoop, .{ self, i });
//         }

//         log.info("Worker pool started with {} workers", .{self.worker_count});
//     }

//     pub fn deinit(self: *Self) void {
//         log.info("Initiating graceful shutdown...", .{});

//         // Stop accepting new connections
//         self.shutdown = true;

//         // Wait for queue to drain with timeout
//         const start_time = milliTimestamp();
//         const timeout_ms: i64 = @intCast(self.graceful_shutdown_timeout_ms);

//         while (self.connection_queue.size() > 0) {
//             const elapsed = milliTimestamp() - start_time;
//             if (elapsed > timeout_ms) {
//                 log.warn("Graceful shutdown timeout reached, {} connections still queued", .{self.connection_queue.size()});
//                 break;
//             }
//             // Yield CPU to avoid busy-waiting
//             std.Thread.yield() catch {};
//         }

//         // Signal queue shutdown to wake up waiting workers
//         self.connection_queue.shutdownQueue();

//         // Wait for all workers to finish current connections
//         for (self.workers) |worker| {
//             worker.join();
//         }

//         self.allocator.free(self.workers);
//         self.message_buffer_pool.deinit();
//         self.session_pool.deinit();
//         self.connection_queue.deinit();

//         const metrics = self.metrics.snapshot();
//         log.info("Worker pool shutdown complete. Final stats: processed={}, rejected={}, errors={}", .{ metrics.total_processed, metrics.total_rejected, metrics.total_errors });
//     }

//     /// Submit a connection to be handled by a worker
//     pub fn submitConnection(self: *Self, connection: net.Stream) !void {
//         // Check max_sessions limit
//         const active = self.metrics.active_connections.load(.monotonic);
//         const queued = self.metrics.queued_connections.load(.monotonic);

//         if (active + queued >= self.max_sessions) {
//             _ = self.metrics.total_rejected.fetchAdd(1, .monotonic);
//             return error.MaxSessionsReached;
//         }

//         try self.connection_queue.push(connection);
//     }

//     /// Worker thread main loop
//     fn workerLoop(self: *Self, worker_id: usize) void {
//         log.info("Worker {} started", .{worker_id});

//         while (!self.shutdown) {
//             // Get connection from queue (blocks until available)
//             const connection = self.connection_queue.pop() orelse break;

//             // Track active connection
//             _ = self.metrics.active_connections.fetchAdd(1, .monotonic);
//             defer _ = self.metrics.active_connections.fetchSub(1, .monotonic);

//             // Acquire a session from the pool
//             var session = self.session_pool.acquire(connection) catch |err| {
//                 log.err("Worker {} failed to acquire session: {}", .{ worker_id, err });
//                 _ = self.metrics.total_errors.fetchAdd(1, .monotonic);
//                 connection.close(self.io);
//                 continue;
//             };

//             // Handle the connection
//             session.run() catch |err| {
//                 if (err == error.IdleTimeout) {
//                     _ = self.metrics.total_timeouts.fetchAdd(1, .monotonic);
//                 } else {
//                     log.err("Worker {} session error: {}", .{ worker_id, err });
//                     _ = self.metrics.total_errors.fetchAdd(1, .monotonic);
//                 }
//             };

//             // Close connection
//             connection.close(self.io);

//             // Return session to pool
//             self.session_pool.release(session);

//             // Update processed count
//             _ = self.metrics.total_processed.fetchAdd(1, .monotonic);
//         }

//         log.info("Worker {} stopped", .{worker_id});
//     }

//     /// Get current metrics snapshot
//     pub fn getMetrics(self: *const Self) MetricsSnapshot {
//         return self.metrics.snapshot();
//     }
// };

// ============================================================================
// Unit Tests
// ============================================================================

test "PoolMetrics - init all zeros" {
    const metrics = PoolMetrics.init();

    try std.testing.expectEqual(@as(u64, 0), metrics.active_connections.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.queued_connections.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_processed.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_rejected.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_timeouts.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_errors.load(.monotonic));
}

test "PoolMetrics - atomic operations" {
    var metrics = PoolMetrics.init();

    // Test fetchAdd
    _ = metrics.active_connections.fetchAdd(1, .monotonic);
    _ = metrics.active_connections.fetchAdd(1, .monotonic);
    try std.testing.expectEqual(@as(u64, 2), metrics.active_connections.load(.monotonic));

    // Test fetchSub
    _ = metrics.active_connections.fetchSub(1, .monotonic);
    try std.testing.expectEqual(@as(u64, 1), metrics.active_connections.load(.monotonic));
}

test "PoolMetrics - snapshot captures all values" {
    var metrics = PoolMetrics.init();

    // Set various values
    _ = metrics.active_connections.fetchAdd(5, .monotonic);
    _ = metrics.queued_connections.fetchAdd(10, .monotonic);
    _ = metrics.total_processed.fetchAdd(100, .monotonic);
    _ = metrics.total_rejected.fetchAdd(3, .monotonic);
    _ = metrics.total_timeouts.fetchAdd(7, .monotonic);
    _ = metrics.total_errors.fetchAdd(2, .monotonic);

    // Take snapshot
    const snapshot = metrics.snapshot();

    try std.testing.expectEqual(@as(u64, 5), snapshot.active_connections);
    try std.testing.expectEqual(@as(u64, 10), snapshot.queued_connections);
    try std.testing.expectEqual(@as(u64, 100), snapshot.total_processed);
    try std.testing.expectEqual(@as(u64, 3), snapshot.total_rejected);
    try std.testing.expectEqual(@as(u64, 7), snapshot.total_timeouts);
    try std.testing.expectEqual(@as(u64, 2), snapshot.total_errors);
}

test "PoolMetrics - concurrent updates" {
    var metrics = PoolMetrics.init();
    const num_threads = 4;
    const ops_per_thread = 100;

    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(m: *PoolMetrics) void {
                for (0..ops_per_thread) |_| {
                    _ = m.total_processed.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{&metrics});
    }

    for (&threads) |*t| {
        t.join();
    }

    try std.testing.expectEqual(@as(u64, num_threads * ops_per_thread), metrics.total_processed.load(.monotonic));
}

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
