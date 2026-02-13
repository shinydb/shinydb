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
const MessageBufferPool = @import("message_buffer_pool.zig").MessageBufferPool;
const milliTimestamp = common.milliTimestamp;

const log = std.log.scoped(.worker_pool);




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



// ============================================================================
// Unit Tests
// ============================================================================

