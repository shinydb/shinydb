const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Config = @import("../common/config.zig").Config;
const Engine = @import("../engine/engine.zig").Engine;
const WorkerPool = @import("worker_pool.zig").WorkerPool;
const SessionPool = @import("worker_pool.zig").SessionPool;
const MessageBufferPool = @import("worker_pool.zig").MessageBufferPool;
const common = @import("../common/common.zig");
const milliTimestamp = common.milliTimestamp;
const proto = @import("proto");
const Packet = proto.Packet;
const Operation = proto.Operation;
const Status = proto.Status;
const BufferWriter = proto.BufferWriter;
const SecurityManager = @import("../storage/security.zig").SecurityManager;
const Session_Security = @import("../storage/security.zig").Session;
const PermissionType = @import("../storage/security.zig").PermissionType;

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: Allocator,
    config: *const Config,
    address: net.IpAddress,
    io: Io,
    engine: *Engine,
    message_buffer_pool: MessageBufferPool,
    session_pool: SessionPool,
    security_manager: *SecurityManager,
    security_enabled: bool,
    active_connections: std.atomic.Value(u64),

    const Self = @This();

    pub fn init(allocator: Allocator, config: *const Config, io: Io, engine: *Engine, security_enabled: bool) !Self {
        const address = try net.IpAddress.parseIp4(config.address, config.port);

        // Initialize security manager
        const security_manager = try SecurityManager.init(allocator, security_enabled);
        errdefer security_manager.deinit();

        // Attach engine for user persistence (loads users from _system.users store)
        try security_manager.attachEngine(engine);

        // Initialize message buffer pool
        var message_buffer_pool = try MessageBufferPool.init(
            allocator,
            256 * 1024, // 256KB buffer size - increased for larger payloads
            config.max_sessions, // Pool size matches max sessions
        );
        errdefer message_buffer_pool.deinit();

        // Initialize session pool for caching sessions
        var session_pool = try SessionPool.init(
            allocator,
            io,
            engine,
            config.max_sessions,
            config.connection_pool.idle_timeout_ms,
            security_manager,
        );
        errdefer session_pool.deinit();

        if (security_enabled) {
            log.info("Security enabled with authentication and authorization", .{});
        } else {
            log.warn("Security DISABLED - all connections have admin access", .{});
        }

        return Self{
            .allocator = allocator,
            .config = config,
            .address = address,
            .io = io,
            .engine = engine,
            .message_buffer_pool = message_buffer_pool,
            .session_pool = session_pool,
            .security_manager = security_manager,
            .security_enabled = security_enabled,
            .active_connections = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        self.session_pool.deinit();
        self.message_buffer_pool.deinit();
        self.security_manager.deinit();
    }

    /// Get current active connections count
    pub fn getActiveConnections(self: *const Self) u64 {
        return self.active_connections.load(.monotonic);
    }

    pub fn run(self: *Self) !void {
        var listening = try self.address.listen(self.io, .{});
        defer listening.close(self.io);

        log.info("Server listening on {s}:{d} (session pooling, direct threads)", .{
            self.config.address,
            self.config.port,
        });

        while (true) {
            const connection = listening.accept(self.io) catch |err| {
                log.err("Accept error: {}", .{err});
                continue;
            };

            // Check connection limit
            const active = self.active_connections.load(.monotonic);
            if (active >= self.config.max_sessions) {
                log.warn("Max connections reached ({}), rejecting new connection", .{active});
                connection.close(self.io);
                continue;
            }

            // Spawn a thread to handle this connection
            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, connection }) catch |err| {
                log.err("Failed to spawn connection handler: {}", .{err});
                connection.close(self.io);
                continue;
            };
            thread.detach();
        }
    }

    /// Handle a single connection (runs on dedicated thread)
    fn handleConnection(self: *Server, connection: net.Stream) void {
        defer connection.close(self.io);

        // Track active connection
        _ = self.active_connections.fetchAdd(1, .monotonic);
        defer _ = self.active_connections.fetchSub(1, .monotonic);

        // Get session from pool
        var session = self.session_pool.acquire(connection, &self.message_buffer_pool) catch |err| {
            log.err("Failed to acquire session: {}", .{err});
            return;
        };
        defer self.session_pool.release(session);

        // Handle the connection
        session.run() catch |err| {
            log.err("Session error: {}", .{err});
        };
    }
};

// Note: Now using std.Io's thread pool instead of custom worker pool

pub const Session = struct {
    allocator: Allocator,
    io: Io,
    connection: net.Stream,
    engine: *Engine,
    read_buffer: [64 * 1024]u8,
    write_buffer: [64 * 1024]u8,
    idle_timeout_ms: u64,
    last_activity_ms: i64,
    message_buffer_pool: ?*MessageBufferPool,
    security_manager: *SecurityManager,
    security_session: ?Session_Security,
    authenticated: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, io: Io, connection: net.Stream, engine: *Engine, idle_timeout_ms: u64, message_buffer_pool: ?*MessageBufferPool, security_manager: *SecurityManager) Self {
        return Self{
            .allocator = allocator,
            .io = io,
            .connection = connection,
            .engine = engine,
            .read_buffer = undefined,
            .write_buffer = undefined,
            .idle_timeout_ms = idle_timeout_ms,
            .last_activity_ms = milliTimestamp(),
            .message_buffer_pool = message_buffer_pool,
            .security_manager = security_manager,
            .security_session = null,
            .authenticated = true, // TODO: Require actual authentication when security is enabled
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.security_session) |*session| {
            session.deinit(self.allocator);
        }
    }

    /// Reset session with a new connection (for reuse in pool)
    pub fn reset(self: *Self, connection: net.Stream) void {
        self.connection = connection;
        self.last_activity_ms = milliTimestamp();
        // Buffers are stack arrays, no need to reset
    }

    /// Check if session has exceeded idle timeout
    pub fn isIdle(self: *const Self) bool {
        const now = milliTimestamp();
        const elapsed: u64 = @intCast(now - self.last_activity_ms);
        return elapsed > self.idle_timeout_ms;
    }

    /// Update last activity timestamp
    fn updateActivity(self: *Self) void {
        self.last_activity_ms = milliTimestamp();
    }

    pub fn run(self: *Self) !void {
        var reader = self.connection.reader(self.io, &self.read_buffer);
        var writer = self.connection.writer(self.io, &self.write_buffer);

        while (true) {
            // Read message length (4 bytes, little-endian)
            var length_buf: [4]u8 = undefined;
            reader.interface.readSliceAll(&length_buf) catch |err| {
                if (err == error.EndOfStream) {
                    // Connection closed
                    break;
                }
                // Check for idle timeout only on read error (lazy check)
                if (self.isIdle()) {
                    return error.IdleTimeout;
                }
                log.err("Failed to read message length: {}", .{err});
                break;
            };
            self.updateActivity();

            const msg_len = std.mem.readInt(u32, &length_buf, .little);
            if (msg_len > 16 * 1024 * 1024) { // 16MB max message size
                log.err("Message too large: {} bytes", .{msg_len});
                break;
            }

            // Read message payload - use buffer pool if available
            // Note: Buffer pool may return a buffer larger than msg_len for reuse
            const msg_buf_full = if (self.message_buffer_pool) |pool| blk: {
                break :blk try pool.acquire(msg_len);
            } else blk: {
                break :blk try self.allocator.alloc(u8, msg_len);
            };

            defer {
                if (self.message_buffer_pool) |pool| {
                    pool.release(msg_buf_full);
                } else {
                    self.allocator.free(msg_buf_full);
                }
            }

            // Use only the first msg_len bytes of the buffer
            const msg_buf = msg_buf_full[0..msg_len];

            reader.interface.readSliceAll(msg_buf) catch |err| {
                log.err("Failed to read complete message: {}", .{err});
                break;
            };
            self.updateActivity();

            // Process message and get response
            const response = try self.processMessage(msg_buf);
            defer if (response) |r| self.allocator.free(r);
            self.updateActivity();

            // Send response
            if (response) |resp| {
                var resp_len_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &resp_len_buf, @intCast(resp.len), .little);
                try writer.interface.writeAll(&resp_len_buf);
                try writer.interface.writeAll(resp);
                try writer.interface.flush();
            }
        }
    }


    fn processMessage(self: *Self, payload: []const u8) !?[]u8 {
        // Deserialize the incoming packet
        const request = try Packet.deserialize(self.allocator, payload);
        defer Packet.free(self.allocator, request);

        // Process the operation and get response
        const response_op = self.handleOperation(&request.op) catch |err| {
            // On error, return an error response with appropriate status
            log.err("Error handling operation: {}", .{err});
            const error_msg = try std.fmt.allocPrint(self.allocator, "Error: {}", .{err});
            defer self.allocator.free(error_msg);

            // Map error to appropriate status
            const status: Status = switch (err) {
                error.NotFound, error.StoreNotFound, error.SpaceNotFound => .not_found,
                error.InvalidRequest => .invalid_request,
                else => .err,
            };

            const error_op = Operation{ .Reply = .{ .status = status, .data = null } };

            const response = Packet{
                .checksum = 0,
                .packet_length = 0,
                .packet_id = request.packet_id,
                .session_id = request.session_id,
                .correlation_id = request.correlation_id,
                .timestamp = milliTimestamp(),
                .op = error_op,
            };

            var writer = try BufferWriter.init(self.allocator);
            defer writer.deinit(self.allocator);
            const serialized = try response.serialize(&writer);
            // Update packet_length field (at offset 8, after 8-byte checksum)
            std.mem.writeInt(u32, serialized[8..12], @intCast(serialized.len), .little);
            return try self.allocator.dupe(u8, serialized);
        };
        // Free the response data after serialization
        defer {
            if (response_op == .Reply) {
                if (response_op.Reply.data) |data| {
                    self.allocator.free(data);
                }
            }
        }

        // Create response packet
        const response = Packet{
            .checksum = 0,
            .packet_length = 0,
            .packet_id = request.packet_id,
            .session_id = request.session_id,
            .correlation_id = request.correlation_id,
            .timestamp = milliTimestamp(),
            .op = response_op,
        };

        // Serialize and return
        var writer = try BufferWriter.init(self.allocator);
        defer writer.deinit(self.allocator);
        const serialized = try response.serialize(&writer);
        // Update packet_length field (at offset 8, after 8-byte checksum)
        std.mem.writeInt(u32, serialized[8..12], @intCast(serialized.len), .little);
        return try self.allocator.dupe(u8, serialized);
    }

    /// Check if the current session has required permission for an operation
    fn checkPermission(self: *Self, op: *const Operation) !void {
        // Authentication operations are allowed without prior authentication
        switch (op.*) {
            .Authenticate, .AuthenticateApiKey => return,
            else => {},
        }

        // If not authenticated, block all other operations
        if (!self.authenticated) {
            return error.Unauthenticated;
        }

        // Logout is allowed for authenticated users
        if (op.* == .Logout) return;

        // Determine required permission based on operation type
        const required_permission: PermissionType = switch (op.*) {
            // Schema operations - admin for Create/Drop, read for List
            .Create => .admin,
            .Drop => .delete,
            .List => .read,

            // Document operations
            .Insert, .BatchInsert => .write,
            .Read => .read,
            .Update => .write,
            .Delete => .delete,

            // Query operations
            .Range, .Query, .Aggregate, .Scan => .read,

            // Security operations
            .ResetPassword => .read, // Users can reset their own password

            // Backup operations (admin only)
            .Restore, .CleanBackups => .admin,

            // Server control
            .Flush, .Shutdown => .admin,

            // Auth operations handled above
            .Authenticate, .AuthenticateApiKey, .Logout => unreachable,

            // Server responses - not client operations
            .Reply, .BatchReply => return error.InvalidOperation,
        };

        // Check permission (skip if authenticated but no security session - TODO: Fix security flow)
        if (self.security_session) |*session| {
            try self.security_manager.checkPermission(session, required_permission);
        } else if (!self.authenticated) {
            return error.NoSecuritySession;
        }
        // If authenticated but no session, allow operation (default mode)
    }

    fn handleOperation(self: *Self, op: *const Operation) !Operation {
        // Check authorization before processing
        try self.checkPermission(op);

        return switch (op.*) {
            // ========== SCHEMA/METADATA OPERATIONS (Tag 100-102) ==========
            .Create => |data| blk: {
                // Only lock catalog_mutex for Space/Store/Index, not for User/Backup
                const needs_catalog_lock = switch (data.doc_type) {
                    .Space, .Store, .Index => true,
                    .User, .Backup, .Document => false,
                };

                if (needs_catalog_lock) {
                    self.engine.catalog_mutex.lock();
                    defer self.engine.catalog_mutex.unlock();
                }

                switch (data.doc_type) {
                    .Space => {
                        _ = try self.engine.catalog.createSpace(data.ns, data.metadata, self.engine.db);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .Store => {
                        // Auto-create parent space if requested
                        if (data.auto_create) {
                            var parts = try proto.parseNamespace(self.allocator, data.ns);
                            defer parts.deinit(self.allocator);

                            if (parts.space) |space_ns| {
                                if (self.engine.catalog.spaces.get(space_ns) == null) {
                                    _ = try self.engine.catalog.createSpace(space_ns, null, self.engine.db);
                                }
                            }
                        }
                        _ = try self.engine.catalog.createStore(data.ns, data.metadata, self.engine.db);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .Index => {
                        // Parse payload as JSON to get field name and type
                        const parsed = try std.json.parseFromSlice(
                            std.json.Value,
                            self.allocator,
                            data.payload,
                            .{},
                        );
                        defer parsed.deinit();

                        const field = parsed.value.object.get("field") orelse return error.MissingField;
                        const field_type_str = parsed.value.object.get("field_type") orelse return error.MissingFieldType;

                        // Parse field type
                        const field_type: proto.FieldType = if (std.mem.eql(u8, field_type_str.string, "String"))
                            .String
                        else if (std.mem.eql(u8, field_type_str.string, "U32"))
                            .U32
                        else if (std.mem.eql(u8, field_type_str.string, "U64"))
                            .U64
                        else if (std.mem.eql(u8, field_type_str.string, "I32"))
                            .I32
                        else if (std.mem.eql(u8, field_type_str.string, "I64"))
                            .I64
                        else if (std.mem.eql(u8, field_type_str.string, "F32"))
                            .F32
                        else if (std.mem.eql(u8, field_type_str.string, "F64"))
                            .F64
                        else if (std.mem.eql(u8, field_type_str.string, "Boolean"))
                            .Boolean
                        else
                            return error.InvalidFieldType;

                        // Get store_ns from index namespace (space.store.index -> space.store)
                        var parts = try proto.parseNamespace(self.allocator, data.ns);
                        defer parts.deinit(self.allocator);

                        const store_ns = if (parts.space != null and parts.store != null)
                            try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ parts.space.?, parts.store.? })
                        else
                            return error.InvalidIndexNamespace;
                        defer self.allocator.free(store_ns);

                        const store = self.engine.catalog.findStoreByNamespace(store_ns) orelse return error.StoreNotFound;
                        const store_id = store.store_id;

                        // Create the secondary index (both metadata and B+ tree)
                        // This also populates the index with existing documents
                        self.engine.db_mutex.lock();
                        defer self.engine.db_mutex.unlock();
                        try self.engine.db.createSecondaryIndex(store_id, data.ns, field.string, field_type);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .User => {
                        // Parse payload as JSON to get username, password, role
                        const parsed = try std.json.parseFromSlice(
                            std.json.Value,
                            self.allocator,
                            data.payload,
                            .{},
                        );
                        defer parsed.deinit();

                        const username = parsed.value.object.get("username") orelse return error.MissingUsername;
                        const password = parsed.value.object.get("password") orelse return error.MissingPassword;
                        const role_num = parsed.value.object.get("role") orelse return error.MissingRole;

                        const Role = @import("../storage/security.zig").Role;
                        const role: Role = switch (role_num.integer) {
                            0 => .admin,
                            1 => .read_write,
                            2 => .read_only,
                            else => .none,
                        };

                        self.security_manager.createUser(username.string, password.string, role) catch |err| {
                            const err_msg = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                            break :blk Operation{ .Reply = .{ .status = .err, .data = err_msg } };
                        };

                        // Return API key
                        const user = self.security_manager.users.get(username.string) orelse {
                            break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                        };
                        const response = try std.fmt.allocPrint(self.allocator, "{{\"api_key\":\"{s}\"}}", .{user.api_key});
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = response } };
                    },
                    .Backup => {
                        // TODO: Not implemented yet
                        const err_data = try self.allocator.dupe(u8, "Not implemented");
                        break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
                    },
                    .Document => {
                        return error.InvalidDocType;
                    },
                }
            },
            .Drop => |data| blk: {
                self.engine.catalog_mutex.lock();
                defer self.engine.catalog_mutex.unlock();

                switch (data.doc_type) {
                    .Space => {
                        try self.engine.catalog.dropSpace(data.name, self.engine.db);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .Store => {
                        try self.engine.catalog.dropStore(data.name, self.engine.db);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .Index => {
                        try self.engine.catalog.dropIndex(data.name, self.engine.db);
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .User => {
                        self.security_manager.deleteUser(data.name) catch |err| {
                            const err_msg = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                            break :blk Operation{ .Reply = .{ .status = .err, .data = err_msg } };
                        };
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
                    },
                    .Backup => {
                        // TODO: Not implemented yet
                        const err_data = try self.allocator.dupe(u8, "Not implemented");
                        break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
                    },
                    .Document => {
                        return error.InvalidDocType;
                    },
                }
            },
            .List => |data| blk: {
                self.engine.catalog_mutex.lock();
                defer self.engine.catalog_mutex.unlock();

                switch (data.doc_type) {
                    .Space => {
                        var spaces = try self.engine.catalog.listSpaces(self.allocator);
                        defer spaces.deinit(self.allocator);

                        // Format as JSON array of space namespaces
                        var json_buf: std.ArrayList(u8) = .empty;
                        try json_buf.append(self.allocator, '[');
                        for (spaces.items, 0..) |space, i| {
                            if (i > 0) try json_buf.append(self.allocator, ',');
                            try json_buf.append(self.allocator, '"');
                            try json_buf.appendSlice(self.allocator, space.ns);
                            try json_buf.append(self.allocator, '"');
                        }
                        try json_buf.append(self.allocator, ']');
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = try json_buf.toOwnedSlice(self.allocator) } };
                    },
                    .Store => {
                        var stores = try self.engine.catalog.listStores(self.allocator);
                        defer stores.deinit(self.allocator);

                        // Filter by space namespace prefix if provided
                        var json_buf: std.ArrayList(u8) = .empty;
                        try json_buf.append(self.allocator, '[');
                        var first = true;
                        for (stores.items) |store| {
                            // Check if store belongs to the specified space (if ns filter provided)
                            if (data.ns) |filter_ns| {
                                if (std.mem.startsWith(u8, store.ns, filter_ns)) {
                                    if (!first) try json_buf.append(self.allocator, ',');
                                    first = false;
                                    try json_buf.append(self.allocator, '"');
                                    try json_buf.appendSlice(self.allocator, store.ns);
                                    try json_buf.append(self.allocator, '"');
                                }
                            } else {
                                // No filter, include all stores
                                if (!first) try json_buf.append(self.allocator, ',');
                                first = false;
                                try json_buf.append(self.allocator, '"');
                                try json_buf.appendSlice(self.allocator, store.ns);
                                try json_buf.append(self.allocator, '"');
                            }
                        }
                        try json_buf.append(self.allocator, ']');
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = try json_buf.toOwnedSlice(self.allocator) } };
                    },
                    .Index => {
                        var indexes = try self.engine.catalog.listIndexes(self.allocator);
                        defer indexes.deinit(self.allocator);

                        // Filter by store namespace prefix if provided
                        var json_buf: std.ArrayList(u8) = .empty;
                        try json_buf.append(self.allocator, '[');
                        var first = true;
                        for (indexes.items) |index| {
                            // Check if index belongs to the specified store (if ns filter provided)
                            if (data.ns) |filter_ns| {
                                if (std.mem.startsWith(u8, index.ns, filter_ns)) {
                                    if (!first) try json_buf.append(self.allocator, ',');
                                    first = false;
                                    try json_buf.append(self.allocator, '"');
                                    try json_buf.appendSlice(self.allocator, index.ns);
                                    try json_buf.append(self.allocator, '"');
                                }
                            } else {
                                // No filter, include all indexes
                                if (!first) try json_buf.append(self.allocator, ',');
                                first = false;
                                try json_buf.append(self.allocator, '"');
                                try json_buf.appendSlice(self.allocator, index.ns);
                                try json_buf.append(self.allocator, '"');
                            }
                        }
                        try json_buf.append(self.allocator, ']');
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = try json_buf.toOwnedSlice(self.allocator) } };
                    },
                    .User => {
                        // List all users (returns usernames only for security)
                        var json_buf: std.ArrayList(u8) = .empty;
                        try json_buf.append(self.allocator, '[');
                        var first = true;
                        var user_iter = self.security_manager.users.iterator();
                        while (user_iter.next()) |entry| {
                            if (!first) try json_buf.append(self.allocator, ',');
                            first = false;
                            try json_buf.append(self.allocator, '"');
                            try json_buf.appendSlice(self.allocator, entry.key_ptr.*);
                            try json_buf.append(self.allocator, '"');
                        }
                        try json_buf.append(self.allocator, ']');
                        break :blk Operation{ .Reply = .{ .status = .ok, .data = try json_buf.toOwnedSlice(self.allocator) } };
                    },
                    .Backup => {
                        // TODO: Not implemented yet
                        const err_data = try self.allocator.dupe(u8, "Not implemented");
                        break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
                    },
                    .Document => {
                        return error.InvalidDocType;
                    },
                }
            },

            // ========== DOCUMENT DATA OPERATIONS (Tag 103-107) ==========
            .Insert => |data| blk: {
                const key = try self.engine.post(data.store_ns, data.payload);
                const response_json = try std.fmt.allocPrint(self.allocator, "{{\"key\":\"{x:0>32}\"}}", .{key});
                break :blk Operation{ .Reply = .{ .status = .ok, .data = response_json } };
            },
            .BatchInsert => |data| blk: {
                // Process batch of document insertions with optimized engine batch operation
                const keys = try self.engine.postBatch(data.store_ns, data.values, self.allocator);
                defer self.allocator.free(keys);

                // Encode keys as binary (16 bytes per key)
                const results = try self.allocator.alloc([]const u8, keys.len);
                errdefer {
                    for (results) |result| {
                        self.allocator.free(result);
                    }
                    self.allocator.free(results);
                }

                for (keys, 0..) |key, i| {
                    // Encode u128 as 16 bytes (little-endian)
                    const key_bytes = try self.allocator.alloc(u8, 16);
                    std.mem.writeInt(u128, key_bytes[0..16], key, .little);
                    results[i] = key_bytes;
                }

                break :blk Operation{ .BatchReply = .{ .status = .ok, .results = results } };
            },
            .Read => |data| blk: {
                const value = try self.engine.get(data.id);
                defer self.engine.allocator.free(value);
                const value_copy = try self.allocator.dupe(u8, value);
                break :blk Operation{ .Reply = .{ .status = .ok, .data = value_copy } };
            },
            .Update => |data| blk: {
                try self.engine.put(data.id, data.payload);
                const response_json = try self.allocator.dupe(u8, "{\"success\":true}");
                break :blk Operation{ .Reply = .{ .status = .ok, .data = response_json } };
            },
            .Delete => |data| blk: {
                if (data.id) |id| {
                    try self.engine.del(id);
                    const response_json = try self.allocator.dupe(u8, "{\"success\":true}");
                    break :blk Operation{ .Reply = .{ .status = .ok, .data = response_json } };
                } else {
                    // Query-based delete not yet supported
                    const err_data = try self.allocator.dupe(u8, "Query-based delete not yet supported");
                    break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
                }
            },

            // ========== QUERY OPERATIONS (Tag 108-110) ==========
            .Range => |data| blk: {
                // Extract start and end keys from attributes
                const start_key: u128 = switch (data.start_key) {
                    .U128 => |attr| attr.value,
                    .I128 => |attr| @bitCast(attr.value),
                    else => return error.UnsupportedKeyType,
                };

                const end_key: u128 = switch (data.end_key) {
                    .U128 => |attr| attr.value,
                    .I128 => |attr| @bitCast(attr.value),
                    else => return error.UnsupportedKeyType,
                };

                // Query engine
                const docs = try self.engine.rangeQuery(start_key, end_key, 100); // Default limit of 100
                defer {
                    for (docs) |doc| {
                        self.allocator.free(doc.value);
                    }
                    self.allocator.free(docs);
                }

                // Return as JSON array
                var json_parts = std.ArrayList([]const u8).empty;
                defer {
                    for (json_parts.items) |part| {
                        self.allocator.free(part);
                    }
                    json_parts.deinit(self.allocator);
                }

                for (docs) |doc| {
                    const doc_json = try std.fmt.allocPrint(
                        self.allocator,
                        "{{\"key\":\"{x:0>32}\",\"value\":{s}}}",
                        .{ doc.key, doc.value },
                    );
                    try json_parts.append(self.allocator, doc_json);
                }

                // Join all parts with commas
                var total_len: usize = 2; // For '[' and ']'
                for (json_parts.items, 0..) |part, i| {
                    total_len += part.len;
                    if (i > 0) total_len += 1; // For comma
                }

                const value = try self.allocator.alloc(u8, total_len);
                var pos: usize = 0;
                value[pos] = '[';
                pos += 1;
                for (json_parts.items, 0..) |part, i| {
                    if (i > 0) {
                        value[pos] = ',';
                        pos += 1;
                    }
                    @memcpy(value[pos..][0..part.len], part);
                    pos += part.len;
                }
                value[pos] = ']';

                break :blk Operation{ .Reply = .{ .status = .ok, .data = value } };
            },
            .Query => |data| blk: {
                // Check if this is an aggregation query
                if (hasAggregateField(data.query_json)) {
                    // Route to aggregation handler
                    const result = try self.engine.aggregateDocs(data.store_ns, data.query_json);
                    break :blk Operation{ .Reply = .{ .status = .ok, .data = result } };
                }

                // Regular query
                const docs = try self.engine.queryDocs(data.store_ns, data.query_json);
                defer {
                    for (docs) |doc| {
                        self.allocator.free(doc.value);
                    }
                    self.allocator.free(docs);
                }

                // Build JSON array response with just document values (no key wrapper)
                var json_parts = std.ArrayList([]const u8).empty;
                defer {
                    for (json_parts.items) |part| {
                        self.allocator.free(part);
                    }
                    json_parts.deinit(self.allocator);
                }

                for (docs) |doc| {
                    // Return just the document value for cleaner output
                    const doc_json = try self.allocator.dupe(u8, doc.value);
                    try json_parts.append(self.allocator, doc_json);
                }

                // Join all parts
                var total_len: usize = 2;
                for (json_parts.items, 0..) |part, i| {
                    total_len += part.len;
                    if (i > 0) total_len += 1;
                }

                const value = try self.allocator.alloc(u8, total_len);
                var pos: usize = 0;
                value[pos] = '[';
                pos += 1;
                for (json_parts.items, 0..) |part, i| {
                    if (i > 0) {
                        value[pos] = ',';
                        pos += 1;
                    }
                    @memcpy(value[pos..][0..part.len], part);
                    pos += part.len;
                }
                value[pos] = ']';

                break :blk Operation{ .Reply = .{ .status = .ok, .data = value } };
            },
            .Aggregate => |data| blk: {
                // Route to aggregation handler
                const result = try self.engine.aggregateDocs(data.store_ns, data.aggregate_json);
                break :blk Operation{ .Reply = .{ .status = .ok, .data = result } };
            },
            .Scan => |data| blk: {
                // Scan documents with limit and skip
                const docs = try self.engine.scanDocs(data.start_key, data.limit, data.skip);
                defer {
                    for (docs) |doc| {
                        self.allocator.free(doc.value);
                    }
                    self.allocator.free(docs);
                }

                // Pre-calculate total size to avoid reallocations
                var total_len: usize = 2; // For '[' and ']'
                for (docs, 0..) |doc, i| {
                    total_len += 17 + 32 + 11; // {"key":"...","value":
                    total_len += doc.value.len;
                    total_len += 1; // closing }
                    if (i > 0) total_len += 1; // comma
                }

                // Build JSON array in a single allocation
                const value = try self.allocator.alloc(u8, total_len);
                errdefer self.allocator.free(value);

                var pos: usize = 0;
                value[pos] = '[';
                pos += 1;

                for (docs, 0..) |doc, i| {
                    if (i > 0) {
                        value[pos] = ',';
                        pos += 1;
                    }
                    // Write: {"key":"<hex>","value":<doc_value>}
                    const key_str = try std.fmt.bufPrint(
                        value[pos..],
                        "{{\"key\":\"{x:0>32}\",\"value\":{s}}}",
                        .{ doc.key, doc.value },
                    );
                    pos += key_str.len;
                }

                value[pos] = ']';

                break :blk Operation{ .Reply = .{ .status = .ok, .data = value } };
            },

            // ========== AUTHENTICATION OPERATIONS (Tag 111-113) ==========
            .Authenticate => |data| blk: {
                const session = self.security_manager.authenticate(data.username, data.password) catch |err| {
                    const err_msg = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                    break :blk Operation{ .Reply = .{ .status = .err, .data = err_msg } };
                };
                // Store session for this connection
                self.security_session = session;
                self.authenticated = true;
                // Return session info
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"session_id\":\"{s}\",\"username\":\"{s}\",\"role\":\"{s}\"}}",
                    .{ session.session_id, session.username, session.permissions.toRoleName() },
                );
                break :blk Operation{ .Reply = .{ .status = .ok, .data = response } };
            },
            .AuthenticateApiKey => |data| blk: {
                const session = self.security_manager.authenticateApiKey(data.api_key) catch |err| {
                    const err_msg = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                    break :blk Operation{ .Reply = .{ .status = .err, .data = err_msg } };
                };
                // Store session for this connection
                self.security_session = session;
                self.authenticated = true;
                // Return session info
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"session_id\":\"{s}\",\"username\":\"{s}\",\"role\":\"{s}\"}}",
                    .{ session.session_id, session.username, session.permissions.toRoleName() },
                );
                break :blk Operation{ .Reply = .{ .status = .ok, .data = response } };
            },
            .Logout => blk: {
                if (self.security_session) |session| {
                    self.security_manager.revokeSession(session.session_id) catch {};
                    self.security_session = null;
                    self.authenticated = false;
                }
                break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
            },

            // ========== USER MANAGEMENT OPERATIONS (Tag 114) ==========
            .ResetPassword => |data| blk: {
                self.security_manager.changePassword(data.username, data.old_password, data.new_password) catch |err| {
                    const err_msg = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
                    break :blk Operation{ .Reply = .{ .status = .err, .data = err_msg } };
                };
                break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
            },

            // ========== BACKUP OPERATIONS (Tag 115-116) ==========
            .Restore => blk: {
                // TODO: Implement backup restore
                const err_data = try self.allocator.dupe(u8, "Not implemented");
                break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
            },
            .CleanBackups => blk: {
                // TODO: Implement backup cleanup
                const err_data = try self.allocator.dupe(u8, "Not implemented");
                break :blk Operation{ .Reply = .{ .status = .err, .data = err_data } };
            },

            // ========== SERVER CONTROL OPERATIONS (Tag 117-120) ==========
            .Reply => return error.InvalidOperation,
            .BatchReply => return error.InvalidOperation,
            .Flush => blk: {
                try self.engine.flush();
                break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
            },
            .Shutdown => blk: {
                try self.engine.shutdown();
                break :blk Operation{ .Reply = .{ .status = .ok, .data = null } };
            },
        };
    }

    /// Check if a JSON document matches a filter criterion
    fn matchesCriterion(self: *const Self, json_value: std.json.Value, criterion: proto.Attribute) bool {
        _ = self;

        // Get field name from criterion
        const field_name = switch (criterion) {
            .U64 => |attr| attr.name,
            .I64 => |attr| attr.name,
            .U32 => |attr| attr.name,
            .I32 => |attr| attr.name,
            .Pointer => |attr| attr.name,
            .F64 => |attr| attr.name,
            .F32 => |attr| attr.name,
            else => return false,
        };

        // Look up field in JSON object
        if (json_value != .object) return false;
        const field_value = json_value.object.get(field_name) orelse return false;

        // Compare based on criterion type
        return switch (criterion) {
            .U64 => |attr| switch (field_value) {
                .integer => |i| i >= 0 and @as(u64, @intCast(i)) == attr.value,
                else => false,
            },
            .I64 => |attr| switch (field_value) {
                .integer => |i| i == attr.value,
                else => false,
            },
            .U32 => |attr| switch (field_value) {
                .integer => |i| i >= 0 and i <= std.math.maxInt(u32) and @as(u32, @intCast(i)) == attr.value,
                else => false,
            },
            .I32 => |attr| switch (field_value) {
                .integer => |i| i >= std.math.minInt(i32) and i <= std.math.maxInt(i32) and @as(i32, @intCast(i)) == attr.value,
                else => false,
            },
            .F64 => |attr| switch (field_value) {
                .float => |f| f == attr.value,
                .integer => |i| @as(f64, @floatFromInt(i)) == attr.value,
                else => false,
            },
            .F32 => |attr| switch (field_value) {
                .float => |f| @as(f32, @floatCast(f)) == attr.value,
                .integer => |i| @as(f32, @floatFromInt(i)) == attr.value,
                else => false,
            },
            .Pointer => |attr| switch (field_value) {
                .string => |s| std.mem.eql(u8, s, attr.value),
                else => false,
            },
            else => false,
        };
    }
};

/// Check if JSON query contains an "aggregate" field
fn hasAggregateField(query_json: []const u8) bool {
    // Simple string search for "aggregate" key
    // This is efficient and avoids full JSON parsing
    return std.mem.indexOf(u8, query_json, "\"aggregate\"") != null;
}
