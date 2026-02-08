const std = @import("std");
const Allocator = std.mem.Allocator;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;
const Engine = @import("../engine/engine.zig").Engine;

/// System store namespace for persistent user storage
const SYSTEM_USERS_STORE_NS = "_system.users";

/// User role for RBAC
pub const Role = enum {
    admin, // Full access
    read_write, // Can read and write
    read_only, // Can only read
    none, // No access
};

/// Permission flags
pub const Permission = struct {
    can_read: bool = false,
    can_write: bool = false,
    can_delete: bool = false,
    can_admin: bool = false,

    pub fn fromRole(role: Role) Permission {
        return switch (role) {
            .admin => Permission{
                .can_read = true,
                .can_write = true,
                .can_delete = true,
                .can_admin = true,
            },
            .read_write => Permission{
                .can_read = true,
                .can_write = true,
                .can_delete = true,
                .can_admin = false,
            },
            .read_only => Permission{
                .can_read = true,
                .can_write = false,
                .can_delete = false,
                .can_admin = false,
            },
            .none => Permission{},
        };
    }

    /// Convert permissions back to role name for display
    pub fn toRoleName(self: Permission) []const u8 {
        if (self.can_admin) return "admin";
        if (self.can_write) return "read_write";
        if (self.can_read) return "read_only";
        return "none";
    }
};

/// User account
pub const User = struct {
    username: []const u8,
    password_hash: []const u8,
    role: Role,
    api_key: []const u8,
    created_at: i64,
    last_login: i64,
    enabled: bool,

    pub fn deinit(self: *User, allocator: Allocator) void {
        allocator.free(self.username);
        allocator.free(self.password_hash);
        allocator.free(self.api_key);
    }
};

/// Authentication session
pub const Session = struct {
    session_id: []const u8,
    username: []const u8,
    created_at: i64,
    expires_at: i64,
    permissions: Permission,

    pub fn isValid(self: *const Session) bool {
        return milliTimestamp() < self.expires_at;
    }

    pub fn deinit(self: *Session, allocator: Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.username);
    }
};

/// Security manager
pub const SecurityManager = struct {
    allocator: Allocator,
    enabled: bool,

    // Persistence: Engine reference for storing users (null until attachEngine called)
    engine: ?*Engine,
    users_store_id: ?u16,

    // User store: username -> User
    users: std.StringHashMap(User),
    users_mutex: std.Thread.Mutex,

    // Session store: session_id -> Session
    sessions: std.StringHashMap(Session),
    sessions_mutex: std.Thread.Mutex,

    // API key store: api_key -> username
    api_keys: std.StringHashMap([]const u8),
    api_keys_mutex: std.Thread.Mutex,

    session_timeout_ms: i64,

    pub fn init(allocator: Allocator, enabled: bool) !*SecurityManager {
        const mgr = try allocator.create(SecurityManager);
        mgr.* = SecurityManager{
            .allocator = allocator,
            .enabled = enabled,
            .engine = null,
            .users_store_id = null,
            .users = std.StringHashMap(User).init(allocator),
            .users_mutex = .{},
            .sessions = std.StringHashMap(Session).init(allocator),
            .sessions_mutex = .{},
            .api_keys = std.StringHashMap([]const u8).init(allocator),
            .api_keys_mutex = .{},
            .session_timeout_ms = 3600 * 1000, // 1 hour
        };

        // Note: Default admin is created in attachEngine() after loading persisted users
        // For tests without Engine, createDefaultAdmin() must be called explicitly

        return mgr;
    }

    pub fn deinit(self: *SecurityManager) void {
        // Free users: both keys and values
        var user_iter = self.users.iterator();
        while (user_iter.next()) |entry| {
            var u = entry.value_ptr.*;
            u.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.users.deinit();

        // Free sessions: both keys and values
        var session_iter = self.sessions.iterator();
        while (session_iter.next()) |entry| {
            var s = entry.value_ptr.*;
            s.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.sessions.deinit();

        // Free api_keys: both keys and values
        var api_key_iter = self.api_keys.iterator();
        while (api_key_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.api_keys.deinit();

        self.allocator.destroy(self);
    }

    fn createDefaultAdmin(self: *SecurityManager) !void {
        const username = "admin";
        const password = "admin"; // Should be changed on first use

        try self.createUser(username, password, .admin);
    }

    /// Create a new user
    pub fn createUser(self: *SecurityManager, username: []const u8, password: []const u8, role: Role) !void {
        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        if (self.users.contains(username)) {
            return error.UserAlreadyExists;
        }

        const password_hash = try self.hashPassword(password);
        const api_key = try self.generateApiKey(username);

        const user = User{
            .username = try self.allocator.dupe(u8, username),
            .password_hash = password_hash,
            .role = role,
            .api_key = api_key,
            .created_at = milliTimestamp(),
            .last_login = 0,
            .enabled = true,
        };

        try self.users.put(try self.allocator.dupe(u8, username), user);

        // Store API key mapping
        self.api_keys_mutex.lock();
        defer self.api_keys_mutex.unlock();
        try self.api_keys.put(try self.allocator.dupe(u8, api_key), try self.allocator.dupe(u8, username));

        // Persist user to storage (no-op if engine not attached)
        try self.persistUser(&user);
    }

    /// Authenticate with username and password
    pub fn authenticate(self: *SecurityManager, username: []const u8, password: []const u8) !Session {
        if (!self.enabled) {
            return Session{
                .session_id = try self.allocator.dupe(u8, "anonymous"),
                .username = try self.allocator.dupe(u8, "anonymous"),
                .created_at = milliTimestamp(),
                .expires_at = std.math.maxInt(i64),
                .permissions = Permission.fromRole(.admin),
            };
        }

        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        const user = self.users.get(username) orelse return error.InvalidCredentials;

        if (!user.enabled) {
            return error.UserDisabled;
        }

        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        if (!std.mem.eql(u8, user.password_hash, password_hash)) {
            return error.InvalidCredentials;
        }

        // Create session
        const session_id = try self.generateSessionId(username);
        const session = Session{
            .session_id = session_id,
            .username = try self.allocator.dupe(u8, username),
            .created_at = milliTimestamp(),
            .expires_at = milliTimestamp() + self.session_timeout_ms,
            .permissions = Permission.fromRole(user.role),
        };

        // Store session
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();
        try self.sessions.put(try self.allocator.dupe(u8, session_id), session);

        return session;
    }

    /// Authenticate with API key
    pub fn authenticateApiKey(self: *SecurityManager, api_key: []const u8) !Session {
        if (!self.enabled) {
            return Session{
                .session_id = try self.allocator.dupe(u8, "anonymous"),
                .username = try self.allocator.dupe(u8, "anonymous"),
                .created_at = milliTimestamp(),
                .expires_at = std.math.maxInt(i64),
                .permissions = Permission.fromRole(.admin),
            };
        }

        self.api_keys_mutex.lock();
        const username = self.api_keys.get(api_key) orelse {
            self.api_keys_mutex.unlock();
            return error.InvalidApiKey;
        };
        self.api_keys_mutex.unlock();

        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        const user = self.users.get(username) orelse return error.UserNotFound;

        if (!user.enabled) {
            return error.UserDisabled;
        }

        // Create long-lived session for API key
        return Session{
            .session_id = try self.allocator.dupe(u8, api_key),
            .username = try self.allocator.dupe(u8, username),
            .created_at = milliTimestamp(),
            .expires_at = std.math.maxInt(i64), // API key sessions don't expire
            .permissions = Permission.fromRole(user.role),
        };
    }

    /// Validate a session
    pub fn validateSession(self: *SecurityManager, session_id: []const u8) !Session {
        if (!self.enabled) {
            return Session{
                .session_id = try self.allocator.dupe(u8, "anonymous"),
                .username = try self.allocator.dupe(u8, "anonymous"),
                .created_at = milliTimestamp(),
                .expires_at = std.math.maxInt(i64),
                .permissions = Permission.fromRole(.admin),
            };
        }

        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        const session = self.sessions.get(session_id) orelse return error.InvalidSession;

        if (!session.isValid()) {
            return error.SessionExpired;
        }

        return session;
    }

    /// Check if session has permission
    pub fn checkPermission(self: *SecurityManager, session: *const Session, permission_type: PermissionType) !void {
        _ = self;
        const has_permission = switch (permission_type) {
            .read => session.permissions.can_read,
            .write => session.permissions.can_write,
            .delete => session.permissions.can_delete,
            .admin => session.permissions.can_admin,
        };

        if (!has_permission) {
            return error.PermissionDenied;
        }
    }

    /// Revoke a session
    pub fn revokeSession(self: *SecurityManager, session_id: []const u8) !void {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        if (self.sessions.fetchRemove(session_id)) |kv| {
            var session = kv.value;
            session.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    /// Change user password
    pub fn changePassword(self: *SecurityManager, username: []const u8, old_password: []const u8, new_password: []const u8) !void {
        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        const user_ptr = self.users.getPtr(username) orelse return error.UserNotFound;

        const old_password_hash = try self.hashPassword(old_password);
        defer self.allocator.free(old_password_hash);

        if (!std.mem.eql(u8, user_ptr.password_hash, old_password_hash)) {
            return error.InvalidCredentials;
        }

        self.allocator.free(user_ptr.password_hash);
        user_ptr.password_hash = try self.hashPassword(new_password);
    }

    /// Delete a user
    pub fn deleteUser(self: *SecurityManager, username: []const u8) !void {
        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        if (self.users.fetchRemove(username)) |kv| {
            var user = kv.value;
            user.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    // ===== Helper methods =====

    fn hashPassword(self: *SecurityManager, password: []const u8) ![]u8 {
        // Simple hash for demo (use bcrypt/argon2 in production)
        var hash_buf: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(password);
        hasher.update("salt"); // Should use random salt
        hasher.final(&hash_buf);

        return try self.allocator.dupe(u8, &hash_buf);
    }

    fn generateApiKey(self: *SecurityManager, username: []const u8) ![]u8 {
        // Simple API key generation (use secure random in production)
        var buf: [64]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "yadb_{s}_{d}", .{ username, milliTimestamp() });
        return try self.allocator.dupe(u8, key);
    }

    fn generateSessionId(self: *SecurityManager, username: []const u8) ![]u8 {
        var buf: [64]u8 = undefined;
        const session_id = try std.fmt.bufPrint(&buf, "sess_{s}_{d}", .{ username, milliTimestamp() });
        return try self.allocator.dupe(u8, session_id);
    }

    // ===== Persistence Methods =====

    /// Attach engine for user persistence. Must be called after Engine is initialized.
    /// This loads persisted users and creates default admin if no users exist.
    pub fn attachEngine(self: *SecurityManager, engine: *Engine) !void {
        self.engine = engine;

        if (!self.enabled) {
            return;
        }

        // Ensure the _system.users store exists
        try self.ensureUsersStore();

        // Load persisted users
        try self.loadUsersFromStore();

        // Create default admin if no users exist
        self.users_mutex.lock();
        const user_count = self.users.count();
        self.users_mutex.unlock();

        if (user_count == 0) {
            try self.createDefaultAdmin();
        }
    }

    /// Ensure the _system.users store exists, creating it if necessary
    fn ensureUsersStore(self: *SecurityManager) !void {
        const engine = self.engine orelse return error.EngineNotAttached;

        // Try to get the store_id for _system.users
        if (engine.catalog.findStoreByNamespace(SYSTEM_USERS_STORE_NS)) |store| {
            self.users_store_id = store.id;
            return;
        }

        // Store doesn't exist, create it
        const store = try engine.catalog.createStore(SYSTEM_USERS_STORE_NS, "System user accounts", engine.db);
        self.users_store_id = store.id;
    }

    /// Load all users from persistent storage into the in-memory hashmap
    fn loadUsersFromStore(self: *SecurityManager) !void {
        const engine = self.engine orelse return error.EngineNotAttached;
        if (self.users_store_id == null) return error.StoreNotInitialized;

        // Get all documents from the _system.users store
        const entries = engine.listDocs(SYSTEM_USERS_STORE_NS, null, null) catch |err| {
            // If store is empty or not found, that's okay - we'll create default admin
            if (err == error.StoreNotFound) return;
            return err;
        };
        defer self.allocator.free(entries);

        // Iterate through entries and parse each user
        for (entries) |entry| {
            // Parse the JSON value from the entry
            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, entry.value, .{}) catch |err| {
                std.log.warn("Failed to parse user JSON: {}", .{err});
                continue;
            };
            defer parsed.deinit();

            if (parsed.value != .object) continue;

            // Parse user from the object
            self.parseAndAddUser(parsed.value.object) catch |err| {
                std.log.warn("Failed to parse user: {}", .{err});
                continue;
            };
        }
    }

    /// Parse a user JSON object and add to the in-memory hashmap
    fn parseAndAddUser(self: *SecurityManager, obj: std.json.ObjectMap) !void {

        // Extract required fields
        const username_val = obj.get("username") orelse return error.MissingField;
        const password_hash_hex = obj.get("password_hash") orelse return error.MissingField;
        const role_str = obj.get("role") orelse return error.MissingField;
        const api_key_val = obj.get("api_key") orelse return error.MissingField;
        const created_at_val = obj.get("created_at") orelse return error.MissingField;
        const enabled_val = obj.get("enabled") orelse return error.MissingField;

        if (username_val != .string or password_hash_hex != .string or
            role_str != .string or api_key_val != .string)
        {
            return error.InvalidFieldType;
        }

        // Decode hex password hash
        const password_hash = try self.hexDecode(password_hash_hex.string);
        errdefer self.allocator.free(password_hash);

        // Parse role
        const role: Role = if (std.mem.eql(u8, role_str.string, "admin"))
            .admin
        else if (std.mem.eql(u8, role_str.string, "read_write"))
            .read_write
        else if (std.mem.eql(u8, role_str.string, "read_only"))
            .read_only
        else
            .none;

        // Parse timestamps
        const created_at: i64 = switch (created_at_val) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            else => 0,
        };

        const last_login_val = obj.get("last_login");
        const last_login: i64 = if (last_login_val) |v| switch (v) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            else => 0,
        } else 0;

        const enabled = enabled_val == .bool and enabled_val.bool;

        // Create user
        const user = User{
            .username = try self.allocator.dupe(u8, username_val.string),
            .password_hash = password_hash,
            .role = role,
            .api_key = try self.allocator.dupe(u8, api_key_val.string),
            .created_at = created_at,
            .last_login = last_login,
            .enabled = enabled,
        };

        // Add to hashmap
        self.users_mutex.lock();
        defer self.users_mutex.unlock();

        const username_key = try self.allocator.dupe(u8, username_val.string);
        try self.users.put(username_key, user);

        // Add to API keys map
        self.api_keys_mutex.lock();
        defer self.api_keys_mutex.unlock();
        try self.api_keys.put(
            try self.allocator.dupe(u8, api_key_val.string),
            try self.allocator.dupe(u8, username_val.string),
        );
    }

    /// Persist a user to the _system.users store
    fn persistUser(self: *SecurityManager, user: *const User) !void {
        const engine = self.engine orelse return; // Silently skip if no engine (for tests)
        if (self.users_store_id == null) return; // Store not initialized

        const json = try self.serializeUserToJson(user);
        defer self.allocator.free(json);

        // Post the user document using store namespace (key is auto-generated)
        _ = engine.post(SYSTEM_USERS_STORE_NS, json) catch |err| {
            std.log.err("Failed to persist user {s}: {}", .{ user.username, err });
            return err;
        };
    }

    /// Serialize a User struct to JSON string
    fn serializeUserToJson(self: *SecurityManager, user: *const User) ![]u8 {
        const hex_hash = try self.hexEncode(user.password_hash);
        defer self.allocator.free(hex_hash);

        const role_str = switch (user.role) {
            .admin => "admin",
            .read_write => "read_write",
            .read_only => "read_only",
            .none => "none",
        };

        // Build JSON manually for control over format
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.print(self.allocator,
            \\{{"username":"{s}","password_hash":"{s}","role":"{s}","api_key":"{s}","created_at":{d},"last_login":{d},"enabled":{s}}}
        , .{
            user.username,
            hex_hash,
            role_str,
            user.api_key,
            user.created_at,
            user.last_login,
            if (user.enabled) "true" else "false",
        });

        return try buf.toOwnedSlice(self.allocator);
    }

    /// Encode binary data to hex string
    fn hexEncode(self: *SecurityManager, data: []const u8) ![]u8 {
        const hex_chars = "0123456789abcdef";
        const result = try self.allocator.alloc(u8, data.len * 2);

        for (data, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        return result;
    }

    /// Decode hex string to binary data
    fn hexDecode(self: *SecurityManager, hex: []const u8) ![]u8 {
        if (hex.len % 2 != 0) return error.InvalidHexLength;

        const result = try self.allocator.alloc(u8, hex.len / 2);
        errdefer self.allocator.free(result);

        for (0..hex.len / 2) |i| {
            const high = hexCharToValue(hex[i * 2]) orelse return error.InvalidHexChar;
            const low = hexCharToValue(hex[i * 2 + 1]) orelse return error.InvalidHexChar;
            result[i] = (high << 4) | low;
        }

        return result;
    }

    fn hexCharToValue(c: u8) ?u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => null,
        };
    }
};

pub const PermissionType = enum {
    read,
    write,
    delete,
    admin,
};

// ============================================================================
// Unit Tests
// ============================================================================

test "Role - enum values" {
    const admin = Role.admin;
    const read_write = Role.read_write;
    const read_only = Role.read_only;
    const none = Role.none;

    try std.testing.expect(admin != read_write);
    try std.testing.expect(read_write != read_only);
    try std.testing.expect(read_only != none);
}

test "Permission - fromRole admin" {
    const perm = Permission.fromRole(.admin);

    try std.testing.expectEqual(true, perm.can_read);
    try std.testing.expectEqual(true, perm.can_write);
    try std.testing.expectEqual(true, perm.can_delete);
    try std.testing.expectEqual(true, perm.can_admin);
}

test "Permission - fromRole read_write" {
    const perm = Permission.fromRole(.read_write);

    try std.testing.expectEqual(true, perm.can_read);
    try std.testing.expectEqual(true, perm.can_write);
    try std.testing.expectEqual(true, perm.can_delete);
    try std.testing.expectEqual(false, perm.can_admin);
}

test "Permission - fromRole read_only" {
    const perm = Permission.fromRole(.read_only);

    try std.testing.expectEqual(true, perm.can_read);
    try std.testing.expectEqual(false, perm.can_write);
    try std.testing.expectEqual(false, perm.can_delete);
    try std.testing.expectEqual(false, perm.can_admin);
}

test "Permission - fromRole none" {
    const perm = Permission.fromRole(.none);

    try std.testing.expectEqual(false, perm.can_read);
    try std.testing.expectEqual(false, perm.can_write);
    try std.testing.expectEqual(false, perm.can_delete);
    try std.testing.expectEqual(false, perm.can_admin);
}

test "Permission - default values" {
    const perm = Permission{};

    try std.testing.expectEqual(false, perm.can_read);
    try std.testing.expectEqual(false, perm.can_write);
    try std.testing.expectEqual(false, perm.can_delete);
    try std.testing.expectEqual(false, perm.can_admin);
}

test "User - structure" {
    const user = User{
        .username = "testuser",
        .password_hash = "hash123",
        .role = .read_write,
        .api_key = "api_123",
        .created_at = 1000,
        .last_login = 2000,
        .enabled = true,
    };

    try std.testing.expectEqualStrings("testuser", user.username);
    try std.testing.expectEqual(Role.read_write, user.role);
    try std.testing.expectEqual(true, user.enabled);
}

test "User - disabled" {
    const user = User{
        .username = "disabled_user",
        .password_hash = "hash",
        .role = .none,
        .api_key = "key",
        .created_at = 0,
        .last_login = 0,
        .enabled = false,
    };

    try std.testing.expectEqual(false, user.enabled);
    try std.testing.expectEqual(Role.none, user.role);
}

test "Session - isValid when not expired" {
    // Session that expires far in the future
    const session = Session{
        .session_id = "sess_123",
        .username = "testuser",
        .created_at = 1000,
        .expires_at = std.math.maxInt(i64), // Far future
        .permissions = Permission.fromRole(.admin),
    };

    try std.testing.expectEqual(true, session.isValid());
}

test "Session - isValid when expired" {
    // Session that already expired (timestamp 0)
    const session = Session{
        .session_id = "sess_old",
        .username = "testuser",
        .created_at = 0,
        .expires_at = 0, // Expired at epoch
        .permissions = Permission.fromRole(.read_only),
    };

    try std.testing.expectEqual(false, session.isValid());
}

test "PermissionType - enum values" {
    const read = PermissionType.read;
    const write = PermissionType.write;
    const delete = PermissionType.delete;
    const admin = PermissionType.admin;

    try std.testing.expect(read != write);
    try std.testing.expect(write != delete);
    try std.testing.expect(delete != admin);
}

test "SecurityManager - init disabled" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    try std.testing.expectEqual(false, mgr.enabled);
    try std.testing.expectEqual(@as(i64, 3600 * 1000), mgr.session_timeout_ms);
}

test "SecurityManager - init enabled no auto admin" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try std.testing.expectEqual(true, mgr.enabled);

    // Admin is NOT created in init() - only in attachEngine()
    // For tests without Engine, createDefaultAdmin() must be called explicitly
    mgr.users_mutex.lock();
    defer mgr.users_mutex.unlock();
    try std.testing.expect(!mgr.users.contains("admin"));
}

test "SecurityManager - createDefaultAdmin" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    // Explicitly create default admin for tests
    try mgr.createDefaultAdmin();

    // Check admin user was created
    mgr.users_mutex.lock();
    defer mgr.users_mutex.unlock();
    try std.testing.expect(mgr.users.contains("admin"));
}

test "SecurityManager - authenticate when disabled" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    // When disabled, any auth should return anonymous admin session
    var session = try mgr.authenticate("anyone", "anything");
    defer session.deinit(allocator);

    try std.testing.expectEqualStrings("anonymous", session.username);
    try std.testing.expectEqual(true, session.permissions.can_admin);
}

test "SecurityManager - createUser duplicate error" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    // Create admin first (no longer auto-created in init)
    try mgr.createDefaultAdmin();

    // Now admin exists - creating again should fail
    const result = mgr.createUser("admin", "newpass", .admin);
    try std.testing.expectError(error.UserAlreadyExists, result);
}

test "SecurityManager - authenticate invalid credentials" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try mgr.createDefaultAdmin();

    // Wrong password
    const result = mgr.authenticate("admin", "wrongpassword");
    try std.testing.expectError(error.InvalidCredentials, result);
}

test "SecurityManager - authenticate valid credentials" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try mgr.createDefaultAdmin();

    // Correct admin password
    // Note: Don't call session.deinit() - mgr.deinit() frees the stored session
    const session = try mgr.authenticate("admin", "admin");

    try std.testing.expectEqualStrings("admin", session.username);
    try std.testing.expectEqual(true, session.permissions.can_admin);
}

test "SecurityManager - validateSession invalid" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    const result = mgr.validateSession("nonexistent_session");
    try std.testing.expectError(error.InvalidSession, result);
}

test "SecurityManager - checkPermission admin has all" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const session = Session{
        .session_id = "test",
        .username = "admin",
        .created_at = 0,
        .expires_at = std.math.maxInt(i64),
        .permissions = Permission.fromRole(.admin),
    };

    // Admin should have all permissions
    try mgr.checkPermission(&session, .read);
    try mgr.checkPermission(&session, .write);
    try mgr.checkPermission(&session, .delete);
    try mgr.checkPermission(&session, .admin);
}

test "SecurityManager - checkPermission read_only denied write" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const session = Session{
        .session_id = "test",
        .username = "reader",
        .created_at = 0,
        .expires_at = std.math.maxInt(i64),
        .permissions = Permission.fromRole(.read_only),
    };

    // Read only should have read, but not write
    try mgr.checkPermission(&session, .read);

    const write_result = mgr.checkPermission(&session, .write);
    try std.testing.expectError(error.PermissionDenied, write_result);

    const admin_result = mgr.checkPermission(&session, .admin);
    try std.testing.expectError(error.PermissionDenied, admin_result);
}

test "SecurityManager - checkPermission none denied all" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const session = Session{
        .session_id = "test",
        .username = "nobody",
        .created_at = 0,
        .expires_at = std.math.maxInt(i64),
        .permissions = Permission.fromRole(.none),
    };

    // No permissions
    try std.testing.expectError(error.PermissionDenied, mgr.checkPermission(&session, .read));
    try std.testing.expectError(error.PermissionDenied, mgr.checkPermission(&session, .write));
    try std.testing.expectError(error.PermissionDenied, mgr.checkPermission(&session, .delete));
    try std.testing.expectError(error.PermissionDenied, mgr.checkPermission(&session, .admin));
}

test "SecurityManager - deleteUser" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    // Create a user
    try mgr.createUser("testuser", "password", .read_only);

    // Delete the user
    try mgr.deleteUser("testuser");

    // Verify user is gone
    mgr.users_mutex.lock();
    defer mgr.users_mutex.unlock();
    try std.testing.expect(!mgr.users.contains("testuser"));
}

test "SecurityManager - changePassword wrong old password" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try mgr.createDefaultAdmin();

    const result = mgr.changePassword("admin", "wrongold", "newpass");
    try std.testing.expectError(error.InvalidCredentials, result);
}

test "SecurityManager - changePassword success" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try mgr.createDefaultAdmin();

    // Change admin password
    try mgr.changePassword("admin", "admin", "newpassword");

    // Old password should fail
    const old_auth = mgr.authenticate("admin", "admin");
    try std.testing.expectError(error.InvalidCredentials, old_auth);

    // New password should work
    // Note: Don't call session.deinit() - mgr.deinit() frees the stored session
    const session = try mgr.authenticate("admin", "newpassword");
    try std.testing.expectEqualStrings("admin", session.username);
}

test "SecurityManager - revokeSession" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, true);
    defer mgr.deinit();

    try mgr.createDefaultAdmin();

    // Create session
    // Note: Don't call session.deinit() - revokeSession will free it
    const session = try mgr.authenticate("admin", "admin");
    const session_id = try allocator.dupe(u8, session.session_id);
    defer allocator.free(session_id);

    // Validate it works (don't deinit - memory shared with stored session)
    _ = try mgr.validateSession(session_id);

    // Revoke it - this frees the session
    try mgr.revokeSession(session_id);

    // Should no longer be valid
    const result = mgr.validateSession(session_id);
    try std.testing.expectError(error.InvalidSession, result);
}

test "SecurityManager - hexEncode" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const data = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    const hex = try mgr.hexEncode(&data);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("48656c6c6f", hex);
}

test "SecurityManager - hexDecode" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const decoded = try mgr.hexDecode("48656c6c6f");
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("Hello", decoded);
}

test "SecurityManager - hexEncode/hexDecode roundtrip" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    // Test with SHA256-like data (32 bytes)
    const original = [_]u8{ 0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71 } ** 4;
    const hex = try mgr.hexEncode(&original);
    defer allocator.free(hex);

    const decoded = try mgr.hexDecode(hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}

test "SecurityManager - serializeUserToJson" {
    const allocator = std.testing.allocator;
    const mgr = try SecurityManager.init(allocator, false);
    defer mgr.deinit();

    const user = User{
        .username = "testuser",
        .password_hash = "abc", // Will be hex-encoded as "616263"
        .role = .read_write,
        .api_key = "yadb_test_123",
        .created_at = 1000,
        .last_login = 2000,
        .enabled = true,
    };

    const json = try mgr.serializeUserToJson(&user);
    defer allocator.free(json);

    // Verify JSON contains expected fields
    try std.testing.expect(std.mem.indexOf(u8, json, "\"username\":\"testuser\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"password_hash\":\"616263\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"role\":\"read_write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"enabled\":true") != null);
}
