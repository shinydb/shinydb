const std = @import("std");
const mem = std.mem;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;
const proto = @import("proto");
const Space = proto.Space;
const Store = proto.Store;
const Index = proto.Index;
const User = proto.User;
const Backup = proto.Backup;
const VLog = proto.VLog;
const FieldType = proto.FieldType;
const bson = @import("bson");
const Io = std.Io;
const File = Io.File;
const Dir = Io.Dir;
const Allocator = mem.Allocator;

const METADATA_FILE = "metadata.bson";
const USER_STORE_START_ID: u16 = 101; // User stores start at 101

const MetadataContainer = struct {
    spaces: []Space,
    stores: []Store,
    indexes: []Index,
    users: []User,
    backups: []Backup,
};

pub const Catalog = struct {
    allocator: mem.Allocator,
    spaces: std.StringHashMap(*Space),
    stores: std.StringHashMap(*Store),
    stores_by_id: std.AutoHashMap(u16, *Store),
    next_store_id: u16 = USER_STORE_START_ID,
    indexes: std.StringHashMap(*Index),
    indexes_by_store: std.AutoHashMap(u16, std.ArrayList(*Index)),
    users: std.StringHashMap(*User),
    backups: std.StringHashMap(*Backup),
    metadata_path: []const u8,
    io: Io,

    pub fn init(allocator: mem.Allocator, metadata_dir: []const u8, io: Io) !*Catalog {
        const catalog = try allocator.create(Catalog);

        const metadata_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ metadata_dir, METADATA_FILE });
        errdefer allocator.free(metadata_path);

        catalog.* = Catalog{
            .allocator = allocator,
            .spaces = std.StringHashMap(*Space).init(allocator),
            .stores = std.StringHashMap(*Store).init(allocator),
            .stores_by_id = std.AutoHashMap(u16, *Store).init(allocator),
            .indexes = std.StringHashMap(*Index).init(allocator),
            .indexes_by_store = std.AutoHashMap(u16, std.ArrayList(*Index)).init(allocator),
            .users = std.StringHashMap(*User).init(allocator),
            .backups = std.StringHashMap(*Backup).init(allocator),
            .metadata_path = metadata_path,
            .io = io,
        };

        try catalog.initDefaults();
        return catalog;
    }

    fn initDefaults(self: *Catalog) !void {
        // Create system space in memory
        const system_space = try self.allocator.create(Space);
        system_space.* = Space{
            .id = 0,
            .ns = try self.allocator.dupe(u8, "system"),
            .description = try self.allocator.dupe(u8, "System namespace for metadata"),
            .created_at = milliTimestamp(),
        };
        try self.spaces.put(system_space.ns, system_space);
    }

    /// Load all metadata from metadata.bson file
    pub fn loadMetadata(self: *Catalog) !void {
        std.log.info("Loading catalog from metadata file: {s}", .{self.metadata_path});

        // Read entire metadata file
        const file_data = Dir.readFileAlloc(.cwd(), self.io, self.metadata_path, self.allocator, @enumFromInt(10 * 1024 * 1024)) catch |err| {
            if (err == error.FileNotFound) {
                std.log.info("Metadata file not found, starting with empty catalog", .{});
                return;
            }
            return err;
        };
        defer self.allocator.free(file_data);

        if (file_data.len == 0) {
            std.log.info("Metadata file is empty", .{});
            return;
        }

        // Decode BSON
        const doc = try bson.decode(self.allocator, MetadataContainer, file_data);
        defer {
            self.allocator.free(doc.spaces);
            self.allocator.free(doc.stores);
            self.allocator.free(doc.indexes);
            self.allocator.free(doc.users);
            self.allocator.free(doc.backups);
        }

        // Load spaces
        for (doc.spaces) |space_data| {
            if (self.spaces.contains(space_data.ns)) {
                // Free BSON-decoded strings we won't use
                self.allocator.free(@constCast(space_data.ns));
                if (space_data.description) |d| self.allocator.free(@constCast(d));
                continue;
            }

            const space = try self.allocator.create(Space);
            space.* = Space{
                .id = space_data.id,
                .ns = space_data.ns,
                .description = space_data.description,
                .created_at = space_data.created_at,
            };
            try self.spaces.put(space.ns, space);
        }

        // Load stores
        for (doc.stores) |store_data| {
            if (self.stores.contains(store_data.ns)) {
                self.allocator.free(@constCast(store_data.ns));
                if (store_data.description) |d| self.allocator.free(@constCast(d));
                continue;
            }

            const store = try self.allocator.create(Store);
            store.* = Store{
                .id = store_data.id,
                .store_id = store_data.store_id,
                .ns = store_data.ns,
                .description = store_data.description,
                .created_at = store_data.created_at,
            };
            try self.stores.put(store.ns, store);
            try self.stores_by_id.put(store.store_id, store);

            // Track max store_id for monotonic counter
            if (store.store_id >= self.next_store_id) {
                self.next_store_id = store.store_id + 1;
            }
        }

        // Load indexes
        for (doc.indexes) |index_data| {
            if (self.indexes.contains(index_data.ns)) {
                self.allocator.free(@constCast(index_data.ns));
                self.allocator.free(@constCast(index_data.field));
                if (index_data.description) |d| self.allocator.free(@constCast(d));
                continue;
            }

            const index = try self.allocator.create(Index);
            index.* = Index{
                .id = index_data.id,
                .store_id = index_data.store_id,
                .ns = index_data.ns,
                .field = index_data.field,
                .unique = index_data.unique,
                .field_type = index_data.field_type,
                .description = index_data.description,
                .created_at = index_data.created_at,
            };
            try self.indexes.put(index.ns, index);

            const gop = try self.indexes_by_store.getOrPut(index.store_id);
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }
            try gop.value_ptr.append(self.allocator, index);
        }

        // Load users
        for (doc.users) |user_data| {
            if (self.users.contains(user_data.username)) {
                self.allocator.free(@constCast(user_data.username));
                self.allocator.free(@constCast(user_data.password_hash));
                continue;
            }

            const user = try self.allocator.create(User);
            user.* = User{
                .id = user_data.id,
                .username = user_data.username,
                .password_hash = user_data.password_hash,
                .role = user_data.role,
                .created_at = user_data.created_at,
            };
            try self.users.put(user.username, user);
        }

        // Load backups
        for (doc.backups) |backup_data| {
            if (self.backups.contains(backup_data.name)) {
                self.allocator.free(@constCast(backup_data.name));
                self.allocator.free(@constCast(backup_data.backup_path));
                if (backup_data.description) |d| self.allocator.free(@constCast(d));
                continue;
            }

            const backup = try self.allocator.create(Backup);
            backup.* = Backup{
                .id = backup_data.id,
                .name = backup_data.name,
                .backup_path = backup_data.backup_path,
                .size_bytes = backup_data.size_bytes,
                .created_at = backup_data.created_at,
                .description = backup_data.description,
            };
            try self.backups.put(backup.name, backup);
        }

        std.log.info("Loaded {} spaces, {} stores, {} indexes, {} users, {} backups", .{
            self.spaces.count(),
            self.stores.count(),
            self.indexes.count(),
            self.users.count(),
            self.backups.count(),
        });
    }

    /// Save all metadata to metadata.bson file
    pub fn saveMetadata(self: *Catalog) !void {
        // Collect all entities into arrays
        var spaces_list: std.ArrayList(Space) = .empty;
        defer spaces_list.deinit(self.allocator);
        var space_iter = self.spaces.valueIterator();
        while (space_iter.next()) |space| {
            try spaces_list.append(self.allocator, space.*.*);
        }

        var stores_list: std.ArrayList(Store) = .empty;
        defer stores_list.deinit(self.allocator);
        var store_iter = self.stores.valueIterator();
        while (store_iter.next()) |store| {
            try stores_list.append(self.allocator, store.*.*);
        }

        var indexes_list: std.ArrayList(Index) = .empty;
        defer indexes_list.deinit(self.allocator);
        var index_iter = self.indexes.valueIterator();
        while (index_iter.next()) |index| {
            try indexes_list.append(self.allocator, index.*.*);
        }

        var users_list: std.ArrayList(User) = .empty;
        defer users_list.deinit(self.allocator);
        var user_iter = self.users.valueIterator();
        while (user_iter.next()) |user| {
            try users_list.append(self.allocator, user.*.*);
        }

        var backups_list: std.ArrayList(Backup) = .empty;
        defer backups_list.deinit(self.allocator);
        var backup_iter = self.backups.valueIterator();
        while (backup_iter.next()) |backup| {
            try backups_list.append(self.allocator, backup.*.*);
        }

        // Create metadata container
        const metadata = MetadataContainer{
            .spaces = spaces_list.items,
            .stores = stores_list.items,
            .indexes = indexes_list.items,
            .users = users_list.items,
            .backups = backups_list.items,
        };

        // Encode to BSON
        const encoded = try bson.encode(self.allocator, metadata);
        defer self.allocator.free(encoded);

        // Write to file atomically (write to temp, then rename)
        const temp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.metadata_path});
        defer self.allocator.free(temp_path);

        const file = try Dir.createFile(.cwd(), self.io, temp_path, .{ .read = false, .truncate = true });
        defer file.close(self.io);

        try file.writePositionalAll(self.io, encoded, 0);
        try file.sync(self.io);

        // Atomic rename
        try Dir.rename(.cwd(), temp_path, .cwd(), self.metadata_path, self.io);

        std.log.info("Saved metadata: {} spaces, {} stores, {} indexes, {} users, {} backups", .{
            spaces_list.items.len,
            stores_list.items.len,
            indexes_list.items.len,
            users_list.items.len,
            backups_list.items.len,
        });
    }

    // ========================================================================
    // Space operations
    // ========================================================================

    pub fn createSpace(self: *Catalog, ns: []const u8, description: ?[]const u8) !*Space {
        if (self.spaces.get(ns)) |existing| {
            return existing;
        }

        const ns_owned = try self.allocator.dupe(u8, ns);
        errdefer self.allocator.free(ns_owned);

        const desc_owned = if (description) |d| try self.allocator.dupe(u8, d) else null;
        errdefer if (desc_owned) |d| self.allocator.free(d);

        const space = try self.allocator.create(Space);
        space.* = Space{
            .id = @intCast(self.spaces.count()),
            .ns = ns_owned,
            .description = desc_owned,
            .created_at = milliTimestamp(),
        };
        try self.spaces.put(ns_owned, space);
        try self.saveMetadata();

        return space;
    }

    pub fn dropSpace(self: *Catalog, space_ns: []const u8) !void {
        if (self.spaces.fetchRemove(space_ns)) |entry| {
            const space = entry.value;
            self.allocator.free(@constCast(space.ns));
            if (space.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(space);
            try self.saveMetadata();
        } else {
            return error.SpaceNotFound;
        }
    }

    pub fn listSpaces(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Space) {
        var result: std.ArrayList(*Space) = .empty;
        var iter = self.spaces.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    /// List spaces as BSON-encoded bytes for protocol replies
    pub fn listSpacesBson(self: *Catalog, allocator: mem.Allocator, ns_filter: ?[]const u8) ![]const u8 {
        var list: std.ArrayList(Space) = .empty;
        defer list.deinit(allocator);
        var iter = self.spaces.valueIterator();
        while (iter.next()) |space_ptr| {
            const space = space_ptr.*;
            if (ns_filter) |filter| {
                if (!mem.startsWith(u8, space.ns, filter)) continue;
            }
            try list.append(allocator, space.*);
        }
        const wrapper = struct { spaces: []Space }{ .spaces = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    pub fn getSpace(self: *Catalog, ns: []const u8) ?*Space {
        return self.spaces.get(ns);
    }

    // ========================================================================
    // Store operations
    // ========================================================================

    pub fn createStore(self: *Catalog, ns: []const u8, description: ?[]const u8) !*Store {
        if (self.stores.get(ns)) |existing| {
            return existing;
        }

        const ns_owned = try self.allocator.dupe(u8, ns);
        errdefer self.allocator.free(ns_owned);

        const desc_owned = if (description) |d| try self.allocator.dupe(u8, d) else null;
        errdefer if (desc_owned) |d| self.allocator.free(d);

        // Use monotonic counter for store_id assignment
        const store_id: u16 = self.next_store_id;
        self.next_store_id += 1;

        const store = try self.allocator.create(Store);
        store.* = Store{
            .id = @intCast(self.stores.count()),
            .store_id = store_id,
            .ns = ns_owned,
            .description = desc_owned,
            .created_at = milliTimestamp(),
        };
        try self.stores.put(ns_owned, store);
        try self.stores_by_id.put(store_id, store);
        try self.saveMetadata();

        return store;
    }

    pub fn dropStore(self: *Catalog, store_ns: []const u8) !void {
        if (self.stores.fetchRemove(store_ns)) |entry| {
            const store = entry.value;
            _ = self.stores_by_id.remove(store.store_id);
            self.allocator.free(@constCast(store.ns));
            if (store.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(store);
            try self.saveMetadata();
        } else {
            return error.StoreNotFound;
        }
    }

    pub fn listStores(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Store) {
        var result: std.ArrayList(*Store) = .empty;
        var iter = self.stores.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    /// List stores as BSON-encoded bytes for protocol replies
    pub fn listStoresBson(self: *Catalog, allocator: mem.Allocator, ns_filter: ?[]const u8) ![]const u8 {
        var list: std.ArrayList(Store) = .empty;
        defer list.deinit(allocator);
        var iter = self.stores.valueIterator();
        while (iter.next()) |store_ptr| {
            const store = store_ptr.*;
            if (ns_filter) |filter| {
                if (!mem.startsWith(u8, store.ns, filter)) continue;
            }
            try list.append(allocator, store.*);
        }
        const wrapper = struct { stores: []Store }{ .stores = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    pub fn getStore(self: *Catalog, ns: []const u8) ?*Store {
        return self.stores.get(ns);
    }

    pub fn findStoreByNamespace(self: *Catalog, ns: []const u8) ?*Store {
        return self.getStore(ns);
    }

    pub fn getStoreById(self: *Catalog, store_id: u16) ?*Store {
        return self.stores_by_id.get(store_id);
    }

    // ========================================================================
    // Index operations
    // ========================================================================

    pub fn createIndex(self: *Catalog, index_ns: []const u8, field: []const u8, field_type: FieldType, unique: bool) !*Index {
        const index = try self.allocator.create(Index);
        index.* = Index{
            .id = @intCast(self.indexes.count() + 1),
            .store_id = 0, // Will be set by createIndexForStore
            .ns = index_ns,
            .field = field,
            .field_type = field_type,
            .unique = unique,
            .description = null,
            .created_at = milliTimestamp(),
        };
        try self.indexes.put(index_ns, index);
        return index;
    }

    pub fn createIndexForStore(self: *Catalog, store_id: u16, index_ns: []const u8, field: []const u8, field_type: FieldType, unique: bool) !*Index {
        if (self.indexes.get(index_ns)) |existing| {
            return existing;
        }

        const ns_owned = try self.allocator.dupe(u8, index_ns);
        errdefer self.allocator.free(ns_owned);

        const field_owned = try self.allocator.dupe(u8, field);
        errdefer self.allocator.free(field_owned);

        const index = try self.allocator.create(Index);
        index.* = Index{
            .id = @intCast(self.indexes.count() + 1),
            .store_id = store_id,
            .ns = ns_owned,
            .field = field_owned,
            .field_type = field_type,
            .unique = unique,
            .description = null,
            .created_at = milliTimestamp(),
        };
        try self.indexes.put(ns_owned, index);

        const gop = try self.indexes_by_store.getOrPut(store_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, index);
        try self.saveMetadata();

        return index;
    }

    pub fn getIndexesByStoreId(self: *Catalog, store_id: u16) ?*std.ArrayList(*Index) {
        return self.indexes_by_store.getPtr(store_id);
    }

    pub fn dropIndex(self: *Catalog, index_ns: []const u8) !void {
        if (self.indexes.fetchRemove(index_ns)) |entry| {
            const index = entry.value;

            // Remove from indexes_by_store
            if (self.indexes_by_store.getPtr(index.store_id)) |idx_list| {
                for (idx_list.items, 0..) |idx, i| {
                    if (mem.eql(u8, idx.ns, index_ns)) {
                        _ = idx_list.swapRemove(i);
                        break;
                    }
                }
            }

            self.allocator.free(@constCast(index.ns));
            self.allocator.free(@constCast(index.field));
            if (index.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(index);
            try self.saveMetadata();
        } else {
            return error.IndexNotFound;
        }
    }

    pub fn listIndexes(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Index) {
        var result: std.ArrayList(*Index) = .empty;
        var iter = self.indexes.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    /// List indexes as BSON-encoded bytes for protocol replies
    pub fn listIndexesBson(self: *Catalog, allocator: mem.Allocator, ns_filter: ?[]const u8) ![]const u8 {
        var list: std.ArrayList(Index) = .empty;
        defer list.deinit(allocator);
        var iter = self.indexes.valueIterator();
        while (iter.next()) |index_ptr| {
            const index = index_ptr.*;
            if (ns_filter) |filter| {
                if (!mem.startsWith(u8, index.ns, filter)) continue;
            }
            try list.append(allocator, index.*);
        }
        const wrapper = struct { indexes: []Index }{ .indexes = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    pub fn hasIndex(self: *Catalog, index_ns: []const u8) bool {
        return self.indexes.contains(index_ns);
    }

    pub fn getIndexesForStore(self: *Catalog, store_ns: []const u8, allocator: mem.Allocator) !std.ArrayList(*Index) {
        var result: std.ArrayList(*Index) = .empty;
        var iter = self.indexes.iterator();
        while (iter.next()) |entry| {
            const index = entry.value_ptr.*;
            if (self.getStoreById(index.store_id)) |store| {
                if (mem.eql(u8, store.ns, store_ns)) {
                    try result.append(allocator, index);
                }
            }
        }
        return result;
    }

    // ========================================================================
    // User operations
    // ========================================================================

    /// List users as BSON-encoded bytes for protocol replies
    pub fn listUsersBson(self: *Catalog, allocator: mem.Allocator) ![]const u8 {
        var list: std.ArrayList(User) = .empty;
        defer list.deinit(allocator);
        var iter = self.users.valueIterator();
        while (iter.next()) |user_ptr| {
            try list.append(allocator, user_ptr.*.*);
        }
        const wrapper = struct { users: []User }{ .users = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    // ========================================================================
    // Backup operations
    // ========================================================================

    /// List backups as BSON-encoded bytes for protocol replies
    pub fn listBackupsBson(self: *Catalog, allocator: mem.Allocator) ![]const u8 {
        var list: std.ArrayList(Backup) = .empty;
        defer list.deinit(allocator);
        var iter = self.backups.valueIterator();
        while (iter.next()) |backup_ptr| {
            try list.append(allocator, backup_ptr.*.*);
        }
        const wrapper = struct { backups: []Backup }{ .backups = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    // ========================================================================
    // VLog operations
    // ========================================================================

    /// List vlogs as BSON-encoded bytes for protocol replies
    /// This is used by the replication protocol to get the list of available vlogs and their metadata
    pub fn listVLogsBson(self: *Catalog, allocator: mem.Allocator) ![]const u8 {
        var list: std.ArrayList(VLog) = .empty;
        defer list.deinit(allocator);
        var iter = self.vlogs.valueIterator();
        while (iter.next()) |vlog_ptr| {
            try list.append(allocator, vlog_ptr.*.*);
        }
        const wrapper = struct { vlogs: []VLog }{ .vlogs = list.items };
        var encoder = bson.Encoder.init(allocator);
        defer encoder.deinit();
        return try encoder.encode(wrapper);
    }

    pub fn createVLog(self: *Catalog, id: u16, file_name: []const u8) !*VLog {
        const vlog = try self.allocator.create(VLog);
        vlog.* = VLog{
            .id = id,
            .file_name = try self.allocator.dupe(u8, file_name),
            .created_at = milliTimestamp(),
        };
        try self.vlogs.put(file_name, vlog);
        try self.saveMetadata();
        return vlog;
    }

    pub fn listVLogs(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*VLog) {
        var result: std.ArrayList(*VLog) = .empty;
        var iter = self.vlogs.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    pub fn deinit(self: *Catalog) void {
        var space_iter = self.spaces.iterator();
        while (space_iter.next()) |pair| {
            const space = pair.value_ptr.*;
            self.allocator.free(@constCast(space.ns));
            if (space.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(space);
        }
        self.spaces.deinit();

        var store_iter = self.stores.iterator();
        while (store_iter.next()) |pair| {
            const store = pair.value_ptr.*;
            self.allocator.free(@constCast(store.ns));
            if (store.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(store);
        }
        self.stores.deinit();
        self.stores_by_id.deinit();

        var index_iter = self.indexes.iterator();
        while (index_iter.next()) |pair| {
            const index = pair.value_ptr.*;
            self.allocator.free(@constCast(index.ns));
            self.allocator.free(@constCast(index.field));
            if (index.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(index);
        }
        self.indexes.deinit();

        var idx_by_store_iter = self.indexes_by_store.iterator();
        while (idx_by_store_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.indexes_by_store.deinit();

        var user_iter = self.users.iterator();
        while (user_iter.next()) |pair| {
            const user = pair.value_ptr.*;
            self.allocator.free(@constCast(user.username));
            self.allocator.free(@constCast(user.password_hash));
            self.allocator.destroy(user);
        }
        self.users.deinit();

        var backup_iter = self.backups.iterator();
        while (backup_iter.next()) |pair| {
            const backup = pair.value_ptr.*;
            self.allocator.free(@constCast(backup.name));
            self.allocator.free(@constCast(backup.backup_path));
            if (backup.description) |d| self.allocator.free(@constCast(d));
            self.allocator.destroy(backup);
        }
        self.backups.deinit();

        self.allocator.free(self.metadata_path);
        self.allocator.destroy(self);
    }
};
