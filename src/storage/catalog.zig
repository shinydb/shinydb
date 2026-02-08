const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;
const Entry = @import("../common/common.zig").Entry;
const proto = @import("proto");
const Space = proto.Space;
const Store = proto.Store;
const Index = proto.Index;
const FieldType = proto.FieldType;
const bson = @import("bson");

// Catalog doc_types for persistence
const CATALOG_DOC_TYPE_SPACE: u8 = 1;
const CATALOG_DOC_TYPE_STORE: u8 = 2;
const CATALOG_DOC_TYPE_INDEX: u8 = 3;

pub const Catalog = struct {
    allocator: mem.Allocator,
    spaces: std.StringHashMap(*Space),
    stores: std.StringHashMap(*Store),
    stores_by_id: std.AutoHashMap(u16, *Store),  // store_id → Store
    indexes: std.StringHashMap(*Index),
    indexes_by_store: std.AutoHashMap(u16, std.ArrayList(*Index)),  // store_id → indexes

    pub fn init(allocator: mem.Allocator) !*Catalog {
        const catalog = try allocator.create(Catalog);
        catalog.* = Catalog{
            .allocator = allocator,
            .spaces = std.StringHashMap(*Space).init(allocator),
            .stores = std.StringHashMap(*Store).init(allocator),
            .stores_by_id = std.AutoHashMap(u16, *Store).init(allocator),
            .indexes = std.StringHashMap(*Index).init(allocator),
            .indexes_by_store = std.AutoHashMap(u16, std.ArrayList(*Index)).init(allocator),
        };
        try catalog.initDefaults();
        return catalog;
    }

    fn initDefaults(self: *Catalog) !void {
        const catalog_index = try self.allocator.create(Index);
        catalog_index.* = Index{
            .id = 1,
            .store_id = 0,  // Reserved for system
            .ns = "system.catalog.ns",
            .field = "ns",
            .unique = true,
            .field_type = FieldType.String,
            .description = "Default system index",
            .created_at = milliTimestamp(),
        };
        try self.indexes.put(catalog_index.ns, catalog_index);
    }

    /// Load catalog entries from database
    /// This should be called after the database is fully initialized
    pub fn loadFromDb(self: *Catalog, db: anytype) !void {
        const allocator = self.allocator;

        std.log.info("Loading catalog from database...", .{});


        // Scan the primary index for catalog entries
        // We need to iterate through keys with doc_types 1, 2, and 3
        var it = try db.primary_index.iterator();
        defer it.deinit();

        var total_keys: usize = 0;

        while (try it.next()) |cell| {
            total_keys += 1;
            // Convert key bytes to u128 (index stores keys in big-endian)
            if (cell.key.len != @sizeOf(u128)) continue;
            const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .big);

            // Catalog keys have a specific format:
            // - store_id at bits 0-15 = 0
            // - vlog_id at bits 16-23 = 0
            // - doc_type at bits 24-31 = 1, 2, or 3
            // Document keys (keygen) have store_id at bits 112-127 (non-zero for actual stores)

            // First check if this looks like a catalog key (store_id=0, vlog_id=0 in catalog format)
            const catalog_store_id: u16 = @truncate(key & 0xFFFF);
            const catalog_vlog_id: u8 = @truncate((key >> 16) & 0xFF);
            const doc_type: u8 = @truncate((key >> 24) & 0xFF);

            // Only process as catalog entry if it matches catalog key format:
            // - catalog store_id (bits 0-15) must be 0
            // - catalog vlog_id (bits 16-23) must be 0
            // - doc_type must be valid catalog type (1, 2, or 3)
            const is_catalog_key = catalog_store_id == 0 and catalog_vlog_id == 0 and
                (doc_type == CATALOG_DOC_TYPE_SPACE or
                doc_type == CATALOG_DOC_TYPE_STORE or
                doc_type == CATALOG_DOC_TYPE_INDEX);

            if (is_catalog_key) {

                // Get the value from database
                const value = try db.get(@as(i128, @bitCast(key)));

                // Deserialize based on doc_type
                if (doc_type == CATALOG_DOC_TYPE_SPACE) {
                    const space = try allocator.create(Space);
                    errdefer allocator.destroy(space);

                    var decoder = bson.Decoder.init(allocator, value);
                    space.* = try decoder.decode(Space);
                    try self.spaces.put(space.ns, space);

                } else if (doc_type == CATALOG_DOC_TYPE_STORE) {
                    const store = try allocator.create(Store);
                    errdefer allocator.destroy(store);

                    var decoder = bson.Decoder.init(allocator, value);
                    store.* = try decoder.decode(Store);
                    try self.stores.put(store.ns, store);
                    try self.stores_by_id.put(store.store_id, store);  // Use store_id, not id

                } else if (doc_type == CATALOG_DOC_TYPE_INDEX) {
                    const index = try allocator.create(Index);
                    errdefer allocator.destroy(index);

                    var decoder = bson.Decoder.init(allocator, value);
                    index.* = try decoder.decode(Index);
                    try self.indexes.put(index.ns, index);

                    // Add to indexes_by_store
                    const gop = try self.indexes_by_store.getOrPut(index.store_id);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .empty;
                    }
                    try gop.value_ptr.append(allocator, index);
                }
            }
        }

        std.log.info("Scanned {} total keys in primary index", .{total_keys});
        std.log.info("Loaded {} spaces, {} stores, {} indexes from database", .{
            self.spaces.count(),
            self.stores.count(),
            self.indexes.count(),
        });
    }

    /// Generate a key for a catalog entry
    fn catalogKey(entity_id: u64, doc_type: u8) u128 {
        // Format: store_id=0 (16 bits) | vlog_id=0 (8 bits) | doc_type (8 bits) | entity_id (64 bits) | random (32 bits)
        // IMPORTANT: The flush function uses KeyGen.extractMetadata which expects vlog_id at bits 96-103.
        // We must keep bits 96-103 = 0 so catalog entries use vlog_id=0.
        // Only use bits 104-127 for the random part (24 bits).
        const store_id: u128 = 0;
        const vlog_id: u128 = 0;
        const dt: u128 = doc_type;
        const eid: u128 = entity_id;

        // Put random part at bits 104-127 (NOT bits 96-127) to keep vlog_id bits (96-103) = 0
        const random: u128 = (entity_id & 0xFFFFFF) << 8; // Shift by 8 to start at bit 104

        return store_id | (vlog_id << 16) | (dt << 24) | (eid << 32) | (random << 96);
    }

    /// Save a space to the database
    fn saveSpace(self: *Catalog, space: *Space, db: anytype) !void {
        // Serialize space to BSON
        var encoder = bson.Encoder.init(self.allocator);
        defer encoder.deinit();
        const encoded_copy = try encoder.encode(space.*);

        // Generate key
        const key = catalogKey(space.id, CATALOG_DOC_TYPE_SPACE);

        // Create entry
        const entry = Entry{
            .key = key,
            .ns = space.ns,
            .value = encoded_copy,
            .timestamp = milliTimestamp(),
            .kind = .insert,
        };

        // Save to database
        try db.post(entry);
    }

    /// Save a store to the database
    fn saveStore(self: *Catalog, store: *Store, db: anytype) !void {
        // Serialize store to BSON
        var encoder = bson.Encoder.init(self.allocator);
        defer encoder.deinit();
        const encoded_copy = try encoder.encode(store.*);

        // Generate key
        const key = catalogKey(store.id, CATALOG_DOC_TYPE_STORE);

        // Create entry
        const entry = Entry{
            .key = key,
            .ns = store.ns,
            .value = encoded_copy,
            .timestamp = milliTimestamp(),
            .kind = .insert,
        };

        // Save to database
        try db.post(entry);
    }

    /// Save an index to the database
    fn saveIndex(self: *Catalog, index: *Index, db: anytype) !void {
        // Serialize index to BSON
        var encoder = bson.Encoder.init(self.allocator);
        defer encoder.deinit();
        const encoded_copy = try encoder.encode(index.*);

        // Generate key
        const key = catalogKey(index.id, CATALOG_DOC_TYPE_INDEX);

        // Create entry
        const entry = Entry{
            .key = key,
            .ns = index.ns,
            .value = encoded_copy,
            .timestamp = milliTimestamp(),
            .kind = .insert,
        };

        // Save to database
        try db.post(entry);
    }

    /// Delete a catalog entry from the database
    fn deleteCatalogEntry(entity_id: u64, doc_type: u8, db: anytype) !void {
        const key = catalogKey(entity_id, doc_type);
        try db.del(@as(i128, @bitCast(key)), milliTimestamp());
    }

    pub fn deinit(self: *Catalog) void {
        var space_iter = self.spaces.iterator();
        while (space_iter.next()) |pair| {
            self.allocator.destroy(pair.value_ptr.*);
        }
        self.spaces.deinit();

        var store_iter = self.stores.iterator();
        while (store_iter.next()) |pair| {
            self.allocator.destroy(pair.value_ptr.*);
        }
        self.stores.deinit();
        self.stores_by_id.deinit();

        var index_iter = self.indexes.iterator();
        while (index_iter.next()) |pair| {
            self.allocator.destroy(pair.value_ptr.*);
        }
        self.indexes.deinit();

        // Cleanup indexes_by_store
        var idx_by_store_iter = self.indexes_by_store.iterator();
        while (idx_by_store_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.indexes_by_store.deinit();

        self.allocator.destroy(self);
    }

    /// Get all indexes for a specific store
    pub fn getIndexesForStore(self: *Catalog, store_ns: []const u8, allocator: mem.Allocator) !std.ArrayList(*Index) {
        var result: std.ArrayList(*Index) = .empty;
        var iter = self.indexes.iterator();
        while (iter.next()) |entry| {
            const index = entry.value_ptr.*;
            // Check if index namespace starts with store namespace
            if (mem.startsWith(u8, index.ns, store_ns)) {
                try result.append(allocator, index);
            }
        }
        return result;
    }

    /// Create and register a new index
    pub fn createIndex(self: *Catalog, index_ns: []const u8, field: []const u8, field_type: FieldType, unique: bool) !*Index {
        const index = try self.allocator.create(Index);
        index.* = Index{
            .id = @intCast(self.indexes.count() + 1),
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

    /// Check if an index exists
    pub fn hasIndex(self: *Catalog, index_ns: []const u8) bool {
        return self.indexes.contains(index_ns);
    }

    /// Create and register a new space
    pub fn createSpace(self: *Catalog, ns: []const u8, description: ?[]const u8, db: anytype) !*Space {
        // Check if space already exists - return it instead of error
        if (self.spaces.get(ns)) |existing_space| {
            return existing_space;
        }

        // Duplicate strings so catalog owns them
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

        // Persist to database
        try self.saveSpace(space, db);

        return space;
    }

    /// Drop (delete) a space
    pub fn dropSpace(self: *Catalog, space_ns: []const u8, db: anytype) !void {
        if (self.spaces.fetchRemove(space_ns)) |entry| {
            const space = entry.value;

            // Delete from database
            try deleteCatalogEntry(space.id, CATALOG_DOC_TYPE_SPACE, db);

            // Free owned strings
            self.allocator.free(@constCast(space.ns));
            if (space.description) |d| self.allocator.free(@constCast(d));

            self.allocator.destroy(space);
        } else {
            return error.SpaceNotFound;
        }
    }

    /// List all spaces
    pub fn listSpaces(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Space) {
        var result: std.ArrayList(*Space) = .empty;
        var iter = self.spaces.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    /// Create and register a new store
    pub fn createStore(self: *Catalog, ns: []const u8, description: ?[]const u8, db: anytype) !*Store {
        // Check if store already exists - return it instead of error
        if (self.stores.get(ns)) |existing_store| {
            return existing_store;
        }

        // Duplicate strings so catalog owns them
        const ns_owned = try self.allocator.dupe(u8, ns);
        errdefer self.allocator.free(ns_owned);

        const desc_owned = if (description) |d| try self.allocator.dupe(u8, d) else null;
        errdefer if (desc_owned) |d| self.allocator.free(d);

        // Generate IDs (simple counter-based approach)
        const id: u16 = @intCast(self.stores.count());
        const store_id: u16 = @intCast(self.stores.count() + 1);

        const store = try self.allocator.create(Store);
        store.* = Store{
            .id = id,
            .store_id = store_id,
            .ns = ns_owned,
            .description = desc_owned,
            .created_at = milliTimestamp(),
        };
        try self.stores.put(ns_owned, store);
        try self.stores_by_id.put(store_id, store);

        // Persist to database
        try self.saveStore(store, db);

        return store;
    }

    /// Drop (delete) a store
    pub fn dropStore(self: *Catalog, store_ns: []const u8, db: anytype) !void {
        if (self.stores.fetchRemove(store_ns)) |entry| {
            const store = entry.value;
            _ = self.stores_by_id.remove(store.store_id);  // Use store_id, not id

            // Delete from database (still use id for the catalog key)
            try deleteCatalogEntry(store.id, CATALOG_DOC_TYPE_STORE, db);

            // Free owned strings
            self.allocator.free(@constCast(store.ns));
            if (store.description) |d| self.allocator.free(@constCast(d));

            self.allocator.destroy(store);
        } else {
            return error.StoreNotFound;
        }
    }

    /// List all stores
    pub fn listStores(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Store) {
        var result: std.ArrayList(*Store) = .empty;
        var iter = self.stores.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }

    /// Find a store by namespace
    pub fn findStoreByNamespace(self: *Catalog, store_ns: []const u8) ?*Store {
        return self.stores.get(store_ns);
    }

    /// Get all indexes for a specific store by store_id
    pub fn getIndexesByStoreId(self: *Catalog, store_id: u16) ?*std.ArrayList(*Index) {
        return self.indexes_by_store.getPtr(store_id);
    }

    /// Create and register a new index with store_id
    pub fn createIndexForStore(self: *Catalog, store_id: u16, index_ns: []const u8, field: []const u8, field_type: FieldType, unique: bool, db: anytype) !*Index {
        // Duplicate strings so catalog owns them
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

        // Register in main index map
        try self.indexes.put(ns_owned, index);

        // Register in store_id → indexes map
        const gop = try self.indexes_by_store.getOrPut(store_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, index);

        // Persist to database
        try self.saveIndex(index, db);

        return index;
    }

    /// Drop (delete) an index
    pub fn dropIndex(self: *Catalog, index_ns: []const u8, db: anytype) !void {
        if (self.indexes.fetchRemove(index_ns)) |entry| {
            const index = entry.value;

            // Remove from indexes_by_store map if present
            if (self.indexes_by_store.getPtr(index.store_id)) |idx_list| {
                for (idx_list.items, 0..) |idx, i| {
                    if (mem.eql(u8, idx.ns, index_ns)) {
                        _ = idx_list.swapRemove(i);
                        break;
                    }
                }
            }

            // Delete from database
            try deleteCatalogEntry(index.id, CATALOG_DOC_TYPE_INDEX, db);

            // Free owned strings
            self.allocator.free(@constCast(index.ns));
            self.allocator.free(@constCast(index.field));
            if (index.description) |d| self.allocator.free(@constCast(d));

            self.allocator.destroy(index);
        } else {
            return error.IndexNotFound;
        }
    }

    /// List all indexes
    pub fn listIndexes(self: *Catalog, allocator: mem.Allocator) !std.ArrayList(*Index) {
        var result: std.ArrayList(*Index) = .empty;
        var iter = self.indexes.iterator();
        while (iter.next()) |entry| {
            try result.append(allocator, entry.value_ptr.*);
        }
        return result;
    }
};

test "catalog" {
    const allocator = std.heap.page_allocator;
    var catalog = try Catalog.init(allocator);
    defer catalog.deinit();

    // Test adding spaces
    const space1 = try allocator.create(Space);
    space1.* = Space{
        .id = 0,
        .ns = "system.spaces1",
        .description = "Default system space",
        .created_at = milliTimestamp(),
    };
    try catalog.spaces.put(space1.ns, space1);

    const space2 = try allocator.create(Space);
    space2.* = Space{
        .id = 1,
        .ns = "system.spaces2",
        .description = "Default system space",
        .created_at = milliTimestamp(),
    };
    try catalog.spaces.put(space2.ns, space2);

    // Test getting spaces
    try std.testing.expect(catalog.spaces.get("system.spaces1") != null);
    try std.testing.expect(catalog.spaces.get("system.spaces2") != null);
}
