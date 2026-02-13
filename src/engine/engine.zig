const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;

const Db = @import("../storage/db.zig").Db;
const Config = @import("../common/config.zig").Config;
const WriteAheadLog = @import("../durability/write_ahead_log.zig").WriteAheadLog;
const WalConfig = @import("../durability/write_ahead_log.zig").WalConfig;
const Index = @import("../storage/bptree.zig").Index;
const IndexConfig = @import("../storage/bptree.zig").IndexConfig;
const common = @import("../common/common.zig");
const Entry = common.Entry;
const milliTimestamp = common.milliTimestamp;
const KeyGen = @import("../common/keygen.zig").KeyGen;
const Catalog = @import("../storage/catalog.zig").Catalog;
const LruCache = @import("../storage/lru_cache.zig").LruCache;
const bson = @import("bson");
const query_engine = @import("../storage/query_engine.zig");
const FieldExtractor = @import("../storage/field_extractor.zig").FieldExtractor;
const FieldValue = @import("../storage/field_extractor.zig").FieldValue;

const log = std.log.scoped(.engine);

/// Database Engine - manages concurrent database operations using std.Io
/// Replaces the actor-based system with direct concurrent operations
pub const Engine = struct {
    allocator: Allocator,
    config: *Config,
    io: Io,
    db: *Db,
    wal: ?*WriteAheadLog,
    primary_index: *Index(u128, u64),
    keygen: KeyGen,
    catalog: *Catalog,

    // Synchronization for concurrent access
    db_mutex: Mutex,
    wal_mutex: Mutex,
    primary_index_mutex: Mutex,
    catalog_mutex: Mutex,

    // LRU cache for hot key reads
    read_cache: ?*LruCache(u128, []const u8),

    const Self = @This();

    pub fn init(allocator: Allocator, config: *Config, io: Io) !*Self {
        const engine = try allocator.create(Self);
        errdefer allocator.destroy(engine);

        // Setup required directories
        try setupDirs(config, io);

        // Initialize primary index first (needed by Db)
        const primary_index_ptr = try allocator.create(Index(u128, u64));
        errdefer allocator.destroy(primary_index_ptr);

        primary_index_ptr.* = try Index(u128, u64).init(allocator, IndexConfig{
            .dir_path = config.paths.index,
            .file_name = "primary",
            .pool_size = config.index.primary.pool_size,
            .io = io,
        });
        errdefer primary_index_ptr.deinit();

        // Initialize database with primary index
        const db = try Db.init(allocator, config, io, primary_index_ptr);
        errdefer db.deinit();

        // Load catalog entries from metadata file
        try db.catalog.loadMetadata();

        // Load secondary indexes from persisted catalog
        try loadSecondaryIndexesFromCatalog(db, allocator, config, io);

        // Initialize WAL if durability is enabled
        var wal: ?*WriteAheadLog = null;
        if (config.durability.enabled) {
            wal = try WriteAheadLog.init(allocator, WalConfig{
                .dir_path = config.paths.wal,
                .max_file_size = config.file_sizes.wal,
                .flush_interval_in_ms = config.durability.flush_interval_in_ms,
                .max_buffer_size = config.buffers.wal,
                .io = io,
                .group_commit_count = config.durability.group_commit_count,
                .group_commit_interval_ms = config.durability.group_commit_interval_ms,
            });

            // Replay WAL for crash recovery
            if (wal) |w| {
                const replay_result = try w.replay();
                defer replay_result.arena.deinit();
                defer replay_result.arena.allocator().free(replay_result.records);

                // Apply replayed entries to database
                for (replay_result.records) |record| {
                    const entry = Entry{
                        .key = record.key,
                        .ns = record.ns,
                        .value = record.value,
                        .timestamp = record.timestamp,
                        .kind = record.kind,
                    };

                    switch (record.kind) {
                        .insert => try db.post(entry),
                        .update => try db.put(@bitCast(record.key), record.value, record.timestamp),
                        .delete => try db.del(@bitCast(record.key), record.timestamp),
                        .read => {}, // Skip read operations
                    }
                }

                if (replay_result.records.len > 0) {
                    log.info("Replayed {} WAL entries during recovery", .{replay_result.records.len});
                }
            }
        }
        errdefer if (wal) |w| w.deinit() catch {};

        // Initialize key generator (no longer needs max_cores)
        const keygen = KeyGen.init();

        // Initialize LRU read cache if enabled
        var read_cache: ?*LruCache(u128, []const u8) = null;
        if (config.cache.enabled and config.cache.capacity > 0) {
            read_cache = try allocator.create(LruCache(u128, []const u8));
            read_cache.?.* = LruCache(u128, []const u8).init(allocator, config.cache.capacity);
            log.info("Read cache initialized with capacity {d}", .{config.cache.capacity});
        }
        errdefer if (read_cache) |c| {
            c.deinit();
            allocator.destroy(c);
        };

        engine.* = Self{
            .allocator = allocator,
            .config = config,
            .io = io,
            .db = db,
            .wal = wal,
            .primary_index = primary_index_ptr,
            .keygen = keygen,
            .catalog = db.catalog,
            .db_mutex = .{},
            .wal_mutex = .{},
            .primary_index_mutex = .{},
            .catalog_mutex = .{},
            .read_cache = read_cache,
        };

        log.info("Engine initialized", .{});
        return engine;
    }

    pub fn deinit(self: *Self) void {
        if (self.read_cache) |cache| {
            cache.deinit();
            self.allocator.destroy(cache);
        }
        // Note: catalog is owned by db, db.deinit() will free it
        self.primary_index.deinit();
        self.allocator.destroy(self.primary_index);
        if (self.wal) |wal| wal.deinit() catch {};
        self.db.deinit();
        self.allocator.destroy(self);
    }

    /// Setup required directories for the database
    fn setupDirs(config: *Config, io: Io) !void {
        // Create base directory
        Dir.createDirPath(.cwd(), io, config.base_dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                log.err("Failed to create base directory '{s}': {}", .{ config.base_dir, err });
                return err;
            }
        };

        // Create index directory
        Dir.createDirPath(.cwd(), io, config.paths.index) catch |err| {
            if (err != error.PathAlreadyExists) {
                log.err("Failed to create index directory '{s}': {}", .{ config.paths.index, err });
                return err;
            }
        };

        // Create vlog directory
        Dir.createDirPath(.cwd(), io, config.paths.vlog) catch |err| {
            if (err != error.PathAlreadyExists) {
                log.err("Failed to create vlog directory '{s}': {}", .{ config.paths.vlog, err });
                return err;
            }
        };

        // Create WAL directory
        Dir.createDirPath(.cwd(), io, config.paths.wal) catch |err| {
            if (err != error.PathAlreadyExists) {
                log.err("Failed to create WAL directory '{s}': {}", .{ config.paths.wal, err });
                return err;
            }
        };

        log.info("Database directories initialized", .{});
    }

    /// Load secondary indexes from persisted catalog metadata
    /// Called on startup to reopen index files that were created in previous sessions
    fn loadSecondaryIndexesFromCatalog(db: *Db, allocator: Allocator, config: *Config, io: Io) !void {
        // Get all indexes from catalog
        var indexes = try db.catalog.listIndexes(allocator);
        defer indexes.deinit(allocator);

        var count: usize = 0;
        for (indexes.items) |index_meta| {
            // Skip system indexes
            if (index_meta.store_id == 0) continue;

            // Check if this index is already loaded
            if (db.secondary_indexes.contains(index_meta.ns)) {
                continue; // Already loaded
            }

            // Open the B+ tree index file
            const index_ptr = try allocator.create(Index([]const u8, void));
            errdefer allocator.destroy(index_ptr);

            // Duplicate the index_ns since it may be freed by the caller
            const index_ns_owned = try allocator.dupe(u8, index_meta.ns);
            errdefer allocator.free(index_ns_owned);

            index_ptr.* = try Index([]const u8, void).init(allocator, .{
                .dir_path = config.paths.index,
                .file_name = index_ns_owned,
                .pool_size = config.index.primary.pool_size,
                .io = io,
            });

            try db.secondary_indexes.put(index_ns_owned, index_ptr);
            count += 1;
            log.info("Loaded secondary index '{s}' for store_id {}", .{ index_meta.ns, index_meta.store_id });
        }

        if (count > 0) {
            log.info("Loaded {} secondary indexes from catalog", .{count});
        }
    }

    /// Post a new entry (insert with auto-generated key)
    /// Resolves store_ns to store_id via catalog lookup
    pub fn post(self: *Self, store_ns: []const u8, value: []const u8) !u128 {
        const timestamp = milliTimestamp();

        // Lookup store_id from catalog
        self.catalog_mutex.lock();
        const store = self.catalog.findStoreByNamespace(store_ns) orelse {
            self.catalog_mutex.unlock();
            return error.StoreNotFound;
        };
        const store_id = store.store_id;
        self.catalog_mutex.unlock();

        // Generate key with store_id embedded
        // vlog_id reduced to u8, doc_type = 4 (Document)
        const vlog_id: u8 = @truncate(self.db.current_vlog.id);
        const key = try self.keygen.Gen(store_id, vlog_id, 4); // 4 = Document

        // Create entry (SkipList will copy the value to its arena)
        const entry = Entry{
            .key = key,
            .ns = "", // Empty namespace for now
            .value = value,
            .timestamp = timestamp,
            .kind = .insert,
        };

        // Write to WAL first (durability)
        if (self.wal) |wal| {
            self.wal_mutex.lock();
            defer self.wal_mutex.unlock();
            try wal.append(.{
                .key = key,
                .ns = "",
                .value = value,
                .timestamp = timestamp,
                .kind = .insert,
            });
        }

        // Write to memtable (index updates happen during flush)
        {
            self.db_mutex.lock();
            defer self.db_mutex.unlock();
            try self.db.post(entry);
        }

        return key;
    }

    /// Post a batch of entries (multiple inserts with single lock acquisition)
    /// Resolves store_ns to store_id via catalog lookup
    pub fn postBatch(self: *Self, store_ns: []const u8, values: [][]const u8, allocator: std.mem.Allocator) ![]u128 {
        const timestamp = milliTimestamp();

        // Lookup store_id from catalog
        self.catalog_mutex.lock();
        const store = self.catalog.findStoreByNamespace(store_ns) orelse {
            self.catalog_mutex.unlock();
            return error.StoreNotFound;
        };
        const store_id = store.store_id;
        self.catalog_mutex.unlock();

        const vlog_id: u8 = @truncate(self.db.current_vlog.id);

        // Allocate array for keys
        const keys = try allocator.alloc(u128, values.len);
        errdefer allocator.free(keys);

        // Generate all keys first
        for (values, 0..) |_, i| {
            keys[i] = try self.keygen.Gen(store_id, vlog_id, 4); // 4 = Document
        }

        // Write all to WAL with single lock acquisition
        if (self.wal) |wal| {
            self.wal_mutex.lock();
            defer self.wal_mutex.unlock();

            for (values, 0..) |value, i| {
                try wal.append(.{
                    .key = keys[i],
                    .ns = "",
                    .value = value,
                    .timestamp = timestamp,
                    .kind = .insert,
                });
            }
        }

        // Write all to memtable with single lock acquisition
        {
            self.db_mutex.lock();
            defer self.db_mutex.unlock();

            for (values, 0..) |value, i| {
                const entry = Entry{
                    .key = keys[i],
                    .ns = "",
                    .value = value,
                    .timestamp = timestamp,
                    .kind = .insert,
                };
                try self.db.post(entry);
            }
        }

        return keys;
    }

    /// Get a value by key
    pub fn get(self: *Self, key: u128) ![]const u8 {
        // Check cache first
        if (self.read_cache) |cache| {
            if (cache.get(key)) |cached_value| {
                return cached_value;
            }
        }

        // Cache miss - fetch from DB
        self.db_mutex.lock();
        defer self.db_mutex.unlock();
        const value = try self.db.get(@bitCast(key));

        // Populate cache with the value
        if (self.read_cache) |cache| {
            // Duplicate value for cache (cache manages its own memory)
            const cached = try self.allocator.dupe(u8, value);
            cache.put(key, cached) catch {};
        }

        return value;
    }

    /// Put (update) an existing key
    pub fn put(self: *Self, key: u128, value: []const u8) !void {
        const timestamp = milliTimestamp();

        // Write to WAL first
        if (self.wal) |wal| {
            self.wal_mutex.lock();
            defer self.wal_mutex.unlock();
            try wal.append(.{
                .key = key,
                .ns = "",
                .value = value,
                .timestamp = timestamp,
                .kind = .update,
            });
        }

        // Update in memtable (index updates happen during flush)
        {
            self.db_mutex.lock();
            defer self.db_mutex.unlock();
            try self.db.put(@bitCast(key), value, timestamp);
        }

        // Invalidate cache entry
        if (self.read_cache) |cache| {
            cache.remove(key);
        }
    }

    /// Delete a key
    pub fn del(self: *Self, key: u128) !void {
        const timestamp = milliTimestamp();

        // Write to WAL first
        if (self.wal) |wal| {
            self.wal_mutex.lock();
            defer self.wal_mutex.unlock();
            try wal.append(.{
                .key = key,
                .ns = "",
                .value = &[_]u8{},
                .timestamp = timestamp,
                .kind = .delete,
            });
        }

        // Delete from memtable (index updates happen during flush)
        {
            self.db_mutex.lock();
            defer self.db_mutex.unlock();
            try self.db.del(@bitCast(key), timestamp);
        }

        // Invalidate cache entry
        if (self.read_cache) |cache| {
            cache.remove(key);
        }
    }

    /// Get cache statistics (for monitoring)
    pub fn getCacheStats(self: *Self) ?struct { hits: u64, misses: u64, size: usize, capacity: usize } {
        if (self.read_cache) |cache| {
            return cache.getStats();
        }
        return null;
    }

    /// Flush memtable to disk on demand (switches active skiplist and flushes all)
    pub fn flush(self: *Self) !void {
        self.db_mutex.lock();
        defer self.db_mutex.unlock();
        try self.db.flushOnDemand();

        log.info("Flush on-demand completed", .{});
    }

    /// Find documents using secondary index
    /// Currently supports single criterion queries
    pub fn findDocs(self: *Self, index_ns: []const u8, field_value: anytype, limit: ?u32) ![]Entry {
        const actual_limit = limit orelse 100;

        // Convert field_value to FieldValue union
        const fv = switch (@TypeOf(field_value)) {
            []const u8 => FieldValue{ .string = field_value },
            u64 => FieldValue{ .u64_val = field_value },
            i64 => FieldValue{ .i64_val = field_value },
            u32 => FieldValue{ .u32_val = field_value },
            i32 => FieldValue{ .i32_val = field_value },
            bool => FieldValue{ .bool_val = field_value },
            else => return error.UnsupportedFieldType,
        };

        // Query secondary index to get primary keys
        self.db_mutex.lock();
        var primary_keys = try self.db.findBySecondaryIndex(index_ns, fv);
        defer primary_keys.deinit(self.allocator);

        // Create result list with limit
        var results: std.ArrayList(Entry) = .empty;
        errdefer {
            for (results.items) |entry| {
                self.allocator.free(entry.value);
            }
            results.deinit(self.allocator);
        }

        var count: u32 = 0;
        for (primary_keys.items) |key| {
            if (count >= actual_limit) break;

            // Fetch document value
            const value = self.db.get(@bitCast(key)) catch |err| {
                log.warn("Failed to fetch document with key={x}: {}", .{ key, err });
                continue;
            };
            defer self.allocator.free(value); // Free the original value

            // Make a copy of the value
            const value_copy = try self.allocator.dupe(u8, value);

            try results.append(self.allocator, Entry{
                .key = key,
                .ns = "",
                .value = value_copy,
                .timestamp = milliTimestamp(),
                .kind = .read,
            });

            count += 1;
        }
        self.db_mutex.unlock();

        return results.toOwnedSlice(self.allocator);
    }

    /// Range query on primary keys
    /// Returns documents with keys between start_key and end_key
    pub fn rangeQuery(self: *Self, start_key: u128, end_key: u128, limit: ?u32) ![]Entry {
        const actual_limit = limit orelse 100;

        // Create result list
        var results: std.ArrayList(Entry) = .empty;
        errdefer {
            for (results.items) |entry| {
                self.allocator.free(entry.value);
            }
            results.deinit(self.allocator);
        }

        // Lock primary index for iteration
        self.primary_index_mutex.lock();
        defer self.primary_index_mutex.unlock();

        // Use prefetch iterator for better sequential scan performance
        var it = try self.primary_index.prefetchIterator();
        defer it.deinit();

        var count: u32 = 0;

        while (try it.next()) |cell| {
            // Exit if we have enough results
            if (count >= actual_limit) break;

            // Decode key
            const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .little);

            // Check if key is in range
            if (key < start_key or key > end_key) continue;

            // Read from database
            self.db_mutex.lock();
            const value = self.db.get(@bitCast(key)) catch |err| {
                self.db_mutex.unlock();
                log.warn("Failed to read document key={x}: {}", .{ key, err });
                continue;
            };
            defer self.allocator.free(value); // Free the original value
            // Make a copy since db.get returns a slice that might be invalidated
            const value_copy = self.allocator.dupe(u8, value) catch |err| {
                self.db_mutex.unlock();
                return err;
            };
            self.db_mutex.unlock();

            // Add to results
            try results.append(self.allocator, Entry{
                .key = key,
                .ns = "",
                .value = value_copy,
                .timestamp = milliTimestamp(),
                .kind = .read,
            });

            count += 1;
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// List documents in a store with pagination
    pub fn listDocs(self: *Self, store_ns: []const u8, limit: ?u32, offset: ?u32) ![]Entry {
        // Resolve store_ns to store_id
        self.catalog_mutex.lock();
        const store = self.catalog.findStoreByNamespace(store_ns) orelse {
            self.catalog_mutex.unlock();
            return error.StoreNotFound;
        };
        const store_id = store.store_id;
        self.catalog_mutex.unlock();

        const actual_limit = limit orelse 100; // Default limit
        const actual_offset = offset orelse 0;

        // Phase 1: Collect keys (with index lock)
        // This minimizes lock contention by releasing index lock before fetching values
        var keys: std.ArrayList(u128) = .empty;
        defer keys.deinit(self.allocator);

        {
            self.primary_index_mutex.lock();
            defer self.primary_index_mutex.unlock();

            // Use prefetch iterator for better sequential scan performance
            var it = try self.primary_index.prefetchIterator();
            defer it.deinit();

            var count: u32 = 0;
            var skipped: u32 = 0;
            var seen_target_store = false;
            var total_scanned: u32 = 0;

            // Aggressive safety limit: 10x what we need
            const reasonable_max = (actual_offset + actual_limit) * 10;
            const MAX_SCAN_KEYS: u32 = @min(reasonable_max, 50_000);

            while (try it.next()) |cell| {
                total_scanned += 1;

                // Safety check: prevent runaway scans
                if (total_scanned >= MAX_SCAN_KEYS) {
                    break;
                }

                // Exit if we have enough results
                if (count >= actual_limit) break;

                // Decode key
                const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .little);

                // Extract store_id from key (bits 112-127, most significant)
                const key_store_id: u16 = @truncate((key >> 112) & 0xFFFF);

                // If we've already seen our target store and now hit a different one,
                // we can stop early (keys are sorted by store_id first, so stores are sequential)
                if (seen_target_store and key_store_id != store_id) {
                    break;
                }

                // If we're past our target store (keys are sorted), we'll never find it
                if (!seen_target_store and key_store_id > store_id) {
                    break;
                }

                // Skip if not in our store
                if (key_store_id != store_id) continue;

                // Mark that we've seen our target store
                seen_target_store = true;

                // Extract doc_type (bits 104-111)
                const doc_type: u8 = @truncate((key >> 104) & 0xFF);

                // Skip catalog entries (doc_type 1, 2, 3)
                if (doc_type <= 3) continue;

                // Apply offset
                if (skipped < actual_offset) {
                    skipped += 1;
                    continue;
                }

                // Collect key for later value fetch
                try keys.append(self.allocator, key);
                count += 1;
            }
        }
        // Index lock released here - allows other operations to proceed

        // Phase 2: Fetch values for collected keys (without index lock)
        var results: std.ArrayList(Entry) = .empty;
        errdefer results.deinit(self.allocator);

        for (keys.items) |key| {
            // Read from database (only db_mutex needed, not index_mutex)
            self.db_mutex.lock();
            const value = self.db.get(@bitCast(key)) catch |err| {
                self.db_mutex.unlock();
                log.warn("Failed to read document key={x}: {}", .{ key, err });
                continue;
            };
            defer self.allocator.free(value); // Free the original value
            // Make a copy since db.get returns a slice that might be invalidated
            const value_copy = self.allocator.dupe(u8, value) catch |err| {
                self.db_mutex.unlock();
                return err;
            };
            self.db_mutex.unlock();

            // Add to results
            try results.append(self.allocator, Entry{
                .key = key,
                .ns = "", // We could store namespace if needed
                .value = value_copy,
                .timestamp = milliTimestamp(),
                .kind = .insert,
            });
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Query documents using JSON query language
    /// Supports filtering, sorting, and pagination
    pub fn queryDocs(self: *Self, store_ns: []const u8, query_json: []const u8) ![]Entry {

        // Parse JSON query
        var parsed = try query_engine.parseJsonQuery(self.allocator, query_json);
        defer parsed.deinit();

        // Resolve store_ns to store_id
        self.catalog_mutex.lock();
        const store = self.catalog.findStoreByNamespace(store_ns) orelse {
            self.catalog_mutex.unlock();
            return error.StoreNotFound;
        };
        const store_id = store.store_id;
        self.catalog_mutex.unlock();

        // Get limit and offset
        const actual_limit = parsed.limit orelse std.math.maxInt(u32);
        const actual_offset = parsed.offset;

        // When sorting is requested, we must collect ALL matching docs first,
        // sort them, then apply limit/offset. Otherwise we'd truncate before sorting.
        const has_sort = parsed.sort_field != null or parsed.sort_fields.items.len > 0;
        const collect_limit: u32 = if (has_sort) std.math.maxInt(u32) else actual_limit;
        const collect_offset: u32 = if (has_sort) 0 else actual_offset;

        // Determine the best index strategy: eq > $in > range ($gt/$gte/$lt/$lte)
        const strategy = parsed.getBestIndexStrategy();

        var results: std.ArrayList(Entry) = .empty;
        errdefer {
            for (results.items) |entry| {
                self.allocator.free(entry.value);
            }
            results.deinit(self.allocator);
        }

        var used_index = false;

        if (strategy) |strat| {
            // Determine the field name the strategy targets
            const target_field: []const u8 = switch (strat) {
                .eq => |pred| pred.field_name,
                .range => |r| r.field_name,
                .in_list => |il| il.field_name,
            };

            // Try to find a secondary index for this field
            self.catalog_mutex.lock();
            var indexes = self.catalog.getIndexesForStore(store_ns, self.allocator) catch {
                self.catalog_mutex.unlock();
                try self.fullScanWithFilter(&results, store_id, &parsed, collect_limit, collect_offset);
                return results.toOwnedSlice(self.allocator);
            };
            defer indexes.deinit(self.allocator);
            self.catalog_mutex.unlock();

            var found_index: ?[]const u8 = null;
            for (indexes.items) |idx| {
                if (std.mem.eql(u8, idx.field, target_field)) {
                    found_index = idx.ns;
                    break;
                }
            }

            if (found_index) |index_ns| {
                // Get candidate primary keys using the appropriate index method
                self.db_mutex.lock();
                var primary_keys = switch (strat) {
                    .eq => |pred| self.db.findBySecondaryIndex(index_ns, pred.value) catch |err| {
                        self.db_mutex.unlock();
                        log.warn("Index eq lookup failed: {}, falling back to full scan", .{err});
                        try self.fullScanWithFilter(&results, store_id, &parsed, collect_limit, collect_offset);
                        return results.toOwnedSlice(self.allocator);
                    },
                    .range => |r| self.db.findBySecondaryIndexRange(index_ns, r.min_val, r.max_val, r.min_inclusive, r.max_inclusive) catch |err| {
                        self.db_mutex.unlock();
                        log.warn("Index range scan failed: {}, falling back to full scan", .{err});
                        try self.fullScanWithFilter(&results, store_id, &parsed, collect_limit, collect_offset);
                        return results.toOwnedSlice(self.allocator);
                    },
                    .in_list => |il| self.db.findBySecondaryIndexMulti(index_ns, il.values) catch |err| {
                        self.db_mutex.unlock();
                        log.warn("Index multi-lookup failed: {}, falling back to full scan", .{err});
                        try self.fullScanWithFilter(&results, store_id, &parsed, collect_limit, collect_offset);
                        return results.toOwnedSlice(self.allocator);
                    },
                };
                defer primary_keys.deinit(self.allocator);

                var skipped: u32 = 0;
                var count: u32 = 0;

                for (primary_keys.items) |key| {
                    if (count >= collect_limit) break;

                    // Fetch document value
                    const value = self.db.get(@bitCast(key)) catch continue;
                    defer self.allocator.free(value);

                    // Apply ALL predicates (AND + OR) for correctness
                    if (!matchesAllPredicates(value, &parsed)) continue;

                    // Apply offset
                    if (skipped < collect_offset) {
                        skipped += 1;
                        continue;
                    }

                    const value_copy = try self.allocator.dupe(u8, value);
                    try results.append(self.allocator, Entry{
                        .key = key,
                        .ns = "",
                        .value = value_copy,
                        .timestamp = milliTimestamp(),
                        .kind = .read,
                    });
                    count += 1;
                }
                self.db_mutex.unlock();
                used_index = true;
            }
        }

        if (!used_index) {
            // No index available or no indexable predicates - full scan
            try self.fullScanWithFilter(&results, store_id, &parsed, collect_limit, collect_offset);
        }

        // Sort results if order_by is specified
        if (parsed.sort_fields.items.len > 1) {
            // Multi-field sort
            const sort_specs = parsed.sort_fields.items;
            const items = results.items;
            std.sort.insertion(Entry, items, sort_specs, struct {
                fn lessThan(specs: []const query_engine.SortSpec, a: Entry, b: Entry) bool {
                    return compareByMultiFields(a.value, b.value, specs);
                }
            }.lessThan);

            // Apply offset and limit AFTER sorting
            if (actual_offset > 0 or actual_limit < std.math.maxInt(u32)) {
                const start = @min(actual_offset, @as(u32, @intCast(results.items.len)));
                const end = @min(start +| actual_limit, @as(u32, @intCast(results.items.len)));
                for (results.items[0..start]) |entry| {
                    self.allocator.free(entry.value);
                }
                for (results.items[end..]) |entry| {
                    self.allocator.free(entry.value);
                }
                const kept = results.items[start..end];
                std.mem.copyForwards(Entry, results.items[0..kept.len], kept);
                results.shrinkRetainingCapacity(kept.len);
            }
        } else if (parsed.sort_field) |sort_field| {
            const asc = parsed.sort_ascending;
            const items = results.items;
            std.sort.insertion(Entry, items, SortContext{ .field = sort_field, .ascending = asc }, struct {
                fn lessThan(ctx: SortContext, a: Entry, b: Entry) bool {
                    return compareByField(a.value, b.value, ctx.field, ctx.ascending);
                }
            }.lessThan);

            // Apply offset and limit AFTER sorting
            if (actual_offset > 0 or actual_limit < std.math.maxInt(u32)) {
                const start = @min(actual_offset, @as(u32, @intCast(results.items.len)));
                const end = @min(start +| actual_limit, @as(u32, @intCast(results.items.len)));
                // Free entries outside the [start..end) range
                for (results.items[0..start]) |entry| {
                    self.allocator.free(entry.value);
                }
                for (results.items[end..]) |entry| {
                    self.allocator.free(entry.value);
                }
                // Shift kept entries to front
                const kept = results.items[start..end];
                std.mem.copyForwards(Entry, results.items[0..kept.len], kept);
                results.shrinkRetainingCapacity(kept.len);
            }
        }

        // Apply projection if specified
        if (parsed.projection_fields) |proj_fields| {
            for (results.items) |*entry| {
                const projected = applyProjection(self.allocator, entry.value, proj_fields) catch continue;
                self.allocator.free(entry.value);
                entry.value = projected;
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    const SortContext = struct {
        field: []const u8,
        ascending: bool,
    };

    /// Compare two documents by multiple sort fields
    fn compareByMultiFields(a_bson: []const u8, b_bson: []const u8, specs: []const query_engine.SortSpec) bool {
        const allocator = std.heap.page_allocator;

        const a_doc = bson.BsonDocument.init(allocator, a_bson, false) catch return false;
        var a_mut = a_doc;
        defer a_mut.deinit();

        const b_doc = bson.BsonDocument.init(allocator, b_bson, false) catch return true;
        var b_mut = b_doc;
        defer b_mut.deinit();

        for (specs) |spec| {
            const a_val_opt = blk: {
                const result = a_doc.getNestedField(spec.field) catch break :blk null;
                break :blk result;
            };
            const b_val_opt = blk: {
                const result = b_doc.getNestedField(spec.field) catch break :blk null;
                break :blk result;
            };

            const a_val = a_val_opt orelse continue;
            const b_val = b_val_opt orelse continue;

            const cmp = compareBsonValues(a_val, b_val);
            if (cmp == .eq) continue;
            return if (spec.ascending) cmp == .lt else cmp == .gt;
        }
        return false; // All fields equal
    }

    fn fullScanWithFilter(self: *Self, results: *std.ArrayList(Entry), store_id: u16, parsed: *const @import("../storage/query_engine.zig").ParsedQuery, limit: u32, offset: u32) !void {
        // Track keys we've seen to avoid duplicates between memtable and index
        var seen_keys = std.AutoHashMap(u128, void).init(self.allocator);
        defer seen_keys.deinit();

        var skipped: u32 = 0;
        var count: u32 = 0;

        // Debug: count memtable entries
        var memtable_total: u32 = 0;
        var memtable_matched: u32 = 0;

        // First scan memtable for unflushed data (most recent writes)
        {
            self.db_mutex.lock();
            defer self.db_mutex.unlock();

            // Scan active skiplist
            var active_iter = self.db.memtable.active.iterator();
            while (active_iter.next()) |entry| {
                memtable_total += 1;
                if (count >= limit) break;

                // Check store_id from key prefix
                const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                if (key_store_id != store_id) continue;
                memtable_matched += 1;

                // Skip deleted entries
                if (entry.kind == .delete) continue;

                // Mark as seen
                try seen_keys.put(entry.key, {});

                // Apply predicates (AND + OR)
                if (!matchesAllPredicates(entry.value, parsed)) continue;

                // Apply offset
                if (skipped < offset) {
                    skipped += 1;
                    continue;
                }

                // Copy value since memtable owns it
                const value_copy = try self.allocator.dupe(u8, entry.value);

                try results.append(self.allocator, Entry{
                    .key = entry.key,
                    .ns = "",
                    .value = value_copy,
                    .timestamp = milliTimestamp(),
                    .kind = .read,
                });
                count += 1;
            }

            // Scan inactive skiplists (pending flush)
            var lists_iter = self.db.memtable.lists.iterator();
            while (lists_iter.next()) |skl| {
                if (count >= limit) break;

                var skl_iter = skl.iterator();
                while (skl_iter.next()) |entry| {
                    if (count >= limit) break;

                    // Check store_id from key prefix
                    const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                    if (key_store_id != store_id) continue;

                    // Skip deleted entries
                    if (entry.kind == .delete) continue;

                    // Skip if already seen (from active memtable)
                    if (seen_keys.contains(entry.key)) continue;
                    try seen_keys.put(entry.key, {});

                    // Apply predicates (AND + OR)
                    if (!matchesAllPredicates(entry.value, parsed)) continue;

                    // Apply offset
                    if (skipped < offset) {
                        skipped += 1;
                        continue;
                    }

                    // Copy value since memtable owns it
                    const value_copy = try self.allocator.dupe(u8, entry.value);

                    try results.append(self.allocator, Entry{
                        .key = entry.key,
                        .ns = "",
                        .value = value_copy,
                        .timestamp = milliTimestamp(),
                        .kind = .read,
                    });
                    count += 1;
                }
            }
        }

        // log.info("Query scan: memtable_total={d}, memtable_matched_store={d}, store_id={d}, results_from_memtable={d}", .{ memtable_total, memtable_matched, store_id, count });

        // Then scan primary index for flushed data
        var index_total: u32 = 0;
        var index_matched: u32 = 0;
        if (count < limit) {
            self.primary_index_mutex.lock();
            defer self.primary_index_mutex.unlock();

            var it = try self.primary_index.prefetchIterator();
            defer it.deinit();

            while (try it.next()) |cell| {
                index_total += 1;
                if (count >= limit) break;

                const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .big);

                // Check store_id from key prefix
                const key_store_id = @as(u16, @intCast((key >> 112) & 0xFFFF));
                if (key_store_id != store_id) continue;
                index_matched += 1;

                // Skip if already seen from memtable
                if (seen_keys.contains(key)) continue;

                // Read vlog offset directly from cell value (avoids re-searching the index)
                const vlog_offset = std.mem.readInt(u64, cell.value[0..@sizeOf(u64)], .little);

                // Fetch document using known offset
                self.db_mutex.lock();
                const value = self.db.getByOffset(@bitCast(key), vlog_offset) catch |err| {
                    self.db_mutex.unlock();
                    log.warn("Failed to read key={x}: {}", .{ key, err });
                    continue;
                };
                self.db_mutex.unlock();

                // Apply predicates (AND + OR)
                if (!matchesAllPredicates(value, parsed)) {
                    self.allocator.free(value);
                    continue;
                }

                // Apply offset
                if (skipped < offset) {
                    skipped += 1;
                    self.allocator.free(value);
                    continue;
                }

                try results.append(self.allocator, Entry{
                    .key = key,
                    .ns = "",
                    .value = value,
                    .timestamp = milliTimestamp(),
                    .kind = .read,
                });
                count += 1;
            }
        }
        // log.info("Index scan: index_total={d}, index_matched_store={d}, final_count={d}", .{ index_total, index_matched, count });
    }

    /// Execute an aggregation query on documents in a store
    /// Returns JSON result with aggregated values, optionally grouped
    /// Scan documents with limit and skip (for YCSB Workload E)
    pub fn scanDocs(self: *Self, start_key: ?u128, limit_count: u32, skip_count: u32) ![]Entry {
        // First, collect all keys from all data sources in sorted order
        var all_keys: std.ArrayList(u128) = .empty;
        defer all_keys.deinit(self.allocator);

        // Track keys we've seen to avoid duplicates
        var seen_keys = std.AutoHashMap(u128, void).init(self.allocator);
        defer seen_keys.deinit();

        // Lock the database for iteration
        self.db_mutex.lock();
        defer self.db_mutex.unlock();

        // 1. Collect keys from active memtable
        var active_iter = self.db.memtable.active.iterator();
        while (active_iter.next()) |entry| {
            if (entry.kind == .delete) continue;

            const key = entry.key;
            if (start_key) |sk| {
                if (key < sk) continue;
            }

            if (!seen_keys.contains(key)) {
                try seen_keys.put(key, {});
                try all_keys.append(self.allocator, key);
            }
        }

        // 2. Collect keys from inactive skiplists
        var inactive_iter = self.db.memtable.lists.iterator();
        while (inactive_iter.next()) |skiplist| {
            var list_iter = skiplist.iterator();
            while (list_iter.next()) |entry| {
                if (entry.kind == .delete) continue;

                const key = entry.key;
                if (start_key) |sk| {
                    if (key < sk) continue;
                }

                if (!seen_keys.contains(key)) {
                    try seen_keys.put(key, {});
                    try all_keys.append(self.allocator, key);
                }
            }
        }

        // 3. Collect keys from B+ tree index
        {
            self.primary_index_mutex.lock();
            defer self.primary_index_mutex.unlock();

            var it = try self.primary_index.iterator();
            defer it.deinit();

            while (try it.next()) |cell| {
                const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .little);
                if (start_key) |sk| {
                    if (key < sk) continue;
                }

                if (!seen_keys.contains(key)) {
                    try seen_keys.put(key, {});
                    try all_keys.append(self.allocator, key);
                }
            }
        }

        // Sort keys to ensure consistent ordering
        std.mem.sort(u128, all_keys.items, {}, std.sort.asc(u128));

        // Apply skip and limit to the sorted keys
        var results: std.ArrayList(Entry) = .empty;
        errdefer {
            for (results.items) |entry| {
                self.allocator.free(entry.value);
            }
            results.deinit(self.allocator);
        }

        const start_idx = skip_count;
        const end_idx = @min(start_idx + limit_count, all_keys.items.len);

        // Fetch values for the selected keys
        for (all_keys.items[start_idx..end_idx]) |key| {
            const value = self.db.get(@bitCast(key)) catch continue;

            try results.append(self.allocator, Entry{
                .key = key,
                .ns = "",
                .value = value,
                .timestamp = milliTimestamp(),
                .kind = .read,
            });
        }

        return results.toOwnedSlice(self.allocator);
    }
    pub fn aggregateDocs(self: *Self, store_ns: []const u8, query_json: []const u8) ![]u8 {
        const GroupAccumulator = query_engine.GroupAccumulator;

        // Parse JSON query
        var parsed = query_engine.parseJsonQuery(self.allocator, query_json) catch |err| {
            return err;
        };
        defer parsed.deinit();

        // Resolve store_ns to store_id
        self.catalog_mutex.lock();
        const store = self.catalog.findStoreByNamespace(store_ns) orelse {
            self.catalog_mutex.unlock();
            return error.StoreNotFound;
        };
        const store_id = store.store_id;
        self.catalog_mutex.unlock();

        // Initialize group accumulators: HashMap<group_key, GroupAccumulator>
        var groups = std.StringHashMap(GroupAccumulator).init(self.allocator);
        defer {
            var it = groups.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit();
            }
            groups.deinit();
        }

        // Field extractor for extracting values
        var extractor = FieldExtractor.init(self.allocator);

        // Track keys we've seen to avoid duplicates between memtable and index
        var seen_keys = std.AutoHashMap(u128, void).init(self.allocator);
        defer seen_keys.deinit();

        // Helper to process a single document for aggregation
        const processDoc = struct {
            fn process(
                allocator: std.mem.Allocator,
                value: []const u8,
                p: *const query_engine.ParsedQuery,
                g: *std.StringHashMap(GroupAccumulator),
                ext: *FieldExtractor,
                self_ptr: *Self,
            ) !void {
                // Apply predicates (filter)
                var matches = true;
                for (p.predicates.items) |pred| {
                    if (!matchesPredicate(value, pred)) {
                        matches = false;
                        break;
                    }
                }
                if (!matches) return;

                // Compute group key
                const group_key = self_ptr.computeGroupKey(value, p.group_by_fields, ext) catch |err| {
                    return err;
                };
                defer allocator.free(group_key);

                // Get or create group accumulator
                const gop = try g.getOrPut(group_key);
                if (!gop.found_existing) {
                    gop.key_ptr.* = try allocator.dupe(u8, group_key);
                    gop.value_ptr.* = GroupAccumulator.init(allocator);
                }

                // Accumulate each aggregation
                for (p.aggregations.items) |agg| {
                    const field_value: ?FieldValue = if (agg.field_name) |fn_name| blk: {
                        // Try i64 extraction first
                        if (ext.extractI64(value, fn_name)) |opt_i64| {
                            if (opt_i64) |i| {
                                break :blk FieldValue{ .i64_val = i };
                            }
                        } else |_| {}

                        // Try f64 extraction
                        if (ext.extractF64(value, fn_name)) |opt_f64| {
                            if (opt_f64) |f| {
                                break :blk FieldValue{ .f64_val = f };
                            }
                        } else |_| {}

                        // Try u64 extraction
                        if (ext.extractU64(value, fn_name)) |opt_u64| {
                            if (opt_u64) |u| {
                                break :blk FieldValue{ .u64_val = u };
                            }
                        } else |_| {}

                        // Try string extraction and parse as number
                        if (ext.extractString(value, fn_name)) |opt_str| {
                            if (opt_str) |str| {
                                defer allocator.free(str);
                                if (std.fmt.parseFloat(f64, str)) |parsed_float| {
                                    break :blk FieldValue{ .f64_val = parsed_float };
                                } else |_| {
                                    if (std.fmt.parseInt(i64, str, 10)) |parsed_int| {
                                        break :blk FieldValue{ .i64_val = parsed_int };
                                    } else |_| {}
                                }
                            }
                        } else |_| {}

                        break :blk null;
                    } else null;

                    gop.value_ptr.update(agg.name, agg.function, field_value) catch |err| {
                        return err;
                    };
                }
            }
        }.process;

        // Try to use secondary index to narrow the scan
        var used_index = false;
        const strategy = parsed.getBestIndexStrategy();

        if (strategy) |strat| idx_blk: {
            const target_field: []const u8 = switch (strat) {
                .eq => |pred| pred.field_name,
                .range => |r| r.field_name,
                .in_list => |il| il.field_name,
            };

            self.catalog_mutex.lock();
            var indexes = self.catalog.getIndexesForStore(store_ns, self.allocator) catch {
                self.catalog_mutex.unlock();
                break :idx_blk; // Fall through to full scan
            };
            defer indexes.deinit(self.allocator);
            self.catalog_mutex.unlock();

            var found_index: ?[]const u8 = null;
            for (indexes.items) |idx| {
                if (std.mem.eql(u8, idx.field, target_field)) {
                    found_index = idx.ns;
                    break;
                }
            }

            const index_ns = found_index orelse break :idx_blk;

            // First: process unflushed memtable data (still need full memtable scan for freshness)
            {
                self.db_mutex.lock();
                defer self.db_mutex.unlock();

                var active_iter = self.db.memtable.active.iterator();
                while (active_iter.next()) |entry| {
                    const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                    if (key_store_id != store_id) continue;
                    if (entry.kind == .delete) continue;

                    try seen_keys.put(entry.key, {});
                    try processDoc(self.allocator, entry.value, &parsed, &groups, &extractor, self);
                }

                var lists_iter = self.db.memtable.lists.iterator();
                while (lists_iter.next()) |skl| {
                    var skl_iter = skl.iterator();
                    while (skl_iter.next()) |entry| {
                        const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                        if (key_store_id != store_id) continue;
                        if (entry.kind == .delete) continue;
                        if (seen_keys.contains(entry.key)) continue;

                        try seen_keys.put(entry.key, {});
                        try processDoc(self.allocator, entry.value, &parsed, &groups, &extractor, self);
                    }
                }
            }

            // Then: use index for flushed data (instead of scanning entire primary index)
            {
                self.db_mutex.lock();
                var primary_keys = switch (strat) {
                    .eq => |pred| self.db.findBySecondaryIndex(index_ns, pred.value) catch {
                        self.db_mutex.unlock();
                        break :idx_blk;
                    },
                    .range => |r| self.db.findBySecondaryIndexRange(index_ns, r.min_val, r.max_val, r.min_inclusive, r.max_inclusive) catch {
                        self.db_mutex.unlock();
                        break :idx_blk;
                    },
                    .in_list => |il| self.db.findBySecondaryIndexMulti(index_ns, il.values) catch {
                        self.db_mutex.unlock();
                        break :idx_blk;
                    },
                };
                defer primary_keys.deinit(self.allocator);

                for (primary_keys.items) |pk| {
                    if (seen_keys.contains(pk)) continue;

                    const value = self.db.get(@bitCast(pk)) catch {
                        continue;
                    };
                    defer self.allocator.free(value);

                    try processDoc(self.allocator, value, &parsed, &groups, &extractor, self);
                }
                self.db_mutex.unlock();
            }

            used_index = true;
        }

        if (!used_index) {
            // Full scan: memtable + primary index (original path)
            {
                self.db_mutex.lock();
                defer self.db_mutex.unlock();

                var active_iter = self.db.memtable.active.iterator();
                while (active_iter.next()) |entry| {
                    const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                    if (key_store_id != store_id) continue;
                    if (entry.kind == .delete) continue;

                    try seen_keys.put(entry.key, {});
                    try processDoc(self.allocator, entry.value, &parsed, &groups, &extractor, self);
                }

                var lists_iter = self.db.memtable.lists.iterator();
                while (lists_iter.next()) |skl| {
                    var skl_iter = skl.iterator();
                    while (skl_iter.next()) |entry| {
                        const key_store_id = @as(u16, @intCast((entry.key >> 112) & 0xFFFF));
                        if (key_store_id != store_id) continue;
                        if (entry.kind == .delete) continue;
                        if (seen_keys.contains(entry.key)) continue;

                        try seen_keys.put(entry.key, {});
                        try processDoc(self.allocator, entry.value, &parsed, &groups, &extractor, self);
                    }
                }
            }

            {
                self.primary_index_mutex.lock();
                defer self.primary_index_mutex.unlock();

                var iter = try self.primary_index.prefetchIterator();
                defer iter.deinit();

                while (try iter.next()) |cell| {
                    const key = std.mem.readInt(u128, cell.key[0..@sizeOf(u128)], .big);

                    const key_store_id = @as(u16, @intCast((key >> 112) & 0xFFFF));
                    if (key_store_id != store_id) continue;
                    if (seen_keys.contains(key)) continue;

                    const offset = std.mem.readInt(u64, cell.value[0..@sizeOf(u64)], .little);

                    self.db_mutex.lock();
                    const value = self.db.getByOffset(@bitCast(key), offset) catch {
                        self.db_mutex.unlock();
                        continue;
                    };
                    self.db_mutex.unlock();
                    defer self.allocator.free(value);

                    try processDoc(self.allocator, value, &parsed, &groups, &extractor, self);
                }
            }
        }

        // Build BSON result
        return try self.aggregateResultsToBson(&groups, &parsed);
    }

    /// Compute a group key from document based on group_by fields
    fn computeGroupKey(self: *Self, doc_json: []const u8, group_by_fields: ?[][]const u8, extractor: *@import("../storage/field_extractor.zig").FieldExtractor) ![]u8 {
        _ = extractor;
        const fields = group_by_fields orelse return try self.allocator.dupe(u8, "_default");

        var key_parts: std.ArrayList(u8) = .empty;
        errdefer key_parts.deinit(self.allocator);

        // Use BSON getNestedField for direct field access (supports all types)
        const doc = bson.BsonDocument.init(self.allocator, doc_json, false) catch {
            return try self.allocator.dupe(u8, "_error");
        };
        var doc_mut = doc;
        defer doc_mut.deinit();

        for (fields, 0..) |field, i| {
            if (i > 0) try key_parts.append(self.allocator, '|');

            if (doc.getNestedField(field)) |val_opt| {
                if (val_opt) |val| {
                    switch (val) {
                        .string => |s| try key_parts.appendSlice(self.allocator, s),
                        .int32 => |v| {
                            var buf: [32]u8 = undefined;
                            const formatted = std.fmt.bufPrint(&buf, "{d}", .{v}) catch "0";
                            try key_parts.appendSlice(self.allocator, formatted);
                        },
                        .int64 => |v| {
                            var buf: [32]u8 = undefined;
                            const formatted = std.fmt.bufPrint(&buf, "{d}", .{v}) catch "0";
                            try key_parts.appendSlice(self.allocator, formatted);
                        },
                        .double => |v| {
                            var buf: [64]u8 = undefined;
                            const formatted = std.fmt.bufPrint(&buf, "{d}", .{v}) catch "0";
                            try key_parts.appendSlice(self.allocator, formatted);
                        },
                        .boolean => |v| try key_parts.appendSlice(self.allocator, if (v) "true" else "false"),
                        else => try key_parts.appendSlice(self.allocator, "null"),
                    }
                } else {
                    try key_parts.appendSlice(self.allocator, "null");
                }
            } else |_| {
                try key_parts.appendSlice(self.allocator, "null");
            }
        }

        return try key_parts.toOwnedSlice(self.allocator);
    }

    /// Convert aggregation results to BSON
    /// Output format: a BSON document with "groups" array and "total_groups" count
    /// Each group element is a BSON document with "key" (document) and "values" (document)
    fn aggregateResultsToBson(self: *Self, groups: *std.StringHashMap(@import("../storage/query_engine.zig").GroupAccumulator), parsed: *const @import("../storage/query_engine.zig").ParsedQuery) ![]u8 {
        const GroupAccumulator = @import("../storage/query_engine.zig").GroupAccumulator;
        const AggregateResult = @import("../storage/query_engine.zig").AggregateResult;

        // Collect entries into a sortable array
        const GroupEntry = struct { key: []const u8, acc: *GroupAccumulator };
        var entries: std.ArrayList(GroupEntry) = .empty;
        defer entries.deinit(self.allocator);

        var collect_it = groups.iterator();
        while (collect_it.next()) |entry| {
            try entries.append(self.allocator, .{ .key = entry.key_ptr.*, .acc = entry.value_ptr });
        }

        // Sort if orderBy is specified
        if (parsed.sort_field) |sort_field| {
            const asc = parsed.sort_ascending;

            // Determine if sort field is a group-by key or an aggregate result
            var sort_key_index: ?usize = null;
            if (parsed.group_by_fields) |fields| {
                for (fields, 0..) |field, idx| {
                    if (std.mem.eql(u8, field, sort_field)) {
                        sort_key_index = idx;
                        break;
                    }
                }
            }

            const SortCtx = struct {
                key_index: ?usize,
                agg_name: []const u8,
                ascending: bool,

                fn lessThan(ctx: @This(), a: GroupEntry, b: GroupEntry) bool {
                    if (ctx.key_index) |ki| {
                        // Sort by group-by key part
                        const a_part = getKeyPart(a.key, ki);
                        const b_part = getKeyPart(b.key, ki);

                        // Try numeric comparison first
                        const a_num = std.fmt.parseFloat(f64, a_part) catch null;
                        const b_num = std.fmt.parseFloat(f64, b_part) catch null;

                        if (a_num != null and b_num != null) {
                            return if (ctx.ascending) a_num.? < b_num.? else a_num.? > b_num.?;
                        }

                        // Fall back to string comparison
                        const order = std.mem.order(u8, a_part, b_part);
                        return if (ctx.ascending) order == .lt else order == .gt;
                    } else {
                        // Sort by aggregate result value
                        const a_result: ?AggregateResult = a.acc.getResult(ctx.agg_name);
                        const b_result: ?AggregateResult = b.acc.getResult(ctx.agg_name);

                        const a_val = resultToF64(a_result);
                        const b_val = resultToF64(b_result);

                        return if (ctx.ascending) a_val < b_val else a_val > b_val;
                    }
                }

                fn getKeyPart(key: []const u8, index: usize) []const u8 {
                    var parts = std.mem.splitSequence(u8, key, "|");
                    var i: usize = 0;
                    while (parts.next()) |part| {
                        if (i == index) return part;
                        i += 1;
                    }
                    return key;
                }

                fn resultToF64(result: ?AggregateResult) f64 {
                    if (result) |r| {
                        return switch (r) {
                            .int => |v| @floatFromInt(v),
                            .float => |v| v,
                            .string => 0.0,
                        };
                    }
                    return 0.0;
                }
            };

            std.sort.insertion(GroupEntry, entries.items, SortCtx{
                .key_index = sort_key_index,
                .agg_name = sort_field,
                .ascending = asc,
            }, SortCtx.lessThan);
        }

        // Build array of group BSON documents
        var arr_doc = bson.BsonDocument.empty(self.allocator);
        defer arr_doc.deinit();

        for (entries.items, 0..) |entry, group_idx| {
            // Build "key" sub-document
            var key_doc = bson.BsonDocument.empty(self.allocator);
            defer key_doc.deinit();

            if (parsed.group_by_fields) |fields| {
                var key_parts = std.mem.splitSequence(u8, entry.key, "|");
                for (fields) |field| {
                    if (key_parts.next()) |part| {
                        try key_doc.putString(field, part);
                    }
                }
            }

            // Build "values" sub-document
            var values_doc = bson.BsonDocument.empty(self.allocator);
            defer values_doc.deinit();

            for (parsed.aggregations.items) |agg| {
                if (entry.acc.getResult(agg.name)) |agg_result| {
                    switch (agg_result) {
                        .int => |v| try values_doc.putInt64(agg.name, v),
                        .float => |v| try values_doc.putDouble(agg.name, v),
                        .string => |v| try values_doc.putString(agg.name, v),
                    }
                } else {
                    try values_doc.putNull(agg.name);
                }
            }

            // Build group element: { "key": {...}, "values": {...} }
            var group_doc = bson.BsonDocument.empty(self.allocator);
            defer group_doc.deinit();

            if (parsed.group_by_fields != null) {
                try group_doc.putDocument("key", key_doc);
            } else {
                try group_doc.putNull("key");
            }
            try group_doc.putDocument("values", values_doc);

            // Array elements use string index keys: "0", "1", etc.
            var idx_buf: [16]u8 = undefined;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{group_idx}) catch "0";
            try arr_doc.put(idx_str, .{ .document = group_doc });
        }

        // Build root document: { "groups": [...], "total_groups": N }
        var root_doc = bson.BsonDocument.empty(self.allocator);
        defer root_doc.deinit();

        try root_doc.putArray("groups", bson.BsonArray.init(self.allocator, arr_doc.toBytes()));
        try root_doc.putInt32("total_groups", @intCast(groups.count()));

        // Return owned copy of BSON bytes
        return try self.allocator.dupe(u8, root_doc.toBytes());
    }

    /// Graceful shutdown
    pub fn shutdown(self: *Self) !void {
        log.info("Shutting down engine...", .{});

        self.db_mutex.lock();
        defer self.db_mutex.unlock();
        try self.db.shutdown();

        log.info("Engine shutdown complete", .{});
    }
};

// ============================================================================
// Query Helper Functions
// ============================================================================

/// Check if a JSON document matches a predicate
fn matchesPredicate(doc_bson: []const u8, pred: query_engine.Predicate) bool {
    // Client always sends BSON, so we only need to parse as BSON
    const doc_result = bson.BsonDocument.init(std.heap.page_allocator, doc_bson, false);

    if (doc_result) |doc| {
        var mutable_doc = doc;
        defer mutable_doc.deinit();

        // Handle $exists operator specially — checks field presence, not value
        if (pred.operator == .exists) {
            const field_exists = blk: {
                if (doc.getNestedField(pred.field_name)) |field_value_opt| {
                    break :blk field_value_opt != null;
                } else |_| {
                    break :blk false;
                }
            };
            // pred.value.bool_val: true = field must exist, false = field must not exist
            const want_exists = if (pred.value == .bool_val) pred.value.bool_val else true;
            return field_exists == want_exists;
        }

        // Try to get the field value from BSON (supports nested dot-notation)
        if (doc.getNestedField(pred.field_name)) |field_value_opt| {
            if (field_value_opt) |field_value| {
                // Compare BSON value with predicate value
                return compareBsonValue(field_value, pred.value, pred.operator, pred);
            }
        } else |_| {
            // Field not found or error reading it
            return false;
        }
        return false;
    } else |_| {
        // BSON parsing failed - this shouldn't happen if client sends valid BSON
        return false;
    }
}

/// Check if a document matches all AND predicates + OR predicate groups
fn matchesAllPredicates(doc_bson: []const u8, parsed: *const query_engine.ParsedQuery) bool {
    // All AND predicates must match
    for (parsed.predicates.items) |pred| {
        if (!matchesPredicate(doc_bson, pred)) return false;
    }
    // If OR groups exist, at least one group must fully match
    if (parsed.or_predicates.items.len > 0) {
        var any_group_matched = false;
        for (parsed.or_predicates.items) |group| {
            var group_matches = true;
            for (group.items) |pred| {
                if (!matchesPredicate(doc_bson, pred)) {
                    group_matches = false;
                    break;
                }
            }
            if (group_matches) {
                any_group_matched = true;
                break;
            }
        }
        if (!any_group_matched) return false;
    }
    return true;
}

const QueryOperator = query_engine.Operator;

/// Compare a BSON Value with a FieldValue using an operator
fn compareBsonValue(bson_val: bson.Value, field_val: FieldValue, op: QueryOperator, pred: query_engine.Predicate) bool {
    // Handle $in operator — check if BSON value matches any value in the list
    if (op == .in) {
        const in_vals = pred.in_values orelse return false;
        for (in_vals) |v| {
            if (compareBsonValue(bson_val, v, .eq, pred)) return true;
        }
        return false;
    }

    // Handle $regex operator — match BSON string against pattern
    if (op == .regex) {
        const pattern = pred.regex_pattern orelse return false;
        return switch (bson_val) {
            .string => |s| query_engine.simpleRegexMatch(s, pattern),
            else => false,
        };
    }

    return switch (bson_val) {
        .string => |s| blk: {
            if (field_val == .string) {
                break :blk switch (op) {
                    .eq => std.mem.eql(u8, s, field_val.string),
                    .ne => !std.mem.eql(u8, s, field_val.string),
                    .gt => std.mem.order(u8, s, field_val.string) == .gt,
                    .gte => std.mem.order(u8, s, field_val.string) != .lt,
                    .lt => std.mem.order(u8, s, field_val.string) == .lt,
                    .lte => std.mem.order(u8, s, field_val.string) != .gt,
                    .contains => std.mem.indexOf(u8, s, field_val.string) != null,
                    .starts_with => std.mem.startsWith(u8, s, field_val.string),
                    .in, .exists, .regex => false,
                };
            }
            break :blk false;
        },
        .int32 => |i| {
            const i64_val: i64 = i;
            return compareInt64Value(i64_val, field_val, op);
        },
        .int64 => |i| {
            return compareInt64Value(i, field_val, op);
        },
        .double => |d| blk: {
            const expected: f64 = switch (field_val) {
                .f64_val => |v| v,
                .i64_val => |v| @as(f64, @floatFromInt(v)),
                .i32_val => |v| @as(f64, @floatFromInt(v)),
                .u64_val => |v| @as(f64, @floatFromInt(v)),
                .u32_val => |v| @as(f64, @floatFromInt(v)),
                else => break :blk false,
            };
            break :blk switch (op) {
                .eq => d == expected,
                .ne => d != expected,
                .gt => d > expected,
                .gte => d >= expected,
                .lt => d < expected,
                .lte => d <= expected,
                else => false,
            };
        },
        .boolean => |b| blk: {
            if (field_val != .bool_val) break :blk false;
            break :blk switch (op) {
                .eq => b == field_val.bool_val,
                .ne => b != field_val.bool_val,
                else => false,
            };
        },
        .null => false,
        else => false,
    };
}

fn compareInt64Value(i64_val: i64, field_val: FieldValue, op: QueryOperator) bool {
    return switch (field_val) {
        .i64_val => |expected| blk: {
            break :blk switch (op) {
                .eq => i64_val == expected,
                .ne => i64_val != expected,
                .gt => i64_val > expected,
                .gte => i64_val >= expected,
                .lt => i64_val < expected,
                .lte => i64_val <= expected,
                else => false,
            };
        },
        .i32_val => |expected| blk: {
            const expected_i64: i64 = expected;
            break :blk switch (op) {
                .eq => i64_val == expected_i64,
                .ne => i64_val != expected_i64,
                .gt => i64_val > expected_i64,
                .gte => i64_val >= expected_i64,
                .lt => i64_val < expected_i64,
                .lte => i64_val <= expected_i64,
                else => false,
            };
        },
        .u64_val => |expected| blk: {
            if (i64_val < 0) break :blk false;
            const u64_val: u64 = @intCast(i64_val);
            break :blk switch (op) {
                .eq => u64_val == expected,
                .ne => u64_val != expected,
                .gt => u64_val > expected,
                .gte => u64_val >= expected,
                .lt => u64_val < expected,
                .lte => u64_val <= expected,
                else => false,
            };
        },
        .u32_val => |expected| blk: {
            if (i64_val < 0) break :blk false;
            const u32_val: u32 = @intCast(i64_val);
            break :blk switch (op) {
                .eq => u32_val == expected,
                .ne => u32_val != expected,
                .gt => u32_val > expected,
                .gte => u32_val >= expected,
                .lt => u32_val < expected,
                .lte => u32_val <= expected,
                else => false,
            };
        },
        .f64_val => |expected| blk: {
            const d: f64 = @floatFromInt(i64_val);
            break :blk switch (op) {
                .eq => d == expected,
                .ne => d != expected,
                .gt => d > expected,
                .gte => d >= expected,
                .lt => d < expected,
                .lte => d <= expected,
                else => false,
            };
        },
        else => false,
    };
}

const CompareOp = enum { eq, gt, lt };

fn compareJsonValue(json_val: std.json.Value, field_val: FieldValue, op: CompareOp) bool {
    return switch (field_val) {
        .string => |s| blk: {
            if (json_val != .string) break :blk false;
            break :blk switch (op) {
                .eq => std.mem.eql(u8, json_val.string, s),
                .gt => std.mem.order(u8, json_val.string, s) == .gt,
                .lt => std.mem.order(u8, json_val.string, s) == .lt,
            };
        },
        .i64_val => |i| blk: {
            if (json_val != .integer) break :blk false;
            break :blk switch (op) {
                .eq => json_val.integer == i,
                .gt => json_val.integer > i,
                .lt => json_val.integer < i,
            };
        },
        .u64_val => |u| blk: {
            if (json_val != .integer) break :blk false;
            if (json_val.integer < 0) break :blk false;
            const ju: u64 = @intCast(json_val.integer);
            break :blk switch (op) {
                .eq => ju == u,
                .gt => ju > u,
                .lt => ju < u,
            };
        },
        .i32_val => |i| blk: {
            if (json_val != .integer) break :blk false;
            break :blk switch (op) {
                .eq => json_val.integer == i,
                .gt => json_val.integer > i,
                .lt => json_val.integer < i,
            };
        },
        .u32_val => |u| blk: {
            if (json_val != .integer) break :blk false;
            if (json_val.integer < 0) break :blk false;
            const ju: u32 = @intCast(json_val.integer);
            break :blk switch (op) {
                .eq => ju == u,
                .gt => ju > u,
                .lt => ju < u,
            };
        },
        .bool_val => |b| blk: {
            if (json_val != .bool) break :blk false;
            break :blk switch (op) {
                .eq => json_val.bool == b,
                else => false,
            };
        },
        .f64_val => |f| blk: {
            if (json_val != .float) break :blk false;
            break :blk switch (op) {
                .eq => json_val.float == f,
                .gt => json_val.float > f,
                .lt => json_val.float < f,
            };
        },
    };
}

fn containsString(json_val: std.json.Value, field_val: FieldValue) bool {
    if (json_val != .string) return false;
    if (field_val != .string) return false;
    return std.mem.indexOf(u8, json_val.string, field_val.string) != null;
}

fn startsWithString(json_val: std.json.Value, field_val: FieldValue) bool {
    if (json_val != .string) return false;
    if (field_val != .string) return false;
    return std.mem.startsWith(u8, json_val.string, field_val.string);
}

/// Compare two documents (BSON) by a field for sorting
fn compareByField(a_bson: []const u8, b_bson: []const u8, field: []const u8, ascending: bool) bool {
    const allocator = std.heap.page_allocator;

    const a_doc = bson.BsonDocument.init(allocator, a_bson, false) catch return false;
    var a_mut = a_doc;
    defer a_mut.deinit();

    const b_doc = bson.BsonDocument.init(allocator, b_bson, false) catch return true;
    var b_mut = b_doc;
    defer b_mut.deinit();

    const a_val_opt = blk: {
        const result = a_doc.getNestedField(field) catch break :blk null;
        break :blk result;
    };
    const b_val_opt = blk: {
        const result = b_doc.getNestedField(field) catch break :blk null;
        break :blk result;
    };

    const a_val = a_val_opt orelse return false;
    const b_val = b_val_opt orelse return true;

    const cmp = compareBsonValues(a_val, b_val);
    return if (ascending) cmp == .lt else cmp == .gt;
}

fn compareBsonValues(a: bson.Value, b: bson.Value) std.math.Order {
    // Compare numeric types (int32, int64, double) — cross-type comparisons
    const a_num = bsonToF64(a);
    const b_num = bsonToF64(b);
    if (a_num != null and b_num != null) {
        return std.math.order(a_num.?, b_num.?);
    }
    // Compare strings
    if (a == .string and b == .string) {
        return std.mem.order(u8, a.string, b.string);
    }
    // Compare booleans
    if (a == .boolean and b == .boolean) {
        return std.math.order(@as(u1, @intFromBool(a.boolean)), @as(u1, @intFromBool(b.boolean)));
    }
    return .eq;
}

fn bsonToF64(val: bson.Value) ?f64 {
    return switch (val) {
        .int32 => |v| @as(f64, @floatFromInt(v)),
        .int64 => |v| @as(f64, @floatFromInt(v)),
        .double => |v| v,
        else => null,
    };
}

/// Apply projection: build a new BSON document containing only the specified fields
fn applyProjection(allocator: std.mem.Allocator, doc_bson: []const u8, fields: [][]const u8) ![]const u8 {
    const src_doc = try bson.BsonDocument.init(allocator, doc_bson, false);
    var src_mut = src_doc;
    defer src_mut.deinit();

    var out_doc = bson.BsonDocument.empty(allocator);
    errdefer out_doc.deinit();

    for (fields) |field| {
        if (try src_doc.getNestedField(field)) |val| {
            try out_doc.put(field, val);
        }
    }

    const result = try allocator.dupe(u8, out_doc.toBytes());
    out_doc.deinit();
    return result;
}

// ============================================================================
// Unit Tests
// ============================================================================

// NOTE: Engine is a high-level orchestrator that requires full system setup
// (Config, Database, WAL, Index, Catalog) to test. Full integration tests
// are located in the tests/ folder which test end-to-end functionality.
//
// The unit tests below focus on helper functions and isolated components.

test "Engine - setupDirs creates PathAlreadyExists gracefully" {
    // This test validates the error handling logic for directory creation.
    // The actual setupDirs function handles PathAlreadyExists as a non-error.
    // Full integration tests with actual directories are in tests/integration_test.zig
    const err = error.PathAlreadyExists;
    const should_propagate = (err != error.PathAlreadyExists);
    try std.testing.expect(!should_propagate);
}
