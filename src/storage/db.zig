const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const ValueLog = @import("vlog.zig").ValueLog;
const VLogConfig = @import("vlog.zig").VLogConfig;
const BackupManager = @import("backup.zig").BackupManager;
const BackupMetadata = @import("backup.zig").BackupMetadata;
const MetricsCollector = @import("metrics.zig").MetricsCollector;
const MetricsSnapshot = @import("metrics.zig").MetricsSnapshot;
const StorageMetrics = @import("metrics.zig").StorageMetrics;
const GcMetricsSnapshot = @import("metrics.zig").GcMetricsSnapshot;
const TxnMetricsSnapshot = @import("metrics.zig").TxnMetricsSnapshot;
const VlogMetrics = @import("metrics.zig").VlogMetrics;
const WriteAheadLog = @import("../durability/write_ahead_log.zig").WriteAheadLog;
const WalConfig = @import("../durability/write_ahead_log.zig").WalConfig;
const LogRecord = @import("../common/common.zig").LogRecord;
const OpKind = @import("../common/common.zig").OpKind;
const common = @import("../common/common.zig");
const sortedFiles = common.sortedFiles;
const VlogEntry = common.VlogEntry;
const Entry = common.Entry;
const CurrentVlog = common.CurrentVlog;
const milliTimestamp = common.milliTimestamp;
const Config = @import("../common/config.zig").Config;
// const IndexEntry = @import("../common/common.zig").IndexEntry;
const StoreMetrics = @import("../common/stopwatch.zig").StoreMetrics;
const KeyGen = @import("../common/keygen.zig").KeyGen;
const Index = @import("bptree.zig").Index;
const MemTable = @import("../memtable/memtable.zig").MemTable;
const SkipList = @import("../memtable/skiplist.zig").SkipList;
const Catalog = @import("catalog.zig").Catalog;
const FieldExtractor = @import("field_extractor.zig").FieldExtractor;
const FieldValue = @import("field_extractor.zig").FieldValue;
const proto = @import("proto");
const GarbageCollector = @import("gc.zig").GarbageCollector;

const log = std.log.scoped(.db);

pub const Db = struct {
    allocator: Allocator,
    io: Io,
    memtable: *MemTable,
    vlogs: std.HashMap(u16, *ValueLog, std.hash_map.AutoContext(u16), std.hash_map.default_max_load_percentage),
    current_vlog: CurrentVlog,
    head_vlog_id: u16, // oldest vlog (GC candidate)
    tail_vlog_id: u16, // newest vlog (current writes)
    config: *Config,
    primary_index: *Index(u128, u64),
    catalog: *Catalog,
    // Secondary indexes: index_ns → Index
    secondary_indexes: std.StringHashMap(*Index([]const u8, void)),
    metrics: StoreMetrics = StoreMetrics{},
    count: usize = 0,
    // Background GC
    gc: *GarbageCollector,

    // Metrics Collector
    metrics_collector: *MetricsCollector,
    // Write-Ahead Log for crash recovery
    wal: *WriteAheadLog,

    // Bootstrap key for system store recovery (O(1) lookup instead of scanning 10M primary index keys)
    system_store_key: u128 = 0,

    pub fn init(allocator: Allocator, config: *Config, io: Io, primary_index: *Index(u128, u64)) !*Db {
        const db = try allocator.create(Db);

        const catalog = try Catalog.init(allocator, config.paths.metadata, io);
        const metrics_collector = try MetricsCollector.init(allocator);

        // Initialize Write-Ahead Log
        const wal = try WriteAheadLog.init(allocator, WalConfig{
            .dir_path = config.paths.wal,
            .max_file_size = 100 * 1024 * 1024, // 100MB
            .max_buffer_size = 4 * 1024 * 1024, // 4MB buffer
            .flush_interval_in_ms = 1000,
            .io = io,
        });

        db.* = Db{
            .allocator = allocator,
            .io = io,
            .memtable = try MemTable.init(allocator, config.buffers.memtable),
            .vlogs = std.HashMap(u16, *ValueLog, std.hash_map.AutoContext(u16), std.hash_map.default_max_load_percentage).init(allocator),
            .config = config,
            .primary_index = primary_index,
            .catalog = catalog,
            .secondary_indexes = std.StringHashMap(*Index([]const u8, void)).init(allocator),
            .current_vlog = CurrentVlog{ .id = 0, .offset = 0 },
            .head_vlog_id = 0,
            .tail_vlog_id = 0,
            .gc = undefined, // Will be initialized after load_vlogs
            .metrics_collector = metrics_collector,
            .wal = wal,
        };

        try db.load_vlogs();

        // Initialize GarbageCollector after vlogs are loaded
        db.gc = try GarbageCollector.init(allocator, config, &db.vlogs, primary_index, &db.secondary_indexes, &db.tail_vlog_id, wal, io);

        // Crash Recovery: Replay WAL logs
        const replay_result = try wal.replay();
        defer {
            replay_result.arena.deinit();
            std.heap.page_allocator.destroy(replay_result.arena);
        }

        // Apply replayed records to memtable
        for (replay_result.records) |record| {
            switch (record.kind) {
                .insert, .update => {
                    _ = try db.memtable.put(@bitCast(record.key), record.value, record.timestamp);
                },
                .delete => {
                    _ = try db.memtable.del(@bitCast(record.key));
                },
                .read => {}, // Read operations don't need replay
            }
        }

        return db;
    }

    pub fn deinit(self: *Db) void {
        // Shutdown GC
        self.gc.deinit();

        // Cleanup vlogs
        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |vlog| {
            vlog.value_ptr.*.deinit() catch {};
        }
        self.vlogs.deinit();

        // Cleanup secondary indexes
        var idx_iter = self.secondary_indexes.iterator();
        while (idx_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        self.secondary_indexes.deinit();

        // Cleanup memtable
        self.memtable.deinit();

        self.catalog.deinit();
        self.metrics_collector.deinit();
        self.wal.deinit() catch {};
        self.allocator.destroy(self);
    }

    fn load_vlogs(self: *Db) !void {
        // Open the vlog directory for iteration
        const vlog_dir = try Dir.openDir(.cwd(), self.io, self.config.paths.vlog, .{ .iterate = true });
        defer vlog_dir.close(self.io);

        var min_id: u16 = std.math.maxInt(u16);
        var max_id: u16 = 0;
        var files_found: bool = false;

        // Iterate through directory and process .vlog files directly
        var iter = vlog_dir.iterate();
        while (try iter.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".vlog")) continue;

            files_found = true;

            var buf: [512]u8 = undefined;
            const vlog_file_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ self.config.paths.vlog, entry.name });

            // Create ValueLog instance - the ID will be read from the header during init
            const vlog = try ValueLog.init(self.allocator, .{
                .id = 0, // Placeholder - actual ID comes from header
                .file_name = vlog_file_path,
                .max_file_size = self.config.file_sizes.vlog,
                .block_size = self.config.buffers.vlog,
                .io = self.io,
            });

            // Get the actual vlog_id from the header (authoritative source)
            const vlog_id = vlog.header.id;
            try self.vlogs.put(vlog_id, vlog);

            // Track min and max IDs for head/tail determination
            if (vlog_id < min_id) min_id = vlog_id;
            if (vlog_id > max_id) max_id = vlog_id;

            // Initialize byte tracking in header if not set (backward compatibility)
            if (vlog.header.total_bytes == 0) {
                vlog.header.total_bytes = vlog.offset;
                vlog.header.live_bytes = vlog.offset;
                vlog.header.dead_bytes = 0;
            }
        }

        if (!files_found) {
            // No vlogs found, create the first one (ID 0)
            var buf: [256]u8 = undefined;
            const vlog_file_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, 0 });
            const vlog = try ValueLog.init(self.allocator, .{
                .id = 0,
                .file_name = vlog_file_name,
                .max_file_size = self.config.file_sizes.vlog,
                .block_size = self.config.buffers.vlog,
                .io = self.io,
            });
            try self.vlogs.put(0, vlog);

            self.head_vlog_id = 0;
            self.tail_vlog_id = 0;
        } else {
            self.head_vlog_id = min_id;
            self.tail_vlog_id = max_id;
        }

        // Set current_vlog to tail (newest)
        self.current_vlog.id = self.tail_vlog_id;
        if (self.vlogs.get(self.current_vlog.id)) |vlog| {
            self.current_vlog.offset = vlog.offset;
        }
    }

    pub fn post(self: *Db, entry: Entry) !void {

        // Post to memtable
        self.metrics.memtable_writes.start();
        const switched = try self.memtable.post(entry);
        self.metrics.memtable_writes.stop();

        // Index updates happen during flush when actual offsets are known
        if (switched) {
            try self.flush();
        }
    }

    pub fn put(self: *Db, key: i128, value: []const u8, timestamp: i64) !void {
        // NOTE: WAL write is handled by Engine layer with group commits
        // Do not write to WAL here to avoid double-writing

        // Write to memtable
        const switched = try self.memtable.put(key, value, timestamp);
        if (switched) {
            // If memtable switched, flush the old one
            try self.flush();
        }
    }

    pub fn get(self: *Db, key: i128) ![]const u8 {
        // First check memtable (most recent writes)
        const ret = self.memtable.get(key) catch |e| {
            if (e == error.NotFound) {
                // Not found in memtable - check primary index and vlogs
                const key_u128: u128 = @bitCast(key);
                if (try self.primary_index.search(key_u128)) |offset| {
                    const metadata = KeyGen.extractMetadata(key_u128);
                    if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                        var vlog_entry = try vlog.get(offset);
                        defer vlog_entry.deinit(self.allocator);

                        // Check if this is a tombstone (deleted entry)
                        if (vlog_entry.tombstone) {
                            return error.NotFound;
                        }

                        return try self.allocator.dupe(u8, vlog_entry.value);
                    }
                }
                // Not found in any storage layer
                return error.NotFound;
            }
            return e;
        };
        if (ret.len > 0) {
            // Always return allocated memory for consistency
            return try self.allocator.dupe(u8, ret);
        }
        // If memtable returns empty, treat as not found
        return error.NotFound;
    }

    /// Get a document by key using a known vlog offset (avoids re-searching the primary index).
    /// Used when the caller has already iterated the primary index and has the offset.
    pub fn getByOffset(self: *Db, key: i128, offset: u64) ![]const u8 {
        // First check memtable (most recent writes override flushed data)
        const ret = self.memtable.get(key) catch |e| {
            if (e == error.NotFound) {
                // Use the provided offset to read directly from vlog
                const key_u128: u128 = @bitCast(key);
                const metadata = KeyGen.extractMetadata(key_u128);
                if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                    var vlog_entry = try vlog.get(offset);
                    defer vlog_entry.deinit(self.allocator);

                    if (vlog_entry.tombstone) {
                        return error.NotFound;
                    }

                    return try self.allocator.dupe(u8, vlog_entry.value);
                }
                return error.NotFound;
            }
            return e;
        };
        if (ret.len > 0) {
            return try self.allocator.dupe(u8, ret);
        }
        return error.NotFound;
    }

    pub fn del(self: *Db, key: i128, timestamp: i64) !void {
        // NOTE: WAL write is handled by Engine layer with group commits
        // Do not write to WAL here to avoid double-writing

        // First, mark as deleted in memtable
        _ = self.memtable.del(key) catch |e| {
            if (e == error.NotFound) {
                // Not found in memtable - check if it exists in vlog
                const key_u128: u128 = @bitCast(key);
                if (try self.primary_index.search(key_u128)) |old_offset| {
                    // Key exists in vlog - need to write tombstone immediately
                    const metadata = KeyGen.extractMetadata(key_u128);
                    if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                        // Read the old value to get it for secondary index removal
                        var old_entry = try vlog.get(old_offset);
                        defer old_entry.deinit(self.allocator);

                        // Mark old value as dead in stats
                        try self.gc.markValueAsDead(vlog, old_offset);

                        // Get the current vlog for writing the tombstone
                        const current_vlog_id = self.current_vlog.id;
                        if (self.vlogs.get(current_vlog_id)) |current_vlog| {
                            // Write tombstone to current vlog
                            const tombstone = VlogEntry{
                                .key = key_u128,
                                .value = &[_]u8{}, // Empty value
                                .timestamp = timestamp,
                                .tombstone = true, // Explicit tombstone marker
                            };
                            const new_offset = try current_vlog.put(tombstone);

                            // Increment deleted counter in vlog header
                            try current_vlog.incrementDeleted();

                            // Update vlog stats in memory
                            try self.updateVlogStats(current_vlog, tombstone.size(), true);

                            // Update primary index with tombstone offset
                            try self.primary_index.insert(key_u128, new_offset);

                            // Remove from secondary indexes using old value
                            try self.removeFromSecondaryIndexes(key_u128, old_entry.value);

                            // Flush to ensure durability
                            try current_vlog.flush();
                            try self.primary_index.flush();
                        }
                    }
                }
                // If not found anywhere, silently succeed (idempotent delete)
                return;
            }
            return e;
        };
    }

    pub fn shutdown(self: *Db) !void {
        // Switch active memtable to inactive list (replaces with fresh empty one)
        // This ensures memtable.active always points to a valid skiplist for deinit
        try self.memtable.switchActive();

        try self.flush();
    }

    /// Create a secondary index for a specific field
    /// This will create the index structure and populate it by scanning the primary index
    pub fn createSecondaryIndex(self: *Db, store_id: u16, index_ns: []const u8, field_name: []const u8, field_type: proto.FieldType) !void {
        // Create index in catalog with store_id
        _ = try self.catalog.createIndexForStore(store_id, index_ns, field_name, field_type, false);

        // Duplicate the index_ns since it may be freed by the caller
        const index_ns_owned = try self.allocator.dupe(u8, index_ns);
        errdefer self.allocator.free(index_ns_owned);

        // Create the actual B+ tree index
        const index_ptr = try self.allocator.create(Index([]const u8, void));
        index_ptr.* = try Index([]const u8, void).init(self.allocator, .{
            .dir_path = self.config.paths.index,
            .file_name = index_ns_owned,
            .pool_size = self.config.index.primary.pool_size,
            .io = self.io,
        });

        try self.secondary_indexes.put(index_ns_owned, index_ptr);

        var extractor = FieldExtractor.init(self.allocator);
        var doc_count: usize = 0;

        // STEP 1: Populate from memtable (active skiplist)
        {
            var mem_iter = self.memtable.active.iterator();
            while (mem_iter.next()) |entry| {
                const primary_key = entry.key;

                // Check if this entry belongs to the specified store_id
                const metadata = KeyGen.extractMetadata(primary_key);
                if (metadata.store_id != store_id) {
                    continue; // Skip entries from other stores
                }

                // Extract field value from the document
                const field_value = try extractor.extract(entry.value, field_name, field_type);
                defer if (field_value) |fv| fv.deinit(self.allocator);

                if (field_value) |fv| {
                    // Create composite key and insert into secondary index
                    var composite_key_buf: [256]u8 = undefined;
                    const composite_key = try self.makeCompositeKey(&composite_key_buf, fv, primary_key);
                    try index_ptr.insert(composite_key, {});
                    doc_count += 1;
                }
            }
        }

        // STEP 2: Populate from inactive skiplists in memtable
        {
            var inactive_iter = self.memtable.lists.iterator();
            while (inactive_iter.next()) |skiplist| {
                var list_iter = skiplist.iterator();
                while (list_iter.next()) |entry| {
                    const primary_key = entry.key;

                    // Check if this entry belongs to the specified store_id
                    const metadata = KeyGen.extractMetadata(primary_key);
                    if (metadata.store_id != store_id) {
                        continue; // Skip entries from other stores
                    }

                    // Extract field value from the document
                    const field_value = try extractor.extract(entry.value, field_name, field_type);
                    defer if (field_value) |fv| fv.deinit(self.allocator);

                    if (field_value) |fv| {
                        // Create composite key and insert into secondary index
                        var composite_key_buf: [256]u8 = undefined;
                        const composite_key = try self.makeCompositeKey(&composite_key_buf, fv, primary_key);
                        try index_ptr.insert(composite_key, {});
                        doc_count += 1;
                    }
                }
            }
        }

        // STEP 3: Populate from primary B+ tree index (flushed data)
        {
            var iter = try self.primary_index.iterator();
            defer iter.deinit();

            while (try iter.next()) |cell| {
                // Parse key from cell
                if (cell.key.len >= 16) {
                    const primary_key = std.mem.readInt(u128, cell.key[0..16], .big);

                    // Check if this entry belongs to the specified store_id
                    const metadata = KeyGen.extractMetadata(primary_key);
                    if (metadata.store_id != store_id) {
                        continue; // Skip entries from other stores
                    }

                    // Parse offset from cell value
                    if (cell.value.len >= 8) {
                        const offset = std.mem.readInt(u64, cell.value[0..8], .little);

                        // Get the vlog for this entry
                        if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                            // Read the document from vlog
                            var vlog_entry = vlog.get(offset) catch continue;
                            defer vlog_entry.deinit(self.allocator);

                            // Skip tombstones (deleted entries)
                            if (vlog_entry.tombstone) continue;

                            // Extract field value from the document
                            const field_value = try extractor.extract(vlog_entry.value, field_name, field_type);
                            defer if (field_value) |fv| fv.deinit(self.allocator);

                            if (field_value) |fv| {
                                // Create composite key and insert into secondary index
                                var composite_key_buf: [256]u8 = undefined;
                                const composite_key = try self.makeCompositeKey(&composite_key_buf, fv, primary_key);
                                try index_ptr.insert(composite_key, {});
                                doc_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // Flush to persist the index metadata to catalog
        try self.flush();

        // Flush the secondary index B+ tree to disk
        try index_ptr.flush();

        // Index created successfully
    }

    /// Update secondary indexes for a newly inserted entry
    /// Uses store_id from the key to route to the correct indexes
    fn updateSecondaryIndexes(self: *Db, primary_key: u128, value: []const u8) !void {
        // Extract store_id from the primary key
        const metadata = KeyGen.extractMetadata(primary_key);
        const store_id = metadata.store_id;

        // Get indexes for this specific store
        const indexes_list = self.catalog.getIndexesByStoreId(store_id) orelse return;

        var extractor = FieldExtractor.init(self.allocator);

        // Only update indexes that belong to this store
        for (indexes_list.items) |index_meta| {
            // Get the actual B+ tree index
            if (self.secondary_indexes.get(index_meta.ns)) |index| {
                // Extract field value from JSON
                const field_value = try extractor.extract(value, index_meta.field, index_meta.field_type);
                defer if (field_value) |fv| fv.deinit(self.allocator);

                if (field_value) |fv| {
                    // Create composite key: field_value + primary_key
                    var composite_key_buf: [256]u8 = undefined;
                    const composite_key = try self.makeCompositeKey(&composite_key_buf, fv, primary_key);

                    // Insert into secondary index (value is void)
                    try index.insert(composite_key, {});
                }
            }
        }
    }

    /// Remove entries from secondary indexes for a deleted document
    /// Uses store_id from the key to route to the correct indexes
    fn removeFromSecondaryIndexes(self: *Db, primary_key: u128, value: []const u8) !void {
        // Extract store_id from the primary key
        const metadata = KeyGen.extractMetadata(primary_key);
        const store_id = metadata.store_id;

        // Get indexes for this specific store
        const indexes_list = self.catalog.getIndexesByStoreId(store_id) orelse return;

        var extractor = FieldExtractor.init(self.allocator);

        // Remove from all indexes that belong to this store
        for (indexes_list.items) |index_meta| {
            // Get the actual B+ tree index
            if (self.secondary_indexes.get(index_meta.ns)) |index| {
                // Extract field value from CBOR
                const field_value = try extractor.extract(value, index_meta.field, index_meta.field_type);
                defer if (field_value) |fv| fv.deinit(self.allocator);

                if (field_value) |fv| {
                    // Create composite key: field_value + primary_key
                    var composite_key_buf: [256]u8 = undefined;
                    const composite_key = try self.makeCompositeKey(&composite_key_buf, fv, primary_key);

                    // Delete from secondary index
                    try index.delete(composite_key);
                }
            }
        }
    }

    /// Helper to create composite key bytes from field value and primary key
    fn makeCompositeKey(self: *Db, buf: []u8, field_value: FieldValue, primary_key: u128) ![]const u8 {
        _ = self;
        var offset: usize = 0;

        // IMPORTANT: Use big-endian encoding for field values to ensure correct
        // lexicographic sort order in B+ tree for range queries.
        // For signed integers, XOR with sign bit to map negative values before positive.
        // For floats, use IEEE 754 sortable encoding (XOR sign bit for positive, all bits for negative).
        // WARNING: This is a BREAKING CHANGE from previous little-endian encoding.
        // All existing secondary indexes must be dropped and recreated.

        // Write field value
        switch (field_value) {
            .string => |s| {
                const hash = std.hash.Wyhash.hash(0, s);
                std.mem.writeInt(u64, buf[offset..][0..8], hash, .big);
                offset += 8;
            },
            .u64_val => |v| {
                // Unsigned: big-endian directly gives correct sort order
                std.mem.writeInt(u64, buf[offset..][0..8], v, .big);
                offset += 8;
            },
            .i64_val => |v| {
                // Signed: XOR with sign bit (0x8000...) to map negatives before positives
                const biased: u64 = @bitCast(v ^ @as(i64, std.math.minInt(i64)));
                std.mem.writeInt(u64, buf[offset..][0..8], biased, .big);
                offset += 8;
            },
            .u32_val => |v| {
                // Unsigned: big-endian directly gives correct sort order
                std.mem.writeInt(u32, buf[offset..][0..4], v, .big);
                offset += 4;
            },
            .i32_val => |v| {
                // Signed: XOR with sign bit to map negatives before positives
                const biased: u32 = @bitCast(v ^ @as(i32, std.math.minInt(i32)));
                std.mem.writeInt(u32, buf[offset..][0..4], biased, .big);
                offset += 4;
            },
            .bool_val => |v| {
                buf[offset] = if (v) 1 else 0;
                offset += 1;
            },
            .f64_val => |v| {
                // IEEE 754 sortable encoding: flip sign bit for positive, all bits for negative
                const bits: u64 = @bitCast(v);
                const sortable = if (v >= 0.0)
                    bits ^ 0x8000000000000000 // Positive: flip sign bit
                else
                    ~bits; // Negative: flip all bits
                std.mem.writeInt(u64, buf[offset..][0..8], sortable, .big);
                offset += 8;
            },
        }

        // Write primary key (unsigned, big-endian for consistent ordering)
        std.mem.writeInt(u128, buf[offset..][0..16], primary_key, .big);
        offset += 16;

        return buf[0..offset];
    }

    /// Convert a query FieldValue to match the index's field_type.
    /// The query parser always produces i64_val for integer literals, but the
    /// index may have been built with u32_val, i32_val, u64_val, etc.
    /// Without conversion, the composite key byte length won't match.
    fn convertFieldValue(fv: FieldValue, target_type: proto.FieldType) FieldValue {
        return switch (target_type) {
            .U32 => switch (fv) {
                .i64_val => |v| FieldValue{ .u32_val = @intCast(v) },
                .i32_val => |v| FieldValue{ .u32_val = @intCast(v) },
                .u64_val => |v| FieldValue{ .u32_val = @intCast(v) },
                else => fv,
            },
            .I32 => switch (fv) {
                .i64_val => |v| FieldValue{ .i32_val = @intCast(v) },
                .u32_val => |v| FieldValue{ .i32_val = @intCast(v) },
                .u64_val => |v| FieldValue{ .i32_val = @intCast(v) },
                else => fv,
            },
            .U64 => switch (fv) {
                .i64_val => |v| FieldValue{ .u64_val = @intCast(v) },
                .i32_val => |v| FieldValue{ .u64_val = @intCast(v) },
                .u32_val => |v| FieldValue{ .u64_val = v },
                else => fv,
            },
            .I64 => switch (fv) {
                .u64_val => |v| FieldValue{ .i64_val = @intCast(v) },
                .i32_val => |v| FieldValue{ .i64_val = v },
                .u32_val => |v| FieldValue{ .i64_val = v },
                else => fv,
            },
            .F64 => switch (fv) {
                .i64_val => |v| FieldValue{ .f64_val = @floatFromInt(v) },
                .i32_val => |v| FieldValue{ .f64_val = @floatFromInt(v) },
                .u64_val => |v| FieldValue{ .f64_val = @floatFromInt(v) },
                .u32_val => |v| FieldValue{ .f64_val = @floatFromInt(v) },
                else => fv,
            },
            else => fv,
        };
    }

    /// Update vlog statistics after a write
    fn updateVlogStats(self: *Db, vlog: *ValueLog, bytes_written: u64, is_delete: bool) !void {
        _ = self;
        vlog.header.total_bytes += bytes_written;
        vlog.header.live_bytes += bytes_written;
        vlog.header.count += 1;
        if (is_delete) {
            vlog.header.deleted += 1;
        }
    }

    /// Mark old value as dead in vlog statistics (called on update/delete)
    /// Check if vlog rotation is needed and perform it
    fn maybeRotateVlog(self: *Db) !void {
        if (self.vlogs.get(self.current_vlog.id)) |current_vlog| {
            // Check if current vlog has reached max size
            if (current_vlog.offset >= self.config.file_sizes.vlog) {
                // Flush current vlog before rotation
                try current_vlog.flush();

                // Create new vlog file
                const new_vlog_id = self.tail_vlog_id + 1;
                var buf: [256]u8 = undefined;
                const vlog_file_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, new_vlog_id });
                const new_vlog = try ValueLog.init(self.allocator, .{
                    .id = new_vlog_id,
                    .file_name = vlog_file_name,
                    .max_file_size = self.config.file_sizes.vlog,
                    .block_size = self.config.buffers.vlog,
                    .io = self.io,
                });

                // Add new vlog to HashMap
                try self.vlogs.put(new_vlog_id, new_vlog);

                // Update tail and current vlog
                self.tail_vlog_id = new_vlog_id;
                self.current_vlog.id = new_vlog_id;
                self.current_vlog.offset = 0;
            }
        }
    }

    /// On-demand flush: switch active memtable and flush all pending data to disk
    /// Call this after bulk inserts to ensure durability
    pub fn flushOnDemand(self: *Db) !void {
        // Switch active skiplist to inactive (even if below threshold)
        try self.memtable.switchActive();
        // Flush all pending skiplists
        try self.flush();
    }

    pub fn flush(self: *Db) !void {
        // Check if vlog rotation is needed before flushing
        try self.maybeRotateVlog();

        var flush_total: u32 = 0;
        var flush_skipped: u32 = 0;

        while (self.memtable.lists.pop()) |skl| {
            self.metrics.db_flush.start();
            self.count += skl.count;
            var iter = skl.iterator();

            while (iter.next()) |entry| {
                flush_total += 1;

                // Extract metadata from key using KeyGen format
                // store_id (bits 112-127) | doc_type (bits 104-111) | vlog_id (bits 96-103) | random (bits 0-95)
                const metadata = KeyGen.extractMetadata(entry.key);
                const vlog_id = metadata.vlog_id;

                if (self.vlogs.get(vlog_id)) |vlog| {
                    // Check if key already exists and mark old value as dead
                    if (try self.primary_index.search(entry.key)) |old_offset| {
                        try self.gc.markValueAsDead(vlog, old_offset);
                    }

                    if (entry.kind == .delete) {
                        // Handle deletion: remove from indexes
                        // Write tombstone to vlog for consistency
                        self.metrics.vlog_writes.start();
                        const vlog_entry = VlogEntry{
                            .key = entry.key,
                            .value = &[_]u8{}, // Empty value
                            .timestamp = entry.timestamp,
                            .tombstone = true, // Explicit tombstone marker
                        };
                        const offset = try vlog.put(vlog_entry);
                        self.metrics.vlog_writes.stop();

                        // Increment deleted counter in vlog header
                        try vlog.incrementDeleted();

                        // Update vlog stats in memory
                        try self.updateVlogStats(vlog, vlog_entry.size(), true);

                        // Update primary index with tombstone offset
                        try self.primary_index.insert(entry.key, offset);

                        // Remove from secondary indexes
                        try self.removeFromSecondaryIndexes(entry.key, entry.value);
                    } else {
                        // Handle insert/update
                        self.metrics.vlog_writes.start();
                        const vlog_entry = VlogEntry{
                            .key = entry.key,
                            .value = entry.value,
                            .timestamp = entry.timestamp,
                        };
                        const offset = try vlog.put(vlog_entry);
                        self.metrics.vlog_writes.stop();

                        // Update vlog stats
                        try self.updateVlogStats(vlog, vlog_entry.size(), false);

                        // Update primary index with actual offset from vlog
                        try self.primary_index.insert(entry.key, offset);

                        // Update secondary indexes
                        try self.updateSecondaryIndexes(entry.key, entry.value);
                    }
                } else {
                    flush_skipped += 1;
                    log.warn("Flush: skipping entry - vlog_id={d} not found in vlogs map", .{vlog_id});
                }
            }

            log.info("Flush batch: total={d}, skipped={d}, written={d}", .{ flush_total, flush_skipped, flush_total - flush_skipped });
            skl.deinit();
            var vlog_iter = self.vlogs.iterator();
            while (vlog_iter.next()) |vlog| {
                try vlog.value_ptr.*.flush();
            }

            // Sync all vlog headers to persist statistics (count, deleted, byte tracking)
            var header_sync_iter = self.vlogs.iterator();
            while (header_sync_iter.next()) |vlog| {
                try vlog.value_ptr.*.syncHeader();
            }
            log.info("All vlog headers synced to disk", .{});

            // Flush primary index to disk to ensure durability
            try self.primary_index.flush();
            log.info("Primary index flushed to disk", .{});

            // Flush all secondary indexes to disk
            var sec_iter = self.secondary_indexes.iterator();
            while (sec_iter.next()) |sec_entry| {
                try sec_entry.value_ptr.*.flush();
            }

            // Checkpoint WAL after successful flush
            try self.wal.checkpoint();
            try self.wal.truncate();
        }
    }

    /// Query by secondary index
    /// Returns a list of primary keys that match the given field value
    pub fn findBySecondaryIndex(self: *Db, index_ns: []const u8, field_value: FieldValue) !std.ArrayList(u128) {
        var result: std.ArrayList(u128) = .empty;

        // Get the secondary index
        const index = self.secondary_indexes.get(index_ns) orelse return error.IndexNotFound;

        // Look up the index metadata to get the field_type so we can convert
        // the query FieldValue to match the type the index was built with.
        // The query parser always produces i64_val for integers, but the index
        // may have been built with u32_val, i32_val, etc.
        const index_meta = self.catalog.indexes.get(index_ns);
        const converted_fv = if (index_meta) |meta|
            convertFieldValue(field_value, meta.field_type)
        else
            field_value;

        // Create composite key range for the field value
        var start_key_buf: [256]u8 = undefined;
        var end_key_buf: [256]u8 = undefined;

        const start_key = try self.makeCompositeKey(&start_key_buf, converted_fv, 0);
        const end_key = try self.makeCompositeKey(&end_key_buf, converted_fv, std.math.maxInt(u128));

        // Range scan the secondary index
        var iter = try index.tree.rangeScan(start_key, end_key);
        defer iter.deinit();

        while (try iter.next()) |entry| {
            // Extract primary key from the composite key
            // The primary key is the last 16 bytes of the composite key (big-endian)
            const key_len = entry.key.len;
            if (key_len >= 16) {
                const primary_key = std.mem.readInt(u128, entry.key[key_len - 16 ..][0..16], .big);
                try result.append(self.allocator, primary_key);
            }
        }

        return result;
    }

    /// Helper struct for batching vlog reads
    const VlogReadRequest = struct {
        key: u128,
        offset: u64,
    };

    /// Helper to get documents by secondary index with batched vlog reads
    /// Returns the actual document values, not just keys
    /// Optimized: groups reads by vlog and sorts by offset for sequential I/O
    pub fn getBySecondaryIndex(self: *Db, index_ns: []const u8, field_value: FieldValue) !std.ArrayList([]const u8) {
        var result: std.ArrayList([]const u8) = .empty;

        // Get primary keys from secondary index
        const primary_keys = try self.findBySecondaryIndex(index_ns, field_value);
        defer primary_keys.deinit(self.allocator);

        if (primary_keys.items.len == 0) return result;

        // Group keys by vlog_id and collect offsets
        var by_vlog = std.AutoHashMap(u16, std.ArrayList(VlogReadRequest)).init(self.allocator);
        defer {
            var iter = by_vlog.iterator();
            while (iter.next()) |entry| {
                entry.value_ptr.deinit();
            }
            by_vlog.deinit();
        }

        // Phase 1: Group keys by vlog_id
        for (primary_keys.items) |key| {
            if (try self.primary_index.search(key)) |offset| {
                const metadata = KeyGen.extractMetadata(key);
                const vlog_id = metadata.vlog_id;

                var list = by_vlog.get(vlog_id) orelse blk: {
                    const new_list = std.ArrayList(VlogReadRequest).init(self.allocator);
                    try by_vlog.put(vlog_id, new_list);
                    break :blk new_list;
                };

                try list.append(VlogReadRequest{ .key = key, .offset = offset });
                try by_vlog.put(vlog_id, list);
            }
        }

        // Phase 2: Sort offsets within each vlog for sequential reads
        var iter = by_vlog.iterator();
        while (iter.next()) |entry| {
            const requests = entry.value_ptr;
            std.mem.sort(VlogReadRequest, requests.items, {}, struct {
                fn lessThan(_: void, a: VlogReadRequest, b: VlogReadRequest) bool {
                    return a.offset < b.offset;
                }
            }.lessThan);
        }

        // Phase 3: Batch read from each vlog (now sorted for sequential I/O)
        var vlog_iter = by_vlog.iterator();
        while (vlog_iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;
            const requests = entry.value_ptr;

            if (self.vlogs.get(vlog_id)) |vlog| {
                for (requests.items) |req| {
                    // Read from vlog using offset
                    var vlog_entry = vlog.get(req.offset) catch {
                        // If vlog read fails, try memtable as fallback
                        const value = self.get(@bitCast(req.key)) catch continue;
                        try result.append(self.allocator, value);
                        continue;
                    };
                    defer vlog_entry.deinit(self.allocator);

                    // Skip tombstones (deleted entries)
                    if (vlog_entry.tombstone) continue;

                    // Allocate and copy the value so it persists
                    const value_copy = try self.allocator.dupe(u8, vlog_entry.value);
                    try result.append(self.allocator, value_copy);
                }
            } else {
                // Vlog not found, try memtable fallback for all requests
                for (requests.items) |req| {
                    const value = self.get(@intCast(req.key)) catch continue;
                    try result.append(self.allocator, value);
                }
            }
        }

        return result;
    }

    // ===== Backup/Restore Methods =====

    /// Create a full backup of the database
    pub fn createBackup(self: *Db, backup_dir: []const u8) !BackupMetadata {
        // Flush all pending writes
        try self.flush();

        // Create backup manager
        var backup_mgr = try BackupManager.init(self.allocator, self.io, backup_dir);
        defer backup_mgr.deinit();

        // Collect all vlog IDs
        var vlog_ids: std.ArrayList(u16) = .empty;
        defer vlog_ids.deinit(self.allocator);

        var iter = self.vlogs.keyIterator();
        while (iter.next()) |vlog_id| {
            try vlog_ids.append(self.allocator, vlog_id.*);
        }

        // Get index entry count estimate
        const entry_count = self.count;

        // Get database path from config
        const db_path = self.config.data_dir;

        // Create backup
        return try backup_mgr.createFullBackup(db_path, vlog_ids.items, entry_count);
    }

    /// Restore database from backup file
    pub fn restoreFromBackup(self: *Db, backup_path: []const u8) !BackupMetadata {
        _ = self;
        _ = backup_path;
        // This would require rebuilding the database, which is complex
        // For now, return error - typically restoration happens during init
        return error.RestoreNotSupported;
    }

    /// List all available backups
    pub fn listBackups(self: *Db, backup_dir: []const u8) !std.ArrayList(BackupMetadata) {
        var backup_mgr = try BackupManager.init(self.allocator, self.io, backup_dir);
        defer backup_mgr.deinit();

        return try backup_mgr.listBackups();
    }

    /// Clean up old backups, keeping only the most recent N
    pub fn cleanupBackups(self: *Db, backup_dir: []const u8, keep_count: usize) !usize {
        var backup_mgr = try BackupManager.init(self.allocator, self.io, backup_dir);
        defer backup_mgr.deinit();

        return try backup_mgr.cleanupOldBackups(keep_count);
    }

    // ===== Monitoring/Metrics Methods =====

    /// Get a snapshot of all database metrics
    pub fn getMetrics(self: *Db) !MetricsSnapshot {
        // Calculate total storage size
        var total_vlog_size: u64 = 0;
        var vlog_metrics_list: std.ArrayList(VlogMetrics) = .empty;
        defer vlog_metrics_list.deinit(self.allocator);

        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;
            const vlog = entry.value_ptr.*;

            total_vlog_size += vlog.header.total_bytes;

            try vlog_metrics_list.append(self.allocator, VlogMetrics{
                .vlog_id = vlog_id,
                .total_bytes = vlog.header.total_bytes,
                .live_bytes = vlog.header.live_bytes,
                .dead_bytes = vlog.header.dead_bytes,
                .dead_ratio = vlog.header.deadRatio(),
                .entry_count = vlog.header.count,
                .deleted_count = vlog.header.deleted,
                .last_gc_timestamp = vlog.header.last_gc_ts,
            });
        }

        const gc_metrics = self.gc.getMetrics();

        return MetricsSnapshot{
            .timestamp = milliTimestamp(),
            .storage = StorageMetrics{
                .total_entries = self.count,
                .total_vlogs = @intCast(self.vlogs.count()),
                .total_size_bytes = total_vlog_size,
                .memtable_size_bytes = 0, // TODO: Add memtable size tracking
                .index_size_bytes = 0, // TODO: Add index size tracking
                .vlog_size_bytes = total_vlog_size,
            },
            .gc = GcMetricsSnapshot{
                .enabled = self.config.gc_config.enabled,
                .total_runs = gc_metrics.total_runs.load(.monotonic),
                .total_bytes_reclaimed = gc_metrics.total_bytes_reclaimed.load(.monotonic),
                .last_run_duration_ms = gc_metrics.last_run_duration_ms.load(.monotonic),
                .last_run_timestamp = gc_metrics.last_run_timestamp.load(.monotonic),
                .next_run_estimate_ms = 0, // TODO: Calculate based on interval
            },
            .performance = self.metrics_collector.getPerformanceMetrics(),
            .vlogs = try self.allocator.dupe(VlogMetrics, vlog_metrics_list.items),
        };
    }

    /// Export metrics as JSON string
    pub fn getMetricsJson(self: *Db) ![]const u8 {
        var snapshot = try self.getMetrics();
        defer snapshot.deinit(self.allocator);

        return try self.metrics_collector.exportJson(snapshot);
    }
};
