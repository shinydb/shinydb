const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const ValueLog = @import("vlog.zig").ValueLog;
const VLogConfig = @import("vlog.zig").VLogConfig;
const TxnManager = @import("transaction.zig").TxnManager;
const Transaction = @import("transaction.zig").Transaction;
const IsolationLevel = @import("transaction.zig").IsolationLevel;
const TxnId = @import("transaction.zig").TxnId;
const BackupManager = @import("backup.zig").BackupManager;
const BackupMetadata = @import("backup.zig").BackupMetadata;
const MetricsCollector = @import("metrics.zig").MetricsCollector;
const MetricsSnapshot = @import("metrics.zig").MetricsSnapshot;
const StorageMetrics = @import("metrics.zig").StorageMetrics;
const GcMetricsSnapshot = @import("metrics.zig").GcMetricsSnapshot;
const TxnMetricsSnapshot = @import("metrics.zig").TxnMetricsSnapshot;
const VlogMetrics = @import("metrics.zig").VlogMetrics;
const Compressor = @import("compression.zig").Compressor;
const CompressionConfig = @import("compression.zig").CompressionConfig;
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
const IndexEntry = @import("../common/common.zig").IndexEntry;
const StoreMetrics = @import("../common/stopwatch.zig").StoreMetrics;
const KeyGen = @import("../common/keygen.zig").KeyGen;
const Index = @import("bptree.zig").Index;
const MemTable = @import("../memtable/memtable.zig").MemTable;
const SkipList = @import("../memtable/skiplist.zig").SkipList;
const Catalog = @import("catalog.zig").Catalog;
const FieldExtractor = @import("field_extractor.zig").FieldExtractor;
const FieldValue = @import("field_extractor.zig").FieldValue;
const proto = @import("proto");

const log = std.log.scoped(.db);

pub const VLogStats = struct {
    total_bytes: u64,
    live_bytes: u64,
    dead_bytes: u64,
    count: u64,
    deleted: u64,
    last_gc_ts: i64,

    pub fn deadRatio(self: *const VLogStats) f64 {
        if (self.total_bytes == 0) return 0.0;
        return @as(f64, @floatFromInt(self.dead_bytes)) /
            @as(f64, @floatFromInt(self.total_bytes));
    }

    pub fn isGcCandidate(self: *const VLogStats, threshold: f64) bool {
        return self.deadRatio() >= threshold;
    }
};

pub const GcConfig = struct {
    enabled: bool = true,
    interval_seconds: u64 = 300, // 5 minutes
    dead_ratio_threshold: f64 = 0.5, // 50% dead space
    max_concurrent: usize = 1, // One vlog at a time
};

pub const GcMetrics = struct {
    total_runs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes_reclaimed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_run_duration_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_run_timestamp: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
};

pub const Db = struct {
    allocator: Allocator,
    io: Io,
    memtable: *MemTable,
    vlogs: std.HashMap(u16, *ValueLog, std.hash_map.AutoContext(u16), std.hash_map.default_max_load_percentage),
    vlog_stats: std.AutoHashMap(u16, VLogStats),
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
    gc_config: GcConfig,
    gc_metrics: GcMetrics,
    gc_thread: ?std.Thread = null,
    gc_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // Transaction Manager
    txn_manager: *TxnManager,
    // Metrics Collector
    metrics_collector: *MetricsCollector,
    // Compressor
    compressor: *Compressor,
    // Write-Ahead Log for crash recovery
    wal: *WriteAheadLog,

    pub fn init(allocator: Allocator, config: *Config, io: Io, primary_index: *Index(u128, u64)) !*Db {
        const db = try allocator.create(Db);

        const catalog = try Catalog.init(allocator);
        const txn_manager = try TxnManager.init(allocator);
        const metrics_collector = try MetricsCollector.init(allocator);
        const compressor = try Compressor.init(allocator, CompressionConfig{});

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
            .vlog_stats = std.AutoHashMap(u16, VLogStats).init(allocator),
            .config = config,
            .primary_index = primary_index,
            .catalog = catalog,
            .secondary_indexes = std.StringHashMap(*Index([]const u8, void)).init(allocator),
            .current_vlog = CurrentVlog{ .id = 0, .offset = 0 },
            .head_vlog_id = 0,
            .tail_vlog_id = 0,
            .gc_config = GcConfig{},
            .gc_metrics = GcMetrics{},
            .txn_manager = txn_manager,
            .metrics_collector = metrics_collector,
            .compressor = compressor,
            .wal = wal,
        };

        try db.load_vlogs();

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

        // Start background GC thread if enabled
        if (db.gc_config.enabled) {
            db.gc_thread = try std.Thread.spawn(.{}, backgroundGcWorker, .{db});
        }

        return db;
    }

    /// Background GC worker thread
    fn backgroundGcWorker(db: *Db) void {
        var seconds_elapsed: u64 = 0;

        while (!db.gc_shutdown.load(.acquire)) {
            // Sleep in small increments to allow quick shutdown
            var i: u64 = 0;
            while (i < 10 and !db.gc_shutdown.load(.acquire)) : (i += 1) {
                std.Thread.yield() catch {};
            }
            seconds_elapsed += 1;

            // Check if it's time to run GC
            if (seconds_elapsed < db.gc_config.interval_seconds) continue;
            seconds_elapsed = 0;

            // Check if shutdown was requested
            if (db.gc_shutdown.load(.acquire)) break;

            // Run GC cycle
            const start_time = milliTimestamp();
            var bytes_reclaimed: u64 = 0;

            // Select GC candidates
            var candidates = db.selectGcCandidates(db.gc_config.dead_ratio_threshold) catch {
                continue;
            };
            defer candidates.deinit(db.allocator);

            if (candidates.items.len == 0) {
                // std.debug.print("GC: No candidates found\n", .{});
                continue;
            }

            // GC up to max_concurrent vlogs
            const to_gc = @min(candidates.items.len, db.gc_config.max_concurrent);
            for (candidates.items[0..to_gc]) |vlog_id| {
                _ = db.garbageCollectVlog(vlog_id) catch {
                    continue;
                };

                // Estimate bytes reclaimed (approximate)
                if (db.vlog_stats.get(vlog_id)) |stats| {
                    bytes_reclaimed += stats.dead_bytes;
                }
            }

            // Compact primary index to remove tombstones
            _ = db.compactPrimaryIndex() catch {};

            // Update metrics
            const duration = milliTimestamp() - start_time;
            _ = db.gc_metrics.total_runs.fetchAdd(1, .release);
            _ = db.gc_metrics.total_bytes_reclaimed.fetchAdd(bytes_reclaimed, .release);
            db.gc_metrics.last_run_duration_ms.store(@intCast(duration), .release);
            db.gc_metrics.last_run_timestamp.store(start_time, .release);
        }
    }

    pub fn deinit(self: *Db) void {
        // Shutdown GC thread
        if (self.gc_thread) |thread| {
            self.gc_shutdown.store(true, .release);
            thread.join();
        }

        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |vlog| {
            vlog.value_ptr.*.deinit() catch {};
        }

        // Cleanup vlog stats
        self.vlog_stats.deinit();

        // Cleanup secondary indexes
        var idx_iter = self.secondary_indexes.iterator();
        while (idx_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            // Free the duplicated key string
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        self.secondary_indexes.deinit();

        self.catalog.deinit();
        self.txn_manager.deinit();
        self.metrics_collector.deinit();
        self.compressor.deinit();
        self.wal.deinit() catch {};
        self.allocator.destroy(self.config);
        self.allocator.destroy(self);
    }

    fn load_vlogs(self: *Db) !void {
        const files = try sortedFiles(self.allocator, self.config.paths.vlog, self.io);
        defer {
            // Free the files array to prevent memory leak
            for (files) |file_info| {
                self.allocator.free(file_info.name);
            }
            self.allocator.free(files);
        }

        if (files.len == 0) {
            // No vlogs found, create the first one
            var buf: [256]u8 = undefined;
            const vlog_file_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, 0 });
            const meta_vlog = try ValueLog.init(self.allocator, .{
                .file_name = vlog_file_name,
                .max_file_size = self.config.file_sizes.vlog,
                .block_size = self.config.buffers.vlog,
                .io = self.io,
            });
            try self.vlogs.put(@as(u16, @intCast(0)), meta_vlog);

            // Initialize stats for new vlog
            try self.vlog_stats.put(0, VLogStats{
                .total_bytes = 0,
                .live_bytes = 0,
                .dead_bytes = 0,
                .count = meta_vlog.header.count,
                .deleted = meta_vlog.header.deleted,
                .last_gc_ts = meta_vlog.header.last_gc_ts,
            });

            self.head_vlog_id = 0;
            self.tail_vlog_id = 0;
        } else {
            // Load existing vlogs and their statistics
            for (0..files.len) |i| {
                var buf: [256]u8 = undefined;
                const vlog_file_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, i });
                const vlog = try ValueLog.init(self.allocator, .{
                    .file_name = vlog_file_name,
                    .max_file_size = self.config.file_sizes.vlog,
                    .block_size = self.config.buffers.vlog,
                    .io = self.io,
                });
                const vlog_id = @as(u16, @intCast(i));
                try self.vlogs.put(vlog_id, vlog);

                // Initialize stats from vlog header
                // Note: total_bytes and live_bytes will be calculated during first GC scan
                // For now, use approximate values based on file size
                const file_size = vlog.offset; // Current file size
                try self.vlog_stats.put(vlog_id, VLogStats{
                    .total_bytes = file_size,
                    .live_bytes = file_size, // Assume all live initially; GC will update
                    .dead_bytes = 0,
                    .count = vlog.header.count,
                    .deleted = vlog.header.deleted,
                    .last_gc_ts = vlog.header.last_gc_ts,
                });
            }

            // Set head (oldest) and tail (newest) vlog IDs
            self.head_vlog_id = 0; // Oldest vlog (GC candidate)
            self.tail_vlog_id = @as(u16, @intCast(self.vlogs.count() - 1)); // Newest vlog
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

    pub fn del(self: *Db, key: i128, _: i64) !void {
        // NOTE: WAL write is handled by Engine layer with group commits
        // Do not write to WAL here to avoid double-writing
        // timestamp parameter kept for API compatibility

        // Delete from memtable
        return try self.memtable.del(key);
    }

    pub fn shutdown(self: *Db) !void {
        // Flush the current active memtable
        self.memtable.lists.push(self.memtable.active) catch {};

        try self.flush();
    }

    /// Create a secondary index for a specific field
    /// This will create the index structure and populate it by scanning the primary index
    pub fn createSecondaryIndex(self: *Db, store_id: u16, index_ns: []const u8, field_name: []const u8, field_type: proto.FieldType) !void {
        // Create index in catalog with store_id
        _ = try self.catalog.createIndexForStore(store_id, index_ns, field_name, field_type, false, self);

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

        // Write field value
        switch (field_value) {
            .string => |s| {
                const hash = std.hash.Wyhash.hash(0, s);
                std.mem.writeInt(u64, buf[offset..][0..8], hash, .little);
                offset += 8;
            },
            .u64_val => |v| {
                std.mem.writeInt(u64, buf[offset..][0..8], v, .little);
                offset += 8;
            },
            .i64_val => |v| {
                std.mem.writeInt(i64, buf[offset..][0..8], v, .little);
                offset += 8;
            },
            .u32_val => |v| {
                std.mem.writeInt(u32, buf[offset..][0..4], v, .little);
                offset += 4;
            },
            .i32_val => |v| {
                std.mem.writeInt(i32, buf[offset..][0..4], v, .little);
                offset += 4;
            },
            .bool_val => |v| {
                buf[offset] = if (v) 1 else 0;
                offset += 1;
            },
            .f64_val => |v| {
                std.mem.writeInt(u64, buf[offset..][0..8], @bitCast(v), .little);
                offset += 8;
            },
        }

        // Write primary key
        std.mem.writeInt(u128, buf[offset..][0..16], primary_key, .little);
        offset += 16;

        return buf[0..offset];
    }

    /// Update vlog statistics after a write
    fn updateVlogStats(self: *Db, vlog_id: u16, bytes_written: u64, is_delete: bool) !void {
        if (self.vlog_stats.getPtr(vlog_id)) |stats| {
            stats.total_bytes += bytes_written;
            stats.live_bytes += bytes_written;
            stats.count += 1;
            if (is_delete) {
                stats.deleted += 1;
            }
        }
    }

    /// Mark old value as dead in vlog statistics (called on update/delete)
    fn markValueAsDead(self: *Db, key: u128, old_offset: u64) !void {
        const metadata = KeyGen.extractMetadata(key);
        const vlog_id = metadata.vlog_id;

        if (self.vlog_stats.getPtr(vlog_id)) |stats| {
            // Read old entry to get its size
            if (self.vlogs.get(vlog_id)) |vlog| {
                var old_entry = vlog.get(old_offset) catch return;
                defer old_entry.deinit(self.allocator);

                const old_size = old_entry.size();
                if (stats.live_bytes >= old_size) {
                    stats.live_bytes -= old_size;
                    stats.dead_bytes += old_size;
                }
            }
        }
    }

    /// Compact primary index by removing tombstones (deleted entries)
    /// This reclaims space in the B+ tree and improves lookup performance
    pub fn compactPrimaryIndex(self: *Db) !usize {
        var removed_count: usize = 0;
        var keys_to_delete: std.ArrayList(u128) = .empty;
        defer keys_to_delete.deinit(self.allocator);

        // Phase 1: Scan index and identify tombstones
        var iter = try self.primary_index.iterator();
        defer iter.deinit();

        while (try iter.next()) |cell| {
            // Parse key from cell
            if (cell.key.len >= 16) {
                const key = std.mem.readInt(u128, cell.key[0..16], .big);

                // Parse offset from cell value
                if (cell.value.len >= 8) {
                    const offset = std.mem.readInt(u64, cell.value[0..8], .little);

                    // Extract vlog_id from key
                    const metadata = KeyGen.extractMetadata(key);

                    // Check if this points to a tombstone
                    if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                        var vlog_entry = vlog.get(offset) catch continue;
                        defer vlog_entry.deinit(self.allocator);

                        // If value is empty, it's a tombstone
                        if (vlog_entry.value.len == 0) {
                            try keys_to_delete.append(self.allocator, key);
                        }
                    }
                }
            }
        }

        // Phase 2: Delete tombstone entries from index
        for (keys_to_delete.items) |key| {
            try self.primary_index.delete(key);
            removed_count += 1;
        }

        return removed_count;
    }

    /// Select vlog candidates for garbage collection
    /// Returns vlog IDs that exceed the dead ratio threshold
    pub fn selectGcCandidates(self: *Db, dead_ratio_threshold: f64) !std.ArrayList(u16) {
        var candidates: std.ArrayList(u16) = .empty;

        var iter = self.vlog_stats.iterator();
        while (iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;
            const stats = entry.value_ptr.*;

            // Don't GC the current active vlog (tail)
            if (vlog_id == self.tail_vlog_id) continue;

            // Check if this vlog is a GC candidate
            if (stats.isGcCandidate(dead_ratio_threshold)) {
                try candidates.append(self.allocator, vlog_id);
            }
        }

        // Sort by dead ratio (highest first) for prioritization
        std.mem.sort(u16, candidates.items, self, struct {
            fn compare(db: *Db, a: u16, b: u16) bool {
                const stats_a = db.vlog_stats.get(a) orelse return false;
                const stats_b = db.vlog_stats.get(b) orelse return false;
                return stats_a.deadRatio() > stats_b.deadRatio();
            }
        }.compare);

        return candidates;
    }

    /// Garbage collect a vlog file by copying live values to a new file
    /// Returns the number of entries compacted
    pub fn garbageCollectVlog(self: *Db, vlog_id: u16) !usize {
        const old_vlog = self.vlogs.get(vlog_id) orelse return error.VlogNotFound;
        var stats = self.vlog_stats.getPtr(vlog_id) orelse return error.StatsNotFound;

        // Create temp vlog for compacted data
        var buf: [256]u8 = undefined;
        const temp_vlog_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog.tmp", .{ self.config.paths.vlog, vlog_id });
        const temp_vlog = try ValueLog.init(self.allocator, .{
            .file_name = temp_vlog_name,
            .max_file_size = self.config.file_sizes.vlog,
            .block_size = self.config.buffers.vlog,
            .io = self.io,
        });
        defer temp_vlog.deinit() catch {};

        // Track updates for batch index update
        const IndexUpdate = struct { key: u128, new_offset: u64 };
        var index_updates: std.ArrayList(IndexUpdate) = .empty;
        defer index_updates.deinit(self.allocator);

        var live_entries: usize = 0;
        var dead_entries: usize = 0;

        // Phase 1: Scan primary index to find live entries in this vlog
        var iter = try self.primary_index.iterator();
        defer iter.deinit();

        while (try iter.next()) |cell| {
            if (cell.key.len >= 16 and cell.value.len >= 8) {
                const key = std.mem.readInt(u128, cell.key[0..16], .big);
                const old_offset = std.mem.readInt(u64, cell.value[0..8], .little);

                const metadata = KeyGen.extractMetadata(key);

                // Only process entries from the target vlog
                if (metadata.vlog_id != vlog_id) continue;

                // Read entry from old vlog
                var vlog_entry = old_vlog.get(old_offset) catch {
                    dead_entries += 1;
                    continue;
                };
                defer vlog_entry.deinit(self.allocator);

                // Skip tombstones (empty values)
                if (vlog_entry.value.len == 0) {
                    dead_entries += 1;
                    continue;
                }

                // Copy live entry to temp vlog
                const new_offset = try temp_vlog.put(vlog_entry);
                try index_updates.append(self.allocator, .{ .key = key, .new_offset = new_offset });
                live_entries += 1;
            }
        }

        // Flush temp vlog
        try temp_vlog.flush();

        // Phase 2: Batch update primary index with new offsets
        for (index_updates.items) |update| {
            try self.primary_index.insert(update.key, update.new_offset);
        }

        // Phase 3: Swap files atomically
        const old_vlog_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, vlog_id });
        const backup_name = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog.old", .{ self.config.paths.vlog, vlog_id });

        // Close old vlog before file operations
        try old_vlog.deinit();

        // Rename old vlog to backup
        Dir.rename(.cwd(), old_vlog_name, .cwd(), backup_name, self.io) catch |err| {
            return err;
        };

        // Rename temp to actual vlog
        Dir.rename(.cwd(), temp_vlog_name, .cwd(), old_vlog_name, self.io) catch |err| {
            // Try to restore backup
            Dir.rename(.cwd(), backup_name, .cwd(), old_vlog_name, self.io) catch {};
            return err;
        };

        // Delete backup
        Dir.deleteFile(.cwd(), self.io, backup_name) catch {};

        // Reopen the compacted vlog
        const new_vlog = try ValueLog.init(self.allocator, .{
            .file_name = old_vlog_name,
            .max_file_size = self.config.file_sizes.vlog,
            .block_size = self.config.buffers.vlog,
            .io = self.io,
        });
        try self.vlogs.put(vlog_id, new_vlog);

        // Update stats
        stats.total_bytes = new_vlog.offset;
        stats.live_bytes = new_vlog.offset;
        stats.dead_bytes = 0;
        stats.count = live_entries;
        stats.deleted = 0;
        stats.last_gc_ts = milliTimestamp();

        return dead_entries;
    }

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
                    .file_name = vlog_file_name,
                    .max_file_size = self.config.file_sizes.vlog,
                    .block_size = self.config.buffers.vlog,
                    .io = self.io,
                });

                // Add new vlog to HashMap
                try self.vlogs.put(new_vlog_id, new_vlog);

                // Initialize stats for new vlog
                try self.vlog_stats.put(new_vlog_id, VLogStats{
                    .total_bytes = 0,
                    .live_bytes = 0,
                    .dead_bytes = 0,
                    .count = 0,
                    .deleted = 0,
                    .last_gc_ts = 0,
                });

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
                const metadata = KeyGen.extractMetadata(entry.key);

                if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                    // Check if key already exists and mark old value as dead
                    if (try self.primary_index.search(entry.key)) |old_offset| {
                        try self.markValueAsDead(entry.key, old_offset);
                    }

                    if (entry.kind == .delete) {
                        // Handle deletion: remove from indexes
                        // Write tombstone to vlog for consistency
                        self.metrics.vlog_writes.start();
                        const vlog_entry = VlogEntry{
                            .key = entry.key,
                            .value = &[_]u8{}, // Empty value for tombstone
                            .timestamp = entry.timestamp,
                        };
                        const offset = try vlog.put(vlog_entry);
                        self.metrics.vlog_writes.stop();

                        // Update vlog stats
                        try self.updateVlogStats(metadata.vlog_id, vlog_entry.size(), true);

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
                        try self.updateVlogStats(metadata.vlog_id, vlog_entry.size(), false);

                        // Update primary index with actual offset from vlog
                        try self.primary_index.insert(entry.key, offset);

                        // Update secondary indexes
                        try self.updateSecondaryIndexes(entry.key, entry.value);
                    }
                } else {
                    flush_skipped += 1;
                    log.warn("Flush: skipping entry - vlog_id={d} not found in vlogs map", .{metadata.vlog_id});
                }
            }

            log.info("Flush batch: total={d}, skipped={d}, written={d}", .{ flush_total, flush_skipped, flush_total - flush_skipped });
            skl.deinit();
            var vlog_iter = self.vlogs.iterator();
            while (vlog_iter.next()) |vlog| {
                try vlog.value_ptr.*.flush();
            }

            // Flush primary index to disk to ensure durability
            try self.primary_index.flush();
            log.info("Primary index flushed to disk", .{});

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

        // Create composite key range for the field value
        var start_key_buf: [256]u8 = undefined;
        var end_key_buf: [256]u8 = undefined;

        const start_key = try self.makeCompositeKey(&start_key_buf, field_value, 0);
        const end_key = try self.makeCompositeKey(&end_key_buf, field_value, std.math.maxInt(u128));

        // Range scan the secondary index
        var iter = try index.tree.rangeScan(start_key, end_key);
        defer iter.deinit();

        while (try iter.next()) |entry| {
            // Extract primary key from the composite key
            // The primary key is the last 16 bytes of the composite key
            const key_len = entry.key.len;
            if (key_len >= 16) {
                const primary_key = std.mem.readInt(u128, entry.key[key_len - 16 ..][0..16], .little);
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

    // ===== Transaction Methods =====

    /// Begin a new transaction with the specified isolation level
    pub fn beginTransaction(self: *Db, isolation_level: IsolationLevel) !*Transaction {
        return try self.txn_manager.begin(isolation_level);
    }

    /// Put a key-value pair within a transaction (writes to transaction buffer)
    pub fn txnPut(self: *Db, txn: *Transaction, key: u128, value: []const u8) !void {
        _ = self;
        if (txn.state != .active) {
            return error.TransactionNotActive;
        }
        try txn.addWrite(key, value);
    }

    /// Get a value within a transaction (respects snapshot isolation)
    pub fn txnGet(self: *Db, txn: *Transaction, key: u128) ![]const u8 {
        if (txn.state != .active) {
            return error.TransactionNotActive;
        }

        // First check transaction's local write buffer
        if (txn.getLocalWrite(key)) |value| {
            if (value.len == 0) {
                return error.KeyNotFound; // Deleted in this transaction
            }
            return value;
        }

        // Read from database with snapshot isolation
        if (try self.primary_index.search(key)) |offset| {
            const metadata = KeyGen.extractMetadata(key);
            if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                var vlog_entry = try vlog.get(offset);
                defer vlog_entry.deinit(self.allocator);

                // Track read for serializable isolation
                try txn.trackRead(key, txn.id);

                return try self.allocator.dupe(u8, vlog_entry.value);
            }
        }

        return error.KeyNotFound;
    }

    /// Delete a key within a transaction (adds tombstone to transaction buffer)
    pub fn txnDelete(self: *Db, txn: *Transaction, key: u128) !void {
        _ = self;
        if (txn.state != .active) {
            return error.TransactionNotActive;
        }
        try txn.addDelete(key);
    }

    /// Commit a transaction (applies all writes atomically)
    pub fn commitTransaction(self: *Db, txn: *Transaction) !void {
        if (txn.state != .active) {
            return error.TransactionNotActive;
        }

        // Mark as preparing
        txn.state = .preparing;

        // Conflict detection: Check if any keys we're writing have been modified
        // by other committed transactions since we started
        for (txn.writes.items) |write| {
            if (try self.primary_index.search(write.key)) |offset| {
                const metadata = KeyGen.extractMetadata(write.key);
                if (self.vlogs.get(metadata.vlog_id)) |vlog| {
                    var vlog_entry = vlog.get(offset) catch continue;
                    defer vlog_entry.deinit(self.allocator);

                    // Check if value was modified after our snapshot
                    if (vlog_entry.timestamp > txn.snapshot_timestamp) {
                        self.txn_manager.abort(txn);
                        return error.WriteConflict;
                    }
                }
            }
        }

        // Apply all writes to the database
        for (txn.writes.items) |write| {
            if (write.value.len == 0) {
                // Deletion
                try self.del(@bitCast(write.key), write.timestamp);
            } else {
                // Put
                try self.put(@bitCast(write.key), write.value, write.timestamp);
            }
        }

        // Flush to ensure durability
        try self.flush();

        // Commit the transaction
        try self.txn_manager.commit(txn);
    }

    /// Abort a transaction (discards all writes)
    pub fn abortTransaction(self: *Db, txn: *Transaction) void {
        self.txn_manager.abort(txn);
    }

    /// Execute a function within a transaction with automatic commit/rollback
    /// Usage: try db.runInTransaction(.repeatable_read, runMyTransaction, .{&my_context});
    pub fn runInTransaction(
        self: *Db,
        isolation_level: IsolationLevel,
        comptime func: anytype,
        args: anytype,
    ) !void {
        const txn = try self.beginTransaction(isolation_level);
        defer txn.deinit();

        // Call the user function with txn prepended to args
        const full_args = .{ self, txn } ++ args;
        func(full_args) catch |err| {
            self.abortTransaction(txn);
            return err;
        };

        try self.commitTransaction(txn);
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

            if (self.vlog_stats.get(vlog_id)) |stats| {
                total_vlog_size += stats.total_bytes;

                try vlog_metrics_list.append(self.allocator, VlogMetrics{
                    .vlog_id = vlog_id,
                    .total_bytes = stats.total_bytes,
                    .live_bytes = stats.live_bytes,
                    .dead_bytes = stats.dead_bytes,
                    .dead_ratio = stats.deadRatio(),
                    .entry_count = stats.count,
                    .deleted_count = stats.deleted,
                    .last_gc_timestamp = stats.last_gc_ts,
                });
            }
        }

        // Get active transaction count
        const active_txns = self.txn_manager.active_txns.count();

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
                .enabled = self.gc_config.enabled,
                .total_runs = self.gc_metrics.total_runs.load(.monotonic),
                .total_bytes_reclaimed = self.gc_metrics.total_bytes_reclaimed.load(.monotonic),
                .last_run_duration_ms = self.gc_metrics.last_run_duration_ms.load(.monotonic),
                .last_run_timestamp = self.gc_metrics.last_run_timestamp.load(.monotonic),
                .next_run_estimate_ms = 0, // TODO: Calculate based on interval
            },
            .transactions = TxnMetricsSnapshot{
                .active_transactions = @intCast(active_txns),
                .total_committed = self.metrics_collector.total_txn_commits.load(.monotonic),
                .total_aborted = self.metrics_collector.total_txn_aborts.load(.monotonic),
                .total_conflicts = self.metrics_collector.total_txn_conflicts.load(.monotonic),
                .min_active_txn_id = self.txn_manager.getMinActiveTxn(),
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

// NOTE: Db requires full system setup (Config, Io, Index) for testing.
// Full integration tests are located in tests/integration_test.zig.
// Unit tests for helper structs are below.

// ============================================================================
// Unit Tests for Helper Structs
// ============================================================================

test "VLogStats - deadRatio with zero bytes" {
    const stats = VLogStats{
        .total_bytes = 0,
        .live_bytes = 0,
        .dead_bytes = 0,
        .count = 0,
        .deleted = 0,
        .last_gc_ts = 0,
    };

    try std.testing.expectEqual(@as(f64, 0.0), stats.deadRatio());
}

test "VLogStats - deadRatio calculation" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 500,
        .dead_bytes = 500,
        .count = 100,
        .deleted = 50,
        .last_gc_ts = 1234567890,
    };

    try std.testing.expectApproxEqAbs(@as(f64, 0.5), stats.deadRatio(), 0.001);
}

test "VLogStats - deadRatio with all dead" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 0,
        .dead_bytes = 1000,
        .count = 100,
        .deleted = 100,
        .last_gc_ts = 0,
    };

    try std.testing.expectApproxEqAbs(@as(f64, 1.0), stats.deadRatio(), 0.001);
}

test "VLogStats - deadRatio with all live" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 1000,
        .dead_bytes = 0,
        .count = 100,
        .deleted = 0,
        .last_gc_ts = 0,
    };

    try std.testing.expectApproxEqAbs(@as(f64, 0.0), stats.deadRatio(), 0.001);
}

test "VLogStats - isGcCandidate below threshold" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 800,
        .dead_bytes = 200, // 20% dead
        .count = 100,
        .deleted = 20,
        .last_gc_ts = 0,
    };

    try std.testing.expect(!stats.isGcCandidate(0.5)); // 50% threshold
}

test "VLogStats - isGcCandidate above threshold" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 300,
        .dead_bytes = 700, // 70% dead
        .count = 100,
        .deleted = 70,
        .last_gc_ts = 0,
    };

    try std.testing.expect(stats.isGcCandidate(0.5)); // 50% threshold
}

test "VLogStats - isGcCandidate at exactly threshold" {
    const stats = VLogStats{
        .total_bytes = 1000,
        .live_bytes = 500,
        .dead_bytes = 500, // 50% dead
        .count = 100,
        .deleted = 50,
        .last_gc_ts = 0,
    };

    try std.testing.expect(stats.isGcCandidate(0.5)); // Exactly at threshold
}

test "GcConfig - default values" {
    const config = GcConfig{};

    try std.testing.expect(config.enabled);
    try std.testing.expectEqual(@as(u64, 300), config.interval_seconds);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), config.dead_ratio_threshold, 0.001);
    try std.testing.expectEqual(@as(usize, 1), config.max_concurrent);
}

test "GcConfig - custom values" {
    const config = GcConfig{
        .enabled = false,
        .interval_seconds = 600,
        .dead_ratio_threshold = 0.3,
        .max_concurrent = 4,
    };

    try std.testing.expect(!config.enabled);
    try std.testing.expectEqual(@as(u64, 600), config.interval_seconds);
    try std.testing.expectApproxEqAbs(@as(f64, 0.3), config.dead_ratio_threshold, 0.001);
    try std.testing.expectEqual(@as(usize, 4), config.max_concurrent);
}

test "GcMetrics - initial values are zero" {
    const metrics = GcMetrics{};

    try std.testing.expectEqual(@as(u64, 0), metrics.total_runs.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_bytes_reclaimed.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.last_run_duration_ms.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 0), metrics.last_run_timestamp.load(.monotonic));
}

test "GcMetrics - atomic operations" {
    var metrics = GcMetrics{};

    // Test atomic increment
    _ = metrics.total_runs.fetchAdd(1, .release);
    try std.testing.expectEqual(@as(u64, 1), metrics.total_runs.load(.monotonic));

    _ = metrics.total_runs.fetchAdd(1, .release);
    try std.testing.expectEqual(@as(u64, 2), metrics.total_runs.load(.monotonic));

    // Test atomic store
    metrics.total_bytes_reclaimed.store(12345, .release);
    try std.testing.expectEqual(@as(u64, 12345), metrics.total_bytes_reclaimed.load(.monotonic));

    metrics.last_run_timestamp.store(9876543210, .release);
    try std.testing.expectEqual(@as(i64, 9876543210), metrics.last_run_timestamp.load(.monotonic));
}
