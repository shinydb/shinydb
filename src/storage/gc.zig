const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const ValueLog = @import("vlog.zig").ValueLog;
const Index = @import("bptree.zig").Index;
const Config = @import("../common/config.zig").Config;
const common = @import("../common/common.zig");
const milliTimestamp = common.milliTimestamp;
const VlogEntry = common.VlogEntry;
const LogRecord = common.LogRecord;
const OpKind = common.OpKind;
const KeyGen = @import("../common/keygen.zig").KeyGen;
const WriteAheadLog = @import("../durability/write_ahead_log.zig").WriteAheadLog;

const log = std.log.scoped(.gc);

pub const GcMetrics = struct {
    total_runs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_bytes_reclaimed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_run_duration_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_run_timestamp: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
};

pub const GarbageCollector = struct {
    allocator: Allocator,
    config: *Config,
    metrics: GcMetrics,

    // Dependencies injected from Db
    vlogs: *std.HashMap(u16, *ValueLog, std.hash_map.AutoContext(u16), std.hash_map.default_max_load_percentage),
    primary_index: *Index(u128, u64),
    secondary_indexes: *std.StringHashMap(*Index([]const u8, void)),
    tail_vlog_id: *u16, // pointer to db's tail_vlog_id
    wal: *WriteAheadLog, // For post-GC consistency
    io: Io,

    pub fn init(allocator: Allocator, config: *Config, vlogs: *std.HashMap(u16, *ValueLog, std.hash_map.AutoContext(u16), std.hash_map.default_max_load_percentage), primary_index: *Index(u128, u64), secondary_indexes: *std.StringHashMap(*Index([]const u8, void)), tail_vlog_id: *u16, wal: *WriteAheadLog, io: Io) !*GarbageCollector {
        const gc = try allocator.create(GarbageCollector);
        gc.* = GarbageCollector{
            .allocator = allocator,
            .config = config,
            .metrics = GcMetrics{},
            .vlogs = vlogs,
            .primary_index = primary_index,
            .secondary_indexes = secondary_indexes,
            .tail_vlog_id = tail_vlog_id,
            .wal = wal,
            .io = io,
        };
        return gc;
    }

    pub fn deinit(self: *GarbageCollector) void {
        self.allocator.destroy(self);
    }

    /// Shadow GC - creates clean copies of all files during downtime
    /// Returns number of bytes reclaimed
    pub fn runShadowGc(self: *GarbageCollector) !u64 {
        log.info("Starting Shadow GC cycle...", .{});
        const start_time = milliTimestamp();
        var bytes_reclaimed: u64 = 0;

        // Phase 1: Build shadow files (no service interruption)
        try self.buildShadowFiles(&bytes_reclaimed);

        // Phase 2: Atomic switchover (brief downtime)
        try self.atomicSwitchover();

        // Phase 3: Replay WAL for operations that occurred during GC
        try self.replayPostGcOperations(start_time);

        // Phase 4: Cleanup old files (no service interruption)
        self.cleanupOldFiles() catch |err| {
            log.warn("GC cleanup failed: {}", .{err});
        };

        // Update metrics
        const duration = milliTimestamp() - start_time;
        _ = self.metrics.total_runs.fetchAdd(1, .release);
        _ = self.metrics.total_bytes_reclaimed.fetchAdd(bytes_reclaimed, .release);
        self.metrics.last_run_duration_ms.store(@intCast(duration), .release);
        self.metrics.last_run_timestamp.store(start_time, .release);

        log.info("Shadow GC completed: {} bytes reclaimed in {}ms", .{ bytes_reclaimed, duration });
        return bytes_reclaimed;
    }

    /// Build shadow files with "gc_" prefix containing only live data
    fn buildShadowFiles(self: *GarbageCollector, bytes_reclaimed: *u64) !void {
        log.info("Building shadow files...", .{});

        // Select GC candidates
        var candidates = try self.selectCandidates(self.config.gc_config.dead_ratio_threshold);
        defer candidates.deinit(self.allocator);

        if (candidates.items.len == 0) {
            log.info("No GC candidates found", .{});
            return;
        }

        log.info("Found {} vlog candidates for GC", .{candidates.items.len});

        // Build shadow vlogs for candidates
        for (candidates.items) |vlog_id| {
            const dead_bytes_before = if (self.vlogs.get(vlog_id)) |vlog| vlog.header.dead_bytes else 0;
            try self.buildShadowVlog(vlog_id);
            bytes_reclaimed.* += dead_bytes_before;
        }

        // Build shadow primary index
        try self.buildShadowPrimaryIndex();

        // Build shadow secondary indexes
        try self.buildShadowSecondaryIndexes();
    }
    /// Returns vlog IDs that exceed the dead ratio threshold
    pub fn selectCandidates(self: *GarbageCollector, dead_ratio_threshold: f64) !std.ArrayList(u16) {
        var candidates: std.ArrayList(u16) = .empty;

        var iter = self.vlogs.iterator();
        while (iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;
            const vlog = entry.value_ptr.*;

            // Don't GC the current active vlog (tail)
            if (vlog_id == self.tail_vlog_id.*) continue;

            // Check if this vlog is a GC candidate
            if (vlog.header.isGcCandidate(dead_ratio_threshold)) {
                try candidates.append(self.allocator, vlog_id);
            }
        }

        // Sort by dead ratio (highest first) for prioritization
        std.mem.sort(u16, candidates.items, self, struct {
            fn compare(gc: *GarbageCollector, a: u16, b: u16) bool {
                const vlog_a = gc.vlogs.get(a) orelse return false;
                const vlog_b = gc.vlogs.get(b) orelse return false;
                return vlog_a.header.deadRatio() > vlog_b.header.deadRatio();
            }
        }.compare);

        return candidates;
    }

    /// Garbage collect a vlog file by copying live values to a new file
    /// Returns the number of entries compacted
    pub fn collectVlog(self: *GarbageCollector, vlog_id: u16) !usize {
        const old_vlog = self.vlogs.get(vlog_id) orelse return error.VlogNotFound;

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

                // Skip tombstones (deleted entries)
                if (vlog_entry.tombstone) {
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

        // Update header stats
        new_vlog.header.total_bytes = new_vlog.offset;
        new_vlog.header.live_bytes = new_vlog.offset;
        new_vlog.header.dead_bytes = 0;
        new_vlog.header.count = live_entries;
        new_vlog.header.deleted = 0;
        new_vlog.header.last_gc_ts = milliTimestamp();

        return dead_entries;
    }

    /// Compact primary index by removing tombstones (deleted entries)
    /// This reclaims space in the B+ tree and improves lookup performance
    pub fn compactIndex(self: *GarbageCollector) !usize {
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

                        // Check if this is a tombstone (deleted entry)
                        if (vlog_entry.tombstone) {
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

    /// Mark a value as dead in the vlog header statistics
    pub fn markValueAsDead(self: *GarbageCollector, vlog: *ValueLog, old_offset: u64) !void {
        // Read old entry to get its size
        var old_entry = vlog.get(old_offset) catch return;
        defer old_entry.deinit(self.allocator);

        const old_size = old_entry.size();
        if (vlog.header.live_bytes >= old_size) {
            vlog.header.live_bytes -= old_size;
            vlog.header.dead_bytes += old_size;
        }
    }

    /// Get current GC metrics
    pub fn getMetrics(self: *const GarbageCollector) GcMetrics {
        return self.metrics;
    }

    /// Build a shadow vlog file containing only live entries
    fn buildShadowVlog(self: *GarbageCollector, vlog_id: u16) !void {
        const old_vlog = self.vlogs.get(vlog_id) orelse return error.VlogNotFound;

        var buf: [256]u8 = undefined;
        const shadow_vlog_name = try std.fmt.bufPrint(&buf, "{s}/gc_{d}.vlog", .{ self.config.paths.vlog, vlog_id });
        const shadow_vlog = try ValueLog.init(self.allocator, .{
            .file_name = shadow_vlog_name,
            .max_file_size = self.config.file_sizes.vlog,
            .block_size = self.config.buffers.vlog,
            .io = self.io,
        });
        defer shadow_vlog.deinit() catch {};

        var live_entries: usize = 0;

        // Scan primary index to find live entries in this vlog
        var iter = try self.primary_index.iterator();
        defer iter.deinit();

        while (try iter.next()) |cell| {
            if (cell.key.len >= 16 and cell.value.len >= 8) {
                const key = std.mem.readInt(u128, cell.key[0..16], .big);
                const old_offset = std.mem.readInt(u64, cell.value[0..8], .little);

                const metadata = KeyGen.extractMetadata(key);
                if (metadata.vlog_id != vlog_id) continue;

                // Read entry from old vlog
                var vlog_entry = old_vlog.get(old_offset) catch continue;
                defer vlog_entry.deinit(self.allocator);

                // Skip tombstones (deleted entries)
                if (vlog_entry.tombstone) continue;

                // Copy live entry to shadow vlog
                _ = try shadow_vlog.put(vlog_entry);
                live_entries += 1;
            }
        }

        // Update shadow vlog header
        try shadow_vlog.flush();
        shadow_vlog.header.total_bytes = shadow_vlog.offset;
        shadow_vlog.header.live_bytes = shadow_vlog.offset;
        shadow_vlog.header.dead_bytes = 0;
        shadow_vlog.header.count = live_entries;
        shadow_vlog.header.deleted = 0;
        shadow_vlog.header.last_gc_ts = milliTimestamp();
        try shadow_vlog.syncHeader();

        log.info("Built shadow vlog {d}: {} live entries", .{ vlog_id, live_entries });
    }

    /// Build shadow primary index with updated offsets and no tombstones
    fn buildShadowPrimaryIndex(self: *GarbageCollector) !void {
        log.info("Building shadow primary index...", .{});

        var buf: [256]u8 = undefined;
        const shadow_index_name = try std.fmt.bufPrint(&buf, "{s}/gc_primary", .{self.config.paths.index});
        var shadow_index = try Index(u128, u64).init(self.allocator, .{
            .dir_path = self.config.paths.index,
            .file_name = shadow_index_name,
            .pool_size = self.config.index.primary.pool_size,
            .io = self.io,
        });
        defer shadow_index.deinit();

        var live_entries: usize = 0;

        // Track new offsets for live entries
        var offset_map = std.AutoHashMap(u128, u64).init(self.allocator);
        defer offset_map.deinit();

        // Calculate new offsets in shadow vlogs
        try self.buildOffsetMap(&offset_map);

        // Scan original index and rebuild with new offsets, excluding tombstones
        var iter = try self.primary_index.iterator();
        defer iter.deinit();

        while (try iter.next()) |cell| {
            if (cell.key.len >= 16) {
                const key = std.mem.readInt(u128, cell.key[0..16], .big);

                // Check if this entry is live in shadow vlogs
                if (offset_map.get(key)) |new_offset| {
                    try shadow_index.insert(key, new_offset);
                    live_entries += 1;
                }
            }
        }

        try shadow_index.flush();
        log.info("Built shadow primary index: {} live entries", .{live_entries});
    }

    /// Build offset map for new locations in shadow vlogs
    fn buildOffsetMap(self: *GarbageCollector, offset_map: *std.AutoHashMap(u128, u64)) !void {
        // Scan shadow vlogs to build mapping of key -> new_offset
        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;

            var buf: [256]u8 = undefined;
            const shadow_vlog_name = try std.fmt.bufPrint(&buf, "{s}/gc_{d}.vlog", .{ self.config.paths.vlog, vlog_id });

            // Check if shadow vlog exists
            const shadow_vlog = ValueLog.init(self.allocator, .{
                .file_name = shadow_vlog_name,
                .max_file_size = self.config.file_sizes.vlog,
                .block_size = self.config.buffers.vlog,
                .io = self.io,
            }) catch continue;
            defer shadow_vlog.deinit() catch {};

            var offset: u64 = shadow_vlog.header_size;

            // Read all entries from shadow vlog to build offset map
            while (offset < shadow_vlog.offset) {
                var vlog_entry = shadow_vlog.get(offset) catch break;
                defer vlog_entry.deinit(self.allocator);

                try offset_map.put(vlog_entry.key, offset);
                offset += vlog_entry.size();
            }
        }
    }

    /// Build shadow secondary indexes with cleaned entries
    fn buildShadowSecondaryIndexes(self: *GarbageCollector) !void {
        log.info("Building shadow secondary indexes...", .{});

        var sec_iter = self.secondary_indexes.iterator();
        while (sec_iter.next()) |entry| {
            const index_ns = entry.key_ptr.*;
            const original_index = entry.value_ptr.*;

            var buf: [256]u8 = undefined;
            const shadow_index_name = try std.fmt.bufPrint(&buf, "{s}/gc_{s}", .{ self.config.paths.index, index_ns });
            var shadow_index = try Index([]const u8, void).init(self.allocator, .{
                .dir_path = self.config.paths.index,
                .file_name = shadow_index_name,
                .pool_size = self.config.index.primary.pool_size,
                .io = self.io,
            });
            defer shadow_index.deinit();

            var live_entries: usize = 0;

            // Rebuild secondary index with only live entries
            var iter = try original_index.iterator();
            defer iter.deinit();

            while (try iter.next()) |cell| {
                // Extract primary key from composite key (last 16 bytes)
                if (cell.key.len >= 16) {
                    const primary_key = std.mem.readInt(u128, cell.key[cell.key.len - 16 ..][0..16], .big);

                    // Check if this primary key still exists in shadow primary index
                    // If yes, keep this secondary index entry
                    if (self.keyExistsInShadowPrimary(primary_key)) {
                        try shadow_index.insert(cell.key, {});
                        live_entries += 1;
                    }
                }
            }

            try shadow_index.flush();
            log.info("Built shadow secondary index '{}': {} live entries", .{ index_ns, live_entries });
        }
    }

    /// Check if a key exists in shadow primary index
    fn keyExistsInShadowPrimary(self: *GarbageCollector, key: u128) bool {
        var buf: [256]u8 = undefined;
        const shadow_index_name = std.fmt.bufPrint(&buf, "{s}/gc_primary", .{self.config.paths.index}) catch return false;

        var shadow_index = Index(u128, u64).init(self.allocator, .{
            .dir_path = self.config.paths.index,
            .file_name = shadow_index_name,
            .pool_size = self.config.index.primary.pool_size,
            .io = self.io,
        }) catch return false;
        defer shadow_index.deinit();

        return shadow_index.search(key) != null;
    }

    /// Atomically switch from original files to shadow files
    fn atomicSwitchover(self: *GarbageCollector) !void {
        log.info("Starting atomic switchover...", .{});

        // Rename vlogs atomically
        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;

            var buf: [256]u8 = undefined;
            const original_vlog = try std.fmt.bufPrint(&buf, "{s}/{d}.vlog", .{ self.config.paths.vlog, vlog_id });
            const shadow_vlog = try std.fmt.bufPrint(&buf, "{s}/gc_{d}.vlog", .{ self.config.paths.vlog, vlog_id });
            const old_vlog = try std.fmt.bufPrint(&buf, "{s}/old_{d}.vlog", .{ self.config.paths.vlog, vlog_id });

            // Check if shadow file exists
            _ = std.fs.cwd().access(shadow_vlog, .{}) catch continue;

            // Rename original to old
            try Dir.rename(.cwd(), original_vlog, .cwd(), old_vlog, self.io);

            // Rename shadow to original
            Dir.rename(.cwd(), shadow_vlog, .cwd(), original_vlog, self.io) catch |err| {
                // Rollback: restore original
                Dir.rename(.cwd(), old_vlog, .cwd(), original_vlog, self.io) catch {};
                return err;
            };
        }

        // Rename primary index
        try self.switchoverIndex("primary");

        // Rename secondary indexes
        var sec_iter = self.secondary_indexes.iterator();
        while (sec_iter.next()) |entry| {
            const index_ns = entry.key_ptr.*;
            self.switchoverIndex(index_ns) catch |err| {
                log.warn("Failed to switchover secondary index '{}': {}", .{ index_ns, err });
            };
        }

        log.info("Atomic switchover completed", .{});
    }

    /// Switch a single index file atomically
    fn switchoverIndex(self: *GarbageCollector, index_name: []const u8) !void {
        var buf: [512]u8 = undefined;
        const original_index = try std.fmt.bufPrint(&buf[0..256], "{s}/{s}", .{ self.config.paths.index, index_name });
        const shadow_index = try std.fmt.bufPrint(&buf[256..512], "{s}/gc_{s}", .{ self.config.paths.index, index_name });
        var old_buf: [256]u8 = undefined;
        const old_index = try std.fmt.bufPrint(&old_buf, "{s}/old_{s}", .{ self.config.paths.index, index_name });

        // Check if shadow file exists
        _ = std.fs.cwd().access(shadow_index, .{}) catch return;

        // Rename original to old
        try Dir.rename(.cwd(), original_index, .cwd(), old_index, self.io);

        // Rename shadow to original
        Dir.rename(.cwd(), shadow_index, .cwd(), original_index, self.io) catch |err| {
            // Rollback: restore original
            Dir.rename(.cwd(), old_index, .cwd(), original_index, self.io) catch {};
            return err;
        };
    }

    /// Clean up old files after successful switchover
    fn cleanupOldFiles(self: *GarbageCollector) !void {
        log.info("Cleaning up old files...", .{});

        // Delete old vlogs
        var vlog_iter = self.vlogs.iterator();
        while (vlog_iter.next()) |entry| {
            const vlog_id = entry.key_ptr.*;

            var buf: [256]u8 = undefined;
            const old_vlog = try std.fmt.bufPrint(&buf, "{s}/old_{d}.vlog", .{ self.config.paths.vlog, vlog_id });

            Dir.deleteFile(.cwd(), self.io, old_vlog) catch |err| {
                if (err != error.FileNotFound) {
                    log.warn("Failed to delete old vlog {}: {}", .{ vlog_id, err });
                }
            };
        }

        // Delete old primary index
        self.cleanupOldIndex("primary") catch |err| {
            log.warn("Failed to cleanup old primary index: {}", .{err});
        };

        // Delete old secondary indexes
        var sec_iter = self.secondary_indexes.iterator();
        while (sec_iter.next()) |entry| {
            const index_ns = entry.key_ptr.*;
            self.cleanupOldIndex(index_ns) catch |err| {
                log.warn("Failed to cleanup old secondary index '{}': {}", .{ index_ns, err });
            };
        }

        log.info("Old files cleanup completed", .{});
    }

    /// Clean up a single old index file
    fn cleanupOldIndex(self: *GarbageCollector, index_name: []const u8) !void {
        var buf: [256]u8 = undefined;
        const old_index = try std.fmt.bufPrint(&buf, "{s}/old_{s}", .{ self.config.paths.index, index_name });

        Dir.deleteFile(.cwd(), self.io, old_index) catch |err| {
            if (err != error.FileNotFound) {
                return err;
            }
        };
    }

    /// Replay WAL operations that occurred during GC to maintain consistency
    fn replayPostGcOperations(self: *GarbageCollector, gc_start_time: i64) !void {
        log.info("Replaying WAL operations from GC start time: {}", .{gc_start_time});

        // Get all WAL records since the checkpoint
        const replay_result = try self.wal.replay();
        defer {
            replay_result.arena.deinit();
            std.heap.page_allocator.destroy(replay_result.arena);
        }

        var replayed_count: usize = 0;

        // Filter and replay operations that occurred during GC phase
        for (replay_result.records) |record| {
            // Only replay operations that happened after GC start
            if (record.timestamp >= gc_start_time) {
                try self.replayOperation(record);
                replayed_count += 1;
            }
        }

        log.info("Replayed {} operations from GC phase", .{replayed_count});
    }

    /// Replay a single WAL operation to the current (post-switchover) files
    fn replayOperation(self: *GarbageCollector, record: LogRecord) !void {
        switch (record.kind) {
            .write => {
                // Apply write operation to current vlogs and indexes

                // Get current tail vlog
                var current_vlog = self.vlogs.get(self.tail_vlog_id.*) orelse {
                    log.warn("Tail vlog {} not found during WAL replay", .{self.tail_vlog_id.*});
                    return;
                };

                // Create and write vlog entry
                var vlog_entry = VlogEntry{
                    .key = record.key,
                    .value = try self.allocator.dupe(u8, record.value),
                    .ns = try self.allocator.dupe(u8, record.ns),
                    .tombstone = false,
                    .timestamp = record.timestamp,
                };
                defer {
                    self.allocator.free(vlog_entry.value);
                    self.allocator.free(vlog_entry.ns);
                }

                // Put entry in vlog
                const offset = try current_vlog.put(vlog_entry);

                // Update primary index
                try self.primary_index.insert(record.key, offset);

                // Update secondary indexes for this namespace
                if (self.secondary_indexes.get(record.ns)) |secondary_index| {
                    // Create composite key: {secondary_key}{primary_key}
                    var composite_key = std.ArrayList(u8).init(self.allocator);
                    defer composite_key.deinit();

                    try composite_key.appendSlice(record.value);
                    var primary_key_bytes: [16]u8 = undefined;
                    std.mem.writeInt(u128, &primary_key_bytes, record.key, .big);
                    try composite_key.appendSlice(&primary_key_bytes);

                    try secondary_index.insert(composite_key.items, {});
                }
            },
            .delete => {
                // Apply delete operation: mark as tombstone

                // Create tombstone entry
                var vlog_entry = VlogEntry{
                    .key = record.key,
                    .value = try self.allocator.dupe(u8, ""),
                    .ns = try self.allocator.dupe(u8, record.ns),
                    .tombstone = true,
                    .timestamp = record.timestamp,
                };
                defer {
                    self.allocator.free(vlog_entry.value);
                    self.allocator.free(vlog_entry.ns);
                }

                // Get current tail vlog
                var current_vlog = self.vlogs.get(self.tail_vlog_id.*) orelse {
                    log.warn("Tail vlog {} not found during WAL replay", .{self.tail_vlog_id.*});
                    return;
                };

                // Put tombstone in vlog
                _ = try current_vlog.put(vlog_entry);

                // Remove from primary index
                try self.primary_index.delete(record.key);

                // Remove from secondary indexes
                if (self.secondary_indexes.get(record.ns)) |_| {
                    // We need to find and remove the composite key
                    // This is more complex as we need to search by primary key suffix
                    // For now, we'll log and skip secondary index cleanup during WAL replay
                    // This could be improved with reverse index lookups
                    log.warn("Secondary index cleanup during WAL replay not fully implemented for namespace: {s}", .{record.ns});
                }
            },
            .read => {
                // Read operations don't need replay
            },
        }
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

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
