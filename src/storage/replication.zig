const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;

/// Replication mode
pub const ReplicationMode = enum {
    standalone, // No replication
    leader, // Primary node that accepts writes
    follower, // Replica node that receives log entries
};

/// Replication log entry type
pub const LogEntryType = enum(u8) {
    put = 1,
    delete = 2,
    batch = 3,
};

/// Replication log entry
pub const LogEntry = struct {
    lsn: u64, // Log Sequence Number
    timestamp: i64,
    entry_type: LogEntryType,
    key: u128,
    value: []const u8, // Empty for deletes
    checksum: u64,

    pub fn size(self: *const LogEntry) usize {
        return 8 + // lsn
            8 + // timestamp
            1 + // entry_type
            16 + // key
            8 + // value length
            self.value.len + // value data
            8; // checksum
    }

    pub fn write(self: *const LogEntry, writer: anytype) !void {
        try writer.writeInt(u64, self.lsn, .little);
        try writer.writeInt(i64, self.timestamp, .little);
        try writer.writeByte(@intFromEnum(self.entry_type));
        try writer.writeInt(u128, self.key, .little);
        try writer.writeInt(u64, @intCast(self.value.len), .little);
        try writer.writeAll(self.value);
        try writer.writeInt(u64, self.checksum, .little);
    }

    pub fn read(allocator: Allocator, reader: anytype) !LogEntry {
        const lsn = try reader.readInt(u64, .little);
        const timestamp = try reader.readInt(i64, .little);
        const entry_type: LogEntryType = @enumFromInt(try reader.readByte());
        const key = try reader.readInt(u128, .little);
        const value_len = try reader.readInt(u64, .little);

        const value = try allocator.alloc(u8, value_len);
        errdefer allocator.free(value);
        _ = try reader.readAll(value);

        const checksum = try reader.readInt(u64, .little);

        return LogEntry{
            .lsn = lsn,
            .timestamp = timestamp,
            .entry_type = entry_type,
            .key = key,
            .value = value,
            .checksum = checksum,
        };
    }

    pub fn deinit(self: *LogEntry, allocator: Allocator) void {
        allocator.free(self.value);
    }

    pub fn calculateChecksum(self: *const LogEntry) u64 {
        // Simple checksum: XOR of all bytes
        var checksum: u64 = self.lsn ^ @as(u64, @bitCast(self.timestamp));
        checksum ^= @intFromEnum(self.entry_type);
        checksum ^= @truncate(self.key);
        checksum ^= @truncate(self.key >> 64);

        for (self.value) |byte| {
            checksum ^= byte;
        }

        return checksum;
    }
};

/// Replication configuration
pub const ReplicationConfig = struct {
    mode: ReplicationMode = .standalone,
    log_dir: []const u8,
    max_log_size: usize = 100 * 1024 * 1024, // 100MB
    sync_interval_ms: u64 = 1000, // 1 second
    follower_addresses: []const []const u8 = &[_][]const u8{}, // List of follower addresses
};

/// Replication metrics
pub const ReplicationMetrics = struct {
    current_lsn: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_synced_lsn: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    follower_lag: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_entries_replicated: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

/// Replication manager
pub const ReplicationManager = struct {
    allocator: Allocator,
    io: Io,
    config: ReplicationConfig,
    metrics: ReplicationMetrics,

    // Replication log file
    log_file: ?File = null,
    current_lsn: u64,

    // Follower tracking
    follower_lsns: std.AutoHashMap([]const u8, u64),

    pub fn init(allocator: Allocator, io: Io, config: ReplicationConfig) !*ReplicationManager {
        const mgr = try allocator.create(ReplicationManager);
        mgr.* = ReplicationManager{
            .allocator = allocator,
            .io = io,
            .config = config,
            .metrics = ReplicationMetrics{},
            .current_lsn = 0,
            .follower_lsns = std.AutoHashMap([]const u8, u64).init(allocator),
        };

        // Create log directory if needed
        Dir.makeDir(.cwd(), io, config.log_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // Open or create replication log
        if (config.mode == .leader) {
            try mgr.openLog();
        }

        return mgr;
    }

    pub fn deinit(self: *ReplicationManager) void {
        if (self.log_file) |file| {
            file.close(self.io);
        }
        self.follower_lsns.deinit();
        self.allocator.destroy(self);
    }

    fn openLog(self: *ReplicationManager) !void {
        var buf: [512]u8 = undefined;
        const log_path = try std.fmt.bufPrint(&buf, "{s}/replication.log", .{self.config.log_dir});

        self.log_file = try Dir.openFile(.cwd(), self.io, log_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try Dir.createFile(.cwd(), self.io, log_path, .{ .read = true, .truncate = false }),
            else => return err,
        };

        // Read current LSN from log
        const stat = try self.log_file.?.stat(self.io);
        if (stat.size > 0) {
            // TODO: Read last LSN from log file
            self.current_lsn = 0; // Placeholder
        }
    }

    /// Append a log entry (leader only)
    pub fn appendLog(self: *ReplicationManager, entry_type: LogEntryType, key: u128, value: []const u8) !u64 {
        if (self.config.mode != .leader) {
            return error.NotLeader;
        }

        self.current_lsn += 1;
        const lsn = self.current_lsn;

        var entry = LogEntry{
            .lsn = lsn,
            .timestamp = milliTimestamp(),
            .entry_type = entry_type,
            .key = key,
            .value = value,
            .checksum = 0,
        };
        entry.checksum = entry.calculateChecksum();

        // Write to log file
        if (self.log_file) |file| {
            var buffer = std.ArrayList(u8).init(self.allocator);
            defer buffer.deinit();

            const writer = buffer.writer();
            try entry.write(writer);

            // TODO: Get current file position for positional write
            try file.writeAll(buffer.items);
        }

        // Update metrics
        self.metrics.current_lsn.store(lsn, .release);
        _ = self.metrics.total_entries_replicated.fetchAdd(1, .monotonic);

        return lsn;
    }

    /// Read log entries from LSN (follower or leader)
    pub fn readLog(self: *ReplicationManager, from_lsn: u64, max_entries: usize) !std.ArrayList(LogEntry) {
        const entries: std.ArrayList(LogEntry) = .empty;

        if (self.log_file) |_| {
            // TODO: Read entries from log file starting at from_lsn
            // For now, return empty list
            _ = from_lsn;
            _ = max_entries;
        }

        return entries;
    }

    /// Apply a log entry (follower only)
    pub fn applyLogEntry(self: *ReplicationManager, entry: LogEntry, db: anytype) !void {
        if (self.config.mode != .follower) {
            return error.NotFollower;
        }

        // Verify checksum
        const expected_checksum = entry.calculateChecksum();
        if (entry.checksum != expected_checksum) {
            return error.ChecksumMismatch;
        }

        // Apply the operation to the database
        switch (entry.entry_type) {
            .put => {
                try db.put(@bitCast(entry.key), entry.value, entry.timestamp);
            },
            .delete => {
                try db.del(@bitCast(entry.key), entry.timestamp);
            },
            .batch => {
                // TODO: Handle batch operations
            },
        }

        // Update metrics
        self.metrics.last_synced_lsn.store(entry.lsn, .release);
    }

    /// Sync logs to followers (leader only)
    pub fn syncToFollowers(self: *ReplicationManager) !void {
        if (self.config.mode != .leader) {
            return;
        }

        for (self.config.follower_addresses) |follower_addr| {
            const last_lsn = self.follower_lsns.get(follower_addr) orelse 0;

            // Read entries since last LSN
            var entries = try self.readLog(last_lsn + 1, 100);
            defer {
                for (entries.items) |*entry| {
                    entry.deinit(self.allocator);
                }
                entries.deinit(self.allocator);
            }

            if (entries.items.len > 0) {
                // TODO: Send entries to follower over network
                // For now, just update tracking
                const last_entry_lsn = entries.items[entries.items.len - 1].lsn;
                try self.follower_lsns.put(try self.allocator.dupe(u8, follower_addr), last_entry_lsn);
            }
        }
    }

    /// Get replication lag for a follower
    pub fn getFollowerLag(self: *ReplicationManager, follower_addr: []const u8) u64 {
        const follower_lsn = self.follower_lsns.get(follower_addr) orelse 0;
        const current_lsn = self.current_lsn;
        return if (current_lsn > follower_lsn) current_lsn - follower_lsn else 0;
    }

    /// Get current replication status
    pub fn getStatus(self: *ReplicationManager) ReplicationStatus {
        return ReplicationStatus{
            .mode = self.config.mode,
            .current_lsn = self.metrics.current_lsn.load(.monotonic),
            .last_synced_lsn = self.metrics.last_synced_lsn.load(.monotonic),
            .total_entries_replicated = self.metrics.total_entries_replicated.load(.monotonic),
            .follower_count = self.config.follower_addresses.len,
        };
    }
};

pub const ReplicationStatus = struct {
    mode: ReplicationMode,
    current_lsn: u64,
    last_synced_lsn: u64,
    total_entries_replicated: u64,
    follower_count: usize,
};

// ============================================================================
// Unit Tests
// ============================================================================

test "ReplicationMode - enum values" {
    const standalone = ReplicationMode.standalone;
    const leader = ReplicationMode.leader;
    const follower = ReplicationMode.follower;

    try std.testing.expect(standalone != leader);
    try std.testing.expect(leader != follower);
    try std.testing.expect(standalone != follower);
}

test "LogEntryType - enum values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(LogEntryType.put));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(LogEntryType.delete));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(LogEntryType.batch));
}

test "LogEntryType - roundtrip" {
    const put: LogEntryType = @enumFromInt(1);
    const delete: LogEntryType = @enumFromInt(2);
    const batch: LogEntryType = @enumFromInt(3);

    try std.testing.expectEqual(LogEntryType.put, put);
    try std.testing.expectEqual(LogEntryType.delete, delete);
    try std.testing.expectEqual(LogEntryType.batch, batch);
}

test "LogEntry - size calculation" {
    const entry = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 12345,
        .value = "test_value",
        .checksum = 0,
    };

    // Size: lsn(8) + timestamp(8) + entry_type(1) + key(16) + value_len(8) + value(10) + checksum(8)
    const expected_size: usize = 8 + 8 + 1 + 16 + 8 + 10 + 8;
    try std.testing.expectEqual(expected_size, entry.size());
}

test "LogEntry - size with empty value" {
    const entry = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .delete,
        .key = 12345,
        .value = "", // Empty for deletes
        .checksum = 0,
    };

    // Size: lsn(8) + timestamp(8) + entry_type(1) + key(16) + value_len(8) + value(0) + checksum(8)
    const expected_size: usize = 8 + 8 + 1 + 16 + 8 + 0 + 8;
    try std.testing.expectEqual(expected_size, entry.size());
}

test "LogEntry - checksum calculation is deterministic" {
    const entry = LogEntry{
        .lsn = 100,
        .timestamp = 1234567890,
        .entry_type = .put,
        .key = 999,
        .value = "hello world",
        .checksum = 0,
    };

    const checksum1 = entry.calculateChecksum();
    const checksum2 = entry.calculateChecksum();

    try std.testing.expectEqual(checksum1, checksum2);
}

test "LogEntry - different data produces different checksum" {
    const entry1 = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 1,
        .value = "value1",
        .checksum = 0,
    };

    const entry2 = LogEntry{
        .lsn = 2,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 1,
        .value = "value1",
        .checksum = 0,
    };

    // Different LSN should produce different checksum
    try std.testing.expect(entry1.calculateChecksum() != entry2.calculateChecksum());
}

test "LogEntry - checksum includes all fields" {
    // Same LSN, different values
    const entry1 = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 1,
        .value = "value1",
        .checksum = 0,
    };

    const entry2 = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 1,
        .value = "value2",
        .checksum = 0,
    };

    // Different value should produce different checksum
    try std.testing.expect(entry1.calculateChecksum() != entry2.calculateChecksum());
}

test "ReplicationConfig - defaults" {
    const config = ReplicationConfig{
        .log_dir = "/data/replication",
    };

    try std.testing.expectEqual(ReplicationMode.standalone, config.mode);
    try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), config.max_log_size);
    try std.testing.expectEqual(@as(u64, 1000), config.sync_interval_ms);
    try std.testing.expectEqual(@as(usize, 0), config.follower_addresses.len);
}

test "ReplicationConfig - leader mode" {
    const config = ReplicationConfig{
        .mode = .leader,
        .log_dir = "/data/replication",
        .max_log_size = 200 * 1024 * 1024,
        .sync_interval_ms = 500,
    };

    try std.testing.expectEqual(ReplicationMode.leader, config.mode);
    try std.testing.expectEqual(@as(usize, 200 * 1024 * 1024), config.max_log_size);
    try std.testing.expectEqual(@as(u64, 500), config.sync_interval_ms);
}

test "ReplicationMetrics - init zeros" {
    const metrics = ReplicationMetrics{};

    try std.testing.expectEqual(@as(u64, 0), metrics.current_lsn.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.last_synced_lsn.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.follower_lag.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), metrics.total_entries_replicated.load(.monotonic));
}

test "ReplicationMetrics - atomic operations" {
    var metrics = ReplicationMetrics{};

    // Test store and load
    metrics.current_lsn.store(100, .release);
    try std.testing.expectEqual(@as(u64, 100), metrics.current_lsn.load(.monotonic));

    // Test fetchAdd
    _ = metrics.total_entries_replicated.fetchAdd(5, .monotonic);
    try std.testing.expectEqual(@as(u64, 5), metrics.total_entries_replicated.load(.monotonic));
}

test "ReplicationStatus - standalone mode" {
    const status = ReplicationStatus{
        .mode = .standalone,
        .current_lsn = 0,
        .last_synced_lsn = 0,
        .total_entries_replicated = 0,
        .follower_count = 0,
    };

    try std.testing.expectEqual(ReplicationMode.standalone, status.mode);
    try std.testing.expectEqual(@as(usize, 0), status.follower_count);
}

test "ReplicationStatus - leader with followers" {
    const status = ReplicationStatus{
        .mode = .leader,
        .current_lsn = 1000,
        .last_synced_lsn = 990,
        .total_entries_replicated = 1000,
        .follower_count = 3,
    };

    try std.testing.expectEqual(ReplicationMode.leader, status.mode);
    try std.testing.expectEqual(@as(u64, 1000), status.current_lsn);
    try std.testing.expectEqual(@as(usize, 3), status.follower_count);
}

test "ReplicationStatus - follower mode" {
    const status = ReplicationStatus{
        .mode = .follower,
        .current_lsn = 0,
        .last_synced_lsn = 950,
        .total_entries_replicated = 950,
        .follower_count = 0,
    };

    try std.testing.expectEqual(ReplicationMode.follower, status.mode);
    try std.testing.expectEqual(@as(u64, 950), status.last_synced_lsn);
}

test "LogEntry - max values" {
    const entry = LogEntry{
        .lsn = std.math.maxInt(u64),
        .timestamp = std.math.maxInt(i64),
        .entry_type = .batch,
        .key = std.math.maxInt(u128),
        .value = "",
        .checksum = std.math.maxInt(u64),
    };

    try std.testing.expectEqual(std.math.maxInt(u64), entry.lsn);
    try std.testing.expectEqual(std.math.maxInt(u128), entry.key);
}

test "LogEntry - deinit frees value" {
    const allocator = std.testing.allocator;

    // Allocate value
    const value = try allocator.dupe(u8, "test_value");

    var entry = LogEntry{
        .lsn = 1,
        .timestamp = 1000,
        .entry_type = .put,
        .key = 1,
        .value = value,
        .checksum = 0,
    };

    // This should not leak memory
    entry.deinit(allocator);
}
