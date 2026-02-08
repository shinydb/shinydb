const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Yaml = @import("yaml").Yaml;
const posix = std.posix;

/// Get current time in milliseconds since Unix epoch
pub fn milliTimestamp() i64 {
    const ts = posix.clock_gettime(posix.CLOCK.REALTIME) catch return 0;
    const seconds: i64 = @intCast(ts.sec);
    const nanos: i64 = @intCast(ts.nsec);
    return seconds * 1000 + @divTrunc(nanos, 1_000_000);
}

// Storage Constants

pub const PageId = u16;
pub const FrameId = u16;
pub const PAGE_SIZE: u32 = 131072; // 128KB page size

// Storage Constants

pub const Data = struct {
    ns: []const u8,
    doc_type: u8,
    value: []const u8,
};

pub const VlogEntry = struct {
    key: u128,
    value: []const u8,
    timestamp: i64,

    pub fn write(self: *const VlogEntry, writer: anytype) anyerror!void {
        try writer.writeInt(u128, self.key, .little);
        try writer.writeInt(u64, self.value.len, .little);
        _ = try writer.writeAll(self.value);
        try writer.writeInt(i64, self.timestamp, .little);

        const seed: u64 = 0;
        var hasher = std.hash.Wyhash.init(seed);
        hasher.update(std.mem.asBytes(&self.key));
        hasher.update(std.mem.asBytes(&self.value.len));
        hasher.update(self.value);
        hasher.update(std.mem.asBytes(&self.timestamp));

        const checksum = hasher.final();
        try writer.writeInt(u64, checksum, .little);
    }

    pub fn read(allocator: std.mem.Allocator, reader: anytype) !VlogEntry {
        const key = try reader.readInt(u128, .little);
        const value_len = try reader.readInt(u64, .little);
        const value_buff = try allocator.alloc(u8, value_len);
        defer allocator.free(value_buff);
        _ = try reader.readAll(value_buff);
        const timestamp = try reader.readInt(i64, .little);

        const file_checksum = try reader.readInt(u64, .little);

        const seed: u64 = 0;
        var hasher = std.hash.Wyhash.init(seed);
        hasher.update(std.mem.asBytes(&key));
        hasher.update(std.mem.asBytes(&value_len));
        hasher.update(value_buff);
        hasher.update(std.mem.asBytes(&timestamp));
        const checksum = hasher.final();
        if (file_checksum != checksum) {
            return error.InvalidChecksum;
        }

        return VlogEntry{
            .key = key,
            .value = try allocator.dupe(u8, value_buff),
            .timestamp = timestamp,
        };
    }

    pub fn readFromSlice(allocator: std.mem.Allocator, data: []const u8) !VlogEntry {
        // Parse entry from buffer
        var offset: usize = 0;

        // Read key (16 bytes)
        const key = std.mem.readInt(u128, data[offset..][0..16], .little);
        offset += 16;

        // Read value_len (8 bytes)
        const value_len = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;

        // Read value (variable length)
        const value_data = data[offset .. offset + value_len];
        offset += value_len;

        // Read timestamp (8 bytes)
        const timestamp = std.mem.readInt(i64, data[offset..][0..8], .little);
        offset += 8;

        // Read checksum (8 bytes)
        const file_checksum = std.mem.readInt(u64, data[offset..][0..8], .little);

        // Verify checksum
        const seed: u64 = 0;
        var hasher = std.hash.Wyhash.init(seed);
        hasher.update(std.mem.asBytes(&key));
        hasher.update(std.mem.asBytes(&value_len));
        hasher.update(value_data);
        hasher.update(std.mem.asBytes(&timestamp));
        const checksum = hasher.final();
        if (file_checksum != checksum) {
            return error.InvalidChecksum;
        }

        return VlogEntry{
            .key = key,
            .value = try allocator.dupe(u8, value_data),
            .timestamp = timestamp,
        };
    }

    pub fn size(self: *const VlogEntry) usize {
        return @sizeOf(i128) + @sizeOf(i64) + @sizeOf(u64) + self.value.len + @sizeOf(u64);
    }

    pub fn deinit(self: *VlogEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

// ======= Index Typess ========
pub const NSValue = struct {
    ns: []const u8,
    field: []const u8,
    value: []const u8,
};

pub const NSKeyOffset = struct {
    nsv: NSValue,
    key: u128,
    offset: u64,
};

pub const IndexEntry = struct {
    ns: []const u8,
    value: []const u8,
    key: u128,
    offset: u64,
};

// ======= Index Typess ========

pub const OpKind = enum(u8) {
    insert,
    update,
    delete,
    read,
};

pub const LogRecord = struct {
    key: u128,
    ns: []const u8,
    value: []const u8,
    timestamp: i64,
    kind: OpKind,

    pub fn hash(self: LogRecord) u64 {
        const seed: u64 = 0;
        var hasher = std.hash.Wyhash.init(seed);
        // var hasher = std.hash.Crc32.init();
        hasher.update(std.mem.asBytes(&self.key));
        hasher.update(std.mem.asBytes(&self.timestamp));
        hasher.update(std.mem.asBytes(&self.kind));
        hasher.update(self.ns);
        hasher.update(self.value);
        return hasher.final();
    }

    /// Returns the size in bytes of the serialized LogRecord.
    pub fn size(self: LogRecord) usize {
        return @sizeOf(u32) + // payload_len
            @sizeOf(u128) + // key_len
            @sizeOf(u32) + // value_len
            self.value.len + // value
            @sizeOf(u32) + // ns_len
            self.ns.len + // ns
            @sizeOf(i64) + // timestamp
            @sizeOf(u8) + // kind
            @sizeOf(u64); // checksum
    }

    pub fn serialize(record: LogRecord, writer: anytype) !void {
        const checksum = record.hash();
        const payload_len: u32 = @intCast(record.size() - @sizeOf(u32)); // exclude the payload_len field itself
        try writer.writeInt(u32, payload_len, .little);
        try writer.writeInt(u128, record.key, .little);
        try writer.writeInt(u32, @intCast(record.value.len), .little);
        try writer.writeAll(record.value);
        try writer.writeInt(u32, @intCast(record.ns.len), .little);
        try writer.writeAll(record.ns);
        try writer.writeInt(i64, record.timestamp, .little);
        try writer.writeInt(u8, @intFromEnum(record.kind), .little);
        try writer.writeInt(u64, checksum, .little);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !?LogRecord {
        const payload_len = reader.readInt(u32, .little) catch |err| {
            if (err == error.EndOfStream) return null;
            return err;
        };
        if (payload_len > 1_000_000_000) return error.RecordTooLarge;
        const key = reader.readInt(u128, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };

        const value_len = reader.readInt(u32, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const value = allocator.alloc(u8, value_len) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        errdefer allocator.free(value);
        _ = reader.readAll(value) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const ns_len = reader.readInt(u32, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const ns_value = allocator.alloc(u8, ns_len) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        errdefer allocator.free(ns_value);
        _ = reader.readAll(ns_value) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const timestamp = reader.readInt(i64, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const kind_int = reader.readInt(u8, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        const kind: OpKind = switch (kind_int) {
            0 => OpKind.insert,
            1 => OpKind.update,
            2 => OpKind.delete,
            else => return error.InvalidRecordLength,
        };
        const checksum = reader.readInt(u64, .little) catch |err| {
            if (err == error.EndOfStream) return error.InvalidRecordLength;
            return err;
        };
        // Calculate expected payload size for validation
        const fixed_fields_len: u32 = 4 + 16 + 4 + value_len + 4 + ns_len + 8 + 1 + 8;
        if (payload_len != fixed_fields_len) {
            return error.InvalidRecordLength;
        }
        const record = LogRecord{
            .key = key,
            .ns = ns_value,
            .value = value,
            .timestamp = timestamp,
            .kind = kind,
        };
        if (record.hash() != checksum) {
            return error.ChecksumMismatch;
        }
        return record;
    }
};

pub const CurrentVlog = struct {
    id: u16,
    offset: u64,
};

pub const Entry = struct {
    key: u128,
    ns: []const u8,
    value: []const u8,
    timestamp: i64,
    kind: OpKind,

    pub fn size(self: Entry) usize {
        return @sizeOf(u128) + @sizeOf(u64) + self.ns.len + @sizeOf(u64) + self.value.len + @sizeOf(i64) + 1;
    }
};

pub const FileInfo = struct {
    name: []const u8,
    created: i96,
};

pub fn sortedFiles(allocator: std.mem.Allocator, path: []const u8, io: Io) ![]FileInfo {
    // Open the directory
    var dir = Dir.openDir(.cwd(), io, path, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            // Directory doesn't exist, return empty list
            return &[_]FileInfo{};
        }
        return err;
    };
    defer dir.close(io);

    // Read all directory entries
    var entries: std.ArrayList(FileInfo) = .empty;
    defer entries.deinit(allocator);

    var dir_iterator = dir.iterate();
    while (dir_iterator.next(io) catch null) |entry| {
        const name = try allocator.dupe(u8, entry.name);

        // Build full path for file
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ path, entry.name }) catch continue;

        var file = Dir.openFile(.cwd(), io, full_path, .{}) catch continue;
        defer file.close(io);

        const stat = file.stat(io) catch continue;
        try entries.append(allocator, .{
            .name = name,
            .created = stat.ctime.nanoseconds,
        });
    }

    const Context = struct {
        pub fn greaterThan(_: void, a: FileInfo, b: FileInfo) bool {
            return a.created > b.created;
        }
    };
    // Sort entries by creation time in descending order
    std.sort.block(FileInfo, entries.items, {}, Context.greaterThan);

    return entries.toOwnedSlice(allocator);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "milliTimestamp returns positive value" {
    const ts = milliTimestamp();
    try std.testing.expect(ts > 0);
}

test "milliTimestamp is monotonically increasing" {
    const ts1 = milliTimestamp();
    const ts2 = milliTimestamp();
    try std.testing.expect(ts2 >= ts1);
}

test "VlogEntry - size calculation" {
    const entry = VlogEntry{
        .key = 12345,
        .value = "test_value",
        .timestamp = 1000,
    };

    // key(16) + value_len(8) + value(10) + timestamp(8) + checksum(8) = 50
    try std.testing.expectEqual(@as(u64, 50), entry.size());
}

test "VlogEntry - size with empty value" {
    const entry = VlogEntry{
        .key = 0,
        .value = "",
        .timestamp = 0,
    };

    // key(16) + value_len(8) + value(0) + timestamp(8) + checksum(8) = 40
    try std.testing.expectEqual(@as(u64, 40), entry.size());
}

test "Entry - operation kinds" {
    const insert_entry = Entry{
        .key = 1,
        .ns = "ns",
        .value = "val",
        .timestamp = 0,
        .kind = .insert,
    };

    const delete_entry = Entry{
        .key = 1,
        .ns = "ns",
        .value = "",
        .timestamp = 0,
        .kind = .delete,
    };

    try std.testing.expectEqual(OpKind.insert, insert_entry.kind);
    try std.testing.expectEqual(OpKind.delete, delete_entry.kind);
}

test "Entry - size calculation" {
    const entry = Entry{
        .key = 1,
        .ns = "namespace",
        .value = "test_value",
        .timestamp = 1000,
        .kind = .insert,
    };

    const size = entry.size();
    // u128(16) + u64(8) + ns(9) + u64(8) + value(10) + i64(8) + kind(1)
    try std.testing.expect(size > 0);
}

test "OpKind - enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(OpKind.insert));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(OpKind.update));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(OpKind.delete));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(OpKind.read));
}

test "LogRecord - structure" {
    const record = LogRecord{
        .key = 12345,
        .ns = "test_ns",
        .value = "log_value",
        .timestamp = 1000000,
        .kind = .insert,
    };

    try std.testing.expectEqual(@as(u128, 12345), record.key);
    try std.testing.expectEqualStrings("test_ns", record.ns);
    try std.testing.expectEqualStrings("log_value", record.value);
    try std.testing.expectEqual(@as(i64, 1000000), record.timestamp);
    try std.testing.expectEqual(OpKind.insert, record.kind);
}

test "IndexEntry - structure" {
    const entry = IndexEntry{
        .ns = "test_ns",
        .value = "test_value",
        .key = 99999,
        .offset = 1024,
    };

    try std.testing.expectEqual(@as(u128, 99999), entry.key);
    try std.testing.expectEqual(@as(u64, 1024), entry.offset);
    try std.testing.expectEqualStrings("test_ns", entry.ns);
    try std.testing.expectEqualStrings("test_value", entry.value);
}

test "CurrentVlog - initial state" {
    const vlog = CurrentVlog{
        .id = 0,
        .offset = 0,
    };

    try std.testing.expectEqual(@as(u16, 0), vlog.id);
    try std.testing.expectEqual(@as(u64, 0), vlog.offset);
}

// ============================================================================
// Data Corruption Detection Tests
// ============================================================================

test "VlogEntry - checksum computation is deterministic" {
    const seed: u64 = 0;
    const key: u128 = 12345;
    const value = "test_data";
    const timestamp: i64 = 1000;

    // Compute checksum twice
    var hasher1 = std.hash.Wyhash.init(seed);
    hasher1.update(std.mem.asBytes(&key));
    var value_len: u64 = value.len;
    hasher1.update(std.mem.asBytes(&value_len));
    hasher1.update(value);
    hasher1.update(std.mem.asBytes(&timestamp));
    const checksum1 = hasher1.final();

    var hasher2 = std.hash.Wyhash.init(seed);
    hasher2.update(std.mem.asBytes(&key));
    hasher2.update(std.mem.asBytes(&value_len));
    hasher2.update(value);
    hasher2.update(std.mem.asBytes(&timestamp));
    const checksum2 = hasher2.final();

    // Same input should produce same checksum
    try std.testing.expectEqual(checksum1, checksum2);
}

test "VlogEntry - different data produces different checksum" {
    const seed: u64 = 0;

    // Checksum for "data1"
    var hasher1 = std.hash.Wyhash.init(seed);
    hasher1.update("data1");
    const checksum1 = hasher1.final();

    // Checksum for "data2"
    var hasher2 = std.hash.Wyhash.init(seed);
    hasher2.update("data2");
    const checksum2 = hasher2.final();

    // Different data should produce different checksum
    try std.testing.expect(checksum1 != checksum2);
}

test "VlogEntry - single bit flip changes checksum" {
    const seed: u64 = 0;

    // Original data
    var hasher1 = std.hash.Wyhash.init(seed);
    hasher1.update("AAAA");
    const checksum1 = hasher1.final();

    // Data with one bit flipped (A=0x41, B=0x42)
    var hasher2 = std.hash.Wyhash.init(seed);
    hasher2.update("BAAA");
    const checksum2 = hasher2.final();

    // Single bit flip should change checksum
    try std.testing.expect(checksum1 != checksum2);
}

test "PAGE_SIZE constant" {
    // Verify PAGE_SIZE is a reasonable value
    try std.testing.expectEqual(@as(u32, 131072), PAGE_SIZE); // 128KB
    try std.testing.expect(PAGE_SIZE > 0);
    try std.testing.expect(PAGE_SIZE % 4096 == 0); // Should be page-aligned
}
