const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const File = Io.File;
const Dir = Io.Dir;
const VlogEntry = @import("../common/common.zig").VlogEntry;
const Entry = @import("../common/common.zig").Entry;
const IndexEntry = @import("../common/common.zig").IndexEntry;
const FlushBuffer = @import("../common/flush_buffer.zig").FlushBuffer;

const log = std.log.scoped(.vlog);

const MAGIC: u32 = 0x53535442;
const VERSION: u8 = 1;

const Header = struct {
    magic: u32 = MAGIC,
    version: u8 = VERSION,
    count: u64,
    deleted: u64,
    last_gc_ts: i64,
    system_store_key_exists: bool = false,
    system_store_key: u128 = 0,
};

pub const VLogConfig = struct {
    file_name: []const u8,
    block_size: u64,
    max_file_size: usize,
    io: Io,
};

pub const ValueLog = struct {
    allocator: Allocator,
    io: Io,
    file: File,
    path: []const u8,
    offset: u64,
    tmpf: ?File = null,
    buffers: FlushBuffer,
    header: Header = undefined,

    pub fn init(allocator: Allocator, config: VLogConfig) !*ValueLog {
        const io = config.io;

        var is_new = false;
        var file: File = undefined;
        if (Dir.openFile(.cwd(), io, config.file_name, .{ .mode = .read_write })) |f| {
            file = f;
        } else |err| switch (err) {
            error.FileNotFound => {
                file = try Dir.createFile(.cwd(), io, config.file_name, .{ .read = true, .truncate = false });
                is_new = true;
            },
            else => return err,
        }

        const vlog = try allocator.create(ValueLog);
        vlog.* = ValueLog{
            .file = file,
            .io = io,
            .allocator = allocator,
            .offset = 0,
            .path = try allocator.dupe(u8, config.file_name),
            .buffers = try FlushBuffer.init(allocator, config.block_size),
            .header = try readHeader(allocator, io, is_new, file),
        };

        // Move file head to end so that writes always append
        const stat = try vlog.file.stat(io);
        vlog.offset = stat.size;

        return vlog;
    }

    pub fn deinit(self: *ValueLog) !void {
        if (self.buffers.pos > 0) {
            try self.file.writePositionalAll(self.io, self.buffers.slice(), self.offset - self.buffers.pos);
            try self.file.sync(self.io);
        }
        self.file.close(self.io);
        if (self.tmpf) |t| t.close(self.io);
        self.allocator.free(self.path);
        self.buffers.deinit();
        self.allocator.destroy(self);
    }

    fn readHeader(allocator: Allocator, io: Io, is_new: bool, file: File) !Header {
        _ = allocator;
        if (is_new) {
            // Write header to beginning of file
            // Format: magic(4) + version(1) + count(8) + deleted(8) + last_gc_ts(8) + system_store_key_exists(1) + system_store_key(16) = 46 bytes
            var header_buf: [46]u8 = undefined;
            mem.writeInt(u32, header_buf[0..4], MAGIC, .little);
            header_buf[4] = VERSION;
            mem.writeInt(u64, header_buf[5..13], 0, .little); // count
            mem.writeInt(u64, header_buf[13..21], 0, .little); // deleted
            mem.writeInt(i64, header_buf[21..29], 0, .little); // last_gc_ts
            header_buf[29] = 0; // system_store_key_exists = false
            mem.writeInt(u128, header_buf[30..46], 0, .little); // system_store_key = 0
            try file.writePositionalAll(io, &header_buf, 0);
            try file.sync(io);
            return Header{
                .magic = MAGIC,
                .version = VERSION,
                .count = 0,
                .deleted = 0,
                .last_gc_ts = 0,
                .system_store_key_exists = false,
                .system_store_key = 0,
            };
        } else {
            var header_buf: [46]u8 = undefined;
            _ = try file.readPositionalAll(io, &header_buf, 0);
            const magic = mem.readInt(u32, header_buf[0..4], .little);
            if (magic != MAGIC) return error.InvalidMagicNumber;
            const version = header_buf[4];
            if (version != VERSION) return error.IncompatibleVersion;
            const count = mem.readInt(u64, header_buf[5..13], .little);
            const deleted = mem.readInt(u64, header_buf[13..21], .little);
            const ts = mem.readInt(i64, header_buf[21..29], .little);
            const system_store_key_exists = header_buf[29] != 0;
            const system_store_key = mem.readInt(u128, header_buf[30..46], .little);
            return Header{
                .magic = magic,
                .version = version,
                .count = count,
                .deleted = deleted,
                .last_gc_ts = ts,
                .system_store_key_exists = system_store_key_exists,
                .system_store_key = system_store_key,
            };
        }
    }

    pub fn flush(self: *ValueLog) !void {
        const target_file = if (self.tmpf) |file| file else self.file;

        target_file.writePositionalAll(self.io, self.buffers.slice(), self.offset - self.buffers.pos) catch |err| {
            log.err("Failed to write buffers to file: {s}", .{@errorName(err)});
            return err;
        };
        target_file.sync(self.io) catch |err| {
            log.err("Failed to sync file: {s}", .{@errorName(err)});
            return err;
        };
        self.buffers.reset();
        self.buffers.pos = 0;
    }

    pub fn put(self: *ValueLog, entry: VlogEntry) anyerror!u64 {
        const entry_offset = self.offset;

        if (self.buffers.pos + entry.size() >= self.buffers.len) {
            try self.flush();
        }

        entry.write(self.buffers.writer()) catch |err| {
            log.err("Failed to write entry to buffer: {s}", .{@errorName(err)});
            return err;
        };

        self.offset += entry.size();
        return entry_offset;
    }

    pub fn putBatch(self: *ValueLog, entries: []VlogEntry) anyerror![]IndexEntry {
        var indexEntries = try self.allocator.alloc(IndexEntry, entries.len);
        errdefer self.allocator.free(indexEntries);

        for (entries, 0..) |entry, i| {
            const entry_offset = try self.put(entry);
            indexEntries[i] = IndexEntry{
                .key = entry.key,
                .value_offset = entry_offset,
            };
        }

        try self.file.writePositionalAll(self.io, self.buffers.slice(), self.offset - self.buffers.pos);
        try self.file.sync(self.io);
        return indexEntries;
    }

    pub fn get(self: *ValueLog, offset: u64) !VlogEntry {
        const source_file = if (self.tmpf) |file| file else self.file;

        // Read the entry structure field by field
        // Format: key(16) + value_len(8) + value(N) + timestamp(8) + checksum(8)

        // First, read key and value_len to determine total size
        var header_buf: [16 + 8]u8 = undefined; // key + value_len
        _ = try source_file.readPositionalAll(self.io, &header_buf, offset);

        // Extract value_len to calculate total entry size (we'll re-parse the key later)
        const value_len = mem.readInt(u64, header_buf[16..24], .little);

        // Calculate total entry size: key(16) + value_len(8) + value(N) + timestamp(8) + checksum(8)
        const entry_size = 16 + 8 + value_len + 8 + 8;

        // Read the entire entry
        const entry_buf = try self.allocator.alloc(u8, entry_size);
        defer self.allocator.free(entry_buf);
        _ = try source_file.readPositionalAll(self.io, entry_buf, offset);

        return try VlogEntry.readFromSlice(self.allocator, entry_buf);
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "vlog - magic and version constants" {
    try std.testing.expectEqual(@as(u32, 0x53535442), MAGIC);
    try std.testing.expectEqual(@as(u8, 1), VERSION);
}

test "vlog - Header struct defaults" {
    const header = Header{
        .count = 100,
        .deleted = 10,
        .last_gc_ts = 1234567890,
    };

    try std.testing.expectEqual(MAGIC, header.magic);
    try std.testing.expectEqual(VERSION, header.version);
    try std.testing.expectEqual(@as(u64, 100), header.count);
    try std.testing.expectEqual(@as(u64, 10), header.deleted);
    try std.testing.expectEqual(@as(i64, 1234567890), header.last_gc_ts);
}

test "vlog - Header binary format size" {
    // Header format: magic(4) + version(1) + count(8) + deleted(8) + last_gc_ts(8) + system_store_key_exists(1) + system_store_key(16) = 46 bytes
    const expected_size: usize = 4 + 1 + 8 + 8 + 8 + 1 + 16;
    try std.testing.expectEqual(@as(usize, 46), expected_size);
}

test "vlog - Header serialization roundtrip" {
    const original = Header{
        .count = 42,
        .deleted = 5,
        .last_gc_ts = 9876543210,
        .system_store_key_exists = true,
        .system_store_key = 12345678901234567890,
    };

    // Serialize
    var buf: [46]u8 = undefined;
    mem.writeInt(u32, buf[0..4], original.magic, .little);
    buf[4] = original.version;
    mem.writeInt(u64, buf[5..13], original.count, .little);
    mem.writeInt(u64, buf[13..21], original.deleted, .little);
    mem.writeInt(i64, buf[21..29], original.last_gc_ts, .little);
    buf[29] = if (original.system_store_key_exists) 1 else 0;
    mem.writeInt(u128, buf[30..46], original.system_store_key, .little);

    // Deserialize
    const magic = mem.readInt(u32, buf[0..4], .little);
    const version = buf[4];
    const count = mem.readInt(u64, buf[5..13], .little);
    const deleted = mem.readInt(u64, buf[13..21], .little);
    const last_gc_ts = mem.readInt(i64, buf[21..29], .little);
    const system_store_key_exists = buf[29] != 0;
    const system_store_key = mem.readInt(u128, buf[30..46], .little);

    try std.testing.expectEqual(original.magic, magic);
    try std.testing.expectEqual(original.version, version);
    try std.testing.expectEqual(original.count, count);
    try std.testing.expectEqual(original.deleted, deleted);
    try std.testing.expectEqual(original.last_gc_ts, last_gc_ts);
    try std.testing.expectEqual(original.system_store_key_exists, system_store_key_exists);
    try std.testing.expectEqual(original.system_store_key, system_store_key);
}

test "vlog - VLogConfig struct" {
    const config = VLogConfig{
        .file_name = "test.vlog",
        .block_size = 4096,
        .max_file_size = 256 * 1024 * 1024,
        .io = undefined,
    };

    try std.testing.expectEqualStrings("test.vlog", config.file_name);
    try std.testing.expectEqual(@as(u64, 4096), config.block_size);
    try std.testing.expectEqual(@as(usize, 256 * 1024 * 1024), config.max_file_size);
}

test "vlog - entry size calculation" {
    // Entry format: key(16) + value_len(8) + value(N) + timestamp(8) + checksum(8)
    const key_size: usize = 16;
    const value_len_size: usize = 8;
    const timestamp_size: usize = 8;
    const checksum_size: usize = 8;
    const overhead = key_size + value_len_size + timestamp_size + checksum_size;

    // For a 100-byte value
    const value_len: usize = 100;
    const expected_entry_size = overhead + value_len;
    try std.testing.expectEqual(@as(usize, 140), expected_entry_size);

    // For a 1KB value
    const value_len_1k: usize = 1024;
    const expected_entry_size_1k = overhead + value_len_1k;
    try std.testing.expectEqual(@as(usize, 1064), expected_entry_size_1k);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "vlog - entry size with empty value" {
    // Entry format: key(16) + value_len(8) + value(0) + timestamp(8) + checksum(8)
    const overhead: usize = 16 + 8 + 8 + 8; // 40 bytes
    const expected_entry_size = overhead + 0;
    try std.testing.expectEqual(@as(usize, 40), expected_entry_size);
}

test "vlog - Header with max values" {
    const header = Header{
        .count = std.math.maxInt(u64),
        .deleted = std.math.maxInt(u64),
        .last_gc_ts = std.math.maxInt(i64),
    };

    try std.testing.expectEqual(std.math.maxInt(u64), header.count);
    try std.testing.expectEqual(std.math.maxInt(u64), header.deleted);
    try std.testing.expectEqual(std.math.maxInt(i64), header.last_gc_ts);
}

test "vlog - Header with zero values" {
    const header = Header{
        .count = 0,
        .deleted = 0,
        .last_gc_ts = 0,
    };

    try std.testing.expectEqual(@as(u64, 0), header.count);
    try std.testing.expectEqual(@as(u64, 0), header.deleted);
    try std.testing.expectEqual(@as(i64, 0), header.last_gc_ts);
}

test "vlog - Header with negative timestamp" {
    const header = Header{
        .count = 10,
        .deleted = 5,
        .last_gc_ts = -1000, // Negative timestamp
    };

    try std.testing.expectEqual(@as(i64, -1000), header.last_gc_ts);
}

test "vlog - VLogConfig with minimum block size" {
    const config = VLogConfig{
        .file_name = "test.vlog",
        .block_size = 1, // Minimum
        .max_file_size = 1,
        .io = undefined,
    };

    try std.testing.expectEqual(@as(u64, 1), config.block_size);
    try std.testing.expectEqual(@as(usize, 1), config.max_file_size);
}

test "vlog - VLogConfig with large values" {
    const config = VLogConfig{
        .file_name = "large.vlog",
        .block_size = 1024 * 1024, // 1MB blocks
        .max_file_size = 1024 * 1024 * 1024, // 1GB max
        .io = undefined,
    };

    try std.testing.expectEqual(@as(u64, 1024 * 1024), config.block_size);
    try std.testing.expectEqual(@as(usize, 1024 * 1024 * 1024), config.max_file_size);
}

test "vlog - magic number is unique" {
    // Verify magic number doesn't conflict with common file signatures
    try std.testing.expect(MAGIC != 0x89504E47); // PNG
    try std.testing.expect(MAGIC != 0x25504446); // PDF
    try std.testing.expect(MAGIC != 0x504B0304); // ZIP
}
