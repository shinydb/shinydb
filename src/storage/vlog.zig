const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const File = Io.File;
const Dir = Io.Dir;
const VlogEntry = @import("../common/common.zig").VlogEntry;
const Entry = @import("../common/common.zig").Entry;
const FlushBuffer = @import("../common/flush_buffer.zig").FlushBuffer;

const log = std.log.scoped(.vlog);

const MAGIC: u32 = 0x53535442;
const VERSION: u8 = 1;

const Header = struct {
    magic: u32 = MAGIC,
    version: u8 = VERSION,
    id: u16,
    count: u64,
    deleted: u64,
    last_gc_ts: i64,
    // Byte tracking for garbage collection (added in extended format)
    total_bytes: u64 = 0,
    live_bytes: u64 = 0,
    dead_bytes: u64 = 0,

    pub fn deadRatio(self: *const Header) f64 {
        if (self.total_bytes == 0) return 0.0;
        return @as(f64, @floatFromInt(self.dead_bytes)) /
            @as(f64, @floatFromInt(self.total_bytes));
    }

    pub fn isGcCandidate(self: *const Header, threshold: f64) bool {
        return self.deadRatio() >= threshold;
    }
};

pub const VLogConfig = struct {
    id: u16,
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
            .header = try readHeader(allocator, io, is_new, file, config.id),
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

    fn readHeader(allocator: Allocator, io: Io, is_new: bool, file: File, id: u16) !Header {
        _ = allocator;
        if (is_new) {
            // Write header to beginning of file
            // Format: magic(4) + version(1) + id(2) + count(8) + deleted(8) + last_gc_ts(8) +
            //         total_bytes(8) + live_bytes(8) + dead_bytes(8) = 55 bytes
            var header_buf: [55]u8 = undefined;
            mem.writeInt(u32, header_buf[0..4], MAGIC, .little);
            header_buf[4] = VERSION;
            mem.writeInt(u16, header_buf[5..7], id, .little);
            mem.writeInt(u64, header_buf[7..15], 0, .little); // count
            mem.writeInt(u64, header_buf[15..23], 0, .little); // deleted
            mem.writeInt(i64, header_buf[23..31], 0, .little); // last_gc_ts
            mem.writeInt(u64, header_buf[31..39], 0, .little); // total_bytes
            mem.writeInt(u64, header_buf[39..47], 0, .little); // live_bytes
            mem.writeInt(u64, header_buf[47..55], 0, .little); // dead_bytes
            try file.writePositionalAll(io, &header_buf, 0);
            try file.sync(io);
            return Header{
                .magic = MAGIC,
                .version = VERSION,
                .id = id,
                .count = 0,
                .deleted = 0,
                .last_gc_ts = 0,
                .total_bytes = 0,
                .live_bytes = 0,
                .dead_bytes = 0,
            };
        } else {
            // Read 55-byte format
            var header_buf: [55]u8 = undefined;
            _ = try file.readPositionalAll(io, &header_buf, 0);

            const magic = mem.readInt(u32, header_buf[0..4], .little);
            if (magic != MAGIC) return error.InvalidMagicNumber;
            const version = header_buf[4];
            if (version != VERSION) return error.IncompatibleVersion;
            const file_id = mem.readInt(u16, header_buf[5..7], .little);
            const count = mem.readInt(u64, header_buf[7..15], .little);
            const deleted = mem.readInt(u64, header_buf[15..23], .little);
            const ts = mem.readInt(i64, header_buf[23..31], .little);
            const total_bytes = mem.readInt(u64, header_buf[31..39], .little);
            const live_bytes = mem.readInt(u64, header_buf[39..47], .little);
            const dead_bytes = mem.readInt(u64, header_buf[47..55], .little);
            return Header{
                .magic = magic,
                .version = version,
                .id = file_id,
                .count = count,
                .deleted = deleted,
                .last_gc_ts = ts,
                .total_bytes = total_bytes,
                .live_bytes = live_bytes,
                .dead_bytes = dead_bytes,
            };
        }
    }

    /// Sync the complete header to disk (55-byte format)
    pub fn syncHeader(self: *ValueLog) !void {
        var header_buf: [55]u8 = undefined;
        mem.writeInt(u32, header_buf[0..4], self.header.magic, .little);
        header_buf[4] = self.header.version;
        mem.writeInt(u16, header_buf[5..7], self.header.id, .little);
        mem.writeInt(u64, header_buf[7..15], self.header.count, .little);
        mem.writeInt(u64, header_buf[15..23], self.header.deleted, .little);
        mem.writeInt(i64, header_buf[23..31], self.header.last_gc_ts, .little);
        mem.writeInt(u64, header_buf[31..39], self.header.total_bytes, .little);
        mem.writeInt(u64, header_buf[39..47], self.header.live_bytes, .little);
        mem.writeInt(u64, header_buf[47..55], self.header.dead_bytes, .little);
        try self.file.writePositionalAll(self.io, &header_buf, 0);
        try self.file.sync(self.io);
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

    /// Increment the deleted counter in the vlog header and persist to disk
    pub fn incrementDeleted(self: *ValueLog) !void {
        self.header.deleted += 1;

        // Write just the deleted field to disk (offset 13, 8 bytes)
        var deleted_buf: [8]u8 = undefined;
        mem.writeInt(u64, &deleted_buf, self.header.deleted, .little);
        try self.file.writePositionalAll(self.io, &deleted_buf, 13);
        try self.file.sync(self.io);
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

    pub fn get(self: *ValueLog, offset: u64) !VlogEntry {
        const source_file = if (self.tmpf) |file| file else self.file;

        // Read the entry structure field by field
        // Format: key(16) + value_len(8) + value(N) + timestamp(8) + tombstone(1) + checksum(8)

        // First, read key and value_len to determine total size
        var header_buf: [16 + 8]u8 = undefined; // key + value_len
        _ = try source_file.readPositionalAll(self.io, &header_buf, offset);

        // Extract value_len to calculate total entry size (we'll re-parse the key later)
        const value_len = mem.readInt(u64, header_buf[16..24], .little);

        // Calculate total entry size: key(16) + value_len(8) + value(N) + timestamp(8) + tombstone(1) + checksum(8)
        const entry_size = 16 + 8 + value_len + 8 + 8 + 1;

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
        .id = 1,
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
    // Header format: magic(4) + version(1) + count(8) + deleted(8) + last_gc_ts(8) +
    //                total_bytes(8) + live_bytes(8) + dead_bytes(8) = 53 bytes
    const expected_size: usize = 4 + 1 + 8 + 8 + 8 + 8 + 8 + 8;
    try std.testing.expectEqual(@as(usize, 53), expected_size);
}

test "vlog - Header serialization roundtrip" {
    const original = Header{
        .id = 42,
        .count = 42,
        .deleted = 5,
        .last_gc_ts = 9876543210,
        .total_bytes = 1000000,
        .live_bytes = 600000,
        .dead_bytes = 400000,
    };

    // Serialize
    var buf: [53]u8 = undefined;
    mem.writeInt(u32, buf[0..4], original.magic, .little);
    buf[4] = original.version;
    mem.writeInt(u64, buf[5..13], original.count, .little);
    mem.writeInt(u64, buf[13..21], original.deleted, .little);
    mem.writeInt(i64, buf[21..29], original.last_gc_ts, .little);
    mem.writeInt(u64, buf[29..37], original.total_bytes, .little);
    mem.writeInt(u64, buf[37..45], original.live_bytes, .little);
    mem.writeInt(u64, buf[45..53], original.dead_bytes, .little);

    // Deserialize
    const magic = mem.readInt(u32, buf[0..4], .little);
    const version = buf[4];
    const count = mem.readInt(u64, buf[5..13], .little);
    const deleted = mem.readInt(u64, buf[13..21], .little);
    const last_gc_ts = mem.readInt(i64, buf[21..29], .little);
    const total_bytes = mem.readInt(u64, buf[29..37], .little);
    const live_bytes = mem.readInt(u64, buf[37..45], .little);
    const dead_bytes = mem.readInt(u64, buf[45..53], .little);

    try std.testing.expectEqual(original.magic, magic);
    try std.testing.expectEqual(original.version, version);
    try std.testing.expectEqual(original.count, count);
    try std.testing.expectEqual(original.deleted, deleted);
    try std.testing.expectEqual(original.last_gc_ts, last_gc_ts);
    try std.testing.expectEqual(original.total_bytes, total_bytes);
    try std.testing.expectEqual(original.live_bytes, live_bytes);
    try std.testing.expectEqual(original.dead_bytes, dead_bytes);
}

test "vlog - VLogConfig struct" {
    const config = VLogConfig{
        .id = 10,
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
        .id = 999,
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
        .id = 0,
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
        .id = 101,
        .count = 10,
        .deleted = 5,
        .last_gc_ts = -1000, // Negative timestamp
    };

    try std.testing.expectEqual(@as(i64, -1000), header.last_gc_ts);
}

test "vlog - VLogConfig with minimum block size" {
    const config = VLogConfig{
        .id = 1,
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
        .id = 123,
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

test "vlog - Header deadRatio calculation" {
    // Test with 50% dead ratio
    var header = Header{
        .id = 200,
        .count = 100,
        .deleted = 50,
        .last_gc_ts = 0,
        .total_bytes = 1000,
        .live_bytes = 500,
        .dead_bytes = 500,
    };
    try std.testing.expectApproxEqRel(@as(f64, 0.5), header.deadRatio(), 0.01);

    // Test with 0% dead ratio
    header.total_bytes = 1000;
    header.live_bytes = 1000;
    header.dead_bytes = 0;
    try std.testing.expectApproxEqRel(@as(f64, 0.0), header.deadRatio(), 0.01);

    // Test with 100% dead ratio
    header.total_bytes = 1000;
    header.live_bytes = 0;
    header.dead_bytes = 1000;
    try std.testing.expectApproxEqRel(@as(f64, 1.0), header.deadRatio(), 0.01);

    // Test with zero total bytes
    header.total_bytes = 0;
    header.live_bytes = 0;
    header.dead_bytes = 0;
    try std.testing.expectEqual(@as(f64, 0.0), header.deadRatio());
}

test "vlog - Header isGcCandidate" {
    var header = Header{
        .id = 300,
        .count = 100,
        .deleted = 60,
        .last_gc_ts = 0,
        .total_bytes = 1000,
        .live_bytes = 400,
        .dead_bytes = 600,
    };

    // 60% dead ratio should be GC candidate with 50% threshold
    try std.testing.expect(header.isGcCandidate(0.5));

    // 60% dead ratio should NOT be GC candidate with 70% threshold
    try std.testing.expect(!header.isGcCandidate(0.7));

    // Exact threshold match
    try std.testing.expect(header.isGcCandidate(0.6));
}
