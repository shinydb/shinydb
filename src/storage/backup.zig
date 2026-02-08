const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;

/// Backup format version
const BACKUP_VERSION: u8 = 1;
const BACKUP_MAGIC: u32 = 0x42414442; // "BADB" in hex

/// Backup header
pub const BackupHeader = struct {
    magic: u32 = BACKUP_MAGIC,
    version: u8 = BACKUP_VERSION,
    timestamp: i64,
    vlog_count: u16,
    index_entry_count: u64,
    compressed: bool = false,
};

/// Backup metadata
pub const BackupMetadata = struct {
    backup_path: []const u8,
    timestamp: i64,
    size_bytes: u64,
    vlog_count: u16,
    entry_count: u64,
};

/// Backup manager
pub const BackupManager = struct {
    allocator: Allocator,
    io: Io,
    backup_dir: []const u8,

    pub fn init(allocator: Allocator, io: Io, backup_dir: []const u8) !*BackupManager {
        const mgr = try allocator.create(BackupManager);
        mgr.* = BackupManager{
            .allocator = allocator,
            .io = io,
            .backup_dir = try allocator.dupe(u8, backup_dir),
        };

        // Ensure backup directory exists
        Dir.makeDir(.cwd(), io, backup_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return mgr;
    }

    pub fn deinit(self: *BackupManager) void {
        self.allocator.free(self.backup_dir);
        self.allocator.destroy(self);
    }

    /// Create a full backup of the database
    pub fn createFullBackup(
        self: *BackupManager,
        db_path: []const u8,
        vlog_ids: []const u16,
        index_entries: u64,
    ) !BackupMetadata {
        const timestamp = milliTimestamp();

        // Generate backup file name: backup_<timestamp>.shinydb
        var backup_name_buf: [256]u8 = undefined;
        const backup_name = try std.fmt.bufPrint(&backup_name_buf, "backup_{d}.shinydb", .{timestamp});

        var backup_path_buf: [512]u8 = undefined;
        const backup_path = try std.fmt.bufPrint(&backup_path_buf, "{s}/{s}", .{ self.backup_dir, backup_name });

        // Create backup file
        const backup_file = try Dir.createFile(.cwd(), self.io, backup_path, .{ .read = false, .truncate = true });
        defer backup_file.close(self.io);

        // Write header
        const header = BackupHeader{
            .timestamp = timestamp,
            .vlog_count = @intCast(vlog_ids.len),
            .index_entry_count = index_entries,
        };
        try self.writeHeader(backup_file, header);

        // Copy all vlog files
        for (vlog_ids) |vlog_id| {
            var vlog_name_buf: [256]u8 = undefined;
            const vlog_name = try std.fmt.bufPrint(&vlog_name_buf, "{s}/vlog_{d}.db", .{ db_path, vlog_id });

            try self.copyVlogToBackup(vlog_name, backup_file, vlog_id);
        }

        // Get backup file size
        const stat = try backup_file.stat(self.io);

        return BackupMetadata{
            .backup_path = try self.allocator.dupe(u8, backup_path),
            .timestamp = timestamp,
            .size_bytes = stat.size,
            .vlog_count = @intCast(vlog_ids.len),
            .entry_count = index_entries,
        };
    }

    /// Restore database from backup
    pub fn restoreFromBackup(
        self: *BackupManager,
        backup_path: []const u8,
        db_path: []const u8,
    ) !BackupMetadata {
        // Open backup file
        const backup_file = try Dir.openFile(.cwd(), self.io, backup_path, .{ .mode = .read_only });
        defer backup_file.close(self.io);

        // Read header
        const header = try self.readHeader(backup_file);

        if (header.magic != BACKUP_MAGIC) {
            return error.InvalidBackupFile;
        }
        if (header.version != BACKUP_VERSION) {
            return error.IncompatibleBackupVersion;
        }

        // Ensure db_path directory exists
        Dir.makeDir(.cwd(), self.io, db_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // Restore all vlog files
        var i: u16 = 0;
        while (i < header.vlog_count) : (i += 1) {
            try self.restoreVlogFromBackup(backup_file, db_path, i);
        }

        const stat = try backup_file.stat(self.io);

        return BackupMetadata{
            .backup_path = try self.allocator.dupe(u8, backup_path),
            .timestamp = header.timestamp,
            .size_bytes = stat.size,
            .vlog_count = header.vlog_count,
            .entry_count = header.index_entry_count,
        };
    }

    /// List all available backups
    pub fn listBackups(self: *BackupManager) !std.ArrayList(BackupMetadata) {
        var backups: std.ArrayList(BackupMetadata) = .empty;

        // Open backup directory
        var dir = try Dir.open(.cwd(), self.io, self.backup_dir, .{ .iterate = true });
        defer dir.close(self.io);

        // Iterate through backup files
        var walker = try dir.walk(self.allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;

            // Check if file matches backup pattern
            if (!std.mem.endsWith(u8, entry.basename, ".shinydb")) continue;
            if (!std.mem.startsWith(u8, entry.basename, "backup_")) continue;

            // Read backup metadata
            var path_buf: [512]u8 = undefined;
            const full_path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.backup_dir, entry.basename });

            const backup_file = try Dir.openFile(.cwd(), self.io, full_path, .{ .mode = .read_only });
            defer backup_file.close(self.io);

            const header = try self.readHeader(backup_file);
            const stat = try backup_file.stat(self.io);

            try backups.append(self.allocator, BackupMetadata{
                .backup_path = try self.allocator.dupe(u8, full_path),
                .timestamp = header.timestamp,
                .size_bytes = stat.size,
                .vlog_count = header.vlog_count,
                .entry_count = header.index_entry_count,
            });
        }

        return backups;
    }

    /// Delete old backups, keeping only the most recent N
    pub fn cleanupOldBackups(self: *BackupManager, keep_count: usize) !usize {
        var backups = try self.listBackups();
        defer {
            for (backups.items) |backup| {
                self.allocator.free(backup.backup_path);
            }
            backups.deinit(self.allocator);
        }

        if (backups.items.len <= keep_count) return 0;

        // Sort by timestamp (newest first)
        std.mem.sort(BackupMetadata, backups.items, {}, struct {
            fn lessThan(_: void, a: BackupMetadata, b: BackupMetadata) bool {
                return a.timestamp > b.timestamp;
            }
        }.lessThan);

        // Delete old backups
        var deleted: usize = 0;
        var i = keep_count;
        while (i < backups.items.len) : (i += 1) {
            Dir.deleteFile(.cwd(), self.io, backups.items[i].backup_path) catch {
                continue;
            };
            deleted += 1;
        }

        return deleted;
    }

    // ==== Private helper methods ====

    fn writeHeader(self: *BackupManager, file: File, header: BackupHeader) !void {
        _ = self;
        var buf: [29]u8 = undefined; // Calculate based on struct size

        var offset: usize = 0;
        std.mem.writeInt(u32, buf[offset..][0..4], header.magic, .little);
        offset += 4;
        buf[offset] = header.version;
        offset += 1;
        std.mem.writeInt(i64, buf[offset..][0..8], header.timestamp, .little);
        offset += 8;
        std.mem.writeInt(u16, buf[offset..][0..2], header.vlog_count, .little);
        offset += 2;
        std.mem.writeInt(u64, buf[offset..][0..8], header.index_entry_count, .little);
        offset += 8;
        buf[offset] = if (header.compressed) 1 else 0;
        offset += 1;

        // Pad to alignment
        while (offset < buf.len) : (offset += 1) {
            buf[offset] = 0;
        }

        try file.writeAll(&buf);
    }

    fn readHeader(self: *BackupManager, file: File) !BackupHeader {
        _ = self;
        var buf: [29]u8 = undefined;
        _ = try file.readAll(&buf);

        var offset: usize = 0;
        const magic = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;
        const version = buf[offset];
        offset += 1;
        const timestamp = std.mem.readInt(i64, buf[offset..][0..8], .little);
        offset += 8;
        const vlog_count = std.mem.readInt(u16, buf[offset..][0..2], .little);
        offset += 2;
        const index_entry_count = std.mem.readInt(u64, buf[offset..][0..8], .little);
        offset += 8;
        const compressed = buf[offset] != 0;

        return BackupHeader{
            .magic = magic,
            .version = version,
            .timestamp = timestamp,
            .vlog_count = vlog_count,
            .index_entry_count = index_entry_count,
            .compressed = compressed,
        };
    }

    fn copyVlogToBackup(self: *BackupManager, vlog_path: []const u8, backup_file: File, vlog_id: u16) !void {
        // Open source vlog file
        const vlog_file = Dir.openFile(.cwd(), self.io, vlog_path, .{ .mode = .read_only }) catch {
            return;
        };
        defer vlog_file.close(self.io);

        // Get file size
        const stat = try vlog_file.stat(self.io);
        const file_size = stat.size;

        // Write vlog header: vlog_id (2 bytes) + size (8 bytes)
        var header_buf: [10]u8 = undefined;
        std.mem.writeInt(u16, header_buf[0..2], vlog_id, .little);
        std.mem.writeInt(u64, header_buf[2..10], file_size, .little);
        try backup_file.writeAll(&header_buf);

        // Copy file contents in chunks
        const chunk_size = 64 * 1024; // 64KB chunks
        var buffer = try self.allocator.alloc(u8, chunk_size);
        defer self.allocator.free(buffer);

        var remaining = file_size;
        while (remaining > 0) {
            const to_read = @min(remaining, chunk_size);
            const bytes_read = try vlog_file.read(buffer[0..to_read]);
            if (bytes_read == 0) break;

            try backup_file.writeAll(buffer[0..bytes_read]);
            remaining -= bytes_read;
        }
    }

    fn restoreVlogFromBackup(self: *BackupManager, backup_file: File, db_path: []const u8, expected_vlog_id: u16) !void {
        // Read vlog header
        var header_buf: [10]u8 = undefined;
        _ = try backup_file.readAll(&header_buf);

        const vlog_id = std.mem.readInt(u16, header_buf[0..2], .little);
        const file_size = std.mem.readInt(u64, header_buf[2..10], .little);

        if (vlog_id != expected_vlog_id) {
            return error.CorruptedBackup;
        }

        // Create target vlog file
        var vlog_path_buf: [512]u8 = undefined;
        const vlog_path = try std.fmt.bufPrint(&vlog_path_buf, "{s}/vlog_{d}.db", .{ db_path, vlog_id });

        const vlog_file = try Dir.createFile(.cwd(), self.io, vlog_path, .{ .read = false, .truncate = true });
        defer vlog_file.close(self.io);

        // Copy file contents in chunks
        const chunk_size = 64 * 1024; // 64KB chunks
        var buffer = try self.allocator.alloc(u8, chunk_size);
        defer self.allocator.free(buffer);

        var remaining = file_size;
        while (remaining > 0) {
            const to_read = @min(remaining, chunk_size);
            const bytes_read = try backup_file.read(buffer[0..to_read]);
            if (bytes_read == 0) break;

            try vlog_file.writeAll(buffer[0..bytes_read]);
            remaining -= bytes_read;
        }
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "BackupHeader - default values" {
    const header = BackupHeader{
        .timestamp = 1000,
        .vlog_count = 5,
        .index_entry_count = 100,
    };

    try std.testing.expectEqual(BACKUP_MAGIC, header.magic);
    try std.testing.expectEqual(BACKUP_VERSION, header.version);
    try std.testing.expectEqual(@as(i64, 1000), header.timestamp);
    try std.testing.expectEqual(@as(u16, 5), header.vlog_count);
    try std.testing.expectEqual(@as(u64, 100), header.index_entry_count);
    try std.testing.expectEqual(false, header.compressed);
}

test "BackupHeader - with compression" {
    const header = BackupHeader{
        .timestamp = 2000,
        .vlog_count = 10,
        .index_entry_count = 500,
        .compressed = true,
    };

    try std.testing.expectEqual(true, header.compressed);
}

test "BackupHeader - magic number is unique" {
    // Verify magic number is "BADB" in hex
    try std.testing.expectEqual(@as(u32, 0x42414442), BACKUP_MAGIC);
    // Should not conflict with common file signatures
    try std.testing.expect(BACKUP_MAGIC != 0x89504E47); // PNG
    try std.testing.expect(BACKUP_MAGIC != 0x25504446); // PDF
}

test "BackupHeader - version constant" {
    try std.testing.expectEqual(@as(u8, 1), BACKUP_VERSION);
}

test "BackupHeader - max values" {
    const header = BackupHeader{
        .timestamp = std.math.maxInt(i64),
        .vlog_count = std.math.maxInt(u16),
        .index_entry_count = std.math.maxInt(u64),
    };

    try std.testing.expectEqual(std.math.maxInt(i64), header.timestamp);
    try std.testing.expectEqual(std.math.maxInt(u16), header.vlog_count);
    try std.testing.expectEqual(std.math.maxInt(u64), header.index_entry_count);
}

test "BackupHeader - zero values" {
    const header = BackupHeader{
        .timestamp = 0,
        .vlog_count = 0,
        .index_entry_count = 0,
    };

    try std.testing.expectEqual(@as(i64, 0), header.timestamp);
    try std.testing.expectEqual(@as(u16, 0), header.vlog_count);
    try std.testing.expectEqual(@as(u64, 0), header.index_entry_count);
}

test "BackupHeader - negative timestamp" {
    const header = BackupHeader{
        .timestamp = -1000, // Before epoch
        .vlog_count = 1,
        .index_entry_count = 1,
    };

    try std.testing.expectEqual(@as(i64, -1000), header.timestamp);
}

test "BackupMetadata - structure" {
    const metadata = BackupMetadata{
        .backup_path = "/backups/backup_123.shinydb",
        .timestamp = 1234567890,
        .size_bytes = 1024 * 1024, // 1MB
        .vlog_count = 3,
        .entry_count = 10000,
    };

    try std.testing.expectEqualStrings("/backups/backup_123.shinydb", metadata.backup_path);
    try std.testing.expectEqual(@as(i64, 1234567890), metadata.timestamp);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), metadata.size_bytes);
    try std.testing.expectEqual(@as(u16, 3), metadata.vlog_count);
    try std.testing.expectEqual(@as(u64, 10000), metadata.entry_count);
}

test "BackupMetadata - empty backup" {
    const metadata = BackupMetadata{
        .backup_path = "",
        .timestamp = 0,
        .size_bytes = 0,
        .vlog_count = 0,
        .entry_count = 0,
    };

    try std.testing.expectEqualStrings("", metadata.backup_path);
    try std.testing.expectEqual(@as(u64, 0), metadata.size_bytes);
}

test "BackupMetadata - large backup" {
    const metadata = BackupMetadata{
        .backup_path = "/data/backups/large_backup.shinydb",
        .timestamp = 1700000000000,
        .size_bytes = 10 * 1024 * 1024 * 1024, // 10GB
        .vlog_count = 100,
        .entry_count = 1_000_000_000, // 1 billion entries
    };

    try std.testing.expectEqual(@as(u64, 10 * 1024 * 1024 * 1024), metadata.size_bytes);
    try std.testing.expectEqual(@as(u64, 1_000_000_000), metadata.entry_count);
}

test "BackupHeader - serialization size" {
    // Header format: magic(4) + version(1) + timestamp(8) + vlog_count(2) + index_entry_count(8) + compressed(1) + padding(5) = 29 bytes
    const expected_size: usize = 4 + 1 + 8 + 2 + 8 + 1 + 5;
    try std.testing.expectEqual(@as(usize, 29), expected_size);
}
