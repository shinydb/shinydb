const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;
const Config = @import("../common/config.zig").Config;

/// Backup format version
const BACKUP_VERSION: u8 = 1;
const BACKUP_MAGIC: u32 = 0x42414442; // "BADB" in hex

/// Backup header with component count
pub const BackupHeader = struct {
    magic: u32 = BACKUP_MAGIC,
    version: u8 = BACKUP_VERSION,
    timestamp: i64,
    component_count: u32, // Number of SectionHeader sections
    total_size: u64, // Total backup file size
    compressed: bool = false,
};

const What = enum(u8) {
    Metadata = 0,
    ValueLog = 1,
    Index = 2,
    SecondaryIndex = 3,
    WAL = 4,
    Config = 5,
};

pub const SectionHeader = struct {
    what: What,
    file_name_len: u32,
    file_name: []const u8,
    original_size: u64,
    compressed_size: u64,
    checksum: u32,
    compressed: bool,

    const SECTION_HEADER_FIXED_SIZE = 1 + 4 + 8 + 8 + 4 + 1; // 26 bytes + variable filename

    pub fn dataSize(self: SectionHeader) u64 {
        return if (self.compressed) self.compressed_size else self.original_size;
    }
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
        config: *const Config,
        secondary_index_paths: []const []const u8,
        config_path: ?[]const u8,
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

        // Discover vlog files from the vlog directory
        var vlog_files = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (vlog_files.items) |path| {
                self.allocator.free(path);
            }
            vlog_files.deinit();
        }

        // Scan vlog directory for vlog_*.db files
        var vlog_dir_buf: [512]u8 = undefined;
        const vlog_dir_path = try std.fmt.bufPrint(&vlog_dir_buf, "{s}/{s}", .{ config.base_dir, config.paths.vlog });

        if (Dir.open(.cwd(), self.io, vlog_dir_path, .{ .iterate = true })) |dir| {
            defer dir.close(self.io);
            var walker = try dir.walk(self.allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                if (entry.kind == .file and std.mem.startsWith(u8, entry.basename, "vlog_") and std.mem.endsWith(u8, entry.basename, ".db")) {
                    var full_path_buf: [512]u8 = undefined;
                    const full_path = try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ vlog_dir_path, entry.basename });
                    try vlog_files.append(try self.allocator.dupe(u8, full_path));
                }
            }
        } else |err| switch (err) {
            error.FileNotFound => {
                // No vlog directory, continue with empty vlog list
            },
            else => return err,
        }

        // Count total components
        var component_count: u32 = 0;
        component_count += @intCast(vlog_files.items.len); // Value logs
        component_count += 1; // Primary index (always present)
        component_count += @intCast(secondary_index_paths.len);
        component_count += 1; // WAL (always present)
        if (config_path != null) component_count += 1;
        component_count += 1; // Metadata

        // Reserve space for header (we'll update total_size later)
        const header_pos = try backup_file.getPos();
        var header = BackupHeader{
            .timestamp = timestamp,
            .component_count = component_count,
            .total_size = 0, // Will be updated at the end
        };
        try self.writeHeader(backup_file, header);

        var total_entries: u64 = 0;

        // Write metadata section
        try self.writeMetadataSection(backup_file, config.base_dir, timestamp);

        // Backup all discovered value logs
        for (vlog_files.items) |vlog_path| {
            const basename = std.fs.path.basename(vlog_path);
            const entries = try self.writeFileSection(backup_file, vlog_path, basename, .ValueLog);
            total_entries += entries;
        }

        // Backup primary index
        {
            var primary_index_buf: [512]u8 = undefined;
            const primary_index_path = try std.fmt.bufPrint(&primary_index_buf, "{s}/{s}", .{ config.base_dir, config.paths.index });
            _ = try self.writeFileSection(backup_file, primary_index_path, "primary.idx", .Index);
        }

        // Backup secondary indexes
        for (secondary_index_paths, 0..) |path, i| {
            var idx_name_buf: [256]u8 = undefined;
            const idx_name = try std.fmt.bufPrint(&idx_name_buf, "secondary_{d}.idx", .{i});
            _ = try self.writeFileSection(backup_file, path, idx_name, .SecondaryIndex);
        }

        // Backup WAL
        {
            var wal_path_buf: [512]u8 = undefined;
            const wal_path = try std.fmt.bufPrint(&wal_path_buf, "{s}/{s}", .{ config.base_dir, config.paths.wal });
            _ = try self.writeFileSection(backup_file, wal_path, "wal.log", .WAL);
        }

        // Backup config
        if (config_path) |path| {
            _ = try self.writeFileSection(backup_file, path, "config.yaml", .Config);
        }

        // Update header with final file size
        const final_size = try backup_file.getPos();
        header.total_size = final_size;
        try backup_file.seekTo(header_pos);
        try self.writeHeader(backup_file, header);

        return BackupMetadata{
            .backup_path = try self.allocator.dupe(u8, backup_path),
            .timestamp = timestamp,
            .size_bytes = final_size,
            .vlog_count = @intCast(vlog_files.items.len),
            .entry_count = total_entries,
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

        var total_entries: u64 = 0;
        var vlog_count: u16 = 0;

        // Restore all sections
        var i: u32 = 0;
        while (i < header.component_count) : (i += 1) {
            const section_header = try self.readSectionHeader(backup_file);
            defer self.allocator.free(section_header.file_name);

            const entries = try self.restoreSection(backup_file, section_header, db_path);
            if (section_header.what == .ValueLog) {
                vlog_count += 1;
                total_entries += entries;
            }
        }

        return BackupMetadata{
            .backup_path = try self.allocator.dupe(u8, backup_path),
            .timestamp = header.timestamp,
            .size_bytes = header.total_size,
            .vlog_count = vlog_count,
            .entry_count = total_entries,
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

            try backups.append(self.allocator, BackupMetadata{
                .backup_path = try self.allocator.dupe(u8, full_path),
                .timestamp = header.timestamp,
                .size_bytes = header.total_size,
                .vlog_count = 0, // Will be calculated during restore
                .entry_count = 0, // Will be calculated during restore
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
        var buf: [29]u8 = undefined;

        var offset: usize = 0;
        std.mem.writeInt(u32, buf[offset..][0..4], header.magic, .little);
        offset += 4;
        buf[offset] = header.version;
        offset += 1;
        std.mem.writeInt(i64, buf[offset..][0..8], header.timestamp, .little);
        offset += 8;
        std.mem.writeInt(u32, buf[offset..][0..4], header.component_count, .little);
        offset += 4;
        std.mem.writeInt(u64, buf[offset..][0..8], header.total_size, .little);
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
        const component_count = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;
        const total_size = std.mem.readInt(u64, buf[offset..][0..8], .little);
        offset += 8;
        const compressed = buf[offset] != 0;

        return BackupHeader{
            .magic = magic,
            .version = version,
            .timestamp = timestamp,
            .component_count = component_count,
            .total_size = total_size,
            .compressed = compressed,
        };
    }

    fn writeMetadataSection(self: *BackupManager, backup_file: File, db_path: []const u8, timestamp: i64) !void {
        // Create metadata JSON
        var metadata_buf: [1024]u8 = undefined;
        const metadata_json = try std.fmt.bufPrint(&metadata_buf, "{{\"db_path\":\"{s}\",\"backup_timestamp\":{d},\"version\":\"{s}\"}}", .{ db_path, timestamp, "1.0.0" });

        const section_header = SectionHeader{
            .what = .Metadata,
            .file_name_len = 12, // "metadata.json".len
            .file_name = "metadata.json",
            .original_size = metadata_json.len,
            .compressed_size = metadata_json.len, // No compression for metadata
            .checksum = std.hash.crc.crc32(std.hash.crc.Crc32Ieee.init(), metadata_json),
            .compressed = false,
        };

        try self.writeSectionHeader(backup_file, section_header);
        try backup_file.writeAll(metadata_json);
    }

    fn writeFileSection(self: *BackupManager, backup_file: File, file_path: []const u8, file_name: []const u8, what: What) !u64 {
        // Open source file
        const source_file = Dir.openFile(.cwd(), self.io, file_path, .{ .mode = .read_only }) catch {
            return 0; // File doesn't exist, skip
        };
        defer source_file.close(self.io);

        // Get file size
        const stat = try source_file.stat(self.io);
        const file_size = stat.size;
        if (file_size == 0) return 0;

        // Read file data
        const file_data = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(file_data);
        _ = try source_file.readAll(file_data);

        // Calculate checksum
        const checksum = std.hash.crc.crc32(std.hash.crc.Crc32Ieee.init(), file_data);

        const section_header = SectionHeader{
            .what = what,
            .file_name_len = @intCast(file_name.len),
            .file_name = file_name,
            .original_size = file_size,
            .compressed_size = file_size, // No compression for now
            .checksum = checksum,
            .compressed = false,
        };

        try self.writeSectionHeader(backup_file, section_header);
        try backup_file.writeAll(file_data);

        // For vlogs, count entries (simplified - could be more accurate)
        if (what == .ValueLog) {
            return file_size / 64; // Rough estimate
        }
        return 0;
    }

    fn writeSectionHeader(self: *BackupManager, file: File, header: SectionHeader) !void {
        _ = self;
        // Write fixed part first
        var buf: [SectionHeader.SECTION_HEADER_FIXED_SIZE]u8 = undefined;
        var offset: usize = 0;

        buf[offset] = @intFromEnum(header.what);
        offset += 1;
        std.mem.writeInt(u32, buf[offset..][0..4], header.file_name_len, .little);
        offset += 4;
        std.mem.writeInt(u64, buf[offset..][0..8], header.original_size, .little);
        offset += 8;
        std.mem.writeInt(u64, buf[offset..][0..8], header.compressed_size, .little);
        offset += 8;
        std.mem.writeInt(u32, buf[offset..][0..4], header.checksum, .little);
        offset += 4;
        buf[offset] = if (header.compressed) 1 else 0;

        try file.writeAll(&buf);
        try file.writeAll(header.file_name);
    }

    fn readSectionHeader(self: *BackupManager, file: File) !SectionHeader {
        // Read fixed part
        var buf: [SectionHeader.SECTION_HEADER_FIXED_SIZE]u8 = undefined;
        _ = try file.readAll(&buf);

        var offset: usize = 0;
        const what: What = @enumFromInt(buf[offset]);
        offset += 1;
        const file_name_len = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;
        const original_size = std.mem.readInt(u64, buf[offset..][0..8], .little);
        offset += 8;
        const compressed_size = std.mem.readInt(u64, buf[offset..][0..8], .little);
        offset += 8;
        const checksum = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;
        const compressed = buf[offset] != 0;

        // Read variable filename
        const file_name = try self.allocator.alloc(u8, file_name_len);
        _ = try file.readAll(file_name);

        return SectionHeader{
            .what = what,
            .file_name_len = file_name_len,
            .file_name = file_name,
            .original_size = original_size,
            .compressed_size = compressed_size,
            .checksum = checksum,
            .compressed = compressed,
        };
    }

    fn restoreSection(self: *BackupManager, backup_file: File, section_header: SectionHeader, db_path: []const u8) !u64 {
        // Read section data
        const data_size = section_header.dataSize();
        var section_data = try self.allocator.alloc(u8, data_size);
        defer self.allocator.free(section_data);
        _ = try backup_file.readAll(section_data);

        // Verify checksum (for uncompressed data)
        if (!section_header.compressed) {
            const calculated_checksum = std.hash.crc.crc32(std.hash.crc.Crc32Ieee.init(), section_data);
            if (calculated_checksum != section_header.checksum) {
                return error.ChecksumMismatch;
            }
        }

        // Skip metadata section (already processed)
        if (section_header.what == .Metadata) {
            return 0;
        }

        var target_filename: []u8 = undefined;
        var should_free_filename = false;

        // For vlog files, extract the vlog_id from the file header to create correct filename
        if (section_header.what == .ValueLog) {
            // Vlog header format: magic(4) + version(1) + id(2) + ...
            // Extract id from bytes 5-7
            if (section_data.len < 7) {
                return error.InvalidVlogData;
            }

            const vlog_id = std.mem.readInt(u16, section_data[5..7], .little);

            // Create filename based on the id from the header
            var filename_buf: [64]u8 = undefined;
            const filename = try std.fmt.bufPrint(&filename_buf, "vlog_{d}.db", .{vlog_id});
            target_filename = try self.allocator.dupe(u8, filename);
            should_free_filename = true;
        } else {
            // For non-vlog files, use the filename from section header
            target_filename = try self.allocator.dupe(u8, section_header.file_name);
            should_free_filename = true;
        }
        defer if (should_free_filename) self.allocator.free(target_filename);

        // Create target file path
        var target_path_buf: [512]u8 = undefined;
        const target_path = try std.fmt.bufPrint(&target_path_buf, "{s}/{s}", .{ db_path, target_filename });

        // Create target file
        const target_file = try Dir.createFile(.cwd(), self.io, target_path, .{ .read = false, .truncate = true });
        defer target_file.close(self.io);

        // Write data to target file
        try target_file.writeAll(section_data);

        // Return entry count estimate for vlogs
        if (section_header.what == .ValueLog) {
            return section_data.len / 64; // Rough estimate
        }
        return 0;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "BackupHeader - default values" {
    const header = BackupHeader{
        .timestamp = 1000,
        .component_count = 5,
        .total_size = 1024,
    };

    try std.testing.expectEqual(BACKUP_MAGIC, header.magic);
    try std.testing.expectEqual(BACKUP_VERSION, header.version);
    try std.testing.expectEqual(@as(i64, 1000), header.timestamp);
    try std.testing.expectEqual(@as(u32, 5), header.component_count);
    try std.testing.expectEqual(@as(u64, 1024), header.total_size);
    try std.testing.expectEqual(false, header.compressed);
}

test "BackupHeader - with compression" {
    const header = BackupHeader{
        .timestamp = 2000,
        .component_count = 10,
        .total_size = 2048,
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
        .component_count = std.math.maxInt(u32),
        .total_size = std.math.maxInt(u64),
    };

    try std.testing.expectEqual(std.math.maxInt(i64), header.timestamp);
    try std.testing.expectEqual(std.math.maxInt(u32), header.component_count);
    try std.testing.expectEqual(std.math.maxInt(u64), header.total_size);
}

test "BackupHeader - zero values" {
    const header = BackupHeader{
        .timestamp = 0,
        .component_count = 0,
        .total_size = 0,
    };

    try std.testing.expectEqual(@as(i64, 0), header.timestamp);
    try std.testing.expectEqual(@as(u32, 0), header.component_count);
    try std.testing.expectEqual(@as(u64, 0), header.total_size);
}

test "BackupHeader - negative timestamp" {
    const header = BackupHeader{
        .timestamp = -1000, // Before epoch
        .component_count = 1,
        .total_size = 1,
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
    // Header format: magic(4) + version(1) + timestamp(8) + component_count(4) + total_size(8) + compressed(1) + padding(3) = 29 bytes
    const expected_size: usize = 4 + 1 + 8 + 4 + 8 + 1 + 3;
    try std.testing.expectEqual(@as(usize, 29), expected_size);
}

test "SectionHeader - dataSize method" {
    const uncompressed_header = SectionHeader{
        .what = .ValueLog,
        .file_name_len = 10,
        .file_name = "test.vlog",
        .original_size = 1024,
        .compressed_size = 512,
        .checksum = 12345,
        .compressed = false,
    };
    try std.testing.expectEqual(@as(u64, 1024), uncompressed_header.dataSize());

    const compressed_header = SectionHeader{
        .what = .ValueLog,
        .file_name_len = 10,
        .file_name = "test.vlog",
        .original_size = 1024,
        .compressed_size = 512,
        .checksum = 12345,
        .compressed = true,
    };
    try std.testing.expectEqual(@as(u64, 512), compressed_header.dataSize());
}

test "SectionHeader - What enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(What.Metadata));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(What.ValueLog));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(What.Index));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(What.SecondaryIndex));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(What.WAL));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(What.Config));
}
