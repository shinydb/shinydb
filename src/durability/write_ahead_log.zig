const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const crc32 = std.hash.Crc32;
const json = std.json;

const LogRecordKind = @import("../common/common.zig").LogRecordKind;
const LogRecord = @import("../common/common.zig").LogRecord;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;
const FlushBuffer = @import("../common/flush_buffer.zig").FlushBuffer;

pub const WalConfig = struct {
    dir_path: []const u8,
    max_file_size: usize,
    max_buffer_size: usize,
    flush_interval_in_ms: u64,
    io: Io,

    // Group commit settings (for improved write throughput)
    /// Maximum number of writes to accumulate before forcing sync (0 = sync every flush)
    group_commit_count: u32 = 0,
    /// Maximum milliseconds to wait before forcing sync (0 = sync every flush)
    group_commit_interval_ms: u64 = 0,
};

const CheckpointRecord = struct {
    checkpoint_seq: u64,
    const CHECKPOINT_FILENAME = "CHECKPOINT";

    pub fn load(allocator: mem.Allocator, io: Io, dir_path: []const u8) !CheckpointRecord {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const checkpoint_path = fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, CHECKPOINT_FILENAME }) catch return CheckpointRecord{ .checkpoint_seq = 0 };
        const data = Dir.readFileAlloc(.cwd(), io, checkpoint_path, allocator, @enumFromInt(100)) catch |err| {
            if (err == error.FileNotFound) return CheckpointRecord{ .checkpoint_seq = 0 };
            return err;
        };
        defer allocator.free(data);
        const gpa = std.heap.page_allocator;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const parsed = try std.json.parseFromSlice(CheckpointRecord, arena.allocator(), data, .{});
        return parsed.value;
    }

    pub fn save(self: CheckpointRecord, allocator: mem.Allocator, io: Io, dir_path: []const u8) !void {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try fmt.bufPrint(&path_buf, "{s}/CHECKPOINT.tmp", .{dir_path});

        // Serialize to buffer (simple JSON for checkpoint)
        var buf: [128]u8 = undefined;
        const data = try fmt.bufPrint(&buf, "{{\"checkpoint_seq\":{}}}", .{self.checkpoint_seq});

        // Write to temp file
        var file = try Dir.createFile(.cwd(), io, tmp_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, data);
        try file.sync(io);

        // Rename temp to final
        var final_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const final_path = try fmt.bufPrint(&final_path_buf, "{s}/{s}", .{ dir_path, CHECKPOINT_FILENAME });
        try Dir.rename(.cwd(), tmp_path, .cwd(), final_path, io);
        _ = allocator;
    }
};

pub const ReplayResult = struct {
    arena: *std.heap.ArenaAllocator,
    records: []const LogRecord,
};

pub const WriteAheadLog = struct {
    allocator: mem.Allocator,
    io: Io,
    dir_path: []const u8,
    current_seq: u64,
    current_file: ?File,
    buffer: FlushBuffer,
    max_buffer_size: usize,
    max_file_size: usize,
    file_size: usize = 0,

    // Group commit state
    group_commit_count: u32,
    group_commit_interval_ms: u64,
    pending_writes: u32 = 0,
    last_sync_time: i64 = 0,
    needs_sync: bool = false,

    const WalError = error{
        OpenFileFailed,
        WriteFailed,
        SyncFailed,
        CreateDirFailed,
        InvalidFileName,
        TruncateFailed,
        SeekFailed,
        GetPathFailed,
        FileTooLarge,
        ChecksumMismatch,
        ReplayFailed,
        RecordTooLarge,
        InvalidRecordLength,
        FileNotFound,
        PathAlreadyExists,
        AccessDenied,
        OutOfMemory,
        EndOfStream,
        Unexpected,
        FileTooBig,
        NoDevice,
        SystemResources,
        DeviceBusy,
        DiskQuota,
        NoSpaceLeft,
        WouldBlock,
        InputOutput,
        InvalidArgument,
        BrokenPipe,
        OperationAborted,
        NotOpenForWriting,
        LockViolation,
        ConnectionResetByPeer,
        ProcessNotFound,
        SymLinkLoop,
        ProcessFdQuotaExceeded,
        NameTooLong,
        SystemFdQuotaExceeded,
        FileBusy,
        NotDir,
        InvalidUtf8,
        InvalidWtf8,
        BadPathName,
        NetworkNotFound,
        SharingViolation,
        Canceled,
        PermissionDenied,
        FileLocksUnsupported,
        PipeBusy,
        AntivirusInterference,
        IsDir,
        FileLocksNotSupported,
        ReadOnlyFileSystem,
        LinkQuotaExceeded,
        RenameAcrossMountPoints,
        FileSystem,
    };

    pub fn init(allocator: mem.Allocator, config: WalConfig) !*WriteAheadLog {
        const io = config.io;

        // Ensure WAL directory exists
        Dir.createDirPath(.cwd(), io, config.dir_path) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        var self = try allocator.create(WriteAheadLog);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .dir_path = try allocator.dupe(u8, config.dir_path),
            .current_seq = 0,
            .current_file = null,
            .buffer = try FlushBuffer.init(allocator, config.max_buffer_size),
            .max_buffer_size = config.max_buffer_size,
            .max_file_size = config.max_file_size,
            .group_commit_count = config.group_commit_count,
            .group_commit_interval_ms = config.group_commit_interval_ms,
            .last_sync_time = milliTimestamp(),
        };

        // Scan directory for existing WAL files
        var max_seq: u64 = 0;
        var found_file = false;

        if (Dir.openDir(.cwd(), io, self.dir_path, .{ .iterate = true })) |dir| {
            var wal_dir = dir;
            defer wal_dir.close(io);
            var dir_iter = wal_dir.iterate();
            while (dir_iter.next(io) catch null) |entry| {
                if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wal")) {
                    const seq_str = entry.name[0 .. entry.name.len - 4];
                    const seq = fmt.parseUnsigned(u64, seq_str, 10) catch continue;
                    if (!found_file or seq > max_seq) {
                        max_seq = seq;
                    }
                    found_file = true;
                }
            }
        } else |_| {}

        if (found_file) {
            self.current_seq = max_seq;
            const file_path = try self.getFilePath(self.current_seq);
            defer self.allocator.free(file_path);
            self.current_file = Dir.openFile(.cwd(), io, file_path, .{ .mode = .read_write }) catch null;
            if (self.current_file) |file| {
                // Seek to end by getting file size
                const stat = file.stat(io) catch null;
                if (stat) |s| {
                    self.file_size = s.size;
                }
            }
        } else {
            self.current_seq = 0;
            self.current_file = null;
        }
        return self;
    }

    pub fn deinit(self: *WriteAheadLog) WalError!void {
        // std.debug.print("WAL: deinit start\n", .{});
        try self.flush();
        if (self.current_file) |file| {
            // std.debug.print("WAL: closing file\n", .{});
            file.close(self.io);
        }
        // std.debug.print("WAL: buffer deinit\n", .{});
        self.buffer.deinit();
        // std.debug.print("WAL: freeing dir_path\n", .{});
        self.allocator.free(self.dir_path);
        // std.debug.print("WAL: destroying struct\n", .{});
        self.allocator.destroy(self);
        // std.debug.print("WAL: deinit end\n", .{});
    }

    fn getFilePath(self: *WriteAheadLog, seq: u64) ![]u8 {
        return try fmt.allocPrint(self.allocator, "{s}/{d:0>6}.wal", .{ self.dir_path, seq });
    }

    /// Write buffer to disk WITHOUT fsync (for group commits)
    fn flushBuffer(self: *WriteAheadLog) WalError!void {
        if (self.buffer.pos == 0) {
            return;
        }
        if (self.current_file == null) {
            try self.rotate();
        }
        var file = self.current_file.?;
        try file.writeStreamingAll(self.io, self.buffer.slice());
        self.buffer.reset();
        self.needs_sync = true;
    }

    /// Perform fsync on the current WAL file
    pub fn sync(self: *WriteAheadLog) WalError!void {
        if (!self.needs_sync) return;
        if (self.current_file) |file| {
            try file.sync(self.io);
            self.needs_sync = false;
            self.pending_writes = 0;
            self.last_sync_time = milliTimestamp();
        }
    }

    /// Check if we should sync based on group commit thresholds
    fn shouldSync(self: *WriteAheadLog) bool {
        // If group commit is disabled (both thresholds are 0), always sync
        if (self.group_commit_count == 0 and self.group_commit_interval_ms == 0) {
            return true;
        }
        // Sync if we've accumulated enough writes
        if (self.group_commit_count > 0 and self.pending_writes >= self.group_commit_count) {
            return true;
        }
        // Sync if enough time has passed since last sync
        if (self.group_commit_interval_ms > 0) {
            const now = milliTimestamp();
            const elapsed = @as(u64, @intCast(@max(0, now - self.last_sync_time)));
            if (elapsed >= self.group_commit_interval_ms) {
                return true;
            }
        }
        return false;
    }

    /// Flush with group commit logic (sync based on thresholds)
    pub fn flushGrouped(self: *WriteAheadLog) WalError!void {
        try self.flushBuffer();
        if (self.shouldSync()) {
            try self.sync();
        }
    }

    /// Flush and sync immediately (for callers that need guaranteed durability)
    pub fn flush(self: *WriteAheadLog) WalError!void {
        try self.flushBuffer();
        try self.sync();
    }

    /// Append a record using group commit (may defer sync)
    pub fn append(self: *WriteAheadLog, record: LogRecord) !void {
        if (self.buffer.pos + record.size() >= self.max_buffer_size) {
            try self.flushGrouped();
        }

        if (self.file_size >= self.max_file_size) {
            try self.flushGrouped();
            try self.rotate();
        }

        try LogRecord.serialize(record, self.buffer.writer());
        self.file_size += record.size();
        self.pending_writes += 1;

        // Check if we should sync based on thresholds
        if (self.shouldSync()) {
            try self.flushGrouped();
        }
    }

    /// Append and immediately flush+sync (for critical operations)
    pub fn appendAndSync(self: *WriteAheadLog, record: LogRecord) !void {
        try LogRecord.serialize(record, self.buffer.writer());
        self.file_size += record.size();
        try self.flush();
    }

    pub fn rotate(self: *WriteAheadLog) WalError!void {
        // Ensure any pending data is synced before rotating
        try self.sync();
        if (self.current_file) |file| {
            file.close(self.io);
        }
        self.current_seq += 1;
        const file_path = try self.getFilePath(self.current_seq);
        defer self.allocator.free(file_path);
        self.current_file = try Dir.createFile(.cwd(), self.io, file_path, .{ .read = true, .truncate = false });
        self.file_size = 0;
        self.needs_sync = false;
    }

    pub fn checkpoint(self: *WriteAheadLog) WalError!void {
        try self.flush();
        const cp = CheckpointRecord{ .checkpoint_seq = if (self.current_file == null) 0 else self.current_seq };
        try cp.save(self.allocator, self.io, self.dir_path);
        try self.rotate();
        // Debug: std.log.info("WAL Checkpoint created and rotated to seq {d}", .{self.current_seq});
    }

    pub fn truncate(self: *WriteAheadLog) WalError!void {
        const cp = CheckpointRecord.load(self.allocator, self.io, self.dir_path) catch return;
        if (cp.checkpoint_seq == 0) return;
        // Debug: std.log.info("WAL Truncating logs before seq: {d}", .{cp.checkpoint_seq});
        var wal_dir = Dir.openDir(.cwd(), self.io, self.dir_path, .{ .iterate = true }) catch return;
        defer wal_dir.close(self.io);
        var dir_iter = wal_dir.iterate();
        while (dir_iter.next(self.io) catch null) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wal")) {
                const seq_str = entry.name[0 .. entry.name.len - 4];
                const seq = fmt.parseUnsigned(u64, seq_str, 10) catch continue;
                if (seq < cp.checkpoint_seq) {
                    // Debug: std.log.info("Deleting obsolete WAL file: {s}", .{entry.name});
                    const file_path = self.getFilePath(seq) catch continue;
                    defer self.allocator.free(file_path);
                    Dir.deleteFile(.cwd(), self.io, file_path) catch {};
                }
            }
        }
    }
    /// Note: The returned LogRecord's value slice is owned by the caller and must be freed.
    fn replayFile(self: *WriteAheadLog, seq: u64, list: *std.ArrayList(LogRecord), allocator: mem.Allocator) !void {
        const file_path = try self.getFilePath(seq);
        defer self.allocator.free(file_path);
        var file = try Dir.openFile(.cwd(), self.io, file_path, .{});
        defer file.close(self.io);

        // Read entire file content
        const stat = try file.stat(self.io);
        const content = try allocator.alloc(u8, stat.size);
        defer allocator.free(content);
        _ = try file.readPositionalAll(self.io, content, 0);

        // Parse records from buffer
        var offset: usize = 0;
        while (offset < content.len) {
            // Create a simple reader interface from the buffer
            const BufferReader = struct {
                buffer: []const u8,
                pos: usize,

                pub fn readInt(r: *@This(), comptime T: type, endian: std.builtin.Endian) !T {
                    const size = @sizeOf(T);
                    if (r.pos + size > r.buffer.len) return error.EndOfStream;
                    const value = std.mem.readInt(T, r.buffer[r.pos..][0..size], endian);
                    r.pos += size;
                    return value;
                }

                pub fn readAll(r: *@This(), buf: []u8) !void {
                    if (r.pos + buf.len > r.buffer.len) return error.EndOfStream;
                    @memcpy(buf, r.buffer[r.pos..][0..buf.len]);
                    r.pos += buf.len;
                }
            };

            var reader = BufferReader{ .buffer = content[offset..], .pos = 0 };
            const record_result = LogRecord.deserialize(allocator, &reader) catch |err| {
                // Handle incomplete records at end of WAL file gracefully
                // This happens when server crashes before completing a write
                if (err == error.InvalidRecordLength or err == error.ChecksumMismatch) {
                    // Treat as end of valid data - partial write during crash
                    break;
                }
                return err;
            };
            if (record_result) |record| {
                try list.append(allocator, record);
                offset += record.size();
            } else {
                break; // Clean EndOfStream for this file.
            }
        }
    }

    pub fn replay(self: *WriteAheadLog) !ReplayResult {
        try self.flush();
        const gpa = std.heap.page_allocator;
        var arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        var records_list: std.ArrayList(LogRecord) = .empty;
        const cp = try CheckpointRecord.load(self.allocator, self.io, self.dir_path);
        var seq = cp.checkpoint_seq;
        if (seq == 0) seq = 1;
        while (seq <= self.current_seq) : (seq += 1) {
            self.replayFile(seq, &records_list, arena.allocator()) catch |err| {
                if (err == error.FileNotFound) {
                    break;
                }
                return err;
            };
        }
        return ReplayResult{
            .arena = arena,
            .records = try records_list.toOwnedSlice(arena.allocator()),
        };
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

// NOTE: WAL tests require file system operations and have been moved to
// tests/integration_test.zig for proper end-to-end testing.
// The tests here were using outdated APIs that have been updated in Zig 0.16.
