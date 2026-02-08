const std = @import("std");

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const Logger = struct {
    allocator: std.mem.Allocator,
    file: ?std.fs.File,
    level: LogLevel,
    path: []const u8,
    max_size: usize,
    current_size: usize,
    
    pub fn init(allocator: std.mem.Allocator, path: []const u8, level: LogLevel) !Logger {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = false, .read = false });
        const stat = try std.fs.cwd().statFile(path);
        return Logger{
            .allocator = allocator,
            .file = file,
            .level = level,
            .path = path,
            .max_size = 1024 * 1024 * 2, // 2MB default
            .current_size = stat.size,
        };
    }

    fn log(self: *Logger, level: LogLevel, msg: []const u8) !void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) return;
        if (self.file) |file| {
            const timestamp = try std.time.timestamp();
            const log_line = std.fmt.allocPrint(
                self.allocator,
                "[{d}] [{s}] {s}\n",
                .{ timestamp, @tagName(level), msg }
            ) catch return;
            defer self.allocator.free(log_line);
            try file.writeAll(log_line);
            self.current_size += log_line.len;
            try file.flush();
            if (self.current_size >= self.max_size) {
                file.close();
                // Roll file: rename current, open new
                const rolled_path = std.fmt.allocPrint(
                    self.allocator,
                    "{s}.{d}",
                    .{ self.path, timestamp }
                ) catch return;
                defer self.allocator.free(rolled_path);
                try std.fs.cwd().rename(self.path, rolled_path);
                self.file = try std.fs.cwd().createFile(self.path, .{ .truncate = true, .read = false });
                self.current_size = 0;
            }
        }
    }

    pub fn close(self: *Logger) void {
        if (self.file) |file| {
            file.close();
            self.file = null;
        }
    }

    pub fn info(self: *Logger, msg: []const u8) !void {
        try self.log(LogLevel.info, msg);
    }

    pub fn err(self: *Logger, msg: []const u8) !void {
        try self.log(LogLevel.err, msg);
    }

    pub fn debug(self: *Logger, msg: []const u8) !void {
        try self.log(LogLevel.debug, msg);
    }

    pub fn warn(self: *Logger, msg: []const u8) !void {
        try self.log(LogLevel.warn, msg);
    }
};
