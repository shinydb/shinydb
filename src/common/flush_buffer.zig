const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const FlushBuffer = struct {
    pub const FlushBufferError = error{
        OutOfMemory,
        InvalidRange,
    };

    buf: []u8,
    len: usize, // buffer capacity
    pos: usize = 0, // number of bytes used
    read_pos: usize = 0, // number of bytes read
    allocator: std.mem.Allocator,

    pub const Writer = struct {
        context: *FlushBuffer,

        pub fn writeInt(self: Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
            var bytes: [@sizeOf(T)]u8 = undefined;
            switch (endian) {
                .little => std.mem.writeInt(T, &bytes, value, .little),
                .big => std.mem.writeInt(T, &bytes, value, .big),
            }
            _ = try self.context.write(&bytes);
        }

        pub fn writeAll(self: Writer, bytes: []const u8) !void {
            _ = try self.context.write(bytes);
        }
    };

    pub const Reader = struct {
        context: *FlushBuffer,

        pub fn readInt(self: Reader, comptime T: type, endian: std.builtin.Endian) !T {
            var bytes: [@sizeOf(T)]u8 = undefined;
            _ = try self.context.read(&bytes);
            return switch (endian) {
                .little => std.mem.readInt(T, &bytes, .little),
                .big => std.mem.readInt(T, &bytes, .big),
            };
        }

        pub fn readAll(self: Reader, buf: []u8) !void {
            var index: usize = 0;
            while (index < buf.len) {
                const n = try self.context.read(buf[index..]);
                if (n == 0) return error.EndOfStream;
                index += n;
            }
        }
    };

    pub fn init(allocator: Allocator, size: usize) !FlushBuffer {
        const buffer = FlushBuffer{
            .buf = try allocator.alloc(u8, size),
            .len = size,
            .pos = 0,
            .read_pos = 0,
            .allocator = allocator,
        };
        return buffer;
    }

    pub fn deinit(self: *FlushBuffer) void {
        self.allocator.free(self.buf);
        self.buf = &[_]u8{};
        self.len = 0;
        self.pos = 0;
        self.read_pos = 0;
    }

    pub fn reader(self: *FlushBuffer) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *FlushBuffer) Writer {
        // self.pos = self.len;
        return .{ .context = self };
    }

    pub fn write(self: *FlushBuffer, bytes: []const u8) !usize {
        if (self.pos + bytes.len > self.len) return error.OutOfMemory;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
        return bytes.len;
    }

    pub fn read(self: *FlushBuffer, out: []u8) !usize {
        const bytes_available = self.pos - self.read_pos;
        if (bytes_available == 0) {
            return 0;
        }
        const bytes_to_read = @min(out.len, bytes_available);
        @memcpy(out[0..bytes_to_read], self.buf[self.read_pos..][0..bytes_to_read]);
        self.read_pos += bytes_to_read;
        return bytes_to_read;
    }

    pub fn reset(self: *FlushBuffer) void {
        @memset(self.buf, 0);
        self.pos = 0;
        self.read_pos = 0;
    }

    pub fn capacity(self: *FlushBuffer) usize {
        return self.len;
    }

    pub fn used(self: *FlushBuffer) usize {
        return self.pos;
    }

    pub fn slice(self: *FlushBuffer) []u8 {
        return self.buf[0..self.pos];
    }
};

test "FlushBuffer basic usage" {
    const allocator = std.testing.allocator;
    var buf = try FlushBuffer.init(allocator, 16);
    defer buf.deinit();

    // Initially empty
    try std.testing.expectEqual(@as(usize, 0), buf.used());
    try std.testing.expectEqual(@as(usize, 16), buf.capacity());

    // Write some bytes
    _ = try buf.write("hello");
    try std.testing.expectEqual(@as(usize, 5), buf.used());
    try std.testing.expectEqualStrings("hello", buf.slice());

    // Write more bytes
    _ = try buf.write("123");
    try std.testing.expectEqual(@as(usize, 8), buf.used());
    try std.testing.expectEqualStrings("hello123", buf.slice());

    // Read back
    var out: [8]u8 = undefined;
    const n = try buf.read(out[0..]);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualStrings("hello123", out[0..n]);
}

test "FlushBuffer reset zeroes and clears" {
    const allocator = std.testing.allocator;
    var buf = try FlushBuffer.init(allocator, 8);
    defer buf.deinit();

    _ = try buf.write("abcdefg");
    try std.testing.expectEqual(@as(usize, 7), buf.used());
    buf.reset();
    try std.testing.expectEqual(@as(usize, 0), buf.used());
    for (buf.buf) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "FlushBuffer out of memory" {
    const allocator = std.testing.allocator;
    var buf = try FlushBuffer.init(allocator, 4);
    defer buf.deinit();

    _ = try buf.write("abcd");
    const result = buf.write("e");
    try std.testing.expectError(error.OutOfMemory, result);
}

test "FlushBuffer read partial" {
    const allocator = std.testing.allocator;
    var buf = try FlushBuffer.init(allocator, 10);
    defer buf.deinit();

    _ = try buf.write("abcdef");
    buf.read_pos = 0;
    var out: [3]u8 = undefined;
    const n1 = try buf.read(out[0..]);
    try std.testing.expectEqual(@as(usize, 3), n1);
    try std.testing.expectEqualStrings("abc", out[0..n1]);
    const n2 = try buf.read(out[0..]);
    try std.testing.expectEqual(@as(usize, 3), n2);
    try std.testing.expectEqualStrings("def", out[0..n2]);
    const n3 = try buf.read(out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n3);
}
test "FlushBuffer read beyond end" {
    const allocator = std.testing.allocator;
    var buf = try FlushBuffer.init(allocator, 10);
    defer buf.deinit();

    _ = try buf.write("abc");
    buf.read_pos = 0;
    var out: [5]u8 = undefined;
    const n = try buf.read(out[0..]);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("abc", out[0..n]);
}
