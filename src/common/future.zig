const std = @import("std");

pub fn Future(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        result: ?T = null,
        const Self = @This();

        pub fn wait(self: *Self) T {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.result == null) {
                self.cond.wait(&self.mutex);
            }
            return self.result.?;
        }

        pub fn signal(self: *Self, value: T) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.result = value;
            self.cond.signal();
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self);
        }
    };
}
