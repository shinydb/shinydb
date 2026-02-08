const std = @import("std");

pub const StopWatch = struct {
    start_time: ?std.time.Instant = null,
    total_time: f64 = 0.0,
    total_time_ns: i128 = 0,

    pub fn start(self: *StopWatch) void {
        self.start_time = std.time.Instant.now() catch unreachable;
    }

    pub fn stop(self: *StopWatch) void {
        if (self.start_time) |begin| {
            const end_time = std.time.Instant.now() catch unreachable;
            const duration_ns: i128 = @intCast(end_time.since(begin));
            self.total_time += @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;
            self.total_time_ns += duration_ns;
            self.start_time = null;
        }
    }

    pub fn reset(self: *StopWatch) void {
        self.start_time = null;
        self.total_time = 0.0;
    }
    pub fn elapsed(self: *const StopWatch) f64 {
        return self.total_time;
    }
};

pub const StoreMetrics = struct {
    time_to_finish_operation: StopWatch = .{},
    test_data_gen: StopWatch = .{},
    wal_writes: StopWatch = .{},
    memtable_writes: StopWatch = .{},
    vlog_writes: StopWatch = .{},
    db_flush: StopWatch = .{},
    req_parsing: StopWatch = .{},
    req_processing: StopWatch = .{},
    packet_parsing: StopWatch = .{},
    index_msg_send: StopWatch = .{},
    send_to_index_from_dispatcher: StopWatch = .{},
    index_writes: StopWatch = .{},
    index_searches: StopWatch = .{},
    index_deletes: StopWatch = .{},
    db_reads: StopWatch = .{},
};
