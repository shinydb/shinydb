const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;
const Order = std.math.Order;

pub const MemoryPoolConfig = struct {
    /// Initial chunk size in bytes
    initial_chunk_size: usize = 64 * 1024, // 64KB
    /// Maximum chunk size before we stop growing
    max_chunk_size: usize = 1024 * 1024, // 1MB
    /// Growth factor for new chunks
    growth_factor: f32 = 1.5,
    /// Alignment for allocations
    alignment: u29 = @alignOf(usize),
};

const MemoryChunk = struct {
    data: []u8,
    used: usize,

    const Self = @This();

    fn init(allocator: Allocator, size: usize) !Self {
        const data = try allocator.alloc(u8, size);
        return Self{
            .data = data,
            .used = 0,
        };
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }

    fn remaining(self: *const Self) usize {
        return self.data.len - self.used;
    }

    fn allocate(self: *Self, size: usize, alignment: u29) ?[]u8 {
        const current_addr = @intFromPtr(self.data.ptr) + self.used;
        const aligned_addr = std.mem.alignForward(usize, current_addr, alignment);
        const aligned_offset = aligned_addr - @intFromPtr(self.data.ptr);
        const end_pos = aligned_offset + size;

        if (end_pos > self.data.len) {
            return null; // Not enough space
        }

        const result = self.data[aligned_offset..end_pos];
        self.used = end_pos;
        return result;
    }
};

/// Memory pool for skiplist nodes
pub const MemoryPool = struct {
    allocator: Allocator,
    chunks: ArrayList(MemoryChunk),
    config: MemoryPoolConfig,
    current_chunk_size: usize,
    total_allocated: usize,

    const Self = @This();

    pub fn init(allocator: Allocator, config: MemoryPoolConfig) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .chunks = .empty,
            .config = config,
            .current_chunk_size = config.initial_chunk_size,
            .total_allocated = 0,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.releaseAll();
        self.chunks.deinit(self.allocator);
    }

    /// Release all memory chunks - call this when flushing to disk
    pub fn releaseAll(self: *Self) void {
        for (self.chunks.items) |*chunk| {
            chunk.deinit(self.allocator);
        }
        self.chunks.clearAndFree(self.allocator);
        self.current_chunk_size = self.config.initial_chunk_size;
        self.total_allocated = 0;
    }

    /// Allocate memory from the pool
    pub fn alloc(self: *Self, comptime T: type, n: usize) ![]T {
        const size = @sizeOf(T) * n;
        const alignment = @alignOf(T);

        // Try to allocate from existing chunks first
        for (self.chunks.items) |*chunk| {
            if (chunk.allocate(size, alignment)) |memory| {
                // Verify alignment is correct
                std.debug.assert(@intFromPtr(memory.ptr) % @alignOf(T) == 0);
                // Cast to the proper pointer type
                const typed_ptr: [*]T = @ptrCast(@alignCast(memory.ptr));
                return typed_ptr[0..n];
            }
        }

        // Need a new chunk
        const chunk_size = @max(self.current_chunk_size, size * 2);
        var new_chunk = try MemoryChunk.init(self.allocator, chunk_size);

        // Allocate from the new chunk
        const memory = new_chunk.allocate(size, alignment) orelse {
            new_chunk.deinit(self.allocator);
            return error.OutOfMemory;
        };

        try self.chunks.append(self.allocator, new_chunk);

        // Grow chunk size for next time
        if (self.current_chunk_size < self.config.max_chunk_size) {
            self.current_chunk_size = @min(@as(usize, @intFromFloat(@as(f32, @floatFromInt(self.current_chunk_size)) * self.config.growth_factor)), self.config.max_chunk_size);
        }

        self.total_allocated += chunk_size;

        // Verify alignment is correct
        std.debug.assert(@intFromPtr(memory.ptr) % @alignOf(T) == 0);
        // Cast to the proper pointer type
        const typed_ptr: [*]T = @ptrCast(@alignCast(memory.ptr));
        return typed_ptr[0..n];
    }

    /// Allocate a single item
    pub fn create(self: *Self, comptime T: type) !*T {
        const slice = try self.alloc(T, 1);
        return &slice[0];
    }

    /// Get memory usage statistics
    pub fn getStats(self: *const Self) MemoryStats {
        var used: usize = 0;
        var largest: usize = 0;
        var smallest: usize = std.math.maxInt(usize);
        var total_utilization: f64 = 0;

        for (self.chunks.items) |chunk| {
            used += chunk.used;
            largest = @max(largest, chunk.data.len);
            smallest = @min(smallest, chunk.data.len);

            if (chunk.data.len > 0) {
                total_utilization += @as(f64, @floatFromInt(chunk.used)) / @as(f64, @floatFromInt(chunk.data.len));
            }
        }

        if (self.chunks.items.len == 0) {
            smallest = 0;
        }

        const avg_utilization = if (self.chunks.items.len > 0)
            total_utilization / @as(f64, @floatFromInt(self.chunks.items.len))
        else
            0.0;

        return MemoryStats{
            .total_allocated = self.total_allocated,
            .total_used = used,
            .chunk_count = self.chunks.items.len,
            .largest_chunk = largest,
            .smallest_chunk = smallest,
            .average_chunk_utilization = avg_utilization,
        };
    }

    /// Reset the pool without deallocating chunks (for reuse after flush)
    pub fn reset(self: *Self) void {
        for (self.chunks.items) |*chunk| {
            chunk.used = 0;
        }
    }
};

pub const MemoryStats = struct {
    total_allocated: usize,
    total_used: usize,
    chunk_count: usize,
    largest_chunk: usize,
    smallest_chunk: usize,
    average_chunk_utilization: f64,

    pub fn efficiency(self: *const MemoryStats) f64 {
        if (self.total_allocated == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_used)) / @as(f64, @floatFromInt(self.total_allocated));
    }

    pub fn print(self: *const MemoryStats) void {
        std.log.info("Memory Stats:", .{});
        std.log.info("  Total allocated: {} bytes ({} MB)", .{ self.total_allocated, self.total_allocated / (1024 * 1024) });
        std.log.info("  Total used: {} bytes ({} MB)", .{ self.total_used, self.total_used / (1024 * 1024) });
        std.log.info("  Chunks: {}", .{self.chunk_count});
        std.log.info("  Efficiency: {d:.1}%", .{self.efficiency() * 100});
        std.log.info("  Avg utilization: {d:.1}%", .{self.average_chunk_utilization * 100});
        std.log.info("  Largest chunk: {} bytes", .{self.largest_chunk});
        std.log.info("  Smallest chunk: {} bytes", .{self.smallest_chunk});
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "MemoryPoolConfig - defaults" {
    const config = MemoryPoolConfig{};
    try testing.expectEqual(@as(usize, 64 * 1024), config.initial_chunk_size);
    try testing.expectEqual(@as(usize, 1024 * 1024), config.max_chunk_size);
    try testing.expectApproxEqAbs(@as(f32, 1.5), config.growth_factor, 0.001);
    try testing.expectEqual(@as(u29, @alignOf(usize)), config.alignment);
}

test "MemoryChunk - init and remaining" {
    const allocator = testing.allocator;
    var chunk = try MemoryChunk.init(allocator, 1024);
    defer chunk.deinit(allocator);

    try testing.expectEqual(@as(usize, 1024), chunk.remaining());
    try testing.expectEqual(@as(usize, 0), chunk.used);
    try testing.expectEqual(@as(usize, 1024), chunk.data.len);
}

test "MemoryChunk - allocate consumes space" {
    const allocator = testing.allocator;
    var chunk = try MemoryChunk.init(allocator, 1024);
    defer chunk.deinit(allocator);

    const mem1 = chunk.allocate(100, 1);
    try testing.expect(mem1 != null);
    try testing.expectEqual(@as(usize, 100), mem1.?.len);
    try testing.expectEqual(@as(usize, 924), chunk.remaining());

    const mem2 = chunk.allocate(200, 1);
    try testing.expect(mem2 != null);
    try testing.expectEqual(@as(usize, 724), chunk.remaining());
}

test "MemoryChunk - allocate returns null when full" {
    const allocator = testing.allocator;
    var chunk = try MemoryChunk.init(allocator, 100);
    defer chunk.deinit(allocator);

    // Allocate more than available
    const mem = chunk.allocate(200, 1);
    try testing.expect(mem == null);
}

test "MemoryChunk - allocate respects alignment" {
    const allocator = testing.allocator;
    var chunk = try MemoryChunk.init(allocator, 1024);
    defer chunk.deinit(allocator);

    // Allocate 1 byte first
    _ = chunk.allocate(1, 1);

    // Now allocate with 8-byte alignment
    const mem = chunk.allocate(16, 8);
    try testing.expect(mem != null);
    try testing.expectEqual(@as(usize, 0), @intFromPtr(mem.?.ptr) % 8);
}

test "MemoryPool - init and deinit" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{});
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    try testing.expectEqual(@as(usize, 0), pool.chunks.items.len);
    try testing.expectEqual(@as(usize, 0), pool.total_allocated);
}

test "MemoryPool - alloc creates chunks" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    const data = try pool.alloc(u8, 100);
    try testing.expectEqual(@as(usize, 100), data.len);
    try testing.expectEqual(@as(usize, 1), pool.chunks.items.len);
}

test "MemoryPool - alloc reuses chunks" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    // Multiple small allocations should fit in one chunk
    _ = try pool.alloc(u8, 100);
    _ = try pool.alloc(u8, 100);
    _ = try pool.alloc(u8, 100);

    try testing.expectEqual(@as(usize, 1), pool.chunks.items.len);
}

test "MemoryPool - alloc grows chunks" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 100,
        .max_chunk_size = 500,
        .growth_factor = 2.0,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    // First allocation creates a chunk
    _ = try pool.alloc(u8, 50);
    try testing.expectEqual(@as(usize, 1), pool.chunks.items.len);

    // Second allocation that doesn't fit forces a new chunk
    // Need to allocate more than remaining space in first chunk
    _ = try pool.alloc(u8, 60);
    _ = try pool.alloc(u8, 60); // This should force a second chunk

    // Should have at least 2 chunks now (might be more depending on alignment)
    try testing.expect(pool.chunks.items.len >= 2);
    // Verify chunk size grew
    try testing.expect(pool.current_chunk_size > 100);
}

test "MemoryPool - create allocates single item" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    const TestStruct = struct {
        a: u32,
        b: u64,
        c: bool,
    };

    const item = try pool.create(TestStruct);
    item.* = .{ .a = 42, .b = 123456789, .c = true };

    try testing.expectEqual(@as(u32, 42), item.a);
    try testing.expectEqual(@as(u64, 123456789), item.b);
    try testing.expect(item.c);
}

test "MemoryPool - getStats returns correct values" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    // Initially empty
    var stats = pool.getStats();
    try testing.expectEqual(@as(usize, 0), stats.chunk_count);
    try testing.expectEqual(@as(usize, 0), stats.total_allocated);
    try testing.expectEqual(@as(usize, 0), stats.total_used);

    // After allocation
    _ = try pool.alloc(u8, 100);
    stats = pool.getStats();
    try testing.expectEqual(@as(usize, 1), stats.chunk_count);
    try testing.expect(stats.total_allocated >= 1024);
    try testing.expect(stats.total_used >= 100);
}

test "MemoryPool - reset clears usage but keeps chunks" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    _ = try pool.alloc(u8, 100);
    const chunks_before = pool.chunks.items.len;

    pool.reset();

    try testing.expectEqual(chunks_before, pool.chunks.items.len);
    // All chunks should have used = 0
    for (pool.chunks.items) |chunk| {
        try testing.expectEqual(@as(usize, 0), chunk.used);
    }
}

test "MemoryPool - releaseAll frees all memory" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 1024,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    _ = try pool.alloc(u8, 100);
    _ = try pool.alloc(u8, 2000); // Force new chunk

    pool.releaseAll();

    try testing.expectEqual(@as(usize, 0), pool.chunks.items.len);
    try testing.expectEqual(@as(usize, 0), pool.total_allocated);
}

test "MemoryStats - efficiency calculation" {
    const stats = MemoryStats{
        .total_allocated = 1000,
        .total_used = 750,
        .chunk_count = 1,
        .largest_chunk = 1000,
        .smallest_chunk = 1000,
        .average_chunk_utilization = 0.75,
    };

    try testing.expectApproxEqAbs(@as(f64, 0.75), stats.efficiency(), 0.001);
}

test "MemoryStats - efficiency with zero allocation" {
    const stats = MemoryStats{
        .total_allocated = 0,
        .total_used = 0,
        .chunk_count = 0,
        .largest_chunk = 0,
        .smallest_chunk = 0,
        .average_chunk_utilization = 0.0,
    };

    try testing.expectEqual(@as(f64, 0.0), stats.efficiency());
}
