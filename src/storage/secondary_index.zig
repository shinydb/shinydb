const std = @import("std");
const Index = @import("bptree.zig").Index;
const IndexConfig = @import("bptree.zig").IndexConfig;
const Allocator = std.mem.Allocator;

/// Composite key for string-based secondary indexes
/// Stores field_value + primary_key to ensure uniqueness
pub const StringCompositeKey = struct {
    field_value_hash: u64,  // Hash of the string for efficient comparison
    primary_key: u128,

    pub fn init(field_value: []const u8, primary_key: u128) StringCompositeKey {
        return .{
            .field_value_hash = std.hash.Wyhash.hash(0, field_value),
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: StringCompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= @sizeOf(StringCompositeKey));
        std.mem.writeInt(u64, buf[0..8], self.field_value_hash, .little);
        std.mem.writeInt(u128, buf[8..24], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) StringCompositeKey {
        std.debug.assert(buf.len >= @sizeOf(StringCompositeKey));
        return .{
            .field_value_hash = std.mem.readInt(u64, buf[0..8], .little),
            .primary_key = std.mem.readInt(u128, buf[8..24], .little),
        };
    }
};

/// Composite key for u64-based secondary indexes
pub const U64CompositeKey = struct {
    field_value: u64,
    primary_key: u128,

    pub fn init(field_value: u64, primary_key: u128) U64CompositeKey {
        return .{
            .field_value = field_value,
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: U64CompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= @sizeOf(U64CompositeKey));
        std.mem.writeInt(u64, buf[0..8], self.field_value, .little);
        std.mem.writeInt(u128, buf[8..24], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) U64CompositeKey {
        std.debug.assert(buf.len >= @sizeOf(U64CompositeKey));
        return .{
            .field_value = std.mem.readInt(u64, buf[0..8], .little),
            .primary_key = std.mem.readInt(u128, buf[8..24], .little),
        };
    }
};

/// Composite key for i64-based secondary indexes
pub const I64CompositeKey = struct {
    field_value: i64,
    primary_key: u128,

    pub fn init(field_value: i64, primary_key: u128) I64CompositeKey {
        return .{
            .field_value = field_value,
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: I64CompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= @sizeOf(I64CompositeKey));
        std.mem.writeInt(i64, buf[0..8], self.field_value, .little);
        std.mem.writeInt(u128, buf[8..24], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) I64CompositeKey {
        std.debug.assert(buf.len >= @sizeOf(I64CompositeKey));
        return .{
            .field_value = std.mem.readInt(i64, buf[0..8], .little),
            .primary_key = std.mem.readInt(u128, buf[8..24], .little),
        };
    }
};

/// Composite key for u32-based secondary indexes
pub const U32CompositeKey = struct {
    field_value: u32,
    primary_key: u128,

    pub fn init(field_value: u32, primary_key: u128) U32CompositeKey {
        return .{
            .field_value = field_value,
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: U32CompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= 20); // 4 + 16
        std.mem.writeInt(u32, buf[0..4], self.field_value, .little);
        std.mem.writeInt(u128, buf[4..20], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) U32CompositeKey {
        std.debug.assert(buf.len >= 20);
        return .{
            .field_value = std.mem.readInt(u32, buf[0..4], .little),
            .primary_key = std.mem.readInt(u128, buf[4..20], .little),
        };
    }
};

/// Composite key for i32-based secondary indexes
pub const I32CompositeKey = struct {
    field_value: i32,
    primary_key: u128,

    pub fn init(field_value: i32, primary_key: u128) I32CompositeKey {
        return .{
            .field_value = field_value,
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: I32CompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= 20); // 4 + 16
        std.mem.writeInt(i32, buf[0..4], self.field_value, .little);
        std.mem.writeInt(u128, buf[4..20], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) I32CompositeKey {
        std.debug.assert(buf.len >= 20);
        return .{
            .field_value = std.mem.readInt(i32, buf[0..4], .little),
            .primary_key = std.mem.readInt(u128, buf[4..20], .little),
        };
    }
};

/// Composite key for boolean-based secondary indexes
pub const BoolCompositeKey = struct {
    field_value: bool,
    primary_key: u128,

    pub fn init(field_value: bool, primary_key: u128) BoolCompositeKey {
        return .{
            .field_value = field_value,
            .primary_key = primary_key,
        };
    }

    pub fn toBytes(self: BoolCompositeKey, buf: []u8) void {
        std.debug.assert(buf.len >= 17); // 1 + 16
        buf[0] = if (self.field_value) 1 else 0;
        std.mem.writeInt(u128, buf[1..17], self.primary_key, .little);
    }

    pub fn fromBytes(buf: []const u8) BoolCompositeKey {
        std.debug.assert(buf.len >= 17);
        return .{
            .field_value = buf[0] != 0,
            .primary_key = std.mem.readInt(u128, buf[1..17], .little),
        };
    }
};

/// Secondary index type wrapping different composite key types
pub const SecondaryIndexType = enum {
    string,
    u64_type,
    i64_type,
    u32_type,
    i32_type,
    bool_type,
};

/// Generic secondary index wrapper
pub const SecondaryIndex = struct {
    index_type: SecondaryIndexType,
    field_name: []const u8,

    // Only one of these will be non-null based on index_type
    string_index: ?*Index(u64, u128) = null,  // Hash of string → primary_key
    u64_index: ?*Index(u64, u128) = null,
    i64_index: ?*Index(i64, u128) = null,
    u32_index: ?*Index(u32, u128) = null,
    i32_index: ?*Index(i32, u128) = null,
    bool_index: ?*Index(u8, u128) = null,  // 0 or 1 → primary_key

    pub fn deinit(self: *SecondaryIndex) void {
        switch (self.index_type) {
            .string => if (self.string_index) |idx| idx.deinit(),
            .u64_type => if (self.u64_index) |idx| idx.deinit(),
            .i64_type => if (self.i64_index) |idx| idx.deinit(),
            .u32_type => if (self.u32_index) |idx| idx.deinit(),
            .i32_type => if (self.i32_index) |idx| idx.deinit(),
            .bool_type => if (self.bool_index) |idx| idx.deinit(),
        }
    }
};
