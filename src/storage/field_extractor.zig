const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto");
const FieldType = proto.FieldType;
const bson = @import("bson");

/// Extract a field value from a BSON document
pub const FieldExtractor = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) FieldExtractor {
        return .{ .allocator = allocator };
    }

    /// Extract a string field from BSON (supports nested dot-notation)
    pub fn extractString(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?[]const u8 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .string => |s| s,
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract a u64 field from BSON (supports nested dot-notation)
    pub fn extractU64(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?u64 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .int64 => |v| if (v >= 0) @intCast(v) else return error.TypeMismatch,
                .int32 => |v| if (v >= 0) @intCast(v) else return error.TypeMismatch,
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract an i64 field from BSON (supports nested dot-notation)
    pub fn extractI64(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?i64 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .int64 => |v| v,
                .int32 => |v| @intCast(v),
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract a u32 field from BSON (supports nested dot-notation)
    pub fn extractU32(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?u32 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .int32 => |v| if (v >= 0) @intCast(v) else return error.TypeMismatch,
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract an i32 field from BSON (supports nested dot-notation)
    pub fn extractI32(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?i32 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .int32 => |v| v,
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract a boolean field from BSON (supports nested dot-notation)
    pub fn extractBool(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?bool {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .boolean => |v| v,
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Extract an f64 field from BSON (supports nested dot-notation)
    pub fn extractF64(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8) !?f64 {
        const doc = try bson.BsonDocument.init(self.allocator, bson_value, false);
        if (try doc.getNestedField(field_name)) |val| {
            return switch (val) {
                .double => |v| v,
                .int64 => |v| @floatFromInt(v),
                .int32 => |v| @floatFromInt(v),
                else => return error.TypeMismatch,
            };
        }
        return null;
    }

    /// Generic field extractor that returns the appropriate type based on FieldType
    pub fn extract(self: *FieldExtractor, bson_value: []const u8, field_name: []const u8, field_type: FieldType) !?FieldValue {
        return switch (field_type) {
            .String => blk: {
                if (try self.extractString(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .string = val };
                }
                break :blk null;
            },
            .U64 => blk: {
                if (try self.extractU64(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .u64_val = val };
                }
                break :blk null;
            },
            .I64 => blk: {
                if (try self.extractI64(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .i64_val = val };
                }
                break :blk null;
            },
            .U32 => blk: {
                if (try self.extractU32(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .u32_val = val };
                }
                break :blk null;
            },
            .I32 => blk: {
                if (try self.extractI32(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .i32_val = val };
                }
                break :blk null;
            },
            .Boolean => blk: {
                if (try self.extractBool(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .bool_val = val };
                }
                break :blk null;
            },
            .F64 => blk: {
                if (try self.extractF64(bson_value, field_name)) |val| {
                    break :blk FieldValue{ .f64_val = val };
                }
                break :blk null;
            },
            else => null,
        };
    }
};

/// Union type for extracted field values
pub const FieldValue = union(enum) {
    string: []const u8,
    u64_val: u64,
    i64_val: i64,
    u32_val: u32,
    i32_val: i32,
    f64_val: f64,
    bool_val: bool,

    pub fn deinit(self: FieldValue, allocator: Allocator) void {
        switch (self) {
            .string => |s| allocator.free(s),
            else => {},
        }
    }

    /// Convert numeric field values to f64 for aggregation calculations
    pub fn toF64(self: FieldValue) ?f64 {
        return switch (self) {
            .i64_val => |v| @floatFromInt(v),
            .u64_val => |v| @floatFromInt(v),
            .i32_val => |v| @floatFromInt(v),
            .u32_val => |v| @floatFromInt(v),
            .f64_val => |v| v,
            else => null,
        };
    }
};
