const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto");
const milliTimestamp = @import("../common/common.zig").milliTimestamp;

/// Schema version
pub const SchemaVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,

    pub fn format(self: SchemaVersion, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{d}.{d}.{d}", .{ self.major, self.minor, self.patch });
    }

    pub fn compare(self: SchemaVersion, other: SchemaVersion) i8 {
        if (self.major != other.major) {
            return if (self.major > other.major) 1 else -1;
        }
        if (self.minor != other.minor) {
            return if (self.minor > other.minor) 1 else -1;
        }
        if (self.patch != other.patch) {
            return if (self.patch > other.patch) 1 else -1;
        }
        return 0;
    }
};

/// Field definition in schema
pub const FieldDefinition = struct {
    name: []const u8,
    field_type: proto.FieldType,
    required: bool = false,
    default_value: ?[]const u8 = null,
    indexed: bool = false,
    unique: bool = false,
    validation_rules: []const ValidationRule = &[_]ValidationRule{},

    pub fn deinit(self: *FieldDefinition, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.default_value) |val| {
            allocator.free(val);
        }
        allocator.free(self.validation_rules);
    }
};

/// Validation rule for fields
pub const ValidationRule = struct {
    rule_type: ValidationType,
    value: []const u8,

    pub const ValidationType = enum {
        min_length,
        max_length,
        pattern, // Regex pattern
        min_value,
        max_value,
        enum_values,
    };
};

/// Collection schema
pub const CollectionSchema = struct {
    name: []const u8,
    version: SchemaVersion,
    fields: []FieldDefinition,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: *CollectionSchema, allocator: Allocator) void {
        allocator.free(self.name);
        for (self.fields) |*field| {
            field.deinit(allocator);
        }
        allocator.free(self.fields);
    }

    /// Validate a document against this schema
    pub fn validate(self: *const CollectionSchema, document: []const u8) !void {
        // TODO: Parse document and validate each field
        // For now, just check if document is not empty
        _ = self;
        if (document.len == 0) {
            return error.EmptyDocument;
        }
    }
};

/// Schema migration
pub const Migration = struct {
    from_version: SchemaVersion,
    to_version: SchemaVersion,
    operations: []MigrationOperation,
    created_at: i64,

    pub fn deinit(self: *Migration, allocator: Allocator) void {
        for (self.operations) |*op| {
            op.deinit(allocator);
        }
        allocator.free(self.operations);
    }
};

/// Migration operation
pub const MigrationOperation = union(enum) {
    add_field: struct {
        field_name: []const u8,
        field_def: FieldDefinition,
    },
    remove_field: struct {
        field_name: []const u8,
    },
    rename_field: struct {
        old_name: []const u8,
        new_name: []const u8,
    },
    change_type: struct {
        field_name: []const u8,
        new_type: proto.FieldType,
    },
    add_index: struct {
        field_name: []const u8,
    },
    remove_index: struct {
        field_name: []const u8,
    },

    pub fn deinit(self: *MigrationOperation, allocator: Allocator) void {
        switch (self.*) {
            .add_field => |*op| {
                allocator.free(op.field_name);
                op.field_def.deinit(allocator);
            },
            .remove_field => |*op| allocator.free(op.field_name),
            .rename_field => |*op| {
                allocator.free(op.old_name);
                allocator.free(op.new_name);
            },
            .change_type => |*op| allocator.free(op.field_name),
            .add_index => |*op| allocator.free(op.field_name),
            .remove_index => |*op| allocator.free(op.field_name),
        }
    }
};

/// Schema manager
pub const SchemaManager = struct {
    allocator: Allocator,

    // Schema store: collection_name -> CollectionSchema
    schemas: std.StringHashMap(CollectionSchema),
    schemas_mutex: std.Thread.Mutex,

    // Migration history
    migrations: std.ArrayList(Migration),
    migrations_mutex: std.Thread.Mutex,

    pub fn init(allocator: Allocator) !*SchemaManager {
        const mgr = try allocator.create(SchemaManager);
        mgr.* = SchemaManager{
            .allocator = allocator,
            .schemas = std.StringHashMap(CollectionSchema).init(allocator),
            .schemas_mutex = .{},
            .migrations = .empty,
            .migrations_mutex = .{},
        };
        return mgr;
    }

    pub fn deinit(self: *SchemaManager) void {
        // Free both keys and values from the hashmap
        var key_iter = self.schemas.keyIterator();
        while (key_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        var schema_iter = self.schemas.valueIterator();
        while (schema_iter.next()) |schema| {
            var s = schema.*;
            s.deinit(self.allocator);
        }
        self.schemas.deinit();

        for (self.migrations.items) |*migration| {
            migration.deinit(self.allocator);
        }
        self.migrations.deinit(self.allocator);

        self.allocator.destroy(self);
    }

    /// Register a new schema
    pub fn registerSchema(self: *SchemaManager, schema: CollectionSchema) !void {
        self.schemas_mutex.lock();
        defer self.schemas_mutex.unlock();

        if (self.schemas.contains(schema.name)) {
            return error.SchemaAlreadyExists;
        }

        // Duplicate key separately from schema.name to avoid double-free issues
        const key_copy = try self.allocator.dupe(u8, schema.name);
        errdefer self.allocator.free(key_copy);

        // Deep clone the schema - duplicate all owned memory
        const name_copy = try self.allocator.dupe(u8, schema.name);
        errdefer self.allocator.free(name_copy);

        // Duplicate fields array and clone each field's owned data
        const fields_copy = try self.allocator.alloc(FieldDefinition, schema.fields.len);
        errdefer self.allocator.free(fields_copy);

        for (schema.fields, 0..) |field, i| {
            fields_copy[i] = FieldDefinition{
                .name = try self.allocator.dupe(u8, field.name),
                .field_type = field.field_type,
                .required = field.required,
                .default_value = if (field.default_value) |v| try self.allocator.dupe(u8, v) else null,
                .indexed = field.indexed,
                .unique = field.unique,
                .validation_rules = try self.allocator.dupe(ValidationRule, field.validation_rules),
            };
        }

        const schema_copy = CollectionSchema{
            .name = name_copy,
            .version = schema.version,
            .fields = fields_copy,
            .created_at = schema.created_at,
            .updated_at = schema.updated_at,
        };

        try self.schemas.put(key_copy, schema_copy);
    }

    /// Get schema for a collection
    pub fn getSchema(self: *SchemaManager, collection_name: []const u8) ?CollectionSchema {
        self.schemas_mutex.lock();
        defer self.schemas_mutex.unlock();

        return self.schemas.get(collection_name);
    }

    /// Update schema (creates a migration)
    pub fn updateSchema(self: *SchemaManager, collection_name: []const u8, new_schema: CollectionSchema) !void {
        self.schemas_mutex.lock();
        defer self.schemas_mutex.unlock();

        const old_schema = self.schemas.get(collection_name) orelse return error.SchemaNotFound;

        // Create migration
        const migration = try self.createMigration(old_schema, new_schema);

        // Store migration
        self.migrations_mutex.lock();
        defer self.migrations_mutex.unlock();
        try self.migrations.append(migration);

        // Update schema
        try self.schemas.put(try self.allocator.dupe(u8, collection_name), new_schema);
    }

    /// Create a migration between two schemas
    fn createMigration(self: *SchemaManager, old_schema: CollectionSchema, new_schema: CollectionSchema) !Migration {
        var operations: std.ArrayList(MigrationOperation) = .empty;

        // Detect field additions and removals
        // This is a simplified implementation
        for (new_schema.fields) |new_field| {
            var found = false;
            for (old_schema.fields) |old_field| {
                if (std.mem.eql(u8, new_field.name, old_field.name)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                try operations.append(self.allocator, MigrationOperation{
                    .add_field = .{
                        .field_name = try self.allocator.dupe(u8, new_field.name),
                        .field_def = new_field,
                    },
                });
            }
        }

        return Migration{
            .from_version = old_schema.version,
            .to_version = new_schema.version,
            .operations = try self.allocator.dupe(MigrationOperation, operations.items),
            .created_at = milliTimestamp(),
        };
    }

    /// Apply migrations to a database
    pub fn applyMigrations(self: *SchemaManager, db: anytype, target_version: SchemaVersion) !void {
        self.migrations_mutex.lock();
        defer self.migrations_mutex.unlock();

        for (self.migrations.items) |migration| {
            if (migration.to_version.compare(target_version) <= 0) {
                try self.applyMigration(db, migration);
            }
        }
    }

    fn applyMigration(self: *SchemaManager, db: anytype, migration: Migration) !void {
        _ = self;
        _ = db;

        for (migration.operations) |op| {
            switch (op) {
                .add_field => {
                    // TODO: Apply field addition to all documents
                },
                .remove_field => {
                    // TODO: Remove field from all documents
                },
                .rename_field => {
                    // TODO: Rename field in all documents
                },
                .change_type => {
                    // TODO: Convert field type in all documents
                },
                .add_index => {
                    // TODO: Create index
                },
                .remove_index => {
                    // TODO: Drop index
                },
            }
        }
    }

    /// Validate a document against a schema
    pub fn validateDocument(self: *SchemaManager, collection_name: []const u8, document: []const u8) !void {
        const schema = self.getSchema(collection_name) orelse return error.SchemaNotFound;
        try schema.validate(document);
    }

    /// List all registered schemas
    pub fn listSchemas(self: *SchemaManager) !std.ArrayList([]const u8) {
        self.schemas_mutex.lock();
        defer self.schemas_mutex.unlock();

        var names: std.ArrayList([]const u8) = .empty;

        var iter = self.schemas.keyIterator();
        while (iter.next()) |name| {
            try names.append(self.allocator, try self.allocator.dupe(u8, name.*));
        }

        return names;
    }

    /// Get migration history for a collection
    pub fn getMigrationHistory(self: *SchemaManager, collection_name: []const u8) !std.ArrayList(Migration) {
        _ = collection_name;
        self.migrations_mutex.lock();
        defer self.migrations_mutex.unlock();

        // Return copy of migrations
        var history: std.ArrayList(Migration) = .empty;
        for (self.migrations.items) |migration| {
            try history.append(self.allocator, migration);
        }

        return history;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "SchemaVersion - compare equal versions" {
    const v1 = SchemaVersion{ .major = 1, .minor = 2, .patch = 3 };
    const v2 = SchemaVersion{ .major = 1, .minor = 2, .patch = 3 };
    try std.testing.expectEqual(@as(i8, 0), v1.compare(v2));
}

test "SchemaVersion - compare major version difference" {
    const v1 = SchemaVersion{ .major = 2, .minor = 0, .patch = 0 };
    const v2 = SchemaVersion{ .major = 1, .minor = 9, .patch = 9 };
    try std.testing.expectEqual(@as(i8, 1), v1.compare(v2));
    try std.testing.expectEqual(@as(i8, -1), v2.compare(v1));
}

test "SchemaVersion - compare minor version difference" {
    const v1 = SchemaVersion{ .major = 1, .minor = 5, .patch = 0 };
    const v2 = SchemaVersion{ .major = 1, .minor = 3, .patch = 9 };
    try std.testing.expectEqual(@as(i8, 1), v1.compare(v2));
    try std.testing.expectEqual(@as(i8, -1), v2.compare(v1));
}

test "SchemaVersion - compare patch version difference" {
    const v1 = SchemaVersion{ .major = 1, .minor = 2, .patch = 5 };
    const v2 = SchemaVersion{ .major = 1, .minor = 2, .patch = 3 };
    try std.testing.expectEqual(@as(i8, 1), v1.compare(v2));
    try std.testing.expectEqual(@as(i8, -1), v2.compare(v1));
}

test "SchemaVersion - compare and ordering" {
    const v1 = SchemaVersion{ .major = 1, .minor = 0, .patch = 0 };
    const v2 = SchemaVersion{ .major = 1, .minor = 2, .patch = 0 };
    const v3 = SchemaVersion{ .major = 1, .minor = 2, .patch = 3 };
    const v4 = SchemaVersion{ .major = 2, .minor = 0, .patch = 0 };

    // Same versions
    try std.testing.expectEqual(@as(i8, 0), v1.compare(v1));

    // Major version comparison
    try std.testing.expectEqual(@as(i8, -1), v1.compare(v4));
    try std.testing.expectEqual(@as(i8, 1), v4.compare(v1));

    // Minor version comparison
    try std.testing.expectEqual(@as(i8, -1), v1.compare(v2));
    try std.testing.expectEqual(@as(i8, 1), v2.compare(v1));

    // Patch version comparison
    try std.testing.expectEqual(@as(i8, -1), v2.compare(v3));
    try std.testing.expectEqual(@as(i8, 1), v3.compare(v2));
}

test "FieldDefinition - defaults" {
    const field = FieldDefinition{
        .name = "test_field",
        .field_type = .String,
    };

    try std.testing.expect(!field.required);
    try std.testing.expect(field.default_value == null);
    try std.testing.expect(!field.indexed);
    try std.testing.expect(!field.unique);
    try std.testing.expectEqual(@as(usize, 0), field.validation_rules.len);
}

test "ValidationRule - types" {
    const rules = [_]ValidationRule{
        .{ .rule_type = .min_length, .value = "5" },
        .{ .rule_type = .max_length, .value = "100" },
        .{ .rule_type = .pattern, .value = "^[a-z]+$" },
        .{ .rule_type = .min_value, .value = "0" },
        .{ .rule_type = .max_value, .value = "1000" },
        .{ .rule_type = .enum_values, .value = "a,b,c" },
    };

    try std.testing.expectEqual(ValidationRule.ValidationType.min_length, rules[0].rule_type);
    try std.testing.expectEqual(ValidationRule.ValidationType.max_length, rules[1].rule_type);
    try std.testing.expectEqual(ValidationRule.ValidationType.pattern, rules[2].rule_type);
    try std.testing.expectEqual(ValidationRule.ValidationType.min_value, rules[3].rule_type);
    try std.testing.expectEqual(ValidationRule.ValidationType.max_value, rules[4].rule_type);
    try std.testing.expectEqual(ValidationRule.ValidationType.enum_values, rules[5].rule_type);
}

test "CollectionSchema - validate rejects empty document" {
    const schema = CollectionSchema{
        .name = "test_collection",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .fields = &[_]FieldDefinition{},
        .created_at = 0,
        .updated_at = 0,
    };

    try std.testing.expectError(error.EmptyDocument, schema.validate(""));
}

test "CollectionSchema - validate accepts non-empty document" {
    const schema = CollectionSchema{
        .name = "test_collection",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .fields = &[_]FieldDefinition{},
        .created_at = 0,
        .updated_at = 0,
    };

    try schema.validate("{\"key\": \"value\"}");
}

test "MigrationOperation - union tags" {
    const add_field_op = MigrationOperation{
        .add_field = .{
            .field_name = "new_field",
            .field_def = .{ .name = "new_field", .field_type = .String },
        },
    };
    const remove_field_op = MigrationOperation{ .remove_field = .{ .field_name = "old_field" } };
    const rename_field_op = MigrationOperation{ .rename_field = .{ .old_name = "old", .new_name = "new" } };
    const change_type_op = MigrationOperation{ .change_type = .{ .field_name = "field", .new_type = .I64 } };
    const add_index_op = MigrationOperation{ .add_index = .{ .field_name = "indexed_field" } };
    const remove_index_op = MigrationOperation{ .remove_index = .{ .field_name = "unindexed_field" } };

    try std.testing.expect(add_field_op == .add_field);
    try std.testing.expect(remove_field_op == .remove_field);
    try std.testing.expect(rename_field_op == .rename_field);
    try std.testing.expect(change_type_op == .change_type);
    try std.testing.expect(add_index_op == .add_index);
    try std.testing.expect(remove_index_op == .remove_index);
}

test "SchemaManager - init and deinit" {
    const allocator = std.testing.allocator;
    var mgr = try SchemaManager.init(allocator);
    defer mgr.deinit();

    // Should start with no schemas
    const schema = mgr.getSchema("nonexistent");
    try std.testing.expect(schema == null);
}

test "SchemaManager - register and get schema" {
    const allocator = std.testing.allocator;
    var mgr = try SchemaManager.init(allocator);
    defer mgr.deinit();

    const schema = CollectionSchema{
        .name = "users",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .fields = &[_]FieldDefinition{},
        .created_at = 1000,
        .updated_at = 1000,
    };

    try mgr.registerSchema(schema);

    const retrieved = mgr.getSchema("users");
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings("users", retrieved.?.name);
    try std.testing.expectEqual(@as(u16, 1), retrieved.?.version.major);
}

test "SchemaManager - register duplicate schema fails" {
    const allocator = std.testing.allocator;
    var mgr = try SchemaManager.init(allocator);
    defer mgr.deinit();

    const schema = CollectionSchema{
        .name = "users",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .fields = &[_]FieldDefinition{},
        .created_at = 1000,
        .updated_at = 1000,
    };

    try mgr.registerSchema(schema);
    try std.testing.expectError(error.SchemaAlreadyExists, mgr.registerSchema(schema));
}

test "SchemaManager - validateDocument with unknown schema fails" {
    const allocator = std.testing.allocator;
    var mgr = try SchemaManager.init(allocator);
    defer mgr.deinit();

    try std.testing.expectError(error.SchemaNotFound, mgr.validateDocument("unknown", "{}"));
}
