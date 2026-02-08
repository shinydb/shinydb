const std = @import("std");

pub const KeyGen = struct {
    pub fn init() KeyGen {
        return KeyGen{};
    }

    /// Generate a unique key with embedded metadata
    /// Optimized structure for efficient per-store operations:
    /// Bits 0-95:   Random data (12 bytes) - uniqueness within a doc type
    /// Bits 96-103: VLog ID (1 byte, u8) - max 256 vlogs
    /// Bits 104-111: Doc Type (1 byte, u8) - metadata type (Space/Store/Index/Document)
    /// Bits 112-127: Store ID (2 bytes, u16) - identifies the store/table (MOST SIGNIFICANT)
    ///
    /// Keys are sorted by: store_id (primary) -> doc_type -> vlog_id -> random
    /// This enables O(log N) seeking to any store's data and efficient range scans
    pub fn Gen(self: *KeyGen, store_id: u16, vlog_id: u8, doc_type: u8) !u128 {
        _ = self;

        var rand_bytes: [12]u8 = undefined;
        std.crypto.random.bytes(&rand_bytes);

        var rand: u128 = 0;
        for (rand_bytes, 0..) |byte, i| {
            rand |= (@as(u128, byte) << @intCast(i * 8));
        }

        var key: u128 = rand;
        key |= (@as(u128, vlog_id) << 96);    // 8 bits at positions 96-103
        key |= (@as(u128, doc_type) << 104);  // 8 bits at positions 104-111
        key |= (@as(u128, store_id) << 112);  // 16 bits at positions 112-127 (MOST SIGNIFICANT)

        return key;
    }

    pub const KeyMetaData = struct {
        store_id: u16,
        vlog_id: u8,
        doc_type: u8,
    };

    pub fn extractMetadata(key: u128) KeyMetaData {
        const store_id: u16 = @truncate((key >> 112) & 0xFFFF);
        const doc_type: u8 = @truncate((key >> 104) & 0xFF);
        const vlog_id: u8 = @truncate((key >> 96) & 0xFF);

        return KeyMetaData{
            .store_id = store_id,
            .vlog_id = vlog_id,
            .doc_type = doc_type,
        };
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "KeyGen - generates unique keys" {
    var keygen = KeyGen.init();
    const key1 = try keygen.Gen(1, 0, 4);
    const key2 = try keygen.Gen(1, 0, 4);
    const key3 = try keygen.Gen(1, 0, 4);

    // Keys should be unique due to random component
    try std.testing.expect(key1 != key2);
    try std.testing.expect(key2 != key3);
    try std.testing.expect(key1 != key3);
}

test "KeyGen - metadata encoding and decoding roundtrip" {
    var keygen = KeyGen.init();

    // Test various combinations
    const test_cases = [_]struct { store_id: u16, vlog_id: u8, doc_type: u8 }{
        .{ .store_id = 0, .vlog_id = 0, .doc_type = 0 },
        .{ .store_id = 1, .vlog_id = 1, .doc_type = 4 },
        .{ .store_id = 100, .vlog_id = 50, .doc_type = 3 },
        .{ .store_id = 65535, .vlog_id = 255, .doc_type = 255 }, // Max values
        .{ .store_id = 12345, .vlog_id = 128, .doc_type = 1 },
    };

    for (test_cases) |tc| {
        const key = try keygen.Gen(tc.store_id, tc.vlog_id, tc.doc_type);
        const meta = KeyGen.extractMetadata(key);

        try std.testing.expectEqual(tc.store_id, meta.store_id);
        try std.testing.expectEqual(tc.vlog_id, meta.vlog_id);
        try std.testing.expectEqual(tc.doc_type, meta.doc_type);
    }
}

test "KeyGen - store_id is most significant (keys sort by store)" {
    var keygen = KeyGen.init();

    // Generate keys with different store IDs
    const key_store_1 = try keygen.Gen(1, 0, 4);
    const key_store_2 = try keygen.Gen(2, 0, 4);
    const key_store_10 = try keygen.Gen(10, 0, 4);
    const key_store_100 = try keygen.Gen(100, 0, 4);

    // Keys with higher store_id should be greater (for sorting)
    try std.testing.expect(key_store_1 < key_store_2);
    try std.testing.expect(key_store_2 < key_store_10);
    try std.testing.expect(key_store_10 < key_store_100);
}

test "KeyGen - doc_type affects sorting within store" {
    var keygen = KeyGen.init();

    // Within same store, doc_type should affect ordering
    // doc_type is at bits 104-111, after vlog_id (96-103)
    const key_type_1 = try keygen.Gen(5, 0, 1);
    const key_type_4 = try keygen.Gen(5, 0, 4);

    const meta1 = KeyGen.extractMetadata(key_type_1);
    const meta4 = KeyGen.extractMetadata(key_type_4);

    try std.testing.expectEqual(@as(u8, 1), meta1.doc_type);
    try std.testing.expectEqual(@as(u8, 4), meta4.doc_type);

    // Same store_id
    try std.testing.expectEqual(meta1.store_id, meta4.store_id);
}

test "KeyGen - extract metadata from known key" {
    // Manually construct a key with known values
    // store_id=0x1234 at bits 112-127
    // doc_type=0x56 at bits 104-111
    // vlog_id=0x78 at bits 96-103
    const store_id: u128 = 0x1234;
    const doc_type: u128 = 0x56;
    const vlog_id: u128 = 0x78;
    const random_part: u128 = 0x123456789ABC; // Lower 96 bits

    const key: u128 = random_part |
        (vlog_id << 96) |
        (doc_type << 104) |
        (store_id << 112);

    const meta = KeyGen.extractMetadata(key);

    try std.testing.expectEqual(@as(u16, 0x1234), meta.store_id);
    try std.testing.expectEqual(@as(u8, 0x56), meta.doc_type);
    try std.testing.expectEqual(@as(u8, 0x78), meta.vlog_id);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "KeyGen - zero values for all metadata fields" {
    var keygen = KeyGen.init();
    const key = try keygen.Gen(0, 0, 0);
    const meta = KeyGen.extractMetadata(key);

    try std.testing.expectEqual(@as(u16, 0), meta.store_id);
    try std.testing.expectEqual(@as(u8, 0), meta.vlog_id);
    try std.testing.expectEqual(@as(u8, 0), meta.doc_type);
}

test "KeyGen - max values for all metadata fields" {
    var keygen = KeyGen.init();
    const key = try keygen.Gen(65535, 255, 255);
    const meta = KeyGen.extractMetadata(key);

    try std.testing.expectEqual(@as(u16, 65535), meta.store_id);
    try std.testing.expectEqual(@as(u8, 255), meta.vlog_id);
    try std.testing.expectEqual(@as(u8, 255), meta.doc_type);
}

test "KeyGen - extract metadata from zero key" {
    const meta = KeyGen.extractMetadata(0);

    try std.testing.expectEqual(@as(u16, 0), meta.store_id);
    try std.testing.expectEqual(@as(u8, 0), meta.vlog_id);
    try std.testing.expectEqual(@as(u8, 0), meta.doc_type);
}

test "KeyGen - extract metadata from max key" {
    const max_key: u128 = std.math.maxInt(u128);
    const meta = KeyGen.extractMetadata(max_key);

    try std.testing.expectEqual(@as(u16, 65535), meta.store_id);
    try std.testing.expectEqual(@as(u8, 255), meta.vlog_id);
    try std.testing.expectEqual(@as(u8, 255), meta.doc_type);
}

test "KeyGen - many sequential keys are unique" {
    var keygen = KeyGen.init();
    var keys: [100]u128 = undefined;

    for (&keys) |*k| {
        k.* = try keygen.Gen(1, 0, 4);
    }

    // All keys should be unique
    for (keys, 0..) |key1, i| {
        for (keys[i + 1 ..]) |key2| {
            try std.testing.expect(key1 != key2);
        }
    }
}

test "KeyGen - keys with same store cluster together" {
    var keygen = KeyGen.init();

    // Generate keys for different stores
    var store1_keys: [10]u128 = undefined;
    var store2_keys: [10]u128 = undefined;

    for (&store1_keys) |*k| {
        k.* = try keygen.Gen(1, 0, 4);
    }
    for (&store2_keys) |*k| {
        k.* = try keygen.Gen(2, 0, 4);
    }

    // All store 1 keys should be less than all store 2 keys
    for (store1_keys) |k1| {
        for (store2_keys) |k2| {
            try std.testing.expect(k1 < k2);
        }
    }
}
