const std = @import("std");
const testing = std.testing;

// Import modules under test from shinydb module
const shinydb = @import("shinydb");
const MemTable = shinydb.MemTable;
const SkipList = shinydb.SkipList;
const MemoryPool = shinydb.MemoryPool;
const MemoryPoolConfig = shinydb.MemoryPoolConfig;
const SlottedPage = shinydb.SlottedPage;
const Cell = shinydb.Cell;
const Entry = shinydb.Entry;
const OpKind = shinydb.OpKind;
const KeyGen = shinydb.KeyGen;
const milliTimestamp = shinydb.milliTimestamp;

// ============================================================================
// MemTable Integration Tests
// ============================================================================

test "integration - MemTable basic CRUD operations" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 1000);
    defer mt.deinit();

    // Insert multiple keys
    _ = try mt.put(100, "value_100", milliTimestamp());
    _ = try mt.put(200, "value_200", milliTimestamp());
    _ = try mt.put(300, "value_300", milliTimestamp());

    // Read them back
    try testing.expectEqualStrings("value_100", try mt.get(100));
    try testing.expectEqualStrings("value_200", try mt.get(200));
    try testing.expectEqualStrings("value_300", try mt.get(300));

    // Update one
    _ = try mt.put(200, "updated_200", milliTimestamp());
    try testing.expectEqualStrings("updated_200", try mt.get(200));

    // Delete one
    try mt.del(300);
    try testing.expectError(error.NotFound, mt.get(300));

    // Others should still be accessible
    try testing.expectEqualStrings("value_100", try mt.get(100));
    try testing.expectEqualStrings("updated_200", try mt.get(200));
}

test "integration - MemTable handles large number of entries" {
    const allocator = testing.allocator;
    var mt = try MemTable.init(allocator, 100000);
    defer mt.deinit();

    // Insert 1000 entries
    const count: usize = 1000;
    for (0..count) |i| {
        var buf: [64]u8 = undefined;
        const value = std.fmt.bufPrint(&buf, "value_{d}", .{i}) catch unreachable;
        _ = try mt.put(@intCast(i), value, milliTimestamp());
    }

    // Verify random samples
    try testing.expectEqualStrings("value_0", try mt.get(0));
    try testing.expectEqualStrings("value_500", try mt.get(500));
    try testing.expectEqualStrings("value_999", try mt.get(999));
}

// ============================================================================
// SkipList Integration Tests
// ============================================================================

test "integration - SkipList maintains sorted order" {
    const allocator = testing.allocator;
    var sl = try SkipList.init(allocator, 64, @intCast(milliTimestamp()));
    defer sl.deinit();

    // Insert in random order
    _ = try sl.post(.{ .key = 50, .ns = "", .value = "fifty", .timestamp = 0, .kind = OpKind.insert });
    _ = try sl.post(.{ .key = 10, .ns = "", .value = "ten", .timestamp = 0, .kind = OpKind.insert });
    _ = try sl.post(.{ .key = 90, .ns = "", .value = "ninety", .timestamp = 0, .kind = OpKind.insert });
    _ = try sl.post(.{ .key = 30, .ns = "", .value = "thirty", .timestamp = 0, .kind = OpKind.insert });
    _ = try sl.post(.{ .key = 70, .ns = "", .value = "seventy", .timestamp = 0, .kind = OpKind.insert });

    // Verify retrieval
    try testing.expectEqualStrings("ten", sl.get(10).?.value);
    try testing.expectEqualStrings("thirty", sl.get(30).?.value);
    try testing.expectEqualStrings("fifty", sl.get(50).?.value);
    try testing.expectEqualStrings("seventy", sl.get(70).?.value);
    try testing.expectEqualStrings("ninety", sl.get(90).?.value);
}

// ============================================================================
// MemoryPool Integration Tests
// ============================================================================

test "integration - MemoryPool allocates various sizes" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 4096,
        .max_chunk_size = 16384,
        .growth_factor = 2.0,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    // Allocate small items
    const small = try pool.alloc(u8, 64);
    try testing.expectEqual(@as(usize, 64), small.len);

    // Allocate medium items
    const medium = try pool.alloc(u8, 512);
    try testing.expectEqual(@as(usize, 512), medium.len);

    // Allocate larger items
    const large = try pool.alloc(u8, 2048);
    try testing.expectEqual(@as(usize, 2048), large.len);

    // Check stats
    const stats = pool.getStats();
    try testing.expect(stats.chunk_count >= 1);
    try testing.expect(stats.total_used >= 64 + 512 + 2048);
}

test "integration - MemoryPool reset reuses memory" {
    const allocator = testing.allocator;
    var pool = try MemoryPool.init(allocator, MemoryPoolConfig{
        .initial_chunk_size = 4096,
    });
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

    // First allocation cycle
    _ = try pool.alloc(u8, 1000);
    _ = try pool.alloc(u8, 1000);
    const stats1 = pool.getStats();

    // Reset and allocate again
    pool.reset();

    _ = try pool.alloc(u8, 1000);
    _ = try pool.alloc(u8, 1000);
    const stats2 = pool.getStats();

    // Chunk count should remain the same (memory reused)
    try testing.expectEqual(stats1.chunk_count, stats2.chunk_count);
}

// ============================================================================
// SlottedPage Integration Tests
// ============================================================================

test "integration - SlottedPage insert and retrieve many cells" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    // Insert multiple cells
    var cells_inserted: u16 = 0;
    while (cells_inserted < 100) : (cells_inserted += 1) {
        var key_buf: [32]u8 = undefined;
        var val_buf: [64]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "key_{d:0>5}", .{cells_inserted}) catch unreachable;
        const val = std.fmt.bufPrint(&val_buf, "value_{d}", .{cells_inserted}) catch unreachable;

        const cell = Cell{ .key = key, .value = val };
        if (!page.hasSpace(cell.len())) break;

        try page.insertCell(cells_inserted, cell);
    }

    try testing.expect(cells_inserted > 0);
    try testing.expectEqual(cells_inserted, page.headerPtr().num_cells);

    // Verify first and last cells
    const first = page.getCell(0);
    try testing.expect(first != null);
    try testing.expectEqualStrings("key_00000", first.?.key);

    if (cells_inserted > 1) {
        const last = page.getCell(cells_inserted - 1);
        try testing.expect(last != null);
    }
}

test "integration - SlottedPage compact after deletions" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    // Insert cells
    try page.insertCell(0, .{ .key = "aaa", .value = "111" });
    try page.insertCell(1, .{ .key = "bbb", .value = "222" });
    try page.insertCell(2, .{ .key = "ccc", .value = "333" });
    try page.insertCell(3, .{ .key = "ddd", .value = "444" });

    try testing.expectEqual(@as(u16, 4), page.headerPtr().num_cells);

    // Delete some cells
    page.deleteCell(1);
    page.deleteCell(3);

    // Compact
    page.compact();

    // Should have 2 cells left
    try testing.expectEqual(@as(u16, 2), page.headerPtr().num_cells);

    // Remaining cells should be accessible
    try testing.expectEqualStrings("aaa", page.getCell(0).?.key);
    try testing.expectEqualStrings("ccc", page.getCell(1).?.key);
}

// ============================================================================
// KeyGen Integration Tests
// ============================================================================

test "integration - KeyGen generates unique keys" {
    var keygen = KeyGen.init();

    var keys: [100]u128 = undefined;
    for (0..100) |i| {
        keys[i] = try keygen.Gen(1, 0, 4);
    }

    // All keys should be unique
    for (0..100) |i| {
        for (i + 1..100) |j| {
            try testing.expect(keys[i] != keys[j]);
        }
    }
}

test "integration - KeyGen keys are sortable by store_id" {
    var keygen = KeyGen.init();

    // Generate keys for different stores
    const key_store1 = try keygen.Gen(1, 0, 4);
    const key_store2 = try keygen.Gen(2, 0, 4);
    const key_store3 = try keygen.Gen(3, 0, 4);

    // Store 1 keys should sort before store 2, which sorts before store 3
    try testing.expect(key_store1 < key_store2);
    try testing.expect(key_store2 < key_store3);
}

test "integration - KeyGen metadata extraction" {
    var keygen = KeyGen.init();
    const key = try keygen.Gen(42, 7, 4);

    const metadata = KeyGen.extractMetadata(key);
    try testing.expectEqual(@as(u16, 42), metadata.store_id);
    try testing.expectEqual(@as(u8, 7), metadata.vlog_id);
    try testing.expectEqual(@as(u8, 4), metadata.doc_type);
}

// ============================================================================
// Cross-Component Integration Tests
// ============================================================================

test "integration - Entry serialization consistency" {
    const entry = Entry{
        .key = 0x123456789ABCDEF0,
        .ns = "test_namespace",
        .value = "test_value_data",
        .timestamp = 1234567890,
        .kind = OpKind.insert,
    };

    // Verify fields are accessible
    try testing.expectEqual(@as(u128, 0x123456789ABCDEF0), entry.key);
    try testing.expectEqualStrings("test_namespace", entry.ns);
    try testing.expectEqualStrings("test_value_data", entry.value);
    try testing.expectEqual(@as(i64, 1234567890), entry.timestamp);
    try testing.expectEqual(OpKind.insert, entry.kind);
}
