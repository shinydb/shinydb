const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const milliTimestamp = @import("../common/common.zig").milliTimestamp;

/// Transaction ID type
pub const TxnId = u64;

/// Transaction state
pub const TxnState = enum {
    active,
    preparing,
    committed,
    aborted,
};

/// Transaction isolation level
pub const IsolationLevel = enum {
    read_uncommitted,
    read_committed,
    repeatable_read,
    serializable,
};

/// Write operation in a transaction
pub const TxnWrite = struct {
    key: u128,
    value: []const u8, // Empty for deletions
    timestamp: i64,

    pub fn deinit(self: *TxnWrite, allocator: Allocator) void {
        allocator.free(self.value);
    }
};

/// Read operation tracking for conflict detection
pub const TxnRead = struct {
    key: u128,
    version: TxnId,
};

/// Transaction metadata and state
pub const Transaction = struct {
    allocator: Allocator,
    id: TxnId,
    state: TxnState,
    isolation_level: IsolationLevel,
    start_timestamp: i64,
    commit_timestamp: i64,

    // Transaction-local write buffer
    writes: std.ArrayList(TxnWrite),

    // Read tracking for validation (only needed for serializable isolation)
    reads: std.ArrayList(TxnRead),

    // Snapshot timestamp for consistent reads
    snapshot_timestamp: i64,

    pub fn init(allocator: Allocator, id: TxnId, isolation_level: IsolationLevel) !*Transaction {
        const txn = try allocator.create(Transaction);
        txn.* = Transaction{
            .allocator = allocator,
            .id = id,
            .state = .active,
            .isolation_level = isolation_level,
            .start_timestamp = milliTimestamp(),
            .commit_timestamp = 0,
            .writes = .empty,
            .reads = .empty,
            .snapshot_timestamp = milliTimestamp(),
        };
        return txn;
    }

    pub fn deinit(self: *Transaction) void {
        for (self.writes.items) |*write| {
            write.deinit(self.allocator);
        }
        self.writes.deinit(self.allocator);
        self.reads.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Add a write operation to the transaction buffer
    pub fn addWrite(self: *Transaction, key: u128, value: []const u8) !void {
        const value_copy = try self.allocator.dupe(u8, value);
        try self.writes.append(self.allocator, TxnWrite{
            .key = key,
            .value = value_copy,
            .timestamp = milliTimestamp(),
        });
    }

    /// Add a delete operation to the transaction buffer
    pub fn addDelete(self: *Transaction, key: u128) !void {
        // Empty value indicates deletion
        try self.writes.append(self.allocator, TxnWrite{
            .key = key,
            .value = &[_]u8{},
            .timestamp = milliTimestamp(),
        });
    }

    /// Track a read for validation (serializable isolation only)
    pub fn trackRead(self: *Transaction, key: u128, version: TxnId) !void {
        if (self.isolation_level == .serializable) {
            try self.reads.append(self.allocator, TxnRead{
                .key = key,
                .version = version,
            });
        }
    }

    /// Check if this transaction has written to a key
    pub fn getLocalWrite(self: *Transaction, key: u128) ?[]const u8 {
        // Scan writes in reverse to get most recent write
        var i = self.writes.items.len;
        while (i > 0) {
            i -= 1;
            const write = self.writes.items[i];
            if (write.key == key) {
                return write.value;
            }
        }
        return null;
    }
};

/// Transaction Manager - coordinates all transactions
pub const TxnManager = struct {
    allocator: Allocator,
    next_txn_id: std.atomic.Value(TxnId),

    // Active transactions map: txn_id -> Transaction
    active_txns: std.AutoHashMap(TxnId, *Transaction),
    active_txns_mutex: std.Thread.Mutex,

    // Committed transaction watermark for garbage collection
    min_active_txn: std.atomic.Value(TxnId),

    pub fn init(allocator: Allocator) !*TxnManager {
        const mgr = try allocator.create(TxnManager);
        mgr.* = TxnManager{
            .allocator = allocator,
            .next_txn_id = std.atomic.Value(TxnId).init(1),
            .active_txns = std.AutoHashMap(TxnId, *Transaction).init(allocator),
            .active_txns_mutex = .{},
            .min_active_txn = std.atomic.Value(TxnId).init(0),
        };
        return mgr;
    }

    pub fn deinit(self: *TxnManager) void {
        // Save allocator before potentially freeing self
        const allocator = self.allocator;

        self.active_txns_mutex.lock();

        var iter = self.active_txns.valueIterator();
        while (iter.next()) |txn_ptr| {
            txn_ptr.*.deinit();
        }
        self.active_txns.deinit();

        self.active_txns_mutex.unlock();

        // Destroy self AFTER unlocking mutex (otherwise we access freed memory)
        allocator.destroy(self);
    }

    /// Begin a new transaction
    pub fn begin(self: *TxnManager, isolation_level: IsolationLevel) !*Transaction {
        const txn_id = self.next_txn_id.fetchAdd(1, .monotonic);
        const txn = try Transaction.init(self.allocator, txn_id, isolation_level);

        self.active_txns_mutex.lock();
        defer self.active_txns_mutex.unlock();

        try self.active_txns.put(txn_id, txn);
        self.updateMinActiveTxn();

        return txn;
    }

    /// Commit a transaction
    pub fn commit(self: *TxnManager, txn: *Transaction) !void {
        if (txn.state != .active) {
            return error.TransactionNotActive;
        }

        txn.state = .preparing;
        txn.commit_timestamp = milliTimestamp();

        // Validation happens in the database layer
        txn.state = .committed;

        self.active_txns_mutex.lock();
        defer self.active_txns_mutex.unlock();

        _ = self.active_txns.remove(txn.id);
        self.updateMinActiveTxn();
    }

    /// Abort a transaction
    pub fn abort(self: *TxnManager, txn: *Transaction) void {
        if (txn.state != .active and txn.state != .preparing) {
            return;
        }

        txn.state = .aborted;

        self.active_txns_mutex.lock();
        defer self.active_txns_mutex.unlock();

        _ = self.active_txns.remove(txn.id);
        self.updateMinActiveTxn();
    }

    /// Get the minimum active transaction ID (for snapshot isolation)
    pub fn getMinActiveTxn(self: *TxnManager) TxnId {
        return self.min_active_txn.load(.monotonic);
    }

    /// Update the minimum active transaction ID
    fn updateMinActiveTxn(self: *TxnManager) void {
        var min_txn_id: TxnId = std.math.maxInt(TxnId);

        var iter = self.active_txns.keyIterator();
        while (iter.next()) |txn_id| {
            if (txn_id.* < min_txn_id) {
                min_txn_id = txn_id.*;
            }
        }

        if (min_txn_id == std.math.maxInt(TxnId)) {
            min_txn_id = self.next_txn_id.load(.monotonic);
        }

        self.min_active_txn.store(min_txn_id, .release);
    }

    /// Check if a transaction can see a version (for snapshot isolation)
    pub fn canSeeVersion(self: *TxnManager, txn: *Transaction, version_txn_id: TxnId) bool {
        _ = self;
        // A transaction can see a version if it was committed before this transaction started
        return version_txn_id < txn.id;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "TxnState - enum values" {
    try std.testing.expectEqual(@as(usize, 0), @intFromEnum(TxnState.active));
    try std.testing.expectEqual(@as(usize, 1), @intFromEnum(TxnState.preparing));
    try std.testing.expectEqual(@as(usize, 2), @intFromEnum(TxnState.committed));
    try std.testing.expectEqual(@as(usize, 3), @intFromEnum(TxnState.aborted));
}

test "IsolationLevel - enum values" {
    try std.testing.expectEqual(@as(usize, 0), @intFromEnum(IsolationLevel.read_uncommitted));
    try std.testing.expectEqual(@as(usize, 1), @intFromEnum(IsolationLevel.read_committed));
    try std.testing.expectEqual(@as(usize, 2), @intFromEnum(IsolationLevel.repeatable_read));
    try std.testing.expectEqual(@as(usize, 3), @intFromEnum(IsolationLevel.serializable));
}

test "Transaction - init creates active transaction" {
    const allocator = std.testing.allocator;
    var txn = try Transaction.init(allocator, 1, .read_committed);
    defer txn.deinit();

    try std.testing.expectEqual(@as(TxnId, 1), txn.id);
    try std.testing.expectEqual(TxnState.active, txn.state);
    try std.testing.expectEqual(IsolationLevel.read_committed, txn.isolation_level);
    try std.testing.expect(txn.start_timestamp > 0);
    try std.testing.expectEqual(@as(i64, 0), txn.commit_timestamp);
}

test "Transaction - addWrite stores write" {
    const allocator = std.testing.allocator;
    var txn = try Transaction.init(allocator, 1, .read_committed);
    defer txn.deinit();

    try txn.addWrite(100, "test_value");

    try std.testing.expectEqual(@as(usize, 1), txn.writes.items.len);
    try std.testing.expectEqual(@as(u128, 100), txn.writes.items[0].key);
    try std.testing.expectEqualStrings("test_value", txn.writes.items[0].value);
}

test "Transaction - addDelete stores empty value" {
    const allocator = std.testing.allocator;
    var txn = try Transaction.init(allocator, 1, .read_committed);
    defer txn.deinit();

    try txn.addDelete(100);

    try std.testing.expectEqual(@as(usize, 1), txn.writes.items.len);
    try std.testing.expectEqual(@as(u128, 100), txn.writes.items[0].key);
    try std.testing.expectEqual(@as(usize, 0), txn.writes.items[0].value.len);
}

test "Transaction - getLocalWrite finds latest write" {
    const allocator = std.testing.allocator;
    var txn = try Transaction.init(allocator, 1, .read_committed);
    defer txn.deinit();

    try txn.addWrite(100, "first");
    try txn.addWrite(100, "second");
    try txn.addWrite(100, "third");

    const result = txn.getLocalWrite(100);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("third", result.?);
}

test "Transaction - getLocalWrite returns null for missing key" {
    const allocator = std.testing.allocator;
    var txn = try Transaction.init(allocator, 1, .read_committed);
    defer txn.deinit();

    try txn.addWrite(100, "value");

    const result = txn.getLocalWrite(999);
    try std.testing.expect(result == null);
}

test "Transaction - trackRead only tracks for serializable" {
    const allocator = std.testing.allocator;

    // Non-serializable should not track
    var txn1 = try Transaction.init(allocator, 1, .read_committed);
    defer txn1.deinit();
    try txn1.trackRead(100, 1);
    try std.testing.expectEqual(@as(usize, 0), txn1.reads.items.len);

    // Serializable should track
    var txn2 = try Transaction.init(allocator, 2, .serializable);
    defer txn2.deinit();
    try txn2.trackRead(100, 1);
    try std.testing.expectEqual(@as(usize, 1), txn2.reads.items.len);
}

test "TxnManager - init starts with txn_id 1" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit();

    try std.testing.expectEqual(@as(TxnId, 1), mgr.next_txn_id.load(.monotonic));
}

test "TxnManager - begin creates transaction" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit(); // Manager deinit will clean up active transactions

    var txn = try mgr.begin(.read_committed);
    // DON'T defer txn.deinit() - manager owns the transaction

    try std.testing.expectEqual(@as(TxnId, 1), txn.id);
    try std.testing.expectEqual(TxnState.active, txn.state);
}

test "TxnManager - begin increments txn_id" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit(); // Manager cleans up all transactions

    var txn1 = try mgr.begin(.read_committed);
    var txn2 = try mgr.begin(.read_committed);
    var txn3 = try mgr.begin(.read_committed);

    // Manager owns transactions - don't manually deinit

    try std.testing.expectEqual(@as(TxnId, 1), txn1.id);
    try std.testing.expectEqual(@as(TxnId, 2), txn2.id);
    try std.testing.expectEqual(@as(TxnId, 3), txn3.id);
}

test "TxnManager - commit changes transaction state" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit();

    var txn = try mgr.begin(.read_committed);

    try std.testing.expectEqual(TxnState.active, txn.state);

    try mgr.commit(txn);

    try std.testing.expectEqual(TxnState.committed, txn.state);
    try std.testing.expect(txn.commit_timestamp > 0);

    // After commit, transaction is removed from manager, so we must free it manually
    txn.deinit();
}

test "TxnManager - commit non-active transaction fails" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit();

    var txn = try mgr.begin(.read_committed);

    try mgr.commit(txn);

    // Try to commit again - should fail
    try std.testing.expectError(error.TransactionNotActive, mgr.commit(txn));

    // After commit, we must free manually
    txn.deinit();
}

test "TxnManager - abort changes transaction state" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit();

    var txn = try mgr.begin(.read_committed);

    mgr.abort(txn);

    try std.testing.expectEqual(TxnState.aborted, txn.state);

    // After abort, transaction is removed from manager, so we must free it manually
    txn.deinit();
}

test "TxnManager - getMinActiveTxn with no active txns" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit();

    // With no active transactions, min is initially 0 (set by init)
    const min = mgr.getMinActiveTxn();
    try std.testing.expectEqual(@as(TxnId, 0), min);
}

test "TxnManager - canSeeVersion snapshot isolation" {
    const allocator = std.testing.allocator;
    var mgr = try TxnManager.init(allocator);
    defer mgr.deinit(); // Manager will clean up the transaction

    const txn = try mgr.begin(.read_committed);

    // Transaction 1 can see versions from earlier transactions
    try std.testing.expect(mgr.canSeeVersion(txn, 0));

    // Transaction 1 cannot see versions from same or later transactions
    try std.testing.expect(!mgr.canSeeVersion(txn, 1));
    try std.testing.expect(!mgr.canSeeVersion(txn, 2));
}

test "TxnWrite - empty value indicates deletion" {
    const write = TxnWrite{
        .key = 100,
        .value = &[_]u8{},
        .timestamp = 12345,
    };

    try std.testing.expectEqual(@as(usize, 0), write.value.len);
    try std.testing.expectEqual(@as(u128, 100), write.key);
}

test "TxnRead - stores key and version" {
    const read = TxnRead{
        .key = 200,
        .version = 5,
    };

    try std.testing.expectEqual(@as(u128, 200), read.key);
    try std.testing.expectEqual(@as(TxnId, 5), read.version);
}
