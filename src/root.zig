//! ShinyDb
//! Root module that exports all public APIs and imports all testable modules.
const std = @import("std");
const Io = std.Io;

// ============================================================================
// Public API Exports
// ============================================================================

pub const Engine = @import("engine/engine.zig").Engine;
pub const Config = @import("common/config.zig").Config;
pub const Entry = @import("common/common.zig").Entry;
pub const KeyGen = @import("common/keygen.zig").KeyGen;
pub const MemTable = @import("memtable/memtable.zig").MemTable;
pub const SkipList = @import("memtable/skiplist.zig").SkipList;
pub const MemoryPool = @import("memtable/memory_pool.zig").MemoryPool;
pub const MemoryPoolConfig = @import("memtable/memory_pool.zig").MemoryPoolConfig;
pub const milliTimestamp = @import("common/common.zig").milliTimestamp;
pub const OpKind = @import("common/common.zig").OpKind;
pub const Db = @import("storage/db.zig").Db;
pub const ValueLog = @import("storage/vlog.zig").ValueLog;
pub const SchemaManager = @import("storage/schema.zig").SchemaManager;
pub const Index = @import("storage/bptree.zig").Index;
pub const IndexConfig = @import("storage/bptree.zig").IndexConfig;
pub const SlottedPage = @import("storage/bptree.zig").SlottedPage;
pub const PageType = @import("storage/bptree.zig").PageType;
pub const Cell = @import("storage/bptree.zig").Cell;
pub const LruCache = @import("storage/lru_cache.zig").LruCache;
pub const WriteAheadLog = @import("durability/write_ahead_log.zig").WriteAheadLog;

// ============================================================================
// Test Imports (for test discovery)
// ============================================================================

test {
    // Import all modules with tests so they get discovered
    @import("std").testing.refAllDecls(@This());

    // Common modules
    _ = @import("common/config.zig");
    _ = @import("common/keygen.zig");
    _ = @import("common/common.zig");

    // Storage modules
    _ = @import("storage/vlog.zig");
    _ = @import("storage/schema.zig");
    _ = @import("storage/bptree.zig");
    _ = @import("storage/lru_cache.zig");
    _ = @import("storage/db.zig");
    _ = @import("storage/backup.zig");
    _ = @import("storage/replication.zig");
    _ = @import("storage/security.zig");

    // Memtable modules
    _ = @import("memtable/memtable.zig");
    _ = @import("memtable/memory_pool.zig");
    _ = @import("memtable/skiplist.zig");

    // Engine module
    _ = @import("engine/engine.zig");

    // TCP/Server modules
    _ = @import("tcp/worker_pool.zig");
}
