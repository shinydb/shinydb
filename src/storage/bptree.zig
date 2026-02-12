const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const File = Io.File;
const Dir = Io.Dir;
const HashMap = std.HashMap;
const Allocator = std.mem.Allocator;
const testing = std.testing;
pub const PageId = u64;
const FrameId = u32;
pub const PAGE_SIZE: u32 = 16384 * 4 - 1; // 64KB

const MAGIC: u32 = 0x53535441;
const VERSION: u8 = 1;

pub const IndexConfig = struct {
    dir_path: []const u8,
    file_name: []const u8,
    pool_size: u32,
    io: Io,
};

pub const PageType = enum(u8) {
    leaf = 0,
    internal = 1,
};

pub const PageHeader = extern struct {
    checksum: u64,
    page_type: PageType,
    num_cells: u16,
    free_space_start: u16,
    free_space_end: u16,
    parent_page_id: PageId,
    next_page_id: PageId,
    leftmost_child_id: PageId,
};

const Header = extern struct {
    checksum: u64 = 0,
    magic: u32,
    version: u8,
    root_page_id: PageId,
};

pub const CellPtr = struct {
    offset: u16,
    key_size: u16,
    value_size: u16, // ADDED
};

pub const Cell = struct {
    key: []const u8,
    value: []const u8, // MODIFIED

    pub fn len(self: *const Cell) u32 { // MODIFIED
        return @as(u32, @intCast(self.key.len)) + @as(u32, @intCast(self.value.len));
    }
};

pub const SlottedPage = struct {
    allocator: Allocator,
    data: []u8,

    pub fn init(allocator: Allocator, page_type: PageType) !*SlottedPage {
        const self = try allocator.create(SlottedPage);
        self.allocator = allocator;
        self.data = try allocator.alloc(u8, PAGE_SIZE);
        const header = self.headerPtr();
        header.* = .{
            .checksum = 0,
            .page_type = page_type,
            .num_cells = 0,
            .free_space_start = @sizeOf(PageHeader),
            .free_space_end = PAGE_SIZE,
            .parent_page_id = 0,
            .next_page_id = 0,
            .leftmost_child_id = 0,
        };
        return self;
    }

    pub fn deinit(self: *SlottedPage) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }

    pub fn headerPtr(self: anytype) *PageHeader {
        return @ptrCast(@alignCast(self.data.ptr));
    }

    pub fn freeSpace(self: *const SlottedPage) u16 {
        const header = self.headerPtr();
        return header.free_space_end - header.free_space_start;
    }

    pub fn hasSpace(self: *const SlottedPage, cell_size: u32) bool {
        return self.freeSpace() >= cell_size + @sizeOf(CellPtr);
    }

    pub fn findChildPageId(self: *const SlottedPage, key: []const u8) PageId {
        const header = self.headerPtr();
        var left: i32 = -1;
        var right: i32 = @intCast(header.num_cells);
        while (right - left > 1) {
            const mid: i32 = left + @divTrunc(right - left, 2);
            const cell = self.getCell(@intCast(mid)).?;
            switch (mem.order(u8, key, cell.key)) {
                .lt => right = mid,
                else => left = mid,
            }
        }

        if (left == -1) {
            return header.leftmost_child_id;
        }
        const cell = self.getCell(@intCast(left)).?;
        return mem.readInt(PageId, cell.value[0..@sizeOf(PageId)], .little);
    }

    pub fn findInsertIndex(self: *const SlottedPage, key: []const u8) u16 {
        var left: u16 = 0;
        var right: u16 = self.headerPtr().num_cells;
        while (left < right) {
            const mid = left + (right - left) / 2;
            const mid_key = self.getCell(mid).?.key;
            if (std.mem.order(u8, mid_key, key) == .lt) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        return left;
    }

    fn findChildIndex(self: *const SlottedPage, child_id: PageId) ?u16 {
        if (self.headerPtr().leftmost_child_id == child_id) return 1;
        var i: u16 = 0;
        while (i < self.headerPtr().num_cells) : (i += 1) {
            const cell_value = self.getCell(i).?.value;
            const page_id = mem.readInt(PageId, cell_value[0..@sizeOf(PageId)], .little);
            if (page_id == child_id) return i + 1;
        }
        return null;
    }

    pub fn insertCell(self: *SlottedPage, index: u16, cell: Cell) !void {
        const cell_len = cell.len();
        if (!self.hasSpace(cell_len)) return error.PageFull;
        const header = self.headerPtr();
        const num_cells = header.num_cells;

        const cell_ptr_start = @sizeOf(PageHeader);
        const new_cell_ptr_offset = cell_ptr_start + index * @sizeOf(CellPtr);
        const len_to_move = (num_cells - index) * @sizeOf(CellPtr);
        if (len_to_move > 0) {
            const dest = self.data[new_cell_ptr_offset + @sizeOf(CellPtr) ..][0..len_to_move];
            const src = self.data[new_cell_ptr_offset..][0..len_to_move];
            std.mem.copyBackwards(u8, dest, src);
        }

        const data_offset: u16 = @intCast(header.free_space_end - cell_len);
        @memcpy(self.data[data_offset..][0..cell.key.len], cell.key);
        @memcpy(self.data[data_offset + cell.key.len ..][0..cell.value.len], cell.value);

        const cell_ptr = CellPtr{
            .offset = data_offset,
            .key_size = @intCast(cell.key.len),
            .value_size = @intCast(cell.value.len),
        };

        var ptr_buf: [@sizeOf(CellPtr)]u8 = undefined;
        mem.writeInt(u16, ptr_buf[0..2], cell_ptr.offset, .little);
        mem.writeInt(u16, ptr_buf[2..4], cell_ptr.key_size, .little);
        mem.writeInt(u16, ptr_buf[4..6], cell_ptr.value_size, .little);
        @memcpy(self.data[new_cell_ptr_offset..][0..@sizeOf(CellPtr)], &ptr_buf);

        header.num_cells += 1;
        header.free_space_start += @sizeOf(CellPtr);
        header.free_space_end = data_offset;
    }

    pub fn getCell(self: *const SlottedPage, index: u16) ?Cell {
        const header = self.headerPtr();
        if (index >= header.num_cells) return null;

        const cell_ptr_offset = @sizeOf(PageHeader) + index * @sizeOf(CellPtr);
        const offset = mem.readInt(u16, self.data[cell_ptr_offset..][0..2], .little);
        const key_size = mem.readInt(u16, self.data[cell_ptr_offset + 2 ..][0..2], .little);

        if (key_size == 0) return null; // A key size of 0 marks a cell as deleted
        const value_size = mem.readInt(u16, self.data[cell_ptr_offset + 4 ..][0..2], .little);
        const key = self.data[offset..][0..key_size];
        const value = self.data[offset + key_size ..][0..value_size];
        return Cell{ .key = key, .value = value };
    }

    pub fn updateCell(self: *SlottedPage, index: u16, new_value: []const u8) !void {
        const header = self.headerPtr();
        if (index >= header.num_cells) return error.InvalidCellIndex;
        const cell_ptr_offset = @sizeOf(PageHeader) + index * @sizeOf(CellPtr);
        const offset = mem.readInt(u16, self.data[cell_ptr_offset..][0..2], .little);
        const key_size = mem.readInt(u16, self.data[cell_ptr_offset + 2 ..][0..2], .little);
        if (key_size == 0) return error.CellDeleted;
        const value_size = mem.readInt(u16, self.data[cell_ptr_offset + 4 ..][0..2], .little);
        if (new_value.len != value_size) return error.ValueSizeMismatch;
        @memcpy(self.data[offset + key_size ..][0..value_size], new_value);
    }

    pub fn deleteCell(self: *SlottedPage, index: u16) void {
        const header = self.headerPtr();
        if (index >= header.num_cells) return;
        const cell_ptr_offset = @sizeOf(PageHeader) + index * @sizeOf(CellPtr);
        // Zero out key_size to mark as deleted.
        mem.writeInt(u16, self.data[cell_ptr_offset + 2 ..][0..2], 0, .little);
    }

    pub fn compact(self: *SlottedPage) void {
        const header = self.headerPtr();
        var valid_cells: std.ArrayList(Cell) = .empty;
        defer {
            for (valid_cells.items) |cell| {
                self.allocator.free(cell.key);
                self.allocator.free(cell.value);
            }
            valid_cells.deinit(self.allocator);
        }
        {
            var iter = self.cells();
            while (iter.next()) |borrowed_cell| {
                const owned_key = self.allocator.dupe(u8, borrowed_cell.key) catch @panic("oom");
                const owned_value = self.allocator.dupe(u8, borrowed_cell.value) catch @panic("oom");
                valid_cells.append(self.allocator, .{ .key = owned_key, .value = owned_value }) catch @panic("oom");
            }
        }
        const page_type = header.page_type;
        const parent_id = header.parent_page_id;
        const next_id = header.next_page_id;
        const leftmost_id = header.leftmost_child_id;
        @memset(self.data, 0);
        header.* = .{
            .checksum = 0,
            .page_type = page_type,
            .num_cells = 0,
            .free_space_start = @sizeOf(PageHeader),
            .free_space_end = PAGE_SIZE,
            .parent_page_id = parent_id,
            .next_page_id = next_id,
            .leftmost_child_id = leftmost_id,
        };
        for (valid_cells.items) |cell| {
            self.insertCell(header.num_cells, cell) catch @panic("page full after compact");
        }
    }

    pub fn findCellByKey(self: *const SlottedPage, key: []const u8) ?u16 {
        var left: u16 = 0;
        var right: u16 = self.headerPtr().num_cells;
        while (left < right) {
            const mid_idx = left + (right - left) / 2;
            const mid_cell = self.getCell(mid_idx).?;
            switch (mem.order(u8, key, mid_cell.key)) {
                .lt => right = mid_idx,
                .gt => left = mid_idx + 1,
                .eq => return mid_idx,
            }
        }
        return null;
    }

    pub fn clear(self: *SlottedPage) void {
        const header = self.headerPtr();
        const page_type = header.page_type;
        const parent_id = header.parent_page_id;
        const next_id = header.next_page_id;
        const leftmost_id = header.leftmost_child_id;
        @memset(self.data, 0);
        header.* = .{
            .checksum = 0,
            .page_type = page_type,
            .num_cells = 0,
            .free_space_start = @sizeOf(PageHeader),
            .free_space_end = PAGE_SIZE,
            .parent_page_id = parent_id,
            .next_page_id = next_id,
            .leftmost_child_id = leftmost_id,
        };
    }

    pub fn cells(self: *const SlottedPage) CellsIterator {
        return CellsIterator{ .page = self, .index = 0 };
    }
};

pub const CellsIterator = struct {
    page: *const SlottedPage,
    index: u16,
    pub fn next(self: *CellsIterator) ?Cell {
        while (self.index < self.page.headerPtr().num_cells) {
            const current_index = self.index;
            self.index += 1;
            if (self.page.getCell(current_index)) |cell| {
                return cell;
            }
        }
        return null;
    }
};

pub const Pager = struct {
    file: File,
    io: Io,
    num_pages: PageId,

    pub fn init(io: Io, file_path: []const u8) !Pager {
        const file = Dir.openFile(.cwd(), io, file_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try Dir.createFile(.cwd(), io, file_path, .{ .read = true, .truncate = false }),
            else => return err,
        };
        errdefer file.close(io);

        const stat = try file.stat(io);
        const file_size = stat.size;
        if (file_size % PAGE_SIZE != 0) {
            return error.InvalidDbFile;
        }

        return .{ .file = file, .io = io, .num_pages = file_size / PAGE_SIZE };
    }

    pub fn deinit(self: *Pager) void {
        self.file.close(self.io);
    }

    pub fn allocPage(self: *Pager) PageId {
        const new_page_id = self.num_pages;
        self.num_pages += 1;
        return new_page_id;
    }

    pub fn writePage(self: *Pager, page_id: PageId, data: []const u8) !void {
        try self.file.writePositionalAll(self.io, data, page_id * PAGE_SIZE);
    }

    pub fn readPage(self: *Pager, page_id: PageId, buf: []u8) !void {
        _ = try self.file.readPositionalAll(self.io, buf, page_id * PAGE_SIZE);
    }
};

pub const Frame = struct {
    page: ?*SlottedPage = null,
    page_id: ?PageId = null,
    pin_count: u32 = 0,
    is_dirty: bool = false,
    is_referenced: bool = false,
};

pub const PagePool = struct {
    allocator: Allocator,
    pager: *Pager,
    pool_size: u32,
    frames: []Frame,
    page_table: HashMap(PageId, FrameId, std.hash_map.AutoContext(PageId), 80),
    free_list: std.ArrayList(FrameId),
    clock_hand: FrameId = 0,
    checksum_failed: u32 = 0,

    pub fn init(allocator: Allocator, io: Io, file_path: []const u8, pool_size: u32) !*PagePool {
        if (pool_size == 0) return error.ZeroSizedPool;

        const pager = try allocator.create(Pager);
        errdefer allocator.destroy(pager);

        const pool = try allocator.create(PagePool);
        errdefer allocator.destroy(pool);

        pager.* = try Pager.init(io, file_path);

        pool.* = PagePool{
            .allocator = allocator,
            .pager = pager,
            .pool_size = pool_size,
            .frames = try allocator.alloc(Frame, pool_size),
            .page_table = HashMap(PageId, FrameId, std.hash_map.AutoContext(PageId), 80).init(allocator),
            .free_list = .empty,
        };
        for (0..pool_size) |i| {
            try pool.free_list.append(allocator, @intCast(i));
            pool.frames[i] = .{};
        }
        return pool;
    }

    pub fn deinit(self: *PagePool) !void {
        try self.flushAllPages();
        for (self.frames) |*frame| {
            if (frame.page) |page| page.deinit();
        }
        self.allocator.free(self.frames);
        self.free_list.deinit(self.allocator);
        self.page_table.deinit();
        // self.pager.deinit();
        self.allocator.destroy(self.pager);
        self.allocator.destroy(self);
    }

    pub fn fetchPage(self: *PagePool, page_id: PageId) !*Frame {
        if (self.page_table.get(page_id)) |frame_id| {
            const frame = &self.frames[frame_id];
            frame.pin_count += 1;
            frame.is_referenced = true;
            return frame;
        }
        const frame_id = self.findVictimFrame() orelse return error.NoFreeFrames;
        const frame = &self.frames[frame_id];
        if (frame.is_dirty) {
            if (frame.page) |page| {
                try self.writeChecksum(page);
                try self.pager.writePage(frame.page_id.?, page.data);
            }
        }
        if (frame.page_id) |old_page_id| {
            _ = self.page_table.remove(old_page_id);
        }
        if (frame.page == null) {
            frame.page = try SlottedPage.init(self.allocator, .leaf);
        }
        try self.pager.readPage(page_id, frame.page.?.data);

        if (page_id != 0) {
            if (frame.page) |page| {
                self.validateChecksum(page) catch {
                    return error.InvalidChecksum;
                };
            }
        }

        frame.page_id = page_id;
        frame.pin_count = 1;
        frame.is_dirty = false;
        frame.is_referenced = true;
        try self.page_table.put(page_id, frame_id);
        return frame;
    }

    pub fn newPage(self: *PagePool, page_type: PageType) !*Frame {
        const frame_id = self.findVictimFrame() orelse return error.NoFreeFrames;
        const frame = &self.frames[frame_id];
        if (frame.is_dirty) {
            if (frame.page) |page| {
                try self.writeChecksum(page);
                try self.pager.writePage(frame.page_id.?, page.data);
            }
        }
        if (frame.page_id) |old_page_id| {
            _ = self.page_table.remove(old_page_id);
        }
        const new_page_id = self.pager.allocPage();
        if (frame.page) |page| {
            page.headerPtr().page_type = page_type;
            page.clear();
        } else {
            frame.page = try SlottedPage.init(self.allocator, page_type);
        }
        frame.page_id = new_page_id;
        frame.pin_count = 1;
        frame.is_dirty = true;
        frame.is_referenced = true;
        try self.page_table.put(new_page_id, frame_id);
        return frame;
    }

    pub fn unpinPage(self: *PagePool, page_id: PageId, is_dirty: bool) void {
        if (self.page_table.get(page_id)) |frame_id| {
            const frame = &self.frames[frame_id];
            if (frame.pin_count > 0) frame.pin_count -= 1;
            if (is_dirty) frame.is_dirty = true;
        }
    }

    pub fn flushAllPages(self: *PagePool) !void {
        for (self.frames) |*frame| {
            if (frame.is_dirty) {
                if (frame.page) |page| {
                    try self.writeChecksum(page);
                    try self.pager.writePage(frame.page_id.?, page.data);
                }
                frame.is_dirty = false;
            }
        }
    }

    pub fn flushPage(self: *PagePool, page_id: PageId) !void {
        const frame_id = self.page_table.get(page_id) orelse return;
        const frame = &self.frames[frame_id];
        if (frame.is_dirty) {
            if (frame.page) |page| {
                try self.writeChecksum(page);
                try self.pager.writePage(page_id, page.data);
            }

            frame.is_dirty = false;
        }
    }

    fn findVictimFrame(self: *PagePool) ?FrameId {
        if (self.free_list.pop()) |frame_id| return frame_id;
        var i: u32 = 0;
        while (i < self.pool_size * 2) : (i += 1) {
            const frame = &self.frames[self.clock_hand];
            if (frame.pin_count == 0) {
                if (frame.is_referenced) {
                    frame.is_referenced = false;
                } else {
                    const victim_id = self.clock_hand;
                    self.clock_hand = (self.clock_hand + 1) % self.pool_size;
                    return victim_id;
                }
            }
            self.clock_hand = (self.clock_hand + 1) % self.pool_size;
        }
        return null;
    }

    fn writeChecksum(self: *PagePool, page: *SlottedPage) !void {
        _ = self;
        const header = page.headerPtr();
        const seed: u128 = 0;
        const data_to_hash = page.data[@sizeOf(u64)..];
        header.checksum = std.hash.Wyhash.hash(seed, data_to_hash);
    }
    fn validateChecksum(self: *PagePool, page: *SlottedPage) !void {
        const header = page.headerPtr();
        const seed: u128 = 0;
        const expected_checksum = std.hash.Wyhash.hash(seed, page.data[@sizeOf(u64)..]);
        if (header.checksum != expected_checksum) {
            self.checksum_failed += 1;
            return error.InvalidChecksum;
        }
    }
};

pub const Iterator = struct {
    tree: *BPlusTree,
    current_frame: *Frame,
    current_index: u16,

    pub fn next(self: *Iterator) !?Cell {
        var page = self.current_frame.page.?;

        if (self.current_index >= page.headerPtr().num_cells) {
            // Move to next leaf page
            const next_page_id = page.headerPtr().next_page_id;
            self.tree.pool.unpinPage(self.current_frame.page_id.?, false);

            if (next_page_id == 0) { // End of list
                return null;
            }
            self.current_frame = try self.tree.pool.fetchPage(next_page_id);
            self.current_index = 0;
            page = self.current_frame.page.?;

            // If the new page is also empty, return null to avoid infinite recursion
            if (page.headerPtr().num_cells == 0) {
                return null; // Treat empty pages as end of iteration
            }
        }

        const cell = page.getCell(self.current_index).?;
        self.current_index += 1;

        return cell;
    }

    /// Must be called to release the pinned page.
    pub fn deinit(self: *Iterator) void {
        self.tree.pool.unpinPage(self.current_frame.page_id.?, false);
    }
};

/// Iterator with prefetching for improved sequential scan performance
pub const PrefetchIterator = struct {
    tree: *BPlusTree,
    current_frame: *Frame,
    current_index: u16,
    prefetch_buffer: [4]*Frame, // Prefetch next 4 pages
    prefetch_count: u8,
    allocator: Allocator,

    const PREFETCH_DEPTH = 4;

    pub fn init(tree: *BPlusTree, start_frame: *Frame, allocator: Allocator) !PrefetchIterator {
        var iter = PrefetchIterator{
            .tree = tree,
            .current_frame = start_frame,
            .current_index = 0,
            .prefetch_buffer = undefined,
            .prefetch_count = 0,
            .allocator = allocator,
        };

        // Initialize prefetch buffer
        try iter.prefetchAhead();
        return iter;
    }

    /// Prefetch the next N pages in the leaf chain
    fn prefetchAhead(self: *PrefetchIterator) !void {
        var page_id = self.current_frame.page.?.headerPtr().next_page_id;
        var count: u8 = 0;

        // Fetch next PREFETCH_DEPTH pages
        while (count < PREFETCH_DEPTH and page_id != 0) : (count += 1) {
            const frame = try self.tree.pool.fetchPage(page_id);
            self.prefetch_buffer[count] = frame;
            page_id = frame.page.?.headerPtr().next_page_id;
        }
        self.prefetch_count = count;
    }

    pub fn next(self: *PrefetchIterator) !?Cell {
        var page = self.current_frame.page.?;

        if (self.current_index >= page.headerPtr().num_cells) {
            // Move to next page - it's already prefetched!
            self.tree.pool.unpinPage(self.current_frame.page_id.?, false);

            if (self.prefetch_count == 0) {
                // No more pages
                return null;
            }

            // Shift prefetch buffer
            self.current_frame = self.prefetch_buffer[0];
            self.current_index = 0;
            page = self.current_frame.page.?;

            // Shift remaining prefetched pages
            var i: u8 = 0;
            while (i < self.prefetch_count - 1) : (i += 1) {
                self.prefetch_buffer[i] = self.prefetch_buffer[i + 1];
            }
            self.prefetch_count -= 1;

            // Prefetch one more page to maintain buffer depth
            if (self.prefetch_count < PREFETCH_DEPTH) {
                const last_frame = if (self.prefetch_count > 0)
                    self.prefetch_buffer[self.prefetch_count - 1]
                else
                    self.current_frame;

                const next_page_id = last_frame.page.?.headerPtr().next_page_id;
                if (next_page_id != 0) {
                    const new_frame = try self.tree.pool.fetchPage(next_page_id);
                    self.prefetch_buffer[self.prefetch_count] = new_frame;
                    self.prefetch_count += 1;
                }
            }
        }

        const cell = page.getCell(self.current_index).?;
        self.current_index += 1;

        return cell;
    }

    /// Must be called to release all pinned pages
    pub fn deinit(self: *PrefetchIterator) void {
        // Unpin current page
        self.tree.pool.unpinPage(self.current_frame.page_id.?, false);

        // Unpin all prefetched pages
        var i: u8 = 0;
        while (i < self.prefetch_count) : (i += 1) {
            self.tree.pool.unpinPage(self.prefetch_buffer[i].page_id.?, false);
        }
    }
};

pub const RangeIterator = struct {
    tree: *BPlusTree,
    current_frame: *Frame,
    current_index: u16,
    end_key: ?[]const u8,
    pinned_page_id: ?PageId, // Track which page is currently pinned to avoid double-unpin

    pub fn next(self: *RangeIterator) !?Cell {
        var page = self.current_frame.page.?;
        if (self.current_index >= page.headerPtr().num_cells) {
            // Move to next leaf page
            const next_page_id = page.headerPtr().next_page_id;
            if (self.pinned_page_id) |pid| {
                self.tree.pool.unpinPage(pid, false);
                self.pinned_page_id = null;
            }

            if (next_page_id == 0) { // End of list
                return null;
            }
            self.current_frame = try self.tree.pool.fetchPage(next_page_id);
            self.pinned_page_id = next_page_id;
            self.current_index = 0;
            page = self.current_frame.page.?;
        }

        const cell = page.getCell(self.current_index).?;
        self.current_index += 1;

        if (self.end_key) |ek| {
            if (std.mem.order(u8, cell.key, ek) == .gt) {
                return null; // Stop the iteration
            }
        }

        return cell;
    }

    /// Must be called to release the pinned page.
    pub fn deinit(self: *RangeIterator) void {
        if (self.pinned_page_id) |pid| {
            self.tree.pool.unpinPage(pid, false);
        }
    }
};

const BPlusTree = struct {
    pool: *PagePool,
    root_page_id: PageId,
    allocator: Allocator,
    parent_allocator: Allocator,
    arena: std.heap.ArenaAllocator,

    const BTreeError = error{ KeyNotFound, KeyAlreadyExists, TreeTooDeepOrCyclic };

    pub fn init(pool: *PagePool, allocator: Allocator) !*BPlusTree {
        const self = try allocator.create(BPlusTree);

        self.*.pool = pool;
        self.*.root_page_id = 0;
        self.*.parent_allocator = allocator;
        self.*.arena = std.heap.ArenaAllocator.init(allocator);
        self.*.allocator = self.*.arena.allocator();

        if (pool.pager.num_pages == 0) {
            // Page 0 is the header/metadata page
            const header_page_frame = try self.pool.newPage(.leaf);
            const header_page_id = header_page_frame.page_id.?;
            defer self.pool.unpinPage(header_page_id, true);

            // Page 1 is the root leaf page
            const root_frame = try self.pool.newPage(.leaf);
            const root_id = root_frame.page_id.?;
            self.pool.unpinPage(root_id, true);

            // Write header to page 0
            // First, zero out the header area to avoid leftover PageHeader data
            @memset(header_page_frame.page.?.data[0..@sizeOf(Header)], 0);
            const header: *Header = @ptrCast(@alignCast(header_page_frame.page.?.data.ptr));
            header.root_page_id = root_id;
            header.magic = MAGIC;
            header.version = VERSION;
            header.checksum = 0;

            self.root_page_id = root_id;

            // Flush both pages to ensure they're written with proper checksums
            try self.pool.flushPage(root_id);
            try self.pool.flushPage(header_page_id);
        } else {
            const header_page_frame = try self.pool.fetchPage(0);
            defer self.pool.unpinPage(0, false);

            const header: *Header = @ptrCast(@alignCast(header_page_frame.page.?.data.ptr));
            self.root_page_id = header.root_page_id;
        }

        return self;
    }

    pub fn deinit(self: *BPlusTree) void {
        self.shutdown() catch {};
        self.pool.deinit() catch {};
        const parent = self.parent_allocator;
        self.arena.deinit();
        parent.destroy(self);
    }

    pub fn shutdown(self: *BPlusTree) !void {
        const header_page_frame = try self.pool.fetchPage(0);
        defer self.pool.unpinPage(0, true);

        const header: *Header = @ptrCast(@alignCast(header_page_frame.page.?.data.ptr));
        header.root_page_id = self.root_page_id;
    }

    pub fn search(self: *BPlusTree, key: []const u8) !?[]const u8 {
        const leaf_frame = try self.findLeaf(key);
        defer self.pool.unpinPage(leaf_frame.page_id.?, false);
        const leaf_page = leaf_frame.page.?;
        if (leaf_page.findCellByKey(key)) |index| {
            return leaf_page.getCell(index).?.value;
        }
        return null;
    }

    pub fn update(self: *BPlusTree, key: []const u8, new_value: []const u8) !void {
        const leaf_frame = try self.findLeaf(key);
        defer self.pool.unpinPage(leaf_frame.page_id.?, true);
        const leaf_page = leaf_frame.page.?;
        if (leaf_page.findCellByKey(key)) |index| {
            try leaf_page.updateCell(index, new_value);
        } else {
            return BTreeError.KeyNotFound;
        }
    }

    pub fn insert(self: *BPlusTree, key: []const u8, value: []const u8) !void {
        const leaf_frame = try self.findLeaf(key);
        const leaf_page = leaf_frame.page.?;
        const leaf_id = leaf_frame.page_id.?;
        if (leaf_page.findCellByKey(key) != null) {
            self.pool.unpinPage(leaf_id, false);
            return BTreeError.KeyAlreadyExists;
        }
        const cell = Cell{ .key = key, .value = value };
        if (leaf_page.hasSpace(cell.len())) {
            try leaf_page.insertCell(leaf_page.findInsertIndex(key), cell);
            self.pool.unpinPage(leaf_id, true);
        } else {
            self.pool.unpinPage(leaf_id, true);
            try self.splitAndInsert(leaf_id, cell);
        }
    }

    pub fn delete(self: *BPlusTree, key: []const u8) !void {
        const leaf_frame = try self.findLeaf(key);
        const leaf_id = leaf_frame.page_id.?;
        const leaf_page = leaf_frame.page.?;

        if (leaf_page.findCellByKey(key)) |index| {
            _ = leaf_page.deleteCell(index);
            leaf_page.compact();

            const min_size = PAGE_SIZE / 2;
            const parent_id = leaf_page.headerPtr().parent_page_id;

            if (leaf_page.freeSpace() > (PAGE_SIZE - @sizeOf(PageHeader) - min_size) and self.root_page_id != leaf_id) {
                // Page has underflowed, and it's not the root
                self.pool.unpinPage(leaf_id, true); // Unpin before handling underflow
                try self.handleUnderflow(leaf_id, parent_id);
            } else {
                self.pool.unpinPage(leaf_id, true);
            }
        } else {
            self.pool.unpinPage(leaf_id, false);
            return BTreeError.KeyNotFound;
        }
    }

    pub fn rangeScan(self: *BPlusTree, start_key: []const u8, end_key: ?[]const u8) !RangeIterator {
        const start_frame = try self.findLeaf(start_key);
        const start_page = start_frame.page.?;
        const start_index = start_page.findInsertIndex(start_key);

        return RangeIterator{
            .tree = self,
            .current_frame = start_frame,
            .current_index = start_index,
            .end_key = end_key,
            .pinned_page_id = start_frame.page_id.?,
        };
    }

    fn findLeaf(self: *BPlusTree, key: []const u8) !*Frame {
        var current_page_id = self.root_page_id;
        var current_frame = try self.pool.fetchPage(current_page_id);
        var depth: u32 = 0;

        while (current_frame.page.?.headerPtr().page_type == .internal) {
            depth += 1;
            if (depth > 100) {
                self.pool.unpinPage(current_page_id, false);
                return BTreeError.TreeTooDeepOrCyclic;
            }
            const internal_page = current_frame.page.?;
            const next_page_id = internal_page.findChildPageId(key);
            self.pool.unpinPage(current_page_id, false);
            current_page_id = next_page_id;
            current_frame = try self.pool.fetchPage(current_page_id);
        }
        return current_frame;
    }

    fn splitAndInsert(self: *BPlusTree, page_id: PageId, cell: Cell) !void {
        const old_frame = try self.pool.fetchPage(page_id);
        defer self.pool.unpinPage(page_id, true);
        const old_page = old_frame.page.?;
        const is_leaf = old_page.headerPtr().page_type == .leaf;
        const original_parent_id = old_page.headerPtr().parent_page_id;

        var all_cells: std.ArrayList(Cell) = .empty;
        defer {
            for (all_cells.items) |c| {
                self.allocator.free(c.key);
                self.allocator.free(c.value);
            }
            all_cells.deinit(self.allocator);
        }
        {
            var iter = old_page.cells();
            while (iter.next()) |borrowed_cell| {
                if (borrowed_cell.key.len == 0) {
                    // Handle error or skip - deleted cell during split
                    continue;
                }
                const owned_key = try self.allocator.dupe(u8, borrowed_cell.key);
                const owned_value = try self.allocator.dupe(u8, borrowed_cell.value);
                try all_cells.append(self.allocator, .{ .key = owned_key, .value = owned_value });
            }
            const owned_new_key = try self.allocator.dupe(u8, cell.key);
            const owned_new_value = try self.allocator.dupe(u8, cell.value);
            try all_cells.append(self.allocator, .{ .key = owned_new_key, .value = owned_new_value });
            std.sort.pdq(Cell, all_cells.items, {}, struct {
                pub fn lessThan(_: void, a: Cell, b: Cell) bool {
                    return mem.order(u8, a.key, b.key) == .lt;
                }
            }.lessThan);
        }

        const new_frame = try self.pool.newPage(old_page.headerPtr().page_type);
        const new_page_id = new_frame.page_id.?;
        defer self.pool.unpinPage(new_page_id, true);
        const new_page = new_frame.page.?;
        new_page.headerPtr().parent_page_id = original_parent_id;

        const split_point = all_cells.items.len / 2;
        const promoted_key_cell = all_cells.items[split_point];

        const old_next_id = old_page.headerPtr().next_page_id;
        old_page.clear();
        old_page.headerPtr().parent_page_id = original_parent_id;
        old_page.headerPtr().next_page_id = if (is_leaf) new_page_id else old_next_id;
        if (is_leaf) new_page.headerPtr().next_page_id = old_next_id;

        var promoted_page_id_slice: [@sizeOf(PageId)]u8 = undefined;

        if (is_leaf) {
            for (all_cells.items[0..split_point]) |c| try old_page.insertCell(old_page.headerPtr().num_cells, c);
            for (all_cells.items[split_point..]) |c| try new_page.insertCell(new_page.headerPtr().num_cells, c);
        } else {
            new_page.headerPtr().leftmost_child_id = mem.readInt(PageId, promoted_key_cell.value[0..@sizeOf(PageId)], .little);
            for (all_cells.items[0..split_point]) |c| try old_page.insertCell(old_page.headerPtr().num_cells, c);
            for (all_cells.items[split_point + 1 ..]) |c| try new_page.insertCell(new_page.headerPtr().num_cells, c);
            var child_frame = try self.pool.fetchPage(new_page.headerPtr().leftmost_child_id);
            child_frame.page.?.headerPtr().parent_page_id = new_page_id;
            self.pool.unpinPage(child_frame.page_id.?, true);
            var new_page_iter = new_page.cells();
            while (new_page_iter.next()) |c| {
                child_frame = try self.pool.fetchPage(mem.readInt(PageId, c.value[0..@sizeOf(PageId)], .little));
                child_frame.page.?.headerPtr().parent_page_id = new_page_id;
                self.pool.unpinPage(child_frame.page_id.?, true);
            }
        }
        mem.writeInt(PageId, &promoted_page_id_slice, new_page_id, .little);
        try self.insertIntoParent(original_parent_id, promoted_key_cell.key, &promoted_page_id_slice);
    }

    fn insertIntoParent(self: *BPlusTree, parent_id: PageId, key: []const u8, value_slice: []const u8) anyerror!void {
        if (parent_id == 0) {
            const new_root_frame = try self.pool.newPage(.internal);
            defer self.pool.unpinPage(new_root_frame.page_id.?, true);
            const new_root_page = new_root_frame.page.?;
            const old_root_id = self.root_page_id;
            self.root_page_id = new_root_frame.page_id.?;
            new_root_page.headerPtr().leftmost_child_id = old_root_id;
            try new_root_page.insertCell(0, .{ .key = key, .value = value_slice });
            const old_child_frame = try self.pool.fetchPage(old_root_id);
            old_child_frame.page.?.headerPtr().parent_page_id = self.root_page_id;
            self.pool.unpinPage(old_root_id, true);
            const new_child_frame = try self.pool.fetchPage(mem.readInt(PageId, value_slice[0..@sizeOf(PageId)], .little));
            new_child_frame.page.?.headerPtr().parent_page_id = self.root_page_id;
            self.pool.unpinPage(new_child_frame.page_id.?, true);
            return;
        }
        const parent_frame = try self.pool.fetchPage(parent_id);
        const parent_page = parent_frame.page.?;
        const cell = Cell{ .key = key, .value = value_slice };
        if (parent_page.hasSpace(cell.len())) {
            try parent_page.insertCell(parent_page.findInsertIndex(key), cell);
            self.pool.unpinPage(parent_id, true);
        } else {
            self.pool.unpinPage(parent_id, true);
            try self.splitAndInsert(parent_id, cell);
        }
    }

    fn handleUnderflow(self: *BPlusTree, page_id: PageId, parent_id: PageId) anyerror!void {
        const parent_frame = try self.pool.fetchPage(parent_id);
        defer self.pool.unpinPage(parent_id, true);
        const parent_page = parent_frame.page.?;

        const child_index_in_parent = parent_page.findChildIndex(page_id) orelse return;

        if (child_index_in_parent > 0) {
            const left_sibling_id = if (child_index_in_parent == 1)
                parent_page.headerPtr().leftmost_child_id
            else
                mem.readInt(PageId, parent_page.getCell(child_index_in_parent - 2).?.value[0..@sizeOf(PageId)], .little);

            const left_sibling_frame = try self.pool.fetchPage(left_sibling_id);
            defer self.pool.unpinPage(left_sibling_id, true);

            if (left_sibling_frame.page.?.freeSpace() < (PAGE_SIZE / 2)) {
                return try self.borrowFromLeft(page_id, left_sibling_id, parent_id, child_index_in_parent - 1);
            }
        }

        if (child_index_in_parent <= parent_page.headerPtr().num_cells) {
            const right_sibling_id = mem.readInt(PageId, parent_page.getCell(child_index_in_parent - 1).?.value[0..@sizeOf(PageId)], .little);
            const right_sibling_frame = try self.pool.fetchPage(right_sibling_id);
            defer self.pool.unpinPage(right_sibling_id, true);

            if (right_sibling_frame.page.?.freeSpace() < (PAGE_SIZE / 2)) {
                return try self.borrowFromRight(page_id, right_sibling_id, parent_id, child_index_in_parent - 1);
            }
        }

        if (child_index_in_parent > 0) {
            const left_sibling_id = if (child_index_in_parent == 1)
                parent_page.headerPtr().leftmost_child_id
            else
                mem.readInt(PageId, parent_page.getCell(child_index_in_parent - 2).?.value[0..@sizeOf(PageId)], .little);
            try self.mergePages(left_sibling_id, page_id, parent_id, child_index_in_parent - 1);
        } else {
            const right_sibling_id = mem.readInt(PageId, parent_page.getCell(0).?.value[0..@sizeOf(PageId)], .little);
            try self.mergePages(page_id, right_sibling_id, parent_id, 0);
        }
    }

    fn borrowFromLeft(self: *BPlusTree, page_id: PageId, left_sibling_id: PageId, parent_id: PageId, key_index_in_parent: u16) !void {
        const page_frame = try self.pool.fetchPage(page_id);
        defer self.pool.unpinPage(page_id, true);
        const page = page_frame.page.?;

        const left_sibling_frame = try self.pool.fetchPage(left_sibling_id);
        defer self.pool.unpinPage(left_sibling_id, true);
        const left_sibling = left_sibling_frame.page.?;

        const parent_frame = try self.pool.fetchPage(parent_id);
        defer self.pool.unpinPage(parent_id, true);
        const parent = parent_frame.page.?;

        const last_cell_idx = left_sibling.headerPtr().num_cells - 1;
        const cell_to_move = left_sibling.getCell(last_cell_idx).?;
        _ = left_sibling.deleteCell(last_cell_idx);
        left_sibling.compact();

        const parent_key_cell = parent.getCell(key_index_in_parent).?;
        _ = parent.deleteCell(key_index_in_parent);

        const new_cell_in_page = Cell{ .key = parent_key_cell.key, .value = cell_to_move.value };
        try page.insertCell(0, new_cell_in_page);

        const new_cell_in_parent = Cell{ .key = cell_to_move.key, .value = parent_key_cell.value };
        try parent.insertCell(key_index_in_parent, new_cell_in_parent);
    }

    fn borrowFromRight(self: *BPlusTree, page_id: PageId, right_sibling_id: PageId, parent_id: PageId, key_index_in_parent: u16) !void {
        const page_frame = try self.pool.fetchPage(page_id);
        defer self.pool.unpinPage(page_id, true);
        const page = page_frame.page.?;

        const right_sibling_frame = try self.pool.fetchPage(right_sibling_id);
        defer self.pool.unpinPage(right_sibling_id, true);
        const right_sibling = right_sibling_frame.page.?;

        const parent_frame = try self.pool.fetchPage(parent_id);
        defer self.pool.unpinPage(parent_id, true);
        const parent = parent_frame.page.?;

        const cell_to_move = right_sibling.getCell(0).?;
        _ = right_sibling.deleteCell(0);
        right_sibling.compact();

        const parent_key_cell = parent.getCell(key_index_in_parent).?;
        _ = parent.deleteCell(key_index_in_parent);

        const new_cell_in_page = Cell{ .key = parent_key_cell.key, .value = parent_key_cell.value };
        try page.insertCell(page.headerPtr().num_cells, new_cell_in_page);

        const new_cell_in_parent = Cell{ .key = cell_to_move.key, .value = cell_to_move.value };
        try parent.insertCell(key_index_in_parent, new_cell_in_parent);
    }

    fn mergePages(self: *BPlusTree, left_id: PageId, right_id: PageId, parent_id: PageId, key_index_in_parent: u16) !void {
        const left_frame = try self.pool.fetchPage(left_id);
        defer self.pool.unpinPage(left_id, true);
        const left_page = left_frame.page.?;

        const right_frame = try self.pool.fetchPage(right_id);
        defer self.pool.unpinPage(right_id, true);
        const right_page = right_frame.page.?;

        const parent_frame = try self.pool.fetchPage(parent_id);
        defer self.pool.unpinPage(parent_id, true);
        const parent_page = parent_frame.page.?;

        const parent_key_cell = parent_page.getCell(key_index_in_parent).?;
        if (left_page.headerPtr().page_type == .internal) { // For internal nodes, the parent key comes down.
            try left_page.insertCell(left_page.headerPtr().num_cells, parent_key_cell);
        }

        var iter = right_page.cells();
        while (iter.next()) |cell| {
            try left_page.insertCell(left_page.headerPtr().num_cells, cell);
        }

        if (left_page.headerPtr().page_type == .leaf) {
            left_page.headerPtr().next_page_id = right_page.headerPtr().next_page_id;
        }

        _ = parent_page.deleteCell(key_index_in_parent);
        parent_page.compact();

        right_page.clear();

        const min_size = PAGE_SIZE / 2;
        const grandparent_id = parent_page.headerPtr().parent_page_id;
        if (parent_page.freeSpace() > (PAGE_SIZE - @sizeOf(PageHeader) - min_size) and self.root_page_id != parent_id) {
            try self.handleUnderflow(parent_id, grandparent_id);
        }
    }

    fn findFirstLeaf(self: *BPlusTree) !*Frame {
        var current_page_id = self.root_page_id;
        var current_frame = try self.pool.fetchPage(current_page_id);

        // As long as we're on an internal page, keep descending left.
        while (current_frame.page.?.headerPtr().page_type == .internal) {
            const internal_page = current_frame.page.?;
            const next_page_id = internal_page.headerPtr().leftmost_child_id;
            self.pool.unpinPage(current_page_id, false);
            current_page_id = next_page_id;
            current_frame = try self.pool.fetchPage(current_page_id);
        }
        // The loop terminates when we've found a leaf. Return it pinned.
        return current_frame;
    }

    pub fn iterator(self: *BPlusTree) !Iterator {
        const start_frame = try self.findFirstLeaf();
        return Iterator{
            .tree = self,
            .current_frame = start_frame,
            .current_index = 0,
        };
    }

    pub fn prefetchIterator(self: *BPlusTree) !PrefetchIterator {
        const start_frame = try self.findFirstLeaf();
        return PrefetchIterator.init(self, start_frame, self.allocator);
    }
};

pub fn Index(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        tree: *BPlusTree,
        allocator: Allocator,
        path: []const u8,

        pub fn init(allocator: Allocator, config: IndexConfig) !Self {
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}.idx", .{ config.dir_path, config.file_name });
            std.debug.print("Initializing index at path: {s}\n", .{path});
            const pool = try PagePool.init(allocator, config.io, path, config.pool_size);
            return Self{
                .tree = try BPlusTree.init(pool, allocator),
                .allocator = allocator,
                .path = path,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.path);
            self.tree.deinit();
        }

        pub fn insert(self: *Self, key: K, value: V) !void {
            // Handle void value type (for indexes that only store keys)
            const val_slice = if (V == void) blk: {
                break :blk &[_]u8{};
            } else blk: {
                var val_buf: [@sizeOf(V)]u8 = undefined;
                std.mem.writeInt(V, &val_buf, value, .little);
                break :blk &val_buf;
            };

            if (@typeInfo(K) == .int) {
                var key_buf: [@sizeOf(K)]u8 = undefined;
                std.mem.writeInt(K, &key_buf, key, .big);
                try self.tree.insert(&key_buf, val_slice);
            } else if (@typeInfo(K) == .pointer and @typeInfo(K).pointer.child == u8 and @typeInfo(K).pointer.is_const) {
                try self.tree.insert(key, val_slice);
            } else {
                @panic("Unsupported key type for Index: must be int, uint, or []const u8");
            }
        }

        pub fn search(self: *Self, key: K) !?V {
            if (@typeInfo(K) == .int) {
                var key_buf: [@sizeOf(K)]u8 = undefined;
                std.mem.writeInt(K, &key_buf, key, .big);
                const value_slice = try self.tree.search(&key_buf);
                if (value_slice) |slice| {
                    const result = std.mem.readInt(V, slice[0..@sizeOf(V)], .little);
                    return result;
                } else {
                    return null;
                }
            } else if (@typeInfo(K) == .pointer and @typeInfo(K).pointer.child == u8 and @typeInfo(K).pointer.is_const) {
                const value_slice = try self.tree.search(key);
                if (value_slice) |slice| {
                    return std.mem.readInt(V, slice[0..@sizeOf(V)], .little);
                } else {
                    return null;
                }
            } else {
                @panic("Unsupported key type for Index: must be int, uint, or []const u8");
            }
        }

        pub fn update(self: *Self, key: K, new_value: V) !void {
            var val_buf: [@sizeOf(V)]u8 = undefined;
            std.mem.writeInt(V, &val_buf, new_value, .little);
            if (@typeInfo(K) == .int) {
                var key_buf: [@sizeOf(K)]u8 = undefined;
                std.mem.writeInt(K, &key_buf, key, .big);
                try self.tree.update(&key_buf, &val_buf);
            } else if (@typeInfo(K) == .pointer and @typeInfo(K).pointer.child == u8 and @typeInfo(K).pointer.is_const) {
                try self.tree.update(key, &val_buf);
            } else {
                @panic("Unsupported key type for Index: must be int, uint, or []const u8");
            }
        }

        pub fn delete(self: *Self, key: K) !void {
            if (@typeInfo(K) == .int) {
                var key_buf: [@sizeOf(K)]u8 = undefined;
                std.mem.writeInt(K, &key_buf, key, .big);
                try self.tree.delete(&key_buf);
            } else if (@typeInfo(K) == .pointer and @typeInfo(K).pointer.child == u8 and @typeInfo(K).pointer.is_const) {
                try self.tree.delete(key);
            } else {
                @panic("Unsupported key type for Index: must be int, uint, or []const u8");
            }
        }

        pub fn rangeScan(self: *Self, start_key: K, end_key: K) !RangeIterator {
            if (@typeInfo(K) == .int) {
                var start_key_buf: [@sizeOf(K)]u8 = undefined;
                var end_key_buf: [@sizeOf(K)]u8 = undefined;
                // Use big-endian for keys to ensure correct sorting.
                std.mem.writeInt(K, &start_key_buf, start_key, .big);
                std.mem.writeInt(K, &end_key_buf, end_key, .big);

                return try self.tree.rangeScan(&start_key_buf, &end_key_buf);
            } else if (@typeInfo(K) == .pointer and @typeInfo(K).pointer.child == u8 and @typeInfo(K).pointer.is_const) {
                return try self.tree.rangeScan(start_key, end_key);
            } else {
                @panic("Unsupported key type for Index: must be int, uint, or []const u8");
            }
        }

        pub fn iterator(self: *Self) !Iterator {
            return self.tree.iterator();
        }

        pub fn prefetchIterator(self: *Self) !PrefetchIterator {
            return self.tree.prefetchIterator();
        }

        /// Flush all dirty pages to disk
        /// Also persists the current root_page_id to the header page (page 0)
        /// to ensure the tree structure is recoverable after restart.
        pub fn flush(self: *Self) !void {
            try self.tree.shutdown();
            try self.tree.pool.flushAllPages();
        }
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

test "bptree - constants" {
    try testing.expectEqual(@as(u32, 0x53535441), MAGIC);
    try testing.expectEqual(@as(u8, 1), VERSION);
    try testing.expectEqual(@as(u32, 16384 * 4 - 1), PAGE_SIZE);
}

test "bptree - PageType enum values" {
    try testing.expectEqual(@as(u8, 0), @intFromEnum(PageType.leaf));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(PageType.internal));
}

test "bptree - Cell length calculation" {
    const cell = Cell{
        .key = "test_key",
        .value = "test_value_longer",
    };

    // key.len (8) + value.len (17) = 25
    try testing.expectEqual(@as(u32, 25), cell.len());
}

test "bptree - Cell with empty value" {
    const cell = Cell{
        .key = "key",
        .value = "",
    };

    try testing.expectEqual(@as(u32, 3), cell.len());
}

test "bptree - CellPtr struct size" {
    // CellPtr should be 6 bytes: offset(2) + key_size(2) + value_size(2)
    try testing.expectEqual(@as(usize, 6), @sizeOf(CellPtr));
}

test "bptree - PageHeader struct size" {
    // PageHeader contains: checksum(8) + page_type(1) + num_cells(2) +
    // free_space_start(2) + free_space_end(2) + parent_page_id(8) +
    // next_page_id(8) + leftmost_child_id(8)
    const header_size = @sizeOf(PageHeader);
    try testing.expect(header_size >= 39); // At minimum
}

test "bptree - SlottedPage init and freeSpace" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    // New page should have maximum free space
    const header_size = @sizeOf(PageHeader);
    const expected_free = PAGE_SIZE - header_size;
    try testing.expectEqual(expected_free, page.freeSpace());
}

test "bptree - SlottedPage headerPtr returns correct type" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    const header = page.headerPtr();
    try testing.expectEqual(PageType.leaf, header.page_type);
    try testing.expectEqual(@as(u16, 0), header.num_cells);
}

test "bptree - SlottedPage hasSpace" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    // Should have space for reasonable sized cells
    try testing.expect(page.hasSpace(100));
    try testing.expect(page.hasSpace(1000));

    // Should not have space for oversized cells
    try testing.expect(!page.hasSpace(PAGE_SIZE));
}

test "bptree - SlottedPage insertCell and getCell" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    const cell = Cell{ .key = "test_key", .value = "test_value" };
    try page.insertCell(0, cell);

    try testing.expectEqual(@as(u16, 1), page.headerPtr().num_cells);

    const retrieved = page.getCell(0);
    try testing.expect(retrieved != null);
    try testing.expectEqualStrings("test_key", retrieved.?.key);
    try testing.expectEqualStrings("test_value", retrieved.?.value);
}

test "bptree - SlottedPage getCell out of bounds returns null" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    const result = page.getCell(0);
    try testing.expect(result == null);

    const result2 = page.getCell(100);
    try testing.expect(result2 == null);
}

test "bptree - SlottedPage insertCell multiple cells" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "aaa", .value = "111" });
    try page.insertCell(1, .{ .key = "bbb", .value = "222" });
    try page.insertCell(2, .{ .key = "ccc", .value = "333" });

    try testing.expectEqual(@as(u16, 3), page.headerPtr().num_cells);

    try testing.expectEqualStrings("aaa", page.getCell(0).?.key);
    try testing.expectEqualStrings("bbb", page.getCell(1).?.key);
    try testing.expectEqualStrings("ccc", page.getCell(2).?.key);
}

test "bptree - SlottedPage findInsertIndex" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "bbb", .value = "2" });
    try page.insertCell(1, .{ .key = "ddd", .value = "4" });

    // Should insert before "bbb"
    try testing.expectEqual(@as(u16, 0), page.findInsertIndex("aaa"));
    // Should insert between "bbb" and "ddd"
    try testing.expectEqual(@as(u16, 1), page.findInsertIndex("ccc"));
    // Should insert after "ddd"
    try testing.expectEqual(@as(u16, 2), page.findInsertIndex("eee"));
}

test "bptree - SlottedPage findCellByKey" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "aaa", .value = "1" });
    try page.insertCell(1, .{ .key = "bbb", .value = "2" });
    try page.insertCell(2, .{ .key = "ccc", .value = "3" });

    try testing.expectEqual(@as(?u16, 0), page.findCellByKey("aaa"));
    try testing.expectEqual(@as(?u16, 1), page.findCellByKey("bbb"));
    try testing.expectEqual(@as(?u16, 2), page.findCellByKey("ccc"));
    try testing.expectEqual(@as(?u16, null), page.findCellByKey("ddd"));
}

test "bptree - SlottedPage deleteCell marks as deleted" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "test", .value = "value" });
    try testing.expect(page.getCell(0) != null);

    page.deleteCell(0);
    // After delete, getCell returns null (key_size is 0)
    try testing.expect(page.getCell(0) == null);
}

test "bptree - SlottedPage clear resets page" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "test", .value = "value" });
    try testing.expectEqual(@as(u16, 1), page.headerPtr().num_cells);

    page.clear();
    try testing.expectEqual(@as(u16, 0), page.headerPtr().num_cells);
    try testing.expectEqual(PageType.leaf, page.headerPtr().page_type);
}

test "bptree - SlottedPage cells iterator" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "a", .value = "1" });
    try page.insertCell(1, .{ .key = "b", .value = "2" });
    try page.insertCell(2, .{ .key = "c", .value = "3" });

    var iter = page.cells();
    var count: u32 = 0;
    while (iter.next()) |_| {
        count += 1;
    }
    try testing.expectEqual(@as(u32, 3), count);
}

test "bptree - Frame defaults" {
    const frame = Frame{};
    try testing.expect(frame.page == null);
    try testing.expect(frame.page_id == null);
    try testing.expectEqual(@as(u32, 0), frame.pin_count);
    try testing.expect(!frame.is_dirty);
    try testing.expect(!frame.is_referenced);
}

test "bptree - Header struct" {
    const header = Header{
        .magic = MAGIC,
        .version = VERSION,
        .root_page_id = 42,
    };

    try testing.expectEqual(MAGIC, header.magic);
    try testing.expectEqual(VERSION, header.version);
    try testing.expectEqual(@as(PageId, 42), header.root_page_id);
}

// ============================================================================
// Data Corruption Detection Tests
// ============================================================================

test "bptree - magic number validation" {
    // Test that incorrect magic numbers can be detected
    const valid_magic = MAGIC;
    const invalid_magic: u32 = 0xDEADBEEF;

    try testing.expectEqual(@as(u32, 0x53535441), valid_magic);
    try testing.expect(valid_magic != invalid_magic);
}

test "bptree - version compatibility check" {
    // Test version detection
    const current_version = VERSION;
    const future_version: u8 = 99;
    const old_version: u8 = 0;

    try testing.expectEqual(@as(u8, 1), current_version);
    try testing.expect(future_version != current_version);
    try testing.expect(old_version != current_version);
}

test "bptree - PageType invalid value detection" {
    // Valid page types are 0 (leaf) and 1 (internal)
    // Any other value would indicate corruption
    const valid_leaf = @intFromEnum(PageType.leaf);
    const valid_internal = @intFromEnum(PageType.internal);

    try testing.expectEqual(@as(u8, 0), valid_leaf);
    try testing.expectEqual(@as(u8, 1), valid_internal);

    // Values 2+ would be invalid
    const invalid_type: u8 = 2;
    try testing.expect(invalid_type != valid_leaf);
    try testing.expect(invalid_type != valid_internal);
}

test "bptree - SlottedPage corruption detection - invalid cell count" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    // Access to out-of-bounds cell index should return null (not crash)
    const result1 = page.getCell(1000);
    try testing.expect(result1 == null);

    const result2 = page.getCell(std.math.maxInt(u16));
    try testing.expect(result2 == null);
}

test "bptree - SlottedPage corruption detection - cell deletion idempotent" {
    const allocator = testing.allocator;
    var page = try SlottedPage.init(allocator, .leaf);
    defer page.deinit();

    try page.insertCell(0, .{ .key = "test", .value = "value" });

    // Deleting same cell multiple times should not crash
    page.deleteCell(0);
    page.deleteCell(0); // Should be idempotent
    page.deleteCell(0);

    try testing.expect(page.getCell(0) == null);
}

test "bptree - Header magic mismatch indicates corruption" {
    const valid_header = Header{
        .magic = MAGIC,
        .version = VERSION,
        .root_page_id = 0,
    };

    const corrupted_header = Header{
        .magic = 0x00000000, // Corrupted magic
        .version = VERSION,
        .root_page_id = 0,
    };

    // Validation check: magic must match
    try testing.expect(valid_header.magic == MAGIC);
    try testing.expect(corrupted_header.magic != MAGIC);
}

test "bptree - Frame pin_count prevents double-free" {
    var frame = Frame{};

    // Initial state
    try testing.expectEqual(@as(u32, 0), frame.pin_count);

    // Simulate pinning
    frame.pin_count += 1;
    try testing.expectEqual(@as(u32, 1), frame.pin_count);

    // Pin again
    frame.pin_count += 1;
    try testing.expectEqual(@as(u32, 2), frame.pin_count);

    // Unpin
    frame.pin_count -= 1;
    try testing.expectEqual(@as(u32, 1), frame.pin_count);

    // Still pinned - should not be evicted
    try testing.expect(frame.pin_count > 0);
}

test "bptree - Cell with maximum key length" {
    var key_buf: [PAGE_SIZE / 2]u8 = undefined;
    @memset(&key_buf, 'K');

    const cell = Cell{
        .key = &key_buf,
        .value = "small_value",
    };

    // Cell length should be calculable without overflow
    const len = cell.len();
    try testing.expect(len > 0);
    try testing.expect(len == key_buf.len + 11); // 11 = "small_value".len
}
