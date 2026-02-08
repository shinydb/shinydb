const std = @import("std");
const Allocator = std.mem.Allocator;
const SkipList = @import("skiplist.zig").SkipList;

pub const SkipLists = struct {
    const Node = struct {
        data: *SkipList,
        next: ?*Node,
    };

    head: ?*Node,
    tail: ?*Node,
    len: usize,
    allocator: Allocator,

    // Initialize empty linked list
    pub fn init(allocator: Allocator) !*SkipLists {
        const skiplists = try allocator.create(SkipLists);

        skiplists.head = null;
        skiplists.tail = null;
        skiplists.len = 0;
        skiplists.allocator = allocator;
        return skiplists;
    }

    // Deinitialize and free all nodes
    pub fn deinit(self: *SkipLists) void {
        self.clear();
        self.allocator.destroy(self);
    }

    // Add element to the end of the list
    pub fn push(self: *SkipLists, list: *SkipList) !void {
        const node = try self.allocator.create(Node);

        node.* = Node{
            .data = list,
            .next = null,
        };

        if (self.tail) |tail| {
            tail.next = node;
            self.tail = node;
        } else {
            self.head = node;
            self.tail = node;
        }

        self.len += 1;
    }

    // Remove first element
    pub fn pop(self: *SkipLists) ?*SkipList {
        const head = self.head orelse return null;

        self.head = head.next;
        if (self.head == null) {
            self.tail = null;
        }

        const data = head.data;

        self.len -= 1;
        self.allocator.destroy(head); // Free the node memory
        return data;
    }

    pub fn get(self: *SkipLists, index: usize) !?*SkipList {
        if (index >= self.len) return error.IndexOutOfBounds;
        if (self.head == null) return null;

        var current = self.head;
        var i: usize = 0;
        while (i < index and current != null) : (i += 1) {
            current = current.?.next;
        }

        return if (current) |node| node.data else null;
    }

    // Remove all elements
    pub fn clear(self: *SkipLists) void {
        while (self.pop()) |node| {
            node.deinit();
        }
    }

    // Check if list is empty
    pub fn isEmpty(self: *const SkipLists) bool {
        return self.len == 0;
    }

    // Iterator for traversal
    pub const Iterator = struct {
        current: ?*Node,

        pub fn next(self: *Iterator) ?*SkipList {
            if (self.current) |node| {
                self.current = node.next;
                return node.data;
            } else {
                return null;
            }
        }

        pub fn peek(self: *const Iterator) ?*SkipList {
            if (self.current) |node| {
                return node.data;
            } else {
                return null;
            }
        }
    };

    // Get iterator
    pub fn iterator(self: *const SkipLists) Iterator {
        return Iterator{ .current = self.head };
    }
};
