const std = @import("std");

pub const Offset = struct {
    page_id: u16,
    slot_id: u16,

    pub fn encode(page_id: u16, slot_id: u16) u64 {
        // Pack page_id (16 bits), slot_id (16 bits) into u64
        return (@as(u64, page_id) << 16) | @as(u64, slot_id);
    }

    pub fn decode(offset: u64) Offset {
        const page_id: u16 = @truncate((offset >> 16) & 0xFFFF);
        const slot_id: u16 = @truncate(offset & 0xFFFF);
        return Offset{ .page_id = page_id, .slot_id = slot_id };
    }
};

test "Offset encode and decode" {
    const page_id: u16 = 12345;
    const slot_id: u16 = 54321;
    const encoded = Offset.encode(page_id, slot_id);
    const decoded = Offset.decode(encoded);
    try std.testing.expectEqual(page_id, decoded.page_id);
    try std.testing.expectEqual(slot_id, decoded.slot_id);
}
