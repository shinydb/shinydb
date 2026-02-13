const std = @import("std");

pub const MetricsSnapshot = struct {
    active_connections: u64,
    queued_connections: u64,
    total_processed: u64,
    total_rejected: u64,
    total_timeouts: u64,
    total_errors: u64,
};
