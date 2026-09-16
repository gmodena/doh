const std = @import("std");

const LATENCY_BUCKETS_MS = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 1_000, 5_000, std.math.maxInt(u64) };

pub const Metrics = struct {
    requests_success: std.atomic.Value(u64),
    requests_error: std.atomic.Value(u64),
    latency_buckets: [LATENCY_BUCKETS_MS.len]std.atomic.Value(u64),
    latency_count: std.atomic.Value(u64),
    latency_sum: std.atomic.Value(u64),

    pub fn init() Metrics {
        return .{
            .requests_success = .init(0),
            .requests_error = .init(0),
            .latency_buckets = [_]std.atomic.Value(u64){.init(0)} ** LATENCY_BUCKETS_MS.len,
            .latency_count = .init(0),
            .latency_sum = .init(0),
        };
    }

    pub fn recordSuccess(self: *Metrics) void {
        _ = self.requests_success.fetchAdd(1, .monotonic);
    }

    pub fn recordError(self: *Metrics) void {
        _ = self.requests_error.fetchAdd(1, .monotonic);
    }

    pub fn recordLatency(self: *Metrics, ms: u64) void {
        _ = self.latency_count.fetchAdd(1, .monotonic);
        _ = self.latency_sum.fetchAdd(ms, .monotonic);

        inline for (LATENCY_BUCKETS_MS, 0..) |bound, i| {
            if (ms <= bound) {
                _ = self.latency_buckets[i].fetchAdd(1, .monotonic);
                return;
            }
        }
    }

    pub fn write(self: *Metrics, writer: anytype) !void {
        try writer.print(
            \\# HELP doh_requests_success_total Successful DNS responses
            \\# TYPE doh_requests_success_total counter
            \\doh_requests_success_total {d}
            \\# HELP doh_requests_error_total Failed DNS requests
            \\# TYPE doh_requests_error_total counter
            \\doh_requests_error_total {d}
            \\
        , .{
            self.requests_success.load(.monotonic),
            self.requests_error.load(.monotonic),
        });

        try writer.writeAll(
            \\# HELP doh_request_duration_ms Request latency
            \\# TYPE doh_request_duration_ms histogram
            \\
        );

        var cumulative: u64 = 0;
        inline for (LATENCY_BUCKETS_MS, 0..) |bound, i| {
            cumulative += self.latency_buckets[i].load(.monotonic);
            if (bound == std.math.maxInt(u64)) {
                try writer.print(
                    "doh_request_duration_ms{{le=\"+Inf\"}} {d}\n",
                    .{cumulative},
                );
            } else {
                try writer.print(
                    "doh_request_duration_ms{{le=\"{d}\"}} {d}\n",
                    .{ bound, cumulative },
                );
            }
        }
        // prom requires _sum and _count as part of the histogram type
        try writer.print(
            \\doh_request_duration_ms_count {d}
            \\doh_request_duration_ms_sum {d}
            \\
        , .{
            self.latency_count.load(.monotonic),
            self.latency_sum.load(.monotonic),
        });
    }
};
