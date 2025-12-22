const std = @import("std");
const testing = std.testing;
const errorz = @import("error");

var retry_count: u32 = 0;

fn failingFunction() !void {
    retry_count += 1;
    return error.DnsQueryFailed;
}

test "retry: basic retry" {
    retry_count = 0;

    const policy = errorz.RetryPolicy{
        .max_tries = 5,
        .delay_ms = 2,
        .timeout_ms = 10,
    };

    const result = errorz.retry(failingFunction, .{}, policy);

    try testing.expectError(error.DnsQueryFailed, result);
    try testing.expectEqual(@as(u32, 5), retry_count);
}
