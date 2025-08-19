const std = @import("std");
const testing = std.testing;

pub fn main() !void {
    std.log.info("Starting DoH server test suite...", .{});

    _ = @import("test_suite.zig");

    std.log.info("All tests completed successfully!", .{});
}

test "unit tests" {
    _ = @import("unit_tests.zig");
}

test "integration tests" {
    _ = @import("integration_tests.zig");
}

test "mock tests" {
    _ = @import("mock_tests.zig");
}
