const std = @import("std");

test {
    _ = @import("unit_tests.zig");
    _ = @import("integration_tests.zig");
    _ = @import("mock_tests.zig");
}
