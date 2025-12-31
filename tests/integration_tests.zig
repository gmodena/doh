const std = @import("std");
const testing = std.testing;
const server = @import("server");
const net = std.net;
const time = std.time;

const TestClient = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    pub fn createDnsQuery(self: Self) ![]u8 {
        var query: std.ArrayList(u8) = .empty;
        defer query.deinit(self.allocator);

        // DNS header (12 bytes)
        // Transaction ID (2 bytes)
        try query.appendSlice(self.allocator, &[_]u8{ 0x12, 0x34 });
        // Flags (2 bytes) - standard query
        try query.appendSlice(self.allocator, &[_]u8{ 0x01, 0x00 });
        // Questions (2 bytes)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 });
        // Answer RRs (2 bytes)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 });
        // Authority RRs (2 bytes)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 });
        // Additional RRs (2 bytes)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 });

        // Question section (simplified)
        // Domain name (encoded)
        try query.append(self.allocator, 7); // Length of "example"
        try query.appendSlice(self.allocator, "example");
        try query.append(self.allocator, 3); // Length of "com"
        try query.appendSlice(self.allocator, "com");
        try query.append(self.allocator, 0); // End of name

        // Query type (A record = 1)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 });
        // Query class (IN = 1)
        try query.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 });

        return query.toOwnedSlice(self.allocator);
    }

    pub fn encodeDnsQuery(self: Self, dns_query: []const u8) ![]u8 {
        const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(dns_query.len);
        const encoded = try self.allocator.alloc(u8, encoded_len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, dns_query);
        return encoded;
    }
};

test "DNS query creation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = TestClient.init(allocator);
    const query = try client.createDnsQuery();
    defer allocator.free(query);

    try testing.expect(query.len >= 12); // At least DNS header

    try testing.expectEqual(@as(u8, 0x12), query[0]); // Transaction ID high byte
    try testing.expectEqual(@as(u8, 0x34), query[1]); // Transaction ID low byte
    try testing.expectEqual(@as(u8, 0x01), query[2]); // Flags high byte
    try testing.expectEqual(@as(u8, 0x00), query[3]); // Flags low byte
}

test "DNS query encoding" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = TestClient.init(allocator);
    const query = try client.createDnsQuery();
    defer allocator.free(query);
    const encoded = try client.encodeDnsQuery(query);
    defer allocator.free(encoded);

    try testing.expect(encoded.len > 0);

    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);
    defer allocator.free(decoded);
    try testing.expectEqualSlices(u8, query, decoded);
}

test "Server config validation" {
    const config1 = try server.Config.defaults(testing.allocator);
    defer config1.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 8443), config1.server.listen_port);
    try testing.expectEqualSlices(u8, "8.8.8.8", config1.dns.server);
    try testing.expectEqual(@as(u16, 53), config1.dns.port);

    try testing.expect(config1.server.listen_port > 0);
    try testing.expect(config1.dns.port > 0);
    try testing.expect(config1.dns.server.len > 0);
    try testing.expect(config1.ssl.cert_file.len > 0);
    try testing.expect(config1.ssl.key_file.len > 0);
}

test "Address parsing validation" {
    const ipv4_tests = [_]struct {
        ip: []const u8,
        port: u16,
        should_succeed: bool,
        expected_error: ?anyerror,
    }{
        .{ .ip = "127.0.0.1", .port = 443, .should_succeed = true, .expected_error = null },
        .{ .ip = "0.0.0.0", .port = 8443, .should_succeed = true, .expected_error = null },
        .{ .ip = "192.168.1.1", .port = 53, .should_succeed = true, .expected_error = null },
        .{ .ip = "invalid.ip", .port = 443, .should_succeed = false, .expected_error = error.InvalidCharacter },
        .{ .ip = "256.256.256.256", .port = 443, .should_succeed = false, .expected_error = error.Overflow },
    };

    for (ipv4_tests) |test_case| {
        const result = net.Address.parseIp4(test_case.ip, test_case.port);
        if (test_case.should_succeed) {
            _ = result catch |err| {
                std.debug.print("Unexpected error for {s}: {}\n", .{ test_case.ip, err });
                return err;
            };
        } else {
            if (test_case.expected_error) |expected_err| {
                try testing.expectError(expected_err, result);
            } else {
                try testing.expect(result == error.InvalidCharacter or result == error.Overflow);
            }
        }
    }
}

test "Memory allocation patterns" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var allocations: std.ArrayList([]u8) = .empty;
    defer {
        for (allocations.items) |allocation| {
            testing.allocator.free(allocation);
        }
        allocations.deinit(testing.allocator);
    }

    for (0..10) |i| {
        const test_data = try std.fmt.allocPrint(testing.allocator, "test_query_{d}", .{i});
        try allocations.append(testing.allocator, test_data);

        const encoded = try server.decodeUrlSafeBase64(allocator, "dGVzdA"); // "test"
        defer allocator.free(encoded);
        try testing.expectEqualSlices(u8, "test", encoded);
    }
}

test "Concurrent connection simulation" {
    const max_connections = 1;
    var connection_data = [_]struct {
        id: u32,
        processed: bool,
    }{.{ .id = 0, .processed = false }} ** max_connections;

    for (&connection_data, 0..) |*conn, i| {
        conn.id = @intCast(i);
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const encoded_query = "dGVzdA"; // "test" in base64
        const decoded = try server.decodeUrlSafeBase64(allocator, encoded_query);
        defer allocator.free(decoded);
        try testing.expectEqualSlices(u8, "test", decoded);

        conn.processed = true;
    }

    for (connection_data) |conn| {
        try testing.expect(conn.processed);
    }
}

test "Error handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const error_test_cases = [_]struct {
        input: []const u8,
        expected_error: anyerror,
    }{
        .{ .input = "invalid_base64!!!", .expected_error = error.InvalidCharacter },
        .{ .input = "!@#$%^&*()", .expected_error = error.InvalidCharacter },
    };

    for (error_test_cases) |test_case| {
        const result = server.decodeUrlSafeBase64(allocator, test_case.input);
        try testing.expectError(test_case.expected_error, result);
    }
}

test "DNS query parameter parsing" {
    const test_paths = [_]struct {
        path: []const u8,
        should_contain_dns: bool,
        expected_dns_param: []const u8,
    }{
        .{ .path = "/dns-query?dns=dGVzdA", .should_contain_dns = true, .expected_dns_param = "dGVzdA" },
        .{ .path = "/dns-query?dns=aGVsbG8&other=param", .should_contain_dns = true, .expected_dns_param = "aGVsbG8" },
        .{ .path = "/dns-query?other=param", .should_contain_dns = false, .expected_dns_param = "" },
        .{ .path = "/other-endpoint", .should_contain_dns = false, .expected_dns_param = "" },
    };

    for (test_paths) |test_case| {
        var dns_param: []const u8 = "";

        if (std.mem.indexOf(u8, test_case.path, "?")) |query_start| {
            const query_string = test_case.path[query_start + 1 ..];
            var params_iter = std.mem.splitSequence(u8, query_string, "&");

            while (params_iter.next()) |param| {
                if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                    const key = param[0..eq_pos];
                    const value = param[eq_pos + 1 ..];

                    if (std.mem.eql(u8, key, "dns")) {
                        dns_param = value;
                        break;
                    }
                }
            }
        }

        if (test_case.should_contain_dns) {
            try testing.expectEqualSlices(u8, test_case.expected_dns_param, dns_param);
        } else {
            try testing.expectEqualSlices(u8, "", dns_param);
        }
    }
}

test "Resource cleanup simulation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const response_data = "test response data";

    const StreamData = struct {
        response_buffer: []const u8,
        response_len: usize,
        response_pos: usize = 0,
        stream_id: i32,
    };

    const stream_data = try allocator.create(StreamData);
    defer allocator.destroy(stream_data);

    const response_copy = try allocator.dupe(u8, response_data);
    defer allocator.free(response_copy);

    stream_data.* = StreamData{
        .response_buffer = response_copy,
        .response_len = response_copy.len,
        .response_pos = 0,
        .stream_id = 1,
    };

    try testing.expectEqualSlices(u8, response_data, stream_data.response_buffer);
    try testing.expectEqual(response_data.len, stream_data.response_len);
    try testing.expectEqual(@as(usize, 0), stream_data.response_pos);
    try testing.expectEqual(@as(i32, 1), stream_data.stream_id);
}

test "Stress test: multiple DNS queries" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const num_queries = 100;

    for (0..num_queries) |i| {
        var query_arena = std.heap.ArenaAllocator.init(allocator);
        defer query_arena.deinit();
        const query_allocator = query_arena.allocator();

        const test_query = try std.fmt.allocPrint(query_allocator, "query_{d}", .{i});

        const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(test_query.len);
        const encoded = try query_allocator.alloc(u8, encoded_len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, test_query);

        const decoded = try server.decodeUrlSafeBase64(query_allocator, encoded);
        try testing.expectEqualSlices(u8, test_query, decoded);
    }
}
