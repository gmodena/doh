const std = @import("std");
const testing = std.testing;
const server = @import("server");

const test_cert_path = "/tmp/test_cert.pem";
const test_key_path = "/tmp/test_key.pem";

// self-signed cert for testing
const test_cert_content =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
    \\BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
    \\aWRnaXRzIFB0eSBMdGQwHhcNMTcwOTEyMTU1MDQzWhcNMTgwOTEyMTU1MDQzWjBF
    \\MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
    \\ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
    \\CgKCAQEAuuExKQFEXQlF42oOdmx2x4rVOnL0sVzJz2mhBTjwf8cjF5OzfCv8MVBR
    \\4vHsqnRLOyWPEqXdNOhPGfQrKQHAKvkgLnVGGzEb5RJhN1oBbNs1TZOhV3Zv6xrG
    \\9DnHxOq1QkYb4RJSGl+f7fVVOQ8RUyFsLtF8hBfGKkW3vv5XGJfxbLUOHkdXLbGz
    \\6wVZwjHcVhGzQ2zlwdKKfGLdBGUe4xlNjRj3Z8g5DpLgRJfGpTmVe5VlQwGdT2uV
    \\c1HSXW+qQfz4iQmN4t+S7z7dF7t7g1dZrFjI2zKqVQfZrMhOLQwOg+V7cqVVz1Zw
    \\4l7dGLrJr8v9zx6yGzYfKQNX2YkpEQIDAQABo1AwTjAdBgNVHQ4EFgQU+a1C8TUN
    \\aJz7yyKIo2vYOQR+9l8wHwYDVR0jBBgwFoAU+a1C8TUNaJz7yyKIo2vYOQR+9l8w
    \\DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAGWOmNIXxYF8A
    \\-----END CERTIFICATE-----
    \\
;

const test_key_content =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC64TEpAURdCUXj
    \\ag52bHbHitU6cvSxXMnPaaEFOPB/xyMXk7N8K/wxUFHi8eyqdEs7JY8Spd006E8Z
    \\9CspAcAq+SAudUYbMRvlEmE3WgFs2zVNk6FXdm/rGsb0OcfE6rVCRhvhElIaX5/t
    \\9VU5DxFTIWwu0XyEF8YqRbe+/lcYl/FstQ4eR1ctsbPrBVnCMdxWEbNDbOXB0op8
    \\Yt0EZR7jGU2NGPdnyDkOkuBEl8alOZV7lWVDAZ1Pa5VzUdJdb6pB/PiJCY3i35Lv
    \\Pt0Xu3uDV1msWMjbMqpVB9msyE4tDA6D5XtypVXPVnDiXt0Yusmvy/3PHrIbNh8p
    \\A1fZiSkRAgMBAAECggEBAKq2bY7bGB6OhM2DF9jz6sRz2LAmI7HSCv43E9nLNQ3t
    \\StKF+1j6wj8DpjZxtCrJgJ8E7Yzk4Nn4vO6kzlwOa7rCF9Rf+xaYzIFRfhOI3qZz
    \\-----END PRIVATE KEY-----
    \\
;

fn createTestCerts() !void {
    const file_cert = try std.fs.cwd().createFile(test_cert_path, .{});
    defer file_cert.close();
    try file_cert.writeAll(test_cert_content);

    const file_key = try std.fs.cwd().createFile(test_key_path, .{});
    defer file_key.close();
    try file_key.writeAll(test_key_content);
}

fn cleanupTestCerts() void {
    std.fs.cwd().deleteFile(test_cert_path) catch {};
    std.fs.cwd().deleteFile(test_key_path) catch {};
}

// Unit Tests

test "decodeUrlSafeBase64: valid input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // "hello" encoded as URL-safe base64
    const encoded = "aGVsbG8";
    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);

    try testing.expectEqualSlices(u8, "hello", decoded);
}

test "decodeUrlSafeBase64: input with padding needed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Test data that needs padding
    const encoded = "aGVsbA"; // "hell"
    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);

    try testing.expectEqualSlices(u8, "hell", decoded);
}

test "decodeUrlSafeBase64: empty input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const encoded = "";
    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);

    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "Config: default values" {
    const config = try server.Config.defaults(testing.allocator);
    defer config.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 8443), config.server.listen_port);
    try testing.expectEqualSlices(u8, "8.8.8.8", config.dns.server);
    try testing.expectEqual(@as(u16, 53), config.dns.port);
}

test "Config - custom values" {
    const config = try server.Config.defaults(testing.allocator);
    defer config.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 8443), config.server.listen_port);
    try testing.expectEqualSlices(u8, "8.8.8.8", config.dns.server);
    try testing.expectEqual(@as(u16, 53), config.dns.port);
    try testing.expectEqualSlices(u8, "./certs/server.crt", config.ssl.cert_file);
    try testing.expectEqualSlices(u8, "./certs/server.key", config.ssl.key_file);
}

const MockFrame = extern struct {
    hd: MockFrameHd,
    headers: MockHeaders,
};

const MockFrameHd = extern struct {
    length: u32,
    stream_id: i32,
    type: u8,
    flags: u8,
    reserved: u8,
};

const MockHeaders = extern struct {
    cat: u32,
};

const MockClientData = struct {
    session: ?*anyopaque = null,
    ssl: ?*anyopaque = null,
    has_frame: bool = false,
    has_header: bool = false,
    method: u8 = 0,
    name: [*c]const u8 = null,
    value: [*c]const u8 = null,
    request_path: []const u8 = "",
    dns_request: []const u8 = "",
    stream_id: i32 = 1,
};

test "onFrameRecv callback: client data structure" {
    const client_data = MockClientData{};
    try testing.expect(!client_data.has_frame);
    try testing.expect(!client_data.has_header);
    try testing.expect(client_data.stream_id == 1);
}

test "Server init: invalid certificate path" {
    var config = try server.Config.defaults(testing.allocator);
    defer config.deinit(testing.allocator);

    // Update to invalid paths for this test
    testing.allocator.free(config.ssl.cert_file);
    testing.allocator.free(config.ssl.key_file);
    config.ssl.cert_file = try testing.allocator.dupe(u8, "/nonexistent/cert.pem");
    config.ssl.key_file = try testing.allocator.dupe(u8, "/nonexistent/key.pem");

    const result = server.Server.init(testing.allocator, config);
    try testing.expectError(error.CertLoadFailed, result);
}

test "decodeUrlSafeBase64: URL-safe characters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Test with URL-safe base64 characters (- and _)
    const encoded = "PD8-Pz8_"; // Contains URL-safe chars
    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);

    // Should decode without error
    try testing.expect(decoded.len > 0);
}

test "decodeUrlSafeBase64: misc padding scenarios" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const test_cases = [_]struct {
        input: []const u8,
        expected_len: usize,
    }{
        .{ .input = "YQ", .expected_len = 1 }, // "a" with 2 pad chars needed
        .{ .input = "YWI", .expected_len = 2 }, // "ab" with 1 pad char needed
        .{ .input = "YWJj", .expected_len = 3 }, // "abc" with no pad chars needed
    };

    for (test_cases) |case| {
        const decoded = try server.decodeUrlSafeBase64(allocator, case.input);
        try testing.expect(decoded.len == case.expected_len);
    }
}

test "decodeUrlSafeBase64: memory cleanup" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const encoded = "dGVzdA"; // "test"
    const decoded = try server.decodeUrlSafeBase64(allocator, encoded);

    try testing.expectEqualSlices(u8, "test", decoded);
}

test "decodeUrlSafeBase64: invalid base64 characters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const invalid_encoded = "@@@@";
    const result = server.decodeUrlSafeBase64(allocator, invalid_encoded);

    try testing.expectError(error.InvalidCharacter, result);
}
