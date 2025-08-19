const std = @import("std");
const net = std.net;
const http = std.http;
const server = @import("server.zig");
const config = @import("config.zig");

const Config = config.Config;
const Server = server.Server;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer if (gpa.deinit() != .ok) @panic("leak");
    const allocator = gpa.allocator();

    const server_config = try Config.loadFromFile(allocator, "config.json");
    defer server_config.deinit(allocator);

    var doh_server = try Server.init(allocator, server_config);
    defer doh_server.deinit();

    std.log.info("DoH server starting on port {d}", .{server_config.server.listen_port});
    try doh_server.accept();
}
