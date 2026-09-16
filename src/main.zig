const std = @import("std");
const server = @import("server.zig");
const config = @import("config.zig");
const prom = @import("metrics.zig");
const metrics_server = @import("metrics_server.zig");

const Config = config.Config;
const Server = server.Server;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer if (gpa.deinit() != .ok) @panic("leak");
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var metrics = prom.Metrics.init();

    const server_config = try Config.loadFromFile(io, allocator, "config.json");
    defer server_config.deinit(allocator);

    var doh_server = try Server.init(io, allocator, server_config, &metrics);
    defer doh_server.deinit();

    std.log.info("DoH server starting at {s}:{d}", .{
        server_config.server.listen_address,
        server_config.server.listen_port,
    });

    const metrics_thread = try std.Thread.spawn(.{}, metrics_server.run, .{ io, &metrics, server_config });
    metrics_thread.detach();

    try doh_server.accept();
}
