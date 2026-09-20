const prom = @import("metrics");
const std = @import("std");
const doh = @import("config.zig");

pub fn run(io: std.Io, metrics: *prom.Metrics, config: doh.Config) !void {
    const doh_server_addr = std.Io.net.IpAddress.parseIp4(config.server.listen_address, config.server.metrics_port) catch |err| {
        std.debug.print("An error occurred while resolving the IP address: {}\n", .{err});
        return;
    };
    var listener = try doh_server_addr.listen(io, .{});
    defer listener.deinit(io);

    while (true) {
        const conn = listener.accept(io) catch |err| {
            std.log.err("Error {}", .{err});
            continue;
        };
        defer conn.close(io);
        handleRequest(conn, metrics) catch |err| {
            std.log.err("Metrics handler error {}", .{err});
            continue;
        };
    }
}

fn handleRequest(stream: std.Io.net.Stream, metrics: *prom.Metrics) !void {
    var req_buffer: [256]u8 = undefined;
    const n = try std.posix.read(stream.socket.handle, &req_buffer);
    const path_ok = std.mem.startsWith(u8, req_buffer[0..n], "GET /metrics");
    const status = if (path_ok) "200 OK" else "404 Not Found";

    var body_buf: [4096]u8 = undefined;
    var body_writer = std.Io.Writer.fixed(&body_buf);
    if (path_ok) try metrics.write(&body_writer);
    const body = body_writer.buffered();

    var header_buf: [128]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 {s}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n", .{ status, body.len });
    try sendAll(stream.socket.handle, header);
    if (path_ok) try sendAll(stream.socket.handle, body);
}

fn sendAll(fd: std.posix.fd_t, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = std.posix.system.send(fd, data[sent..].ptr, data.len - sent, std.posix.MSG.NOSIGNAL);
        switch (std.posix.errno(rc)) {
            .SUCCESS => sent += @intCast(rc),
            .INTR => {},
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }
}
