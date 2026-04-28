const std = @import("std");
const net = std.Io.net;
const config = @import("config.zig");

const Allocator = std.mem.Allocator;

const SocketState = enum { available, in_use };

pub const HEADER_LEN = 12;
pub const QUERY_LEN = 4096; // RFC 8484 recommends 512 bytes for UDP compatibility

pub const ConnectionPool = struct {
    const Self = @This();

    sockets: std.ArrayListUnmanaged(net.Socket),
    state: std.ArrayListUnmanaged(SocketState),
    mutex: std.Io.Mutex = .init,
    dns_addr: net.IpAddress,
    allocator: Allocator,
    io: std.Io,

    pub fn init(io: std.Io, allocator: Allocator, dns_addr: net.IpAddress, pool_size: u32) !Self {
        var pool = Self{
            .sockets = try std.ArrayListUnmanaged(net.Socket).initCapacity(allocator, pool_size),
            .state = try std.ArrayListUnmanaged(SocketState).initCapacity(allocator, pool_size),
            .dns_addr = dns_addr,
            .allocator = allocator,
            .io = io,
        };

        const ephemeral: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
        for (0..pool_size) |_| {
            const sock = try ephemeral.bind(io, .{ .mode = .dgram });
            try pool.sockets.append(pool.allocator, sock);
            try pool.state.append(pool.allocator, SocketState.available);
        }
        return pool;
    }

    pub fn deinit(self: *Self) void {
        for (self.sockets.items) |*sock| {
            sock.close(self.io);
        }
        self.sockets.deinit(self.allocator);
        self.state.deinit(self.allocator);
    }

    pub fn acquire(self: *Self, io: std.Io) ?net.Socket {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        for (self.state.items, 0..) |state, i| {
            if (state == .available) {
                self.state.items[i] = .in_use;
                return self.sockets.items[i];
            }
        }
        return null;
    }

    pub fn release(self: *Self, io: std.Io, socket: net.Socket) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        for (self.sockets.items, 0..) |sock, i| {
            if (sock.handle == socket.handle) {
                switch (self.state.items[i]) {
                    .in_use => {
                        self.state.items[i] = .available;
                    },
                    .available => {
                        std.log.warn("Attempted to free a socket in state=available", .{});
                    },
                }
            }
        }
    }
};

pub fn isValidQuery(data: []const u8) bool {
    if (data.len < HEADER_LEN) return false;

    // QR bit (bit 0 of byte 2) must be 0 for query
    const flags = (@as(u16, data[2]) << 8) | data[3];
    const qr_bit = (flags >> 15) & 0x01;
    if (qr_bit != 0) return false; // Must be query, not response

    // Question count is at least 1
    const qdcount = (@as(u16, data[4]) << 8) | data[5];
    if (qdcount == 0) return false;

    return true;
}
