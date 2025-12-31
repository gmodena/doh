const std = @import("std");
const posix = std.posix;
const config = @import("config.zig");

const Allocator = std.mem.Allocator;

const SocketState = enum { available, in_use };

pub const HEADER_LEN = 12;
pub const QUERY_LEN = 4096; // RFC 8484 recommends 512 bytes for UDP compatibility

pub const ConnectionPool = struct {
    const Self = @This();

    sockets: std.ArrayList(posix.socket_t),
    state: std.ArrayList(SocketState),
    mutex: std.Thread.Mutex = .{},
    dns_addr: std.net.Address,
    allocator: Allocator,

    pub fn init(allocator: Allocator, dns_addr: std.net.Address, pool_size: u32, socket_timeout_sec: u32) !Self {
        var pool = Self{
            .sockets = try std.ArrayList(posix.socket_t).initCapacity(allocator, pool_size),
            .state = try std.ArrayList(SocketState).initCapacity(allocator, pool_size),
            .dns_addr = dns_addr,
            .allocator = allocator,
        };

        const timeout = posix.timeval{ .sec = @intCast(socket_timeout_sec), .usec = 0 };

        for (0..pool_size) |_| {
            const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
            try pool.sockets.append(pool.allocator, sock);
            try pool.state.append(pool.allocator, SocketState.available);
        }
        return pool;
    }

    pub fn deinit(self: *Self) void {
        for (self.sockets.items) |sock| {
            posix.close(sock);
        }
        self.sockets.deinit(self.allocator);
        self.state.deinit(self.allocator);
    }

    pub fn acquire(self: *Self) ?posix.socket_t {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.state.items, 0..) |state, i| {
            if (state == .available) {
                self.state.items[i] = .in_use;
                return self.sockets.items[i];
            }
        }
        return null;
    }

    pub fn release(self: *Self, socket: posix.socket_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.sockets.items, 0..) |sock, i| {
            if (sock == socket) {
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
