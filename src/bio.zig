const std = @import("std");
const net = std.Io.net;
const c = @import("c");

/// WIP: a ring buffer that sits between wolfSSL and Zig's std.Io.Evented.
/// For practical reason, this is being developed and tested assuming linux and
/// the io_uring backend.
///
///
/// TODO (gmodena, 2026-06): Working assumption as this is a learning project.
///
/// When the callbacks call io.operate(.{ .net_read = ... }) or io.vtable.netWrite(...),
/// the Evented implementation suspends the current fiber until the socket
/// is ready and lets the OS thread run other fibers.
///
/// One connection's I/O does not block the  the event loop.
///
/// The caveat is that these calls happen inside wolfSSL's C callbacks.
/// This _should_ be fine because Evented is stackful. E.g. a stackful coroutine
/// swaps the entire native stack, so it can suspend and resume even
/// while C frames (wolfSSL's wolfSSL_read/wolfSSL_accept machinery) are on the stack.
///
/// References
/// - https://ziglang.org/devlog/2026/#2026-02-13
/// - https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls-callback.c
/// Per-connection I/O context passed to wolfSSL recv/send callbacks via
/// wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx.
/// Must remain alive for the lifetime of the SSL object.
pub const IoCtx = struct {
    io: std.Io,
    handle: net.Socket.Handle,
};

/// wolfSSL receive callback. Called by wolfSSL whenever it needs to read
/// encrypted bytes. Under the hood with std.Io.Evented the fiber yields until data
/// arrives. With std.Io.Threaded the calling thread blocks.
pub fn recvCb(
    _: ?*c.WOLFSSL,
    buf: [*c]u8,
    sz: c_int,
    ctx: ?*anyopaque,
) callconv(.c) c_int {
    const io_ctx: *IoCtx = @ptrCast(@alignCast(ctx.?));
    var dest = [1][]u8{buf[0..@intCast(sz)]};
    const result = io_ctx.io.operate(.{ .net_read = .{
        .socket_handle = io_ctx.handle,
        .data = &dest,
    } }) catch return c.WOLFSSL_CBIO_ERR_GENERAL;
    const n = result.net_read catch return c.WOLFSSL_CBIO_ERR_GENERAL;
    if (n == 0) return c.WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return @intCast(n);
}

/// wolfSSL send callback. Called by wolfSSL whenever it has encrypted bytes
/// to write. Loops until all bytes are sent. Under the hood with std.Io.Evented
/// the fiber yields if the socket is not immediately writable.
pub fn sendCb(_: ?*c.WOLFSSL, buf: [*c]u8, sz: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    const io_ctx: *IoCtx = @ptrCast(@alignCast(ctx.?));
    const data = buf[0..@intCast(sz)];
    var sent: usize = 0;
    while (sent < data.len) {
        const n = io_ctx.io.vtable.netWrite(
            io_ctx.io.userdata,
            io_ctx.handle,
            data[sent..], // header
            &.{}, // data (extra iovecs)
            0, // splat
        ) catch return c.WOLFSSL_CBIO_ERR_GENERAL;
        if (n == 0) return c.WOLFSSL_CBIO_ERR_CONN_CLOSE;
        sent += n;
    }
    return @intCast(sent);
}

/// Register recvCb and sendCb on a WOLFSSL_CTX.
pub fn registerCallbacks(ctx: *c.WOLFSSL_CTX) void {
    c.wolfSSL_CTX_SetIORecv(ctx, recvCb);
    c.wolfSSL_CTX_SetIOSend(ctx, sendCb);
}

/// Bind io_ctx to an individual SSL connection so the callbacks can reach
/// the right socket.
pub fn bindToSsl(ssl: *c.WOLFSSL, io_ctx: *IoCtx) void {
    c.wolfSSL_SetIOReadCtx(ssl, io_ctx);
    c.wolfSSL_SetIOWriteCtx(ssl, io_ctx);
}
