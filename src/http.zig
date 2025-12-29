const std = @import("std");
const net = std.net;
const posix = std.posix;
const config = @import("config.zig");
const errorz = @import("error");
const dns = @import("dns.zig");
const c = @cImport({
    @cDefine("XSTAT_TYPE", "struct stat");
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
    @cInclude("nghttp2/nghttp2.h");
});

const Allocator = std.mem.Allocator;
const Error = errorz.Error;

const ALPN_H2 = "h2";
const DNS_PARAM = "dns";
const PATH_HEADER = ":path";

const DOH_PATH = "/dns-query";

pub fn decodeUrlSafeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const padding_needed = (4 - (encoded.len % 4)) % 4;

    // This is unlikely to overflow, but it could happen if
    // `encoded.len` is close to `usize` maximum.
    const padding_len, const overflowed = @addWithOverflow(encoded.len, padding_needed);
    if (overflowed != 0) {
        return error.OutOfMemory;
    }

    var padded_input = try allocator.alloc(u8, padding_len);

    defer allocator.free(padded_input);

    @memcpy(padded_input[0..encoded.len], encoded);

    for (encoded.len..padded_input.len) |i| {
        padded_input[i] = '=';
    }
    const decoded_len = try std.base64.url_safe.Decoder.calcSizeForSlice(padded_input);
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);

    try std.base64.url_safe.Decoder.decode(decoded[0..decoded_len], padded_input);
    return decoded;
}

const SslState = enum {
    uninitialized,
    handshaking,
    connected,
    error_state,
    closed,
};

// Per-connnection SSL data and boilerplate.
pub const SslConnection = struct {
    const Self = @This();

    ssl: ?*c.WOLFSSL = null,
    state: SslState = .uninitialized,
    error_code: ?c_int = null,
    handshake_attempts: u32 = 0,

    pub fn init(ctx: *c.WOLFSSL_CTX, socket_fd: std.posix.fd_t) !SslConnection {
        const ssl = c.wolfSSL_new(ctx) orelse return Error.SslInitFailed;
        errdefer c.wolfSSL_Free(ssl);

        var h2_alpn_buf: [2]u8 = "h2".*;
        const h2_alpn = &h2_alpn_buf;

        if (c.wolfSSL_UseALPN(ssl, h2_alpn, ALPN_H2.len, c.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != c.SSL_SUCCESS) {
            return Error.AlpnFailed;
        }

        if (c.wolfSSL_set_fd(ssl, socket_fd) != c.SSL_SUCCESS) {
            return Error.SslInitFailed;
        }

        return SslConnection{
            .ssl = ssl,
            .state = .handshaking,
        };
    }

    pub fn performHandshake(self: *Self, server_config: config.Config, client_address: std.net.Address) !void {
        const Inner = struct {
            fn doSslAccept(s: *Self) !void {
                const result = c.wolfSSL_accept(s.ssl);
                if (result == c.SSL_SUCCESS) return;
                s.error_code = c.wolfSSL_get_error(s.ssl, result);
                return error.SslHandshakeFailed;
            }
        };

        const policy = errorz.RetryPolicy{
            .max_tries = server_config.ssl.handshake_max_attempts,
            .delay_ms = 10,
            .timeout_ms = server_config.ssl.handshake_timeout_ms,
        };

        errorz.retry(Inner.doSslAccept, .{self}, policy) catch |err| {
            self.state = .error_state;
            std.log.warn("SSL handshake failed from {any}: {}", .{ client_address, err });
            return err;
        };

        self.state = .connected;
        std.log.debug("SSL handshake successful for {any}", .{client_address});
    }

    pub fn isConnected(self: *const Self) bool {
        return self.state == .connected;
    }

    pub fn cleanup(self: *Self) void {
        if (self.ssl) |ssl| {
            c.wolfSSL_free(ssl);
            self.ssl = null;
        }
        self.state = .closed;
    }
};

pub const RequestContext = struct {
    const Self = @This();

    ssl_connection: SslConnection,

    // HTTP/2 state
    session: ?*c.nghttp2_session = null,
    has_frame: bool = false,
    has_header: bool = false,
    stream_id: i32 = 0,

    // DNS Request state
    dns_request: []const u8 = "",
    request_path: []const u8 = "",
    method: u8 = 0,
    name: [*c]const u8 = null,
    value: [*c]const u8 = null,

    connection: std.net.Server.Connection,
    allocator: std.mem.Allocator,

    pub fn init(connection: std.net.Server.Connection, allocator: std.mem.Allocator, ctx: *c.WOLFSSL_CTX) !RequestContext {
        const ssl_connection = try SslConnection.init(ctx, connection.stream.handle);

        return RequestContext{
            .ssl_connection = ssl_connection,
            .connection = connection,
            .allocator = allocator,
            //  .server = server,
        };
    }

    pub fn performHandshake(self: *Self, server_config: config.Config) !void {
        try self.ssl_connection.performHandshake(server_config, self.connection.address);
    }

    pub fn createSession(self: *Self, callbacks: ?*c.nghttp2_session_callbacks, server_config: config.Config) !void {
        if (!self.ssl_connection.isConnected()) return Error.SslHandshakeFailed;

        try checkError(c.nghttp2_session_server_new(&self.session, callbacks, self));

        const settings: [2]c.nghttp2_settings_entry = .{
            .{ .settings_id = c.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = server_config.http2.max_concurrent_streams },
            .{ .settings_id = c.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = server_config.http2.initial_window_size },
        };
        _ = c.nghttp2_submit_settings(self.session, c.NGHTTP2_FLAG_NONE, &settings, settings.len);
    }

    pub fn cleanup(self: *Self) void {
        if (self.session) |session| {
            _ = c.nghttp2_session_del(session);
        }
        self.ssl_connection.cleanup();
    }
};

// nghttp2 callback: frame received
pub fn onFrameRecv(_: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, client_data: ?*anyopaque) callconv(.C) c_int {
    if (client_data) |data| {
        const request_ctx: *RequestContext = @ptrCast(@alignCast(data));
        request_ctx.has_frame = true;

        switch (frame.*.hd.type) {
            c.NGHTTP2_HEADERS => {
                request_ctx.has_header = true;
            },
            else => request_ctx.has_header = false,
        }
    }
    return 0;
}

// nghttp2 callback: parse headers and extract dns query from :path
pub fn onHeader(
    _: ?*c.nghttp2_session,
    frame: [*c]const c.nghttp2_frame,
    name: [*c]const u8,
    namelen: usize,
    value: [*c]const u8,
    valuelen: usize,
    _: u8,
    client_data: ?*anyopaque,
) callconv(.C) c_int {
    const PATH: []const u8 = PATH_HEADER;

    if (client_data) |data| {
        const request_ctx: *RequestContext = @ptrCast(@alignCast(data));
        request_ctx.has_header = true;
        request_ctx.method = frame.*.hd.type;
        request_ctx.stream_id = frame.*.hd.stream_id;

        switch (frame.*.hd.type) {
            c.NGHTTP2_HEADERS => {
                if (frame.*.headers.cat != c.NGHTTP2_HCAT_REQUEST) {
                    return 0;
                }

                // null check
                if (name == null or value == null) {
                    return 0;
                }

                const name_slice = name[0..namelen];
                if (std.mem.eql(u8, name_slice, PATH)) {
                    request_ctx.request_path = value[0..valuelen];

                    // find query params
                    var pathEnd: usize = valuelen;
                    for (0..valuelen) |i| {
                        if (value[i] == '?') {
                            pathEnd = i + 1;
                            break;
                        }
                    }

                    // parse DNS if query string found
                    if (pathEnd < valuelen) {
                        // validate the path portion
                        const path_portion = value[0 .. pathEnd - 1]; // Exclude the '?'

                        if (!std.mem.eql(u8, path_portion, DOH_PATH)) {
                            std.log.warn("Invalid DoH path {s}", .{path_portion});
                            return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                        }

                        // split query params
                        var params_iter = std.mem.splitSequence(u8, value[pathEnd..valuelen], "&");

                        // find DNS param
                        while (params_iter.next()) |param| {
                            // split key=value
                            if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                                const key = param[0..eq_pos];
                                const value_part = param[eq_pos + 1 ..];

                                if (std.mem.eql(u8, key, DNS_PARAM)) {
                                    if (value_part.len > dns.QUERY_LEN) {
                                        std.log.warn("DNS query parameter too large: {} bytes", .{value_part.len});
                                        return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                                    }
                                    request_ctx.dns_request = value_part;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (namelen > 0) {
                    request_ctx.name = name;
                }

                if (valuelen > 0) {
                    request_ctx.value = value;
                }

                return 0;
            },
            else => return 0,
        }
    }
    return 0;
}

// nghttp2 callback: send data over SSL
pub fn onSend(session: ?*c.struct_nghttp2_session, response: [*c]const u8, length: usize, _: c_int, client_data: ?*anyopaque) callconv(.C) isize {
    if (client_data) |data| {
        const request_ctx: *RequestContext = @ptrCast(@alignCast(data));

        const sent = c.wolfSSL_write(request_ctx.ssl_connection.ssl, response, @intCast(length));

        if (sent < 0) {
            const err = c.wolfSSL_get_error(request_ctx.ssl_connection.ssl, sent);
            std.log.err("wolfSSL_write error: {d}", .{err});
            return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        }

        if (c.nghttp2_session_want_write(session) > 0) {
            _ = c.nghttp2_session_send(session);
        }

        return sent;
    }

    return c.NGHTTP2_ERR_CALLBACK_FAILURE;
}

// nghttp2 callback: stream closed
pub fn onStreamClose(_: ?*c.nghttp2_session, stream_id: i32, _: u32, client_data: ?*anyopaque) callconv(.C) c_int {
    _ = stream_id;
    _ = client_data;
    // cleanup handled by session termination
    return 0;
}

// Convert nghttp2 return codes to errors
pub fn checkError(rc: c_int) !void {
    if (rc < 0) return error.NgHttp2Error;
}

// DNS response data for HTTP2 streaming
pub const StreamData = struct { stream_id: i32, response_buffer: []const u8, response_len: usize, response_pos: usize = 0 };

// nghttp2 callback: stream response data
pub fn dataReadCallback(_: ?*c.nghttp2_session, _: i32, buf: [*c]u8, length: usize, data_flags: [*c]u32, source: [*c]c.nghttp2_data_source, _: ?*anyopaque) callconv(.C) isize {
    if (source.*.ptr) |data| {
        const stream_data: *StreamData = @ptrCast(@alignCast(data));

        if (stream_data.response_pos >= stream_data.response_len) {
            data_flags.* = c.NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }

        const remaining = stream_data.response_len - stream_data.response_pos;
        const copy_len = @min(length, remaining);

        if (copy_len > 0) {
            @memcpy(buf[0..copy_len], stream_data.response_buffer[stream_data.response_pos..][0..copy_len]);
            stream_data.response_pos += copy_len;
        }

        return @intCast(copy_len);
    }
    data_flags.* = c.NGHTTP2_DATA_FLAG_EOF;
    return 0;
}

pub fn sendResponse(request_ctx: *RequestContext, dns_response: []const u8, server_config: config.Config) !void {
    const cache_control_value = try std.fmt.allocPrint(request_ctx.allocator, "max-age={}", .{server_config.http.cache_control_max_age});
    defer request_ctx.allocator.free(cache_control_value);

    // @constCast instruces a safety issue.
    // hghttp2 expects the buffers to mutable, however the library should not modify
    // header strings. Err on the side of performance for now, and cast away.
    const headers: [4]c.nghttp2_nv = .{
        .{ .name = @constCast(":status".ptr), .value = @constCast("200".ptr), .namelen = ":status".len, .valuelen = "200".len, .flags = c.NGHTTP2_NV_FLAG_NO_COPY_NAME | c.NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        .{ .name = @constCast("content-type".ptr), .value = @constCast("application/dns-message".ptr), .namelen = "content-type".len, .valuelen = "application/dns-message".len, .flags = c.NGHTTP2_NV_FLAG_NO_COPY_NAME | c.NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        .{ .name = @constCast("server".ptr), .value = @constCast("dohd".ptr), .namelen = "server".len, .valuelen = "dohd".len, .flags = c.NGHTTP2_NV_FLAG_NO_COPY_NAME | c.NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        .{ .name = @constCast("cache-control".ptr), .value = @constCast(cache_control_value.ptr), .namelen = "cache-control".len, .valuelen = cache_control_value.len, .flags = c.NGHTTP2_NV_FLAG_NO_COPY_NAME | c.NGHTTP2_NV_FLAG_NO_COPY_VALUE },
    };

    var stream_data = StreamData{
        .response_buffer = dns_response,
        .response_len = dns_response.len,
        .response_pos = 0,
        .stream_id = request_ctx.stream_id,
    };

    const data_provider = c.nghttp2_data_provider{
        .source = .{ .ptr = @ptrCast(@constCast(&stream_data)) },
        .read_callback = dataReadCallback,
    };

    const rv = c.nghttp2_submit_response(request_ctx.session, request_ctx.stream_id, &headers, headers.len, &data_provider);
    if (rv != 0) {
        std.log.err("nghttp2_submit_response error: {d}", .{rv});
        return Error.DnsQueryFailed;
    }

    while (c.nghttp2_session_want_write(request_ctx.session) != 0) {
        const send_rv = c.nghttp2_session_send(request_ctx.session);
        if (send_rv != 0) {
            std.log.err("nghttp2_session_send error: {d}", .{send_rv});
            return Error.DnsQueryFailed;
        }
    }
}
