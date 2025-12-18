const std = @import("std");
const net = std.net;
const http = std.http;
const posix = std.posix;
const config = @import("config.zig");
const c = @cImport({
    @cDefine("XSTAT_TYPE", "struct stat");
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
    @cInclude("nghttp2/nghttp2.h");
});

const Allocator = std.mem.Allocator;

pub const Config = config.Config;

const Error = error{ ServerInitFailed, SslInitFailed, CertLoadFailed, KeyLoadFailed, DnsQueryFailed, DnsQueryHasNoData, DnsQueryIsNotValid, ServerListenFailed, AlpnFailed, SslHandshakeFailed, SessionFailed, DnsPoolExhausted };

const ALPN_H2 = "h2";
const DNS_PARAM = "dns";
const PATH_HEADER = ":path";
const MAX_DNS_QUERY_LEN = 4096; // RFC 8484 recommends 512 bytes for UDP compatibility
const DNS_HEADER_LEN = 12;
const VALID_DOH_PATH = "/dns-query";

pub fn decodeUrlSafeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const padding_needed = (4 - (encoded.len % 4)) % 4;

    var padded_input = try allocator.alloc(u8, encoded.len + padding_needed);
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

const SocketState = enum { available, in_use };

const DnsConnectionPool = struct {
    const Self = @This();

    sockets: std.ArrayList(posix.socket_t),
    state: std.ArrayList(SocketState),
    mutex: std.Thread.Mutex = .{},
    dns_addr: std.net.Address,
    allocator: Allocator,

    fn init(allocator: Allocator, dns_addr: std.net.Address, pool_size: u32, socket_timeout_sec: u32) !Self {
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
            try pool.sockets.append(sock);
            try pool.state.append(SocketState.available);
        }
        return pool;
    }

    fn deinit(self: *Self) void {
        for (self.sockets.items) |sock| {
            posix.close(sock);
        }
        self.sockets.deinit();
        self.state.deinit();
    }

    fn acquire(self: *Self) ?posix.socket_t {
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

    fn release(self: *Self, socket: posix.socket_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.sockets.items, 0..) |sock, i| {
            if (sock == socket) {
                switch (self.state.items[i]) {
                    .in_use => {
                        self.state.items[i] = .available;
                    },
                    .available => {
                        std.warn("Attempted to free a socket in state=available", .{});
                    },
                }
            }
        }
    }
};

const SslState = enum {
    uninitialized,
    handshaking,
    connected,
    error_state,
    closed,
};

const RequestContext = struct {
    const Self = @This();

    ssl_state: SslState = .uninitialized,
    ssl: ?*c.WOLFSSL = null,
    ssl_error: ?c_int = null,
    handshake_attempts: u32 = 0,

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
    server: *Server,

    fn initSsl(self: *Self, ctx: *c.WOLFSSL_CTX) !void {
        self.ssl = c.wolfSSL_new(ctx) orelse return Error.SslInitFailed;
        self.ssl_state = .handshaking;

        const h2_alpn = @constCast(ALPN_H2.ptr);
        if (c.wolfSSL_UseALPN(self.ssl, h2_alpn, ALPN_H2.len, c.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != c.SSL_SUCCESS) {
            return Error.AlpnFailed;
        }

        if (c.wolfSSL_set_fd(self.ssl, self.connection.stream.handle) != c.SSL_SUCCESS) {
            self.ssl_state = .error_state;
            return Error.SslInitFailed;
        }
    }

    fn performHandshake(self: *Self) !void {
        const max_attempts = self.server.config.ssl.handshake_max_attempts;
        const start_time = std.time.milliTimestamp();
        const timeout_ms = self.server.config.ssl.handshake_timeout_ms;

        while (self.ssl_state == .handshaking and self.handshake_attempts < max_attempts) {
            if (std.time.milliTimestamp() - start_time > timeout_ms) {
                self.ssl_state = .error_state;
                std.log.warn("SSL handshake timeout ({} ms) from {any}", .{ timeout_ms, self.connection.address });
                return Error.SslHandshakeFailed;
            }

            const result = c.wolfSSL_accept(self.ssl);
            if (result == c.SSL_SUCCESS) {
                self.ssl_state = .connected;
                std.log.debug("SSL handshake successful for {any} after {} attempts", .{ self.connection.address, self.handshake_attempts + 1 });
                return;
            }

            const ssl_error = c.wolfSSL_get_error(self.ssl, result);
            switch (ssl_error) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    self.handshake_attempts += 1;
                },
                else => {
                    self.ssl_state = .error_state;
                    self.ssl_error = ssl_error;
                    std.log.warn("SSL handshake failed after {} attempts: SSL error {} from {any}", .{ self.handshake_attempts + 1, ssl_error, self.connection.address });
                    return Error.SslHandshakeFailed;
                },
            }
        }

        if (self.handshake_attempts >= max_attempts) {
            self.ssl_state = .error_state;
            std.log.warn("SSL handshake exceeded max attempts ({}) from {any}", .{ max_attempts, self.connection.address });
            return Error.SslHandshakeFailed;
        }
    }

    fn initHttp2Session(self: *Self, callbacks: ?*c.nghttp2_session_callbacks) !void {
        if (self.ssl_state != .connected) return Error.SslHandshakeFailed;

        try checkError(c.nghttp2_session_server_new(&self.session, callbacks, self));

        const settings: [2]c.nghttp2_settings_entry = .{
            .{ .settings_id = c.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = self.server.config.http2.max_concurrent_streams },
            .{ .settings_id = c.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = self.server.config.http2.initial_window_size },
        };
        _ = c.nghttp2_submit_settings(self.session, c.NGHTTP2_FLAG_NONE, &settings, settings.len);
    }

    fn cleanup(self: *Self) void {
        if (self.session) |session| {
            _ = c.nghttp2_session_del(session);
        }
        if (self.ssl) |ssl| {
            c.wolfSSL_free(ssl);
        }
        self.ssl_state = .closed;
    }
};

// nghttp2 callback: frame received
fn onFrameRecv(_: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, client_data: ?*anyopaque) callconv(.C) c_int {
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
fn onHeader(
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

                        if (!std.mem.eql(u8, path_portion, VALID_DOH_PATH)) {
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
                                    if (value_part.len > MAX_DNS_QUERY_LEN) {
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
fn onSend(session: ?*c.struct_nghttp2_session, response: [*c]const u8, length: usize, _: c_int, client_data: ?*anyopaque) callconv(.C) isize {
    if (client_data) |data| {
        const request_ctx: *RequestContext = @ptrCast(@alignCast(data));

        const sent = c.wolfSSL_write(request_ctx.ssl, response, @intCast(length));

        if (sent < 0) {
            const err = c.wolfSSL_get_error(request_ctx.ssl, sent);
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
fn onStreamClose(_: ?*c.nghttp2_session, stream_id: i32, _: u32, client_data: ?*anyopaque) callconv(.C) c_int {
    _ = stream_id;
    _ = client_data;
    // cleanup handled by session termination
    return 0;
}

// Convert nghttp2 return codes to errors
fn checkError(rc: c_int) !void {
    if (rc < 0) return error.NgHttp2Error;
}

// DNS response data for HTTP2 streaming
const StreamData = struct { stream_id: i32, response_buffer: []const u8, response_len: usize, response_pos: usize = 0 };

// nghttp2 callback: stream response data
fn dataReadCallback(_: ?*c.nghttp2_session, _: i32, buf: [*c]u8, length: usize, data_flags: [*c]u32, source: [*c]c.nghttp2_data_source, _: ?*anyopaque) callconv(.C) isize {
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

fn isValidDnsQuery(data: []const u8) bool {
    if (data.len < DNS_HEADER_LEN) return false;

    // QR bit (bit 0 of byte 2) must be 0 for query
    const flags = (@as(u16, data[2]) << 8) | data[3];
    const qr_bit = (flags >> 15) & 0x01;
    if (qr_bit != 0) return false; // Must be query, not response

    // Question count is at least 1
    const qdcount = (@as(u16, data[4]) << 8) | data[5];
    if (qdcount == 0) return false;

    return true;
}

pub const Server = struct {
    listener: std.net.Server,
    listener_socket: std.posix.socket_t,
    https_server_addr: std.net.Address,
    dns_server_addr: std.net.Address,
    ctx: *c.WOLFSSL_CTX,
    allocator: std.mem.Allocator,
    dns_pool: DnsConnectionPool,
    config: config.Config,

    pub fn init(allocator: std.mem.Allocator, server_config: config.Config) !Server {
        if (c.wolfSSL_Init() != c.SSL_SUCCESS) {
            return Error.SslInitFailed;
        }

        const ctx = c.wolfSSL_CTX_new(c.wolfTLSv1_3_server_method()) orelse
            return Error.SslInitFailed;

        if (c.wolfSSL_CTX_use_certificate_file(ctx, server_config.ssl.cert_file.ptr, c.SSL_FILETYPE_PEM) != c.SSL_SUCCESS) {
            c.wolfSSL_CTX_free(ctx);
            return Error.CertLoadFailed;
        }

        if (c.wolfSSL_CTX_use_PrivateKey_file(ctx, server_config.ssl.key_file.ptr, c.SSL_FILETYPE_PEM) != c.SSL_SUCCESS) {
            c.wolfSSL_CTX_free(ctx);
            return Error.KeyLoadFailed;
        }

        const https_server_addr = net.Address.parseIp4("127.0.0.1", server_config.server.listen_port) catch |err| {
            std.debug.print("An error occurred while resolving the IP address: {}\n", .{err});
            c.wolfSSL_CTX_free(ctx);
            return Error.ServerListenFailed;
        };

        const listener_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        const dns_server_addr = try std.net.Address.parseIp4(server_config.dns.server, server_config.dns.port);
        const dns_pool = try DnsConnectionPool.init(allocator, dns_server_addr, server_config.dns.pool_size, server_config.dns.socket_timeout_sec);
        const listener = try https_server_addr.listen(std.net.Address.ListenOptions{});

        return Server{
            .listener = listener,
            .listener_socket = listener_socket,
            .https_server_addr = https_server_addr,
            .dns_server_addr = dns_server_addr,
            .ctx = ctx,
            .allocator = allocator,
            .dns_pool = dns_pool,
            .config = server_config,
        };
    }

    // Clean up server resources
    pub fn deinit(self: *Server) void {
        self.listener.deinit();
        std.posix.close(self.listener_socket);
        self.dns_pool.deinit();
        c.wolfSSL_CTX_free(self.ctx);
        //c.wolfSSL_Cleanup();
    }

    // Accept and handle HTTPS connections
    // TODO: use async interfaces
    pub fn accept(self: *Server) !void {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = self.allocator, .n_jobs = self.config.server.max_concurrent_connections });
        defer pool.deinit();

        var connection_count: u64 = 0;

        while (true) {
            const connection = self.listener.accept() catch |err| {
                std.log.err("Connection to client interrupted: {}\n", .{err});
                continue;
            };
            connection_count += 1;
            try pool.spawn(handleConnectionWithRetries, .{ self, connection });
            std.log.debug("Connection {} accepted from {any}", .{ connection_count, connection.address });
        }
    }

    // wrap connection hadler with retry on error logic and error managment.
    // returns void so we can pass it to Pool.spawn()
    // TODO: here we retry using only on dns server. We should support cascading or
    // round robin server pools.
    // TODO: this is hacky.
    fn handleConnectionWithRetries(self: *Server, connection: std.net.Server.Connection) void {
        defer connection.stream.close();

        const timeout = std.posix.timeval{
            .sec = @intCast(self.config.server.connection_timeout_sec),
            .usec = 0,
        };

        std.posix.setsockopt(connection.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            std.log.err("Failed to set socket timeout: {}", .{err});
            return;
        };

        std.posix.setsockopt(connection.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            std.log.err("Failed to set socket timeout: {}", .{err});
            return;
        };

        const max_tries = self.config.server.max_retry_attempts;
        var attempt: u8 = 0;

        while (attempt < max_tries) {
            attempt += 1;

            self.handleDohRequest(connection) catch |err| {
                const should_retry = switch (err) {
                    // transient errors
                    Error.DnsQueryFailed => true,
                    Error.SslHandshakeFailed => true,

                    // permanent errors
                    Error.AlpnFailed => false,
                    Error.SslInitFailed => false,
                    //                    Error.OutOfMemory => false,

                    // other errors
                    else => attempt < 2,
                };

                if (should_retry and attempt < max_tries) {
                    std.log.debug("Retrying connection {any} in {}ms (attempt {}/{}): {}", .{ connection.address, self.config.server.retry_delay_ms, attempt, max_tries, err });
                    std.time.sleep(self.config.server.retry_delay_ms * std.time.ns_per_ms);
                    continue;
                } else {
                    std.log.warn("Connection {any} failed permanently after {} attempts: {}", .{ connection.address, attempt, err });
                    return;
                }
            };

            std.log.info("Connection {any} completed successfully", .{connection.address});
        }
    }

    // Handle single client connection: SSL handshake, HTTP/2 setup, DNS processing
    fn handleDohRequest(self: *Server, connection: std.net.Server.Connection) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var request_ctx = RequestContext{
            .connection = connection,
            .allocator = allocator,
            .server = self,
        };
        defer request_ctx.cleanup();

        // SSL handshake
        try request_ctx.initSsl(self.ctx);
        try request_ctx.performHandshake();

        // HTTP2 setup
        var callbacks: ?*c.nghttp2_session_callbacks = null;
        try checkError(c.nghttp2_session_callbacks_new(&callbacks));
        defer c.nghttp2_session_callbacks_del(callbacks);

        _ = c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, onFrameRecv);
        _ = c.nghttp2_session_callbacks_set_on_header_callback(callbacks, onHeader);
        _ = c.nghttp2_session_callbacks_set_send_callback(callbacks, onSend);

        try request_ctx.initHttp2Session(callbacks);

        try self.processHttp2Messages(&request_ctx);
    }

    fn processHttp2Messages(self: *Server, request_ctx: *RequestContext) !void {
        const buf = try self.allocator.alloc(u8, self.config.http.buffer_size);
        defer self.allocator.free(buf);

        while (true) {
            const bytes_read = c.wolfSSL_read(request_ctx.ssl, buf.ptr, @intCast(buf.len));

            if (bytes_read > 0) {
                const res = c.nghttp2_session_mem_recv(request_ctx.session, buf.ptr, @intCast(bytes_read));
                if (res < 0) {
                    std.log.info("nghttp2_session_mem_recv error: {}", .{res});
                    return Error.DnsQueryFailed;
                }

                if (request_ctx.dns_request.len == 0) {
                    continue;
                }

                try self.processDnsRequest(request_ctx);
                break;
            } else if (bytes_read == 0) {
                if (request_ctx.dns_request.len > 0) {
                    try self.processDnsRequest(request_ctx);
                }
                break;
            } else {
                const ssl_error = c.wolfSSL_get_error(request_ctx.ssl, bytes_read);
                if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                    std.log.info("SSL error: {}", .{ssl_error});
                    return Error.DnsQueryFailed;
                }
            }
        }

        _ = c.nghttp2_session_terminate_session(request_ctx.session, c.NGHTTP2_NO_ERROR);
        _ = c.nghttp2_session_send(request_ctx.session);
    }

    // Process DNS request: decode query, forward to DNS server, send response
    fn processDnsRequest(self: *Server, request_ctx: *RequestContext) !void {
        const decoded = decodeUrlSafeBase64(request_ctx.allocator, request_ctx.dns_request) catch |err| {
            std.log.err("Failed to decode DNS parameter: {}", .{err});
            return err;
        };

        if (!isValidDnsQuery(decoded)) {
            return Error.DnsQueryIsNotValid;
        }

        const dns_socket = self.dns_pool.acquire() orelse return Error.DnsPoolExhausted;
        defer self.dns_pool.release(dns_socket);

        const bytes_sent = try std.posix.sendto(
            dns_socket,
            decoded,
            0,
            @ptrCast(&self.dns_server_addr),
            self.dns_server_addr.getOsSockLen(),
        );
        if (bytes_sent != decoded.len) {
            return Error.DnsQueryFailed;
        }

        var response_buffer = try self.allocator.alloc(u8, self.config.dns.response_size);
        defer self.allocator.free(response_buffer);
        const response_addr: std.net.Address = undefined;
        var addrlen: u32 = self.dns_server_addr.getOsSockLen();

        // Guard against truncation attacks.
        const response_size = try std.posix.recvfrom(dns_socket, response_buffer, posix.MSG.TRUNC, @ptrCast(response_addr), &addrlen);

        if (response_size <= 0) {
            return Error.DnsQueryFailed;
        }

        if (response_size > self.config.dns.response_size) {
            std.log.warn("DNS response size ({} bytes)) exceeds max ({} bytes)", .{ response_size, self.config.dns.response_size });
            return Error.DnsQueryFailed;
        }
        // Validate minimum DNS response size
        if (response_size < DNS_HEADER_LEN) {
            std.log.err("DNS response too short: {} bytes", .{response_size});
            return Error.DnsQueryFailed;
        }

        // Validate response came from expected DNS server
        if (!std.net.Address.eql(response_addr, self.dns_server_addr)) {
            std.log.warn("DNS response from unexpected address: {}, expected: {}", .{ response_addr, self.dns_server_addr });
            return Error.DnsQueryFailed;
        }

        // Validate that we received a response, not a query.
        // Guard against confusion attacks.
        const flags = (@as(u16, response_buffer[2]) << 8) | response_buffer[3];
        const qr_bit = (flags >> 15) & 0x01;
        if (qr_bit != 1) {
            std.log.err("Received DNS query instead of response");
            return Error.DnsQueryFailed;
        }

        try self.sendHttp2Response(request_ctx, response_buffer[0..response_size]);
    }

    // Send DNS response as HTTP/2 response with appropriate headers
    fn sendHttp2Response(self: *Server, request_ctx: *RequestContext, dns_response: []const u8) !void {
        const cache_control_value = try std.fmt.allocPrint(request_ctx.allocator, "max-age={}", .{self.config.http.cache_control_max_age});
        defer request_ctx.allocator.free(cache_control_value);

        const headers: [4]c.nghttp2_nv = .{
            .{ .name = @constCast(":status".ptr), .value = @constCast("200".ptr), .namelen = ":status".len, .valuelen = "200".len },
            .{ .name = @constCast("content-type".ptr), .value = @constCast("application/dns-message".ptr), .namelen = "content-type".len, .valuelen = "application/dns-message".len },
            .{ .name = @constCast("server".ptr), .value = @constCast("dohd".ptr), .namelen = "server".len, .valuelen = "dohd".len },
            .{ .name = @constCast("cache-control".ptr), .value = @constCast(cache_control_value.ptr), .namelen = "cache-control".len, .valuelen = cache_control_value.len },
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
};
