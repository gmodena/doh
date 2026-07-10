const std = @import("std");
const net = std.Io.net;
const config = @import("config.zig");
const errorz = @import("error");
const http = @import("http.zig");
const dns = @import("dns.zig");
const c = @import("cimports.zig").c;

const Allocator = std.mem.Allocator;

pub const Config = config.Config;
pub const decodeUrlSafeBase64 = http.decodeUrlSafeBase64;

const Error = errorz.Error;

pub const Server = struct {
    listener: net.Server,
    listener_socket: net.Socket,
    https_server_addr: net.IpAddress,
    dns_server_addr: net.IpAddress,
    ctx: *c.WOLFSSL_CTX,
    allocator: std.mem.Allocator,
    dns_pool: dns.ConnectionPool,
    config: config.Config,
    io: std.Io,
    semaphore: std.Io.Semaphore,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, server_config: config.Config) !Server {
        // Server level ssl context, shared across connections.
        // Context lifetime should match server lifetime.
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

        const https_server_addr = net.IpAddress.parseIp4(server_config.server.listen_address, server_config.server.listen_port) catch |err| {
            std.debug.print("An error occurred while resolving the IP address: {}\n", .{err});
            c.wolfSSL_CTX_free(ctx);
            return Error.ServerListenFailed;
        };

        const ephemeral: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
        const listener_socket = try ephemeral.bind(io, .{ .mode = .dgram });
        const dns_server_addr = try net.IpAddress.parseIp4(server_config.dns.server, server_config.dns.port);
        const dns_pool = try dns.ConnectionPool.init(io, allocator, dns_server_addr, server_config.dns.pool_size);
        const listener = try https_server_addr.listen(io, .{});

        return Server{
            .listener = listener,
            .listener_socket = listener_socket,
            .https_server_addr = https_server_addr,
            .dns_server_addr = dns_server_addr,
            .ctx = ctx,
            .allocator = allocator,
            .dns_pool = dns_pool,
            .config = server_config,
            .io = io,
            .semaphore = .{ .permits = server_config.server.max_concurrent_connections },
        };
    }

    // Clean up server resources
    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.listener_socket.close(self.io);
        self.dns_pool.deinit();
        c.wolfSSL_CTX_free(self.ctx);
        _ = c.wolfSSL_Cleanup();
    }

    // Accept and handle HTTPS connections
    // TODO: use async interfaces
    pub fn accept(self: *Server) !void {
        var group: std.Io.Group = .init;

        var connection_count: u64 = 0;

        while (true) {
            const connection = self.listener.accept(self.io) catch |err| {
                std.log.err("Connection to client interrupted: {}\n", .{err});
                continue;
            };
            connection_count += 1;
            self.semaphore.waitUncancelable(self.io);
            group.concurrent(self.io, handleConnectionWithRetries, .{ self, connection }) catch |err| {
                self.semaphore.post(self.io);
                std.log.err("Failed to spawn connection handler: {}", .{err});
                connection.close(self.io);
                continue;
            };
            std.log.debug("Connection {} accepted", .{connection_count});
        }
    }

    // wrap connection handler with retry on error logic and error management.
    // returns void so we can pass it to Group.concurrent()
    // TODO: here we retry using only on dns server. We should support cascading or
    // round robin server pools.
    // TODO: this is hacky.
    fn handleConnectionWithRetries(self: *Server, connection: net.Stream) void {
        defer self.semaphore.post(self.io);
        defer connection.close(self.io);

        const timeout = std.posix.timeval{
            .sec = @intCast(self.config.server.connection_timeout_ms / 1000),
            .usec = 0,
        };
        std.posix.setsockopt(connection.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            std.log.err("Failed to set SO_RCVTIMEO: {}", .{err});
            return;
        };
        std.posix.setsockopt(connection.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            std.log.err("Failed to set SO_SNDTIMEO: {}", .{err});
            return;
        };

        const retry_policy = errorz.RetryPolicy{
            .max_tries = self.config.server.max_retry_attempts,
            .timeout_ms = self.config.server.connection_timeout_ms,
        };

        errorz.retry(Server.handleConnection, .{ self, connection }, retry_policy) catch |err| {
            std.log.err("Connection fd={} failed with {}", .{ connection.socket.handle, err });
        };

        std.log.info("Connection fd={} completed successfully", .{connection.socket.handle});
    }

    /// Handle client connection: SSL handshake, HTTP/2 setup, DNS processing
    fn handleConnection(self: *Server, connection: net.Stream) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var request_ctx = try http.RequestContext.init(connection, allocator, self.ctx);
        defer request_ctx.cleanup();

        // SSL handshake
        try request_ctx.performHandshake(self.config);

        // HTTP2 setup
        var callbacks: ?*c.nghttp2_session_callbacks = null;
        try http.checkError(c.nghttp2_session_callbacks_new(&callbacks));
        defer c.nghttp2_session_callbacks_del(callbacks);

        _ = c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, http.onFrameRecv);
        _ = c.nghttp2_session_callbacks_set_on_header_callback(callbacks, http.onHeader);
        _ = c.nghttp2_session_callbacks_set_send_callback(callbacks, http.onSend);

        try request_ctx.createSession(callbacks, self.config);

        try self.processDohRequest(&request_ctx);
    }

    /// Processes a DNS-over-HTTPS request from client connection.
    /// Reads SSL/TLS data, parses HTTP/2 frames, extracts DNS query, and sends response.
    fn processDohRequest(self: *Server, request_ctx: *http.RequestContext) !void {
        const buf = try request_ctx.allocator.alloc(u8, self.config.http.buffer_size);

        errdefer {
            _ = c.nghttp2_session_terminate_session(request_ctx.session, c.NGHTTP2_INTERNAL_ERROR);
            _ = c.nghttp2_session_send(request_ctx.session);
        }

        while (true) {
            const bytes_read = c.wolfSSL_read(request_ctx.ssl_connection.ssl, buf.ptr, @intCast(buf.len));

            if (bytes_read > 0) {
                const res = c.nghttp2_session_mem_recv(request_ctx.session, buf.ptr, @intCast(bytes_read));
                if (res < 0) {
                    std.log.info("nghttp2_session_mem_recv error: {}", .{res});
                    return Error.DnsQueryFailed;
                }

                if (request_ctx.dns_request.len == 0) {
                    continue;
                }

                try self.processDnsQuery(request_ctx);
                break;
            } else if (bytes_read == 0) {
                std.log.debug("EOF: dns_request.len={}", .{request_ctx.dns_request.len});
                if (request_ctx.dns_request.len > 0) {
                    try self.processDnsQuery(request_ctx);
                }
                break;
            } else {
                const ssl_error = c.wolfSSL_get_error(request_ctx.ssl_connection.ssl, bytes_read);
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
    fn processDnsQuery(self: *Server, request_ctx: *http.RequestContext) !void {
        const decoded = http.decodeUrlSafeBase64(request_ctx.allocator, request_ctx.dns_request) catch |err| {
            std.log.err("Failed to decode DNS parameter: {}", .{err});
            return err;
        };

        if (!dns.isValidQuery(decoded)) {
            return Error.DnsQueryIsNotValid;
        }

        const query_transaction_id = (@as(u16, decoded[0]) << 8) | decoded[1];

        const dns_socket = self.dns_pool.acquire(self.io);
        defer self.dns_pool.release(self.io, dns_socket);

        try dns_socket.send(self.io, &self.dns_server_addr, decoded);

        var response_buffer = try request_ctx.allocator.alloc(u8, self.config.dns.response_size);

        // Guard against truncation attacks; use receiveTimeout to apply DNS socket deadline.
        const timeout: std.Io.Timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(self.config.dns.socket_timeout_ms),
            .clock = .awake,
        } };
        const msg = try dns_socket.receiveTimeout(self.io, response_buffer, timeout);
        const response_size = msg.data.len;

        if (msg.flags.trunc) {
            std.log.err("DNS response was truncated (exceeds {} bytes)", .{self.config.dns.response_size});
            return Error.DnsQueryFailed;
        }

        if (response_size == 0) {
            return Error.DnsQueryFailed;
        }

        // Validate minimum DNS response size
        if (response_size < dns.HEADER_LEN) {
            std.log.err("DNS response too short: {} bytes", .{response_size});
            return Error.DnsQueryFailed;
        }

        // Validate response came from expected DNS server
        if (!net.IpAddress.eql(&msg.from, &self.dns_server_addr)) {
            std.log.err("DNS response from unexpected address: {any}, expected: {any}", .{ msg.from, self.dns_server_addr });
            return Error.DnsQueryFailed;
        }

        // Validate that we received a response, not a query.
        // Guard against confusion attacks.
        const flags = (@as(u16, response_buffer[2]) << 8) | response_buffer[3];
        const qr_bit = (flags >> 15) & 0x01;
        if (qr_bit != 1) {
            std.log.err("Received DNS query instead of response", .{});
            return Error.DnsQueryFailed;
        }

        // Validate that transaction ID from response matches the query one.
        const response_transaction_id = (@as(u16, response_buffer[0]) << 8) | response_buffer[1];
        if (response_transaction_id != query_transaction_id) {
            std.log.err("DNS transaction ID mismatch: query={}, response={}", .{ query_transaction_id, response_transaction_id });

            return Error.DnsQueryFailed;
        }

        try http.sendResponse(request_ctx, response_buffer[0..response_size], self.config);
    }
};
