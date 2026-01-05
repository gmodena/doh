const std = @import("std");
const net = std.net;
const posix = std.posix;
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
    listener: std.net.Server,
    listener_socket: std.posix.socket_t,
    https_server_addr: std.net.Address,
    dns_server_addr: std.net.Address,
    ctx: *c.WOLFSSL_CTX,
    allocator: std.mem.Allocator,
    dns_pool: dns.ConnectionPool,
    config: config.Config,

    pub fn init(allocator: std.mem.Allocator, server_config: config.Config) !Server {
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

        const https_server_addr = net.Address.parseIp4("127.0.0.1", server_config.server.listen_port) catch |err| {
            std.debug.print("An error occurred while resolving the IP address: {}\n", .{err});
            c.wolfSSL_CTX_free(ctx);
            return Error.ServerListenFailed;
        };

        const listener_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        const dns_server_addr = try std.net.Address.parseIp4(server_config.dns.server, server_config.dns.port);
        const dns_pool = try dns.ConnectionPool.init(allocator, dns_server_addr, server_config.dns.pool_size, server_config.dns.socket_timeout_ms);
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
        _ = c.wolfSSL_Cleanup();
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
            .sec = @intCast(self.config.server.connection_timeout_ms / 1000),
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

        const retry_policy = errorz.RetryPolicy{
            .max_tries = self.config.server.max_retry_attempts,
            .delay_ms = 3,
            .timeout_ms = 100,
        };

        errorz.retry(Server.handleConnection, .{ self, connection }, retry_policy) catch |err| {
            std.log.err("Connection {any} failed with {}", .{ connection.address, err });
        };

        std.log.info("Connection {any} completed successfully", .{connection.address});
    }

    /// Handle client connection: SSL handshake, HTTP/2 setup, DNS processing
    fn handleConnection(self: *Server, connection: std.net.Server.Connection) !void {
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

        var response_buffer = try request_ctx.allocator.alloc(u8, self.config.dns.response_size);

        var response_addr: std.net.Address = undefined;
        var addrlen: u32 = self.dns_server_addr.getOsSockLen();

        // Guard against truncation attacks.
        const response_size = try std.posix.recvfrom(dns_socket, response_buffer, posix.MSG.TRUNC, @ptrCast(&response_addr), &addrlen);

        if (response_size <= 0) {
            return Error.DnsQueryFailed;
        }

        if (response_size > self.config.dns.response_size) {
            std.log.err("DNS response size ({} bytes)) exceeds max ({} bytes)", .{ response_size, self.config.dns.response_size });
            return Error.DnsQueryFailed;
        }
        // Validate minimum DNS response size
        if (response_size < dns.HEADER_LEN) {
            std.log.err("DNS response too short: {} bytes", .{response_size});
            return Error.DnsQueryFailed;
        }

        // Validate response came from expected DNS server
        if (!std.net.Address.eql(response_addr, self.dns_server_addr)) {
            std.log.err("DNS response from unexpected address: {any}, expected: {any}", .{ response_addr, self.dns_server_addr });
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
