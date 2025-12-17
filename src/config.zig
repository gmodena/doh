const std = @import("std");
const json = std.json;

pub const ServerConfig = struct {
    listen_port: u16,
    max_concurrent_connections: u32,
    connection_timeout_sec: u32,
    max_retry_attempts: u32,
    retry_delay_ms: u32,
};

pub const DnsConfig = struct { server: []const u8, port: u16, pool_size: u32, response_size: u32, socket_timeout_sec: u32 };

pub const SslConfig = struct {
    cert_file: []const u8,
    key_file: []const u8,
    handshake_timeout_ms: u32,
    handshake_max_attempts: u32,
};

pub const HttpConfig = struct {
    buffer_size: u32,
    cache_control_max_age: u32,
};

pub const Http2Config = struct {
    max_concurrent_streams: u32,
    initial_window_size: u32,
};

pub const Config = struct {
    server: ServerConfig,
    dns: DnsConfig,
    ssl: SslConfig,
    http: HttpConfig,
    http2: Http2Config,

    const Self = @This();

    pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !Self {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.warn("Config file not found at '{s}', using defaults", .{file_path});
                return Self.defaults(allocator);
            },
            else => return err,
        };
        defer file.close();

        const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(contents);

        const parsed = try json.parseFromSlice(json.Value, allocator, contents, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        const server_obj = root.get("server").?.object;
        const dns_obj = root.get("dns").?.object;
        const ssl_obj = root.get("ssl").?.object;
        const http_obj = root.get("http").?.object;
        const http2_obj = root.get("http2").?.object;

        const cert_file = try allocator.dupe(u8, ssl_obj.get("cert_file").?.string);
        const key_file = try allocator.dupe(u8, ssl_obj.get("key_file").?.string);
        const dns_server = try allocator.dupe(u8, dns_obj.get("server").?.string);

        return Self{
            .server = ServerConfig{
                .listen_port = @intCast(server_obj.get("listen_port").?.integer),
                .max_concurrent_connections = @intCast(server_obj.get("max_concurrent_connections").?.integer),
                .connection_timeout_sec = @intCast(server_obj.get("connection_timeout_sec").?.integer),
                .max_retry_attempts = @intCast(server_obj.get("max_retry_attempts").?.integer),
                .retry_delay_ms = @intCast(server_obj.get("retry_delay_ms").?.integer),
            },
            .dns = DnsConfig{ .server = dns_server, .port = @intCast(dns_obj.get("port").?.integer), .pool_size = @intCast(dns_obj.get("pool_size").?.integer), .response_size = @intCast(dns_obj.get("response_size").?.integer), .socket_timeout_sec = @intCast(dns_obj.get("socket_timeout_sec").?.integer) },
            .ssl = SslConfig{
                .cert_file = cert_file,
                .key_file = key_file,
                .handshake_timeout_ms = @intCast(ssl_obj.get("handshake_timeout_ms").?.integer),
                .handshake_max_attempts = @intCast(ssl_obj.get("handshake_max_attempts").?.integer),
            },
            .http = HttpConfig{
                .buffer_size = @intCast(http_obj.get("buffer_size").?.integer),
                .cache_control_max_age = @intCast(http_obj.get("cache_control_max_age").?.integer),
            },
            .http2 = Http2Config{
                .max_concurrent_streams = @intCast(http2_obj.get("max_concurrent_streams").?.integer),
                .initial_window_size = @intCast(http2_obj.get("initial_window_size").?.integer),
            },
        };
    }

    pub fn defaults(allocator: std.mem.Allocator) !Self {
        const cert_file = try allocator.dupe(u8, "./certs/server.crt");
        const key_file = try allocator.dupe(u8, "./certs/server.key");
        const dns_server = try allocator.dupe(u8, "8.8.8.8");

        return Self{
            .server = ServerConfig{
                .listen_port = 8443,
                .max_concurrent_connections = 100,
                .connection_timeout_sec = 30,
                .max_retry_attempts = 3,
                .retry_delay_ms = 100,
            },
            .dns = DnsConfig{ .server = dns_server, .port = 53, .pool_size = 10, .response_size = 4096, .socket_timeout_sec = 5 },
            .ssl = SslConfig{
                .cert_file = cert_file,
                .key_file = key_file,
                .handshake_timeout_ms = 5000,
                .handshake_max_attempts = 5,
            },
            .http = HttpConfig{
                .buffer_size = 1460,
                .cache_control_max_age = 300,
            },
            .http2 = Http2Config{
                .max_concurrent_streams = 100,
                .initial_window_size = 65536,
            },
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.ssl.cert_file);
        allocator.free(self.ssl.key_file);
        allocator.free(self.dns.server);
    }
};
