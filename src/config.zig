const std = @import("std");
const json = std.json;

pub const ConfigError = error{
    MissingServerConfig,
    MissingDnsConfig,
    MissingSslConfig,
    MissingListenAddress,
    MissingListenPort,
    MissingDnsServer,
    MissingDnsPort,
    MissingCertFile,
    MissingKeyFile,
};

pub const ServerConfig = struct {
    listen_address: []const u8,
    listen_port: u16,
    max_concurrent_connections: u32,
    connection_timeout_ms: u32,
    max_retry_attempts: u8,
    retry_delay_ms: u32,
};

pub const DnsConfig = struct {
    server: []const u8,
    port: u16,
    pool_size: u32,
    response_size: u32,
    socket_timeout_ms: u32,
};

pub const SslConfig = struct {
    cert_file: []const u8,
    key_file: []const u8,
    handshake_timeout_ms: u32,
    handshake_max_attempts: u8,
};

pub const HttpConfig = struct {
    buffer_size: u32,
    cache_control_max_age: u32,
    max_concurrent_streams: u32,
    initial_window_size: u32,
};

fn getIntOrDefault(comptime T: type, obj: ?json.ObjectMap, key: []const u8, default: T) T {
    const map = obj orelse return default;
    const val = map.get(key) orelse return default;
    return switch (val) {
        .integer => |i| @intCast(i),
        else => default,
    };
}

pub const Config = struct {
    server: ServerConfig,
    dns: DnsConfig,
    ssl: SslConfig,
    http: HttpConfig,

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

        // Required sections
        const server_obj = root.get("server") orelse return error.MissingServerConfig;
        const dns_obj = root.get("dns") orelse return error.MissingDnsConfig;
        const ssl_obj = root.get("ssl") orelse return error.MissingSslConfig;

        const server_map = server_obj.object;
        const dns_map = dns_obj.object;
        const ssl_map = ssl_obj.object;

        // Optional section
        const http_map: ?json.ObjectMap = if (root.get("http")) |h| h.object else null;

        // Required fields - will fail if missing
        const listen_address = server_map.get("listen_address") orelse return error.MissingListenAddress;
        const listen_port = server_map.get("listen_port") orelse return error.MissingListenPort;
        const dns_server_val = dns_map.get("server") orelse return error.MissingDnsServer;
        const dns_port = dns_map.get("port") orelse return error.MissingDnsPort;
        const cert_file_val = ssl_map.get("cert_file") orelse return error.MissingCertFile;
        const key_file_val = ssl_map.get("key_file") orelse return error.MissingKeyFile;

        return Self{
            .server = ServerConfig{
                .listen_address = try allocator.dupe(u8, listen_address.string),
                .listen_port = @intCast(listen_port.integer),
                .max_concurrent_connections = getIntOrDefault(u32, server_map, "max_concurrent_connections", 100),
                .connection_timeout_ms = getIntOrDefault(u32, server_map, "connection_timeout_ms", 30000),
                .max_retry_attempts = getIntOrDefault(u8, server_map, "max_retry_attempts", 3),
                .retry_delay_ms = getIntOrDefault(u32, server_map, "retry_delay_ms", 100),
            },
            .dns = DnsConfig{
                .server = try allocator.dupe(u8, dns_server_val.string),
                .port = @intCast(dns_port.integer),
                .pool_size = getIntOrDefault(u32, dns_map, "pool_size", 10),
                .response_size = getIntOrDefault(u32, dns_map, "response_size", 4096),
                .socket_timeout_ms = getIntOrDefault(u32, dns_map, "socket_timeout_ms", 5000),
            },
            .ssl = SslConfig{
                .cert_file = try allocator.dupe(u8, cert_file_val.string),
                .key_file = try allocator.dupe(u8, key_file_val.string),
                .handshake_timeout_ms = getIntOrDefault(u32, ssl_map, "handshake_timeout_ms", 5000),
                .handshake_max_attempts = getIntOrDefault(u8, ssl_map, "handshake_max_attempts", 5),
            },
            .http = HttpConfig{
                .buffer_size = getIntOrDefault(u32, http_map, "buffer_size", 1460),
                .cache_control_max_age = getIntOrDefault(u32, http_map, "cache_control_max_age", 300),
                .max_concurrent_streams = getIntOrDefault(u32, http_map, "max_concurrent_streams", 100),
                .initial_window_size = getIntOrDefault(u32, http_map, "initial_window_size", 65536),
            },
        };
    }

    pub fn defaults(allocator: std.mem.Allocator) !Self {
        return Self{
            .server = ServerConfig{
                .listen_address = try allocator.dupe(u8, "127.0.0.1"),
                .listen_port = 8443,
                .max_concurrent_connections = 100,
                .connection_timeout_ms = 30000,
                .max_retry_attempts = 3,
                .retry_delay_ms = 100,
            },
            .dns = DnsConfig{
                .server = try allocator.dupe(u8, "8.8.8.8"),
                .port = 53,
                .pool_size = 10,
                .response_size = 4096,
                .socket_timeout_ms = 5000,
            },
            .ssl = SslConfig{
                .cert_file = try allocator.dupe(u8, "./certs/server.crt"),
                .key_file = try allocator.dupe(u8, "./certs/server.key"),
                .handshake_timeout_ms = 5000,
                .handshake_max_attempts = 5,
            },
            .http = HttpConfig{
                .buffer_size = 1460,
                .cache_control_max_age = 300,
                .max_concurrent_streams = 100,
                .initial_window_size = 65536,
            },
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.server.listen_address);
        allocator.free(self.ssl.cert_file);
        allocator.free(self.ssl.key_file);
        allocator.free(self.dns.server);
    }
};
