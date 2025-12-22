const std = @import("std");

/// Covers server initialization, SSL/TLS operations, DNS queries, and connection handling.
pub const Error = error{
    ServerInitFailed,
    SslInitFailed,
    CertLoadFailed,
    KeyLoadFailed,
    DnsQueryFailed,
    DnsQueryHasNoData,
    DnsQueryIsNotValid,
    ServerListenFailed,
    AlpnFailed,
    SslHandshakeFailed,
    SessionFailed,
    DnsPoolExhausted,
};

const RetryableError = enum {
    transient, // Should retry
    permanent, // Won't retry
    unknown, // Who knows? Fallback to attempt based retry
};

/// Configuration for retry operations.
///
/// Fields:
/// - max_tries: Maximum number of retry attempts
/// - delay_ms: Optional delay between retries in milliseconds
/// - timeout_ms: Optional total operation timeout in milliseconds
/// - should_retry: Optional custom function to determine if an error should trigger a retry.
///                 Used to filter error classes.
pub const RetryPolicy = struct {
    max_tries: u8,
    delay_ms: ?u32,
    timeout_ms: ?u32,
    should_retry: ?*const fn (anyerror) bool = null,
};

fn retryCall(comptime Context: type, context: Context, config: RetryPolicy) !void {
    var attempt: u8 = 0;
    const start_time = if (config.timeout_ms) |_| std.time.milliTimestamp() else 0;

    while (attempt < config.max_tries) {
        attempt += 1;

        if (config.timeout_ms) |timeout| {
            if (std.time.milliTimestamp() - start_time > timeout) {
                return error.OperationTimeout;
            }
        }

        context.call() catch |err| {
            const should_retry = if (config.should_retry) |classifier|
                classifier(err)
            else
                shouldRetry(err);

            if (should_retry and attempt < config.max_tries) {
                if (config.delay_ms) |delay| {
                    std.time.sleep(@as(u64, delay) * std.time.ns_per_ms);
                }
                continue;
            }
            return err;
        };
        return;
    }
}

fn shouldRetry(err: anyerror) bool {
    return switch (err) {
        error.DnsQueryFailed,
        error.SslHandshakeFailed,
        error.DnsPoolExhausted,
        => true,
        else => false,
    };
}

/// Retry a function call according to the specified policy.
///
/// Parameters:
/// - func: The function to retry
/// - args: Arguments to pass to the function
/// - config: Retry policy configuration
///
/// Returns: void on success, or the last error encountered
pub fn retry(comptime func: anytype, args: anytype, config: RetryPolicy) !void {
    const Args = @TypeOf(args);
    const Ctx = struct {
        args: Args,

        pub fn call(self: *const @This()) !void {
            return @call(.auto, func, self.args);
        }
    };
    const ctx = Ctx{ .args = args };
    return retryCall(*const Ctx, &ctx, config);
}
