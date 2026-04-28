// Shared C imports to ensure consistent opaque types across modules
pub const c = @cImport({
    @cDefine("XSTAT_TYPE", "struct stat");
    // Disable empty aggregate support to avoid GCC pragma directives that
    // Zig's C translator cannot handle (WOLF_AGG_DUMMY_MEMBER in hash.h).
    @cDefine("HAVE_EMPTY_AGGREGATES", "0");
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
    @cInclude("nghttp2/nghttp2.h");
});
