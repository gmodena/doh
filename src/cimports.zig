// Shared C imports to ensure consistent opaque types across modules
pub const c = @cImport({
    @cDefine("XSTAT_TYPE", "struct stat");
    // WIP: Disable empty aggregate support to avoid gcc pragma
    // directives that zig's c translator cannot handle
    // (WOLF_AGG_DUMMY_MEMBER in hash.h).
    @cDefine("HAVE_EMPTY_AGGREGATES", "0");
    // WIP: Disable glibc fortification: with -O2 (ReleaseSafe).
    @cUndef("_FORTIFY_SOURCE");
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
    @cInclude("nghttp2/nghttp2.h");
});
