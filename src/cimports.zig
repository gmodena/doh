// Shared C imports to ensure consistent opaque types across modules
pub const c = @cImport({
    @cDefine("XSTAT_TYPE", "struct stat");
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
    @cInclude("nghttp2/nghttp2.h");
});
