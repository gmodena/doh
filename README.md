# DoH

A [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484) DNS-over-HTTPS (DoH) server implementation in Zig using [WolfSSL](https://www.wolfssl.com/) and [nghttp2](https://nghttp2.org/).

The project is public to simplify my own deployments. I've been daily driving it for a while, but at this point this is just learning/WIP code.

There's significant limitations on monitoring (there is none), and a perf bottle neck because its using a thread pool to handle concurrent requests. This code path is a prime candidate for refactoring to the new async `Io` interface.
