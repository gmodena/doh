# DoH

A [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484) DNS-over-HTTPS (DoH) server implementation in Zig using [WolfSSL](https://www.wolfssl.com/) and [nghttp2](https://nghttp2.org/).

## Dependencies

- Zig 0.15+
- wolfssl
- nghttp2

## Run

Generate SSL certificates (or provide your own):

```
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

Create a `config.json` (example):

```json
{
  "server": {
    "listen_address": "127.0.0.1",
    "listen_port": 8443
  },
  "dns": {
    "server": "1.1.1.1",
    "port": 53
  },
  "ssl": {
    "cert_file": "./certs/server.crt",
    "key_file": "./certs/server.key"
  }
}
```

Start the server:

```
zig build run
```

Point your browser to `https://<listen_address>:<listen_port>/dns-query`.

## Test

```
zig build test
```
