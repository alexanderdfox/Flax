# Flax

A **secure, minimal, production-oriented** static file server written in pure Rust (`std` only).  
It does one thing: serve `.html` and `.css` files safely.

**License: MIT (this crate and every line of code; zero external crates).**

## Features

- Serves **only** files with extensions `.html` or `.css` (case-insensitive). Everything else → 404.
- Configurable document root (CLI or `STATIC_ROOT` env, default `./public`).
- Configurable bind address (CLI or `STATIC_BIND` env, default `127.0.0.1:8080`).
- Strict path-traversal protection via `std::fs::canonicalize` + prefix jail.
- GET and HEAD only; any other method → 405.
- Security headers on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: public, max-age=…` (configurable)
- Request size limit: 8 KiB for the request line + headers.
- Connection read/write timeouts: 10 s.
- Configurable maximum concurrent connections (default 1024).
- No keep-alive by default (optional short keep-alive).
- Graceful shutdown on SIGINT / SIGTERM (Unix).
- Optional privilege dropping after bind (`--drop-user`, Unix only).
- Zero panics on the request path; every error becomes a proper HTTP status.
- Directory listing completely disabled (requesting a directory → 404).
- Clippy-clean with `-D warnings` (on stable Rust).
- No `unsafe` except the minimal, documented blocks required for Unix privilege drop and signal handling.

## Build & Run

```bash
# Requires a recent stable Rust (1.70+ recommended)
cargo build --release

# Run with defaults (serves ./public on 127.0.0.1:8080)
./target/release/static-html-server

# Or during development
cargo run

# Custom root and bind
cargo run -- --root /var/www/static --bind 0.0.0.0:8080

# Drop privileges (must start as root)
sudo ./target/release/static-html-server --bind 0.0.0.0:80 --drop-user www-data
```

Environment variables:

| Variable       | Equivalent flag   | Default          |
|----------------|-------------------|------------------|
| `STATIC_ROOT`  | `--root` / `-r`   | `./public`       |
| `STATIC_BIND`  | `--bind` / `-b`   | `127.0.0.1:8080` |

## Security Model

### Path traversal prevention

1. The document root is **canonicalized once at startup**. If it does not exist or is not a directory the process refuses to start.
2. Every request URI is percent-decoded (malformed sequences → 400).
3. Null bytes are rejected immediately.
4. Path components containing `..` (or other non-`Normal` components after decoding) are rejected.
5. The candidate path is joined under the root and then passed through `std::fs::canonicalize` (which resolves symlinks).
6. The resulting absolute path is checked with `starts_with(root)`. Any escape (symlink attack, `..`, etc.) → 403.
7. Only regular files are accepted; directories always return 404 (no listing).
8. The final extension is lower-cased and compared against the hard-coded allow-list `{html, css}`.

Because the jail check uses the *real* filesystem path after symlink resolution, classic attacks such as `/../../etc/passwd`, encoded variants, and symlink escapes are blocked.

### MIME types

Only two MIME types are ever emitted:

- `text/html; charset=utf-8`
- `text/css; charset=utf-8`

No content sniffing is performed. The `X-Content-Type-Options: nosniff` header is always present.

### Request limits & DoS resistance

- Request line + headers are limited to 8 KiB; excess → 413.
- No request body is ever read (GET/HEAD).
- Read and write timeouts of 10 seconds are set on every socket.
- Concurrent connections are capped (default 1024); excess connections are closed immediately.
- Keep-alive is off by default, eliminating idle-connection resource exhaustion.

### Privilege dropping (Unix)

After the listening socket is bound, if `--drop-user NAME` is supplied and the process is running as root, the server calls `getpwnam` → `setgid` → `setuid` (documented `unsafe` blocks). Failure aborts the process rather than continuing as root.

### TLS

TLS support is intentionally omitted. Every widely-used pure-Rust TLS crate is dual-licensed (Apache-2.0 OR MIT) or pulls non-MIT transitive dependencies, which violates the project’s strict “100 % MIT, no dual-licensed deps” rule. A future pure-MIT TLS backend can be added behind a feature flag without changing the rest of the design.

## Performance notes

Under typical concurrent load (wrk / hey) on a modern laptop the pure-std threaded model comfortably sustains several thousand requests per second for small HTML/CSS files. Because each connection is a short-lived OS thread and keep-alive is off by default, latency stays low and memory usage is predictable. For extreme load a reverse proxy (or a future bounded thread-pool) is recommended; the server itself is deliberately minimal.

## Tests

```bash
cargo test
```

Unit tests cover:

- Allow-list of `.html` / `.css`
- Rejection of other extensions
- Rejection of directories
- Path-traversal variants (`..`, encoded, null bytes)
- Percent-decoding edge cases

## License

MIT. See the `LICENSE` file.

This project contains **zero external crates**. The entire dependency tree is the Rust standard library, which is dual-licensed MIT/Apache-2.0; we use it under the MIT terms. All application code is original and released under the MIT license.
