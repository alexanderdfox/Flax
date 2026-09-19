# Metamorphic Web Kernel

A high-performance, hardened, memory-safe web server written in Rust using **Axum**, **Tokio**, and **rustls**. 

Designed as a low-level network server, it enforces explicit port policies (HTTP 80 / HTTPS 443), automatically drops `root` privileges to `nobody` after socket binding, and includes built-in mitigations against Slowloris attacks and connection exhaustion.

---

## Key Features

- **Memory Safety:** Built in pure Rust to eliminate memory-corruption vulnerabilities (e.g., buffer overflows, use-after-free, dangling pointers).
- **Privilege Dropping:** Binds privileged ports `80` and `443` as `root` (via `sudo`), then immediately strips process privileges down to the unprivileged `nobody` user.
- **DoS & Slowloris Defense:** Employs async task timeouts and a global connection limit (Semaphore capped at 256 active connections).
- **Modern Security Headers:** Injects `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security` (HSTS) onto all HTTP responses.
- **Modern TLS:** Powered by `rustls` for fast, audited, and secure cryptographic handshakes without legacy OpenSSL weaknesses.

---

## Security & Feature Comparison: Commercial Web Servers vs. Custom Rust Kernel

| Feature / Security Dimension | Nginx | Apache HTTP Server | Microsoft IIS | Your Custom Rust Kernel (Hardened) |
| :--- | :--- | :--- | :--- | :--- |
| **Implementation Language** | C (Memory unsafe) | C/C++ (Memory unsafe) | C++ / C (Memory unsafe) | **Rust** (Memory safe by design) |
| **Memory Corruption Risk** | High (Vulnerable to buffer overflows/RCE bugs) | High (Prone to historic parsing/module exploits) | Medium-High (Complex legacy attack surface) | **None** (Eliminated at compile-time) |
| **Privilege Separation** | Master (root) / Worker (unprivileged user) | Root parent / Unprivileged child worker processes | Application Pools running under isolated service accounts | **Bound as Root $\rightarrow$ Immediately drops to `nobody`** |
| **Slowloris / DoS Defenses** | Native client header/body timeouts and request limits | Configurable limits (`LimitRequestBody`, timeouts) | Advanced connection limits and Dynamic IP Restriction | **Manual Tokio timeouts & global connection semaphore (256 cap)** |
| **TLS / Cryptography Engine** | OpenSSL / BoringSSL (Custom OpenSSL hooks) | OpenSSL (Configurable crypto backends) | Windows SChannel (Native OS crypto stack) | **`rustls`** (Modern, audited, memory-safe pure Rust TLS) |
| **WAF & Security Filtering** | ModSecurity, built-in rate-limiting, geo-blocking | ModSecurity, `.htaccess` security rules | URLScan, Request Filtering modules | **None** (Explicit application port-policy only) |
| **Enterprise Features** | Reverse proxy, load balancing, caching, SSL offloading | `.htaccess`, extensive module ecosystem, SSI | ASP.NET integration, GUI management, Windows auth | **Static file serving & Axum routing only** |

---

## Prerequisites

Before compiling and running the kernel, ensure you have the following installed:

* **Rust Toolchain:** (1.75+ recommended) — [Install Rust](https://www.rust-lang.org/tools/install)
* **OpenSSL CLI** or **mkcert:** For generating TLS certificates.
* **Administrator / Root Access:** Required to bind to privileged TCP ports 80 and 443.

---

## Directory Structure Setup

Before launching the server, ensure your project directory contains the static files and certificate paths expected by the binary:

```text
.
├── Cargo.toml
├── cert.pem          <-- TLS Certificate
├── key.pem           <-- TLS Private Key
├── src/
│   └── main.rs
└── static/
    └── index.html    <-- Default landing page

```

Create the `static/` directory and a basic landing page if you haven't already:

```bash
mkdir -p static
echo "<h1>Metamorphic Web Kernel is Online</h1>" > static/index.html

```

---

## Generating SSL/TLS Certificates

The server requires `cert.pem` and `key.pem` in the root directory to handle HTTPS traffic on port 443.

### Option 1: Development Certificate via OpenSSL (Quickest)

Generate a self-signed certificate valid for 365 days:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -subj "/CN=localhost"

```

### Option 2: Trusted Local Certificate via `mkcert` (Recommended for Local Browsing)

If you want your web browser to treat the local certificate as trusted without security warnings:

1. Install `mkcert` (e.g., `brew install mkcert` on macOS or `sudo apt install mkcert` on Linux).
2. Install the local CA and generate certificates:

```bash
mkcert -install
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1

```

---

## Building and Running

### 1. Compile the Binary

Compile an optimized production release build:

```bash
cargo build --release

```

### 2. Run the Server

Because the server binds to privileged system ports (`80` and `443`), it must initially be launched with elevated privileges (`sudo`). The application will immediately drop privileges to `nobody` once the ports are bound.

```bash
sudo cargo run --release

```

Or execute the compiled release binary directly:

```bash
sudo ./target/release/metamorphic_kernel

```

#### Expected Terminal Output

```text
╔════════════════════════════════════════════╗
║    METAMORPHIC WEB KERNEL — ENTERPRISE     ║
║                                            ║
║   HTTP   : TCP/80 (Protected)              ║
║   HTTPS  : TCP/443 (Protected)             ║
║   Other  : REJECTED                        ║
╚════════════════════════════════════════════╝
[+] Bound to TCP/80
[+] Bound to TCP/443
[+] Successfully dropped privileges to user 'nobody' (UID: 65534, GID: 65534)

```

---

## Verification & Testing

Verify that the server is active, serving files, and enforcing security policies:

### Check HTTP (Port 80)

```bash
curl -I http://localhost

```

### Check HTTPS (Port 443)

```bash
curl -kI https://localhost

```

### Inspect Security Headers

Ensure safety headers are attached to responses:

```bash
curl -k -I https://localhost

```

*Look for:*

* `x-frame-options: DENY`
* `x-content-type-options: nosniff`
* `strict-transport-security: max-age=31536000; includeSubDomains`

---

## License

Distributed under the MIT License.