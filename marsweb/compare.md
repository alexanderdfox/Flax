# Security & Feature Comparison: Commercial Web Servers vs. Custom Rust Kernel

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

### Key Takeaways

* **Where you win:** Your kernel beats all three commercial servers in **Memory Safety** and **Modern Cryptography**. You completely bypass entire classes of vulnerabilities that historically plague C/C++ servers.
* **Where enterprise wins:** Nginx, Apache, and IIS offer mature **operational flexibility** (like reverse proxying, load balancing, and dynamic modules) and robust out-of-the-box WAF protection.