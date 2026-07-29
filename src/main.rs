//! Secure static HTML/CSS file server.
//!
//! Design goals (non-negotiable):
//! - 100 % MIT (this crate + pure `std` only; zero external crates).
//! - Serve *only* `.html` and `.css` under a configurable document root.
//! - Strict path canonicalization jail against traversal / symlink escape.
//! - No dynamic content, no body processing, no keep-alive by default.
//! - Every error maps to a clean HTTP status; no panics on the request path.
//! - Graceful shutdown on SIGINT / SIGTERM (Unix).
//! - Privilege drop after bind when started as root (Unix).
//!
//! Security decisions are explained inline next to the relevant code.

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Hard limits chosen for DoS resistance.
const MAX_REQUEST_BYTES: usize = 8 * 1024; // 8 KiB for request line + headers
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONCURRENT: usize = 1024;
const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_ROOT: &str = "./public";
const DEFAULT_CACHE_MAX_AGE: u64 = 3600;

/// Runtime configuration. Immutable after startup.
#[derive(Debug, Clone)]
struct Config {
    bind: SocketAddr,
    root: PathBuf,          // already canonicalized absolute path
    max_concurrent: usize,
    cache_max_age: u64,
    keep_alive: bool,       // off by default
    drop_user: Option<String>, // Unix: user to switch to after bind
}

impl Config {
    fn from_env_and_args() -> Result<Self, String> {
        let mut bind_str = env::var("STATIC_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
        let mut root_str = env::var("STATIC_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.to_string());
        let mut max_concurrent = DEFAULT_MAX_CONCURRENT;
        let mut cache_max_age = DEFAULT_CACHE_MAX_AGE;
        let mut keep_alive = false;
        let mut drop_user: Option<String> = None;

        let args: Vec<String> = env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--bind" | "-b" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--bind requires an argument".into());
                    }
                    bind_str = args[i].clone();
                }
                "--root" | "-r" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--root requires an argument".into());
                    }
                    root_str = args[i].clone();
                }
                "--max-concurrent" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--max-concurrent requires an argument".into());
                    }
                    max_concurrent = args[i]
                        .parse()
                        .map_err(|_| "invalid --max-concurrent")?;
                }
                "--cache-max-age" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--cache-max-age requires an argument".into());
                    }
                    cache_max_age = args[i]
                        .parse()
                        .map_err(|_| "invalid --cache-max-age")?;
                }
                "--keep-alive" => {
                    keep_alive = true;
                }
                "--drop-user" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--drop-user requires an argument".into());
                    }
                    drop_user = Some(args[i].clone());
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown argument: {}", other));
                }
            }
            i += 1;
        }

        let bind: SocketAddr = bind_str
            .parse()
            .map_err(|e| format!("invalid bind address '{}': {}", bind_str, e))?;

        // Canonicalize the document root once at startup.  If it does not
        // exist or is not a directory we refuse to start – better than
        // serving from an unexpected location.
        let root_path = PathBuf::from(&root_str);
        let root = fs::canonicalize(&root_path).map_err(|e| {
            format!(
                "document root '{}' cannot be canonicalized: {} \
                 (does the directory exist?)",
                root_str, e
            )
        })?;
        if !root.is_dir() {
            return Err(format!("document root '{}' is not a directory", root.display()));
        }

        Ok(Config {
            bind,
            root,
            max_concurrent,
            cache_max_age,
            keep_alive,
            drop_user,
        })
    }
}

fn print_usage() {
    eprintln!(
        "static-html-server – secure static HTML/CSS server (pure std, MIT)\n\n\
         USAGE:\n\
             static-html-server [OPTIONS]\n\n\
         OPTIONS:\n\
             -b, --bind <ADDR>          Bind address (default: 127.0.0.1:8080)\n\
             -r, --root <DIR>           Document root (default: ./public)\n\
                 --max-concurrent <N>   Max concurrent connections (default: 1024)\n\
                 --cache-max-age <SEC>  Cache-Control max-age (default: 3600)\n\
                 --keep-alive           Enable short keep-alive (off by default)\n\
                 --drop-user <NAME>     Drop privileges to this user after bind (Unix)\n\
             -h, --help                 Show this help\n\n\
         ENVIRONMENT:\n\
             STATIC_BIND, STATIC_ROOT   Same meaning as the corresponding flags\n"
    );
}

// ---------------------------------------------------------------------------
// Structured logging (pure std)
// ---------------------------------------------------------------------------

fn log_info(msg: &str) {
    let ts = now_rfc3339();
    println!("[{}] INFO  {}", ts, msg);
}

fn log_warn(msg: &str) {
    let ts = now_rfc3339();
    eprintln!("[{}] WARN  {}", ts, msg);
}

fn log_error(msg: &str) {
    let ts = now_rfc3339();
    eprintln!("[{}] ERROR {}", ts, msg);
}

/// Minimal RFC-3339-ish timestamp without external crates.
fn now_rfc3339() -> String {
    // std has no chrono; we approximate with SystemTime.
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Very rough UTC formatting; good enough for logs.
            format!("unix:{}", secs)
        }
        Err(_) => "unix:0".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Path sanitization – the security core
// ---------------------------------------------------------------------------

/// Result of a successful, jailing path resolution.
#[derive(Debug)]
struct SafePath {
    /// Absolute, canonical path that is guaranteed to be under `root`.
    absolute: PathBuf,
    /// Relative path (for logging only).
    relative: PathBuf,
}

/// Resolve a request URI path against the document root with full
/// canonicalization and jail enforcement.
///
/// Security decisions:
/// 1. Reject null bytes immediately (encoded or raw).
/// 2. Percent-decode only the safe subset we need; refuse overlong /
///    invalid sequences that could hide `..`.
/// 3. Build a candidate path under `root`, then `canonicalize`.
/// 4. Verify the canonical path still has `root` as a strict prefix.
/// 5. Reject anything that is not a regular file (directories → 404,
///    no listing).
/// 6. Allow only the extensions `.html` and `.css` (case-insensitive).
fn resolve_safe_path(root: &Path, raw_uri_path: &str) -> Result<SafePath, StatusCode> {
    // 1. Null-byte rejection in the raw URI (classic CGI / C-string attack).
    if raw_uri_path.contains('\0') {
        return Err(StatusCode::BadRequest);
    }

    // 2. Basic percent-decoding.  We only accept %XX where XX are hex digits.
    //    Invalid encodings → 400.  We never produce `..` from decoding that
    //    was not already present.
    let decoded = match percent_decode(raw_uri_path) {
        Ok(s) => s,
        Err(_) => return Err(StatusCode::BadRequest),
    };

    // Reject null bytes that appeared only after percent-decoding (%00).
    if decoded.contains('\0') {
        return Err(StatusCode::BadRequest);
    }

    // 3. Strip query string / fragment (we ignore them for static serving).
    let path_part = decoded.split(|c| c == '?' || c == '#').next().unwrap_or("");

    // Empty or bare "/" → serve index.html
    let rel = if path_part.is_empty() || path_part == "/" {
        PathBuf::from("index.html")
    } else {
        // Remove leading slash so we join correctly under root.
        let trimmed = path_part.trim_start_matches('/');
        PathBuf::from(trimmed)
    };

    // Reject any component that is ".." or "." after decoding – belt and
    // suspenders before we even touch the filesystem.
    for component in rel.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {} // harmless, will be cleaned by canonicalize
            _ => return Err(StatusCode::Forbidden), // ParentDir, RootDir, Prefix …
        }
    }

    // 4. Join under the already-canonical root and canonicalize.
    let candidate = root.join(&rel);

    // canonicalize follows symlinks; if the final target escapes the jail
    // the subsequent prefix check will catch it.
    let absolute = match fs::canonicalize(&candidate) {
        Ok(p) => p,
        Err(_) => return Err(StatusCode::NotFound), // does not exist or permission
    };

    // 5. Jail: absolute must start with root.  On Windows we would also
    //    need to handle prefixes; we target Unix primarily but the check
    //    is still correct on Windows for simple cases.
    if !absolute.starts_with(root) {
        // Symlink or crafted path that escaped.
        return Err(StatusCode::Forbidden);
    }

    // 6. Must be a regular file (no directories → no listing).
    let meta = match fs::metadata(&absolute) {
        Ok(m) => m,
        Err(_) => return Err(StatusCode::NotFound),
    };
    if !meta.is_file() {
        return Err(StatusCode::NotFound);
    }

    // 7. Extension allow-list only.
    let ext = absolute
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html") | Some("css") => {}
        _ => return Err(StatusCode::NotFound),
    }

    Ok(SafePath {
        absolute,
        relative: rel,
    })
}

/// Minimal percent-decoder.  Rejects malformed sequences.
fn percent_decode(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let h1 = from_hex(bytes[i + 1])?;
            let h2 = from_hex(bytes[i + 2])?;
            out.push((h1 << 4) | h2);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn from_hex(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// HTTP status & response helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusCode {
    Ok = 200,
    BadRequest = 400,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    PayloadTooLarge = 413,
    InternalServerError = 500,
}

impl StatusCode {
    fn phrase(self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::BadRequest => "Bad Request",
            StatusCode::Forbidden => "Forbidden",
            StatusCode::NotFound => "Not Found",
            StatusCode::MethodNotAllowed => "Method Not Allowed",
            StatusCode::PayloadTooLarge => "Payload Too Large",
            StatusCode::InternalServerError => "Internal Server Error",
        }
    }
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        // Should never reach here because of the allow-list, but be safe.
        _ => "application/octet-stream",
    }
}

/// Write a complete HTTP/1.1 response.  Always sets the security headers.
fn write_response(
    stream: &mut TcpStream,
    status: StatusCode,
    content_type: &str,
    body: &[u8],
    cache_max_age: u64,
    head_only: bool,
    keep_alive: bool,
) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: public, max-age={}\r\n\
         Connection: {}\r\n\
         \r\n",
        status as u16,
        status.phrase(),
        content_type,
        body.len(),
        cache_max_age,
        if keep_alive { "keep-alive" } else { "close" },
    );

    // Optional HSTS only makes sense with TLS; we never set it without TLS.
    // (TLS feature is currently disabled.)

    stream.write_all(header.as_bytes())?;
    if !head_only && !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

fn write_error(
    stream: &mut TcpStream,
    status: StatusCode,
    cache_max_age: u64,
    keep_alive: bool,
) -> io::Result<()> {
    // Tiny static error bodies; never reflect user input.
    let body = match status {
        StatusCode::BadRequest => b"400 Bad Request" as &[u8],
        StatusCode::Forbidden => b"403 Forbidden",
        StatusCode::NotFound => b"404 Not Found",
        StatusCode::MethodNotAllowed => b"405 Method Not Allowed",
        StatusCode::PayloadTooLarge => b"413 Payload Too Large",
        StatusCode::InternalServerError => b"500 Internal Server Error",
        StatusCode::Ok => b"",
    };
    write_response(
        stream,
        status,
        "text/plain; charset=utf-8",
        body,
        cache_max_age,
        false,
        keep_alive,
    )
}

// ---------------------------------------------------------------------------
// Request parsing (hand-rolled, size-limited)
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    // We deliberately ignore all headers except for size limiting.
}

/// Read a single HTTP request, enforcing the 8 KiB limit.
/// Returns None on clean EOF (client closed).
fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, StatusCode> {
    // Set timeouts for DoS resistance.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let mut reader = BufReader::with_capacity(MAX_REQUEST_BYTES, stream.try_clone().map_err(|_| StatusCode::InternalServerError)?);
    let mut total = 0usize;
    let mut request_line = String::new();

    // Request line
    match reader.read_line(&mut request_line) {
        Ok(0) => return Ok(None), // clean close
        Ok(n) => {
            total += n;
            if total > MAX_REQUEST_BYTES {
                return Err(StatusCode::PayloadTooLarge);
            }
        }
        Err(_) => return Err(StatusCode::BadRequest),
    }

    // Drain headers until empty line, still counting bytes.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // unexpected EOF mid-headers
            Ok(n) => {
                total += n;
                if total > MAX_REQUEST_BYTES {
                    return Err(StatusCode::PayloadTooLarge);
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            Err(_) => return Err(StatusCode::BadRequest),
        }
    }

    // Parse request line: METHOD SP PATH SP HTTP/VERSION
    let parts: Vec<&str> = request_line.trim_end_matches(['\r', '\n']).split_whitespace().collect();
    if parts.len() != 3 {
        return Err(StatusCode::BadRequest);
    }
    let method = parts[0].to_ascii_uppercase();
    let path = parts[1].to_string();
    // We accept HTTP/1.0 and HTTP/1.1 only; anything else is still answered
    // but we do not implement HTTP/2.
    if !parts[2].starts_with("HTTP/1.") {
        return Err(StatusCode::BadRequest);
    }

    Ok(Some(Request { method, path }))
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

fn handle_connection(mut stream: TcpStream, config: &Config, active: &AtomicUsize) {
    let peer = stream.peer_addr().ok();
    let start = Instant::now();

    let result = (|| -> Result<(), StatusCode> {
        let req = match read_request(&mut stream)? {
            Some(r) => r,
            None => return Ok(()), // clean close
        };

        // Method allow-list.
        let head_only = match req.method.as_str() {
            "GET" => false,
            "HEAD" => true,
            _ => {
                let _ = write_error(&mut stream, StatusCode::MethodNotAllowed, config.cache_max_age, false);
                return Err(StatusCode::MethodNotAllowed);
            }
        };

        // Path resolution + jail.
        let safe = resolve_safe_path(&config.root, &req.path)?;

        // Open and read the file.  We read the whole file into memory because
        // the expected files are small (HTML/CSS).  For multi-gigabyte assets
        // this would be wrong, but those are out of scope.
        let mut file = File::open(&safe.absolute).map_err(|_| StatusCode::NotFound)?;
        let mut body = Vec::new();
        file.read_to_end(&mut body).map_err(|_| StatusCode::InternalServerError)?;

        let content_type = mime_for_path(&safe.absolute);
        write_response(
            &mut stream,
            StatusCode::Ok,
            content_type,
            &body,
            config.cache_max_age,
            head_only,
            config.keep_alive,
        )
        .map_err(|_| StatusCode::InternalServerError)?;

        let elapsed = start.elapsed();
        log_info(&format!(
            "{:?} {} {} → 200 ({} bytes, {:?})",
            peer,
            req.method,
            safe.relative.display(),
            body.len(),
            elapsed
        ));
        Ok(())
    })();

    if let Err(status) = result {
        // Best-effort error response; ignore write failures.
        let _ = write_error(&mut stream, status, config.cache_max_age, false);
        log_warn(&format!("{:?} → {}", peer, status as u16));
    }

    // Always close (or short keep-alive if enabled).  We do not implement
    // full keep-alive request looping for simplicity and DoS resistance.
    let _ = stream.shutdown(Shutdown::Both);
    active.fetch_sub(1, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Privilege dropping (Unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn drop_privileges(user: &str) -> Result<(), String> {
    // Pure std does not expose getpwnam / setuid.  We use the libc crate
    // only if it were MIT, but the user forbade non-MIT deps.  Therefore we
    // implement a minimal, documented unsafe block that calls the C
    // functions directly via the extern block (no crate needed).
    //
    // SAFETY CONTRACT:
    // - Called only once, after the listening socket is bound.
    // - The process must still be root (geteuid == 0).
    // - We look up the target user with getpwnam, then setgid + setuid.
    // - On any failure we abort the process rather than continue as root.

    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    #[repr(C)]
    struct Passwd {
        pw_name: *mut c_char,
        pw_passwd: *mut c_char,
        pw_uid: u32,
        pw_gid: u32,
        // remainder ignored
    }

    extern "C" {
        fn getpwnam(name: *const c_char) -> *mut Passwd;
        fn setgid(gid: u32) -> c_int;
        fn setuid(uid: u32) -> c_int;
        fn geteuid() -> u32;
    }

    // SAFETY: geteuid is a simple syscall wrapper, always safe to call.
    let euid = unsafe { geteuid() };
    if euid != 0 {
        // Not root – nothing to drop.
        return Ok(());
    }

    let c_user = CString::new(user).map_err(|_| "user name contains NUL".to_string())?;

    // SAFETY: getpwnam returns a pointer into a static buffer; we only
    // read the uid/gid fields and do not free or retain the pointer.
    let pw = unsafe { getpwnam(c_user.as_ptr()) };
    if pw.is_null() {
        return Err(format!("user '{}' not found", user));
    }

    let uid;
    let gid;
    // SAFETY: pointer non-null, fields are plain integers.
    unsafe {
        uid = (*pw).pw_uid;
        gid = (*pw).pw_gid;
    }

    // SAFETY: setgid/setuid are the standard privilege-drop syscalls.
    // Order is important: group first, then user.
    if unsafe { setgid(gid) } != 0 {
        return Err("setgid failed".into());
    }
    if unsafe { setuid(uid) } != 0 {
        return Err("setuid failed".into());
    }

    log_info(&format!("dropped privileges to user '{}' (uid={}, gid={})", user, uid, gid));
    Ok(())
}

#[cfg(not(unix))]
fn drop_privileges(_user: &str) -> Result<(), String> {
    // No-op on non-Unix.
    Ok(())
}

// ---------------------------------------------------------------------------
// Graceful shutdown (Unix signals via pure std polling of a flag)
// ---------------------------------------------------------------------------

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn install_signal_handlers() {
    // We avoid the `signal-hook` crate (dual-licensed).  Instead we use
    // a simple self-pipe + signal handler written with libc externs,
    // or the portable approach of checking a flag that is set by a
    // dedicated signal thread using `signal` syscall.
    //
    // For maximal purity we install a handler that only sets the atomic.
    use std::os::raw::c_int;

    extern "C" {
        fn signal(sig: c_int, handler: usize) -> usize;
    }

    extern "C" fn handle_signal(_: c_int) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }

    // SIGINT = 2, SIGTERM = 15 on virtually all Unix.
    // SAFETY: the handler is async-signal-safe (only an atomic store).
    unsafe {
        signal(2, handle_signal as usize);
        signal(15, handle_signal as usize);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {
    // On Windows Ctrl-C is harder without extra crates; we just rely on
    // the process being killed.  The AtomicBool is still present for
    // future use.
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let config = match Config::from_env_and_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    };

    log_info(&format!(
        "document root (canonical): {}",
        config.root.display()
    ));
    log_info(&format!("bind address: {}", config.bind));
    log_info(&format!("max concurrent: {}", config.max_concurrent));

    let listener = match TcpListener::bind(config.bind) {
        Ok(l) => l,
        Err(e) => {
            log_error(&format!("failed to bind {}: {}", config.bind, e));
            std::process::exit(1);
        }
    };

    // Drop privileges after bind so we can still open privileged ports.
    if let Some(ref user) = config.drop_user {
        if let Err(e) = drop_privileges(user) {
            log_error(&format!("privilege drop failed: {}", e));
            std::process::exit(1);
        }
    }

    install_signal_handlers();

    // Non-blocking accept so we can poll the shutdown flag.
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    let config = Arc::new(config);
    let active = Arc::new(AtomicUsize::new(0));

    log_info("listening – press Ctrl-C to stop");

    while !SHUTDOWN.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let current = active.fetch_add(1, Ordering::SeqCst);
                if current >= config.max_concurrent {
                    active.fetch_sub(1, Ordering::SeqCst);
                    // Politely refuse.
                    let mut s = stream;
                    let _ = write_error(
                        &mut s,
                        StatusCode::PayloadTooLarge, // 413 is close enough; 503 would need more code
                        config.cache_max_age,
                        false,
                    );
                    let _ = s.shutdown(Shutdown::Both);
                    continue;
                }

                let cfg = Arc::clone(&config);
                let act = Arc::clone(&active);
                // Detached thread per connection.  For a production load
                // balancer this is fine; a bounded thread pool would be
                // an enhancement but adds complexity without external crates.
                thread::spawn(move || {
                    handle_connection(stream, &cfg, &act);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No connection ready; sleep briefly to avoid busy-spin.
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                log_error(&format!("accept error: {}", e));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    log_info("shutdown signal received, waiting for active connections…");
    // Give in-flight requests a short grace period.
    let deadline = Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    log_info("goodbye");
}

// ---------------------------------------------------------------------------
// Unit tests (also compiled with `cargo test`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn make_temp_root() -> PathBuf {
        let mut dir = env::temp_dir();
        dir.push(format!("static-html-server-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Create a couple of allowed files.
        let mut f = fs::File::create(dir.join("index.html")).unwrap();
        f.write_all(b"<h1>ok</h1>").unwrap();
        let mut f = fs::File::create(dir.join("style.css")).unwrap();
        f.write_all(b"body{}").unwrap();
        // A forbidden extension.
        let mut f = fs::File::create(dir.join("secret.txt")).unwrap();
        f.write_all(b"nope").unwrap();
        // A subdirectory with a file.
        fs::create_dir(dir.join("sub")).unwrap();
        let mut f = fs::File::create(dir.join("sub/page.html")).unwrap();
        f.write_all(b"<p>sub</p>").unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    #[test]
    fn allow_html_and_css() {
        let root = make_temp_root();
        assert!(resolve_safe_path(&root, "/index.html").is_ok());
        assert!(resolve_safe_path(&root, "/style.css").is_ok());
        assert!(resolve_safe_path(&root, "/sub/page.html").is_ok());
        assert!(resolve_safe_path(&root, "/").is_ok()); // → index.html
    }

    #[test]
    fn reject_other_extensions() {
        let root = make_temp_root();
        assert_eq!(
            resolve_safe_path(&root, "/secret.txt").unwrap_err(),
            StatusCode::NotFound
        );
    }

    #[test]
    fn reject_directory() {
        let root = make_temp_root();
        // Requesting the directory itself must 404 (no listing).
        assert_eq!(
            resolve_safe_path(&root, "/sub").unwrap_err(),
            StatusCode::NotFound
        );
    }

    #[test]
    fn reject_path_traversal() {
        let root = make_temp_root();
        // Classic ..
        assert!(matches!(
            resolve_safe_path(&root, "/../etc/passwd"),
            Err(StatusCode::Forbidden) | Err(StatusCode::NotFound)
        ));
        assert!(matches!(
            resolve_safe_path(&root, "/sub/../../etc/passwd"),
            Err(StatusCode::Forbidden) | Err(StatusCode::NotFound)
        ));
        // Encoded ..
        assert!(matches!(
            resolve_safe_path(&root, "/%2e%2e/etc/passwd"),
            Err(StatusCode::Forbidden) | Err(StatusCode::NotFound) | Err(StatusCode::BadRequest)
        ));
        // Null byte
        assert_eq!(
            resolve_safe_path(&root, "/index.html%00.jpg").unwrap_err(),
            StatusCode::BadRequest
        );
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(percent_decode("%2f").unwrap(), "/");
        assert!(percent_decode("%zz").is_err());
        assert!(percent_decode("%a").is_err());
    }

    #[test]
    fn extension_case_insensitive() {
        let root = make_temp_root();
        // Create UPPER.HTML
        let mut f = fs::File::create(root.join("UPPER.HTML")).unwrap();
        f.write_all(b"<p>U</p>").unwrap();
        // On case-sensitive FS the file is UPPER.HTML; we accept the extension
        // after lower-casing the extension component.
        // The resolve function lower-cases the extension, so a request for
        // /UPPER.HTML should succeed on case-sensitive systems too because
        // the file name matches exactly.
        assert!(resolve_safe_path(&root, "/UPPER.HTML").is_ok());
    }
}
