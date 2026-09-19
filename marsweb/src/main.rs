use axum::{
	routing::get,
	Router,
	response::Html,
};
use rustls::{
	pki_types::{CertificateDer, PrivateKeyDer},
	ServerConfig,
};
use std::{
	fs::File,
	io::{self, BufReader},
	net::SocketAddr,
	sync::Arc,
	time::Duration,
};
use tokio::{
	net::TcpListener,
	sync::Semaphore,
	task,
	time::timeout,
};
use tokio_rustls::TlsAcceptor;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tower_service::Service;
use tower_http::{
	services::ServeDir,
	set_header::SetResponseHeaderLayer,
};
use http::{HeaderValue, header};

/// The only network services exposed by this kernel.
#[derive(Debug, Clone, Copy)]
enum AllowedPort {
	Http = 80,
	Https = 443,
}

impl AllowedPort {
	fn from_port(port: u16) -> Option<Self> {
		match port {
			80 => Some(Self::Http),
			443 => Some(Self::Https),
			_ => None,
		}
	}
}

/// Metamorphic traffic policy.
#[derive(Debug)]
enum TrafficState {
	Allowed(AllowedPort),
	Rejected(u16),
}

fn metamorphic_policy(addr: SocketAddr) -> TrafficState {
	match AllowedPort::from_port(addr.port()) {
		Some(port) => TrafficState::Allowed(port),
		None => TrafficState::Rejected(addr.port()),
	}
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
	let file = File::open(path)?;
	let mut reader = BufReader::new(file);

	rustls_pemfile::certs(&mut reader)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
	let file = File::open(path)?;
	let mut reader = BufReader::new(file);

	let key = rustls_pemfile::private_key(&mut reader)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

	key.ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"No private key found",
		)
	})
}

fn tls_config() -> io::Result<Arc<ServerConfig>> {
	let certs = load_certs("cert.pem")?;
	let key = load_private_key("key.pem")?;

	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

	Ok(Arc::new(config))
}

/// Drop root privileges securely to an unprivileged user (e.g., "nobody")
fn drop_privileges(username: &str) -> io::Result<()> {
	unsafe {
		// Only attempt if running as root
		if libc::getuid() != 0 {
			println!("[*] Not running as root; skipping privilege drop.");
			return Ok(());
		}

		let c_username = std::ffi::CString::new(username)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

		let pwd = libc::getpwnam(c_username.as_ptr());
		if pwd.is_null() {
			return Err(io::Error::new(
				io::ErrorKind::NotFound,
				format!("User '{}' not found on system", username),
			));
		}

		let uid = (*pwd).pw_uid;
		let gid = (*pwd).pw_gid;

		// 1. Clear supplementary groups
		if libc::setgroups(0, std::ptr::null()) != 0 {
			return Err(io::Error::last_os_error());
		}

		// 2. Set GID first (must be done while still root)
		if libc::setgid(gid) != 0 {
			return Err(io::Error::last_os_error());
		}

		// 3. Set UID last
		if libc::setuid(uid) != 0 {
			return Err(io::Error::last_os_error());
		}

		// 4. Paranoia check: verify we can no longer regain root
		if libc::setuid(0) != -1 {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"CRITICAL: Successfully regained root privileges after dropping!",
			));
		}

		println!("[+] Successfully dropped privileges to user '{}' (UID: {}, GID: {})", username, uid, gid);
	}
	Ok(())
}

#[tokio::main]
async fn main() {
	println!("╔════════════════════════════════════════════╗");
	println!("║    METAMORPHIC WEB KERNEL — ENTERPRISE     ║");
	println!("║                                            ║");
	println!("║   HTTP   : TCP/80 (Protected)              ║");
	println!("║   HTTPS  : TCP/443 (Protected)             ║");
	println!("║   Other  : REJECTED                        ║");
	println!("╚════════════════════════════════════════════╝");

	/*
	 * ------------------------------------------------------------
	 * STEP 1: Bind privileged ports *while* we still have root access
	 * ------------------------------------------------------------
	 */
	let http_listener = TcpListener::bind("0.0.0.0:80").await.expect("Failed to bind port 80");
	println!("[+] Bound to TCP/80");

	let tls = tls_config().expect("Failed to load TLS configuration");
	let https_listener = TcpListener::bind("0.0.0.0:443").await.expect("Failed to bind port 443");
	println!("[+] Bound to TCP/443");

	/*
	 * ------------------------------------------------------------
	 * STEP 2: Drop root privileges immediately after binding
	 * ------------------------------------------------------------
	 */
	drop_privileges("nobody").expect("Failed to drop root privileges!");

	// Concurrency limiter: Max 256 concurrent active connections globally
	let connection_limit = Arc::new(Semaphore::new(256));

	// Define security headers middleware layers
	let app = Router::new()
		.route("/", get(|| async {
			let html_content = tokio::fs::read_to_string("static/index.html")
				.await
				.unwrap_or_else(|_| "<h1>404 Not Found</h1>".into());
			Html(html_content)
		}))
		.nest_service("/static", ServeDir::new("static"))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::X_FRAME_OPTIONS,
			HeaderValue::from_static("DENY"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::X_CONTENT_TYPE_OPTIONS,
			HeaderValue::from_static("nosniff"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::STRICT_TRANSPORT_SECURITY,
			HeaderValue::from_static("max-age=31536000; includeSubDomains"),
		));

	/*
	 * ------------------------------------------------------------
	 * HTTP Loop (TCP 80)
	 * ------------------------------------------------------------
	 */
	let http_app = app.clone();
	let http_limiter = connection_limit.clone();

	task::spawn(async move {
		loop {
			let (stream, remote_addr) = match http_listener.accept().await {
				Ok(v) => v,
				Err(e) => {
					eprintln!("[HTTP] accept error: {e}");
					continue;
				}
			};

			let permit = match http_limiter.clone().acquire_owned().await {
				Ok(p) => p,
				Err(_) => break,
			};

			match metamorphic_policy(SocketAddr::new(remote_addr.ip(), 80)) {
				TrafficState::Allowed(AllowedPort::Http) => {
					println!("[ALLOW] TCP/80 ← {}", remote_addr);
					let service = http_app.clone();

					task::spawn(async move {
						let _permit = permit;
						let io = TokioIo::new(stream);
						let hyper_service = hyper::service::service_fn(move |req| {
							service.clone().call(req)
						});

						let res = timeout(
							Duration::from_secs(15),
							auto::Builder::new(TokioExecutor::new())
								.serve_connection(io, hyper_service)
						).await;

						if res.is_err() {
							eprintln!("[HTTP] timeout/Slowloris drop: {}", remote_addr);
						}
					});
				}
				TrafficState::Rejected(port) => {
					println!("[DROP] TCP/{} ← {}", port, remote_addr);
				}
				_ => unreachable!(),
			}
		}
	});

	/*
	 * ------------------------------------------------------------
	 * HTTPS Loop (TCP 443)
	 * ------------------------------------------------------------
	 */
	let https_limiter = connection_limit.clone();

	loop {
		let (stream, remote_addr) = match https_listener.accept().await {
			Ok(v) => v,
			Err(e) => {
				eprintln!("[HTTPS] accept error: {e}");
				continue;
			}
		};

		let permit = match https_limiter.clone().acquire_owned().await {
			Ok(p) => p,
			Err(_) => break,
		};

		match metamorphic_policy(SocketAddr::new(remote_addr.ip(), 443)) {
			TrafficState::Allowed(AllowedPort::Https) => {
				println!("[ALLOW] TCP/443 ← {}", remote_addr);

				let acceptor = TlsAcceptor::from(tls.clone());
				let service = app.clone();

				task::spawn(async move {
					let _permit = permit;
					match timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
						Ok(Ok(tls_stream)) => {
							let io = TokioIo::new(tls_stream);
							let hyper_service = hyper::service::service_fn(move |req| {
								service.clone().call(req)
							});

							let _ = timeout(
								Duration::from_secs(20),
								auto::Builder::new(TokioExecutor::new())
									.serve_connection(io, hyper_service)
							).await;
						}
						_ => eprintln!("[TLS DROP] {}", remote_addr),
					}
				});
			}
			TrafficState::Rejected(port) => {
				println!("[DROP] TCP/{} ← {}", port, remote_addr);
			}
			_ => unreachable!(),
		}
	}
}