// browser_broker_http.inc.rs
// Stateless Loopback HTTP API Listener for Browser Integration (ADR-0056)

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::Weak;

pub const HTTP_PORT_RANGE_START: u16 = 42800;
pub const HTTP_PORT_RANGE_END: u16 = 42850;
const HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;
const HTTP_MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HTTP_CLIENTS: usize = 32;

pub fn is_valid_browser_origin(origin: &str) -> bool {
    let trimmed = origin.trim();
    if let Some(id) = trimmed
        .strip_prefix("chrome-extension://")
        .and_then(|v| v.strip_suffix('/').or(Some(v)))
    {
        return id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b));
    }
    if trimmed == "vaultmesh@atlantis-mk.github.io" {
        return true;
    }
    if let Some(dev_id) = option_env!("VAULTMESH_FIREFOX_EXTENSION_ID") {
        if trimmed == dev_id {
            return true;
        }
    }
    false
}

pub struct BrowserBrokerHttpListener {
    port: u16,
    stopping: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    active_deferred: Arc<AtomicUsize>,
    broker: Weak<Mutex<BrowserBrokerCore>>,
}

impl BrowserBrokerHttpListener {
    pub fn start(broker: Arc<Mutex<BrowserBrokerCore>>) -> io::Result<Self> {
        if let Ok(override_port) = std::env::var("VAULTMESH_BROWSER_HTTP_PORT") {
            if let Ok(port) = override_port.trim().parse::<u16>() {
                return Self::start_with_port(broker, port);
            }
        }
        for port in HTTP_PORT_RANGE_START..=HTTP_PORT_RANGE_END {
            match Self::start_with_port(Arc::clone(&broker), port) {
                Ok(listener) => return Ok(listener),
                Err(err) if err.kind() == io::ErrorKind::AddrInUse => continue,
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "无法在端口范围 {HTTP_PORT_RANGE_START}..={HTTP_PORT_RANGE_END} 绑定本地回环 API 服务"
            ),
        ))
    }

    pub fn start_with_port(
        broker: Arc<Mutex<BrowserBrokerCore>>,
        requested_port: u16,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", requested_port))?;
        let bound_port = listener.local_addr()?.port();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let active_deferred = Arc::new(AtomicUsize::new(0));
        let active_clients = Arc::new(AtomicUsize::new(0));
        let owned_broker = Arc::downgrade(&broker);

        let thread_deferred = Arc::clone(&active_deferred);
        let thread = thread::spawn(move || {
            while !worker_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if worker_stopping.load(Ordering::Acquire) {
                            break;
                        }
                        if active_clients.fetch_add(1, Ordering::AcqRel) >= MAX_HTTP_CLIENTS {
                            active_clients.fetch_sub(1, Ordering::AcqRel);
                            write_http_response(
                                &mut stream,
                                503,
                                "Service Unavailable",
                                Some("text/plain"),
                                b"Server busy\n",
                            );
                            continue;
                        }
                        let client_clients = Arc::clone(&active_clients);
                        let client_stopping = Arc::clone(&worker_stopping);
                        let client_deferred = Arc::clone(&thread_deferred);
                        let client_broker = Arc::clone(&broker);
                        thread::spawn(move || {
                            struct ClientGuard(Arc<AtomicUsize>);
                            impl Drop for ClientGuard {
                                fn drop(&mut self) {
                                    self.0.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let _guard = ClientGuard(client_clients);
                            handle_http_client(
                                stream,
                                bound_port,
                                &client_stopping,
                                &client_deferred,
                                &client_broker,
                            );
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            port: bound_port,
            stopping,
            thread: Mutex::new(Some(thread)),
            active_deferred,
            broker: owned_broker,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_healthy(&self) -> bool {
        !self.stopping.load(Ordering::Acquire)
    }

    pub fn active_deferred_count(&self) -> usize {
        self.active_deferred.load(Ordering::Acquire)
    }

    pub fn lock_vault(&self) {
        if let Some(broker) = self.broker.upgrade() {
            if let Ok(mut broker) = broker.lock() {
                broker.lock_for_system();
            }
        }
    }

    pub fn stop(&self) {
        if self.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Ok(mut thread) = self.thread.lock() {
            if let Some(thread) = thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for BrowserBrokerHttpListener {
    fn drop(&mut self) {
        self.stop();
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    content_type: Option<&str>,
    body: &[u8],
) {
    let mut header = format!(
        "HTTP/1.1 {status_code} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(ct) = content_type {
        header.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    header.push_str("\r\n");
    let _ = stream.write_all(header.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn handle_http_client(
    mut stream: TcpStream,
    bound_port: u16,
    stopping: &Arc<AtomicBool>,
    active_deferred: &Arc<AtomicUsize>,
    broker: &Arc<Mutex<BrowserBrokerCore>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(35)));

    let mut header_buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let (headers_len, body_start_offset);

    loop {
        if stopping.load(Ordering::Acquire) {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                header_buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_subslice(&header_buf, b"\r\n\r\n") {
                    headers_len = pos;
                    body_start_offset = pos + 4;
                    break;
                }
                if let Some(pos) = find_subslice(&header_buf, b"\n\n") {
                    headers_len = pos;
                    body_start_offset = pos + 2;
                    break;
                }
                if header_buf.len() > HTTP_MAX_HEADER_BYTES {
                    write_http_response(
                        &mut stream,
                        431,
                        "Request Header Fields Too Large",
                        Some("text/plain"),
                        b"Headers too large\n",
                    );
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => return,
            Err(_) => return,
        }
    }

    let header_text = match std::str::from_utf8(&header_buf[..headers_len]) {
        Ok(t) => t,
        Err(_) => {
            write_http_response(
                &mut stream,
                400,
                "Bad Request",
                Some("text/plain"),
                b"Invalid UTF-8 in headers\n",
            );
            return;
        }
    };

    let mut lines = header_text.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };

    let mut parts = request_line.split_whitespace();
    let method = match parts.next() {
        Some(m) => m,
        None => return,
    };
    let path = match parts.next() {
        Some(p) => p,
        None => return,
    };

    let mut origin_header = None;
    let mut sec_fetch_header = false;
    let mut content_length: usize = 0;
    let mut custom_origin_header = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "origin" {
                origin_header = Some(val.to_owned());
            } else if key.starts_with("sec-fetch-") {
                sec_fetch_header = true;
            } else if key == "content-length" {
                if let Ok(len) = val.parse::<usize>() {
                    content_length = len;
                }
            } else if key == "x-vaultmesh-browser-origin" {
                custom_origin_header = Some(val.to_owned());
            }
        }
    }

    // SECURITY DEFENSE:
    // Reject any request with Origin or Sec-Fetch-* headers or OPTIONS method.
    // This strictly isolates the local port from ordinary web pages.
    if origin_header.is_some() || sec_fetch_header || method.eq_ignore_ascii_case("OPTIONS") {
        write_http_response(&mut stream, 403, "Forbidden", Some("text/plain"), b"Forbidden\n");
        return;
    }

    if method.eq_ignore_ascii_case("GET") && path == "/discover" {
        let payload = serde_json::json!({
            "service": "vaultmesh-desktop",
            "version": 2,
            "port": bound_port,
        });
        if let Ok(bytes) = serde_json::to_vec(&payload) {
            write_http_response(&mut stream, 200, "OK", Some("application/json"), &bytes);
        }
        return;
    }

    if method.eq_ignore_ascii_case("POST") && path == "/rpc" {
        let _custom_origin = match custom_origin_header {
            Some(ref o) if is_valid_browser_origin(o) => o,
            _ => {
                write_http_response(
                    &mut stream,
                    403,
                    "Forbidden",
                    Some("text/plain"),
                    b"Invalid or missing browser origin header\n",
                );
                return;
            }
        };

        if content_length > HTTP_MAX_BODY_BYTES {
            write_http_response(
                &mut stream,
                413,
                "Payload Too Large",
                Some("text/plain"),
                b"Payload too large\n",
            );
            return;
        }

        let mut body_bytes = Vec::with_capacity(content_length);
        if body_start_offset < header_buf.len() {
            let available = &header_buf[body_start_offset..];
            let take = available.len().min(content_length);
            body_bytes.extend_from_slice(&available[..take]);
        }

        while body_bytes.len() < content_length {
            let needed = content_length - body_bytes.len();
            let read_size = needed.min(chunk.len());
            match stream.read(&mut chunk[..read_size]) {
                Ok(0) => break,
                Ok(n) => body_bytes.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
                Err(_) => break,
            }
        }

        if body_bytes.len() != content_length {
            write_http_response(
                &mut stream,
                400,
                "Bad Request",
                Some("text/plain"),
                b"Incomplete request body\n",
            );
            return;
        }

        let outcome = broker
            .lock()
            .ok()
            .map(|mut b| b.handle_http_payload_or_defer(&body_bytes));

        match outcome {
            Some(BrokerLineOutcome::Immediate(response)) => {
                if let Ok(bytes) = serde_json::to_vec(&response) {
                    write_http_response(&mut stream, 200, "OK", Some("application/json"), &bytes);
                } else {
                    write_http_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        Some("text/plain"),
                        b"Serialization failed\n",
                    );
                }
            }
            Some(BrokerLineOutcome::Deferred(deferred)) => {
                if active_deferred
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_DEFERRED_WAITERS).then_some(count + 1)
                    })
                    .is_err()
                {
                    let busy = rpc_failure(
                        &deferred.envelope_request_id,
                        "cancelled",
                        "已有过多待处理的自动填充解锁请求，请稍后重试。",
                    );
                    if let Ok(bytes) = serde_json::to_vec(&busy) {
                        write_http_response(&mut stream, 200, "OK", Some("application/json"), &bytes);
                    }
                    return;
                }
                let guard = DeferredWaiterGuard(Arc::clone(active_deferred));
                let response = deferred.wait_and_finish(broker);
                drop(guard);
                if let Ok(bytes) = serde_json::to_vec(&response) {
                    write_http_response(&mut stream, 200, "OK", Some("application/json"), &bytes);
                }
            }
            None => {
                let invalid = host_status("invalid-message", None);
                if let Ok(bytes) = serde_json::to_vec(&invalid) {
                    write_http_response(&mut stream, 400, "Bad Request", Some("application/json"), &bytes);
                }
            }
        }
        return;
    }

    write_http_response(&mut stream, 404, "Not Found", Some("text/plain"), b"Not Found\n");
}

#[cfg(test)]
mod http_tests {
    use super::*;

    #[test]
    fn validates_browser_origins_correctly() {
        assert!(is_valid_browser_origin("chrome-extension://bdneegbnjbheblmamalplnddbodcghbg"));
        assert!(is_valid_browser_origin("chrome-extension://bdneegbnjbheblmamalplnddbodcghbg/"));
        assert!(!is_valid_browser_origin("chrome-extension://short"));
        assert!(!is_valid_browser_origin("chrome-extension://bdneegbnjbheblmamalplnddbodcghbgz"));
        assert!(is_valid_browser_origin("vaultmesh@atlantis-mk.github.io"));
        assert!(!is_valid_browser_origin("https://evil.com"));
        assert!(!is_valid_browser_origin("http://127.0.0.1:42800"));
    }
}
