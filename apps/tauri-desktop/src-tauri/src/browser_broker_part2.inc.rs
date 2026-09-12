/// Owner-only newline-delimited local transport used by the native-messaging
/// forwarding helper on macOS. Windows named-pipe transport remains a separate
/// platform slice.
#[cfg(unix)]
pub struct BrowserBrokerUnixListener {
    broker: std::sync::Weak<Mutex<BrowserBrokerCore>>,
    endpoint: PathBuf,
    stopping: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[cfg(unix)]
impl BrowserBrokerUnixListener {
    pub fn start(
        endpoint: PathBuf,
        broker: Arc<Mutex<BrowserBrokerCore>>,
    ) -> std::io::Result<Self> {
        prepare_socket_endpoint(&endpoint)?;
        let listener = UnixListener::bind(&endpoint)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let owned_broker = Arc::downgrade(&broker);
        let thread = thread::spawn(move || {
            while !worker_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets may inherit O_NONBLOCK from the
                        // listener on macOS. Large responses otherwise stop at
                        // the first kernel buffer with WouldBlock.
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        // The native host writes its single line immediately.
                        // Keep shutdown bounded even if a local client connects
                        // and then withholds the request body.
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let response = read_broker_line(&mut stream)
                            .ok()
                            .and_then(|line| {
                                broker
                                    .lock()
                                    .ok()
                                    .map(|mut broker| broker.handle_line(&line))
                            })
                            .unwrap_or_else(|| host_status("invalid-message", None));
                        if let Ok(mut encoded) = serde_json::to_vec(&response) {
                            if encoded.len() > MAX_BROKER_RESPONSE_BYTES {
                                encoded = serde_json::to_vec(&host_status(
                                    "response-too-large",
                                    response.get("requestId").and_then(Value::as_str),
                                ))
                                .unwrap_or_default();
                            }
                            encoded.push(b'\n');
                            let _ = stream.write_all(&encoded);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            broker: owned_broker,
            endpoint,
            stopping,
            thread: Mutex::new(Some(thread)),
        })
    }

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.endpoint);
    }
    pub(crate) fn lock_vault(&self) { if let Some(broker) = self.broker.upgrade() { if let Ok(mut b) = broker.lock() { b.lock_for_system(); } } }
}

#[cfg(unix)]
impl Drop for BrowserBrokerUnixListener {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(unix)]
fn prepare_socket_endpoint(endpoint: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    if endpoint.as_os_str().as_encoded_bytes().len() > 103 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "broker endpoint exceeds the macOS Unix socket limit",
        ));
    }
    let parent = endpoint.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "broker endpoint has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    match fs::symlink_metadata(endpoint) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(endpoint),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "broker endpoint is not a socket",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn read_broker_line(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "missing newline",
            ));
        }
        if let Some(newline) = chunk[..count].iter().position(|byte| *byte == b'\n') {
            line.extend_from_slice(&chunk[..newline]);
            return (line.len() <= MAX_LINE_BYTES)
                .then_some(line)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "line too large")
                });
        }
        line.extend_from_slice(&chunk[..count]);
        if line.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too large",
            ));
        }
    }
}

fn valid_gesture(input: &Map<String, Value>) -> bool {
    input
        .get("userGestureId")
        .and_then(Value::as_str)
        .is_some_and(|value| Uuid::parse_str(value).is_ok())
}

fn is_runtime_operation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.change-password"
            | "browser.card.capture-status"
            | "browser.login.password-changed"
            | "browser.fill.record"
            | "browser.fill.history"
            | "items.list"
            | "items.detail"
            | "items.add"
            | "items.update"
            | "items.delete"
            | "items.trash.list"
            | "items.trash.restore"
            | "items.trash.purge"
            | "items.trash.empty"
            | "items.history.list"
            | "items.history.restore"
            | "items.history.clear"
            | "cards.list"
            | "cards.detail"
            | "cards.add"
            | "cards.update"
            | "cards.delete"
            | "cards.trash.list"
            | "cards.trash.restore"
            | "cards.trash.purge"
            | "cards.trash.empty"
            | "cards.history.list"
            | "cards.history.restore"
            | "cards.history.clear"
            | "identities.list"
            | "identities.detail"
            | "identities.add"
            | "identities.update"
            | "identities.delete"
            | "identities.trash.list"
            | "identities.trash.restore"
            | "identities.trash.purge"
            | "identities.trash.empty"
            | "identities.history.list"
            | "identities.history.restore"
            | "identities.history.clear"
            | "ssh.list"
            | "ssh.detail"
            | "ssh.add"
            | "ssh.update"
            | "ssh.delete"
            | "ssh.trash.list"
            | "ssh.trash.restore"
            | "ssh.trash.purge"
            | "ssh.trash.empty"
            | "ssh.history.list"
            | "ssh.history.restore"
            | "ssh.history.clear"
            | "secrets.list"
            | "secrets.detail"
            | "secrets.add"
            | "secrets.update"
            | "secrets.delete"
            | "password.health"
    )
}

#[cfg(test)]
fn is_broker_operation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.status"
            | "vault.workspace"
            | "vault.create"
            | "vault.unlock"
            | "vault.unlock-history"
            | "vault.lock"
            | "events.poll"
            | "browser.pairing.status"
            | "confirmation.request"
            | "browser.autofill.candidates"
            | "browser.autofill.profile"
            | "browser.autofill.execute"
            | "browser.fill.request"
    )
}

fn is_runtime_mutation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.change-password"
            | "browser.fill.record"
            | "items.add"
            | "items.update"
            | "items.delete"
            | "items.trash.restore"
            | "items.trash.purge"
            | "items.trash.empty"
            | "items.history.restore"
            | "items.history.clear"
            | "cards.add"
            | "cards.update"
            | "cards.delete"
            | "cards.trash.restore"
            | "cards.trash.purge"
            | "cards.trash.empty"
            | "cards.history.restore"
            | "cards.history.clear"
            | "identities.add"
            | "identities.update"
            | "identities.delete"
            | "identities.trash.restore"
            | "identities.trash.purge"
            | "identities.trash.empty"
            | "identities.history.restore"
            | "identities.history.clear"
            | "ssh.add"
            | "ssh.update"
            | "ssh.delete"
            | "ssh.trash.restore"
            | "ssh.trash.purge"
            | "ssh.trash.empty"
            | "ssh.history.restore"
            | "ssh.history.clear"
            | "secrets.add"
            | "secrets.update"
            | "secrets.delete"
    )
}

fn parse_rpc_time(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| time.timestamp_millis())
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

fn runtime_failure(request_id: &str, error: DesktopRuntimeError) -> Value {
    let (code, message) = match error.status() {
        VAULTMESH_STATUS_AUTH_FAILED => ("operation-failed", "主密码不正确。"),
        VAULTMESH_STATUS_LOCKED => ("unlock-required", "请先在 VaultMesh 插件中单独解锁。"),
        VAULTMESH_STATUS_INVALID_ARGUMENT => ("invalid-request", "插件请求格式无效。"),
        _ => ("operation-failed", error.public_message()),
    };
    rpc_failure(request_id, code, message)
}

fn host_status(status: &str, request_id: Option<&str>) -> Value {
    let mut result = json!({ "kind": "vaultmesh.host-status", "status": status });
    if let Some(request_id) = request_id {
        result["requestId"] = json!(request_id);
    }
    result
}

fn rpc_success(request_id: &str, result: Value) -> Value {
    json!({ "kind": "vaultmesh.rpc-result", "version": RPC_VERSION, "requestId": request_id, "ok": true, "result": result })
}

fn rpc_failure(request_id: &str, code: &str, message: &str) -> Value {
    json!({ "kind": "vaultmesh.rpc-result", "version": RPC_VERSION, "requestId": request_id, "ok": false, "error": { "code": code, "message": message } })
}

#[cfg(test)]
#[path = "browser_broker_tests.rs"]
mod tests;
