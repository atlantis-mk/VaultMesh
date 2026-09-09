//! Trusted LAN transport. All Vault access is through typed Rust runtime methods.
use super::*;
use uuid::Uuid;
use vaultmesh_ffi::DesktopRuntime;
use vaultmesh_ffi::{SYNC_MAX_BYTES, SYNC_MAX_RECORDS, SyncManifest, SyncRecord};

const SYNC_SERVICE: &str = "_vaultmesh-sync._tcp.local.";
const SYNC_PROTOCOL: u8 = 1;
const RETRY_DELAY: Duration = Duration::from_secs(3);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncPeerStatus {
    pub peer_ref: String,
    pub enabled: bool,
    pub state: String,
    pub last_success_at: Option<u64>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncStatus {
    pub peers: Vec<SyncPeerStatus>,
    pub conflict_count: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyncHello {
    version: u8,
    instance: String,
    nonce: String,
    vault: Uuid,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    committed: bool,
}

#[derive(Clone)]
struct Context {
    runtime: Arc<Mutex<DesktopRuntime>>,
    identity: Arc<Identity>,
    trust: TrustStore,
    local: Uuid,
    instance: String,
    nonce: String,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
    states: Arc<Mutex<HashMap<String, SyncPeerStatus>>>,
    changes: Arc<AtomicU64>,
}
struct Running {
    local: Uuid,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
    daemon: ServiceDaemon,
    fullname: String,
}
pub(crate) struct LanSyncService {
    runtime: Arc<Mutex<DesktopRuntime>>,
    trust: TrustStore,
    running: Option<Running>,
    states: Arc<Mutex<HashMap<String, SyncPeerStatus>>>,
    changes: Arc<AtomicU64>,
}
impl LanSyncService {
    pub(crate) fn new(runtime: Arc<Mutex<DesktopRuntime>>, trust_path: PathBuf) -> Self {
        Self {
            runtime,
            trust: TrustStore::new(trust_path),
            running: None,
            states: Arc::new(Mutex::new(HashMap::new())),
            changes: Arc::new(AtomicU64::new(0)),
        }
    }
    pub(crate) fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.stop.store(true, Ordering::Release);
            r.sessions.shutdown_all();
            let _ = r.daemon.unregister(&r.fullname);
            shutdown_daemon(&r.daemon);
        }
        if let Ok(mut states) = self.states.lock() {
            for s in states.values_mut() {
                s.state = "waiting-unlock".into();
            }
        }
    }
    pub(crate) fn interrupt_peer(&mut self, peer: &str) {
        // A fresh service epoch also fences pre-handshake connections.
        self.stop();
        if let Ok(mut states) = self.states.lock() {
            states.remove(peer);
        }
    }
    pub(crate) fn notify_change(&self) {
        self.changes.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn take_changes(&self) -> u64 {
        self.changes.swap(0, Ordering::AcqRel)
    }
    pub(crate) fn retry(&mut self) {
        self.stop();
    }
    pub(crate) fn status(&self) -> Result<SyncStatus, String> {
        let mut runtime = self.runtime.lock().map_err(|_| "同步暂时不可用。")?;
        let state = runtime.sync_state().map_err(|_| "请先解锁保险库。")?;
        let trusted = self.trust.load().map_err(|_| "设备信任不可用。")?;
        let states = self.states.lock().map_err(|_| "同步暂时不可用。")?;
        let peers = trusted
            .iter()
            .map(|peer| {
                let enabled = state.authorizations.iter().any(|a| {
                    a.enabled
                        && a.peer == peer.pairing_ref
                        && a.fingerprint == peer.certificate_fingerprint
                });
                let mut value = states
                    .get(&peer.pairing_ref)
                    .cloned()
                    .unwrap_or(SyncPeerStatus {
                        peer_ref: peer.pairing_ref.clone(),
                        enabled,
                        state: if enabled { "offline" } else { "disabled" }.into(),
                        last_success_at: None,
                    });
                value.enabled = enabled;
                if !enabled {
                    value.state = "disabled".into();
                } else if value.state == "synced"
                    && value
                        .last_success_at
                        .is_some_and(|t| SystemTimeMillis::now().saturating_sub(t) > 10_000)
                {
                    value.state = "offline".into();
                }
                value
            })
            .collect();
        Ok(SyncStatus {
            peers,
            conflict_count: state.conflicts.len(),
        })
    }
    pub(crate) fn tick(&mut self) {
        let state = self
            .runtime
            .lock()
            .ok()
            .and_then(|mut r| r.sync_state().ok());
        let trusted = self.trust.load().unwrap_or_default();
        let enabled = state.as_ref().is_some_and(|s| {
            s.authorizations.iter().any(|a| {
                a.enabled
                    && trusted.iter().any(|p| {
                        p.pairing_ref == a.peer && p.certificate_fingerprint == a.fingerprint
                    })
            })
        });
        if !enabled {
            self.stop();
            return;
        }
        let local = state.unwrap().vault_id;
        if self.running.as_ref().is_some_and(|r| r.local != local) {
            self.stop();
        }
        if self.running.is_none() {
            let _ = self.start(local);
        }
    }
    fn start(&mut self, local: Uuid) -> Result<(), ()> {
        let identity = Arc::new(Identity::load_or_create().map_err(|_| ())?);
        let listener = bind_listener().map_err(|_| ())?;
        listener.set_nonblocking(true).map_err(|_| ())?;
        let instance = random_token();
        let nonce = random_token();
        let hostname = format!("{}.local.", random_token());
        let props = [("v", "1"), ("i", instance.as_str()), ("n", nonce.as_str())];
        let mut info = ServiceInfo::new(
            SYNC_SERVICE,
            &instance,
            &hostname,
            "",
            listener.local_addr().map_err(|_| ())?.port(),
            &props[..],
        )
        .map_err(|_| ())?
        .enable_addr_auto();
        info.set_interfaces(vec![IfKind::Predicate(IfPredicate::new(|interface| {
            usable_interface_address(interface.ip())
        }))]);
        let fullname = info.get_fullname().to_owned();
        let daemon = ServiceDaemon::new().map_err(|_| ())?;
        if daemon.register(info).is_err() {
            shutdown_daemon(&daemon);
            return Err(());
        }
        let browse = match daemon.browse(SYNC_SERVICE) {
            Ok(b) => b,
            Err(_) => {
                shutdown_daemon(&daemon);
                return Err(());
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(SessionRegistry::default());
        let context = Context {
            runtime: self.runtime.clone(),
            identity,
            trust: self.trust.clone(),
            local,
            instance,
            nonce,
            stop: stop.clone(),
            sessions: sessions.clone(),
            states: self.states.clone(),
            changes: self.changes.clone(),
        };
        thread::spawn(move || run_discovery(listener, browse, context));
        self.running = Some(Running {
            local,
            stop,
            sessions,
            daemon,
            fullname,
        });
        Ok(())
    }
}
impl Drop for LanSyncService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_discovery(listener: TcpListener, browse: mdns_sd::Receiver<ServiceEvent>, context: Context) {
    let mut endpoints = HashMap::<String, Endpoint>::new();
    let mut attempted = HashMap::<String, Instant>::new();
    let busy = Arc::new(Mutex::new(HashSet::new()));
    let workers = Arc::new(AtomicUsize::new(0));
    while !context.stop.load(Ordering::Acquire) {
        while let Ok(event) = browse.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let props = info.get_properties();
                    let instance = props.get_property_val_str("i").unwrap_or("");
                    let nonce = props.get_property_val_str("n").unwrap_or("");
                    if props.len() != 3
                        || props.get_property_val_str("v") != Some("1")
                        || !valid_token(instance)
                        || !valid_token(nonce)
                        || instance == context.instance
                    {
                        continue;
                    }
                    let addresses: Vec<_> = info
                        .get_addresses()
                        .iter()
                        .map(|a| a.to_ip_addr())
                        .filter(|ip| same_link(*ip))
                        .collect();
                    if addresses.is_empty()
                        || endpoints.len() >= MAX_PEERS && !endpoints.contains_key(instance)
                    {
                        continue;
                    }
                    endpoints.insert(
                        instance.into(),
                        Endpoint {
                            instance: instance.into(),
                            nonce: nonce.into(),
                            fullname: info.get_fullname().into(),
                            addresses,
                            port: info.get_port(),
                        },
                    );
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    endpoints.retain(|_, e| e.fullname != fullname);
                }
                _ => {}
            }
        }
        if workers.load(Ordering::Acquire) < MAX_HANDSHAKES {
            if let Ok((socket, addr)) = listener.accept() {
                if same_link(addr.ip()) {
                    spawn_worker(socket, false, None, context.clone(), workers.clone());
                }
            }
        }
        for ep in endpoints.values() {
            if context.instance >= ep.instance
                || workers.load(Ordering::Acquire) >= MAX_HANDSHAKES
                || attempted
                    .get(&ep.instance)
                    .is_some_and(|t| t.elapsed() < RETRY_DELAY)
            {
                continue;
            }
            let Ok(mut locked) = busy.lock() else {
                break;
            };
            if !locked.insert(ep.instance.clone()) {
                continue;
            }
            drop(locked);
            attempted.insert(ep.instance.clone(), Instant::now());
            // Bounded connection workers keep the discovery/stop loop responsive.
            let ep = ep.clone();
            let context = context.clone();
            let workers = workers.clone();
            let busy = busy.clone();
            workers.fetch_add(1, Ordering::AcqRel);
            thread::spawn(move || {
                for ip in &ep.addresses {
                    if context.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if let Ok(socket) = TcpStream::connect_timeout(
                        &SocketAddr::new(*ip, ep.port),
                        Duration::from_secs(1),
                    ) {
                        let _ = exchange(
                            socket,
                            true,
                            Some((ep.instance.clone(), ep.nonce.clone())),
                            &context,
                        );
                        break;
                    }
                }
                if let Ok(mut locked) = busy.lock() {
                    locked.remove(&ep.instance);
                }
                workers.fetch_sub(1, Ordering::AcqRel);
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn spawn_worker(
    socket: TcpStream,
    client: bool,
    expected: Option<(String, String)>,
    context: Context,
    workers: Arc<AtomicUsize>,
) {
    workers.fetch_add(1, Ordering::AcqRel);
    thread::spawn(move || {
        let _ = exchange(socket, client, expected, &context);
        workers.fetch_sub(1, Ordering::AcqRel);
    });
}
fn trusted(context: &Context, fingerprint: &str) -> Result<String, ()> {
    if context.stop.load(Ordering::Acquire) {
        return Err(());
    }
    let peer = context
        .trust
        .load()?
        .into_iter()
        .find(|p| p.certificate_fingerprint == fingerprint)
        .ok_or(())?;
    let mut runtime = context.runtime.lock().map_err(|_| ())?;
    let s = runtime.sync_state().map_err(|_| ())?;
    if s.vault_id != context.local
        || !s
            .authorizations
            .iter()
            .any(|a| a.peer == peer.pairing_ref && a.fingerprint == fingerprint && a.enabled)
    {
        return Err(());
    }
    Ok(peer.pairing_ref)
}
fn update(context: &Context, peer: &str, state: &str, success: bool) {
    if let Ok(mut states) = context.states.lock() {
        if context.stop.load(Ordering::Acquire) {
            return;
        }
        let s = states.entry(peer.into()).or_insert(SyncPeerStatus {
            peer_ref: peer.into(),
            enabled: true,
            state: state.into(),
            last_success_at: None,
        });
        s.state = state.into();
        if success {
            s.last_success_at = Some(SystemTimeMillis::now());
        }
    }
}
struct SystemTimeMillis;
impl SystemTimeMillis {
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}
fn exchange(
    mut socket: TcpStream,
    client: bool,
    expected: Option<(String, String)>,
    context: &Context,
) -> Result<(), ()> {
    if context.stop.load(Ordering::Acquire) {
        return Err(());
    }
    let session = context.sessions.register(&socket)?;
    // Absolute session deadline prevents slow-frame peers from occupying a
    // bounded worker indefinitely by making tiny progress before each timeout.
    let deadline_socket = socket.try_clone().map_err(|_| ())?;
    let (_deadline_cancel, deadline_wait) = mpsc::channel::<()>();
    thread::spawn(move || {
        if matches!(
            deadline_wait.recv_timeout(Duration::from_secs(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = deadline_socket.shutdown(std::net::Shutdown::Both);
        }
    });
    socket.set_nonblocking(false).map_err(|_| ())?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    socket.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let cert = if client {
        write_cert(&mut socket, &context.identity.cert)?;
        read_cert(&mut socket)?
    } else {
        let cert = read_cert(&mut socket)?;
        write_cert(&mut socket, &context.identity.cert)?;
        cert
    };
    let fingerprint = hex_digest(&cert);
    // Pin the certificate BEFORE sending a Vault identifier or any sync frame.
    let peer = trusted(context, &fingerprint)?;
    let mut tls = if client {
        client_tls(socket, &context.identity, &cert)?
    } else {
        server_tls(socket, &context.identity, &cert)?
    };
    tls.complete_handshake()?;
    context.sessions.bind_peer(&session, &peer)?;
    update(context, &peer, "syncing", false);
    let result = (|| {
        let local = SyncHello {
            version: SYNC_PROTOCOL,
            instance: context.instance.clone(),
            nonce: context.nonce.clone(),
            vault: context.local,
        };
        let remote: SyncHello = exchange_frame(&mut tls, client, &local)?;
        if remote.version != SYNC_PROTOCOL
            || !valid_token(&remote.instance)
            || !valid_token(&remote.nonce)
            || remote.vault.is_nil()
            || expected
                .as_ref()
                .is_some_and(|(i, n)| i != &remote.instance || n != &remote.nonce)
        {
            return Err(());
        }
        trusted(context, &fingerprint)?;
        context
            .runtime
            .lock()
            .map_err(|_| ())?
            .sync_bind(&peer, &fingerprint, remote.vault, context.local)
            .map_err(|_| ())?;
        let manifest = context
            .runtime
            .lock()
            .map_err(|_| ())?
            .sync_manifest(&peer, &fingerprint, remote.vault, context.local)
            .map_err(|_| ())?;
        let theirs: SyncManifest = exchange_frame(&mut tls, client, &manifest)?;
        if theirs.len() > SYNC_MAX_RECORDS {
            return Err(());
        }
        trusted(context, &fingerprint)?;
        context
            .runtime
            .lock()
            .map_err(|_| ())?
            .sync_confirm_manifest(&peer, &fingerprint, remote.vault, context.local, &theirs)
            .map_err(|_| ())?;
        let outgoing = context
            .runtime
            .lock()
            .map_err(|_| ())?
            .sync_export(&peer, &fingerprint, remote.vault, context.local, &theirs)
            .map_err(|_| ())?;
        let incoming: Vec<SyncRecord> = exchange_frame(&mut tls, client, &outgoing)?;
        trusted(context, &fingerprint)?;
        if !incoming.is_empty() {
            let changed = context
                .runtime
                .lock()
                .map_err(|_| ())?
                .sync_merge_cancellable(
                    &peer,
                    &fingerprint,
                    remote.vault,
                    context.local,
                    &incoming,
                    &context.stop,
                )
                .map_err(|_| ())?;
            if changed > 0 {
                context.changes.fetch_add(1, Ordering::AcqRel);
            }
        }
        let receipt: Receipt = exchange_frame(
            &mut tls,
            client,
            &Receipt {
                version: SYNC_PROTOCOL,
                committed: true,
            },
        )?;
        if receipt.version != SYNC_PROTOCOL || !receipt.committed {
            return Err(());
        }
        trusted(context, &fingerprint)?;
        context
            .runtime
            .lock()
            .map_err(|_| ())?
            .sync_mark_backed_up(&peer, &fingerprint, remote.vault, context.local, &outgoing)
            .map_err(|_| ())?;
        Ok(())
    })();
    update(
        context,
        &peer,
        if result.is_ok() { "synced" } else { "failed" },
        result.is_ok(),
    );
    result
}
fn exchange_frame<T: Serialize, R: for<'de> Deserialize<'de>>(
    tls: &mut TlsStream,
    client: bool,
    local: &T,
) -> Result<R, ()> {
    if client {
        send(tls, local)?;
        receive(tls)
    } else {
        let remote = receive(tls)?;
        send(tls, local)?;
        Ok(remote)
    }
}
struct BoundedFrame(Zeroizing<Vec<u8>>);
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > SYNC_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sync frame limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn send<T: Serialize>(tls: &mut TlsStream, value: &T) -> Result<(), ()> {
    let mut frame = BoundedFrame(Zeroizing::new(Vec::with_capacity(SYNC_MAX_BYTES)));
    serde_json::to_writer(&mut frame, value).map_err(|_| ())?;
    let bytes = frame.0;
    tls.write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    tls.write_all(&bytes).map_err(|_| ())?;
    tls.flush().map_err(|_| ())
}
fn receive<T: for<'de> Deserialize<'de>>(tls: &mut TlsStream) -> Result<T, ()> {
    let mut size = [0; 4];
    tls.read_exact(&mut size).map_err(|_| ())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > SYNC_MAX_BYTES {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    tls.read_exact(&mut bytes).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(name: &str) -> Context {
        let path = std::env::temp_dir().join(format!(
            "vaultmesh-sync-test-{name}-{}.vault",
            Uuid::new_v4()
        ));
        let mut runtime = DesktopRuntime::new(path).unwrap();
        runtime.create(format!("test master {name}")).unwrap();
        let local = runtime.sync_state().unwrap().vault_id;
        Context {
            runtime: Arc::new(Mutex::new(runtime)),
            identity: super::super::tests::identity(),
            trust: super::super::tests::empty_store(name),
            local,
            instance: random_token(),
            nonce: random_token(),
            stop: Arc::new(AtomicBool::new(false)),
            sessions: Arc::new(SessionRegistry::default()),
            states: Arc::new(Mutex::new(HashMap::new())),
            changes: Arc::new(AtomicU64::new(0)),
        }
    }
    fn trust(a: &Context, b: &Context) {
        let peer = format!("lan-peer-{}", b.identity.device_id);
        let fingerprint = hex_digest(&b.identity.cert);
        a.trust
            .approve(LanTrustedPeer {
                pairing_ref: peer.clone(),
                certificate_fingerprint: fingerprint.clone(),
                label: "test peer".into(),
                protocol_major: PROTOCOL,
            })
            .unwrap();
        a.runtime
            .lock()
            .unwrap()
            .sync_authorize(&peer, &fingerprint, true)
            .unwrap();
    }
    fn add(context: &Context, title: &str) {
        context.runtime.lock().unwrap().execute("items.add",serde_json::json!({"title":title,"username":"synthetic user","password":"synthetic password","url":"https://example.test","notes":null,"folder":null,"favorite":false,"totpSecret":null,"recoveryCodes":[],"additionalUrls":[],"autofillOnPageLoad":false,"masterPasswordReprompt":false,"customFields":[]})).unwrap();
    }
    fn connect(a: &Context, b: &Context) -> (Result<(), ()>, Result<(), ()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = b.clone();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            exchange(socket, false, None, &server)
        });
        let client = exchange(
            TcpStream::connect(addr).unwrap(),
            true,
            Some((b.instance.clone(), b.nonce.clone())),
            a,
        );
        (client, worker.join().unwrap())
    }
    fn cleanup(c: &Context) {
        c.stop.store(true, Ordering::Release);
        c.sessions.shutdown_all();
        let path = c.runtime.lock().unwrap().current_path();
        c.runtime.lock().unwrap().lock();
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(&c.trust.path);
    }
    #[test]
    fn ct_lan_sync_real_tls_two_independent_vaults_commit_and_repeat() {
        let a = context("a");
        let b = context("b");
        trust(&a, &b);
        trust(&b, &a);
        add(&a, "from a");
        add(&b, "from b");
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        for c in [&a, &b] {
            assert_eq!(
                c.runtime
                    .lock()
                    .unwrap()
                    .execute("items.list", serde_json::json!({}))
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
        let before = a.runtime.lock().unwrap().sync_state().unwrap().entries;
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        assert_eq!(
            a.runtime.lock().unwrap().sync_state().unwrap().entries,
            before
        );
        cleanup(&a);
        cleanup(&b);
    }
    #[test]
    fn ct_lan_sync_real_tls_requires_both_authorizations_and_unlock() {
        let a = context("unauthorized-a");
        let b = context("unauthorized-b");
        trust(&a, &b);
        add(&a, "private");
        let (x, y) = connect(&a, &b);
        assert!(x.is_err() && y.is_err());
        assert_eq!(b.runtime.lock().unwrap().status().item_count, 0);
        trust(&b, &a);
        b.runtime.lock().unwrap().lock();
        let (x, y) = connect(&a, &b);
        assert!(x.is_err() && y.is_err());
        cleanup(&a);
        cleanup(&b);
    }
    #[test]
    fn ct_lan_sync_real_tls_vault_replacement_and_discovery_binding_rejected() {
        let a = context("replace-a");
        let mut b = context("replace-b");
        trust(&a, &b);
        trust(&b, &a);
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        let other = context("other");
        b.runtime = other.runtime.clone();
        b.local = other.local;
        assert!(connect(&a, &b).0.is_err());
        a.stop.store(true, Ordering::Release);
        assert!(connect(&a, &b).0.is_err());
        cleanup(&a);
        cleanup(&b);
    }
    #[test]
    fn ct_lan_sync_commit_survives_lost_receipt_and_retry() {
        let a = context("lost-a");
        let b = context("lost-b");
        trust(&a, &b);
        trust(&b, &a);
        add(&a, "committed once");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = b.clone();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            exchange(socket, false, None, &server)
        });
        let mut socket = TcpStream::connect(addr).unwrap();
        socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        write_cert(&mut socket, &a.identity.cert).unwrap();
        let cert = read_cert(&mut socket).unwrap();
        let fp = hex_digest(&cert);
        let peer = trusted(&a, &fp).unwrap();
        let mut tls = client_tls(socket, &a.identity, &cert).unwrap();
        tls.complete_handshake().unwrap();
        let hello: SyncHello = exchange_frame(
            &mut tls,
            true,
            &SyncHello {
                version: 1,
                instance: a.instance.clone(),
                nonce: a.nonce.clone(),
                vault: a.local,
            },
        )
        .unwrap();
        a.runtime
            .lock()
            .unwrap()
            .sync_bind(&peer, &fp, hello.vault, a.local)
            .unwrap();
        let manifest = a
            .runtime
            .lock()
            .unwrap()
            .sync_manifest(&peer, &fp, hello.vault, a.local)
            .unwrap();
        let remote: SyncManifest = exchange_frame(&mut tls, true, &manifest).unwrap();
        let records = a
            .runtime
            .lock()
            .unwrap()
            .sync_export(&peer, &fp, hello.vault, a.local, &remote)
            .unwrap();
        add(&b, "concurrent local edit after manifest");
        let _: Vec<SyncRecord> = exchange_frame(&mut tls, true, &records).unwrap();
        drop(tls);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(b.runtime.lock().unwrap().status().item_count, 2);
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        assert_eq!(b.runtime.lock().unwrap().status().item_count, 2);
        assert_eq!(a.runtime.lock().unwrap().status().item_count, 2);
        cleanup(&a);
        cleanup(&b);
    }
    #[test]
    fn ct_lan_sync_rejects_protocol_and_oversized_or_truncated_frames_over_tls() {
        for mode in 0..3 {
            let a = context("malformed-a");
            let b = context("malformed-b");
            trust(&a, &b);
            trust(&b, &a);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = b.clone();
            let worker = thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                exchange(socket, false, None, &server)
            });
            let mut socket = TcpStream::connect(addr).unwrap();
            socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
            write_cert(&mut socket, &a.identity.cert).unwrap();
            let cert = read_cert(&mut socket).unwrap();
            let mut tls = client_tls(socket, &a.identity, &cert).unwrap();
            tls.complete_handshake().unwrap();
            match mode {
                0 => send(
                    &mut tls,
                    &SyncHello {
                        version: 99,
                        instance: a.instance.clone(),
                        nonce: a.nonce.clone(),
                        vault: a.local,
                    },
                )
                .unwrap(),
                1 => {
                    tls.write_all(&((SYNC_MAX_BYTES + 1) as u32).to_be_bytes())
                        .unwrap();
                    tls.flush().unwrap();
                }
                _ => {
                    tls.write_all(&100_u32.to_be_bytes()).unwrap();
                    tls.write_all(b"{").unwrap();
                    tls.flush().unwrap();
                }
            }
            drop(tls);
            assert!(worker.join().unwrap().is_err());
            assert_eq!(b.runtime.lock().unwrap().status().item_count, 0);
            cleanup(&a);
            cleanup(&b);
        }
    }
    #[test]
    fn ct_lan_sync_fixed_certificate_revoke_and_nonce_fail_closed() {
        let a = context("pin-a");
        let b = context("pin-b");
        trust(&a, &b);
        trust(&b, &a);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = b.clone();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            exchange(socket, false, None, &server)
        });
        assert!(
            exchange(
                TcpStream::connect(addr).unwrap(),
                true,
                Some((b.instance.clone(), random_token())),
                &a
            )
            .is_err()
        );
        assert!(worker.join().unwrap().is_err());
        a.trust
            .revoke(&format!("lan-peer-{}", b.identity.device_id))
            .unwrap();
        assert!(connect(&a, &b).0.is_err());
        cleanup(&a);
        cleanup(&b);
    }
}
