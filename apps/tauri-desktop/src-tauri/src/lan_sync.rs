//! Trusted LAN transport. All Vault access is through typed Rust runtime methods.
use super::*;
use uuid::Uuid;
use vaultmesh_ffi::DesktopRuntime;
#[cfg(test)]
use vaultmesh_ffi::SYNC_MAX_BYTES;

const SYNC_SERVICE: &str = "_vaultmesh-sync._tcp.local.";
const SYNC_PROTOCOL: u8 = 2;
#[path = "lan_sync_session.rs"]
mod persistent;
const RETRY_DELAY: Duration = Duration::from_secs(1);
struct Retry {
    failures: u32,
    next: Instant,
}
impl Retry {
    fn new() -> Self {
        Self {
            failures: 0,
            next: Instant::now(),
        }
    }
    fn failed(&mut self, was_healthy: bool) {
        self.failures = if was_healthy {
            1
        } else {
            self.failures.saturating_add(1).min(7)
        };
        let seconds = (1u64 << self.failures.saturating_sub(1)).min(60);
        let jitter =
            u16::from_le_bytes(Uuid::new_v4().as_bytes()[..2].try_into().unwrap()) as u64 % 1_000;
        self.next = Instant::now() + RETRY_DELAY * seconds as u32 + Duration::from_millis(jitter);
    }
}

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
#[cfg(test)]
struct SyncHello {
    version: u8,
    instance: String,
    nonce: String,
    vault: Uuid,
    sending: Uuid,
    receiving: Option<Uuid>,
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
    hub: Arc<vaultmesh_ffi::sync_relay::RelayHub>,
    active_peers: Arc<Mutex<HashSet<String>>>,
    handshakes: Arc<AtomicUsize>,
    bootstraps: Arc<SessionRegistry>,
    #[cfg(test)]
    drop_receipt: Arc<AtomicBool>,
}
struct Running {
    local: Uuid,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
    daemon: ServiceDaemon,
    fullname: String,
    bootstraps: Arc<SessionRegistry>,
}
pub(crate) struct LanSyncService {
    runtime: Arc<Mutex<DesktopRuntime>>,
    trust: TrustStore,
    running: Option<Running>,
    states: Arc<Mutex<HashMap<String, SyncPeerStatus>>>,
    changes: Arc<AtomicU64>,
    verified_proof: Option<String>,
    pumped_generation: u64,
    observed_file: Option<(Option<std::time::SystemTime>, u64, bool)>,
    merged_generation: u64,
}
impl LanSyncService {
    pub(crate) fn lock_sensitive(&self) {
        if let Some(running) = &self.running {
            running.bootstraps.shutdown_all();
        }
    }
    pub(crate) fn new(runtime: Arc<Mutex<DesktopRuntime>>, trust_path: PathBuf) -> Self {
        Self {
            runtime,
            trust: TrustStore::new(trust_path),
            running: None,
            states: Arc::new(Mutex::new(HashMap::new())),
            changes: Arc::new(AtomicU64::new(0)),
            verified_proof: None,
            pumped_generation: 0,
            observed_file: None,
            merged_generation: 0,
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
        self.pumped_generation = 0;
        self.stop();
    }
    pub(crate) fn status(&self) -> Result<SyncStatus, String> {
        let mut runtime = self.runtime.lock().map_err(|_| "同步暂时不可用。")?;
        let state = runtime.sync_state().map_err(|_| "请先解锁保险库。")?;
        let cache_failed = runtime.sync_relay().failed();
        let trusted = self.trust.load().map_err(|_| "设备信任不可用。")?;
        let states = self.states.lock().map_err(|_| "同步暂时不可用。")?;
        let peers = trusted
            .iter()
            .map(|peer| {
                let enabled = state.authorizations.iter().any(|a| {
                    a.enabled
                        && a.outgoing.is_some()
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
                } else if cache_failed {
                    value.state = "failed".into();
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
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        let hub = runtime.sync_relay();
        let generation = hub.generation();
        if generation != self.pumped_generation {
            let _ = runtime.sync_pump();
            self.pumped_generation = hub.generation();
        }
        drop(runtime);
        let merged = hub.merged_generation();
        if self.merged_generation != merged {
            self.merged_generation = merged;
            self.notify_change();
        }
        let Ok((profile, from_core)) = hub.profile() else {
            self.stop();
            return;
        };
        let Ok(proof) = hub.proof() else {
            self.stop();
            return;
        };
        let path = self.runtime.lock().unwrap().current_path();
        let Ok(metadata) = std::fs::metadata(&path) else {
            self.stop();
            return;
        };
        let stamp = (metadata.modified().ok(), metadata.len());
        if self.verified_proof.as_ref() != Some(&proof)
            || self
                .observed_file
                .as_ref()
                .is_none_or(|(t, n, _)| (*t, *n) != stamp)
        {
            self.observed_file = Some((stamp.0, stamp.1, hub.matches_vault()));
        }
        if !self
            .observed_file
            .as_ref()
            .is_some_and(|(_, _, valid)| *valid)
        {
            self.stop();
            return;
        }
        if self.verified_proof.as_ref() != Some(&proof) {
            let account = format!(
                "lan-sync-route-{}",
                hex_digest(
                    self.runtime
                        .lock()
                        .unwrap()
                        .current_path()
                        .to_string_lossy()
                        .as_bytes()
                )
            );
            let valid = if from_core {
                self.trust
                    .credentials
                    .set(&account, proof.as_bytes())
                    .is_ok()
            } else {
                self.trust
                    .credentials
                    .get(&account)
                    .ok()
                    .flatten()
                    .is_some_and(|p| p.as_slice() == proof.as_bytes())
                    && hub.matches_vault()
            };
            if !valid {
                self.stop();
                return;
            }
            self.verified_proof = Some(proof);
        }
        let trusted = self.trust.load().unwrap_or_default();
        let local = profile
            .routes
            .iter()
            .find(|r| {
                trusted
                    .iter()
                    .any(|p| p.pairing_ref == r.peer && p.certificate_fingerprint == r.fingerprint)
            })
            .map(|r| r.local);
        let Some(local) = local else {
            self.stop();
            return;
        };
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
        let props = [("v", "2"), ("i", instance.as_str()), ("n", nonce.as_str())];
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
        let bootstraps = Arc::new(SessionRegistry::default());
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
            hub: self.runtime.lock().map_err(|_| ())?.sync_relay(),
            active_peers: Arc::new(Mutex::new(HashSet::new())),
            handshakes: Arc::new(AtomicUsize::new(0)),
            bootstraps: bootstraps.clone(),
            #[cfg(test)]
            drop_receipt: Arc::new(AtomicBool::new(false)),
        };
        thread::spawn(move || run_discovery(listener, browse, context));
        self.running = Some(Running {
            bootstraps,
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
    let attempted = Arc::new(Mutex::new(HashMap::<String, Retry>::new()));
    let busy = Arc::new(Mutex::new(HashSet::new()));
    let workers = Arc::new(AtomicUsize::new(0));
    while !context.stop.load(Ordering::Acquire) {
        for _ in 0..64 {
            let Ok(event) = browse.try_recv() else { break };
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let props = info.get_properties();
                    let instance = props.get_property_val_str("i").unwrap_or("");
                    let nonce = props.get_property_val_str("n").unwrap_or("");
                    if props.len() != 3
                        || props.get_property_val_str("v") != Some("2")
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
                    if let Ok(mut retries) = attempted.lock() {
                        retries.retain(|id, _| endpoints.contains_key(id));
                    }
                }
                _ => {}
            }
        }
        if workers.load(Ordering::Acquire) < MAX_PEERS + MAX_HANDSHAKES {
            if let Ok((socket, addr)) = listener.accept() {
                if same_link(addr.ip()) {
                    spawn_worker(socket, false, None, context.clone(), workers.clone());
                }
            }
        }
        for ep in endpoints.values() {
            if context.instance >= ep.instance
                || workers.load(Ordering::Acquire) >= MAX_PEERS + MAX_HANDSHAKES
                || attempted
                    .lock()
                    .map(|r| r.get(&ep.instance).is_some_and(|r| Instant::now() < r.next))
                    .unwrap_or(true)
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
            if let Ok(mut retries) = attempted.lock() {
                retries
                    .entry(ep.instance.clone())
                    .or_insert_with(Retry::new);
            }
            // Bounded connection workers keep the discovery/stop loop responsive.
            let ep = ep.clone();
            let context = context.clone();
            let workers = workers.clone();
            let busy = busy.clone();
            let attempted = attempted.clone();
            workers.fetch_add(1, Ordering::AcqRel);
            thread::spawn(move || {
                let started = Instant::now();
                for ip in &ep.addresses {
                    if context.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if let Ok(socket) = TcpStream::connect_timeout(
                        &SocketAddr::new(*ip, ep.port),
                        Duration::from_secs(1),
                    ) {
                        let _ = persistent::exchange(
                            socket,
                            true,
                            Some((ep.instance.clone(), ep.nonce.clone())),
                            &context,
                        );
                        break;
                    }
                }
                if let Ok(mut retries) = attempted.lock() {
                    // Removed advertisements cannot reinsert stale retry state.
                    if let Some(retry) = retries.get_mut(&ep.instance) {
                        retry.failed(started.elapsed() > Duration::from_secs(30));
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
        let _ = persistent::exchange(socket, client, expected, &context);
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
    let (profile, _) = context.hub.profile()?;
    if !profile.routes.iter().any(|r| {
        r.local == context.local && r.peer == peer.pairing_ref && r.fingerprint == fingerprint
    }) {
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
#[cfg(test)]
struct BoundedFrame(Zeroizing<Vec<u8>>);
#[cfg(test)]
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
#[cfg(test)]
fn send<T: Serialize>(tls: &mut TlsStream, value: &T) -> Result<(), ()> {
    let mut frame = BoundedFrame(Zeroizing::new(Vec::with_capacity(SYNC_MAX_BYTES)));
    serde_json::to_writer(&mut frame, value).map_err(|_| ())?;
    let bytes = frame.0;
    tls.write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    tls.write_all(&bytes).map_err(|_| ())?;
    tls.flush().map_err(|_| ())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn live(a: &Context, b: &Context) -> Vec<thread::JoinHandle<Result<(), ()>>> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = b.clone();
        let client = a.clone();
        let expected = (b.instance.clone(), b.nonce.clone());
        vec![
            thread::spawn(move || {
                persistent::exchange(listener.accept().unwrap().0, false, None, &server)
            }),
            thread::spawn(move || {
                persistent::exchange(
                    TcpStream::connect(addr).unwrap(),
                    true,
                    Some(expected),
                    &client,
                )
            }),
        ]
    }
    fn until(mut condition: impl FnMut() -> bool) {
        let start = Instant::now();
        while !condition() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "persistent sync did not converge"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    fn stop_live(contexts: &[&Context], handles: Vec<thread::JoinHandle<Result<(), ()>>>) {
        for c in contexts {
            c.stop.store(true, Ordering::Release);
            c.sessions.shutdown_all();
        }
        for h in handles {
            let _ = h.join().unwrap();
        }
    }
    #[test]
    fn ct_lan_sync_v2_three_devices_push_while_locked_and_merge_on_unlock() {
        let a = context("live-a");
        let b = context("live-b");
        let c = context("live-c");
        for (x, y) in [(&a, &b), (&b, &a), (&b, &c), (&c, &b), (&a, &c), (&c, &a)] {
            trust(x, y);
        }
        let mut handles = live(&a, &b);
        handles.extend(live(&b, &c));
        handles.extend(live(&a, &c));
        until(|| {
            [&a, &b, &c].iter().all(|x| {
                x.hub
                    .profile()
                    .unwrap()
                    .0
                    .routes
                    .iter()
                    .all(|r| r.incoming.is_some())
            })
        });
        c.runtime.lock().unwrap().lock();
        add(&a, "pushed after lock");
        until(|| b.runtime.lock().unwrap().status().item_count == 1);
        until(|| {
            c.hub
                .profile()
                .unwrap()
                .0
                .routes
                .iter()
                .any(|r| c.hub.summary(&r.peer).unwrap().received.is_some())
        });
        assert!(!c.runtime.lock().unwrap().status().unlocked);
        let path = c.runtime.lock().unwrap().current_path();
        let bytes = std::fs::read(path.with_file_name(format!(
            "{}.lan-mailbox",
            path.file_name().unwrap().to_string_lossy()
        )))
        .unwrap();
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("synthetic password")
        );
        c.runtime
            .lock()
            .unwrap()
            .unlock("test master live-c".into())
            .unwrap();
        until(|| c.runtime.lock().unwrap().status().item_count == 1);
        add(&c, "third device edit");
        until(|| {
            [&a, &b, &c]
                .iter()
                .all(|x| x.runtime.lock().unwrap().status().item_count == 2)
        });
        let versions = a.runtime.lock().unwrap().sync_state().unwrap().entries;
        until(|| {
            [&b, &c]
                .iter()
                .all(|x| x.runtime.lock().unwrap().sync_state().unwrap().entries == versions)
        });
        stop_live(&[&a, &b, &c], handles);
        for x in [&a, &b, &c] {
            cleanup(x);
        }
    }
    #[test]
    fn ct_lan_sync_v2_reconnects_locked_and_browser_edits_push_without_desktop_unlock() {
        let a = context("browser-a");
        let b = context("browser-b");
        trust(&a, &b);
        trust(&b, &a);
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        a.runtime.lock().unwrap().lock();
        b.runtime.lock().unwrap().lock();
        let mut browser = DesktopRuntime::new(a.runtime.lock().unwrap().current_path()).unwrap();
        browser
            .unlock_for_browser("test master browser-a".into())
            .unwrap();
        browser.execute("items.add", serde_json::json!({"title":"plugin synthetic edit","username":"u","password":"synthetic password","url":"https://example.test","notes":null,"folder":null,"favorite":false,"totpSecret":null,"recoveryCodes":[],"additionalUrls":[],"autofillOnPageLoad":false,"masterPasswordReprompt":false,"customFields":[]})).unwrap();
        browser.lock();
        let handles = live(&a, &b);
        until(|| {
            b.hub
                .profile()
                .unwrap()
                .0
                .routes
                .iter()
                .any(|r| b.hub.summary(&r.peer).unwrap().received.is_some())
        });
        assert!(!a.runtime.lock().unwrap().status().unlocked);
        assert!(!b.runtime.lock().unwrap().status().unlocked);
        let mut receiver = DesktopRuntime::new(b.runtime.lock().unwrap().current_path()).unwrap();
        receiver
            .unlock_for_browser("test master browser-b".into())
            .unwrap();
        assert_eq!(receiver.status().item_count, 1);
        assert!(!b.runtime.lock().unwrap().status().unlocked);
        stop_live(&[&a, &b], handles);
        cleanup(&a);
        cleanup(&b);
    }
    #[test]
    fn ct_lan_sync_v2_large_first_merge_is_chunked_and_committed_atomically() {
        let a = context("large-a");
        let b = context("large-b");
        trust(&a, &b);
        trust(&b, &a);
        let path = a.runtime.lock().unwrap().current_path();
        let mut fixture = vaultmesh_core::VaultSession::unlock(
            "test master large-a",
            &std::fs::read(&path).unwrap(),
        )
        .unwrap();
        for i in 0..1_650 {
            fixture.add_item(serde_json::from_value(serde_json::json!({"title":format!("synthetic record {i}"),"username":"u","password":"synthetic password","url":"https://example.test","notes":"x".repeat(10_000),"folder":null,"favorite":false,"totp_secret":null,"recovery_codes":[],"additional_urls":[],"autofill_on_page_load":false,"master_password_reprompt":false,"custom_fields":[]})).unwrap()).unwrap();
        }
        fixture.sync_checkpoint(1).unwrap();
        let export = fixture.sync_export(&Default::default()).unwrap();
        assert!(serde_json::to_vec(&export).unwrap().len() > 16 * 1024 * 1024);
        drop(export);
        let encrypted = fixture.save().unwrap();
        assert!(
            encrypted.len() <= 64 * 1024 * 1024,
            "fixture must fit the existing Vault file limit"
        );
        std::fs::write(&path, encrypted).unwrap();
        drop(fixture);
        a.runtime.lock().unwrap().sync_pump().unwrap();
        let handles = live(&a, &b);
        let start = Instant::now();
        while b.runtime.lock().unwrap().status().item_count == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "large batch stalled"
            );
            assert!(
                !handles.iter().any(|h| h.is_finished()),
                "persistent transport closed early"
            );
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(b.runtime.lock().unwrap().status().item_count, 1_650);
        assert_eq!(
            a.runtime.lock().unwrap().sync_state().unwrap().entries,
            b.runtime.lock().unwrap().sync_state().unwrap().entries
        );
        stop_live(&[&a, &b], handles);
        cleanup(&a);
        cleanup(&b);
    }
    fn context(name: &str) -> Context {
        let path = std::env::temp_dir().join(format!(
            "vaultmesh-sync-test-{name}-{}.vault",
            Uuid::new_v4()
        ));
        let mut runtime = DesktopRuntime::new(path).unwrap();
        runtime.create(format!("test master {name}")).unwrap();
        let local = runtime.sync_state().unwrap().vault_id;
        let hub = runtime.sync_relay();
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
            hub,
            active_peers: Arc::new(Mutex::new(HashSet::new())),
            handshakes: Arc::new(AtomicUsize::new(0)),
            bootstraps: Arc::new(SessionRegistry::default()),
            #[cfg(test)]
            drop_receipt: Arc::new(AtomicBool::new(false)),
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
        let mut handles = live(a, b);
        let start = Instant::now();
        loop {
            if handles.iter().any(|h| h.is_finished()) {
                break;
            }
            let settled = [a, b].iter().all(|c| {
                c.hub.profile().unwrap().0.routes.iter().all(|r| {
                    r.incoming.is_some()
                        && c.hub
                            .summary(&r.peer)
                            .is_ok_and(|s| s.data.is_none() && s.received == s.applied)
                })
            });
            if settled && start.elapsed() > Duration::from_millis(200) {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "TLS exchange failed to settle"
            );
            thread::sleep(Duration::from_millis(20));
        }
        // Give a rejected peer time to observe the closed socket as well.
        if handles.iter().any(|h| h.is_finished()) {
            thread::sleep(Duration::from_millis(100));
        }
        a.stop.store(true, Ordering::Release);
        b.stop.store(true, Ordering::Release);
        let client = handles.pop().unwrap().join().unwrap();
        let server = handles.pop().unwrap().join().unwrap();
        a.stop.store(false, Ordering::Release);
        b.stop.store(false, Ordering::Release);
        (client, server)
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
    fn ct_lan_sync_reenable_rotates_channel_and_rejects_old_packets() {
        let a = context("epoch-a");
        let b = context("epoch-b");
        trust(&a, &b);
        trust(&b, &a);
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        add(&a, "before revoke");
        let peer = format!("lan-peer-{}", b.identity.device_id);
        let reverse = format!("lan-peer-{}", a.identity.device_id);
        let old = a.hub.peer(&peer).unwrap().outgoing.unwrap();
        let fp = hex_digest(&b.identity.cert);
        a.runtime
            .lock()
            .unwrap()
            .sync_authorize(&peer, &fp, false)
            .unwrap();
        assert!(a.hub.route(&peer).is_err());
        a.runtime
            .lock()
            .unwrap()
            .sync_authorize(&peer, &fp, true)
            .unwrap();
        assert_eq!(connect(&a, &b), (Ok(()), Ok(())));
        assert!(b.hub.store(&reverse, old, false).is_err());
        assert_eq!(b.runtime.lock().unwrap().status().item_count, 1);
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
        add(&b, "concurrent local edit");
        b.drop_receipt.store(true, Ordering::Release);
        assert!(connect(&a, &b).1.is_err());
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
                persistent::exchange(socket, false, None, &server)
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
                        sending: Uuid::new_v4(),
                        receiving: None,
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
            persistent::exchange(socket, false, None, &server)
        });
        assert!(
            persistent::exchange(
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
