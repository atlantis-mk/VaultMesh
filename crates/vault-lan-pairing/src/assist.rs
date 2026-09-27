//! Independent, short-lived device assistance. Never carries a Vault or sync packet.
use super::*;
use serde_json::Value;
use std::collections::VecDeque;
mod push;
static REGISTRATION_LOCK: Mutex<()> = Mutex::new(());
pub(crate) fn registration_guard() -> Result<std::sync::MutexGuard<'static, ()>, ()> {
    REGISTRATION_LOCK.lock().map_err(|_| ())
}

const SERVICE: &str = "_vm-assist._tcp.local.";
const TTL: Duration = Duration::from_secs(120);
const GRANTS: &str = "device-assist-grants-v1";

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Phone,
    Sms,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub peer: String,
    pub phone: bool,
    pub sms: bool,
    fingerprint: String,
    binding: String,
}
fn stored_grants(credentials: &dyn CredentialStore) -> Result<Vec<Grant>, ()> {
    let grants = match credentials.get(GRANTS)? {
        Some(raw) => serde_json::from_slice::<Vec<Grant>>(&raw).map_err(|_| ())?,
        None => vec![],
    };
    if grants.len() > MAX_PEERS {
        return Err(());
    }
    Ok(grants)
}

// Revoking pairing must survive a future re-pair with the same identity.
pub(crate) fn revoke_grant(credentials: &dyn CredentialStore, peer: &str) -> Result<(), ()> {
    push::revoke_registration(credentials, peer)?;
    let Ok(mut grants) = stored_grants(credentials) else {
        return credentials.delete(GRANTS);
    };
    grants.retain(|g| g.peer != peer);
    credentials.set(
        GRANTS,
        &Zeroizing::new(serde_json::to_vec(&grants).map_err(|_| ())?),
    )
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub kind: Kind,
    pub source: String,
    pub remaining_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<u64>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub id: String,
    pub peer: String,
    pub origin: String,
}
struct Code {
    id: String,
    value: Zeroizing<String>,
    source: String,
    expires: Instant,
    request: Option<(String, String)>,
    received_at: u64,
}
struct Request {
    peer: String,
    kind: Kind,
    origin: String,
    expires: Instant,
}
#[derive(Default)]
struct State {
    grants: Vec<Grant>,
    phone: Zeroizing<String>,
    codes: VecDeque<Code>,
    requests: HashMap<String, Request>,
    seen: HashMap<String, Instant>,
    retired: HashMap<String, Instant>,
    enabled: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    Watch,
    List {
        request: String,
        kind: Kind,
        origin: String,
    },
    Take {
        request: String,
        candidate: String,
    },
    Cancel {
        request: String,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    candidates: Vec<Candidate>,
    value: Option<String>,
}
impl Drop for Reply {
    fn drop(&mut self) {
        if let Some(v) = &mut self.value {
            v.zeroize();
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    instance: String,
}

struct Running {
    daemon: ServiceDaemon,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.sessions.shutdown_all();
        shutdown_daemon(&self.daemon);
    }
}

pub struct AssistHost {
    trust: TrustStore,
    state: Arc<Mutex<State>>,
    binding: String,
    valid: Arc<dyn Fn() -> bool + Send + Sync>,
    running: Option<Running>,
}
impl AssistHost {
    pub fn new(
        path: PathBuf,
        credentials: Arc<dyn CredentialStore>,
        binding: String,
        valid: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self, ()> {
        let grants = stored_grants(credentials.as_ref())?;
        Ok(Self {
            trust: TrustStore::with_credentials(path, credentials),
            state: Arc::new(Mutex::new(State {
                grants,
                ..State::default()
            })),
            binding,
            valid,
            running: None,
        })
    }
    pub fn matches_binding(&self, binding: &str) -> bool {
        self.binding == binding
    }

    pub fn grants(&self) -> Result<Vec<Grant>, ()> {
        if !(self.valid)() {
            return Err(());
        }
        let peers = self.trust.load()?;
        Ok(stored_grants(self.trust.credentials.as_ref())?
            .into_iter()
            .filter(|g| {
                g.binding == self.binding
                    && peers.iter().any(|p| {
                        p.pairing_ref == g.peer && p.certificate_fingerprint == g.fingerprint
                    })
            })
            .collect())
    }

    pub fn set_grant(&self, peer: &str, phone: bool, sms: bool) -> Result<(), ()> {
        if !(self.valid)() {
            return Err(());
        }
        let p = self
            .trust
            .load()?
            .into_iter()
            .find(|p| p.pairing_ref == peer)
            .ok_or(())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        let mut grants = stored_grants(self.trust.credentials.as_ref())?;
        grants.retain(|g| g.peer != peer && g.binding == self.binding);
        if phone || sms {
            grants.push(Grant {
                peer: peer.into(),
                phone,
                sms,
                fingerprint: p.certificate_fingerprint,
                binding: self.binding.clone(),
            });
        }
        if grants.len() > MAX_PEERS {
            return Err(());
        }
        let raw = Zeroizing::new(serde_json::to_vec(&grants).map_err(|_| ())?);
        self.trust.credentials.set(GRANTS, &raw)?;
        state.grants = grants;
        let retired: Vec<_> = state
            .requests
            .iter()
            .filter(|(_, r)| r.peer == peer)
            .map(|(id, _)| id.clone())
            .collect();
        for id in retired {
            state.requests.remove(&id);
            state.retired.insert(id, Instant::now() + TTL);
        }
        if !sms {
            state
                .codes
                .retain(|c| c.request.as_ref().is_none_or(|(_, p)| p != peer));
        }
        if !state.grants.iter().any(|g| g.sms) {
            state.codes.clear();
            state.seen.clear();
        }
        Ok(())
    }
    pub fn set_phone(&self, value: &str) -> Result<(), ()> {
        if value.len() > 24 || !value.bytes().all(|b| b.is_ascii_digit() || b == b'+') {
            return Err(());
        }
        self.state.lock().map_err(|_| ())?.phone = Zeroizing::new(value.to_owned());
        Ok(())
    }
    pub fn clear_sms(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.codes.retain(|c| c.request.is_some());
        }
    }
    pub fn add_code(
        &self,
        value: &str,
        source: &str,
        age_ms: u64,
        dedup: &str,
        request: Option<&str>,
    ) -> Result<(), ()> {
        if !(self.valid)()
            || !(4..=10).contains(&value.len())
            || !value.bytes().all(|b| b.is_ascii_alphanumeric())
            || source.len() > 128
            || source.chars().any(char::is_control)
            || age_ms >= 120_000
            || dedup.len() > 128
        {
            return Err(());
        }
        let mut s = self.state.lock().map_err(|_| ())?;
        prune(&mut s);
        s.grants = self.grants()?;
        if !s.enabled || !self.grants_for_state(&s).iter().any(|g| g.sms) {
            return Err(());
        }
        if s.seen.contains_key(dedup) {
            return Ok(());
        }
        let target = match request {
            Some(id) => {
                let r = s
                    .requests
                    .get(id)
                    .filter(|r| {
                        r.kind == Kind::Sms && s.grants.iter().any(|g| g.peer == r.peer && g.sms)
                    })
                    .ok_or(())?;
                Some((id.into(), r.peer.clone()))
            }
            None => None,
        };
        if s.codes.len() >= 20 {
            s.codes.pop_front();
        }
        // Dedup tombstones survive consumption for the original candidate lifetime.
        if s.seen.len() >= 128 {
            return Err(());
        }
        let expires = Instant::now() + TTL - Duration::from_millis(age_ms);
        let received_at = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64)
            .saturating_sub(age_ms);
        s.seen.insert(dedup.into(), expires);
        s.codes.push_back(Code {
            id: random_token(),
            value: Zeroizing::new(value.into()),
            source: source.into(),
            expires,
            request: target,
            received_at,
        });
        Ok(())
    }
    fn grants_for_state<'a>(&self, s: &'a State) -> Vec<&'a Grant> {
        s.grants
            .iter()
            .filter(|g| g.binding == self.binding)
            .collect()
    }
    pub fn pending(&self) -> Vec<Pending> {
        if !(self.valid)() {
            return vec![];
        }
        let Ok(mut s) = self.state.lock() else {
            return vec![];
        };
        prune(&mut s);
        s.requests
            .iter()
            .filter(|(_, r)| r.kind == Kind::Sms)
            .map(|(id, r)| Pending {
                id: id.clone(),
                peer: r.peer.clone(),
                origin: r.origin.clone(),
            })
            .collect()
    }
    pub fn start(&mut self) -> Result<(), ()> {
        if !(self.valid)() {
            self.stop();
            return Err(());
        }
        if self.running.is_some() {
            return Ok(());
        }
        let id =
            Arc::new(Identity::load_or_create(self.trust.credentials.as_ref()).map_err(|_| ())?);
        let listener = bind_listener().map_err(|_| ())?;
        listener.set_nonblocking(true).map_err(|_| ())?;
        let ipv4_only = listener.local_addr().map_err(|_| ())?.is_ipv4();
        let instance = random_token();
        let hostname = format!("{}.local.", random_token());
        let mut info = ServiceInfo::new(
            SERVICE,
            &instance,
            &hostname,
            "",
            listener.local_addr().map_err(|_| ())?.port(),
            &[("v", "1"), ("i", instance.as_str())][..],
        )
        .map_err(|_| ())?
        .enable_addr_auto();
        info.set_interfaces(vec![IfKind::Predicate(IfPredicate::new(move |i| {
            usable_interface_address(i.ip()) && (!ipv4_only || i.ip().is_ipv4())
        }))]);
        let daemon = ServiceDaemon::new().map_err(|_| ())?;
        if daemon.register(info).is_err() {
            shutdown_daemon(&daemon);
            return Err(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(SessionRegistry::default());
        self.state.lock().map_err(|_| ())?.enabled = true;
        let context = HostContext {
            state: self.state.clone(),
            trust: self.trust.clone(),
            binding: self.binding.clone(),
            valid: self.valid.clone(),
            id,
            instance,
            stop: stop.clone(),
            sessions: sessions.clone(),
        };
        thread::spawn(move || {
            let mut housekeeping = Instant::now();
            while !context.stop.load(Ordering::Acquire) {
                if let Ok((socket, addr)) = listener.accept() {
                    if same_link(addr.ip()) {
                        if let Ok(guard) = context.sessions.register(&socket) {
                            let c = context.clone();
                            thread::spawn(move || {
                                let _guard = guard;
                                let _ = serve(socket, &c);
                            });
                        }
                    }
                }
                if Instant::now() >= housekeeping {
                    housekeeping = Instant::now() + Duration::from_secs(1);
                    if let Ok(mut s) = context.state.lock() {
                        prune(&mut s);
                        s.grants =
                            stored_grants(context.trust.credentials.as_ref()).unwrap_or_default();
                        let trusted = context.trust.load().unwrap_or_default();
                        s.grants.retain(|g| {
                            g.binding == context.binding
                                && trusted.iter().any(|p| {
                                    p.pairing_ref == g.peer
                                        && p.certificate_fingerprint == g.fingerprint
                                })
                        });
                        if !s.grants.iter().any(|g| g.sms) {
                            s.codes.clear();
                        }
                        let sms_peers: HashSet<_> = s
                            .grants
                            .iter()
                            .filter(|g| g.sms)
                            .map(|g| g.peer.clone())
                            .collect();
                        s.codes.retain(|c| {
                            c.request
                                .as_ref()
                                .is_none_or(|(_, p)| sms_peers.contains(p))
                        });
                        let allowed: HashSet<_> = s.grants.iter().map(|g| g.peer.clone()).collect();
                        s.requests.retain(|_, r| allowed.contains(&r.peer));
                        if !(context.valid)() {
                            s.enabled = false;
                            s.phone.zeroize();
                            s.codes.clear();
                            s.requests.clear();
                        }
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        self.running = Some(Running {
            daemon,
            stop,
            sessions,
        });
        Ok(())
    }
    pub fn stop(&mut self) {
        self.running.take();
        if let Ok(mut s) = self.state.lock() {
            s.enabled = false;
            s.phone.zeroize();
            s.codes.clear();
            s.seen.clear();
            s.retired.clear();
            s.requests.clear();
        }
    }
}
impl Drop for AssistHost {
    fn drop(&mut self) {
        self.stop();
    }
}
#[derive(Clone)]
struct HostContext {
    state: Arc<Mutex<State>>,
    trust: TrustStore,
    binding: String,
    valid: Arc<dyn Fn() -> bool + Send + Sync>,
    id: Arc<Identity>,
    instance: String,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
}
fn prune(s: &mut State) {
    let now = Instant::now();
    s.codes.retain(|c| c.expires > now);
    s.retired.retain(|_, expiry| *expiry > now);
    for (id, _) in s.requests.iter().filter(|(_, r)| r.expires <= now) {
        s.retired.insert(id.clone(), now + TTL);
    }
    s.requests.retain(|_, r| r.expires > now);
    s.seen.retain(|_, t| *t > now);
}
fn allowed<'a>(s: &'a State, peer: &LanTrustedPeer, binding: &str, kind: Kind) -> bool {
    s.enabled
        && s.grants.iter().any(|g| {
            g.peer == peer.pairing_ref
                && g.fingerprint == peer.certificate_fingerprint
                && g.binding == binding
                && match kind {
                    Kind::Phone => g.phone,
                    Kind::Sms => g.sms,
                }
        })
}
fn valid_assist_origin(origin: &str) -> bool {
    if origin.len() > 512
        || origin.chars().any(char::is_whitespace)
        || origin.chars().any(char::is_control)
    {
        return false;
    }
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .is_some_and(|authority| {
            !authority.is_empty() && !authority.contains(['/', '?', '#', '@', '\\'])
        })
}
fn handle(s: &mut State, peer: &LanTrustedPeer, binding: &str, cmd: Command) -> Result<Reply, ()> {
    prune(s);
    let now = Instant::now();
    let mut reply = Reply {
        candidates: vec![],
        value: None,
    };
    match cmd {
        Command::Watch => return Err(()),
        Command::List {
            request,
            kind,
            origin,
        } => {
            if !valid_token(&request)
                || s.retired.contains_key(&request)
                || !valid_assist_origin(&origin)
                || !allowed(s, peer, binding, kind)
            {
                return Err(());
            }
            if let Some(r) = s.requests.get(&request) {
                if r.peer != peer.pairing_ref || r.kind != kind || r.origin != origin {
                    return Err(());
                }
            } else {
                if s.requests.len() >= 32 || s.requests.len() + s.retired.len() >= 256 {
                    return Err(());
                }
                s.requests.insert(
                    request.clone(),
                    Request {
                        peer: peer.pairing_ref.clone(),
                        kind,
                        origin,
                        expires: now + TTL,
                    },
                );
            }
            if kind == Kind::Phone && !s.phone.is_empty() {
                reply.candidates.push(Candidate {
                    id: "phone".into(),
                    kind,
                    received_at: None,
                    source: s
                        .phone
                        .chars()
                        .rev()
                        .take(4)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect(),
                    remaining_ms: s.requests[&request]
                        .expires
                        .saturating_duration_since(now)
                        .as_millis() as u64,
                });
            }
            if kind == Kind::Sms {
                reply.candidates = s
                    .codes
                    .iter()
                    .filter(|c| {
                        c.request
                            .as_ref()
                            .is_none_or(|(id, p)| id == &request && p == &peer.pairing_ref)
                    })
                    .map(|c| Candidate {
                        id: c.id.clone(),
                        kind,
                        received_at: Some(c.received_at),
                        source: c.source.clone(),
                        remaining_ms: c
                            .expires
                            .min(s.requests[&request].expires)
                            .saturating_duration_since(now)
                            .as_millis() as u64,
                    })
                    .collect();
            }
        }
        Command::Take { request, candidate } => {
            let r = s.requests.get(&request).ok_or(())?;
            if r.peer != peer.pairing_ref || !allowed(s, peer, binding, r.kind) {
                return Err(());
            }
            let r = s.requests.remove(&request).ok_or(())?;
            s.retired.insert(request.clone(), now + TTL);
            if r.kind == Kind::Phone {
                if candidate != "phone" || s.phone.is_empty() {
                    return Err(());
                }
                reply.value = Some(s.phone.to_string());
            } else {
                let i = s
                    .codes
                    .iter()
                    .position(|c| {
                        c.id == candidate
                            && c.request
                                .as_ref()
                                .is_none_or(|(id, p)| id == &request && p == &peer.pairing_ref)
                    })
                    .ok_or(())?;
                reply.value = Some(s.codes.remove(i).ok_or(())?.value.to_string());
            }
        }
        Command::Cancel { request } => {
            if s.requests
                .get(&request)
                .is_some_and(|r| r.peer == peer.pairing_ref)
            {
                s.requests.remove(&request);
                s.retired.insert(request.clone(), now + TTL);
                s.codes
                    .retain(|c| c.request.as_ref().is_none_or(|(id, _)| id != &request));
            }
        }
    }
    Ok(reply)
}
fn setup_socket(socket: &TcpStream) -> Result<(), ()> {
    socket.set_nonblocking(false).map_err(|_| ())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| ())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| ())?;
    Ok(())
}
fn trusted_cert(trust: &TrustStore, cert: &[u8]) -> Result<LanTrustedPeer, ()> {
    let fp = hex_digest(cert);
    trust
        .load()?
        .into_iter()
        .find(|p| p.certificate_fingerprint == fp)
        .ok_or(())
}
fn secret_write<T: Serialize>(s: &mut TlsStream, v: &T) -> Result<(), ()> {
    let b = Zeroizing::new(serde_json::to_vec(v).map_err(|_| ())?);
    if b.len() > MAX_FRAME {
        return Err(());
    }
    s.write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| s.write_all(&b))
        .and_then(|_| s.flush())
        .map_err(|_| ())
}
fn secret_read<T: for<'a> Deserialize<'a>>(s: &mut TlsStream) -> Result<T, ()> {
    let mut len = [0; 4];
    s.read_exact(&mut len).map_err(|_| ())?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(());
    }
    let mut b = Zeroizing::new(vec![0; n]);
    s.read_exact(&mut b).map_err(|_| ())?;
    serde_json::from_slice(&b).map_err(|_| ())
}
fn deadline(socket: &TcpStream) -> Result<mpsc::Sender<()>, ()> {
    let socket = socket.try_clone().map_err(|_| ())?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if matches!(
            rx.recv_timeout(Duration::from_secs(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    });
    Ok(tx)
}
fn serve(mut socket: TcpStream, c: &HostContext) -> Result<(), ()> {
    let _deadline = deadline(&socket)?;
    setup_socket(&socket)?;
    let cert = read_cert(&mut socket)?;
    let peer = trusted_cert(&c.trust, &cert)?;
    write_cert(&mut socket, &c.id.cert)?;
    let mut tls = server_tls(socket, &c.id, &cert)?;
    tls.complete_handshake()?;
    let hello: Hello = secret_read(&mut tls)?;
    if ![1, 2].contains(&hello.version) || hello.instance != c.instance {
        return Err(());
    }
    let command: Command = secret_read(&mut tls)?;
    if c.stop.load(Ordering::Acquire) || !(c.valid)() {
        return Err(());
    }
    let current = trusted_cert(&c.trust, &cert)?;
    if current.pairing_ref != peer.pairing_ref {
        return Err(());
    }
    if matches!(command, Command::Watch) {
        if hello.version != 2 {
            return Err(());
        }
        return push::serve_watch(&mut tls, c, &peer);
    }
    let reply = {
        let mut state = c.state.lock().map_err(|_| ())?;
        state.grants = stored_grants(c.trust.credentials.as_ref())?;
        handle(&mut state, &peer, &c.binding, command)?
    };
    secret_write(&mut tls, &reply)
}

#[derive(Clone)]
struct Remote {
    address: SocketAddr,
    instance: String,
    full: String,
    expires: Instant,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCandidate {
    pub id: String,
    pub peer: String,
    pub device: String,
    pub kind: Kind,
    pub source: String,
    pub remaining_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<u64>,
}
#[derive(Clone)]
struct Selection {
    remote: Option<Remote>,
    cached: bool,
    candidate: String,
    peer: String,
    expires: Instant,
}
struct Job {
    request: String,
    kind: Kind,
    origin: String,
    expires: Instant,
    busy: bool,
    selected: bool,
    selected_peer: Option<(String, String)>,
    candidates: Vec<RemoteCandidate>,
    selections: HashMap<String, Selection>,
    targets: Vec<Remote>,
    result: Option<Zeroizing<String>>,
    failed: bool,
}
pub struct AssistClient {
    trust: TrustStore,
    id: Arc<Identity>,
    remotes: Arc<Mutex<Vec<Remote>>>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    cache: Option<Arc<Mutex<push::Cache>>>,
    running: Running,
}
impl AssistClient {
    #[cfg(feature = "sync")]
    pub fn new(path: PathBuf) -> Result<Self, ()> {
        Self::with_credentials(path, Arc::new(PlatformCredentialStore))
    }
    pub fn with_credentials(
        path: PathBuf,
        credentials: Arc<dyn CredentialStore>,
    ) -> Result<Self, ()> {
        let id = Arc::new(Identity::load_or_create(credentials.as_ref()).map_err(|_| ())?);
        let trust = TrustStore::with_credentials(path, credentials);
        let daemon = ServiceDaemon::new().map_err(|_| ())?;
        let events = daemon.browse(SERVICE).map_err(|_| ())?;
        let stop = Arc::new(AtomicBool::new(false));
        let remotes = Arc::new(Mutex::new(Vec::<Remote>::new()));
        let targets = remotes.clone();
        let jobs = Arc::new(Mutex::new(HashMap::<String, Job>::new()));
        let expiring_jobs = jobs.clone();
        let stopped = stop.clone();
        thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                if let Ok(mut jobs) = expiring_jobs.lock() {
                    jobs.retain(|_, job| job.expires > Instant::now());
                }
                if let Ok(event) = events.recv_timeout(Duration::from_millis(200)) {
                    if let Ok(mut r) = targets.lock() {
                        r.retain(|e| e.expires > Instant::now());
                        match event {
                            ServiceEvent::ServiceResolved(info) => {
                                let p = info.get_properties();
                                let instance = p.get_property_val_str("i").unwrap_or("");
                                if p.len() != 2
                                    || p.get_property_val_str("v") != Some("1")
                                    || !valid_token(instance)
                                {
                                    continue;
                                }
                                r.retain(|e| e.full != info.get_fullname());
                                for ip in info.get_addresses().iter().take(MAX_ENDPOINT_ADDRESSES) {
                                    if !same_link(ip.to_ip_addr()) || r.len() >= 32 {
                                        continue;
                                    }
                                    let address = match ip {
                                        ScopedIp::V4(v) => {
                                            SocketAddr::new(IpAddr::V4(*v.addr()), info.get_port())
                                        }
                                        ScopedIp::V6(v) => SocketAddr::V6(SocketAddrV6::new(
                                            *v.addr(),
                                            info.get_port(),
                                            0,
                                            v.scope_id().index,
                                        )),
                                        _ => continue,
                                    };
                                    r.push(Remote {
                                        address,
                                        instance: instance.into(),
                                        full: info.get_fullname().into(),
                                        expires: Instant::now() + Duration::from_secs(120),
                                    });
                                }
                            }
                            ServiceEvent::ServiceRemoved(_, name) => r.retain(|e| e.full != name),
                            _ => {}
                        }
                    }
                }
            }
        });
        Ok(Self {
            trust,
            id,
            remotes,
            jobs,
            cache: None,
            running: Running {
                daemon,
                stop,
                sessions: Arc::new(SessionRegistry::default()),
            },
        })
    }
    pub fn enable_registration(&mut self, scope: &str) -> Result<(), ()> {
        if self.cache.is_some() {
            return Err(());
        }
        let cache = Arc::new(Mutex::new(push::Cache::new(
            self.trust.credentials.clone(),
            scope,
        )?));
        push::start(self, cache.clone());
        self.cache = Some(cache);
        Ok(())
    }
    fn cached(
        &self,
        kind: Kind,
        expires: Instant,
    ) -> Result<Vec<(RemoteCandidate, Selection)>, ()> {
        match &self.cache {
            Some(cache) => {
                cache
                    .lock()
                    .map_err(|_| ())?
                    .candidates(kind, &self.trust.load()?, expires)
            }
            None => Ok(vec![]),
        }
    }
    pub fn begin(&self, kind: Kind, origin: &str) -> Result<String, ()> {
        if !valid_assist_origin(origin) {
            return Err(());
        }
        let id = random_token();
        let mut jobs = self.jobs.lock().map_err(|_| ())?;
        jobs.retain(|_, j| j.expires > Instant::now());
        if jobs.len() >= 32 {
            return Err(());
        }
        jobs.insert(
            id.clone(),
            Job {
                request: id.clone(),
                kind,
                origin: origin.into(),
                expires: Instant::now() + TTL,
                busy: false,
                selected: false,
                selected_peer: None,
                candidates: vec![],
                selections: HashMap::new(),
                targets: vec![],
                result: None,
                failed: false,
            },
        );
        drop(jobs);
        self.refresh(&id)?;
        Ok(id)
    }
    pub fn refresh(&self, id: &str) -> Result<(), ()> {
        {
            let all = self.jobs.lock().map_err(|_| ())?;
            let j = all.get(id).ok_or(())?;
            if !self.cached(j.kind, j.expires)?.is_empty() {
                return Ok(());
            }
        }
        let (kind, origin, expires) = {
            let mut j = self.jobs.lock().map_err(|_| ())?;
            let job = j
                .get_mut(id)
                .filter(|j| j.expires > Instant::now())
                .ok_or(())?;
            if job.busy || job.selected || job.result.is_some() {
                return Ok(());
            }
            job.busy = true;
            (job.kind, job.origin.clone(), job.expires)
        };
        let remotes = self.remotes.lock().map_err(|_| ())?.clone();
        let jobs = self.jobs.clone();
        let request = id.to_owned();
        let identity = self.id.clone();
        let trust = self.trust.clone();
        let sessions = self.running.sessions.clone();
        let stop = self.running.stop.clone();
        thread::spawn(move || {
            let mut entries = vec![];
            let mut selections = HashMap::new();
            let mut peers = HashSet::new();
            let mut answered = HashSet::new();
            for remote in remotes {
                if answered.contains(&remote.instance) {
                    continue;
                }
                if stop.load(Ordering::Acquire)
                    || Instant::now() >= expires
                    || jobs
                        .lock()
                        .map(|j| j.get(&request).is_none_or(|job| job.selected))
                        .unwrap_or(true)
                {
                    break;
                }
                let sent = Instant::now();
                if let Ok((peer, reply)) = call(
                    &trust,
                    &identity,
                    &remote,
                    &Command::List {
                        request: request.clone(),
                        kind,
                        origin: origin.clone(),
                    },
                    &sessions,
                ) {
                    answered.insert(remote.instance.clone());
                    let live = if let Ok(mut all) = jobs.lock() {
                        if let Some(job) = all.get_mut(&request) {
                            if !job.targets.iter().any(|r| r.instance == remote.instance)
                                && job.targets.len() < MAX_PEERS
                            {
                                job.targets.push(remote.clone());
                            }
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !live {
                        let _ = call(
                            &trust,
                            &identity,
                            &remote,
                            &Command::Cancel {
                                request: request.clone(),
                            },
                            &sessions,
                        );
                        break;
                    }
                    if !peers.insert(peer.pairing_ref.clone()) {
                        continue;
                    }
                    for c in &reply.candidates {
                        if c.kind != kind
                            || c.source.len() > 128
                            || c.remaining_ms > 120_000
                            || c.remaining_ms == 0
                        {
                            continue;
                        }
                        let deadline = (sent + Duration::from_millis(c.remaining_ms)).min(expires);
                        if deadline <= Instant::now() {
                            continue;
                        }
                        let candidate_id = format!("{}:{}", peer.pairing_ref, c.id);
                        entries.push(RemoteCandidate {
                            id: candidate_id.clone(),
                            peer: peer.pairing_ref.clone(),
                            device: peer.label.clone(),
                            kind,
                            received_at: c.received_at,
                            source: c.source.clone(),
                            remaining_ms: deadline
                                .saturating_duration_since(Instant::now())
                                .as_millis() as u64,
                        });
                        selections.insert(
                            candidate_id,
                            Selection {
                                remote: Some(remote.clone()),
                                cached: false,
                                candidate: c.id.clone(),
                                peer: peer.pairing_ref.clone(),
                                expires: deadline,
                            },
                        );
                        if entries.len() >= 20 {
                            break;
                        }
                    }
                    // Publish authenticated candidates without waiting for other devices or addresses.
                    if let Ok(mut all) = jobs.lock() {
                        if let Some(j) = all.get_mut(&request) {
                            if !j.selected {
                                j.candidates = entries.clone();
                                j.selections = selections.clone();
                            }
                        }
                    }
                }
                if entries.len() >= 20 {
                    break;
                }
            }
            if let Ok(mut all) = jobs.lock() {
                if let Some(j) = all.get_mut(&request) {
                    if !j.selected {
                        j.busy = false;
                        j.candidates = entries;
                        j.selections = selections;
                    }
                }
            }
        });
        Ok(())
    }
    pub fn status(&self, id: &str) -> Result<Value, ()> {
        let mut all = self.jobs.lock().map_err(|_| ())?;
        all.retain(|_, j| j.expires > Instant::now());
        let j = all.get_mut(id).ok_or(())?;
        if !j.selected {
            // Re-read registration state so a received revocation also removes existing menu entries.
            let cached = self.cached(j.kind, j.expires)?;
            j.candidates
                .retain(|c| !j.selections.get(&c.id).is_some_and(|s| s.cached));
            j.selections.retain(|_, s| !s.cached);
            let cached_peers: HashSet<_> = cached.iter().map(|(c, _)| c.peer.as_str()).collect();
            j.candidates
                .retain(|c| !cached_peers.contains(c.peer.as_str()));
            for (candidate, selection) in cached {
                j.selections.insert(candidate.id.clone(), selection);
                j.candidates.insert(0, candidate);
            }
            j.candidates.truncate(20);
        }
        j.candidates.retain(|c| {
            if self
                .cache
                .as_ref()
                .is_some_and(|cache| cache.lock().map(|cch| cch.consumed(&c.id)).unwrap_or(true))
            {
                return false;
            }
            j.selections
                .get(&c.id)
                .is_some_and(|s| s.expires > Instant::now())
        });
        for candidate in &mut j.candidates {
            if let Some(s) = j.selections.get(&candidate.id) {
                candidate.remaining_ms = s
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64;
            }
        }
        Ok(
            serde_json::json!({"busy":j.busy,"failed":j.failed,"ready":j.result.is_some(),"candidates":j.candidates}),
        )
    }
    pub fn consume(&self, id: &str, selection: &str) -> Result<(), ()> {
        let peers = self.trust.load()?;
        let (remote, candidate, peer, expires) = {
            let mut all = self.jobs.lock().map_err(|_| ())?;
            let j = all
                .get_mut(id)
                .filter(|j| {
                    j.expires > Instant::now() && !j.selected && j.result.is_none() && !j.failed
                })
                .ok_or(())?;
            let s = j
                .selections
                .remove(selection)
                .filter(|s| s.expires > Instant::now())
                .ok_or(())?;
            if self.cache.as_ref().is_some_and(|cache| {
                cache
                    .lock()
                    .map(|c| {
                        c.consumed(&s.candidate)
                            || c.consumed(&format!("{}:{}", s.peer, s.candidate))
                    })
                    .unwrap_or(true)
            }) {
                return Err(());
            }
            j.expires = j.expires.min(s.expires);
            let trusted = peers.iter().find(|p| p.pairing_ref == s.peer).ok_or(())?;
            j.selected_peer = Some((
                trusted.pairing_ref.clone(),
                trusted.certificate_fingerprint.clone(),
            ));
            if s.cached {
                let value = self
                    .cache
                    .as_ref()
                    .ok_or(())?
                    .lock()
                    .map_err(|_| ())?
                    .value(&s.candidate, j.kind, &peers)?;
                j.selected = true;
                j.busy = false;
                j.result = Some(value);
                j.candidates.clear();
                j.selections.clear();
                return Ok(());
            }
            j.selected = true;
            j.busy = true;
            j.candidates.clear();
            j.selections.clear();
            (s.remote.ok_or(())?, s.candidate, s.peer, s.expires)
        };
        let jobs = self.jobs.clone();
        let request = id.to_owned();
        let trust = self.trust.clone();
        let identity = self.id.clone();
        let sessions = self.running.sessions.clone();
        thread::spawn(move || {
            let result = call(
                &trust,
                &identity,
                &remote,
                &Command::Take {
                    request: request.clone(),
                    candidate,
                },
                &sessions,
            )
            .ok()
            .and_then(|(p, mut r)| {
                if p.pairing_ref != peer || Instant::now() >= expires {
                    return None;
                }
                r.value.take().map(Zeroizing::new)
            });
            if let Ok(mut all) = jobs.lock() {
                if let Some(j) = all.get_mut(&request) {
                    j.busy = false;
                    j.failed = result.is_none();
                    j.result = result;
                }
            }
        });
        Ok(())
    }
    pub fn take(&self, id: &str) -> Result<Zeroizing<String>, ()> {
        let mut all = self.jobs.lock().map_err(|_| ())?;
        let j = all
            .get_mut(id)
            .filter(|j| j.expires > Instant::now())
            .ok_or(())?;
        let (peer, fingerprint) = j.selected_peer.as_ref().ok_or(())?;
        if !self
            .trust
            .load()?
            .iter()
            .any(|p| &p.pairing_ref == peer && &p.certificate_fingerprint == fingerprint)
        {
            return Err(());
        }
        let value = j.result.take().ok_or(())?;
        drop(all);
        self.cancel(id);
        Ok(value)
    }
    pub fn cancel(&self, id: &str) {
        let job = self.jobs.lock().ok().and_then(|mut j| j.remove(id));
        if let Some(job) = job {
            let remotes = job.targets;
            let trust = self.trust.clone();
            let identity = self.id.clone();
            let sessions = self.running.sessions.clone();
            thread::spawn(move || {
                for r in remotes {
                    let _ = call(
                        &trust,
                        &identity,
                        &r,
                        &Command::Cancel {
                            request: job.request.clone(),
                        },
                        &sessions,
                    );
                }
            });
        }
    }
    pub fn clear(&self) {
        self.running.stop.store(true, Ordering::Release);
        if let Some(cache) = &self.cache {
            if let Ok(mut c) = cache.lock() {
                c.clear_memory();
            }
        }
        if let Ok(mut j) = self.jobs.lock() {
            j.clear();
        }
        self.running.sessions.shutdown_all();
    }
}
impl Drop for AssistClient {
    fn drop(&mut self) {
        self.clear();
    }
}
fn call(
    trust: &TrustStore,
    id: &Identity,
    remote: &Remote,
    command: &Command,
    sessions: &Arc<SessionRegistry>,
) -> Result<(LanTrustedPeer, Reply), ()> {
    if !same_link(remote.address.ip()) {
        return Err(());
    }
    let mut socket =
        TcpStream::connect_timeout(&remote.address, Duration::from_secs(1)).map_err(|_| ())?;
    let _guard = sessions.register_with_limit(&socket, MAX_PEERS)?;
    let _deadline = deadline(&socket)?;
    setup_socket(&socket)?;
    write_cert(&mut socket, &id.cert)?;
    let cert = read_cert(&mut socket)?;
    let peer = trusted_cert(trust, &cert)?;
    let mut tls = client_tls(socket, id, &cert)?;
    tls.complete_handshake()?;
    secret_write(
        &mut tls,
        &Hello {
            version: 1,
            instance: remote.instance.clone(),
        },
    )?;
    secret_write(&mut tls, command)?;
    let reply: Reply = secret_read(&mut tls)?;
    trusted_cert(trust, &cert)?;
    Ok((peer, reply))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ct_device_assist_dns_sd_service_name_is_rfc_compliant() {
        assert!(
            super::SERVICE
                .split('.')
                .next()
                .unwrap()
                .trim_start_matches('_')
                .len()
                <= 15
        );
    }
    use super::*;
    fn peer(id: &Arc<Identity>) -> LanTrustedPeer {
        LanTrustedPeer {
            pairing_ref: format!("lan-peer-{}", id.device_id),
            certificate_fingerprint: hex_digest(&id.cert),
            label: "Synthetic device".into(),
            protocol_major: 2,
        }
    }
    pub(super) fn fixture() -> (AssistHost, Arc<Identity>, TrustStore, HostContext) {
        let store = super::super::tests::empty_store("assist-host");
        let client_store = super::super::tests::empty_store("assist-client");
        let server = Arc::new(Identity::load_or_create(store.credentials.as_ref()).unwrap());
        let client = Arc::new(Identity::load_or_create(client_store.credentials.as_ref()).unwrap());
        store.approve(peer(&client)).unwrap();
        client_store.approve(peer(&server)).unwrap();
        let host = AssistHost::new(
            store.path.clone(),
            store.credentials.clone(),
            "synthetic-vault:epoch".into(),
            Arc::new(|| true),
        )
        .unwrap();
        host.set_grant(&peer(&client).pairing_ref, true, true)
            .unwrap();
        host.state.lock().unwrap().enabled = true;
        let context = HostContext {
            state: host.state.clone(),
            trust: store,
            binding: host.binding.clone(),
            valid: host.valid.clone(),
            id: server,
            instance: random_token(),
            stop: Arc::new(AtomicBool::new(false)),
            sessions: Arc::new(SessionRegistry::default()),
        };
        (host, client, client_store, context)
    }
    fn roundtrip(
        context: &HostContext,
        client: &Identity,
        trust: &TrustStore,
        command: Command,
    ) -> Result<Reply, ()> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = Remote {
            address: listener.local_addr().unwrap(),
            instance: context.instance.clone(),
            full: "test".into(),
            expires: Instant::now() + TTL,
        };
        let c = context.clone();
        let server = thread::spawn(move || serve(listener.accept().unwrap().0, &c));
        let result = call(
            trust,
            client,
            &remote,
            &command,
            &Arc::new(SessionRegistry::default()),
        )
        .map(|(_, r)| r);
        let _ = server.join().unwrap();
        result
    }
    #[test]
    fn ct_device_assist_real_tls_phone_and_sms_once_no_secret_metadata() {
        real_tls_phone_and_sms("https://example.test");
    }
    #[test]
    fn ct_device_assist_http_phone_and_sms_still_use_authenticated_tls() {
        real_tls_phone_and_sms("http://localhost:4173");
        real_tls_phone_and_sms("http://example.test");
    }
    #[test]
    fn ct_device_assist_publishes_candidates_before_slow_remotes_and_skips_duplicate_addresses() {
        let (host, _, trust, context) = fixture();
        host.set_phone("15500001234").unwrap();
        let client =
            AssistClient::with_credentials(trust.path.clone(), trust.credentials.clone()).unwrap();
        let good = TcpListener::bind("127.0.0.1:0").unwrap();
        let duplicate = TcpListener::bind("127.0.0.1:0").unwrap();
        duplicate.set_nonblocking(true).unwrap();
        let slow = TcpListener::bind("127.0.0.1:0").unwrap();
        slow.set_nonblocking(true).unwrap();
        let remote = |listener: &TcpListener, instance: String| Remote {
            address: listener.local_addr().unwrap(),
            instance,
            full: "synthetic".into(),
            expires: Instant::now() + TTL,
        };
        *client.remotes.lock().unwrap() = vec![
            remote(&good, context.instance.clone()),
            remote(&duplicate, context.instance.clone()),
            remote(&slow, random_token()),
        ];
        let server = thread::spawn(move || serve(good.accept().unwrap().0, &context));
        let request = client.begin(Kind::Phone, "http://example.test").unwrap();
        client.refresh(&request).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            if !client.status(&request).unwrap()["candidates"]
                .as_array()
                .unwrap()
                .is_empty()
            {
                break;
            }
            assert!(
                Instant::now() < end,
                "healthy candidate waited for unrelated slow endpoint"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(server.join().unwrap().is_ok());
        let status = client.status(&request).unwrap();
        assert_eq!(status["candidates"].as_array().unwrap().len(), 1);
        assert!(!status.to_string().contains("1550000"));
        // A pending unrelated peer must not delay visibility or cause a second connection to the same phone.
        let _slow_connection = loop {
            if let Ok(connection) = slow.accept() {
                break connection;
            }
            assert!(
                Instant::now() < end,
                "duplicate address blocked the next device"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert!(duplicate.accept().is_err());
        client.clear();
    }
    #[test]
    fn ct_device_assist_origin_rejects_non_web_and_non_origin_strings() {
        for origin in [
            "file:///tmp/form",
            "data:text/html,x",
            "ftp://example.test",
            "https://",
            "http://x/path",
            "http://x?query",
            "http://user@x",
            "http://x\n",
        ] {
            assert!(!valid_assist_origin(origin), "{origin}");
        }
        assert!(valid_assist_origin("http://[::1]:4173"));
    }
    fn real_tls_phone_and_sms(origin: &str) {
        let (host, client, trust, c) = fixture();
        host.set_phone("15500001234").unwrap();
        let request = random_token();
        let list = roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: request.clone(),
                kind: Kind::Phone,
                origin: origin.into(),
            },
        )
        .unwrap();
        let raw = serde_json::to_string(&list).unwrap();
        assert!(!raw.contains("1550000"));
        assert_eq!(list.candidates[0].source, "1234");
        assert_eq!(
            roundtrip(
                &c,
                &client,
                &trust,
                Command::Take {
                    request: request.clone(),
                    candidate: "phone".into()
                }
            )
            .unwrap()
            .value
            .as_deref(),
            Some("15500001234")
        );
        assert!(roundtrip(
            &c,
            &client,
            &trust,
            Command::Take {
                request,
                candidate: "phone".into()
            }
        )
        .is_err());
        host.add_code("428193", "Synthetic SMS", 0, "message-1", None)
            .unwrap();
        let request = random_token();
        let list = roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: request.clone(),
                kind: Kind::Sms,
                origin: origin.into(),
            },
        )
        .unwrap();
        assert!(!serde_json::to_string(&list).unwrap().contains("428193"));
        let candidate = list.candidates[0].id.clone();
        assert_eq!(
            roundtrip(
                &c,
                &client,
                &trust,
                Command::Take {
                    request: request.clone(),
                    candidate: candidate.clone()
                }
            )
            .unwrap()
            .value
            .as_deref(),
            Some("428193")
        );
        host.add_code("428193", "Synthetic SMS", 0, "message-1", None)
            .unwrap();
        assert!(host.state.lock().unwrap().codes.is_empty());
        let other = random_token();
        roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: other.clone(),
                kind: Kind::Sms,
                origin: origin.into(),
            },
        )
        .unwrap();
        assert!(roundtrip(
            &c,
            &client,
            &trust,
            Command::Take {
                request: other,
                candidate
            }
        )
        .is_err());
    }
    #[test]
    fn ct_device_assist_grant_epoch_revocation_expiry_and_manual_binding() {
        let (host, client, trust, c) = fixture();
        let p = peer(&client);
        let request = random_token();
        assert!(host
            .add_code("428193", "source", 120_000, "old", None)
            .is_err());
        roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: request.clone(),
                kind: Kind::Sms,
                origin: "https://example.test".into(),
            },
        )
        .unwrap();
        host.add_code("428193", "manual", 0, "manual-1", Some(&request))
            .unwrap();
        let other = random_token();
        let list = roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: other,
                kind: Kind::Sms,
                origin: "https://other.test".into(),
            },
        )
        .unwrap();
        assert!(list.candidates.is_empty());
        roundtrip(
            &c,
            &client,
            &trust,
            Command::Cancel {
                request: request.clone(),
            },
        )
        .unwrap();
        assert!(host.state.lock().unwrap().codes.is_empty());
        host.set_grant(&p.pairing_ref, true, false).unwrap();
        assert!(roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: random_token(),
                kind: Kind::Sms,
                origin: "https://example.test".into()
            }
        )
        .is_err());
        let replacement = AssistHost::new(
            c.trust.path.clone(),
            c.trust.credentials.clone(),
            "different-epoch".into(),
            Arc::new(|| true),
        )
        .unwrap();
        assert!(replacement.grants().unwrap().is_empty());
        host.set_phone("15500001234").unwrap();
        let req = random_token();
        roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: req.clone(),
                kind: Kind::Phone,
                origin: "https://example.test".into(),
            },
        )
        .unwrap();
        host.state
            .lock()
            .unwrap()
            .requests
            .get_mut(&req)
            .unwrap()
            .expires = Instant::now();
        assert!(roundtrip(
            &c,
            &client,
            &trust,
            Command::Take {
                request: req,
                candidate: "phone".into()
            }
        )
        .is_err());
        c.trust
            .credentials
            .delete(&proof_account(&p.pairing_ref))
            .unwrap();
        assert!(roundtrip(
            &c,
            &client,
            &trust,
            Command::List {
                request: random_token(),
                kind: Kind::Phone,
                origin: "https://example.test".into()
            }
        )
        .is_err());
    }
    #[test]
    fn ct_device_assist_global_atomic_consume_under_race() {
        let (host, client, _, c) = fixture();
        let p = peer(&client);
        host.add_code("428193", "source", 0, "race", None).unwrap();
        let mut handles = vec![];
        let barrier = Arc::new(std::sync::Barrier::new(8));
        for _ in 0..8 {
            let id = random_token();
            let list = handle(
                &mut host.state.lock().unwrap(),
                &p,
                &c.binding,
                Command::List {
                    request: id.clone(),
                    kind: Kind::Sms,
                    origin: "https://example.test".into(),
                },
            )
            .unwrap();
            let candidate = list.candidates[0].id.clone();
            let state = host.state.clone();
            let peer = p.clone();
            let binding = c.binding.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                handle(
                    &mut state.lock().unwrap(),
                    &peer,
                    &binding,
                    Command::Take {
                        request: id,
                        candidate,
                    },
                )
                .is_ok()
            }));
        }
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn ct_device_assist_queue_expiry_and_closed_request_replay() {
        let (host, client, _, c) = fixture();
        for i in 0..21 {
            host.add_code("123456", "synthetic", 0, &format!("message-{i}"), None)
                .unwrap();
        }
        assert_eq!(host.state.lock().unwrap().codes.len(), 20);
        let request = random_token();
        let mut state = host.state.lock().unwrap();
        let p = peer(&client);
        handle(
            &mut state,
            &p,
            &c.binding,
            Command::List {
                request: request.clone(),
                kind: Kind::Sms,
                origin: "https://example.test".into(),
            },
        )
        .unwrap();
        handle(
            &mut state,
            &p,
            &c.binding,
            Command::Cancel {
                request: request.clone(),
            },
        )
        .unwrap();
        assert!(handle(
            &mut state,
            &p,
            &c.binding,
            Command::List {
                request,
                kind: Kind::Sms,
                origin: "https://example.test".into()
            }
        )
        .is_err());
        for code in &mut state.codes {
            code.expires = Instant::now();
        }
        prune(&mut state);
        assert!(state.codes.is_empty());
    }
    #[test]
    fn ct_device_assist_tls_rejects_unknown_version_and_oversized_frame() {
        let (_host, client, _, context) = fixture();
        for oversized in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let c = context.clone();
            let server = thread::spawn(move || serve(listener.accept().unwrap().0, &c));
            let mut socket = TcpStream::connect(address).unwrap();
            setup_socket(&socket).unwrap();
            write_cert(&mut socket, &client.cert).unwrap();
            let cert = read_cert(&mut socket).unwrap();
            let mut tls = client_tls(socket, &client, &cert).unwrap();
            tls.complete_handshake().unwrap();
            if oversized {
                tls.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                    .unwrap();
                tls.flush().unwrap();
            } else {
                secret_write(
                    &mut tls,
                    &Hello {
                        version: 99,
                        instance: context.instance.clone(),
                    },
                )
                .unwrap();
            }
            assert!(secret_read::<Reply>(&mut tls).is_err());
            assert!(server.join().unwrap().is_err());
        }
    }
    #[test]
    fn ct_device_assist_repair_same_identity_does_not_restore_grants() {
        let (host, client, _, c) = fixture();
        let p = peer(&client);
        assert_eq!(host.grants().unwrap().len(), 1);
        c.trust.revoke(&p.pairing_ref).unwrap();
        c.trust.approve(p).unwrap();
        assert!(host.grants().unwrap().is_empty());
        assert!(host
            .add_code("123456", "synthetic", 0, "after-repair", None)
            .is_err());
    }
}
