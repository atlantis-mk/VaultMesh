//! Isolated LAN discovery/pairing owner; this module never receives a Vault runtime.
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use mdns_sd::{IfKind, IfPredicate, ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperties};
use rand_core::{OsRng, RngCore};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use spake2_conflux::{Identity as SpakeIdentity, Password, RistrettoGroup, Spake2};
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL: u8 = 1;
const PROTOCOL_TXT: &str = "1.1";
const SERVICE_TYPE: &str = "_vaultmesh-pair._tcp.local.";
const DISCOVERY_TTL: Duration = Duration::from_secs(600);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PEERS: usize = 32;
const MAX_FRAME: usize = 16 * 1024;
const MAX_CERT: usize = 8 * 1024;
const MAX_HANDSHAKES: usize = 8;
const MAX_CODE_ATTEMPTS: usize = 5;
const KEYRING_SERVICE: &str = "com.vaultmesh.desktop.lan-pairing";
const IDENTITY_ACCOUNT: &str = "device-identity-v1";
const PREFACE: &[u8; 8] = b"VMPAIR01";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LanNearbyDevice {
    pub pairing_ref: String,
    pub status: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LanTrustedPeer {
    pairing_ref: String,
    certificate_fingerprint: String,
    label: String,
    protocol_major: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LanTrustedPeerDto {
    pub pairing_ref: String,
    pub label: String,
    pub protocol_major: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LanPairingStatus {
    pub discoverable: bool,
    pub expires_at: Option<u64>,
    pub pairing_code: Option<String>,
    pub nearby: Vec<LanNearbyDevice>,
    pub trusted: Vec<LanTrustedPeerDto>,
}

impl LanTrustedPeer {
    fn valid(&self) -> bool {
        valid_reference(&self.pairing_ref)
            && valid_fingerprint(&self.certificate_fingerprint)
            && !self.label.is_empty()
            && self.label.chars().count() <= 64
            && self.label.len() <= 256
            && self.protocol_major == PROTOCOL
    }
    fn dto(self) -> LanTrustedPeerDto {
        LanTrustedPeerDto {
            pairing_ref: self.pairing_ref,
            label: self.label,
            protocol_major: self.protocol_major,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeerIndex {
    version: u8,
    peers: Vec<LanTrustedPeer>,
}

#[derive(Clone)]
struct TrustStore {
    path: PathBuf,
    credentials: Arc<dyn CredentialStore>,
    #[cfg(test)]
    fail_save: Arc<AtomicBool>,
}
impl TrustStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            credentials: Arc::new(PlatformCredentialStore),
            #[cfg(test)]
            fail_save: Arc::new(AtomicBool::new(false)),
        }
    }
    #[cfg(test)]
    fn memory(path: PathBuf, credentials: Arc<dyn CredentialStore>) -> Self {
        Self {
            path,
            credentials,
            fail_save: Arc::new(AtomicBool::new(false)),
        }
    }
    fn load(&self) -> Result<Vec<LanTrustedPeer>, ()> {
        let value = self.load_index()?;
        let mut peers = Vec::with_capacity(value.peers.len());
        for peer in value.peers {
            let Some(proof) = self.credentials.get(&proof_account(&peer.pairing_ref))? else {
                continue;
            };
            if proof.as_slice() == peer.certificate_fingerprint.as_bytes() {
                peers.push(peer);
            }
        }
        Ok(peers)
    }
    fn load_index(&self) -> Result<PeerIndex, ()> {
        let bytes = match std::fs::read(&self.path) {
            Ok(v) if v.len() <= 128 * 1024 => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PeerIndex {
                    version: 1,
                    peers: vec![],
                });
            }
            _ => return Err(()),
        };
        let value: PeerIndex = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if value.version != 1
            || value.peers.len() > MAX_PEERS
            || value.peers.iter().any(|p| !p.valid())
        {
            return Err(());
        }
        Ok(value)
    }
    fn save(&self, peers: &[LanTrustedPeer]) -> Result<(), ()> {
        #[cfg(test)]
        if self.fail_save.load(Ordering::Acquire) {
            return Err(());
        }
        write_private(
            &self.path,
            &serde_json::to_vec(&PeerIndex {
                version: 1,
                peers: peers.to_vec(),
            })
            .map_err(|_| ())?,
        )
    }
    fn approve(&self, peer: LanTrustedPeer) -> Result<(), ()> {
        if !peer.valid() {
            return Err(());
        }
        let mut peers = self.load()?;
        let mut peer = peer;
        if let Some(existing) = peers.iter().find(|known| {
            known.pairing_ref == peer.pairing_ref
                && known.certificate_fingerprint == peer.certificate_fingerprint
        }) {
            peer.label.clone_from(&existing.label);
        }
        let account = proof_account(&peer.pairing_ref);
        let previous_proof = self.credentials.get(&account)?;
        self.credentials
            .set(&account, peer.certificate_fingerprint.as_bytes())?;
        peers.retain(|p| p.pairing_ref != peer.pairing_ref);
        peers.push(peer);
        peers.sort_by(|a, b| a.pairing_ref.cmp(&b.pairing_ref));
        if self.save(&peers).is_err() {
            if let Some(previous) = previous_proof {
                let _ = self.credentials.set(&account, previous.as_ref());
            } else {
                let _ = self.credentials.delete(&account);
            }
            return Err(());
        }
        Ok(())
    }
    fn revoke(&self, reference: &str) -> Result<(), ()> {
        let mut peers = self.load()?;
        let account = proof_account(reference);
        let previous_proof = self.credentials.get(&account)?;
        self.credentials.delete(&account)?;
        peers.retain(|p| p.pairing_ref != reference);
        if self.save(&peers).is_err() {
            if let Some(previous) = previous_proof {
                let _ = self.credentials.set(&account, previous.as_ref());
            }
            return Err(());
        }
        Ok(())
    }
    fn rename(&self, reference: &str, label: &str) -> Result<(), ()> {
        let label = label.trim();
        if !valid_reference(reference)
            || label.is_empty()
            || label.chars().count() > 64
            || label.len() > 256
        {
            return Err(());
        }
        let mut peers = self.load()?;
        peers
            .iter_mut()
            .find(|p| p.pairing_ref == reference)
            .ok_or(())?
            .label = label.into();
        self.save(&peers)
    }
}

trait CredentialStore: Send + Sync {
    fn set(&self, account: &str, value: &[u8]) -> Result<(), ()>;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()>;
    fn delete(&self, account: &str) -> Result<(), ()>;
}

struct PlatformCredentialStore;
impl CredentialStore for PlatformCredentialStore {
    fn set(&self, account: &str, value: &[u8]) -> Result<(), ()> {
        secret_set(account, value)
    }
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        secret_get(account)
    }
    fn delete(&self, account: &str) -> Result<(), ()> {
        secret_delete(account)
    }
}

#[derive(Clone)]
struct Identity {
    cert: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    device_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredIdentity {
    version: u8,
    device_id: String,
    certificate: String,
    private_key: String,
}
impl Drop for StoredIdentity {
    fn drop(&mut self) {
        self.device_id.zeroize();
        self.certificate.zeroize();
        self.private_key.zeroize();
    }
}
impl Identity {
    fn load_or_create() -> Result<Self, String> {
        if let Some(raw) = secret_get(IDENTITY_ACCOUNT).map_err(|_| "无法读取局域网设备身份。")?
        {
            let value: StoredIdentity =
                serde_json::from_slice(raw.as_ref()).map_err(|_| "局域网设备身份已损坏。")?;
            if value.version != 1 {
                return Err("局域网设备身份版本不兼容。".into());
            }
            return Self::parts(
                BASE64
                    .decode(value.certificate.as_bytes())
                    .map_err(|_| "局域网设备身份已损坏。")?,
                Zeroizing::new(
                    BASE64
                        .decode(value.private_key.as_bytes())
                        .map_err(|_| "局域网设备身份已损坏。")?,
                ),
                value.device_id.clone(),
            );
        }
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["vaultmesh.local".into()])
                .map_err(|_| "无法生成局域网设备身份。")?;
        let identity = Self::parts(
            cert.der().to_vec(),
            Zeroizing::new(signing_key.serialize_der()),
            random_token(),
        )?;
        let value = Zeroizing::new(
            serde_json::to_vec(&StoredIdentity {
                version: 1,
                device_id: identity.device_id.clone(),
                certificate: BASE64.encode(&identity.cert),
                private_key: BASE64.encode(identity.key.as_slice()),
            })
            .map_err(|_| "无法保存局域网设备身份。")?,
        );
        secret_set(IDENTITY_ACCOUNT, value.as_ref()).map_err(|_| "无法保存局域网设备身份。")?;
        Ok(identity)
    }
    fn parts(cert: Vec<u8>, key: Zeroizing<Vec<u8>>, device_id: String) -> Result<Self, String> {
        if cert.is_empty()
            || cert.len() > MAX_CERT
            || key.is_empty()
            || key.len() > MAX_CERT
            || !valid_token(&device_id)
        {
            Err("局域网设备身份已损坏。".into())
        } else {
            Ok(Self {
                cert,
                key,
                device_id,
            })
        }
    }
}

#[derive(Clone)]
struct Endpoint {
    instance: String,
    fullname: String,
    nonce: String,
    addresses: Vec<IpAddr>,
    port: u16,
}
struct Active {
    daemon: ServiceDaemon,
    fullname: String,
    browse: mdns_sd::Receiver<ServiceEvent>,
    instance: String,
    nonce: String,
    pairing_code: Arc<Zeroizing<String>>,
    failed_code_attempts: Arc<AtomicUsize>,
    endpoints: HashMap<String, Endpoint>,
    stop: Arc<AtomicBool>,
    sessions: Arc<SessionRegistry>,
    expires: Instant,
}
#[derive(Clone)]
struct PairingContext {
    identity: Arc<Identity>,
    instance: String,
    nonce: String,
    pairing_code: Arc<Zeroizing<String>>,
    failed_code_attempts: Arc<AtomicUsize>,
    tx: Sender<Event>,
    trust: TrustStore,
    sessions: Arc<SessionRegistry>,
}
#[derive(Default)]
struct SessionRegistry {
    next: AtomicU64,
    sockets: Mutex<HashMap<u64, TcpStream>>,
    peers: Mutex<HashMap<String, u64>>,
    pairing_intents: Mutex<HashMap<String, Instant>>,
    pairing_collisions: Mutex<HashMap<String, Instant>>,
}
struct SessionGuard {
    id: u64,
    sessions: Arc<SessionRegistry>,
}
impl SessionRegistry {
    fn register(self: &Arc<Self>, socket: &TcpStream) -> Result<SessionGuard, ()> {
        let mut sockets = self.sockets.lock().map_err(|_| ())?;
        if sockets.len() >= MAX_HANDSHAKES {
            return Err(());
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        sockets.insert(id, socket.try_clone().map_err(|_| ())?);
        Ok(SessionGuard {
            id,
            sessions: Arc::clone(self),
        })
    }
    fn shutdown_all(&self) {
        if let Ok(mut sockets) = self.sockets.lock() {
            for (_, socket) in sockets.drain() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
        if let Ok(mut peers) = self.peers.lock() {
            peers.clear();
        }
        if let Ok(mut intents) = self.pairing_intents.lock() {
            intents.clear();
        }
        if let Ok(mut collisions) = self.pairing_collisions.lock() {
            collisions.clear();
        }
    }
    fn bind_peer(&self, session: &SessionGuard, reference: &str) -> Result<(), ()> {
        self.peers
            .lock()
            .map_err(|_| ())?
            .insert(reference.to_owned(), session.id);
        Ok(())
    }
    fn shutdown_peer(&self, reference: &str) {
        let id = self.peers.lock().ok().and_then(|mut p| p.remove(reference));
        if let Some(socket) = id.and_then(|id| {
            self.sockets
                .lock()
                .ok()
                .and_then(|sockets| sockets.get(&id).and_then(|socket| socket.try_clone().ok()))
        }) {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }

    fn mark_pairing_intent(&self, instance: &str) -> Result<(), ()> {
        self.pairing_intents
            .lock()
            .map_err(|_| ())?
            .insert(instance.to_owned(), Instant::now() + IO_TIMEOUT);
        Ok(())
    }

    fn has_pairing_intent(&self, instance: &str) -> bool {
        let Ok(mut intents) = self.pairing_intents.lock() else {
            return false;
        };
        let now = Instant::now();
        intents.retain(|_, expires| *expires > now);
        intents.contains_key(instance)
    }

    fn mark_pairing_collision(&self, instance: &str) -> Result<(), ()> {
        self.pairing_collisions
            .lock()
            .map_err(|_| ())?
            .insert(instance.to_owned(), Instant::now() + IO_TIMEOUT);
        Ok(())
    }

    fn has_pairing_collision(&self, instance: &str) -> bool {
        let Ok(mut collisions) = self.pairing_collisions.lock() else {
            return false;
        };
        let now = Instant::now();
        collisions.retain(|_, expires| *expires > now);
        collisions.contains_key(instance)
    }
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.sessions.sockets.lock() {
            sockets.remove(&self.id);
        }
        if let Ok(mut peers) = self.sessions.peers.lock() {
            peers.retain(|_, id| *id != self.id);
        }
    }
}
enum Event {
    Complete {
        peer: LanTrustedPeer,
        persisted: Sender<bool>,
    },
    Rollback {
        peer_ref: String,
        rolled_back: Sender<bool>,
    },
    Connected {
        instance: String,
        peer_ref: String,
    },
    Closed {
        instance: String,
        peer_ref: Option<String>,
        failure: Option<&'static str>,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Hello {
    version: u8,
    instance: String,
    nonce: String,
    device_id: String,
    pairing_intent: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PakeMessage {
    message: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyConfirmation {
    mac: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistenceState {
    persisted: bool,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustState {
    trusted: bool,
    blocked: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionPing {
    version: u8,
}

enum TlsStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}
impl Read for TlsStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(s) => s.read(b),
            Self::Server(s) => s.read(b),
        }
    }
}
impl Write for TlsStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(s) => s.write(b),
            Self::Server(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Client(s) => s.flush(),
            Self::Server(s) => s.flush(),
        }
    }
}
impl TlsStream {
    fn complete_handshake(&mut self) -> Result<(), ()> {
        match self {
            Self::Client(stream) => {
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock).map_err(|_| ())?;
                }
            }
            Self::Server(stream) => {
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock).map_err(|_| ())?;
                }
            }
        }
        Ok(())
    }

    fn exporter(&self) -> Result<[u8; 32], ()> {
        let out = [0; 32];
        match self {
            Self::Client(s) => {
                s.conn
                    .export_keying_material(out, b"vaultmesh-lan-pairing-v1", None)
            }
            Self::Server(s) => {
                s.conn
                    .export_keying_material(out, b"vaultmesh-lan-pairing-v1", None)
            }
        }
        .map_err(|_| ())
    }
}

pub(crate) struct LanPairingService {
    active: Option<Active>,
    nearby: HashMap<String, LanNearbyDevice>,
    in_flight: HashSet<String>,
    auto_attempted: HashSet<String>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    identity: Option<Arc<Identity>>,
    trust: TrustStore,
}
impl LanPairingService {
    pub(crate) fn new(path: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            active: None,
            nearby: HashMap::new(),
            in_flight: HashSet::new(),
            auto_attempted: HashSet::new(),
            tx,
            rx,
            identity: None,
            trust: TrustStore::new(path),
        }
    }
    pub(crate) fn status(&mut self, now: Instant, now_ms: u64) -> LanPairingStatus {
        self.prune(now, now_ms);
        self.collect_discovery();
        self.collect_events(now, now_ms);
        self.auto_reconnect();
        let expires_at = self
            .active
            .as_ref()
            .map(|a| now_ms + a.expires.saturating_duration_since(now).as_millis() as u64);
        let mut nearby = self.nearby.values().cloned().collect::<Vec<_>>();
        nearby.sort_by(|a, b| a.pairing_ref.cmp(&b.pairing_ref));
        LanPairingStatus {
            discoverable: self.active.is_some(),
            expires_at,
            pairing_code: self.active.as_ref().and_then(|active| {
                (active.failed_code_attempts.load(Ordering::Acquire) < MAX_CODE_ATTEMPTS)
                    .then(|| active.pairing_code.as_ref().as_str().to_owned())
            }),
            nearby,
            trusted: self
                .trust
                .load()
                .unwrap_or_default()
                .into_iter()
                .map(LanTrustedPeer::dto)
                .collect(),
        }
    }
    pub(crate) fn start(&mut self, now: Instant) -> Result<(), String> {
        self.stop();
        let identity = Arc::new(Identity::load_or_create()?);
        let listener = bind_listener().map_err(|_| "无法启动局域网配对监听。")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "无法启动局域网配对监听。")?;
        let port = listener
            .local_addr()
            .map_err(|_| "无法启动局域网配对监听。")?
            .port();
        let instance = random_token();
        let nonce = random_token();
        let pairing_code = Arc::new(Zeroizing::new(random_pairing_code()));
        let failed_code_attempts = Arc::new(AtomicUsize::new(0));
        let hostname = format!("{}.local.", random_token());
        let props = [
            ("v", PROTOCOL_TXT),
            ("i", instance.as_str()),
            ("n", nonce.as_str()),
        ];
        let mut info = ServiceInfo::new(SERVICE_TYPE, &instance, &hostname, "", port, &props[..])
            .map_err(|_| "无法启动局域网发现。")?
            .enable_addr_auto();
        info.set_interfaces(vec![IfKind::Predicate(IfPredicate::new(|interface| {
            usable_interface_address(interface.ip())
        }))]);
        let fullname = info.get_fullname().to_owned();
        let daemon = ServiceDaemon::new().map_err(|_| "无法启动局域网发现。")?;
        if daemon.register(info).is_err() {
            shutdown_daemon(&daemon);
            return Err("无法启动局域网发现。".into());
        }
        let browse = match daemon.browse(SERVICE_TYPE) {
            Ok(browse) => browse,
            Err(_) => {
                let _ = daemon.unregister(&fullname);
                shutdown_daemon(&daemon);
                return Err("无法启动局域网扫描。".into());
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(SessionRegistry::default());
        accept_loop(
            listener,
            stop.clone(),
            PairingContext {
                identity: identity.clone(),
                instance: instance.clone(),
                nonce: nonce.clone(),
                pairing_code: pairing_code.clone(),
                failed_code_attempts: failed_code_attempts.clone(),
                tx: self.tx.clone(),
                trust: self.trust.clone(),
                sessions: sessions.clone(),
            },
        );
        self.identity = Some(identity);
        self.active = Some(Active {
            daemon,
            fullname,
            browse,
            instance,
            nonce,
            pairing_code,
            failed_code_attempts,
            endpoints: HashMap::new(),
            stop,
            sessions,
            expires: now + DISCOVERY_TTL,
        });
        Ok(())
    }
    pub(crate) fn list_trusted(&self) -> Result<Vec<LanTrustedPeerDto>, String> {
        self.trust
            .load()
            .map(|peers| peers.into_iter().map(LanTrustedPeer::dto).collect())
            .map_err(|_| "无法读取已配对设备。".to_owned())
    }
    pub(crate) fn is_active(&self) -> bool {
        self.active.is_some()
    }
    pub(crate) fn begin(
        &mut self,
        reference: &str,
        pairing_code: Zeroizing<String>,
    ) -> Result<(), String> {
        if !valid_pairing_code(&pairing_code) {
            return Err("请输入六位数字配对码。".into());
        }
        self.collect_discovery();
        self.spawn_connection(reference, Some(pairing_code))
    }
    fn spawn_connection(
        &mut self,
        reference: &str,
        pairing_code: Option<Zeroizing<String>>,
    ) -> Result<(), String> {
        let id = reference
            .strip_prefix("lan-peer-")
            .filter(|v| valid_token(v))
            .ok_or("设备引用无效。")?;
        if self.in_flight.contains(reference) {
            return Err("该设备已有进行中的配对会话。".into());
        }
        let (endpoint, context) = {
            let active = self.active.as_ref().ok_or("请先开启附近设备发现。")?;
            (
                active
                    .endpoints
                    .get(id)
                    .cloned()
                    .ok_or("附近设备已离线。")?,
                PairingContext {
                    identity: self.identity.clone().ok_or("局域网设备身份不可用。")?,
                    instance: active.instance.clone(),
                    nonce: active.nonce.clone(),
                    pairing_code: active.pairing_code.clone(),
                    failed_code_attempts: active.failed_code_attempts.clone(),
                    tx: self.tx.clone(),
                    trust: self.trust.clone(),
                    sessions: active.sessions.clone(),
                },
            )
        };
        if pairing_code.is_some() {
            context
                .sessions
                .mark_pairing_intent(&endpoint.instance)
                .map_err(|_| "局域网配对服务暂时不可用。")?;
        }
        self.in_flight.insert(reference.to_owned());
        if let Some(device) = self.nearby.get_mut(id) {
            device.status = "connecting";
        }
        thread::spawn(move || outbound(endpoint, pairing_code, context));
        Ok(())
    }
    pub(crate) fn revoke(&mut self, reference: &str) -> Result<(), String> {
        if !valid_reference(reference) {
            return Err("设备引用无效。".into());
        }
        self.trust
            .revoke(reference)
            .map_err(|_| "无法撤销设备信任。".to_owned())?;
        if let Some(active) = &self.active {
            active.sessions.shutdown_peer(reference);
        }
        if let Some((instance, device)) = self
            .nearby
            .iter_mut()
            .find(|(_, device)| device.pairing_ref == reference)
        {
            device.pairing_ref = format!("lan-peer-{instance}");
            device.status = "unverified";
        }
        Ok(())
    }
    pub(crate) fn rename(&mut self, reference: &str, label: &str) -> Result<(), String> {
        self.trust
            .rename(reference, label)
            .map_err(|_| "无法更新设备名称。".into())
    }
    pub(crate) fn stop(&mut self) {
        if let Some(a) = self.active.take() {
            a.stop.store(true, Ordering::Release);
            a.sessions.shutdown_all();
            if let Ok(unregistered) = a.daemon.unregister(&a.fullname) {
                let _ = unregistered.recv_timeout(Duration::from_millis(500));
            }
            let _ = a.daemon.stop_browse(SERVICE_TYPE);
            shutdown_daemon(&a.daemon);
        }
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Complete { persisted, .. } => {
                    let _ = persisted.send(false);
                }
                Event::Rollback { rolled_back, .. } => {
                    let _ = rolled_back.send(false);
                }
                Event::Connected { .. } | Event::Closed { .. } => {}
            }
        }
        let (tx, rx) = mpsc::channel();
        self.tx = tx;
        self.rx = rx;
        self.nearby.clear();
        self.in_flight.clear();
        self.auto_attempted.clear();
        self.identity = None;
    }
    fn prune(&mut self, now: Instant, _ms: u64) {
        if self.active.as_ref().is_some_and(|a| a.expires <= now) {
            self.stop();
        }
    }
    fn collect_discovery(&mut self) {
        let Some(a) = self.active.as_mut() else {
            return;
        };
        while let Ok(event) = a.browse.try_recv() {
            let ServiceEvent::ServiceResolved(info) = event else {
                if let ServiceEvent::ServiceRemoved(_, fullname) = event {
                    let removed = a.endpoints.iter().find_map(|(instance, endpoint)| {
                        (endpoint.fullname == fullname).then_some(instance.clone())
                    });
                    if let Some(instance) = removed {
                        a.endpoints.remove(&instance);
                        self.auto_attempted.remove(&format!("lan-peer-{instance}"));
                        if let Some(device) = self.nearby.remove(&instance) {
                            a.sessions.shutdown_peer(&device.pairing_ref);
                        }
                    }
                }
                continue;
            };
            let props = info.get_properties();
            let Some((i, n)) = parse_discovery_record(props, &a.instance) else {
                continue;
            };
            if a.endpoints.len() >= MAX_PEERS && !a.endpoints.contains_key(&i) {
                continue;
            }
            let addresses = info
                .get_addresses()
                .iter()
                .map(|ip| ip.to_ip_addr())
                .filter(|ip| same_link(*ip))
                .collect::<Vec<_>>();
            if addresses.is_empty() || info.get_port() == 0 {
                continue;
            }
            a.endpoints.insert(
                i.clone(),
                Endpoint {
                    instance: i.clone(),
                    fullname: info.get_fullname().to_owned(),
                    nonce: n,
                    addresses,
                    port: info.get_port(),
                },
            );
            self.nearby
                .entry(i.clone())
                .or_insert_with(|| LanNearbyDevice {
                    pairing_ref: format!("lan-peer-{i}"),
                    status: "unverified",
                });
        }
    }
    fn collect_events(&mut self, _now: Instant, _ms: u64) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Complete { peer, persisted } => {
                    self.in_flight.remove(&peer.pairing_ref);
                    let _ = persisted.send(self.trust.approve(peer).is_ok());
                }
                Event::Rollback {
                    peer_ref,
                    rolled_back,
                } => {
                    let _ = rolled_back.send(self.trust.revoke(&peer_ref).is_ok());
                }
                Event::Connected { instance, peer_ref } => {
                    self.in_flight.remove(&format!("lan-peer-{instance}"));
                    if let Some(device) = self.nearby.get_mut(&instance) {
                        device.pairing_ref = peer_ref;
                        device.status = "connected";
                    }
                }
                Event::Closed {
                    instance,
                    peer_ref,
                    failure,
                } => {
                    self.in_flight.remove(&format!("lan-peer-{instance}"));
                    let _ = peer_ref;
                    if let Some(device) = self.nearby.get_mut(&instance) {
                        device.pairing_ref = format!("lan-peer-{instance}");
                        device.status = failure.unwrap_or("unverified");
                    }
                }
            }
        }
    }
    fn auto_reconnect(&mut self) {
        // Before the first trust record exists there is nothing to reconnect.
        // Avoid racing an unnecessary identity probe with an explicit pairing.
        if !self.has_trusted_peers() {
            return;
        }
        let Some(active) = &self.active else {
            return;
        };
        let own_instance = active.instance.clone();
        let candidates = active
            .endpoints
            .keys()
            .filter(|instance| own_instance.as_str() < instance.as_str())
            .map(|instance| format!("lan-peer-{instance}"))
            .filter(|reference| !self.auto_attempted.contains(reference))
            .filter(|reference| !self.in_flight.contains(reference))
            .filter(|reference| {
                self.nearby
                    .get(reference.trim_start_matches("lan-peer-"))
                    .is_some_and(|peer| peer.status != "connected")
            })
            .collect::<Vec<_>>();
        for reference in candidates {
            self.auto_attempted.insert(reference.clone());
            let _ = self.spawn_connection(&reference, None);
        }
    }

    fn has_trusted_peers(&self) -> bool {
        self.trust.load().is_ok_and(|trusted| !trusted.is_empty())
    }
}

fn parse_discovery_record(props: &TxtProperties, own_instance: &str) -> Option<(String, String)> {
    if props.len() != 3
        || props
            .iter()
            .any(|property| !matches!(property.key(), "v" | "i" | "n"))
    {
        return None;
    }
    let version = props.get("v")?.val_str();
    let instance = props.get("i")?.val_str();
    let nonce = props.get("n")?.val_str();
    if version != PROTOCOL_TXT
        || instance == own_instance
        || !valid_token(instance)
        || !valid_token(nonce)
    {
        return None;
    }
    Some((instance.to_owned(), nonce.to_owned()))
}

fn accept_loop(listener: TcpListener, stop: Arc<AtomicBool>, context: PairingContext) {
    let handshakes = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((s, a)) if same_link(a.ip()) => {
                    if handshakes
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < MAX_HANDSHAKES).then_some(count + 1)
                        })
                        .is_err()
                    {
                        continue;
                    }
                    let Ok(session) = context.sessions.register(&s) else {
                        handshakes.fetch_sub(1, Ordering::AcqRel);
                        continue;
                    };
                    let context = context.clone();
                    let handshakes = handshakes.clone();
                    thread::spawn(move || {
                        let _session = session;
                        let _ = pair(s, false, None, None, &context, &_session);
                        handshakes.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(_) => break,
            }
        }
    });
}
fn outbound(ep: Endpoint, pairing_code: Option<Zeroizing<String>>, context: PairingContext) {
    let instance = ep.instance.clone();
    let mut reached_peer = false;
    let mut failure = "secure-channel-failed";
    for address in ep.addresses.clone() {
        if let Ok(s) = TcpStream::connect_timeout(&SocketAddr::new(address, ep.port), IO_TIMEOUT) {
            reached_peer = true;
            let Ok(session) = context.sessions.register(&s) else {
                break;
            };
            let result = pair(
                s,
                true,
                pairing_code.as_ref().map(|code| code.as_str()),
                Some((ep.instance.clone(), ep.nonce.clone())),
                &context,
                &session,
            );
            match result {
                Ok(()) | Err(PairError::Reported | PairError::Superseded) => return,
                Err(PairError::Failed(_)) if superseded_outbound(&context, &instance) => {
                    return;
                }
                Err(PairError::Failed(stage)) => failure = stage,
            }
            drop(session);
        }
    }
    let _ = context.tx.send(Event::Closed {
        instance,
        peer_ref: None,
        failure: Some(if reached_peer {
            failure
        } else {
            "transport-failed"
        }),
    });
}

fn superseded_outbound(context: &PairingContext, peer_instance: &str) -> bool {
    context.sessions.has_pairing_collision(peer_instance)
        && context.instance.as_str() > peer_instance
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairError {
    Failed(&'static str),
    Reported,
    Superseded,
}

impl From<()> for PairError {
    fn from((): ()) -> Self {
        Self::Failed("secure-channel-failed")
    }
}

fn pair(
    mut socket: TcpStream,
    client: bool,
    submitted_code: Option<&str>,
    expected: Option<(String, String)>,
    context: &PairingContext,
    session: &SessionGuard,
) -> Result<(), PairError> {
    let pairing_intent = submitted_code.is_some();
    // Accepted sockets can inherit O_NONBLOCK from the listener on macOS/BSD.
    // This worker uses synchronous certificate/TLS reads with socket timeouts;
    // without resetting the mode, a normal gap between packets fails immediately.
    socket.set_nonblocking(false).map_err(|_| ())?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    socket.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let peer_cert = if client {
        write_cert(&mut socket, &context.identity.cert)
            .map_err(|_| PairError::Failed("certificate-exchange-failed"))?;
        read_cert(&mut socket).map_err(|_| PairError::Failed("certificate-exchange-failed"))?
    } else {
        let c =
            read_cert(&mut socket).map_err(|_| PairError::Failed("certificate-exchange-failed"))?;
        write_cert(&mut socket, &context.identity.cert)
            .map_err(|_| PairError::Failed("certificate-exchange-failed"))?;
        c
    };
    let mut tls = if client {
        client_tls(socket, &context.identity, &peer_cert)
            .map_err(|_| PairError::Failed("tls-failed"))?
    } else {
        server_tls(socket, &context.identity, &peer_cert)
            .map_err(|_| PairError::Failed("tls-failed"))?
    };
    tls.complete_handshake()
        .map_err(|_| PairError::Failed("tls-failed"))?;
    write_frame(
        &mut tls,
        &Hello {
            version: PROTOCOL,
            instance: context.instance.clone(),
            nonce: context.nonce.clone(),
            device_id: context.identity.device_id.clone(),
            pairing_intent,
        },
    )
    .map_err(|_| PairError::Failed("protocol-failed"))?;
    let hello: Hello = read_frame(&mut tls).map_err(|_| PairError::Failed("protocol-failed"))?;
    if hello.version != PROTOCOL
        || !valid_token(&hello.instance)
        || !valid_token(&hello.nonce)
        || !valid_token(&hello.device_id)
    {
        return Err(PairError::Failed("protocol-failed"));
    }
    if let Some((ei, en)) = expected
        && ((hello.instance != ei) || (hello.nonce != en))
    {
        return Err(PairError::Failed("discovery-changed"));
    }
    let simultaneous_intent = hello.pairing_intent
        && (pairing_intent || context.sessions.has_pairing_intent(&hello.instance));
    if simultaneous_intent {
        context.sessions.mark_pairing_collision(&hello.instance)?;
        // Bluetooth-style collision handling: when both users select each
        // other, the lower ephemeral instance is the sole TLS client. Both
        // endpoints therefore keep the same transport and silently discard
        // the competing one before authenticating either submitted code.
        let local_is_canonical_client = context.instance < hello.instance;
        if client != local_is_canonical_client {
            return Err(PairError::Superseded);
        }
    }
    let reference = format!("lan-peer-{}", hello.device_id);
    let fingerprint = hex_digest(&peer_cert);
    let state = peer_trust_state(&context.trust, &reference, &fingerprint)
        .map_err(|_| PairError::Failed("local-trust-state-failed"))?;
    write_frame(&mut tls, &state).map_err(|_| PairError::Failed("protocol-failed"))?;
    let remote: TrustState =
        read_frame(&mut tls).map_err(|_| PairError::Failed("protocol-failed"))?;
    if state.blocked {
        return Err(PairError::Failed("identity-changed"));
    }
    if remote.blocked {
        return Err(PairError::Failed("peer-identity-rejected"));
    }
    if state.trusted && remote.trusted {
        session.sessions.bind_peer(session, &reference)?;
        context
            .tx
            .send(Event::Connected {
                instance: hello.instance.clone(),
                peer_ref: reference.clone(),
            })
            .map_err(|_| ())?;
        monitor_connection(tls, session, &context.tx, hello.instance, reference)?;
        return Ok(());
    }
    if !pairing_intent && !hello.pairing_intent {
        return Err(PairError::Failed("protocol-failed"));
    }
    let reserved_code_attempt = if client {
        false
    } else {
        reserve_pairing_attempt(&context.failed_code_attempts)
            .map_err(|_| PairError::Failed("code-attempts-exhausted"))?;
        true
    };
    let code = if client {
        submitted_code.ok_or(PairError::Failed("protocol-failed"))?
    } else {
        context.pairing_code.as_ref().as_str()
    };
    let peer = LanTrustedPeer {
        pairing_ref: reference.clone(),
        certificate_fingerprint: fingerprint,
        label: format!("VaultMesh {}", &hello.instance[..6]),
        protocol_major: PROTOCOL,
    };
    let code_authenticated =
        authenticate_pairing_code(&mut tls, client, code, context, &hello, &peer_cert).is_ok();
    if code_authenticated && reserved_code_attempt {
        context.failed_code_attempts.fetch_sub(1, Ordering::AcqRel);
    }
    if code_authenticated {
        let (persisted_tx, persisted_rx) = mpsc::channel();
        context
            .tx
            .send(Event::Complete {
                peer,
                persisted: persisted_tx,
            })
            .map_err(|_| ())?;
        let local_persisted = persisted_rx.recv_timeout(IO_TIMEOUT).unwrap_or(false);
        let remote_persisted = write_frame(
            &mut tls,
            &PersistenceState {
                persisted: local_persisted,
            },
        )
        .and_then(|_| read_frame::<PersistenceState>(&mut tls));
        let both_persisted = remote_persisted
            .as_ref()
            .is_ok_and(|remote| local_persisted && remote.persisted);
        if !both_persisted {
            if local_persisted && !state.trusted {
                let (rolled_back_tx, rolled_back_rx) = mpsc::channel();
                let _ = context.tx.send(Event::Rollback {
                    peer_ref: reference.clone(),
                    rolled_back: rolled_back_tx,
                });
                let _ = rolled_back_rx.recv_timeout(IO_TIMEOUT);
            }
            let failure = if !local_persisted {
                "local-storage-failed"
            } else if remote_persisted.is_ok_and(|remote| !remote.persisted) {
                "peer-storage-failed"
            } else {
                "persistence-sync-failed"
            };
            let _ = context.tx.send(Event::Closed {
                instance: hello.instance,
                peer_ref: Some(reference),
                failure: Some(failure),
            });
            return Err(PairError::Reported);
        }
        session.sessions.bind_peer(session, &reference)?;
        context
            .tx
            .send(Event::Connected {
                instance: hello.instance.clone(),
                peer_ref: reference.clone(),
            })
            .map_err(|_| ())?;
        monitor_connection(tls, session, &context.tx, hello.instance, reference)?;
    } else {
        let _ = context.tx.send(Event::Closed {
            instance: hello.instance,
            peer_ref: Some(reference),
            failure: Some("code-rejected"),
        });
        return Err(PairError::Reported);
    }
    Ok(())
}

fn reserve_pairing_attempt(attempts: &AtomicUsize) -> Result<(), ()> {
    attempts
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |attempts| {
            (attempts < MAX_CODE_ATTEMPTS).then_some(attempts + 1)
        })
        .map(|_| ())
        .map_err(|_| ())
}

fn authenticate_pairing_code(
    tls: &mut TlsStream,
    client: bool,
    code: &str,
    context: &PairingContext,
    hello: &Hello,
    peer_cert: &[u8],
) -> Result<(), ()> {
    if !valid_pairing_code(code) {
        return Err(());
    }
    let (client_id, server_id) = if client {
        (&context.identity.device_id, &hello.device_id)
    } else {
        (&hello.device_id, &context.identity.device_id)
    };
    let password = Password::new(code.as_bytes());
    let client_identity = SpakeIdentity::new(client_id.as_bytes());
    let server_identity = SpakeIdentity::new(server_id.as_bytes());
    let (state, outbound) = if client {
        Spake2::<RistrettoGroup>::start_a(&password, &client_identity, &server_identity)
            .map_err(|_| ())?
    } else {
        Spake2::<RistrettoGroup>::start_b(&password, &client_identity, &server_identity)
            .map_err(|_| ())?
    };
    write_frame(
        tls,
        &PakeMessage {
            message: BASE64.encode(outbound),
        },
    )?;
    let remote: PakeMessage = read_frame(tls)?;
    if remote.message.len() > 256 {
        return Err(());
    }
    let remote = BASE64.decode(remote.message.as_bytes()).map_err(|_| ())?;
    let shared = state.finish(&remote).map_err(|_| ())?;
    let transcript = pairing_confirmation_transcript(tls, client, context, hello, peer_cert)?;
    let local_role = if client { b"client" } else { b"server" };
    let remote_role = if client { b"server" } else { b"client" };
    let local_mac = pairing_confirmation_mac(shared.as_ref(), &transcript, local_role)?;
    write_frame(
        tls,
        &KeyConfirmation {
            mac: BASE64.encode(local_mac),
        },
    )?;
    let remote: KeyConfirmation = read_frame(tls)?;
    if remote.mac.len() > 128 {
        return Err(());
    }
    let remote_mac = BASE64.decode(remote.mac.as_bytes()).map_err(|_| ())?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(shared.as_ref()).map_err(|_| ())?;
    verifier.update(&transcript);
    verifier.update(remote_role);
    verifier.verify_slice(&remote_mac).map_err(|_| ())
}

fn pairing_confirmation_transcript(
    tls: &TlsStream,
    client: bool,
    context: &PairingContext,
    hello: &Hello,
    peer_cert: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let exporter = Zeroizing::new(tls.exporter()?);
    let mut transcript = Zeroizing::new(Vec::with_capacity(512));
    transcript.extend_from_slice(b"vaultmesh-lan-pairing-code-v1");
    append_transcript_field(&mut transcript, &exporter[..]);
    if client {
        append_transcript_field(&mut transcript, context.identity.device_id.as_bytes());
        append_transcript_field(&mut transcript, hello.device_id.as_bytes());
        append_transcript_field(&mut transcript, &context.identity.cert);
        append_transcript_field(&mut transcript, peer_cert);
        append_transcript_field(&mut transcript, context.instance.as_bytes());
        append_transcript_field(&mut transcript, hello.instance.as_bytes());
        append_transcript_field(&mut transcript, context.nonce.as_bytes());
        append_transcript_field(&mut transcript, hello.nonce.as_bytes());
    } else {
        append_transcript_field(&mut transcript, hello.device_id.as_bytes());
        append_transcript_field(&mut transcript, context.identity.device_id.as_bytes());
        append_transcript_field(&mut transcript, peer_cert);
        append_transcript_field(&mut transcript, &context.identity.cert);
        append_transcript_field(&mut transcript, hello.instance.as_bytes());
        append_transcript_field(&mut transcript, context.instance.as_bytes());
        append_transcript_field(&mut transcript, hello.nonce.as_bytes());
        append_transcript_field(&mut transcript, context.nonce.as_bytes());
    }
    Ok(transcript)
}

fn append_transcript_field(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u32).to_be_bytes());
    transcript.extend_from_slice(field);
}

fn pairing_confirmation_mac(key: &[u8], transcript: &[u8], role: &[u8]) -> Result<Vec<u8>, ()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ())?;
    mac.update(transcript);
    mac.update(role);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn peer_trust_state(
    trust: &TrustStore,
    reference: &str,
    fingerprint: &str,
) -> Result<TrustState, ()> {
    let known = trust
        .load()?
        .into_iter()
        .find(|known| known.pairing_ref == reference);
    Ok(TrustState {
        trusted: known
            .as_ref()
            .is_some_and(|known| known.certificate_fingerprint == fingerprint),
        blocked: known
            .as_ref()
            .is_some_and(|known| known.certificate_fingerprint != fingerprint),
    })
}

fn monitor_connection(
    mut tls: TlsStream,
    _session: &SessionGuard,
    tx: &Sender<Event>,
    instance: String,
    reference: String,
) -> Result<(), ()> {
    let socket = match &mut tls {
        TlsStream::Client(stream) => &stream.sock,
        TlsStream::Server(stream) => &stream.sock,
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| ())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| ())?;
    loop {
        if write_frame(&mut tls, &ConnectionPing { version: PROTOCOL }).is_err() {
            break;
        }
        let Ok(ping) = read_frame::<ConnectionPing>(&mut tls) else {
            break;
        };
        if ping.version != PROTOCOL {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    let _ = tx.send(Event::Closed {
        instance,
        peer_ref: Some(reference),
        failure: None,
    });
    Ok(())
}

fn client_tls(s: TcpStream, id: &Identity, peer: &[u8]) -> Result<TlsStream, ()> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(peer.to_vec()))
        .map_err(|_| ())?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ())?
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![CertificateDer::from(id.cert.clone())], key(id)?)
        .map_err(|_| ())?;
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("vaultmesh.local").map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    Ok(TlsStream::Client(StreamOwned::new(conn, s)))
}
fn server_tls(s: TcpStream, id: &Identity, peer: &[u8]) -> Result<TlsStream, ()> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(peer.to_vec()))
        .map_err(|_| ())?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|_| ())?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(id.cert.clone())], key(id)?)
        .map_err(|_| ())?;
    Ok(TlsStream::Server(StreamOwned::new(
        ServerConnection::new(Arc::new(config)).map_err(|_| ())?,
        s,
    )))
}
fn key(id: &Identity) -> Result<PrivateKeyDer<'static>, ()> {
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        id.key.to_vec(),
    )))
}
fn write_cert(s: &mut TcpStream, c: &[u8]) -> Result<(), ()> {
    if c.is_empty() || c.len() > MAX_CERT {
        return Err(());
    }
    s.write_all(PREFACE)
        .and_then(|_| s.write_all(&(c.len() as u32).to_be_bytes()))
        .and_then(|_| s.write_all(c))
        .map_err(|_| ())
}
fn read_cert(s: &mut TcpStream) -> Result<Vec<u8>, ()> {
    let mut p = [0; 8];
    s.read_exact(&mut p).map_err(|_| ())?;
    if &p != PREFACE {
        return Err(());
    }
    let mut l = [0; 4];
    s.read_exact(&mut l).map_err(|_| ())?;
    let l = u32::from_be_bytes(l) as usize;
    if l == 0 || l > MAX_CERT {
        return Err(());
    }
    let mut c = vec![0; l];
    s.read_exact(&mut c).map_err(|_| ())?;
    Ok(c)
}
fn write_frame<T: Serialize>(s: &mut TlsStream, v: &T) -> Result<(), ()> {
    let b = serde_json::to_vec(v).map_err(|_| ())?;
    if b.len() > MAX_FRAME {
        return Err(());
    }
    s.write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| s.write_all(&b))
        .and_then(|_| s.flush())
        .map_err(|_| ())
}
fn read_frame<T: for<'de> Deserialize<'de>>(s: &mut TlsStream) -> Result<T, ()> {
    let mut l = [0; 4];
    s.read_exact(&mut l).map_err(|_| ())?;
    let l = u32::from_be_bytes(l) as usize;
    if l == 0 || l > MAX_FRAME {
        return Err(());
    }
    let mut b = vec![0; l];
    s.read_exact(&mut b).map_err(|_| ())?;
    serde_json::from_slice(&b).map_err(|_| ())
}

fn random_token() -> String {
    let mut b = [0; 16];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}
fn random_pairing_code() -> String {
    loop {
        let mut bytes = [0_u8; 3];
        OsRng.fill_bytes(&mut bytes);
        let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        if value < 16_000_000 {
            return format!("{:06}", value % 1_000_000);
        }
    }
}
fn hex_digest(v: &[u8]) -> String {
    hex(&Sha256::digest(v))
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_token(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_pairing_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn valid_fingerprint(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_reference(v: &str) -> bool {
    v.strip_prefix("lan-peer-").is_some_and(valid_token)
}
fn shutdown_daemon(daemon: &ServiceDaemon) {
    if let Ok(shutdown) = daemon.shutdown() {
        let _ = shutdown.recv_timeout(Duration::from_millis(500));
    }
}
fn bind_listener() -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::from(([0_u16; 8], 0)).into())?;
    socket.listen(128)?;
    Ok(socket.into())
}
fn usable_interface_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !address.is_unspecified() && !address.is_multicast(),
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}
fn same_link(remote: IpAddr) -> bool {
    let remote = match remote {
        IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => {
            IpAddr::V4(address.to_ipv4_mapped().unwrap())
        }
        address => address,
    };
    if remote.is_loopback() {
        return true;
    }
    if !usable_interface_address(remote) {
        return false;
    }
    if_addrs::get_if_addrs().is_ok_and(|interfaces| {
        interfaces
            .into_iter()
            .any(|interface| match (interface.addr, remote) {
                (if_addrs::IfAddr::V4(local), IpAddr::V4(remote)) => {
                    u32::from(local.ip) & u32::from(local.netmask)
                        == u32::from(remote) & u32::from(local.netmask)
                }
                (if_addrs::IfAddr::V6(local), IpAddr::V6(remote)) => {
                    u128::from(local.ip) & u128::from(local.netmask)
                        == u128::from(remote) & u128::from(local.netmask)
                }
                _ => false,
            })
    })
}
fn proof_account(r: &str) -> String {
    format!("peer-{:x}", Sha256::digest(r.as_bytes()))
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secret_set(a: &str, v: &[u8]) -> Result<(), ()> {
    keyring::Entry::new(KEYRING_SERVICE, a)
        .and_then(|e| e.set_secret(v))
        .map_err(|_| ())
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn secret_set(_: &str, _: &[u8]) -> Result<(), ()> {
    Err(())
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secret_get(a: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    match keyring::Entry::new(KEYRING_SERVICE, a).and_then(|e| e.get_secret()) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(()),
    }
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn secret_get(_: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    Ok(None)
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secret_delete(a: &str) -> Result<(), ()> {
    match keyring::Entry::new(KEYRING_SERVICE, a).and_then(|e| e.delete_credential()) {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(()),
    }
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn secret_delete(_: &str) -> Result<(), ()> {
    Ok(())
}
fn write_private(path: &Path, b: &[u8]) -> Result<(), ()> {
    let p = path.parent().ok_or(())?;
    std::fs::create_dir_all(p).map_err(|_| ())?;
    let mut o = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as A;
        use std::os::unix::fs::OpenOptionsExt as S;
        A::preserve_mode(&mut o, false);
        S::mode(&mut o, 0o600);
    }
    let mut f = o.open(path).map_err(|_| ())?;
    #[cfg(target_os = "windows")]
    set_windows_owner_only(f.as_file())?;
    f.write_all(b).and_then(|_| f.commit()).map_err(|_| ())?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_windows_owner_only(file: &std::fs::File) -> Result<(), ()> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
            PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile, WRITE_DAC,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(());
    }
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
    if required == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(());
    }
    let mut user = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(());
    }
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut sid_string = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_string) } == 0 || sid_string.is_null() {
        return Err(());
    }
    let mut sid_length = 0;
    while unsafe { *sid_string.add(sid_length) } != 0 {
        sid_length += 1;
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, sid_length) })
        .map_err(|_| ());
    unsafe { LocalFree(sid_string.cast()) };
    let sid = sid?;
    let sddl = format!("D:P(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(());
    }
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        unsafe { LocalFree(descriptor) };
        return Err(());
    }
    // std::fs::File is opened for data writes and does not necessarily carry
    // WRITE_DAC. Reopen the same atomic temp file with the exact security
    // right before applying the owner-only DACL, then close that handle before
    // the atomic commit renames the file.
    let security_handle = unsafe {
        ReOpenFile(
            file.as_raw_handle() as HANDLE,
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if security_handle == INVALID_HANDLE_VALUE {
        unsafe { LocalFree(descriptor) };
        return Err(());
    }
    let security_handle = OwnedHandle(security_handle);
    let applied = unsafe {
        SetSecurityInfo(
            security_handle.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    (applied == ERROR_SUCCESS).then_some(()).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, Vec<u8>>>);
    impl CredentialStore for MemoryCredentials {
        fn set(&self, account: &str, value: &[u8]) -> Result<(), ()> {
            self.0
                .lock()
                .map_err(|_| ())?
                .insert(account.to_owned(), value.to_vec());
            Ok(())
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
            Ok(self
                .0
                .lock()
                .map_err(|_| ())?
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }
        fn delete(&self, account: &str) -> Result<(), ()> {
            self.0.lock().map_err(|_| ())?.remove(account);
            Ok(())
        }
    }

    fn identity() -> Arc<Identity> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["vaultmesh.local".into()]).unwrap();
        Arc::new(
            Identity::parts(
                cert.der().to_vec(),
                Zeroizing::new(signing_key.serialize_der()),
                random_token(),
            )
            .unwrap(),
        )
    }

    fn empty_store(name: &str) -> TrustStore {
        TrustStore::memory(
            std::env::temp_dir().join(format!("vaultmesh-lan-test-{name}-{}.json", random_token())),
            Arc::new(MemoryCredentials::default()),
        )
    }

    fn txt_properties(values: &[(&str, &str)]) -> TxtProperties {
        ServiceInfo::new(
            SERVICE_TYPE,
            "test",
            "random.local.",
            "127.0.0.1",
            43210,
            values,
        )
        .unwrap()
        .get_properties()
        .clone()
    }

    fn context(
        identity: Arc<Identity>,
        instance: &str,
        nonce: &str,
        tx: Sender<Event>,
        store: &str,
    ) -> PairingContext {
        PairingContext {
            identity,
            instance: instance.into(),
            nonce: nonce.into(),
            pairing_code: Arc::new(Zeroizing::new("123456".to_owned())),
            failed_code_attempts: Arc::new(AtomicUsize::new(0)),
            tx,
            trust: empty_store(store),
            sessions: Arc::new(SessionRegistry::default()),
        }
    }

    #[test]
    fn pairing_codes_are_bounded_and_randomized() {
        let codes = (0..32)
            .map(|_| random_pairing_code())
            .collect::<HashSet<_>>();
        assert!(codes.iter().all(|code| valid_pairing_code(code)));
        assert!(codes.len() > 1);
    }
    #[test]
    fn pairing_code_attempts_are_atomically_bounded() {
        let attempts = AtomicUsize::new(0);
        for _ in 0..MAX_CODE_ATTEMPTS {
            reserve_pairing_attempt(&attempts).unwrap();
        }
        assert!(reserve_pairing_attempt(&attempts).is_err());
        assert_eq!(attempts.load(Ordering::Acquire), MAX_CODE_ATTEMPTS);
    }
    #[test]
    fn values_are_bounded() {
        assert!(valid_token("aabbccddeeff00112233445566778899"));
        assert!(!valid_token("AABBCCDDEEFF00112233445566778899"));
        assert!(!valid_token("host.local"));
        assert!(valid_fingerprint(&"ab".repeat(32)));
        assert!(valid_pairing_code("000000"));
        assert!(!valid_pairing_code("12345"));
        assert!(!valid_pairing_code("12345a"));
        assert!(same_link(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        assert!(same_link(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(!same_link(IpAddr::V4(std::net::Ipv4Addr::new(
            224, 0, 0, 1
        ))));
    }

    #[test]
    fn ct_lan_pairing_listener_accepts_ipv4_and_ipv6_on_one_ephemeral_port() {
        let listener = bind_listener().unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let first = listener.accept().unwrap().1.ip();
            let second = listener.accept().unwrap().1.ip();
            assert!(same_link(first));
            assert!(same_link(second));
        });
        let ipv4 = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
        let ipv6 = TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).unwrap();
        drop((ipv4, ipv6));
        server.join().unwrap();
    }

    #[test]
    fn ct_lan_pairing_accepts_only_exact_bounded_v1_1_discovery_txt() {
        let own = "ffffffffffffffffffffffffffffffff";
        let valid = txt_properties(&[
            ("v", PROTOCOL_TXT),
            ("i", "00112233445566778899aabbccddeeff"),
            ("n", "ffeeddccbbaa99887766554433221100"),
        ]);
        assert_eq!(
            parse_discovery_record(&valid, own),
            Some((
                "00112233445566778899aabbccddeeff".into(),
                "ffeeddccbbaa99887766554433221100".into()
            ))
        );
        let wrong_version = txt_properties(&[
            ("v", "2.0"),
            ("i", "00112233445566778899aabbccddeeff"),
            ("n", "ffeeddccbbaa99887766554433221100"),
        ]);
        assert!(parse_discovery_record(&wrong_version, own).is_none());
        let legacy_revision = txt_properties(&[
            ("v", "1"),
            ("i", "00112233445566778899aabbccddeeff"),
            ("n", "ffeeddccbbaa99887766554433221100"),
        ]);
        assert!(parse_discovery_record(&legacy_revision, own).is_none());
        let unknown = txt_properties(&[
            ("v", PROTOCOL_TXT),
            ("i", "00112233445566778899aabbccddeeff"),
            ("n", "ffeeddccbbaa99887766554433221100"),
            ("hostname", "private-machine"),
        ]);
        assert!(parse_discovery_record(&unknown, own).is_none());
        let leaked_code = txt_properties(&[
            ("v", PROTOCOL_TXT),
            ("i", "00112233445566778899aabbccddeeff"),
            ("n", "ffeeddccbbaa99887766554433221100"),
            ("code", "123456"),
        ]);
        assert!(parse_discovery_record(&leaked_code, own).is_none());
        let overlong = txt_properties(&[
            ("v", PROTOCOL_TXT),
            ("i", "00112233445566778899aabbccddeeff00"),
            ("n", "ffeeddccbbaa99887766554433221100"),
        ]);
        assert!(parse_discovery_record(&overlong, own).is_none());
    }
    #[test]
    fn dto_hides_endpoint() {
        let v = serde_json::to_string(&LanPairingStatus {
            discoverable: true,
            expires_at: Some(1),
            pairing_code: Some("123456".into()),
            nearby: vec![],
            trusted: vec![LanTrustedPeerDto {
                pairing_ref: "lan-peer-00112233445566778899aabbccddeeff".into(),
                label: "Safe label".into(),
                protocol_major: 1,
            }],
        })
        .unwrap();
        assert!(!v.contains("port"));
        assert!(!v.contains("address"));
        assert!(!v.contains("nonce"));
        assert!(!v.contains("fingerprint"));
        assert!(!v.contains("certificate"));
        assert!(v.contains("123456"));
    }

    #[test]
    fn ct_lan_pairing_production_listener_tolerates_delayed_tls() {
        production_listener_tolerates_delayed_handshake(false);
    }

    #[test]
    fn ct_lan_pairing_production_listener_tolerates_delayed_certificate() {
        production_listener_tolerates_delayed_handshake(true);
    }

    fn production_listener_tolerates_delayed_handshake(delay_certificate: bool) {
        let listener = bind_listener().unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let server_context = context(
            identity(),
            &random_token(),
            &random_token(),
            tx,
            "delayed-tls",
        );
        let sessions = server_context.sessions.clone();
        let stop = Arc::new(AtomicBool::new(false));
        accept_loop(listener, stop.clone(), server_context);
        let client_identity = identity();
        let mut socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if delay_certificate {
            thread::sleep(Duration::from_millis(100));
        }
        write_cert(&mut socket, &client_identity.cert).unwrap();
        let peer_cert = read_cert(&mut socket);
        // Model the network gap between the certificate preface and ClientHello.
        thread::sleep(Duration::from_millis(100));
        let result = peer_cert.and_then(|cert| {
            let mut tls = client_tls(socket, &client_identity, &cert)?;
            tls.complete_handshake()
        });
        stop.store(true, Ordering::Release);
        sessions.shutdown_all();
        assert!(
            result.is_ok(),
            "production listener must wait for delayed TLS data"
        );
        assert!(rx.try_recv().is_err(), "TLS alone must not establish trust");
    }

    #[test]
    fn ct_lan_pairing_production_listener_completes_pairing() {
        let listener = bind_listener().unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (server_tx, server_rx) = mpsc::channel();
        let (client_tx, client_rx) = mpsc::channel();
        let server = context(
            identity(),
            &random_token(),
            &random_token(),
            server_tx,
            "production-server",
        );
        let client = context(
            identity(),
            &random_token(),
            &random_token(),
            client_tx,
            "production-client",
        );
        let endpoint = Endpoint {
            instance: server.instance.clone(),
            fullname: "test.local.".into(),
            nonce: server.nonce.clone(),
            addresses: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            port,
        };
        let stop = Arc::new(AtomicBool::new(false));
        accept_loop(listener, stop.clone(), server.clone());
        let client_worker = client.clone();
        let worker = thread::spawn(move || {
            outbound(
                endpoint,
                Some(Zeroizing::new("123456".into())),
                client_worker,
            );
        });
        let result = (|| -> Result<(), &'static str> {
            for (rx, store) in [(&server_rx, &server.trust), (&client_rx, &client.trust)] {
                match rx.recv_timeout(Duration::from_secs(3)) {
                    Ok(Event::Complete { peer, persisted }) => {
                        persisted
                            .send(store.approve(peer).is_ok())
                            .map_err(|_| "persistence ack")?;
                    }
                    _ => return Err("production connection did not authenticate"),
                }
            }
            for rx in [&server_rx, &client_rx] {
                if !matches!(
                    rx.recv_timeout(Duration::from_secs(3)),
                    Ok(Event::Connected { .. })
                ) {
                    return Err("production connection did not complete");
                }
            }
            if server.trust.load().map_err(|_| "server trust")?.len() != 1
                || client.trust.load().map_err(|_| "client trust")?.len() != 1
            {
                return Err("missing persisted trust");
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        server.sessions.shutdown_all();
        client.sessions.shutdown_all();
        worker.join().unwrap();
        let _ = std::fs::remove_file(server.trust.path);
        let _ = std::fs::remove_file(client.trust.path);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn ct_lan_pairing_one_sided_code_entry_authenticates_and_connects_both_peers() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_identity = identity();
        let client_identity = identity();
        let (server_tx, server_rx) = mpsc::channel();
        let (client_tx, client_rx) = mpsc::channel();
        let server_context = context(
            server_identity,
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            server_tx,
            "server",
        );
        let client_context = context(
            client_identity,
            "22222222222222222222222222222222",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            client_tx,
            "client",
        );
        let server_store = server_context.trust.clone();
        let client_store = client_context.trust.clone();
        let server_sessions = server_context.sessions.clone();
        let client_sessions = client_context.sessions.clone();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let session = server_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &server_context, &session)
        });
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let session = client_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("123456"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )),
                &client_context,
                &session,
            )
        });
        match server_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(server_store.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected automatic server persistence"),
        }
        match client_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(client_store.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected automatic client persistence"),
        }
        assert!(matches!(
            server_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert!(matches!(
            client_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert_eq!(server_store.load().unwrap().len(), 1);
        assert_eq!(client_store.load().unwrap().len(), 1);
        server_sessions.shutdown_all();
        client_sessions.shutdown_all();
        assert!(server.join().unwrap().is_ok());
        assert!(client.join().unwrap().is_ok());
        let _ = std::fs::remove_file(server_store.path);
        let _ = std::fs::remove_file(client_store.path);
    }

    #[test]
    fn ct_lan_pairing_wrong_code_fails_without_persisting_trust() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (server_tx, server_rx) = mpsc::channel();
        let (client_tx, client_rx) = mpsc::channel();
        let server_context = context(
            identity(),
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            server_tx,
            "wrong-code-server",
        );
        let server_attempts = server_context.failed_code_attempts.clone();
        let client_context = context(
            identity(),
            "22222222222222222222222222222222",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            client_tx,
            "wrong-code-client",
        );
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let session = server_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &server_context, &session)
        });
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let session = client_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("654321"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )),
                &client_context,
                &session,
            )
        });
        assert_eq!(server.join().unwrap(), Err(PairError::Reported));
        assert_eq!(client.join().unwrap(), Err(PairError::Reported));
        assert_eq!(server_attempts.load(Ordering::Acquire), 1);
        assert!(matches!(
            server_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::Closed {
                failure: Some("code-rejected"),
                ..
            }
        ));
        assert!(matches!(
            client_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::Closed {
                failure: Some("code-rejected"),
                ..
            }
        ));
        assert!(server_rx.try_recv().is_err());
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn ct_lan_pairing_simultaneous_code_entry_converges_on_one_session() {
        let listener_a = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let listener_b = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address_a = listener_a.local_addr().unwrap();
        let address_b = listener_b.local_addr().unwrap();
        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        let mut context_a = context(
            identity(),
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tx_a,
            "simultaneous-a",
        );
        let mut context_b = context(
            identity(),
            "22222222222222222222222222222222",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            tx_b,
            "simultaneous-b",
        );
        context_a.pairing_code = Arc::new(Zeroizing::new("111111".to_owned()));
        context_b.pairing_code = Arc::new(Zeroizing::new("222222".to_owned()));
        context_a
            .sessions
            .mark_pairing_intent("22222222222222222222222222222222")
            .unwrap();
        context_b
            .sessions
            .mark_pairing_intent("11111111111111111111111111111111")
            .unwrap();

        let inbound_a_context = context_a.clone();
        let inbound_a = thread::spawn(move || {
            let (socket, _) = listener_a.accept().unwrap();
            let session = inbound_a_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &inbound_a_context, &session)
        });
        let inbound_b_context = context_b.clone();
        let inbound_b = thread::spawn(move || {
            let (socket, _) = listener_b.accept().unwrap();
            let session = inbound_b_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &inbound_b_context, &session)
        });
        let outbound_a_context = context_a.clone();
        let outbound_a = thread::spawn(move || {
            let socket = TcpStream::connect(address_b).unwrap();
            let session = outbound_a_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("222222"),
                Some((
                    "22222222222222222222222222222222".into(),
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                )),
                &outbound_a_context,
                &session,
            )
        });
        let outbound_b_context = context_b.clone();
        let outbound_b = thread::spawn(move || {
            let socket = TcpStream::connect(address_a).unwrap();
            let session = outbound_b_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("111111"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )),
                &outbound_b_context,
                &session,
            )
        });

        for (receiver, store) in [(&rx_a, &context_a.trust), (&rx_b, &context_b.trust)] {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Complete { peer, persisted } => {
                    persisted.send(store.approve(peer).is_ok()).unwrap()
                }
                _ => panic!("expected one automatic persistence request"),
            }
        }
        assert!(matches!(
            rx_a.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert!(matches!(
            rx_b.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert!(
            context_b
                .sessions
                .has_pairing_collision("11111111111111111111111111111111")
        );
        assert!(superseded_outbound(
            &context_b,
            "11111111111111111111111111111111"
        ));
        assert!(!superseded_outbound(
            &context_a,
            "22222222222222222222222222222222"
        ));
        context_a.sessions.shutdown_all();
        context_b.sessions.shutdown_all();

        assert_eq!(inbound_a.join().unwrap(), Err(PairError::Superseded));
        assert!(inbound_b.join().unwrap().is_ok());
        assert!(outbound_a.join().unwrap().is_ok());
        assert!(matches!(
            outbound_b.join().unwrap(),
            Err(PairError::Failed(_))
        ));
        let _ = std::fs::remove_file(&context_a.trust.path);
        let _ = std::fs::remove_file(&context_b.trust.path);
    }

    #[test]
    fn ct_lan_pairing_remote_persistence_failure_rolls_back_new_local_trust() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_store = empty_store("persist-server");
        let client_store = empty_store("persist-client");
        client_store.fail_save.store(true, Ordering::Release);
        let server_path = server_store.path.clone();
        let client_path = client_store.path.clone();
        let (server_tx, server_rx) = mpsc::channel();
        let (client_tx, client_rx) = mpsc::channel();
        let server_context = PairingContext {
            identity: identity(),
            instance: "11111111111111111111111111111111".into(),
            nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            pairing_code: Arc::new(Zeroizing::new("123456".to_owned())),
            failed_code_attempts: Arc::new(AtomicUsize::new(0)),
            tx: server_tx,
            trust: server_store.clone(),
            sessions: Arc::new(SessionRegistry::default()),
        };
        let client_context = PairingContext {
            identity: identity(),
            instance: "22222222222222222222222222222222".into(),
            nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            pairing_code: Arc::new(Zeroizing::new("654321".to_owned())),
            failed_code_attempts: Arc::new(AtomicUsize::new(0)),
            tx: client_tx,
            trust: client_store.clone(),
            sessions: Arc::new(SessionRegistry::default()),
        };
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let session = server_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &server_context, &session)
        });
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let session = client_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("123456"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )),
                &client_context,
                &session,
            )
        });

        match server_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(server_store.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected server persistence request"),
        }
        match client_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(client_store.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected client persistence request"),
        }
        match server_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Rollback {
                peer_ref,
                rolled_back,
            } => rolled_back
                .send(server_store.revoke(&peer_ref).is_ok())
                .unwrap(),
            _ => panic!("expected rollback after remote persistence failure"),
        }

        assert_eq!(server.join().unwrap(), Err(PairError::Reported));
        assert_eq!(client.join().unwrap(), Err(PairError::Reported));
        assert!(server_store.load().unwrap().is_empty());
        assert!(client_store.load().unwrap().is_empty());
        assert!(matches!(
            server_rx.try_recv(),
            Ok(Event::Closed {
                failure: Some("peer-storage-failed"),
                ..
            })
        ));
        assert!(matches!(
            client_rx.try_recv(),
            Ok(Event::Closed {
                failure: Some("local-storage-failed"),
                ..
            })
        ));
        let _ = std::fs::remove_file(server_path);
        let _ = std::fs::remove_file(client_path);
    }

    #[test]
    fn ct_lan_pairing_code_entry_persists_and_connects_both_peers() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store_a = empty_store("success-a");
        let store_b = empty_store("success-b");
        let path_a = store_a.path.clone();
        let path_b = store_b.path.clone();
        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        let context_a = PairingContext {
            identity: identity(),
            instance: "11111111111111111111111111111111".into(),
            nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            pairing_code: Arc::new(Zeroizing::new("123456".to_owned())),
            failed_code_attempts: Arc::new(AtomicUsize::new(0)),
            tx: tx_a,
            trust: store_a.clone(),
            sessions: Arc::new(SessionRegistry::default()),
        };
        let context_b = PairingContext {
            identity: identity(),
            instance: "22222222222222222222222222222222".into(),
            nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            pairing_code: Arc::new(Zeroizing::new("654321".to_owned())),
            failed_code_attempts: Arc::new(AtomicUsize::new(0)),
            tx: tx_b,
            trust: store_b.clone(),
            sessions: Arc::new(SessionRegistry::default()),
        };
        let sessions_a = context_a.sessions.clone();
        let sessions_b = context_b.sessions.clone();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let session = context_a.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &context_a, &session)
        });
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let session = context_b.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("123456"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )),
                &context_b,
                &session,
            )
        });

        match rx_a.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(store_a.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected persistence request on A"),
        }
        match rx_b.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Complete { peer, persisted } => {
                persisted.send(store_b.approve(peer).is_ok()).unwrap()
            }
            _ => panic!("expected persistence request on B"),
        }
        assert!(matches!(
            rx_a.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert!(matches!(
            rx_b.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Connected { .. }
        ));
        assert_eq!(store_a.load().unwrap().len(), 1);
        assert_eq!(store_b.load().unwrap().len(), 1);

        sessions_a.shutdown_all();
        sessions_b.shutdown_all();
        assert!(server.join().unwrap().is_ok());
        assert!(client.join().unwrap().is_ok());
        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
    }

    #[test]
    fn ct_lan_pairing_rejects_mdns_nonce_mismatch_before_prompt() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_identity = identity();
        let client_identity = identity();
        let (server_tx, _server_rx) = mpsc::channel();
        let (client_tx, client_rx) = mpsc::channel();
        let server_context = context(
            server_identity,
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            server_tx,
            "nonce-server",
        );
        let client_context = context(
            client_identity,
            "22222222222222222222222222222222",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            client_tx,
            "nonce-client",
        );
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let session = server_context.sessions.register(&socket).unwrap();
            pair(socket, false, None, None, &server_context, &session)
        });
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let session = client_context.sessions.register(&socket).unwrap();
            pair(
                socket,
                true,
                Some("123456"),
                Some((
                    "11111111111111111111111111111111".into(),
                    "cccccccccccccccccccccccccccccccc".into(),
                )),
                &client_context,
                &session,
            )
        });
        assert!(client.join().unwrap().is_err());
        assert!(server.join().unwrap().is_err());
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn ct_lan_pairing_rejects_oversized_certificate_preface() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_cert(&mut socket)
        });
        let mut socket = TcpStream::connect(address).unwrap();
        socket.write_all(PREFACE).unwrap();
        socket
            .write_all(&((MAX_CERT as u32) + 1).to_be_bytes())
            .unwrap();
        assert!(reader.join().unwrap().is_err());
    }

    #[test]
    fn ct_lan_pairing_rejects_invalid_or_secret_bearing_index() {
        let store = empty_store("invalid-index");
        write_private(
            &store.path,
            br#"{"version":1,"peers":[],"vaultKey":"must-not-be-accepted"}"#,
        )
        .unwrap();
        assert!(store.load_index().is_err());
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn ct_lan_pairing_rolls_back_credential_and_index_mutations() {
        let credentials = Arc::new(MemoryCredentials::default());
        let store = TrustStore::memory(
            std::env::temp_dir().join(format!("vaultmesh-lan-rollback-{}.json", random_token())),
            credentials.clone(),
        );
        let peer = LanTrustedPeer {
            pairing_ref: "lan-peer-00112233445566778899aabbccddeeff".into(),
            certificate_fingerprint: "ab".repeat(32),
            label: "Test peer".into(),
            protocol_major: PROTOCOL,
        };
        store.fail_save.store(true, Ordering::Release);
        assert!(store.approve(peer.clone()).is_err());
        assert!(
            credentials
                .get(&proof_account(&peer.pairing_ref))
                .unwrap()
                .is_none()
        );
        assert!(!store.path.exists());

        store.fail_save.store(false, Ordering::Release);
        store.approve(peer.clone()).unwrap();
        assert_eq!(store.load().unwrap().len(), 1);
        store.fail_save.store(true, Ordering::Release);
        assert!(store.revoke(&peer.pairing_ref).is_err());
        assert_eq!(store.load().unwrap(), vec![peer]);
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn ct_lan_pairing_skips_automatic_identity_probes_before_first_trust() {
        let store = empty_store("first-trust-probe");
        let mut service = LanPairingService::new(store.path.clone());
        service.trust = store.clone();
        assert!(!service.has_trusted_peers());

        store
            .approve(LanTrustedPeer {
                pairing_ref: "lan-peer-00112233445566778899aabbccddeeff".into(),
                certificate_fingerprint: "ab".repeat(32),
                label: "Trusted peer".into(),
                protocol_major: PROTOCOL,
            })
            .unwrap();
        assert!(service.has_trusted_peers());
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn ct_lan_pairing_failed_handshake_clears_in_flight_and_allows_retry() {
        let mut service = LanPairingService::new(
            std::env::temp_dir().join(format!("vaultmesh-lan-retry-{}.json", random_token())),
        );
        let instance = "00112233445566778899aabbccddeeff";
        let reference = format!("lan-peer-{instance}");
        service.nearby.insert(
            instance.into(),
            LanNearbyDevice {
                pairing_ref: reference.clone(),
                status: "connecting",
            },
        );
        service.in_flight.insert(reference.clone());
        service
            .tx
            .send(Event::Closed {
                instance: instance.into(),
                peer_ref: None,
                failure: Some("secure-channel-failed"),
            })
            .unwrap();

        service.collect_events(Instant::now(), 0);
        assert!(!service.in_flight.contains(&reference));
        assert_eq!(
            service.nearby.get(instance).unwrap().status,
            "secure-channel-failed"
        );
    }

    #[test]
    fn ct_lan_pairing_restores_pin_by_stable_device_id_and_blocks_cert_change() {
        let store = empty_store("pin-restore");
        let reference = "lan-peer-00112233445566778899aabbccddeeff";
        let fingerprint = "ab".repeat(32);
        store
            .approve(LanTrustedPeer {
                pairing_ref: reference.into(),
                certificate_fingerprint: fingerprint.clone(),
                label: "Persistent peer".into(),
                protocol_major: PROTOCOL,
            })
            .unwrap();
        assert_eq!(
            peer_trust_state(&store, reference, &fingerprint).unwrap(),
            TrustState {
                trusted: true,
                blocked: false
            }
        );
        assert_eq!(
            peer_trust_state(&store, reference, &"cd".repeat(32)).unwrap(),
            TrustState {
                trusted: false,
                blocked: true
            }
        );
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn ct_lan_pairing_stop_closes_sockets_and_cancels_ephemeral_material() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let sessions = Arc::new(SessionRegistry::default());
        let _session = sessions.register(&server).unwrap();
        sessions.shutdown_all();
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);

        let mut service = LanPairingService::new(
            std::env::temp_dir().join(format!("vaultmesh-lan-stop-{}.json", random_token())),
        );
        let reference = "lan-peer-00112233445566778899aabbccddeeff".to_owned();
        service.in_flight.insert(reference);
        service.stop();
        assert!(service.in_flight.is_empty());
        assert!(service.identity.is_none());
    }

    #[test]
    fn ct_lan_pairing_rejects_invalid_code_before_connecting() {
        let mut service = LanPairingService::new(
            std::env::temp_dir().join(format!("vaultmesh-lan-expiry-{}.json", random_token())),
        );
        let reference = "lan-peer-00112233445566778899aabbccddeeff".to_owned();
        assert_eq!(
            service
                .begin(&reference, Zeroizing::new("12345".into()))
                .unwrap_err(),
            "请输入六位数字配对码。"
        );
        assert_eq!(
            service
                .begin(&reference, Zeroizing::new("12345a".into()))
                .unwrap_err(),
            "请输入六位数字配对码。"
        );
        assert!(!service.in_flight.contains(&reference));
    }

    #[cfg(unix)]
    #[test]
    fn ct_lan_pairing_index_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let store = empty_store("permissions");
        store.save(&[]).unwrap();
        assert_eq!(
            std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file(&store.path);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn ct_lan_pairing_index_is_owner_only() {
        let store = empty_store("windows-permissions");
        store.save(&[]).unwrap();
        assert!(store.path.is_file());
        assert_eq!(store.load_index().unwrap().peers.len(), 0);
        let _ = std::fs::remove_file(&store.path);
    }
}
