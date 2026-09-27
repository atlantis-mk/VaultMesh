//! Authenticated v2 snapshots. Persistent phone registration and volatile SMS cache.
use super::*;
const RECORDS: &str = "device-assist-phones-v2";
const SCOPES: &str = "device-assist-registration-scopes-v2";
// A local trust revocation invalidates volatile deliveries even if the same identity is paired again.
const REVOCATION: &str = "device-assist-registration-revision-v2";
fn revision(credentials: &dyn CredentialStore) -> Result<Option<String>, ()> {
    credentials
        .get(REVOCATION)?
        .map(|raw| {
            let value = std::str::from_utf8(&raw).map_err(|_| ())?;
            if !valid_token(value) {
                return Err(());
            }
            Ok(value.to_owned())
        })
        .transpose()
}
fn scopes(credentials: &dyn CredentialStore) -> Result<Vec<String>, ()> {
    let keys = match credentials.get(SCOPES)? {
        Some(raw) => serde_json::from_slice::<Vec<String>>(&raw).map_err(|_| ())?,
        None => vec![],
    };
    if keys.len() > 16
        || keys.iter().any(|k| {
            !k.strip_prefix(&format!("{RECORDS}-"))
                .is_some_and(|suffix| {
                    suffix.len() == 64 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                })
        })
    {
        return Err(());
    }
    Ok(keys)
}
pub(super) fn revoke_registration(credentials: &dyn CredentialStore, peer: &str) -> Result<(), ()> {
    credentials.set(REVOCATION, random_token().as_bytes())?;
    for key in scopes(credentials)? {
        if let Some(raw) = credentials.get(&key)? {
            let mut phones: Vec<Phone> = serde_json::from_slice(&raw).map_err(|_| ())?;
            let old = phones.len();
            phones.retain(|p| p.peer != peer);
            if old != phones.len() {
                credentials.set(
                    &key,
                    &Zeroizing::new(serde_json::to_vec(&phones).map_err(|_| ())?),
                )?;
            }
        }
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    binding: String,
    phone: Option<String>,
    codes: Vec<PushedCode>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        if let Some(v) = &mut self.phone {
            v.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PushedCode {
    id: String,
    value: String,
    source: String,
    received_at: u64,
    remaining_ms: u64,
}
impl Drop for PushedCode {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phone {
    peer: String,
    fingerprint: String,
    binding: String,
    value: String,
}
impl Drop for Phone {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
struct Sms {
    peer: String,
    fingerprint: String,
    binding: String,
    id: String,
    value: Zeroizing<String>,
    source: String,
    received_at: u64,
    expires: Instant,
}
pub(super) struct Cache {
    credentials: Arc<dyn CredentialStore>,
    key: String,
    phones: Vec<Phone>,
    sms: Vec<Sms>,
    consumed: HashMap<String, Instant>,
    blocked: HashSet<String>,
    revocation: Option<String>,
}
impl Cache {
    pub(super) fn new(credentials: Arc<dyn CredentialStore>, scope: &str) -> Result<Self, ()> {
        let key = format!("{RECORDS}-{:x}", Sha256::digest(scope.as_bytes()));
        let mut keys = scopes(credentials.as_ref())?;
        if !keys.contains(&key) {
            if keys.len() >= 16 {
                return Err(());
            }
            keys.push(key.clone());
            credentials.set(
                SCOPES,
                &Zeroizing::new(serde_json::to_vec(&keys).map_err(|_| ())?),
            )?;
        }
        let phones = match credentials.get(&key)? {
            Some(raw) => serde_json::from_slice::<Vec<Phone>>(&raw).map_err(|_| ())?,
            None => vec![],
        };
        if phones.len() > MAX_PEERS || phones.iter().any(|p| !valid_phone(&p.value)) {
            return Err(());
        }
        let seen_key = format!("{key}-consumed");
        let seen = match credentials.get(&seen_key)? {
            Some(raw) => serde_json::from_slice::<HashMap<String, u64>>(&raw).map_err(|_| ())?,
            None => HashMap::new(),
        };
        if seen.len() > 128 {
            return Err(());
        }
        let wall = wall_millis();
        let now = Instant::now();
        let consumed = seen
            .into_iter()
            .filter(|(_, until)| *until > wall)
            .map(|(id, until)| {
                (
                    id,
                    now + Duration::from_millis(until.saturating_sub(wall).min(120_000)),
                )
            })
            .collect();
        let revocation = revision(credentials.as_ref())?;
        Ok(Self {
            credentials,
            key,
            phones,
            sms: vec![],
            consumed,
            blocked: HashSet::new(),
            revocation,
        })
    }
    pub(super) fn clear_memory(&mut self) {
        self.phones.clear();
        self.sms.clear();
        self.consumed.clear();
    }
    fn save_consumed(&self) -> Result<(), ()> {
        let wall = wall_millis();
        let now = Instant::now();
        let seen: HashMap<_, _> = self
            .consumed
            .iter()
            .filter(|(_, end)| **end > now)
            .map(|(id, end)| {
                (
                    id,
                    wall + end.saturating_duration_since(now).as_millis() as u64,
                )
            })
            .collect();
        self.credentials.set(
            &format!("{}-consumed", self.key),
            &Zeroizing::new(serde_json::to_vec(&seen).map_err(|_| ())?),
        )
    }
    fn save(&self) -> Result<(), ()> {
        let raw = Zeroizing::new(serde_json::to_vec(&self.phones).map_err(|_| ())?);
        self.credentials.set(&self.key, &raw)
    }
    fn check_revocation(&mut self) -> Result<(), ()> {
        let revision = revision(self.credentials.as_ref())?;
        if self.revocation != revision {
            self.sms.clear();
            self.revocation = revision;
        }
        Ok(())
    }
    fn expire(&mut self) {
        self.sms.retain(|c| c.expires > Instant::now());
        let old = self.consumed.len();
        self.consumed.retain(|_, end| *end > Instant::now());
        if old != self.consumed.len() {
            let _ = self.save_consumed();
        }
    }
    fn prune(&mut self, trust: &[LanTrustedPeer]) -> Result<(), ()> {
        self.check_revocation()?;
        // The protected record is authoritative, including revocation followed by same-identity repair.
        self.phones = match self.credentials.get(&self.key)? {
            Some(raw) => serde_json::from_slice::<Vec<Phone>>(&raw).map_err(|_| ())?,
            None => vec![],
        };
        if self.phones.len() > MAX_PEERS || self.phones.iter().any(|p| !valid_phone(&p.value)) {
            self.phones.clear();
            return Err(());
        }
        self.phones.retain(|p| !self.blocked.contains(&p.peer));
        let valid = |peer: &str, fp: &str| {
            trust
                .iter()
                .any(|p| p.pairing_ref == peer && p.certificate_fingerprint == fp)
        };
        let n = self.phones.len();
        self.phones.retain(|p| valid(&p.peer, &p.fingerprint));
        self.sms
            .retain(|s| s.expires > Instant::now() && valid(&s.peer, &s.fingerprint));
        let consumed_len = self.consumed.len();
        self.consumed.retain(|_, until| *until > Instant::now());
        if consumed_len != self.consumed.len() {
            self.save_consumed()?;
        }
        if n != self.phones.len() {
            self.save()?;
        }
        Ok(())
    }
    fn update(&mut self, peer: &LanTrustedPeer, _remote: &Remote, s: &Snapshot) -> Result<(), ()> {
        self.check_revocation()?;
        if s.binding.is_empty()
            || s.binding.len() > 256
            || s.codes.len() > 20
            || s.phone.as_ref().is_some_and(|v| !valid_phone(v))
        {
            return Err(());
        }
        if s.codes.iter().any(|c| {
            !valid_token(&c.id)
                || !(4..=10).contains(&c.value.len())
                || !c.value.bytes().all(|b| b.is_ascii_alphanumeric())
                || c.source.len() > 128
                || c.remaining_ms > 120_000
        }) {
            return Err(());
        }
        let old = self.phones.iter().find(|p| p.peer == peer.pairing_ref);
        let changed = self.blocked.contains(&peer.pairing_ref)
            || match (old, &s.phone) {
                (None, None) => false,
                (Some(p), Some(value)) => {
                    p.value != *value
                        || p.binding != s.binding
                        || p.fingerprint != peer.certificate_fingerprint
                }
                _ => true,
            };
        if changed {
            self.phones.retain(|p| p.peer != peer.pairing_ref);
            if let Some(value) = &s.phone {
                if self.phones.len() >= MAX_PEERS {
                    return Err(());
                }
                self.phones.push(Phone {
                    peer: peer.pairing_ref.clone(),
                    fingerprint: peer.certificate_fingerprint.clone(),
                    binding: s.binding.clone(),
                    value: value.clone(),
                });
            }
            // Do not publish a registration that could not be protected on disk.
            if self.save().is_err() {
                self.phones.retain(|p| p.peer != peer.pairing_ref);
                self.blocked.insert(peer.pairing_ref.clone());
                return Err(());
            }
        }
        self.blocked.remove(&peer.pairing_ref);
        let now = Instant::now();
        self.sms.retain(|c| {
            c.expires > now
                && (c.peer != peer.pairing_ref
                    || (c.binding == s.binding && s.codes.iter().any(|v| v.id == c.id)))
        });
        for code in &s.codes {
            let key = format!("{}:{}", peer.pairing_ref, code.id);
            if self.consumed.contains_key(&key) || code.remaining_ms == 0 {
                continue;
            }
            let age = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64)
                .saturating_sub(code.received_at);
            let ttl = code.remaining_ms.min(120_000u64.saturating_sub(age));
            if ttl == 0 {
                continue;
            }
            if let Some(old) = self
                .sms
                .iter_mut()
                .find(|c| c.peer == peer.pairing_ref && c.id == code.id)
            {
                old.expires = old.expires.min(now + Duration::from_millis(ttl));
                continue;
            }
            if self.sms.len() >= 20 {
                self.sms.remove(0);
            }
            self.sms.push(Sms {
                peer: peer.pairing_ref.clone(),
                fingerprint: peer.certificate_fingerprint.clone(),
                binding: s.binding.clone(),
                id: code.id.clone(),
                value: Zeroizing::new(code.value.clone()),
                source: code.source.clone(),
                received_at: code.received_at,
                expires: now + Duration::from_millis(ttl),
            });
        }
        Ok(())
    }
    pub(super) fn candidates(
        &mut self,
        kind: Kind,
        trust: &[LanTrustedPeer],
        expires: Instant,
    ) -> Result<Vec<(RemoteCandidate, Selection)>, ()> {
        self.prune(trust)?;
        let mut out = vec![];
        if kind == Kind::Phone {
            for p in &self.phones {
                let peer = trust.iter().find(|v| v.pairing_ref == p.peer).ok_or(())?;
                let id = format!("registered:{}", p.peer);
                let source = p
                    .value
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                out.push((
                    RemoteCandidate {
                        id: id.clone(),
                        peer: p.peer.clone(),
                        device: peer.label.clone(),
                        kind,
                        source,
                        received_at: None,
                        remaining_ms: expires
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64,
                    },
                    Selection {
                        remote: None,
                        candidate: id,
                        peer: p.peer.clone(),
                        expires,
                        cached: true,
                    },
                ));
            }
        } else {
            for c in &self.sms {
                let peer = trust.iter().find(|v| v.pairing_ref == c.peer).ok_or(())?;
                let expires = expires.min(c.expires);
                let id = format!("pushed:{}:{}", c.peer, c.id);
                out.push((
                    RemoteCandidate {
                        id: id.clone(),
                        peer: c.peer.clone(),
                        device: peer.label.clone(),
                        kind,
                        source: c.source.clone(),
                        received_at: Some(c.received_at),
                        remaining_ms: expires
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64,
                    },
                    Selection {
                        remote: None,
                        candidate: id,
                        peer: c.peer.clone(),
                        expires,
                        cached: true,
                    },
                ));
            }
        }
        out.truncate(20);
        Ok(out)
    }
    pub(super) fn consumed(&self, id: &str) -> bool {
        self.consumed
            .get(id.strip_prefix("pushed:").unwrap_or(id))
            .is_some_and(|until| *until > Instant::now())
    }
    pub(super) fn value(
        &mut self,
        id: &str,
        kind: Kind,
        trust: &[LanTrustedPeer],
    ) -> Result<Zeroizing<String>, ()> {
        self.prune(trust)?;
        if kind == Kind::Phone {
            let p = self
                .phones
                .iter()
                .find(|p| format!("registered:{}", p.peer) == id)
                .ok_or(())?;
            return Ok(Zeroizing::new(p.value.clone()));
        }
        let i = self
            .sms
            .iter()
            .position(|c| format!("pushed:{}:{}", c.peer, c.id) == id)
            .ok_or(())?;
        let c = self.sms.remove(i);
        if self.consumed.len() >= 128 {
            return Err(());
        }
        self.consumed
            .insert(format!("{}:{}", c.peer, c.id), c.expires);
        self.save_consumed()?;
        Ok(c.value)
    }
}
fn wall_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn valid_phone(v: &str) -> bool {
    !v.is_empty() && v.len() <= 24 && v.bytes().all(|b| b.is_ascii_digit() || b == b'+')
}
pub(super) fn serve_watch(
    tls: &mut TlsStream,
    c: &HostContext,
    peer: &LanTrustedPeer,
) -> Result<(), ()> {
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end && !c.stop.load(Ordering::Acquire) {
        let valid = (c.valid)();
        let trusted = c.trust.load()?.iter().any(|p| {
            p.pairing_ref == peer.pairing_ref
                && p.certificate_fingerprint == peer.certificate_fingerprint
        });
        let snapshot = {
            let mut s = c.state.lock().map_err(|_| ())?;
            s.grants = stored_grants(c.trust.credentials.as_ref())?;
            prune(&mut s);
            let phone = valid && trusted && allowed(&s, peer, &c.binding, Kind::Phone);
            let sms = valid && trusted && allowed(&s, peer, &c.binding, Kind::Sms);
            Snapshot {
                binding: c.binding.clone(),
                phone: if phone && !s.phone.is_empty() {
                    Some(s.phone.to_string())
                } else {
                    None
                },
                codes: if sms {
                    s.codes
                        .iter()
                        .filter(|v| v.request.is_none())
                        .map(|v| PushedCode {
                            id: v.id.clone(),
                            value: v.value.to_string(),
                            source: v.source.clone(),
                            received_at: v.received_at,
                            remaining_ms: v
                                .expires
                                .saturating_duration_since(Instant::now())
                                .as_millis() as u64,
                        })
                        .collect()
                } else {
                    vec![]
                },
            }
        };
        secret_write(tls, &snapshot)?;
        if !valid || !trusted {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}
pub(super) fn start(client: &AssistClient, cache: Arc<Mutex<Cache>>) {
    let expiring = cache.clone();
    let jobs = client.jobs.clone();
    let stopped = client.running.stop.clone();
    thread::spawn(move || {
        while !stopped.load(Ordering::Acquire) {
            if let Ok(mut c) = expiring.lock() {
                c.expire();
            }
            if let Ok(mut pending) = jobs.lock() {
                pending.retain(|_, job| job.expires > Instant::now());
            }
            thread::sleep(Duration::from_millis(200));
        }
    });

    let remotes = client.remotes.clone();
    let trust = client.trust.clone();
    let identity = client.id.clone();
    let sessions = client.running.sessions.clone();
    let stop = client.running.stop.clone();
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            let endpoints = remotes.lock().map(|r| r.clone()).unwrap_or_default();
            // One bounded subscription per instance; each connection is still pinned to its paired identity.
            let mut groups: HashMap<String, Vec<Remote>> = HashMap::new();
            for r in endpoints {
                groups.entry(r.instance.clone()).or_default().push(r);
            }
            thread::scope(|scope| {
                for addresses in groups.values().take(MAX_PEERS) {
                    let endpoints = &remotes;
                    let cache = &cache;
                    let trust = &trust;
                    let identity = &identity;
                    let sessions = &sessions;
                    let stop = &stop;
                    scope.spawn(move || {
                        for remote in addresses {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            if watch(trust, identity, remote, sessions, stop, cache, endpoints)
                                .is_ok()
                            {
                                break;
                            }
                        }
                    });
                }
            });
            thread::sleep(Duration::from_millis(500));
        }
    });
}
fn watch(
    trust: &TrustStore,
    id: &Identity,
    remote: &Remote,
    sessions: &Arc<SessionRegistry>,
    stop: &AtomicBool,
    cache: &Mutex<Cache>,
    endpoints: &Mutex<Vec<Remote>>,
) -> Result<(), ()> {
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
            version: 2,
            instance: remote.instance.clone(),
        },
    )?;
    secret_write(&mut tls, &Command::Watch)?;
    let mut received = false;
    while !stop.load(Ordering::Acquire) {
        let snapshot = match secret_read::<Snapshot>(&mut tls) {
            Ok(v) => v,
            Err(()) => return if received { Ok(()) } else { Err(()) },
        };
        let _registration = super::registration_guard()?;
        trusted_cert(trust, &cert)?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        let mut c = cache.lock().map_err(|_| ())?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        c.update(&peer, remote, &snapshot)?;
        received = true;
        if let Ok(mut entries) = endpoints.lock() {
            if let Some(entry) = entries
                .iter_mut()
                .find(|e| e.instance == remote.instance && e.address == remote.address)
            {
                entry.expires = Instant::now() + TTL;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            binding: "synthetic-vault".into(),
            phone: Some("+12025550123".into()),
            codes: vec![PushedCode {
                id: "a".repeat(32),
                value: "123456".into(),
                source: "synthetic".into(),
                received_at: now(),
                remaining_ms: 120_000,
            }],
        }
    }
    fn remote() -> Remote {
        Remote {
            address: "127.0.0.1:1".parse().unwrap(),
            instance: "b".repeat(32),
            full: "synthetic".into(),
            expires: Instant::now() + TTL,
        }
    }
    #[test]
    fn ct_device_assist_registration_persists_is_scoped_and_revokes() {
        let (_, _, trust, c) = super::super::tests::fixture();
        let peer = trust.load().unwrap().remove(0);
        let s = snapshot();
        let mut cache = Cache::new(trust.credentials.clone(), "vault-a").unwrap();
        cache.update(&peer, &remote(), &s).unwrap();
        let mut restored = Cache::new(trust.credentials.clone(), "vault-a").unwrap();
        assert_eq!(
            restored
                .candidates(Kind::Phone, &[peer.clone()], Instant::now() + TTL)
                .unwrap()
                .len(),
            1
        );
        assert!(restored
            .candidates(Kind::Sms, &[peer.clone()], Instant::now() + TTL)
            .unwrap()
            .is_empty());
        assert!(Cache::new(trust.credentials.clone(), "vault-b")
            .unwrap()
            .phones
            .is_empty());
        restored.prune(&[]).unwrap();
        assert!(Cache::new(trust.credentials.clone(), "vault-a")
            .unwrap()
            .phones
            .is_empty());
        cache
            .update(
                &peer,
                &remote(),
                &Snapshot {
                    binding: c.binding,
                    phone: None,
                    codes: vec![],
                },
            )
            .unwrap();
        assert!(cache.phones.is_empty());
    }
    #[test]
    fn ct_device_assist_local_revoke_deletes_registered_phone_before_same_identity_repair() {
        let (_, _, trust, _) = super::super::tests::fixture();
        let peer = trust.load().unwrap().remove(0);
        let mut cache = Cache::new(trust.credentials.clone(), "revoked-vault").unwrap();
        cache.update(&peer, &remote(), &snapshot()).unwrap();
        trust.revoke(&peer.pairing_ref).unwrap();
        trust.approve(peer.clone()).unwrap();
        assert!(cache
            .candidates(Kind::Phone, &[peer.clone()], Instant::now() + TTL)
            .unwrap()
            .is_empty());
        assert!(Cache::new(trust.credentials.clone(), "revoked-vault")
            .unwrap()
            .phones
            .is_empty());
    }
    #[test]
    fn ct_device_assist_push_local_once_per_computer_and_no_ttl_extension() {
        let (_, _, trust, _) = super::super::tests::fixture();
        let peer = trust.load().unwrap().remove(0);
        let s = snapshot();
        let mut a = Cache::new(trust.credentials.clone(), "computer-a").unwrap();
        let mut b = Cache::new(trust.credentials.clone(), "computer-b").unwrap();
        for cache in [&mut a, &mut b] {
            cache.update(&peer, &remote(), &s).unwrap();
        }
        let until = a.sms[0].expires;
        a.update(&peer, &remote(), &s).unwrap();
        assert!(a.sms[0].expires <= until);
        let id = format!("pushed:{}:{}", peer.pairing_ref, s.codes[0].id);
        assert_eq!(
            a.value(&id, Kind::Sms, &[peer.clone()]).unwrap().as_str(),
            "123456"
        );
        assert!(a.value(&id, Kind::Sms, &[peer.clone()]).is_err());
        a.update(&peer, &remote(), &s).unwrap();
        assert!(a.sms.is_empty());
        let mut restarted = Cache::new(trust.credentials.clone(), "computer-a").unwrap();
        restarted.update(&peer, &remote(), &s).unwrap();
        assert!(restarted.sms.is_empty());
        assert_eq!(
            b.value(&id, Kind::Sms, &[peer.clone()]).unwrap().as_str(),
            "123456"
        );
        let mut expired = snapshot();
        expired.codes[0].received_at = now() - 120_001;
        let mut empty = Cache::new(trust.credentials.clone(), "expired").unwrap();
        empty.update(&peer, &remote(), &expired).unwrap();
        assert!(empty.sms.is_empty());
    }
    #[test]
    fn ct_device_assist_real_tls_push_then_offline_local_fill_without_phone_request() {
        let (host, _, trust, context) = super::super::tests::fixture();
        host.set_phone("+12025550123").unwrap();
        host.add_code("123456", "synthetic", 0, "broadcast", None)
            .unwrap();
        host.add_code("654321", "synthetic-second", 0, "broadcast-second", None)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = context.stop.clone();
        let instance = context.instance.clone();
        let server = thread::spawn(move || serve(listener.accept().unwrap().0, &context));
        let mut client =
            AssistClient::with_credentials(trust.path.clone(), trust.credentials.clone()).unwrap();
        *client.remotes.lock().unwrap() = vec![Remote {
            address: addr,
            instance,
            full: "synthetic".into(),
            expires: Instant::now() + TTL,
        }];
        client
            .enable_registration("synthetic-desktop-vault")
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while client
            .cached(Kind::Sms, Instant::now() + TTL)
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < until, "push not received");
            thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Release);
        assert!(server.join().unwrap().is_ok());
        client.remotes.lock().unwrap().clear();
        for (kind, expected, count) in [
            (Kind::Phone, "+12025550123", 1),
            (Kind::Sms, "654321", 2),
            (Kind::Sms, "123456", 1),
        ] {
            let request = client.begin(kind, "http://example.test").unwrap();
            let state = client.status(&request).unwrap();
            assert!(!state.to_string().contains(expected));
            assert_eq!(state["candidates"].as_array().unwrap().len(), count);
            let candidate = state["candidates"][0]["id"].as_str().unwrap();
            client.consume(&request, candidate).unwrap();
            assert!(client.status(&request).unwrap()["ready"] == true);
            assert_eq!(client.take(&request).unwrap().as_str(), expected);
            assert!(client.take(&request).is_err());
        }
        let repeated = client.begin(Kind::Sms, "http://example.test").unwrap();
        assert!(client.status(&repeated).unwrap()["candidates"]
            .as_array()
            .unwrap()
            .is_empty());
        // An abandoned selected value must be dropped on expiry even without another UI poll.
        let abandoned = client.begin(Kind::Phone, "http://example.test").unwrap();
        let selected = client.status(&abandoned).unwrap()["candidates"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        client.consume(&abandoned, &selected).unwrap();
        client
            .jobs
            .lock()
            .unwrap()
            .get_mut(&abandoned)
            .unwrap()
            .expires = Instant::now();
        thread::sleep(Duration::from_millis(250));
        assert!(!client.jobs.lock().unwrap().contains_key(&abandoned));
        client.clear();
    }
}
