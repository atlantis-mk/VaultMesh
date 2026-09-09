//! Durable ciphertext-only cache. Vault transactions remain the source of truth.
use crate::VaultmeshVault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use vaultmesh_core::{SyncPacket, SyncRoute};

pub const RELAY_MAX_BYTES: usize = 256 * 1024 * 1024;
pub const RELAY_MAX_PACKET: usize = 90 * 1024 * 1024;
static SYSTEM_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_system_locked(locked: bool) {
    SYSTEM_LOCKED.store(locked, std::sync::atomic::Ordering::Release);
}
pub fn system_locked() -> bool {
    SYSTEM_LOCKED.load(std::sync::atomic::Ordering::Acquire)
}
#[cfg(test)]
thread_local! { pub(crate) static TEST_CACHE_LIMIT: std::cell::Cell<usize> = const {std::cell::Cell::new(RELAY_MAX_BYTES)}; }
#[cfg(test)]
thread_local! { pub(crate) static FAIL_CACHE: std::cell::Cell<bool> = const {std::cell::Cell::new(false)}; }
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayProfile {
    pub routes: Vec<SyncRoute>,
    pub vault_fingerprint: String,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayPeer {
    pub outgoing: Option<SyncPacket>,
    pub incoming: Option<SyncPacket>,
    pub outgoing_receipt: Option<SyncPacket>,
    pub incoming_receipt: Option<SyncPacket>,
    #[serde(default)]
    pub applied: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayBlob {
    pub id: String,
    pub nonce: String,
    pub channel: uuid::Uuid,
    pub size: usize,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelaySummary {
    pub data: Option<RelayBlob>,
    pub receipt: Option<RelayBlob>,
    pub received: Option<String>,
    pub received_receipt: Option<String>,
    pub applied: Option<String>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    profile: RelayProfile,
    peers: BTreeMap<String, RelayPeer>,
}
struct State {
    disk: Disk,
    generation: u64,
    // Only an unlocked core publication can mint this flag. Loading a cache
    // needs separate OS-protected proof verification by the desktop service.
    from_core: bool,
    projection: String,
    failed: bool,
    merged: u64,
}
pub struct RelayHub {
    path: PathBuf,
    state: Mutex<State>,
}
static HUBS: OnceLock<Mutex<Vec<(PathBuf, Weak<RelayHub>)>>> = OnceLock::new();
fn cache_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.lan-mailbox",
        path.file_name().unwrap().to_string_lossy()
    ))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Disk, ()> {
    let file = std::fs::File::open(path).map_err(|_| ())?;
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(RELAY_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > RELAY_MAX_BYTES {
        return Err(());
    }
    let disk: Disk = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if disk.profile.routes.len() > 32 || disk.peers.len() > 32 {
        return Err(());
    }
    for e in disk.peers.values() {
        for p in [
            &e.outgoing,
            &e.incoming,
            &e.outgoing_receipt,
            &e.incoming_receipt,
        ]
        .into_iter()
        .flatten()
        {
            if p.ciphertext.len() > RELAY_MAX_PACKET
                || !p.ciphertext.is_ascii()
                || p.id.len() != 44
                || p.nonce.len() != 32
            {
                return Err(());
            }
        }
    }
    Ok(disk)
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        let limit = TEST_CACHE_LIMIT.with(|v| v.get());
        #[cfg(not(test))]
        let limit = RELAY_MAX_BYTES;
        if self.0.len().saturating_add(bytes.len()) > limit {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn persist(path: &Path, disk: &Disk) -> Result<(), ()> {
    #[cfg(test)]
    if FAIL_CACHE.with(|v| v.get()) {
        return Err(());
    }
    let mut bytes = Bounded(Vec::new());
    serde_json::to_writer(&mut bytes, disk).map_err(|_| ())?;
    let mut options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StdExt;
        OpenOptionsExt::preserve_mode(&mut options, false);
        StdExt::mode(&mut options, 0o600);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    file.write_all(&bytes.0).map_err(|_| ())?;
    file.commit().map_err(|_| ())
}
impl RelayHub {
    pub(crate) fn invalidate(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.disk = Disk::default();
            s.from_core = false;
            s.projection.clear();
            s.generation = s.generation.wrapping_add(1);
            let _ = std::fs::remove_file(cache_path(&self.path));
        }
    }
    pub fn for_path(path: &Path) -> Arc<Self> {
        let mut hubs = HUBS.get_or_init(Default::default).lock().unwrap();
        hubs.retain(|(_, h)| h.strong_count() > 0);
        if let Some(h) = hubs
            .iter()
            .find(|(p, _)| p == path)
            .and_then(|(_, h)| h.upgrade())
        {
            return h;
        }
        let disk = read(&cache_path(path)).unwrap_or_default();
        let hub = Arc::new(Self {
            path: path.into(),
            state: Mutex::new(State {
                disk,
                generation: 1,
                from_core: false,
                projection: String::new(),
                failed: false,
                merged: 0,
            }),
        });
        // Runtime count is bounded by desktop/browser/Agent authorization limits.
        if hubs.len() < 64 {
            hubs.push((path.into(), Arc::downgrade(&hub)));
        }
        hub
    }
    pub fn profile(&self) -> Result<(RelayProfile, bool), ()> {
        let s = self.state.lock().map_err(|_| ())?;
        Ok((s.disk.profile.clone(), s.from_core))
    }
    pub fn proof(&self) -> Result<String, ()> {
        let s = self.state.lock().map_err(|_| ())?;
        let mut bytes = self.path.to_string_lossy().as_bytes().to_vec();
        bytes.extend(serde_json::to_vec(&s.disk.profile).map_err(|_| ())?);
        Ok(hash(&bytes))
    }
    pub fn matches_vault(&self) -> bool {
        let Ok((profile, _)) = self.profile() else {
            return false;
        };
        crate::storage::read_vault(&self.path)
            .is_ok_and(|bytes| hash(&bytes) == profile.vault_fingerprint)
    }
    pub fn generation(&self) -> u64 {
        self.state.lock().map(|s| s.generation).unwrap_or(0)
    }
    pub fn route(&self, peer: &str) -> Result<SyncRoute, ()> {
        self.state
            .lock()
            .map_err(|_| ())?
            .disk
            .profile
            .routes
            .iter()
            .find(|r| r.peer == peer)
            .cloned()
            .ok_or(())
    }
    pub fn failed(&self) -> bool {
        self.state.lock().map(|s| s.failed).unwrap_or(true)
    }
    pub fn merged_generation(&self) -> u64 {
        self.state.lock().map(|s| s.merged).unwrap_or(0)
    }
    pub fn peer(&self, peer: &str) -> Result<RelayPeer, ()> {
        self.state
            .lock()
            .map_err(|_| ())?
            .disk
            .peers
            .get(peer)
            .cloned()
            .ok_or(())
    }
    pub fn summary(&self, peer: &str) -> Result<RelaySummary, ()> {
        let s = self.state.lock().map_err(|_| ())?;
        let e = s.disk.peers.get(peer).ok_or(())?;
        let info = |p: &SyncPacket| RelayBlob {
            id: p.id.clone(),
            nonce: p.nonce.clone(),
            channel: p.channel,
            size: p.ciphertext.len(),
        };
        Ok(RelaySummary {
            data: e.outgoing.as_ref().map(info),
            receipt: e.outgoing_receipt.as_ref().map(info),
            received: e.incoming.as_ref().map(|p| p.id.clone()),
            received_receipt: e.incoming_receipt.as_ref().map(|p| p.id.clone()),
            applied: e.applied.clone(),
        })
    }
    pub fn chunk(
        &self,
        peer: &str,
        receipt: bool,
        id: &str,
        offset: usize,
        max: usize,
    ) -> Result<Option<String>, ()> {
        let s = self.state.lock().map_err(|_| ())?;
        let e = s.disk.peers.get(peer).ok_or(())?;
        let p = if receipt {
            &e.outgoing_receipt
        } else {
            &e.outgoing
        };
        let Some(p) = p.as_ref().filter(|p| p.id == id) else {
            return Ok(None);
        };
        if offset >= p.ciphertext.len() {
            return Err(());
        }
        Ok(Some(
            p.ciphertext[offset..p.ciphertext.len().min(offset.saturating_add(max))].to_owned(),
        ))
    }
    pub fn store(&self, peer: &str, packet: SyncPacket, receipt: bool) -> Result<(), ()> {
        if packet.ciphertext.len() > RELAY_MAX_PACKET
            || !packet.ciphertext.is_ascii()
            || packet.id.len() != 44
            || packet.nonce.len() != 32
        {
            return Err(());
        }
        let mut s = self.state.lock().map_err(|_| ())?;
        let route = s
            .disk
            .profile
            .routes
            .iter()
            .find(|r| r.peer == peer)
            .ok_or(())?;
        if route.incoming != Some(packet.channel) {
            return Err(());
        }
        let entry = s.disk.peers.get_mut(peer).ok_or(())?;
        let slot = if receipt {
            &mut entry.incoming_receipt
        } else {
            &mut entry.incoming
        };
        if slot.as_ref().is_some_and(|p| p.id == packet.id) {
            return Ok(());
        }
        let old = slot.replace(packet);
        if persist(&cache_path(&self.path), &s.disk).is_err() {
            let e = s.disk.peers.get_mut(peer).unwrap();
            *(if receipt {
                &mut e.incoming_receipt
            } else {
                &mut e.incoming
            }) = old;
            s.failed = true;
            return Err(());
        }
        s.generation = s.generation.wrapping_add(1);
        Ok(())
    }
    fn publish(&self, vault: &VaultmeshVault) -> Result<(), ()> {
        let disk = crate::storage::read_vault(&vault.path)?;
        if crate::vault::vault_fingerprint(&disk) != vault.persisted_fingerprint {
            return Err(());
        }
        let routes = vault.session.sync_routes().map_err(|_| ())?;
        let state = vault.session.sync_state().map_err(|_| ())?;
        let projection =
            hash(&serde_json::to_vec(&(&state.entries, &state.authorizations)).map_err(|_| ())?);
        let profile = RelayProfile {
            routes,
            vault_fingerprint: vault
                .persisted_fingerprint
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        };
        let mut s = self.state.lock().map_err(|_| ())?;
        // Invalidate removed/rotated routes before any fallible cache writes.
        let old_routes = s.disk.profile.routes.clone();
        s.disk.peers.retain(|p, _| {
            profile
                .routes
                .iter()
                .any(|r| &r.peer == p && old_routes.contains(r))
        });
        let changed = s.projection != projection;
        s.disk.profile = profile;
        s.from_core = true;
        if s.disk.profile.routes.is_empty() {
            // Ordinary non-sync Vaults must not acquire sidecar files. Clearing
            // the final authorization also removes the cold-start cache.
            match std::fs::remove_file(cache_path(&self.path)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    s.failed = true;
                    return Err(());
                }
            }
            s.projection = projection;
            s.failed = false;
            s.generation = s.generation.wrapping_add(1);
            return Ok(());
        }
        if changed {
            for route in &s.disk.profile.routes.clone() {
                let packet = vault
                    .session
                    .sync_mailbox_export(&route.peer)
                    .map_err(|_| ())?;
                let entry = s.disk.peers.entry(route.peer.clone()).or_default();
                entry.applied = state
                    .authorizations
                    .iter()
                    .find(|a| a.peer == route.peer)
                    .and_then(|a| a.applied_packet.clone());
                if entry.outgoing.as_ref().map(|p| &p.id) != packet.as_ref().map(|p| &p.id) {
                    entry.outgoing = packet;
                }
            }
        }
        if persist(&cache_path(&self.path), &s.disk).is_err() {
            s.failed = true;
            s.generation = s.generation.wrapping_add(1);
            return Err(());
        }
        s.projection = projection;
        s.failed = false;
        s.generation = s.generation.wrapping_add(1);
        Ok(())
    }
    fn applied_receipt(&self, peer: &str, packet: SyncPacket) -> Result<(), ()> {
        let mut s = self.state.lock().map_err(|_| ())?;
        let entry = s.disk.peers.get_mut(peer).ok_or(())?;
        let old = entry.outgoing_receipt.replace(packet);
        if persist(&cache_path(&self.path), &s.disk).is_err() {
            s.disk.peers.get_mut(peer).unwrap().outgoing_receipt = old;
            s.failed = true;
            return Err(());
        }
        s.generation = s.generation.wrapping_add(1);
        Ok(())
    }
}
/// Publication failure is a sync error, never a failed user mutation after a
/// successful Vault commit. The next unlocked refresh reconstructs the cache.
pub(crate) fn publish(vault: &VaultmeshVault) {
    let lock = crate::vault::mutation_lock(&vault.path);
    let Ok(_guard) = lock.lock() else { return };
    publish_committed(vault);
}
/// Called only while holding the same per-Vault writer lock as the file commit.
pub(crate) fn publish_committed(vault: &VaultmeshVault) {
    let hub = RelayHub::for_path(&vault.path);
    if hub.publish(vault).is_err() {
        if let Ok(mut s) = hub.state.lock() {
            s.failed = true;
        }
    }
}
pub(crate) fn pump(vault: &mut VaultmeshVault) -> Result<(), ()> {
    if system_locked() {
        return Ok(());
    }
    let result = pump_inner(vault);
    if result.is_err() {
        if let Ok(mut s) = RelayHub::for_path(&vault.path).state.lock() {
            s.failed = true;
        }
    }
    result
}
fn pump_inner(vault: &mut VaultmeshVault) -> Result<(), ()> {
    let hub = RelayHub::for_path(&vault.path);
    if hub.failed()
        || hub.profile()?.0.vault_fingerprint
            != vault
                .persisted_fingerprint
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
    {
        publish(vault);
        if hub.failed() {
            return Err(());
        }
    }
    for route in vault.session.sync_routes().map_err(|_| ())? {
        let Some(_) = route.incoming else { continue };
        let peer = hub.peer(&route.peer)?;
        if let Some(receipt) = peer.incoming_receipt {
            let seen = vault
                .session
                .sync_state()
                .map_err(|_| ())?
                .authorizations
                .iter()
                .find(|a| a.peer == route.peer)
                .and_then(|a| a.confirmed_packet.as_ref());
            if seen != Some(&receipt.id) {
                crate::browser_ops::transaction(vault, |s| {
                    s.sync_mailbox_confirm(&route.peer, &receipt)
                        .map_err(crate::vault::map_core_error)?;
                    Ok(serde_json::json!({}))
                })
                .map_err(|_| ())?;
            }
        }
        if let Some(packet) = peer.incoming {
            let applied = vault
                .session
                .sync_state()
                .map_err(|_| ())?
                .authorizations
                .iter()
                .find(|a| a.peer == route.peer)
                .and_then(|a| a.applied_packet.as_ref());
            // A lost receipt cache is safely recreated from the same packet.
            if applied != Some(&packet.id) || peer.outgoing_receipt.is_none() {
                let mut receipt = None;
                let mut changes = 0;
                crate::browser_ops::transaction(vault, |s| {
                    let (count, ack) = s
                        .sync_mailbox_apply(
                            &route.peer,
                            &packet,
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        )
                        .map_err(crate::vault::map_core_error)?;
                    changes = count;
                    receipt = Some(ack);
                    Ok(serde_json::json!({}))
                })
                .map_err(|_| ())?;
                if changes > 0 {
                    let mut state = hub.state.lock().map_err(|_| ())?;
                    state.merged = state.merged.wrapping_add(1);
                }
                hub.applied_receipt(&route.peer, receipt.unwrap())?;
            }
        }
    }
    Ok(())
}
