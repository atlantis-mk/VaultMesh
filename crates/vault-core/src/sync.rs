//! Portable, encrypted record synchronization. No transport, files or UI.
use crate::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const SYNC_MAX_RECORDS: usize = 100_000;
pub const SYNC_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct SyncVersion {
    pub millis: u64,
    pub counter: u64,
    pub replica: Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncEntry {
    pub version: SyncVersion,
    pub digest: String,
    pub deleted: bool,
    pub seen: BTreeMap<Uuid, SyncVersion>,
}
pub type SyncManifest = BTreeMap<String, SyncEntry>;

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecord {
    pub key: String,
    pub entry: SyncEntry,
    pub body: Option<String>,
}
impl std::fmt::Debug for SyncRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncRecord")
            .field("key", &self.key)
            .field("body", &"[REDACTED]")
            .finish()
    }
}
impl Drop for SyncRecord {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncAuthorization {
    pub peer: String,
    pub fingerprint: String,
    pub remote_vault: Option<Uuid>,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing: Option<crate::SyncChannel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming: Option<crate::SyncChannel>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub confirmed: SyncManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_packet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_packet: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    pub vault_id: Uuid,
    pub replica: Uuid,
    pub clock: SyncVersion,
    pub entries: SyncManifest,
    pub authorizations: Vec<SyncAuthorization>,
    pub conflicts: BTreeMap<String, SyncRecord>,
}
impl std::fmt::Debug for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncState")
            .field("records", &self.entries.len())
            .field("conflicts", &self.conflicts.len())
            .finish()
    }
}
impl Default for SyncState {
    fn default() -> Self {
        Self {
            vault_id: Uuid::new_v4(),
            replica: Uuid::new_v4(),
            clock: SyncVersion::default(),
            entries: BTreeMap::new(),
            authorizations: vec![],
            conflicts: BTreeMap::new(),
        }
    }
}
impl Zeroize for SyncState {
    fn zeroize(&mut self) {
        self.conflicts.clear();
        self.entries.clear();
        self.authorizations.clear();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    collection: String,
    data: String,
}
impl Drop for Body {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
type Projection = BTreeMap<String, Zeroizing<String>>;
fn invalid<T>() -> Result<T, VaultError> {
    Err(VaultError::InvalidPayload)
}
fn digest(body: Option<&str>) -> String {
    format!("{:x}", Sha256::digest(body.unwrap_or("").as_bytes()))
}
fn encode<T: Serialize>(collection: &str, item: &T) -> Result<Zeroizing<String>, VaultError> {
    let body = Body {
        collection: collection.into(),
        data: serde_json::to_string(item).map_err(|_| VaultError::Serialization)?,
    };
    serde_json::to_string(&body)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Serialization)
}
fn insert<T: Serialize>(
    map: &mut Projection,
    key: String,
    collection: &str,
    item: &T,
) -> Result<(), VaultError> {
    if map.insert(key, encode(collection, item)?).is_some() {
        return invalid();
    }
    Ok(())
}
fn syncable_secret(item: &SecretItem) -> bool {
    if !item.scopes.iter().any(|s| s == "vaultmesh:passkey:v1") {
        return true;
    }
    // Legacy single-device WebAuthn credentials must never be cloned.
    #[derive(Deserialize)]
    struct Eligibility {
        #[serde(rename = "backupEligible", default)]
        eligible: bool,
    }
    serde_json::from_str::<Eligibility>(&item.secret).is_ok_and(|s| s.eligible)
}
fn portable_secret(item: &SecretItem) -> Result<SecretItem, VaultError> {
    let mut item = item.clone();
    if item.scopes.iter().any(|s| s == "vaultmesh:passkey:v1") {
        // Backup state is local receipt evidence, not a last-writer value.
        let mut value = SensitiveValue(
            serde_json::from_str(&item.secret).map_err(|_| VaultError::InvalidPayload)?,
        );
        value.0["backupState"] = serde_json::Value::Bool(false);
        value.0["lastUsedAt"] = serde_json::Value::Null;
        item.secret.zeroize();
        item.secret = serde_json::to_string(&value.0).map_err(|_| VaultError::Serialization)?;
    }
    Ok(item)
}
fn backed_up(text: &str) -> bool {
    #[derive(Deserialize)]
    struct State {
        #[serde(rename = "backupState", default)]
        backed: bool,
    }
    serde_json::from_str::<State>(text).is_ok_and(|s| s.backed)
}
struct SensitiveValue(serde_json::Value);
impl Drop for SensitiveValue {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}
fn wipe_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}

fn project(p: &VaultPayload) -> Result<Projection, VaultError> {
    let mut out = BTreeMap::new();
    macro_rules! family {
        ($kind:literal, $live:ident, $trash:ident, $history:ident) => {
            for item in &p.$live {
                insert(
                    &mut out,
                    format!("{}/{}", $kind, item.id),
                    stringify!($live),
                    item,
                )?;
            }
            for item in &p.$trash {
                insert(
                    &mut out,
                    format!("{}/{}", $kind, item.item.id),
                    stringify!($trash),
                    item,
                )?;
            }
            for item in &p.$history {
                insert(
                    &mut out,
                    format!("{}/{}", stringify!($history), item.revision_id),
                    stringify!($history),
                    item,
                )?;
            }
        };
    }
    family!("login", items, trash, history);
    family!("card", cards, card_trash, card_history);
    family!("identity", identities, identity_trash, identity_history);
    family!("service", services, service_trash, service_history);
    family!(
        "environment",
        api_environments,
        api_environment_trash,
        api_environment_history
    );
    for value in &p.ssh_items {
        let mut item = value.clone();
        item.managed_ssh_host = None;
        insert(&mut out, format!("ssh/{}", item.id), "ssh_items", &item)?;
    }
    for value in &p.ssh_trash {
        let mut item = value.clone();
        item.item.managed_ssh_host = None;
        insert(
            &mut out,
            format!("ssh/{}", item.item.id),
            "ssh_trash",
            &item,
        )?;
    }
    for value in &p.ssh_history {
        let mut item = value.clone();
        item.item.managed_ssh_host = None;
        insert(
            &mut out,
            format!("ssh_history/{}", item.revision_id),
            "ssh_history",
            &item,
        )?;
    }
    for item in &p.secrets {
        if syncable_secret(item) {
            insert(
                &mut out,
                format!("secret/{}", item.id),
                "secrets",
                &portable_secret(item)?,
            )?;
        }
    }
    for (key, record) in &p.sync.conflicts {
        insert(&mut out, key.clone(), "conflicts", record)?;
    }
    if out.len() > SYNC_MAX_RECORDS {
        return invalid();
    }
    Ok(out)
}

fn next_version(s: &mut SyncState, now: u64) -> Result<SyncVersion, VaultError> {
    let millis = now.max(s.clock.millis);
    let counter = if millis == s.clock.millis {
        s.clock
            .counter
            .checked_add(1)
            .ok_or(VaultError::InvalidPayload)?
    } else {
        0
    };
    s.clock = SyncVersion {
        millis,
        counter,
        replica: s.replica,
    };
    Ok(s.clock.clone())
}
pub(crate) fn record_history_clear(
    p: &mut VaultPayload,
    collection: &str,
    id: Uuid,
) -> Result<(), VaultError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let version = next_version(&mut p.sync, now)?;
    let key = format!("clear_{collection}/{id}");
    let mut seen = p
        .sync
        .entries
        .get(&key)
        .map(|e| e.seen.clone())
        .unwrap_or_default();
    if let Some(old) = p.sync.entries.get(&key) {
        seen.insert(old.version.replica, old.version.clone());
    }
    p.sync.entries.insert(
        key,
        SyncEntry {
            version,
            digest: digest(None),
            deleted: true,
            seen,
        },
    );
    Ok(())
}
fn prune_cleared_history(p: &mut VaultPayload) {
    let entries = &p.sync.entries;
    let cleared = |collection: &str, owner: Uuid, version: &SyncVersion| {
        entries
            .get(&format!("clear_{collection}/{owner}"))
            .is_some_and(|marker| version <= &marker.version)
    };
    macro_rules! history {
        ($field:ident, $owner:ident) => {
            p.$field.retain(|r| {
                !entries
                    .get(&format!("{}/{}", stringify!($field), r.revision_id))
                    .is_some_and(|entry| cleared(stringify!($field), r.$owner, &entry.version))
            });
        };
    }
    history!(history, item_id);
    history!(card_history, item_id);
    history!(identity_history, item_id);
    history!(ssh_history, item_id);
    history!(service_history, service_id);
    history!(api_environment_history, environment_id);
    p.sync
        .conflicts
        .retain(|_, r| !cleared("conflicts", Uuid::from_u128(1), &r.entry.version));
}
fn checkpoint(p: &mut VaultPayload, now: u64) -> Result<(), VaultError> {
    prune_cleared_history(p);
    let values = project(p)?;
    let keys: BTreeSet<_> = values
        .keys()
        .chain(p.sync.entries.keys())
        .cloned()
        .collect();
    for key in keys {
        let value = values.get(&key).map(|s| s.as_str());
        let hash = digest(value);
        if p.sync
            .entries
            .get(&key)
            .is_some_and(|e| e.digest == hash && e.deleted == value.is_none())
        {
            continue;
        }
        let mut seen = p
            .sync
            .entries
            .get(&key)
            .map(|e| e.seen.clone())
            .unwrap_or_default();
        if let Some(old) = p.sync.entries.get(&key) {
            seen.insert(old.version.replica, old.version.clone());
        }
        let version = next_version(&mut p.sync, now)?;
        p.sync.entries.insert(
            key,
            SyncEntry {
                version,
                digest: hash,
                deleted: value.is_none(),
                seen,
            },
        );
    }
    if p.sync.entries.len() > SYNC_MAX_RECORDS {
        return invalid();
    }
    Ok(())
}

// Deserialize only allowlisted typed records; arbitrary payload fields cannot arrive over LAN.
fn apply(p: &mut VaultPayload, key: &str, text: &str) -> Result<(), VaultError> {
    let body: Body = serde_json::from_str(text).map_err(|_| VaultError::InvalidPayload)?;
    let (kind, id) = key.split_once('/').ok_or(VaultError::InvalidPayload)?;
    let id = Uuid::parse_str(id).map_err(|_| VaultError::InvalidPayload)?;
    macro_rules! live {
        ($field:ident, $ty:ty, $kind:literal) => {{
            let item: $ty =
                serde_json::from_str(&body.data).map_err(|_| VaultError::InvalidPayload)?;
            if kind != $kind || item.id != id {
                return invalid();
            }
            p.$field.push(item);
        }};
    }
    macro_rules! trash {
        ($field:ident, $ty:ty, $kind:literal) => {{
            let item: $ty =
                serde_json::from_str(&body.data).map_err(|_| VaultError::InvalidPayload)?;
            if kind != $kind || item.item.id != id {
                return invalid();
            }
            p.$field.push(item);
        }};
    }
    macro_rules! history {
        ($field:ident, $ty:ty) => {{
            let item: $ty =
                serde_json::from_str(&body.data).map_err(|_| VaultError::InvalidPayload)?;
            if kind != stringify!($field) || item.revision_id != id {
                return invalid();
            }
            p.$field.push(item);
        }};
    }
    match body.collection.as_str() {
        "items" => live!(items, LoginItem, "login"),
        "trash" => trash!(trash, TrashedLoginItem, "login"),
        "history" => history!(history, LoginItemRevision),
        "cards" => live!(cards, PaymentCardItem, "card"),
        "card_trash" => trash!(card_trash, TrashedPaymentCard, "card"),
        "card_history" => history!(card_history, PaymentCardRevision),
        "identities" => live!(identities, IdentityItem, "identity"),
        "identity_trash" => trash!(identity_trash, TrashedIdentity, "identity"),
        "identity_history" => history!(identity_history, IdentityRevision),
        "services" => live!(services, ServiceRecord, "service"),
        "service_trash" => trash!(service_trash, TrashedServiceRecord, "service"),
        "service_history" => history!(service_history, ServiceRevision),
        "api_environments" => live!(api_environments, ApiEnvironmentRecord, "environment"),
        "api_environment_trash" => {
            trash!(api_environment_trash, TrashedApiEnvironment, "environment")
        }
        "api_environment_history" => history!(api_environment_history, ApiEnvironmentRevision),
        "ssh_items" => live!(ssh_items, SshCredentialItem, "ssh"),
        "ssh_trash" => trash!(ssh_trash, TrashedSshCredential, "ssh"),
        "ssh_history" => history!(ssh_history, SshCredentialRevision),
        "secrets" => {
            let item: SecretItem =
                serde_json::from_str(&body.data).map_err(|_| VaultError::InvalidPayload)?;
            if kind != "secret" || item.id != id || !syncable_secret(&item) {
                return invalid();
            }
            p.secrets.push(item);
        }
        "conflicts" => {
            let record: SyncRecord =
                serde_json::from_str(&body.data).map_err(|_| VaultError::InvalidPayload)?;
            if kind != "conflict"
                || record.key.starts_with("conflict/")
                || conflict_key(&record)? != key
            {
                return invalid();
            }
            // Validate nested record using the same allowlist, excluding nested conflicts.
            let mut check = VaultPayload::default();
            if let Some(text) = &record.body {
                apply(&mut check, &record.key, text)?;
                validate_payload(&check)?;
            }
            p.sync.conflicts.insert(key.to_owned(), record);
        }
        _ => return invalid(),
    }
    Ok(())
}
fn conflict_key(record: &SyncRecord) -> Result<String, VaultError> {
    let mut hash = Sha256::new();
    hash.update(record.key.as_bytes());
    hash.update(serde_json::to_vec(&record.entry.version).map_err(|_| VaultError::Serialization)?);
    let bytes: [u8; 32] = hash.finalize().into();
    let id = Uuid::from_bytes(
        bytes[..16]
            .try_into()
            .map_err(|_| VaultError::InvalidPayload)?,
    );
    Ok(format!("conflict/{id}"))
}
fn clear_portable(p: &mut VaultPayload) {
    p.items.zeroize();
    p.trash.zeroize();
    p.history.zeroize();
    p.cards.zeroize();
    p.card_trash.zeroize();
    p.card_history.zeroize();
    p.identities.zeroize();
    p.identity_trash.zeroize();
    p.identity_history.zeroize();
    p.services.zeroize();
    p.service_trash.zeroize();
    p.service_history.zeroize();
    p.api_environments.zeroize();
    p.api_environment_trash.zeroize();
    p.api_environment_history.zeroize();
    p.ssh_items.zeroize();
    p.ssh_trash.zeroize();
    p.ssh_history.zeroize();
    p.secrets.retain(|s| !syncable_secret(s));
    p.sync.conflicts.clear();
}

fn local_ssh_binding(
    previous: &SshCredentialItem,
    current: &SshCredentialItem,
) -> Option<ManagedSshHostBinding> {
    (previous.host == current.host
        && previous.port == current.port
        && previous.username == current.username
        && previous.private_key == current.private_key
        && previous.public_key == current.public_key
        && previous.key_passphrase == current.key_passphrase)
        .then(|| previous.managed_ssh_host.clone())
        .flatten()
}

fn as_input<T: serde::de::DeserializeOwned>(record: &impl Serialize) -> Result<T, VaultError> {
    let bytes = Zeroizing::new(serde_json::to_vec(record).map_err(|_| VaultError::Serialization)?);
    serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidPayload)
}
fn validate_payload(p: &VaultPayload) -> Result<(), VaultError> {
    use crate::model::{api_environment_policy_digest, normalize_api_environment};
    for r in p
        .items
        .iter()
        .chain(p.trash.iter().map(|r| &r.item))
        .chain(p.history.iter().map(|r| &r.item))
    {
        as_input::<NewLoginItem>(r)?.into_login_item()?;
    }
    for r in p
        .cards
        .iter()
        .chain(p.card_trash.iter().map(|r| &r.item))
        .chain(p.card_history.iter().map(|r| &r.item))
    {
        as_input::<NewPaymentCardItem>(r)?.into_payment_card()?;
    }
    for r in p
        .ssh_items
        .iter()
        .chain(p.ssh_trash.iter().map(|r| &r.item))
        .chain(p.ssh_history.iter().map(|r| &r.item))
    {
        as_input::<NewSshCredentialItem>(r)?.into_ssh_credential()?;
    }
    for r in p
        .identities
        .iter()
        .chain(p.identity_trash.iter().map(|r| &r.item))
        .chain(p.identity_history.iter().map(|r| &r.item))
    {
        as_input::<NewIdentityItem>(r)?.into_identity()?;
    }
    if p.secrets
        .iter()
        .map(|s| s.id)
        .collect::<BTreeSet<_>>()
        .len()
        != p.secrets.len()
    {
        return invalid();
    }
    for r in &p.secrets {
        let lifecycle: Vec<_> = r
            .scopes
            .iter()
            .filter(|s| s.starts_with("vaultmesh:credential-lifecycle:"))
            .collect();
        if lifecycle.len() > 1
            || lifecycle.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "vaultmesh:credential-lifecycle:revoked"
                        | "vaultmesh:credential-lifecycle:needs-review"
                )
            })
            || (!lifecycle.is_empty() && r.kind != SecretItemKind::AccessToken)
        {
            return invalid();
        }
        let mut input = as_input::<NewSecretItem>(r)?;
        input
            .scopes
            .retain(|s| !s.starts_with("vaultmesh:credential-lifecycle:"));
        input.into_secret_item()?;
    }
    for r in p
        .services
        .iter()
        .chain(p.service_trash.iter().map(|r| &r.item))
        .chain(p.service_history.iter().map(|r| &r.item))
    {
        let input = as_input::<NewServiceRecord>(r)?;
        let mut normalized = input.clone();
        crate::model::normalize_new_service(&mut normalized)?;
        if input != normalized
            || r.relationships
                .iter()
                .map(|r| (r.item_kind, r.item_id))
                .collect::<BTreeSet<_>>()
                .len()
                != r.relationships.len()
        {
            return invalid();
        }
    }

    for r in p
        .api_environments
        .iter()
        .chain(p.api_environment_trash.iter().map(|t| &t.item))
        .chain(p.api_environment_history.iter().map(|h| &h.item))
    {
        let input = NewApiEnvironment {
            service_id: r.service_id,
            name: r.name.clone(),
            kind: r.kind.clone(),
            origin: r.origin.clone(),
            base_path: r.base_path.clone(),
            openapi_url: r.openapi_url.clone(),
            auth: r.auth.clone(),
            fixed_headers: r.fixed_headers.clone(),
        };
        let mut normalized = input.clone();
        normalize_api_environment(&mut normalized)?;
        if normalized != input
            || r.revision == 0
            || api_environment_policy_digest(&input, r.revision)? != r.policy_digest
        {
            return invalid();
        }
    }
    // Dangling navigation/credential references remain unavailable through live
    // core validation; never rewrite them into another credential or target.
    if p.history.iter().any(|r| r.item_id != r.item.id)
        || p.card_history.iter().any(|r| r.item_id != r.item.id)
        || p.identity_history.iter().any(|r| r.item_id != r.item.id)
        || p.ssh_history.iter().any(|r| r.item_id != r.item.id)
        || p.service_history.iter().any(|r| r.service_id != r.item.id)
        || p.api_environment_history
            .iter()
            .any(|r| r.environment_id != r.item.id)
    {
        return invalid();
    }
    Ok(())
}

impl VaultSession {
    /// Must run inside the writer's atomic transaction before serializing.
    pub fn sync_checkpoint(&mut self, now_millis: u64) -> Result<(), VaultError> {
        checkpoint(self.payload_mut()?, now_millis)
    }
    pub fn sync_state(&self) -> Result<&SyncState, VaultError> {
        Ok(&self.payload()?.sync)
    }
    pub fn sync_authorize(
        &mut self,
        peer: &str,
        fingerprint: &str,
        enabled: bool,
    ) -> Result<(), VaultError> {
        if peer.len() > 80
            || !peer.starts_with("lan-peer-")
            || fingerprint.len() != 64
            || !fingerprint.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return invalid();
        }
        let s = &mut self.payload_mut()?.sync;
        if let Some(auth) = s.authorizations.iter_mut().find(|a| a.peer == peer) {
            if auth.fingerprint != fingerprint {
                return invalid();
            }
            if enabled && !auth.enabled {
                auth.remote_vault = None;
                auth.incoming = None;
                auth.outgoing = None;
                auth.confirmed.clear();
                auth.applied_packet = None;
                auth.confirmed_packet = None;
            }
            auth.enabled = enabled;
            if enabled && auth.outgoing.is_none() {
                auth.outgoing = Some(crate::SyncChannel::new());
            }
        } else {
            if s.authorizations.len() >= 32 {
                return invalid();
            }
            s.authorizations.push(SyncAuthorization {
                peer: peer.into(),
                fingerprint: fingerprint.into(),
                remote_vault: None,
                enabled,
                outgoing: enabled.then(crate::SyncChannel::new),
                incoming: None,
                confirmed: BTreeMap::new(),
                applied_packet: None,
                confirmed_packet: None,
            });
        }
        Ok(())
    }
    pub fn sync_bind(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote_vault: Uuid,
    ) -> Result<(), VaultError> {
        if remote_vault.is_nil() {
            return invalid();
        }
        let s = &mut self.payload_mut()?.sync;
        let auth = s
            .authorizations
            .iter_mut()
            .find(|a| a.peer == peer && a.fingerprint == fingerprint && a.enabled)
            .ok_or(VaultError::InvalidPayload)?;
        if auth.remote_vault.is_some_and(|id| id != remote_vault) {
            return invalid();
        }
        auth.remote_vault = Some(remote_vault);
        Ok(())
    }
    pub fn sync_reset_after_restore(&mut self) -> Result<(), VaultError> {
        let s = &mut self.payload_mut()?.sync;
        s.vault_id = Uuid::new_v4();
        s.replica = Uuid::new_v4();
        s.authorizations.clear();
        Ok(())
    }
    pub fn sync_export(&self, remote: &SyncManifest) -> Result<Vec<SyncRecord>, VaultError> {
        if remote.len() > SYNC_MAX_RECORDS {
            return invalid();
        }
        let p = self.payload()?;
        let values = project(p)?;
        let mut records = Vec::new();
        let mut bytes = 0;
        for (key, entry) in &p.sync.entries {
            if let Some(r) = remote.get(key) {
                if r.version == entry.version && r != entry {
                    return invalid();
                }
                if r.version >= entry.version {
                    continue;
                }
            }
            let body = values.get(key).map(|v| v.to_string());
            if digest(body.as_deref()) != entry.digest {
                return invalid();
            }
            bytes += body.as_ref().map_or(0, String::len) + key.len() + 200;
            if bytes > SYNC_MAX_BYTES {
                return invalid();
            }
            records.push(SyncRecord {
                key: key.clone(),
                entry: entry.clone(),
                body,
            });
        }
        Ok(records)
    }
    pub fn sync_merge(&mut self, incoming: &[SyncRecord], now: u64) -> Result<usize, VaultError> {
        if incoming.len() > SYNC_MAX_RECORDS
            || incoming
                .iter()
                .map(|r| r.body.as_ref().map_or(0, String::len) + r.key.len() + 200)
                .sum::<usize>()
                > SYNC_MAX_BYTES
        {
            return invalid();
        }
        let mut candidate = self.payload()?.clone();
        checkpoint(&mut candidate, now)?;
        let mut values = project(&candidate)?;
        let mut seen = BTreeSet::new();
        let mut changed = 0;
        let mut conflicts = Vec::new();
        let mut changed_credentials = Vec::new();
        for r in incoming {
            if r.key.len() > 100
                || !seen.insert(r.key.clone())
                || r.entry.deleted != r.body.is_none()
                || r.entry.digest != digest(r.body.as_deref())
                || r.entry.version.replica.is_nil()
                || r.entry.seen.len() > 1024
                || r.entry
                    .seen
                    .iter()
                    .any(|(id, v)| id.is_nil() || *id != v.replica || v >= &r.entry.version)
            {
                return invalid();
            }
            let (kind, id) = r.key.split_once('/').ok_or(VaultError::InvalidPayload)?;
            if Uuid::parse_str(id).is_err()
                || !matches!(
                    kind,
                    "login"
                        | "card"
                        | "identity"
                        | "service"
                        | "environment"
                        | "ssh"
                        | "secret"
                        | "history"
                        | "card_history"
                        | "identity_history"
                        | "service_history"
                        | "api_environment_history"
                        | "ssh_history"
                        | "conflict"
                        | "clear_history"
                        | "clear_card_history"
                        | "clear_identity_history"
                        | "clear_ssh_history"
                        | "clear_service_history"
                        | "clear_api_environment_history"
                        | "clear_conflicts"
                )
            {
                return invalid();
            }
            // Validate even stale records before accepting the batch.
            if let Some(body) = &r.body {
                let mut validation = VaultPayload::default();
                apply(&mut validation, &r.key, body)?;
                let canonical = project(&validation)?;
                if canonical.get(&r.key).map(|s| s.as_str()) != Some(body.as_str()) {
                    return invalid();
                }
            }
            let old = candidate.sync.entries.get(&r.key).cloned();
            if let Some(old) = &old {
                if old.version == r.entry.version {
                    if old != &r.entry {
                        return invalid();
                    }
                    continue;
                }
                if old.digest != r.entry.digest
                    && !r.key.starts_with("conflict/")
                    && !kind.ends_with("history")
                {
                    let loser = if old.version < r.entry.version {
                        SyncRecord {
                            key: r.key.clone(),
                            entry: old.clone(),
                            body: values.get(&r.key).map(|v| v.to_string()),
                        }
                    } else {
                        r.clone()
                    };
                    let winner = if old.version < r.entry.version {
                        &r.entry
                    } else {
                        old
                    };
                    let observed = winner
                        .seen
                        .get(&loser.entry.version.replica)
                        .is_some_and(|v| v >= &loser.entry.version);
                    if loser.body.is_some() && !observed {
                        conflicts.push(loser);
                    }
                }
                if old.version > r.entry.version {
                    continue;
                }
            }
            if candidate.sync.clock < r.entry.version {
                candidate.sync.clock = r.entry.version.clone();
            }
            if let Some(body) = &r.body {
                values.insert(r.key.clone(), Zeroizing::new(body.clone()));
            } else {
                values.remove(&r.key);
            }
            if old.as_ref().is_none_or(|e| e.digest != r.entry.digest) {
                let kind = match kind {
                    "login" => Some(ApiCredentialItemKind::Login),
                    "secret" => Some(ApiCredentialItemKind::Secret),
                    _ => None,
                };
                if let Some(kind) = kind {
                    changed_credentials.push((
                        kind,
                        Uuid::parse_str(id).map_err(|_| VaultError::InvalidPayload)?,
                    ));
                }
            }
            candidate
                .sync
                .entries
                .insert(r.key.clone(), r.entry.clone());
            changed += 1;
        }
        let bindings: BTreeMap<_, _> = candidate
            .ssh_items
            .iter()
            .map(|s| (s.id, s.clone()))
            .collect();
        let passkey_states: BTreeMap<_, _> = candidate
            .secrets
            .iter()
            .filter(|s| s.scopes.iter().any(|x| x == "vaultmesh:passkey:v1"))
            .map(|s| (s.id, s.clone()))
            .collect();
        clear_portable(&mut candidate);
        for (key, body) in &values {
            apply(&mut candidate, key, body)?;
        }
        // Local OS bindings never travel and cannot be introduced by a peer.
        for ssh in &mut candidate.ssh_items {
            ssh.managed_ssh_host = bindings
                .get(&ssh.id)
                .and_then(|previous| local_ssh_binding(previous, ssh));
        }
        for item in &mut candidate.secrets {
            if item.scopes.iter().any(|x| x == "vaultmesh:passkey:v1") && syncable_secret(item) {
                let mut value = SensitiveValue(
                    serde_json::from_str(&item.secret).map_err(|_| VaultError::InvalidPayload)?,
                );
                let current = encode("secrets", &portable_secret(item)?)?;
                let current_digest = digest(Some(&current));
                let previous = passkey_states.get(&item.id).filter(|s| {
                    portable_secret(s)
                        .and_then(|s| encode("secrets", &s))
                        .is_ok_and(|body| digest(Some(&body)) == current_digest)
                });
                let backed = previous.is_some_and(|s| backed_up(&s.secret))
                    || incoming.iter().any(|r| {
                        r.key == format!("secret/{}", item.id)
                            && r.body.is_some()
                            && r.entry.digest == current_digest
                    });
                if let Some(previous) = previous {
                    let old = SensitiveValue(
                        serde_json::from_str(&previous.secret)
                            .map_err(|_| VaultError::InvalidPayload)?,
                    );
                    value.0["lastUsedAt"] = old.0["lastUsedAt"].clone();
                }
                value.0["backupState"] = serde_json::Value::Bool(backed);
                item.secret.zeroize();
                item.secret =
                    serde_json::to_string(&value.0).map_err(|_| VaultError::Serialization)?;
            }
        }
        for (kind, id) in changed_credentials {
            crate::session::session_api_environment::bump_api_environments_for_credential(
                &mut candidate,
                kind,
                id,
            );
        }
        for r in conflicts {
            let key = conflict_key(&r)?;
            if !candidate.sync.entries.contains_key(&key) {
                candidate.sync.conflicts.insert(key, r);
            }
        }
        checkpoint(&mut candidate, now)?;
        validate_payload(&candidate)?;
        // Complete typed reconstruction precedes publishing the candidate.
        self.restore_payload_snapshot(candidate)?;
        Ok(changed)
    }
    pub fn sync_confirm_manifest(&mut self, manifest: &SyncManifest) -> Result<bool, VaultError> {
        let p = self.payload()?;
        let mut records = Vec::new();
        for item in &p.secrets {
            if !item.scopes.iter().any(|s| s == "vaultmesh:passkey:v1")
                || !syncable_secret(item)
                || backed_up(&item.secret)
            {
                continue;
            }
            let key = format!("secret/{}", item.id);
            if let Some(entry) = p
                .sync
                .entries
                .get(&key)
                .filter(|entry| manifest.get(&key) == Some(entry))
            {
                records.push(SyncRecord {
                    key,
                    entry: entry.clone(),
                    body: Some(encode("secrets", &portable_secret(item)?)?.to_string()),
                });
            }
        }
        self.sync_mark_backed_up(&records)
    }
    pub fn sync_mark_backed_up(&mut self, records: &[SyncRecord]) -> Result<bool, VaultError> {
        let mut changed = false;
        let p = self.payload_mut()?;
        for r in records {
            if !r.key.starts_with("secret/") || r.body.is_none() {
                continue;
            }
            for item in &mut p.secrets {
                if r.key != format!("secret/{}", item.id)
                    || !item.scopes.iter().any(|s| s == "vaultmesh:passkey:v1")
                    || !syncable_secret(item)
                    || backed_up(&item.secret)
                {
                    continue;
                }
                if digest(Some(&encode("secrets", &portable_secret(item)?)?)) != r.entry.digest {
                    continue;
                }
                let mut value = SensitiveValue(
                    serde_json::from_str(&item.secret).map_err(|_| VaultError::InvalidPayload)?,
                );
                value.0["backupState"] = serde_json::Value::Bool(true);
                item.secret.zeroize();
                item.secret =
                    serde_json::to_string(&value.0).map_err(|_| VaultError::Serialization)?;
                changed = true;
            }
        }
        Ok(changed)
    }
    pub fn sync_clear_conflicts(&mut self) -> Result<(), VaultError> {
        record_history_clear(self.payload_mut()?, "conflicts", Uuid::from_u128(1))?;
        self.payload_mut()?.sync.conflicts.clear();
        Ok(())
    }
    pub fn sync_restore_conflict(&mut self, id: &str) -> Result<(), VaultError> {
        let record = self
            .payload()?
            .sync
            .conflicts
            .get(id)
            .cloned()
            .ok_or(VaultError::RevisionNotFound)?;
        let mut p = self.payload()?.clone();
        let mut values = project(&p)?;
        let body = record.body.as_ref().ok_or(VaultError::RevisionNotFound)?;
        if let (Some(current), Some(entry)) =
            (values.get(&record.key), p.sync.entries.get(&record.key))
        {
            if current.as_str() != body {
                let previous = SyncRecord {
                    key: record.key.clone(),
                    entry: entry.clone(),
                    body: Some(current.to_string()),
                };
                let key = conflict_key(&previous)?;
                if !p.sync.entries.contains_key(&key) {
                    values.insert(key, encode("conflicts", &previous)?);
                }
            }
        }
        values.insert(record.key.clone(), Zeroizing::new(body.clone()));
        clear_portable(&mut p);
        for (key, value) in values {
            apply(&mut p, &key, &value)?;
        }
        for ssh in &mut p.ssh_items {
            ssh.managed_ssh_host = self
                .payload()?
                .ssh_items
                .iter()
                .find(|s| s.id == ssh.id)
                .and_then(|s| local_ssh_binding(s, ssh));
        }
        for item in &mut p.secrets {
            if item.scopes.iter().any(|s| s == "vaultmesh:passkey:v1") && syncable_secret(item) {
                if let Some(old) = self.payload()?.secrets.iter().find(|s| s.id == item.id) {
                    if portable_secret(old)? == portable_secret(item)? {
                        item.secret.zeroize();
                        item.secret = old.secret.clone();
                    }
                }
            }
        }
        if let Some((kind, id)) = record.key.split_once('/') {
            let kind = match kind {
                "login" => Some(ApiCredentialItemKind::Login),
                "secret" => Some(ApiCredentialItemKind::Secret),
                _ => None,
            };
            if let Some(kind) = kind {
                crate::session::session_api_environment::bump_api_environments_for_credential(
                    &mut p,
                    kind,
                    Uuid::parse_str(id).map_err(|_| VaultError::InvalidPayload)?,
                );
            }
        }
        validate_payload(&p)?;
        self.restore_payload_snapshot(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn session(item: Option<LoginItem>) -> VaultSession {
        let mut p = VaultPayload::default();
        if let Some(item) = item {
            p.items.push(item);
        }
        let mut s = VaultSession::create_with_payload("test master password", p).unwrap();
        s.sync_checkpoint(0).unwrap();
        s
    }
    fn round(a: &mut VaultSession, b: &mut VaultSession) {
        let am = a.sync_state().unwrap().entries.clone();
        let bm = b.sync_state().unwrap().entries.clone();
        let ar = a.sync_export(&bm).unwrap();
        let br = b.sync_export(&am).unwrap();
        a.sync_merge(&br, 100).unwrap();
        b.sync_merge(&ar, 100).unwrap();
    }
    #[test]
    fn ct_lan_sync_bidirectional_independent_passwords_and_ids() {
        let item = LoginItem::new(
            "same site".into(),
            "same user".into(),
            "test-secret-a".into(),
        );
        let mut a = session(Some(item));
        let mut b = session(Some(LoginItem::new(
            "same site".into(),
            "same user".into(),
            "test-secret-b".into(),
        )));
        b.change_master_password("test master password", "other test password")
            .unwrap();
        round(&mut a, &mut b);
        round(&mut a, &mut b);
        assert_eq!(a.list_items().unwrap().len(), 2);
        assert_eq!(b.list_items().unwrap().len(), 2);
        assert_eq!(
            project(a.payload().unwrap()).unwrap(),
            project(b.payload().unwrap()).unwrap()
        );
        assert!(VaultSession::unlock("other test password", &b.save().unwrap()).is_ok());
        assert!(VaultSession::unlock("test master password", &b.save().unwrap()).is_err());
    }
    #[test]
    fn ct_lan_sync_offline_conflict_converges_and_preserves_loser() {
        let item = LoginItem::new("test".into(), "u".into(), "original".into());
        let id = item.id;
        let mut a = session(Some(item));
        let mut b = session(None);
        round(&mut a, &mut b);
        a.payload_mut().unwrap().items[0].password = "a-version".into();
        a.sync_checkpoint(400).unwrap();
        b.payload_mut().unwrap().items[0].password = "b-version".into();
        b.sync_checkpoint(500).unwrap();
        for _ in 0..4 {
            round(&mut a, &mut b);
        }
        assert_eq!(a.payload().unwrap().items[0].password, "b-version");
        assert_eq!(
            a.sync_state().unwrap().entries,
            b.sync_state().unwrap().entries
        );
        assert_eq!(a.sync_state().unwrap().conflicts.len(), 1);
        let conflict = a
            .sync_state()
            .unwrap()
            .conflicts
            .keys()
            .next()
            .unwrap()
            .clone();
        a.sync_restore_conflict(&conflict).unwrap();
        a.sync_checkpoint(1).unwrap();
        round(&mut a, &mut b);
        assert_eq!(b.payload().unwrap().items[0].password, "a-version");
        assert_eq!(b.payload().unwrap().items[0].id, id);
    }
    #[test]
    fn ct_lan_sync_purge_and_history_clear_do_not_resurrect() {
        let item = LoginItem::new("test".into(), "u".into(), "original".into());
        let id = item.id;
        let mut a = session(Some(item));
        let mut b = session(None);
        round(&mut a, &mut b);
        let stale = b.sync_export(&BTreeMap::new()).unwrap();
        a.delete_item(id).unwrap();
        a.sync_checkpoint(300).unwrap();
        let trash = a.list_trash().unwrap()[0].trash_id;
        a.purge_trash(trash).unwrap();
        a.sync_checkpoint(400).unwrap();
        a.sync_merge(&stale, 1).unwrap();
        round(&mut a, &mut b);
        assert!(a.list_items().unwrap().is_empty());
        assert!(b.list_items().unwrap().is_empty());
        assert!(b.list_trash().unwrap().is_empty());
        assert!(a.sync_state().unwrap().entries[&format!("login/{id}")].deleted);
        assert!(a.sync_state().unwrap().conflicts.is_empty());
    }
    #[test]
    fn ct_lan_sync_malformed_batch_is_atomic_and_local_fields_are_excluded() {
        let mut a = session(Some(LoginItem::new(
            "a".into(),
            "u".into(),
            "synthetic-secret".into(),
        )));
        let mut b = session(None);
        let mut batch = a.sync_export(&BTreeMap::new()).unwrap();
        batch[0].key = "email_accounts/00000000-0000-0000-0000-000000000001".into();
        let before = b.save().unwrap();
        let old = b.payload_snapshot().unwrap();
        assert!(b.sync_merge(&batch, 0).is_err());
        assert_eq!(b.payload_snapshot().unwrap(), old);
        assert!(!format!("{:?}", batch).contains("synthetic-secret"));
        let _ = before;
        a.payload_mut()
            .unwrap()
            .email_accounts
            .push(EmailAccountRecord {
                id: Uuid::new_v4(),
                label: "mail".into(),
                address: "test@example.test".into(),
                provider: "gmail".into(),
                auth_kind: "oauth".into(),
                credential: "mail-only-token".into(),
                imap_host: "example.test".into(),
                imap_port: 993,
                use_tls: true,
                enabled: true,
            });
        a.sync_checkpoint(200).unwrap();
        let wire = Zeroizing::new(
            serde_json::to_string(&a.sync_export(&BTreeMap::new()).unwrap()).unwrap(),
        );
        assert!(!wire.contains("mail-only-token"));
    }
    #[test]
    fn ct_lan_sync_three_replicas_and_idempotence() {
        let mut a = session(Some(LoginItem::new("a".into(), "u".into(), "s".into())));
        let mut b = session(None);
        let mut c = session(None);
        round(&mut a, &mut b);
        round(&mut b, &mut c);
        c.payload_mut().unwrap().items[0].title = "c update".into();
        c.sync_checkpoint(900).unwrap();
        round(&mut c, &mut b);
        round(&mut b, &mut a);
        round(&mut a, &mut c);
        assert_eq!(
            a.sync_state().unwrap().entries,
            c.sync_state().unwrap().entries
        );
        let batch = a.sync_export(&BTreeMap::new()).unwrap();
        let old = c.payload_snapshot().unwrap();
        assert_eq!(c.sync_merge(&batch, 1).unwrap(), 0);
        assert_eq!(c.payload_snapshot().unwrap(), old);
    }
    #[test]
    fn ct_lan_sync_authorization_and_restore_epoch() {
        let mut s = session(None);
        let peer = format!("lan-peer-{}", "a".repeat(32));
        let fp = "b".repeat(64);
        let remote = Uuid::new_v4();
        assert!(s.sync_bind(&peer, &fp, remote).is_err());
        s.sync_authorize(&peer, &fp, true).unwrap();
        s.sync_bind(&peer, &fp, remote).unwrap();
        assert!(s.sync_bind(&peer, &fp, Uuid::new_v4()).is_err());
        let before = s.sync_state().unwrap().replica;
        s.sync_reset_after_restore().unwrap();
        assert_ne!(s.sync_state().unwrap().replica, before);
        assert!(s.sync_state().unwrap().authorizations.is_empty());
        s.lock();
        assert!(s.sync_export(&BTreeMap::new()).is_err());
    }
    #[test]
    fn ct_lan_sync_conflict_clear_is_a_permanent_tombstone() {
        let mut a = session(Some(LoginItem::new(
            "test".into(),
            "u".into(),
            "old".into(),
        )));
        let mut b = session(None);
        round(&mut a, &mut b);
        a.payload_mut().unwrap().items[0].password = "a".into();
        a.sync_checkpoint(200).unwrap();
        b.payload_mut().unwrap().items[0].password = "b".into();
        b.sync_checkpoint(300).unwrap();
        round(&mut a, &mut b);
        round(&mut a, &mut b);
        let stale = b.sync_export(&BTreeMap::new()).unwrap();
        assert!(!a.sync_state().unwrap().conflicts.is_empty());
        a.sync_clear_conflicts().unwrap();
        a.sync_checkpoint(400).unwrap();
        a.sync_merge(&stale, 1).unwrap();
        round(&mut a, &mut b);
        assert!(a.sync_state().unwrap().conflicts.is_empty());
        assert!(b.sync_state().unwrap().conflicts.is_empty());
    }
    #[test]
    fn ct_lan_sync_history_clear_covers_unknown_offline_revisions() {
        let item = LoginItem::new("test".into(), "u".into(), "old".into());
        let id = item.id;
        let mut a = session(Some(item));
        let mut b = session(None);
        round(&mut a, &mut b);
        // A has never seen the revision made by B while offline.
        let item = b.payload().unwrap().items[0].clone();
        let mut value =
            serde_json::json!({"revision_id": Uuid::new_v4(), "item_id": id, "item": item});
        value["saved_at"] = serde_json::json!(100);
        let revision = serde_json::from_value(value).unwrap();
        b.payload_mut().unwrap().history.push(revision);
        b.sync_checkpoint(100).unwrap();
        a.clear_history(id).unwrap();
        a.sync_checkpoint(200).unwrap();
        round(&mut a, &mut b);
        round(&mut a, &mut b);
        assert!(a.payload().unwrap().history.is_empty());
        assert!(b.payload().unwrap().history.is_empty());
        assert_eq!(
            a.sync_state().unwrap().entries,
            b.sync_state().unwrap().entries
        );
    }
    #[test]
    fn ct_lan_sync_legacy_passkey_is_never_exported_and_new_backup_state_is_local() {
        let mut a = session(None);
        let mut secret:SecretItem=serde_json::from_value(serde_json::json!({"id":Uuid::new_v4(),"title":"legacy test key","kind":"authenticator-key","provider":null,"account":null,"secret":"{\"signCount\":4}","environment":null,"scopes":["vaultmesh:passkey:v1"],"expires_at":null,"website":null,"notes":null,"folder":null,"favorite":false,"master_password_reprompt":false})).unwrap();
        a.payload_mut().unwrap().secrets.push(secret.clone());
        a.sync_checkpoint(100).unwrap();
        assert!(a.sync_export(&BTreeMap::new()).unwrap().is_empty());
        secret.id = Uuid::new_v4();
        secret.secret =
            "{\"backupEligible\":true,\"backupState\":false,\"lastUsedAt\":null,\"signCount\":0}"
                .into();
        a.payload_mut().unwrap().secrets.push(secret);
        a.sync_checkpoint(200).unwrap();
        let records = a.sync_export(&BTreeMap::new()).unwrap();
        assert_eq!(records.len(), 1);
        let mut b = session(None);
        b.sync_merge(&records, 300).unwrap();
        assert!(backed_up(&b.payload().unwrap().secrets[0].secret));
        let before = a.sync_state().unwrap().entries.clone();
        a.sync_mark_backed_up(&records).unwrap();
        a.sync_checkpoint(400).unwrap();
        assert_eq!(a.sync_state().unwrap().entries, before);
        // A lost receipt is repaired by the next durable remote manifest.
        let mut c = session(None);
        c.sync_merge(&records, 300).unwrap();
        c.payload_mut().unwrap().secrets[0].secret =
            "{\"backupEligible\":true,\"backupState\":false,\"lastUsedAt\":null,\"signCount\":0}"
                .into();
        assert!(
            c.sync_confirm_manifest(&b.sync_state().unwrap().entries)
                .unwrap()
        );
        assert!(backed_up(&c.payload().unwrap().secrets[0].secret));
        // A stale copy cannot confirm replacement key material as backed up.
        c.payload_mut().unwrap().secrets[0].secret = "{\"backupEligible\":true,\"backupState\":false,\"lastUsedAt\":null,\"signCount\":0,\"privateKey\":\"synthetic replacement\"}".into();
        c.sync_checkpoint(500).unwrap();
        c.sync_merge(&records, 600).unwrap();
        assert!(!backed_up(&c.payload().unwrap().secrets[0].secret));
        assert!(
            !c.sync_confirm_manifest(&b.sync_state().unwrap().entries)
                .unwrap()
        );
    }
}
