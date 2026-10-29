use std::{io::Write, path::PathBuf, sync::Arc};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const AGENT_PAIRING_SERVICE: &str = "com.vaultmesh.desktop.agent-pairing";
const PAIRING_PROOF_BYTES: usize = 32;
const PAIRING_INDEX_VERSION: u8 = 2;
const MAX_PAIRING_INDEX_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug)]
pub struct AgentPairingIdentity<'a> {
    pub client_key: &'a str,
    pub user_id: &'a str,
}

impl AgentPairingIdentity<'_> {
    pub fn pairing_ref(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"vaultmesh-agent-pairing-v2");
        for field in [self.client_key, self.user_id] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        format!("agent-pairing-v2-{:x}", digest.finalize())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPairingRecord {
    pub pairing_ref: String,
    pub client_key: String,
    pub user_id: String,
    #[serde(default, rename = "executable", skip_serializing)]
    legacy_executable: Option<String>,
    #[serde(default, rename = "binaryIdentity", skip_serializing)]
    legacy_binary_identity: Option<String>,
}

impl AgentPairingRecord {
    pub fn identity(&self) -> AgentPairingIdentity<'_> {
        AgentPairingIdentity {
            client_key: &self.client_key,
            user_id: &self.user_id,
        }
    }

    fn valid(&self) -> bool {
        self.pairing_ref == self.identity().pairing_ref()
            && valid_client_key(&self.client_key)
            && !self.user_id.is_empty()
            && self.user_id.len() <= 512
    }
}

pub fn valid_client_key(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentPairingIndex {
    version: u8,
    records: Vec<AgentPairingRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyAgentPairingIndex {
    version: u8,
    records: Vec<LegacyAgentPairingRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyAgentPairingRecord {
    pairing_ref: String,
    client_kind: String,
    user_id: String,
    executable: String,
    binary_identity: String,
}

trait AgentPairingProofStore: Send + Sync {
    fn set(&self, account: &str, proof: &[u8]) -> Result<(), ()>;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()>;
    fn delete(&self, account: &str) -> Result<(), ()>;
}

trait AgentPairingIndexStore: Send + Sync {
    fn load(&self) -> Result<Vec<AgentPairingRecord>, ()>;
    fn save(&self, records: &[AgentPairingRecord]) -> Result<(), ()>;
}

struct PlatformAgentPairingProofStore(crate::device_credentials::ScopedCredentialStore);

impl AgentPairingProofStore for PlatformAgentPairingProofStore {
    fn set(&self, account: &str, proof: &[u8]) -> Result<(), ()> {
        self.0.set(account, proof).map_err(|_| ())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        self.0.get(account).map_err(|_| ())
    }

    fn delete(&self, account: &str) -> Result<(), ()> {
        self.0.delete(account).map_err(|_| ())
    }
}

struct FileAgentPairingIndexStore(PathBuf);

impl AgentPairingIndexStore for FileAgentPairingIndexStore {
    fn load(&self) -> Result<Vec<AgentPairingRecord>, ()> {
        match std::fs::metadata(&self.0) {
            Ok(metadata) if metadata.len() <= MAX_PAIRING_INDEX_BYTES => {}
            Ok(_) => return Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
        }
        let bytes = std::fs::read(&self.0).map_err(|_| ())?;
        let index: AgentPairingIndex = match serde_json::from_slice(&bytes) {
            Ok(index) => index,
            Err(_) => {
                let legacy: LegacyAgentPairingIndex =
                    serde_json::from_slice(&bytes).map_err(|_| ())?;
                if legacy.version != 1
                    || legacy.records.len() > 32
                    || legacy.records.iter().any(|record| {
                        !record.pairing_ref.starts_with("agent-pairing-v1-")
                            || !valid_client_key(&record.client_kind)
                            || record.user_id.is_empty()
                            || record.executable.is_empty()
                            || !record.binary_identity.starts_with("sha256:")
                    })
                {
                    return Err(());
                }
                // v1 bound pairing to the shim path/hash and cannot safely be
                // promoted to the new client-key identity. Treat it as unpaired.
                return Ok(Vec::new());
            }
        };
        if index.version != PAIRING_INDEX_VERSION
            || index.records.len() > 32
            || index.records.iter().any(|record| !record.valid())
        {
            return Err(());
        }
        Ok(index.records)
    }

    fn save(&self, records: &[AgentPairingRecord]) -> Result<(), ()> {
        let bytes = serde_json::to_vec(&AgentPairingIndex {
            version: PAIRING_INDEX_VERSION,
            records: records.to_vec(),
        })
        .map_err(|_| ())?;
        write_private_index(&self.0, &bytes)
    }
}

#[derive(Clone)]
pub struct AgentPairingProofs {
    store: Arc<dyn AgentPairingProofStore>,
    index: Arc<dyn AgentPairingIndexStore>,
}

impl AgentPairingProofs {
    pub fn platform(
        record_path: PathBuf,
        credentials: &crate::device_credentials::DeviceCredentialStore,
    ) -> Self {
        Self {
            store: Arc::new(PlatformAgentPairingProofStore(
                credentials.scoped(AGENT_PAIRING_SERVICE),
            )),
            index: Arc::new(FileAgentPairingIndexStore(record_path)),
        }
    }

    pub fn find(&self, identity: &AgentPairingIdentity<'_>) -> Option<AgentPairingRecord> {
        let pairing_ref = identity.pairing_ref();
        let records = self.index.load().ok()?;
        if let Some(record) = records
            .iter()
            .find(|record| record.pairing_ref == pairing_ref)
            .cloned()
        {
            return self.has_valid_proof(&pairing_ref).then_some(record);
        }
        None
    }

    pub fn record(&self, pairing_ref: &str) -> Option<AgentPairingRecord> {
        self.records()
            .into_iter()
            .find(|record| record.pairing_ref == pairing_ref)
    }

    pub fn records(&self) -> Vec<AgentPairingRecord> {
        self.index
            .load()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| self.has_valid_proof(&record.pairing_ref))
            .collect()
    }

    pub fn approve(&self, identity: &AgentPairingIdentity<'_>) -> Result<AgentPairingRecord, ()> {
        let record = AgentPairingRecord {
            pairing_ref: identity.pairing_ref(),
            client_key: identity.client_key.to_owned(),
            user_id: identity.user_id.to_owned(),
            legacy_executable: None,
            legacy_binary_identity: None,
        };
        if !record.valid() {
            return Err(());
        }
        let mut proof = Zeroizing::new([0_u8; PAIRING_PROOF_BYTES]);
        OsRng.fill_bytes(proof.as_mut());
        self.store.set(&record.pairing_ref, proof.as_ref())?;
        let mut records = self.index.load()?;
        records.retain(|candidate| candidate.pairing_ref != record.pairing_ref);
        records.push(record.clone());
        records.sort_by(|left, right| left.pairing_ref.cmp(&right.pairing_ref));
        if self.index.save(&records).is_err() {
            let _ = self.store.delete(&record.pairing_ref);
            return Err(());
        }
        Ok(record)
    }

    pub fn revoke(&self, identity: &AgentPairingIdentity<'_>) -> Result<(), ()> {
        self.revoke_record(&identity.pairing_ref())
    }

    pub fn revoke_record(&self, pairing_ref: &str) -> Result<(), ()> {
        self.store.delete(pairing_ref)?;
        let mut records = self.index.load().unwrap_or_default();
        records.retain(|record| record.pairing_ref != pairing_ref);
        self.index.save(&records)
    }

    fn has_valid_proof(&self, pairing_ref: &str) -> bool {
        self.store
            .get(pairing_ref)
            .ok()
            .flatten()
            .is_some_and(|proof| proof.len() == PAIRING_PROOF_BYTES)
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self {
            store: Arc::new(MemoryAgentPairingProofStore::default()),
            index: Arc::new(MemoryAgentPairingIndexStore::default()),
        }
    }
}

fn write_private_index(path: &std::path::Path, bytes: &[u8]) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    std::fs::create_dir_all(parent).map_err(|_| ())?;
    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    file.write_all(bytes)
        .and_then(|()| file.commit())
        .map_err(|_| ())
}

#[cfg(test)]
#[derive(Default)]
struct MemoryAgentPairingProofStore(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

#[cfg(test)]
impl AgentPairingProofStore for MemoryAgentPairingProofStore {
    fn set(&self, account: &str, proof: &[u8]) -> Result<(), ()> {
        self.0
            .lock()
            .map_err(|_| ())?
            .insert(account.to_owned(), proof.to_vec());
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

#[cfg(test)]
#[derive(Default)]
struct MemoryAgentPairingIndexStore(
    std::sync::Mutex<std::collections::HashMap<String, AgentPairingRecord>>,
);

#[cfg(test)]
impl AgentPairingIndexStore for MemoryAgentPairingIndexStore {
    fn load(&self) -> Result<Vec<AgentPairingRecord>, ()> {
        Ok(self.0.lock().map_err(|_| ())?.values().cloned().collect())
    }

    fn save(&self, records: &[AgentPairingRecord]) -> Result<(), ()> {
        *self.0.lock().map_err(|_| ())? = records
            .iter()
            .cloned()
            .map(|record| (record.pairing_ref.clone(), record))
            .collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn identity<'a>() -> AgentPairingIdentity<'a> {
        AgentPairingIdentity {
            client_key: "codex",
            user_id: "501",
        }
    }

    #[test]
    fn pairing_record_survives_connection_lifetime_and_clone() {
        let proofs = AgentPairingProofs::memory();
        let approved = proofs.approve(&identity()).expect("approve");
        assert_eq!(proofs.find(&identity()), Some(approved.clone()));
        assert_eq!(proofs.clone().records(), vec![approved.clone()]);

        proofs.revoke_record(&approved.pairing_ref).expect("revoke");
        assert!(proofs.records().is_empty());
        assert!(proofs.find(&identity()).is_none());
    }

    #[test]
    fn pairing_identity_uses_client_key_and_user_not_process_metadata() {
        let original = identity();
        let same_integration = AgentPairingIdentity {
            client_key: "codex",
            user_id: "501",
        };
        let other_integration = AgentPairingIdentity {
            client_key: "cursor.team-a",
            user_id: "501",
        };
        let other_user = AgentPairingIdentity {
            client_key: "codex",
            user_id: "502",
        };

        assert_eq!(original.pairing_ref(), same_integration.pairing_ref());
        assert_ne!(original.pairing_ref(), other_integration.pairing_ref());
        assert_ne!(original.pairing_ref(), other_user.pairing_ref());
        assert!(valid_client_key("custom-client:team@desktop"));
        assert!(!valid_client_key("client key with spaces"));
    }

    #[test]
    fn unindexed_os_proof_does_not_restore_pairing() {
        let proofs = AgentPairingProofs::memory();
        let pairing_ref = identity().pairing_ref();
        proofs
            .store
            .set(&pairing_ref, &[7_u8; PAIRING_PROOF_BYTES])
            .expect("legacy proof");

        assert!(proofs.find(&identity()).is_none());
        assert!(proofs.records().is_empty());
    }

    #[test]
    fn file_index_requires_matching_os_proof_and_corruption_fails_closed() {
        let root = std::env::temp_dir().join(format!("vaultmesh-agent-pairing-{}", Uuid::new_v4()));
        let path = root.join("agent-pairings.json");
        let store = Arc::new(MemoryAgentPairingProofStore::default());
        let proofs = AgentPairingProofs {
            store: store.clone(),
            index: Arc::new(FileAgentPairingIndexStore(path.clone())),
        };
        let approved = proofs.approve(&identity()).expect("approve");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("index metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let reloaded = AgentPairingProofs {
            store: store.clone(),
            index: Arc::new(FileAgentPairingIndexStore(path.clone())),
        };
        assert_eq!(reloaded.records(), vec![approved.clone()]);

        store.delete(&approved.pairing_ref).expect("delete proof");
        assert!(reloaded.records().is_empty());
        assert!(reloaded.find(&identity()).is_none());

        std::fs::write(&path, b"{}").expect("corrupt index");
        assert!(reloaded.records().is_empty());
        assert!(reloaded.approve(&identity()).is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
