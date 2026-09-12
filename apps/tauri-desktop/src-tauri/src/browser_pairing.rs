use std::{io::Write, path::PathBuf, sync::Arc};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const TAURI_PAIRING_SERVICE: &str = "com.vaultmesh.desktop.browser-pairing";
pub const TAURI_PAIRING_ACCOUNT: &str = "native-host-hmac-v1";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingRecord {
    version: u8,
    enabled: bool,
}

trait PairingSecretStore: Send + Sync {
    fn set(&self, encoded: &str) -> Result<(), String>;
    fn get(&self) -> Result<Zeroizing<String>, String>;
    fn delete(&self) -> Result<(), String>;
}

struct PlatformPairingSecretStore {
    service: &'static str,
    account: &'static str,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PairingSecretStore for PlatformPairingSecretStore {
    fn set(&self, encoded: &str) -> Result<(), String> {
        keyring::Entry::new(self.service, self.account)
            .and_then(|entry| entry.set_password(encoded))
            .map_err(|_| "无法保存浏览器配对凭据。".to_owned())
    }

    fn get(&self) -> Result<Zeroizing<String>, String> {
        keyring::Entry::new(self.service, self.account)
            .and_then(|entry| entry.get_password())
            .map(Zeroizing::new)
            .map_err(|_| "无法读取浏览器配对凭据，请重新配对。".to_owned())
    }

    fn delete(&self) -> Result<(), String> {
        keyring::Entry::new(self.service, self.account)
            .and_then(|entry| entry.delete_credential())
            .map_err(|_| "无法删除浏览器配对凭据。".to_owned())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl PairingSecretStore for PlatformPairingSecretStore {
    fn set(&self, _encoded: &str) -> Result<(), String> {
        Err("当前平台不支持浏览器安全配对。".to_owned())
    }
    fn get(&self) -> Result<Zeroizing<String>, String> {
        Err("当前平台不支持浏览器安全配对。".to_owned())
    }
    fn delete(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct BrowserPairingService {
    record_path: PathBuf,
    store: Arc<dyn PairingSecretStore>,
}

impl BrowserPairingService {
    pub fn new(record_path: PathBuf) -> Self {
        Self {
            record_path,
            store: Arc::new(PlatformPairingSecretStore {
                service: TAURI_PAIRING_SERVICE,
                account: TAURI_PAIRING_ACCOUNT,
            }),
        }
    }

    pub fn new_bitwarden_development(record_path: PathBuf) -> Self {
        Self {
            record_path,
            store: Arc::new(PlatformPairingSecretStore {
                service: crate::browser_development_identity::PAIRING_SERVICE,
                account: crate::browser_development_identity::PAIRING_ACCOUNT,
            }),
        }
    }

    #[cfg(test)]
    fn with_store(record_path: PathBuf, store: Arc<dyn PairingSecretStore>) -> Self {
        Self { record_path, store }
    }

    /// Loads the existing credential or provisions the first Tauri pairing.
    /// A present-but-invalid record fails closed and is never silently replaced.
    pub fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        match std::fs::read(&self.record_path) {
            Ok(bytes) => {
                let record: PairingRecord = serde_json::from_slice(&bytes)
                    .map_err(|_| "浏览器配对状态已损坏，请重新配对。".to_owned())?;
                if record.version != 1 || !record.enabled {
                    return Err("浏览器配对已关闭。".to_owned());
                }
                let encoded = self.store.get()?;
                decode_secret(encoded.as_str())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.create(),
            Err(_) => Err("无法读取浏览器配对状态。".to_owned()),
        }
    }

    fn create(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_ref()));
        self.store.set(encoded.as_str())?;
        let record = serde_json::to_vec(&PairingRecord {
            version: 1,
            enabled: true,
        })
        .map_err(|_| "无法保存浏览器配对状态。".to_owned())?;
        write_private_record(&self.record_path, &record)?;
        Ok(secret)
    }

    pub fn revoke(&self) -> Result<(), String> {
        self.store.delete()?;
        let record = serde_json::to_vec(&PairingRecord {
            version: 1,
            enabled: false,
        })
        .map_err(|_| "无法保存浏览器配对状态。".to_owned())?;
        write_private_record(&self.record_path, &record)
    }
}

fn decode_secret(encoded: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "浏览器配对凭据无效。".to_owned())?,
    );
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded {
        return Err("浏览器配对凭据无效。".to_owned());
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(decoded.as_slice());
    Ok(secret)
}

fn write_private_record(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "无法保存浏览器配对状态。".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "无法保存浏览器配对状态。".to_owned())?;
    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "无法保存浏览器配对状态。".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.commit())
        .map_err(|_| "无法保存浏览器配对状态。".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<String>>);
    impl PairingSecretStore for MemoryStore {
        fn set(&self, encoded: &str) -> Result<(), String> {
            *self.0.lock().map_err(|_| "lock".to_owned())? = Some(encoded.to_owned());
            Ok(())
        }
        fn get(&self) -> Result<Zeroizing<String>, String> {
            self.0
                .lock()
                .map_err(|_| "lock".to_owned())?
                .clone()
                .map(Zeroizing::new)
                .ok_or_else(|| "missing".to_owned())
        }
        fn delete(&self) -> Result<(), String> {
            self.0.lock().map_err(|_| "lock".to_owned())?.take();
            Ok(())
        }
    }

    #[test]
    fn provisions_once_and_reloads_the_same_canonical_secret() {
        let root = std::env::temp_dir().join(format!("vaultmesh-pairing-{}", Uuid::new_v4()));
        let record = root.join("browser-pairing.json");
        let store = Arc::new(MemoryStore::default());
        let service = BrowserPairingService::with_store(record.clone(), store.clone());
        let first = service.load_or_create().expect("create");
        let second = service.load_or_create().expect("reload");
        assert_eq!(first.as_ref(), second.as_ref());
        assert!(std::fs::metadata(record).expect("record").len() > 0);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn missing_keychain_secret_and_corrupt_record_fail_without_rotation() {
        let root = std::env::temp_dir().join(format!("vaultmesh-pairing-{}", Uuid::new_v4()));
        let record = root.join("browser-pairing.json");
        let store = Arc::new(MemoryStore::default());
        let service = BrowserPairingService::with_store(record.clone(), store.clone());
        service.load_or_create().expect("create");
        *store.0.lock().expect("store") = None;
        assert!(service.load_or_create().is_err());
        std::fs::write(&record, b"{}").expect("corrupt");
        assert!(service.load_or_create().is_err());
        assert!(store.0.lock().expect("store").is_none());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn revoke_deletes_the_credential_and_persists_a_disabled_tombstone() {
        let root = std::env::temp_dir().join(format!("vaultmesh-pairing-{}", Uuid::new_v4()));
        let record = root.join("browser-pairing.json");
        let store = Arc::new(MemoryStore::default());
        let service = BrowserPairingService::with_store(record.clone(), store.clone());
        service.load_or_create().expect("create");

        service.revoke().expect("revoke");

        assert!(store.0.lock().expect("store").is_none());
        assert!(
            !serde_json::from_slice::<PairingRecord>(&std::fs::read(record).expect("record"))
                .expect("tombstone")
                .enabled
        );
        assert!(service.load_or_create().is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
