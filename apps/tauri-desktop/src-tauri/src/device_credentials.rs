use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ROOT_KEYRING_SERVICE: &str = "com.vaultmesh.desktop";
pub const ROOT_KEYRING_ACCOUNT: &str = "root-secret-v1";
pub const CREDENTIALS_FILE_NAME: &str = "device-credentials.enc";

const MAGIC: &[u8; 4] = b"VMDC";
const VERSION: u8 = 1;
const KDF_INFO: &[u8] = b"vaultmesh:device-credentials:v1";

pub trait RootSecretStore: Send + Sync {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String>;
}

pub trait LegacyKeyringProvider: Send + Sync {
    fn get_legacy_secret(&self, service: &str, account: &str) -> Option<Vec<u8>>;
    fn delete_legacy_secret(&self, service: &str, account: &str);
}

pub struct PlatformRootSecretStore;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl RootSecretStore for PlatformRootSecretStore {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
            .map_err(|e| format!("无法创建钥匙串入口: {e}"))?;
        match entry.get_secret() {
            Ok(bytes) => {
                if bytes.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);
                    Ok(Zeroizing::new(secret))
                } else {
                    let hash = Sha256::digest(&bytes);
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&hash);
                    Ok(Zeroizing::new(secret))
                }
            }
            Err(keyring::Error::NoEntry) => {
                let mut secret = [0u8; 32];
                OsRng.fill_bytes(&mut secret);
                entry
                    .set_secret(&secret)
                    .map_err(|e| format!("无法在钥匙串中保存根密钥: {e}"))?;
                Ok(Zeroizing::new(secret))
            }
            Err(e) => Err(format!("钥匙串错误: {e}")),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl RootSecretStore for PlatformRootSecretStore {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        // Fallback for non-keychain platforms (e.g. headless tests)
        let mut secret = [0u8; 32];
        let hash = Sha256::digest(b"vaultmesh-headless-dev-root-secret");
        secret.copy_from_slice(&hash);
        Ok(Zeroizing::new(secret))
    }
}

pub struct PlatformLegacyKeyring;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl LegacyKeyringProvider for PlatformLegacyKeyring {
    fn get_legacy_secret(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        let entry = keyring::Entry::new(service, account).ok()?;
        if let Ok(secret) = entry.get_secret() {
            return Some(secret);
        }
        if let Ok(password) = entry.get_password() {
            return Some(password.into_bytes());
        }
        None
    }

    fn delete_legacy_secret(&self, service: &str, account: &str) {
        if let Ok(entry) = keyring::Entry::new(service, account) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl LegacyKeyringProvider for PlatformLegacyKeyring {
    fn get_legacy_secret(&self, _service: &str, _account: &str) -> Option<Vec<u8>> {
        None
    }

    fn delete_legacy_secret(&self, _service: &str, _account: &str) {}
}

#[derive(Default, Serialize, Deserialize)]
struct StoredPayload {
    version: u32,
    entries: HashMap<String, String>,
}

struct DeviceCredentialStoreInner {
    file_path: PathBuf,
    root_secret: Zeroizing<[u8; 32]>,
    legacy_provider: Arc<dyn LegacyKeyringProvider>,
    entries: HashMap<String, String>,
}

#[derive(Clone)]
pub struct DeviceCredentialStore {
    inner: Arc<Mutex<DeviceCredentialStoreInner>>,
}

fn derive_encryption_key(root_secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root_secret).expect("HMAC init");
    mac.update(KDF_INFO);
    mac.finalize().into_bytes().into()
}

fn entry_key(service: &str, account: &str) -> String {
    format!("{service}::{account}")
}

impl DeviceCredentialStoreInner {
    fn save(&self) -> Result<(), String> {
        let payload = StoredPayload {
            version: 1,
            entries: self.entries.clone(),
        };
        let plaintext =
            serde_json::to_vec(&payload).map_err(|e| format!("序列化凭据存储失败: {e}"))?;

        let key = derive_encryption_key(&self.root_secret);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES 密码初始化失败: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| format!("凭据加密失败: {e}"))?;

        let mut file_bytes =
            Vec::with_capacity(MAGIC.len() + 1 + nonce_bytes.len() + ciphertext.len());
        file_bytes.extend_from_slice(MAGIC);
        file_bytes.push(VERSION);
        file_bytes.extend_from_slice(&nonce_bytes);
        file_bytes.extend_from_slice(&ciphertext);

        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建凭据目录失败: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        let tmp_path = self.file_path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("创建临时凭据文件失败: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
            file.write_all(&file_bytes)
                .map_err(|e| format!("写入临时凭据文件失败: {e}"))?;
            file.flush().map_err(|e| format!("刷新凭据文件失败: {e}"))?;
        }

        fs::rename(&tmp_path, &self.file_path).map_err(|e| format!("原子更新凭据文件失败: {e}"))?;
        Ok(())
    }

    fn load(file_path: &Path, root_secret: &[u8; 32]) -> Result<HashMap<String, String>, String> {
        if !file_path.is_file() {
            return Ok(HashMap::new());
        }

        let file_bytes = fs::read(file_path).map_err(|e| format!("读取凭据文件失败: {e}"))?;
        if file_bytes.len() < MAGIC.len() + 1 + 12 {
            return Err("凭据文件损坏: 长度过短".to_string());
        }

        if &file_bytes[..MAGIC.len()] != MAGIC {
            return Err("凭据文件标识错误".to_string());
        }

        let version = file_bytes[MAGIC.len()];
        if version != VERSION {
            return Err(format!("不支持的凭据版本: {version}"));
        }

        let nonce_start = MAGIC.len() + 1;
        let nonce_end = nonce_start + 12;
        let nonce = Nonce::from_slice(&file_bytes[nonce_start..nonce_end]);
        let ciphertext = &file_bytes[nonce_end..];

        let key = derive_encryption_key(root_secret);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES 密码初始化失败: {e}"))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("凭据解密失败: {e}"))?;

        let payload: StoredPayload =
            serde_json::from_slice(&plaintext).map_err(|e| format!("反序列化凭据内容失败: {e}"))?;

        Ok(payload.entries)
    }
}

impl DeviceCredentialStore {
    pub fn platform(app_data_dir: &Path) -> Result<Self, String> {
        let file_path = app_data_dir.join(CREDENTIALS_FILE_NAME);
        let root_store = Arc::new(PlatformRootSecretStore);
        let legacy_provider = Arc::new(PlatformLegacyKeyring);
        Self::with_stores(file_path, root_store, legacy_provider)
    }

    pub fn with_stores(
        file_path: PathBuf,
        root_store: Arc<dyn RootSecretStore>,
        legacy_provider: Arc<dyn LegacyKeyringProvider>,
    ) -> Result<Self, String> {
        let root_secret = root_store.get_or_create_root_secret()?;
        let entries = DeviceCredentialStoreInner::load(&file_path, &root_secret)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(DeviceCredentialStoreInner {
                file_path,
                root_secret,
                legacy_provider,
                entries,
            })),
        })
    }

    pub fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        let key = entry_key(service, account);

        if let Some(encoded) = inner.entries.get(&key) {
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|e| format!("Base64 解码凭据失败: {e}"))?;
            return Ok(Some(Zeroizing::new(bytes)));
        }

        // Lazy fallback migration from legacy keyring
        let legacy_provider = inner.legacy_provider.clone();
        drop(inner); // Drop lock while talking to legacy provider to minimize contention

        if let Some(secret) = legacy_provider.get_legacy_secret(service, account) {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "凭据互斥锁中毒".to_string())?;
            inner.entries.insert(key, STANDARD.encode(&secret));
            let _ = inner.save();
            legacy_provider.delete_legacy_secret(service, account);
            return Ok(Some(Zeroizing::new(secret)));
        }

        Ok(None)
    }

    pub fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        let key = entry_key(service, account);
        inner.entries.insert(key, STANDARD.encode(secret));
        inner.save()?;

        let legacy_provider = inner.legacy_provider.clone();
        drop(inner);
        legacy_provider.delete_legacy_secret(service, account);
        Ok(())
    }

    pub fn delete(&self, service: &str, account: &str) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        let key = entry_key(service, account);
        let removed = inner.entries.remove(&key).is_some();
        if removed {
            inner.save()?;
        }

        let legacy_provider = inner.legacy_provider.clone();
        drop(inner);
        legacy_provider.delete_legacy_secret(service, account);
        Ok(())
    }

    pub fn scoped(&self, service: &'static str) -> ScopedCredentialStore {
        ScopedCredentialStore {
            store: self.clone(),
            service,
        }
    }
}

#[derive(Clone)]
pub struct ScopedCredentialStore {
    store: DeviceCredentialStore,
    service: &'static str,
}

impl ScopedCredentialStore {
    pub fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        self.store.get(self.service, account)
    }

    pub fn set(&self, account: &str, secret: &[u8]) -> Result<(), String> {
        self.store.set(self.service, account, secret)
    }

    pub fn delete(&self, account: &str) -> Result<(), String> {
        self.store.delete(self.service, account)
    }
}

impl vaultmesh_lan_pairing::CredentialStore for ScopedCredentialStore {
    fn set(&self, account: &str, value: &[u8]) -> Result<(), ()> {
        self.set(account, value).map_err(|_| ())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        self.get(account).map_err(|_| ())
    }

    fn delete(&self, account: &str) -> Result<(), ()> {
        self.delete(account).map_err(|_| ())
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;

    pub struct MemoryRootSecretStore(pub [u8; 32]);

    impl RootSecretStore for MemoryRootSecretStore {
        fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
            Ok(Zeroizing::new(self.0))
        }
    }

    #[derive(Default)]
    pub struct MemoryLegacyKeyring {
        pub items: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl LegacyKeyringProvider for MemoryLegacyKeyring {
        fn get_legacy_secret(&self, service: &str, account: &str) -> Option<Vec<u8>> {
            let key = entry_key(service, account);
            self.items.lock().unwrap().get(&key).cloned()
        }

        fn delete_legacy_secret(&self, service: &str, account: &str) {
            let key = entry_key(service, account);
            self.items.lock().unwrap().remove(&key);
        }
    }

    pub struct TestDir(pub PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn temp_store() -> (DeviceCredentialStore, TestDir, Arc<MemoryLegacyKeyring>) {
        let temp_dir = std::env::temp_dir().join(format!("vaultmesh-cred-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).expect("create test dir");
        let file_path = temp_dir.join("device-credentials.enc");
        let root_store = Arc::new(MemoryRootSecretStore([42u8; 32]));
        let legacy_provider = Arc::new(MemoryLegacyKeyring::default());
        let store =
            DeviceCredentialStore::with_stores(file_path, root_store, legacy_provider.clone())
                .expect("create store");
        (store, TestDir(temp_dir), legacy_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_device_credential_store_crud_and_persistence() {
        let (store, temp_dir, _) = temp_store();
        let file_path = temp_dir.0.join("device-credentials.enc");

        assert_eq!(store.get("svc1", "acc1").unwrap(), None);

        store.set("svc1", "acc1", b"secret_value_1").unwrap();
        assert_eq!(
            store.get("svc1", "acc1").unwrap().unwrap().as_slice(),
            b"secret_value_1"
        );
        assert!(file_path.is_file());

        // Reload store from disk
        let root_store = Arc::new(MemoryRootSecretStore([42u8; 32]));
        let legacy_provider = Arc::new(MemoryLegacyKeyring::default());
        let reloaded =
            DeviceCredentialStore::with_stores(file_path.clone(), root_store, legacy_provider)
                .unwrap();
        assert_eq!(
            reloaded.get("svc1", "acc1").unwrap().unwrap().as_slice(),
            b"secret_value_1"
        );

        // Delete
        reloaded.delete("svc1", "acc1").unwrap();
        assert_eq!(reloaded.get("svc1", "acc1").unwrap(), None);

        // Reload again, should be gone
        let root_store2 = Arc::new(MemoryRootSecretStore([42u8; 32]));
        let legacy_provider2 = Arc::new(MemoryLegacyKeyring::default());
        let reloaded2 =
            DeviceCredentialStore::with_stores(file_path, root_store2, legacy_provider2).unwrap();
        assert_eq!(reloaded2.get("svc1", "acc1").unwrap(), None);
    }

    #[test]
    fn test_lazy_migration_migrates_and_cleans_up_legacy_entry() {
        let (store, _, legacy_provider) = temp_store();

        // Seed legacy provider with an item
        legacy_provider.items.lock().unwrap().insert(
            entry_key("com.vaultmesh.desktop.agent-pairing", "cursor"),
            b"cursor_proof".to_vec(),
        );

        // Querying store should trigger migration
        let retrieved = store
            .get("com.vaultmesh.desktop.agent-pairing", "cursor")
            .unwrap()
            .expect("should find legacy item");
        assert_eq!(retrieved.as_slice(), b"cursor_proof");

        // Legacy provider must have been cleared!
        assert!(
            legacy_provider
                .items
                .lock()
                .unwrap()
                .get(&entry_key("com.vaultmesh.desktop.agent-pairing", "cursor"))
                .is_none(),
            "Legacy entry must be cleaned up after migration"
        );

        // Subsequent query should read from encrypted file without touching legacy provider
        let retrieved_again = store
            .get("com.vaultmesh.desktop.agent-pairing", "cursor")
            .unwrap()
            .expect("should find migrated item in new store");
        assert_eq!(retrieved_again.as_slice(), b"cursor_proof");
    }

    #[test]
    fn test_scoped_credential_store() {
        let (store, _, _) = temp_store();
        let scoped = store.scoped("com.vaultmesh.desktop.biometric");

        scoped
            .set("user_credential", b"biometric_key_data")
            .unwrap();
        assert_eq!(
            scoped.get("user_credential").unwrap().unwrap().as_slice(),
            b"biometric_key_data"
        );
        assert_eq!(
            store
                .get("com.vaultmesh.desktop.biometric", "user_credential")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"biometric_key_data"
        );

        scoped.delete("user_credential").unwrap();
        assert_eq!(scoped.get("user_credential").unwrap(), None);
    }

    #[test]
    fn test_scoped_credential_store_migrates_legacy_lan_pairing() {
        let (store, _, legacy_provider) = temp_store();
        let scoped = store.scoped("com.vaultmesh.desktop.lan-pairing");

        legacy_provider.items.lock().unwrap().insert(
            entry_key(
                "com.vaultmesh.desktop.lan-pairing",
                "device-assist-registration-scopes-v2",
            ),
            b"scopes_json".to_vec(),
        );

        let retrieved = scoped
            .get("device-assist-registration-scopes-v2")
            .unwrap()
            .expect("migrated");
        assert_eq!(retrieved.as_slice(), b"scopes_json");
        assert!(
            legacy_provider
                .items
                .lock()
                .unwrap()
                .get(&entry_key(
                    "com.vaultmesh.desktop.lan-pairing",
                    "device-assist-registration-scopes-v2"
                ))
                .is_none(),
            "Legacy entry must be cleaned up after migration"
        );
    }
}
