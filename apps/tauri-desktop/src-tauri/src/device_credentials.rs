use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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
pub use crate::keychain_share::APP_DATA_DIR_NAME;

const MAGIC: &[u8; 4] = b"VMDC";
const VERSION_EMPTY_AAD: u8 = 1;
const VERSION_BOUND_AAD: u8 = 2;
const KDF_INFO: &[u8] = b"vaultmesh:device-credentials:v1";

pub trait RootSecretStore: Send + Sync {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String>;
}

pub struct PlatformRootSecretStore;

#[cfg(target_os = "macos")]
impl RootSecretStore for PlatformRootSecretStore {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        crate::macos_root_secret::get_or_create_root_secret()
    }
}

#[cfg(target_os = "windows")]
impl RootSecretStore for PlatformRootSecretStore {
    fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
            .map_err(|e| format!("无法创建钥匙串入口: {e}"))?;
        match entry.get_secret() {
            Ok(bytes) => Ok(normalize_root_secret(&bytes)),
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

#[derive(Default, Serialize, Deserialize)]
struct StoredPayload {
    version: u32,
    entries: HashMap<String, String>,
}

struct DeviceCredentialStoreInner {
    file_path: PathBuf,
    root_secret: Zeroizing<[u8; 32]>,
    entries: HashMap<String, String>,
    /// Set when the OS root secret could not be opened. Every read and write
    /// then fails closed with this non-secret reason instead of aborting startup.
    unavailable: Option<String>,
}

#[derive(Clone)]
pub struct DeviceCredentialStore {
    inner: Arc<Mutex<DeviceCredentialStoreInner>>,
}

fn normalize_root_secret(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    if bytes.len() == 32 {
        secret.copy_from_slice(bytes);
    } else {
        let hash = Sha256::digest(bytes);
        secret.copy_from_slice(&hash);
    }
    secret
}

fn credential_aad() -> Vec<u8> {
    let user = current_os_user_binding();
    format!("app={APP_DATA_DIR_NAME}\nuser={user}\nproto={VERSION_BOUND_AAD}").into_bytes()
}

fn current_os_user_binding() -> String {
    #[cfg(unix)]
    {
        format!("uid:{}", unsafe { libc::geteuid() })
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_owned())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".to_owned()
    }
}

pub fn default_desktop_app_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(APP_DATA_DIR_NAME),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let roaming = std::env::var_os("APPDATA")?;
        Some(PathBuf::from(roaming).join(APP_DATA_DIR_NAME))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
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

        let aad = credential_aad();
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("凭据加密失败: {e}"))?;

        let mut file_bytes =
            Vec::with_capacity(MAGIC.len() + 1 + nonce_bytes.len() + ciphertext.len());
        file_bytes.extend_from_slice(MAGIC);
        file_bytes.push(VERSION_BOUND_AAD);
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

    fn load(file_path: &Path, root_secret: &[u8; 32]) -> Result<LoadedCredentials, String> {
        if !file_path.is_file() {
            return Ok(LoadedCredentials {
                entries: HashMap::new(),
                reseal: false,
            });
        }

        let file_bytes = fs::read(file_path).map_err(|e| format!("读取凭据文件失败: {e}"))?;
        if file_bytes.len() < MAGIC.len() + 1 + 12 {
            return Err("凭据文件损坏: 长度过短".to_string());
        }

        if &file_bytes[..MAGIC.len()] != MAGIC {
            return Err("凭据文件标识错误".to_string());
        }

        let version = file_bytes[MAGIC.len()];
        let nonce_start = MAGIC.len() + 1;
        let nonce_end = nonce_start + 12;
        let nonce = Nonce::from_slice(&file_bytes[nonce_start..nonce_end]);
        let ciphertext = &file_bytes[nonce_end..];
        let key = derive_encryption_key(root_secret);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES 密码初始化失败: {e}"))?;
        let aad = credential_aad();
        let (plaintext, reseal) = match version {
            VERSION_BOUND_AAD => (
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|e| format!("凭据解密失败: {e}"))?,
                false,
            ),
            VERSION_EMPTY_AAD => (
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| format!("凭据解密失败: {e}"))?,
                true,
            ),
            _ => return Err(format!("不支持的凭据版本: {version}")),
        };

        let payload: StoredPayload =
            serde_json::from_slice(&plaintext).map_err(|e| format!("反序列化凭据内容失败: {e}"))?;

        Ok(LoadedCredentials {
            entries: payload.entries,
            reseal,
        })
    }
}

struct LoadedCredentials {
    entries: HashMap<String, String>,
    reseal: bool,
}

impl DeviceCredentialStore {
    pub fn platform(app_data_dir: &Path) -> Result<Self, String> {
        let file_path = app_data_dir.join(CREDENTIALS_FILE_NAME);
        Self::with_stores(file_path, Arc::new(PlatformRootSecretStore))
    }

    /// Opens only the encrypted file. Pre-v0.1.4 per-service Keychain entries
    /// are never read, enumerated or deleted: every one of them would cost the
    /// user a separate login-password prompt (ADR-0053).
    pub fn with_stores(
        file_path: PathBuf,
        root_store: Arc<dyn RootSecretStore>,
    ) -> Result<Self, String> {
        let root_secret = root_store.get_or_create_root_secret()?;
        let loaded = DeviceCredentialStoreInner::load(&file_path, &root_secret)?;
        let store = Self {
            inner: Arc::new(Mutex::new(DeviceCredentialStoreInner {
                file_path,
                root_secret,
                entries: loaded.entries,
                unavailable: None,
            })),
        };
        if loaded.reseal {
            let inner = store
                .inner
                .lock()
                .map_err(|_| "凭据互斥锁中毒".to_string())?;
            inner.save()?;
        }
        Ok(store)
    }

    /// A store that rejects every operation. Used when the root keychain item
    /// cannot be opened so the app can still start and unlock with the master
    /// password while PIN, biometric and pairing features stay disabled.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DeviceCredentialStoreInner {
                file_path: PathBuf::new(),
                root_secret: Zeroizing::new([0u8; 32]),
                entries: HashMap::new(),
                unavailable: Some(reason.into()),
            })),
        }
    }

    pub fn unavailable_reason(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.unavailable.clone())
    }

    pub fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        if let Some(reason) = &inner.unavailable {
            return Err(reason.clone());
        }
        let key = entry_key(service, account);
        let Some(encoded) = inner.entries.get(&key) else {
            return Ok(None);
        };
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|e| format!("Base64 解码凭据失败: {e}"))?;
        Ok(Some(Zeroizing::new(bytes)))
    }

    pub fn read_unified_secret(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ()> {
        match self.get(service, account) {
            Ok(Some(bytes)) => Ok(bytes),
            _ => Err(()),
        }
    }

    pub fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        if let Some(reason) = &inner.unavailable {
            return Err(reason.clone());
        }
        let key = entry_key(service, account);
        inner.entries.insert(key, STANDARD.encode(secret));
        inner.save()
    }

    pub fn delete(&self, service: &str, account: &str) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "凭据互斥锁中毒".to_string())?;
        if let Some(reason) = &inner.unavailable {
            return Err(reason.clone());
        }
        let key = entry_key(service, account);
        let removed = inner.entries.remove(&key).is_some();
        if removed {
            inner.save()?;
        }
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

    pub struct TestDir(pub PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn temp_store() -> (DeviceCredentialStore, TestDir) {
        let temp_dir = std::env::temp_dir().join(format!("vaultmesh-cred-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).expect("create test dir");
        let file_path = temp_dir.join("device-credentials.enc");
        let root_store = Arc::new(MemoryRootSecretStore([42u8; 32]));
        let store =
            DeviceCredentialStore::with_stores(file_path, root_store).expect("create store");
        (store, TestDir(temp_dir))
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    use super::test_helpers::*;
    use super::*;

    #[test]
    fn unavailable_store_fails_closed_without_panicking() {
        let store = DeviceCredentialStore::unavailable("根钥匙串不可用 (-128)");
        assert_eq!(store.unavailable_reason().as_deref(), Some("根钥匙串不可用 (-128)"));
        assert!(store.get("svc", "acc").is_err());
        assert!(store.set("svc", "acc", b"x").is_err());
        assert!(store.delete("svc", "acc").is_err());
        assert!(store.scoped("svc").get("acc").is_err());
        assert!(store.read_unified_secret("svc", "acc").is_err());
    }

    #[test]
    fn test_device_credential_store_crud_and_persistence() {
        let (store, temp_dir) = temp_store();
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
        let reloaded = DeviceCredentialStore::with_stores(file_path.clone(), root_store).unwrap();
        assert_eq!(
            reloaded.get("svc1", "acc1").unwrap().unwrap().as_slice(),
            b"secret_value_1"
        );

        // Delete
        reloaded.delete("svc1", "acc1").unwrap();
        assert_eq!(reloaded.get("svc1", "acc1").unwrap(), None);

        // Reload again, should be gone
        let root_store2 = Arc::new(MemoryRootSecretStore([42u8; 32]));
        let reloaded2 = DeviceCredentialStore::with_stores(file_path, root_store2).unwrap();
        assert_eq!(reloaded2.get("svc1", "acc1").unwrap(), None);
    }

    #[test]
    fn leftover_legacy_migration_marker_does_not_affect_reads_or_writes() {
        let (store, temp_dir) = temp_store();
        let file_path = temp_dir.0.join("device-credentials.enc");
        store
            .set(
                "com.vaultmesh.desktop.migration",
                "legacy-services-v1",
                b"1",
            )
            .unwrap();
        store
            .set("com.vaultmesh.desktop.pin", "desktop-pin-1", b"pin")
            .unwrap();

        let reloaded = DeviceCredentialStore::with_stores(
            file_path,
            Arc::new(MemoryRootSecretStore([42u8; 32])),
        )
        .unwrap();
        assert_eq!(
            reloaded
                .get("com.vaultmesh.desktop.pin", "desktop-pin-1")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"pin"
        );
        assert!(
            reloaded
                .read_unified_secret(
                    "com.vaultmesh.desktop.browser-pairing",
                    "native-host-hmac-v1"
                )
                .is_err()
        );
        reloaded
            .set(
                "com.vaultmesh.desktop.browser-pairing",
                "native-host-hmac-v1",
                b"new",
            )
            .unwrap();
        reloaded
            .delete("com.vaultmesh.desktop.pin", "desktop-pin-1")
            .unwrap();
        assert!(
            reloaded
                .get("com.vaultmesh.desktop.pin", "desktop-pin-1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn empty_aad_file_is_resealed_with_bound_aad() {
        let (store, temp_dir) = temp_store();
        store.set("svc", "acc", b"sealed").unwrap();
        let file_path = temp_dir.0.join("device-credentials.enc");
        let bytes = fs::read(&file_path).unwrap();
        assert_eq!(bytes[MAGIC.len()], VERSION_BOUND_AAD);

        let root = [42u8; 32];
        let key = derive_encryption_key(&root);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [7u8; 12];
        let payload = serde_json::to_vec(&StoredPayload {
            version: 1,
            entries: std::collections::HashMap::from([(
                entry_key(
                    "com.vaultmesh.desktop.browser-pairing",
                    "native-host-hmac-v1",
                ),
                STANDARD.encode(b"legacy-file"),
            )]),
        })
        .unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload.as_slice())
            .unwrap();
        let mut legacy_file = Vec::new();
        legacy_file.extend_from_slice(MAGIC);
        legacy_file.push(VERSION_EMPTY_AAD);
        legacy_file.extend_from_slice(&nonce_bytes);
        legacy_file.extend_from_slice(&ciphertext);
        fs::write(&file_path, &legacy_file).unwrap();

        let reloaded = DeviceCredentialStore::with_stores(
            file_path.clone(),
            Arc::new(MemoryRootSecretStore(root)),
        )
        .unwrap();
        assert_eq!(
            reloaded
                .get(
                    "com.vaultmesh.desktop.browser-pairing",
                    "native-host-hmac-v1"
                )
                .unwrap()
                .unwrap()
                .as_slice(),
            b"legacy-file"
        );
        assert_eq!(
            fs::read(&file_path).unwrap()[MAGIC.len()],
            VERSION_BOUND_AAD
        );
    }

    #[test]
    fn test_scoped_credential_store() {
        let (store, _) = temp_store();
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
    fn desktop_app_data_dir_uses_the_shared_support_directory() {
        let home = Path::new("/Users/example");
        let macos = home
            .join("Library")
            .join("Application Support")
            .join(APP_DATA_DIR_NAME);
        assert!(macos.ends_with("Application Support/com.vaultmesh.desktop"));
        let roaming = Path::new("/Users/example/AppData/Roaming").join(APP_DATA_DIR_NAME);
        assert!(roaming.ends_with("com.vaultmesh.desktop"));
        assert_eq!(APP_DATA_DIR_NAME, "com.vaultmesh.desktop");
    }
}
