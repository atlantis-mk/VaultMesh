use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use atomic_write_file::OpenOptions as AtomicOpenOptions;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand_core::{OsRng, RngCore};
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const QUICK_UNLOCK_KEY_BYTES: usize = 32;
const DEVICE_SECRET_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const DEFAULT_FAILURE_LIMIT: u8 = 5;
const DESKTOP_KEYRING_SERVICE: &str = "com.vaultmesh.desktop.pin";
const BROWSER_KEYRING_SERVICE: &str = "com.vaultmesh.desktop.browser-pin";
const AGENT_KEYRING_SERVICE: &str = "com.vaultmesh.desktop.agent-pin";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinStatus {
    enabled: bool,
    locked: bool,
    failure_limit: u8,
    failed_attempts: u8,
    remaining_attempts: u8,
}

#[derive(Debug)]
pub struct PinCredential {
    pub vault_path: PathBuf,
    pub vault_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinRecord {
    version: u8,
    vault_path: PathBuf,
    credential_id: String,
    salt: String,
    nonce: String,
    authentication_tag: String,
    wrapped_vault_key: String,
    failure_limit: u8,
    failed_attempts: u8,
}

trait DeviceSecretStore: Send + Sync {
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), String>;
    fn get(&self, account: &str) -> Result<Zeroizing<Vec<u8>>, String>;
    fn delete(&self, account: &str) -> Result<(), String>;
}

struct PlatformSecretStore {
    service: &'static str,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl DeviceSecretStore for PlatformSecretStore {
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), String> {
        keyring::Entry::new(self.service, account)
            .and_then(|entry| entry.set_secret(secret))
            .map_err(|_| "无法保存设备安全凭据。".to_owned())
    }

    fn get(&self, account: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        keyring::Entry::new(self.service, account)
            .and_then(|entry| entry.get_secret())
            .map(Zeroizing::new)
            .map_err(|_| "无法读取设备安全凭据。".to_owned())
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        keyring::Entry::new(self.service, account)
            .and_then(|entry| entry.delete_credential())
            .map_err(|_| "无法删除设备安全凭据。".to_owned())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl DeviceSecretStore for PlatformSecretStore {
    fn set(&self, _account: &str, _secret: &[u8]) -> Result<(), String> {
        Err("这台设备当前不支持安全的 PIN 快速解锁。".to_owned())
    }

    fn get(&self, _account: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("这台设备当前不支持安全的 PIN 快速解锁。".to_owned())
    }

    fn delete(&self, _account: &str) -> Result<(), String> {
        Ok(())
    }
}

pub struct PinQuickUnlockService {
    record_path: PathBuf,
    secrets: Arc<dyn DeviceSecretStore>,
    credential_prefix: &'static str,
}

impl PinQuickUnlockService {
    pub fn new(record_path: PathBuf) -> Self {
        Self {
            record_path,
            secrets: Arc::new(PlatformSecretStore {
                service: DESKTOP_KEYRING_SERVICE,
            }),
            credential_prefix: "desktop-pin",
        }
    }

    pub fn new_browser(record_path: PathBuf) -> Self {
        Self {
            record_path,
            secrets: Arc::new(PlatformSecretStore {
                service: BROWSER_KEYRING_SERVICE,
            }),
            credential_prefix: "browser-pin",
        }
    }

    pub fn new_agent(record_path: PathBuf) -> Self {
        Self {
            record_path,
            secrets: Arc::new(PlatformSecretStore {
                service: AGENT_KEYRING_SERVICE,
            }),
            credential_prefix: "agent-pin",
        }
    }

    pub fn new_bitwarden_development(record_path: PathBuf) -> Self {
        Self {
            record_path,
            secrets: Arc::new(PlatformSecretStore {
                service: "com.vaultmesh.desktop.bitwarden-dev-pin",
            }),
            credential_prefix: "bitwarden-dev-pin",
        }
    }

    #[cfg(test)]
    fn with_store(record_path: PathBuf, secrets: Arc<dyn DeviceSecretStore>) -> Self {
        Self {
            record_path,
            secrets,
            credential_prefix: "test-pin",
        }
    }

    pub fn status(&self) -> PinStatus {
        let record = self.read_record();
        let enabled = record
            .as_ref()
            .is_some_and(|record| record.vault_path.is_file());
        let failure_limit = record
            .as_ref()
            .map_or(DEFAULT_FAILURE_LIMIT, |record| record.failure_limit);
        let failed_attempts = record.as_ref().map_or(0, |record| record.failed_attempts);
        PinStatus {
            enabled,
            locked: enabled && failed_attempts >= failure_limit,
            failure_limit,
            failed_attempts,
            remaining_attempts: if enabled {
                failure_limit.saturating_sub(failed_attempts)
            } else {
                failure_limit
            },
        }
    }

    pub fn enable(
        &self,
        vault_path: PathBuf,
        vault_key: &[u8],
        pin: &str,
        failure_limit: u8,
    ) -> Result<PinStatus, String> {
        validate_pin(pin)?;
        if vault_key.len() != QUICK_UNLOCK_KEY_BYTES {
            return Err("无法创建 PIN 快速解锁凭据。".to_owned());
        }
        if !(3..=10).contains(&failure_limit) {
            return Err("PIN 失败次数限制必须在 3 到 10 次之间。".to_owned());
        }
        let vault_path = vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        let credential_id = format!("{}-{}", self.credential_prefix, Uuid::new_v4());
        let mut device_secret = Zeroizing::new([0_u8; DEVICE_SECRET_BYTES]);
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(device_secret.as_mut());
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let wrapping_key = derive_wrapping_key(pin, device_secret.as_ref(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| "无法创建 PIN 快速解锁凭据。".to_owned())?;
        let mut wrapped_vault_key = Zeroizing::new(vault_key.to_vec());
        let aad = aad(&vault_path);
        let tag = cipher
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                aad.as_bytes(),
                &mut wrapped_vault_key,
            )
            .map_err(|_| "无法创建 PIN 快速解锁凭据。".to_owned())?;
        let record = PinRecord {
            version: 1,
            vault_path,
            credential_id: credential_id.clone(),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            authentication_tag: BASE64.encode(tag),
            wrapped_vault_key: BASE64.encode(wrapped_vault_key.as_slice()),
            failure_limit,
            failed_attempts: 0,
        };
        let previous = self.read_record();
        self.secrets.set(&credential_id, device_secret.as_ref())?;
        if let Err(error) = self.write_record(&record) {
            let _ = self.secrets.delete(&credential_id);
            return Err(error);
        }
        if let Some(previous) = previous {
            let _ = self.secrets.delete(&previous.credential_id);
        }
        Ok(self.status())
    }

    pub fn unlock(&self, pin: &str) -> Result<PinCredential, String> {
        validate_pin(pin)?;
        let mut record = self
            .read_record()
            .filter(|record| record.vault_path.is_file())
            .ok_or_else(|| "尚未启用 PIN 快速解锁。".to_owned())?;
        if record.failed_attempts >= record.failure_limit {
            return Err("PIN 已因连续失败而锁定，请使用主密码解锁后重试。".to_owned());
        }
        let result = self.unwrap_key(&record, pin);
        match result {
            Ok(vault_key) => {
                if record.failed_attempts > 0 {
                    record.failed_attempts = 0;
                    self.write_record(&record)?;
                }
                Ok(PinCredential {
                    vault_path: record.vault_path,
                    vault_key,
                })
            }
            Err(()) => {
                record.failed_attempts = record
                    .failure_limit
                    .min(record.failed_attempts.saturating_add(1));
                self.write_record(&record)?;
                let remaining = record.failure_limit.saturating_sub(record.failed_attempts);
                if remaining == 0 {
                    Err("PIN 不正确，失败次数已达上限。请使用主密码解锁。".to_owned())
                } else {
                    Err(format!("PIN 不正确，还可尝试 {remaining} 次。"))
                }
            }
        }
    }

    pub fn reset_failures(&self, vault_path: &Path) -> Result<(), String> {
        let canonical = vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        let Some(mut record) = self.read_record() else {
            return Ok(());
        };
        if record.vault_path == canonical && record.failed_attempts > 0 {
            record.failed_attempts = 0;
            self.write_record(&record)?;
        }
        Ok(())
    }

    pub fn disable_if_for_different_vault(&self, vault_path: &Path) -> Result<(), String> {
        let canonical = vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        if self
            .read_record()
            .is_some_and(|record| record.vault_path != canonical)
        {
            self.disable()?;
        }
        Ok(())
    }

    pub fn disable(&self) -> Result<(), String> {
        let record = self.read_record();
        match std::fs::remove_file(&self.record_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法关闭 PIN 快速解锁。".to_owned()),
        }
        if let Some(record) = record {
            let _ = self.secrets.delete(&record.credential_id);
        }
        Ok(())
    }

    fn unwrap_key(&self, record: &PinRecord, pin: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
        let device_secret = self.secrets.get(&record.credential_id).map_err(|_| ())?;
        if device_secret.len() != DEVICE_SECRET_BYTES {
            return Err(());
        }
        let salt = decode_exact::<SALT_BYTES>(&record.salt)?;
        let nonce = decode_exact::<NONCE_BYTES>(&record.nonce)?;
        let tag = decode_exact::<TAG_BYTES>(&record.authentication_tag)?;
        let wrapping_key =
            derive_wrapping_key(pin, device_secret.as_slice(), &salt).map_err(|_| ())?;
        let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).map_err(|_| ())?;
        let mut vault_key =
            Zeroizing::new(BASE64.decode(&record.wrapped_vault_key).map_err(|_| ())?);
        if vault_key.len() != QUICK_UNLOCK_KEY_BYTES {
            return Err(());
        }
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                aad(&record.vault_path).as_bytes(),
                &mut vault_key,
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| ())?;
        Ok(vault_key)
    }

    fn read_record(&self) -> Option<PinRecord> {
        let bytes = std::fs::read(&self.record_path).ok()?;
        let record: PinRecord = serde_json::from_slice(&bytes).ok()?;
        if record.version != 1
            || record.credential_id.is_empty()
            || !(3..=10).contains(&record.failure_limit)
            || record.failed_attempts > record.failure_limit
            || decode_exact::<SALT_BYTES>(&record.salt).is_err()
            || decode_exact::<NONCE_BYTES>(&record.nonce).is_err()
            || decode_exact::<TAG_BYTES>(&record.authentication_tag).is_err()
            || BASE64
                .decode(&record.wrapped_vault_key)
                .map_or(true, |value| value.len() != QUICK_UNLOCK_KEY_BYTES)
        {
            return None;
        }
        Some(record)
    }

    fn write_record(&self, record: &PinRecord) -> Result<(), String> {
        if let Some(parent) = self.record_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| "无法保存 PIN 快速解锁设置。".to_owned())?;
        }
        let encoded =
            serde_json::to_vec(record).map_err(|_| "无法保存 PIN 快速解锁设置。".to_owned())?;
        let mut options = AtomicOpenOptions::new();
        #[cfg(unix)]
        {
            use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
            use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
            AtomicOpenOptionsExt::preserve_mode(&mut options, false);
            StandardOpenOptionsExt::mode(&mut options, 0o600);
        }
        let mut file = options
            .open(&self.record_path)
            .map_err(|_| "无法保存 PIN 快速解锁设置。".to_owned())?;
        file.write_all(&encoded)
            .and_then(|()| file.commit())
            .map_err(|_| "无法保存 PIN 快速解锁设置。".to_owned())
    }
}

fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() == 6 && pin.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err("PIN 必须为 6 位数字。".to_owned())
    }
}

fn derive_wrapping_key(
    pin: &str,
    device_secret: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; QUICK_UNLOCK_KEY_BYTES]>, String> {
    let mut input = Zeroizing::new(Vec::with_capacity(pin.len() + device_secret.len()));
    input.extend_from_slice(pin.as_bytes());
    input.extend_from_slice(device_secret);
    let params = ScryptParams::new(15, 8, 1, QUICK_UNLOCK_KEY_BYTES)
        .map_err(|_| "无法创建 PIN 快速解锁凭据。".to_owned())?;
    let mut output = Zeroizing::new([0_u8; QUICK_UNLOCK_KEY_BYTES]);
    scrypt(input.as_slice(), salt, &params, output.as_mut())
        .map_err(|_| "无法创建 PIN 快速解锁凭据。".to_owned())?;
    Ok(output)
}

fn aad(vault_path: &Path) -> String {
    format!("desktop:{}", vault_path.to_string_lossy())
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let mut decoded = BASE64.decode(value).map_err(|_| ())?;
    if decoded.len() != N {
        decoded.zeroize();
        return Err(());
    }
    let mut result = [0_u8; N];
    result.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct MemorySecretStore(Mutex<HashMap<String, Vec<u8>>>);

    impl DeviceSecretStore for MemorySecretStore {
        fn set(&self, account: &str, secret: &[u8]) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .insert(account.into(), secret.to_vec());
            Ok(())
        }

        fn get(&self, account: &str) -> Result<Zeroizing<Vec<u8>>, String> {
            self.0
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| "missing".into())
        }

        fn delete(&self, account: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    struct TestCase {
        root: PathBuf,
        vault: PathBuf,
    }

    impl TestCase {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("vaultmesh-tauri-pin-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let vault = root.join("test.vault");
            std::fs::write(&vault, b"encrypted-placeholder").unwrap();
            Self { root, vault }
        }
    }

    impl Drop for TestCase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn pin_round_trip_locks_after_failures_and_master_unlock_resets_counter() {
        let case = TestCase::new();
        let service = PinQuickUnlockService::with_store(
            case.root.join("pin.json"),
            Arc::new(MemorySecretStore::default()),
        );
        let key = [7_u8; QUICK_UNLOCK_KEY_BYTES];
        let status = service
            .enable(case.vault.clone(), &key, "123456", 3)
            .unwrap();
        assert!(status.enabled);
        assert_eq!(service.unlock("123456").unwrap().vault_key.as_slice(), key);
        assert!(service.unlock("000000").unwrap_err().contains("2 次"));
        assert!(service.unlock("000000").unwrap_err().contains("1 次"));
        assert!(service.unlock("000000").unwrap_err().contains("上限"));
        assert!(service.status().locked);
        assert!(service.unlock("123456").unwrap_err().contains("锁定"));
        service.reset_failures(&case.vault).unwrap();
        assert_eq!(service.unlock("123456").unwrap().vault_key.as_slice(), key);
    }

    #[test]
    fn replacement_and_disable_remove_stale_device_secrets() {
        let case = TestCase::new();
        let store = Arc::new(MemorySecretStore::default());
        let service = PinQuickUnlockService::with_store(case.root.join("pin.json"), store.clone());
        service
            .enable(case.vault.clone(), &[1_u8; 32], "123456", 5)
            .unwrap();
        service
            .enable(case.vault.clone(), &[2_u8; 32], "654321", 5)
            .unwrap();
        assert_eq!(store.0.lock().unwrap().len(), 1);
        assert_eq!(
            service.unlock("654321").unwrap().vault_key.as_slice(),
            [2_u8; 32]
        );
        service.disable().unwrap();
        assert!(!service.status().enabled);
        assert!(store.0.lock().unwrap().is_empty());
    }

    #[test]
    fn different_vault_disables_credential_and_invalid_inputs_fail_closed() {
        let case = TestCase::new();
        let other = case.root.join("other.vault");
        std::fs::write(&other, b"other").unwrap();
        let service = PinQuickUnlockService::with_store(
            case.root.join("pin.json"),
            Arc::new(MemorySecretStore::default()),
        );
        assert!(
            service
                .enable(case.vault.clone(), &[1_u8; 31], "123456", 5)
                .is_err()
        );
        assert!(
            service
                .enable(case.vault.clone(), &[1_u8; 32], "12345x", 5)
                .is_err()
        );
        service
            .enable(case.vault.clone(), &[1_u8; 32], "123456", 5)
            .unwrap();
        service.disable_if_for_different_vault(&other).unwrap();
        assert!(!service.status().enabled);
    }
}
