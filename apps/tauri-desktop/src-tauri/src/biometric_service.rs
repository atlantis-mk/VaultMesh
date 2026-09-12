use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::write_private_file;

const KEY_BYTES: usize = 32;
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    available: bool,
    enabled: bool,
    kind: Option<&'static str>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BiometricRecord {
    version: u8,
    vault_path: PathBuf,
    credential_id: String,
}

pub struct BiometricQuickUnlockService {
    record_path: PathBuf,
    keyring_service: &'static str,
    credential_prefix: &'static str,
}

impl BiometricQuickUnlockService {
    pub fn new(
        record_path: PathBuf,
        keyring_service: &'static str,
        credential_prefix: &'static str,
    ) -> Self {
        Self {
            record_path,
            keyring_service,
            credential_prefix,
        }
    }

    pub fn status(&self) -> BiometricStatus {
        let available = biometric_available();
        let enabled = available
            && self.read_record().is_some_and(|record| {
                record.vault_path.is_file() && credential_exists(self.keyring_service, &record)
            });
        BiometricStatus {
            available,
            enabled,
            kind: available.then_some("touchId"),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.status().enabled
    }

    pub fn enable(&self, vault_path: PathBuf, vault_key: &[u8]) -> Result<BiometricStatus, String> {
        if vault_key.len() != KEY_BYTES || !vault_path.is_file() {
            return Err("无法创建 Touch ID 快速解锁凭据。".to_owned());
        }
        prompt_biometric("启用 Touch ID 快速解锁 VaultMesh")?;
        self.provision(vault_path, vault_key)
    }

    pub fn provision(
        &self,
        vault_path: PathBuf,
        vault_key: &[u8],
    ) -> Result<BiometricStatus, String> {
        if vault_key.len() != KEY_BYTES || !vault_path.is_file() {
            return Err("无法创建 Touch ID 快速解锁凭据。".to_owned());
        }
        let vault_path = vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        if self.read_record().is_some_and(|record| {
            record.vault_path == vault_path && credential_exists(self.keyring_service, &record)
        }) {
            return Ok(self.status());
        }
        self.disable()?;
        let record = BiometricRecord {
            version: 1,
            vault_path,
            credential_id: format!("{}-{}", self.credential_prefix, uuid::Uuid::new_v4()),
        };
        set_credential(self.keyring_service, &record, vault_key)?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| "无法保存 Touch ID 快速解锁状态。".to_owned())?;
        if let Err(message) = write_private_file(
            &self.record_path,
            &bytes,
            "无法保存 Touch ID 快速解锁状态。",
        ) {
            let _ = delete_credential(self.keyring_service, &record);
            return Err(message);
        }
        Ok(self.status())
    }

    pub fn unlock(&self) -> Result<(PathBuf, Zeroizing<Vec<u8>>), String> {
        let record = self
            .read_record()
            .ok_or_else(|| "尚未启用 Touch ID 快速解锁。".to_owned())?;
        if !record.vault_path.is_file() {
            return Err("Touch ID 快速解锁对应的保险库不存在。".to_owned());
        }
        prompt_biometric("使用 Touch ID 解锁 VaultMesh")?;
        let key = get_credential(self.keyring_service, &record)?;
        if key.len() != KEY_BYTES {
            return Err("Touch ID 快速解锁凭据无效，请使用主密码重新启用。".to_owned());
        }
        Ok((record.vault_path, key))
    }

    pub fn disable(&self) -> Result<BiometricStatus, String> {
        if let Some(record) = self.read_record() {
            delete_credential(self.keyring_service, &record)?;
        }
        match std::fs::remove_file(&self.record_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法删除 Touch ID 快速解锁状态。".to_owned()),
        }
        Ok(self.status())
    }

    pub fn disable_if_for_different_vault(&self, vault_path: &Path) -> Result<(), String> {
        if self.read_record().is_some_and(|record| {
            vault_path
                .canonicalize()
                .ok()
                .is_none_or(|path| path != record.vault_path)
        }) {
            self.disable()?;
        }
        Ok(())
    }

    fn read_record(&self) -> Option<BiometricRecord> {
        let bytes = std::fs::read(&self.record_path).ok()?;
        let record: BiometricRecord = serde_json::from_slice(&bytes).ok()?;
        (record.version == 1
            && !record.credential_id.is_empty()
            && record.credential_id.len() <= 128
            && record.vault_path.is_absolute())
        .then_some(record)
    }
}

#[cfg(target_os = "macos")]
fn biometric_available() -> bool {
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
    let context = unsafe { LAContext::new() };
    unsafe {
        context
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
            && context.biometryType() == LABiometryType::TouchID
    }
}

#[cfg(not(target_os = "macos"))]
fn biometric_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn prompt_biometric(reason: &str) -> Result<(), String> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    if !biometric_available() {
        return Err("这台设备当前不支持 Touch ID 快速解锁。".to_owned());
    }
    let context = unsafe { LAContext::new() };
    let reason = NSString::from_str(reason);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        let _ = sender.send(success.as_bool());
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason,
            &reply,
        );
    }
    match receiver.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(true) => Ok(()),
        Ok(false) => Err("Touch ID 验证未完成。".to_owned()),
        Err(_) => {
            unsafe { context.invalidate() };
            Err("Touch ID 验证已超时。".to_owned())
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn prompt_biometric(_reason: &str) -> Result<(), String> {
    Err("这台设备当前不支持 Touch ID 快速解锁。".to_owned())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn set_credential(service: &str, record: &BiometricRecord, key: &[u8]) -> Result<(), String> {
    keyring::Entry::new(service, &record.credential_id)
        .and_then(|entry| entry.set_secret(key))
        .map_err(|_| "无法保存 Touch ID 快速解锁凭据。".to_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn set_credential(_service: &str, _record: &BiometricRecord, _key: &[u8]) -> Result<(), String> {
    Err("当前平台不支持生物识别凭据存储。".to_owned())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn get_credential(service: &str, record: &BiometricRecord) -> Result<Zeroizing<Vec<u8>>, String> {
    keyring::Entry::new(service, &record.credential_id)
        .and_then(|entry| entry.get_secret())
        .map(Zeroizing::new)
        .map_err(|_| "无法读取 Touch ID 快速解锁凭据，请使用主密码重新启用。".to_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn get_credential(_service: &str, _record: &BiometricRecord) -> Result<Zeroizing<Vec<u8>>, String> {
    Err("当前平台不支持生物识别凭据存储。".to_owned())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn delete_credential(service: &str, record: &BiometricRecord) -> Result<(), String> {
    let entry = keyring::Entry::new(service, &record.credential_id)
        .map_err(|_| "无法删除 Touch ID 快速解锁凭据。".to_owned())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("无法删除 Touch ID 快速解锁凭据。".to_owned()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn delete_credential(_service: &str, _record: &BiometricRecord) -> Result<(), String> {
    Ok(())
}

fn credential_exists(service: &str, record: &BiometricRecord) -> bool {
    get_credential(service, record).is_ok()
}
