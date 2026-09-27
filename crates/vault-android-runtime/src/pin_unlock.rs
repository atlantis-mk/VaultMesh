//! PIN quick unlock uses a Keystore sealed device secret and a six digit PIN.
//! Only Rust/core decrypts and verifies the Vault Key.

use std::{fs, io::Read};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use scrypt::{Params, scrypt};
use serde::{Deserialize, Serialize};
use vaultmesh_core::VaultSession;
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime, read_vault, write_vault};

const RECORD_FILE: &str = "vaultmesh-pin-wrapper.json";
const MAX_RECORD_BYTES: u64 = 4096;
const AAD: &[u8] = b"vaultmesh-android-pin-wrapper-v1";
const FAILURE_LIMIT: u8 = 5;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    version: u8,
    salt: String,
    nonce: String,
    wrapped_vault_key: String,
    failed_attempts: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidPinStatus {
    pub enabled: bool,
    pub remaining_attempts: u8,
}

fn validate_pin(pin: &str) -> Result<(), AndroidRuntimeError> {
    if pin.len() == 6 && pin.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AndroidRuntimeError::InvalidInput)
    }
}

fn decode_device_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>, AndroidRuntimeError> {
    if encoded.len() > 64 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    let secret = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| AndroidRuntimeError::InvalidInput)?,
    );
    if secret.len() != 32 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(secret)
}

fn derive_key(
    pin: &str,
    device_secret: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, AndroidRuntimeError> {
    let mut input = Zeroizing::new(Vec::with_capacity(6 + 32));
    input.extend_from_slice(pin.as_bytes());
    input.extend_from_slice(device_secret);
    let params = Params::new(15, 8, 1, 32).map_err(|_| AndroidRuntimeError::InvalidInput)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    scrypt(input.as_slice(), salt, &params, key.as_mut())
        .map_err(|_| AndroidRuntimeError::InvalidInput)?;
    Ok(key)
}

impl AndroidVaultRuntime {
    fn pin_record(&self) -> Result<Option<PinRecord>, AndroidRuntimeError> {
        let path = self.vault_path.with_file_name(RECORD_FILE);
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AndroidRuntimeError::Io),
        };
        let metadata = file.metadata().map_err(|_| AndroidRuntimeError::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AndroidRuntimeError::Io)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let record: PinRecord =
            serde_json::from_slice(&bytes).map_err(|_| AndroidRuntimeError::InvalidVault)?;
        if record.version != 1
            || record.failed_attempts > FAILURE_LIMIT
            || STANDARD_NO_PAD
                .decode(&record.salt)
                .map_or(true, |v| v.len() != 16)
            || STANDARD_NO_PAD
                .decode(&record.nonce)
                .map_or(true, |v| v.len() != 24)
            || STANDARD_NO_PAD
                .decode(&record.wrapped_vault_key)
                .map_or(true, |v| v.len() != 48)
        {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        Ok(Some(record))
    }

    fn save_pin_record(&self, record: &PinRecord) -> Result<(), AndroidRuntimeError> {
        let bytes = serde_json::to_vec(record).map_err(|_| AndroidRuntimeError::InvalidVault)?;
        write_vault(&self.vault_path.with_file_name(RECORD_FILE), &bytes)
    }

    pub fn pin_status(&self) -> Result<AndroidPinStatus, AndroidRuntimeError> {
        let record = self.pin_record()?;
        Ok(AndroidPinStatus {
            enabled: record.is_some(),
            remaining_attempts: record
                .map_or(FAILURE_LIMIT, |value| FAILURE_LIMIT - value.failed_attempts),
        })
    }

    pub fn enable_pin_unlock(
        &self,
        pin: &str,
        encoded_device_secret: &str,
    ) -> Result<(), AndroidRuntimeError> {
        validate_pin(pin)?;
        let secret = decode_device_secret(encoded_device_secret)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let vault_key = session.quick_unlock_key()?;
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key(pin, &secret, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let wrapped = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: vault_key.as_ref(),
                    aad: AAD,
                },
            )
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        self.save_pin_record(&PinRecord {
            version: 1,
            salt: STANDARD_NO_PAD.encode(salt),
            nonce: STANDARD_NO_PAD.encode(nonce),
            wrapped_vault_key: STANDARD_NO_PAD.encode(wrapped),
            failed_attempts: 0,
        })
    }

    pub fn unlock_with_pin(
        &mut self,
        pin: &str,
        encoded_device_secret: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let candidate = self.pin_session_from_secret(pin, encoded_device_secret)?;
        self.replace_session(candidate);
        Ok(())
    }

    pub(crate) fn pin_session_from_secret(
        &self,
        pin: &str,
        encoded_device_secret: &str,
    ) -> Result<VaultSession, AndroidRuntimeError> {
        validate_pin(pin)?;
        let secret = decode_device_secret(encoded_device_secret)?;
        let mut record = self
            .pin_record()?
            .ok_or(AndroidRuntimeError::ValueUnavailable)?;
        if record.failed_attempts >= FAILURE_LIMIT {
            return Err(AndroidRuntimeError::PinLocked);
        }
        let salt = STANDARD_NO_PAD
            .decode(&record.salt)
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let nonce = STANDARD_NO_PAD
            .decode(&record.nonce)
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let wrapped = STANDARD_NO_PAD
            .decode(&record.wrapped_vault_key)
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let key = derive_key(pin, &secret, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let candidate_key = cipher.decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &wrapped,
                aad: AAD,
            },
        );
        let candidate = match candidate_key {
            Ok(candidate_key) => {
                let encrypted = read_vault(&self.vault_path)?;
                VaultSession::unlock_with_vault_key(&Zeroizing::new(candidate_key), &encrypted)
                    .map_err(AndroidRuntimeError::from)
            }
            Err(_) => Err(AndroidRuntimeError::UnlockFailed),
        };
        match candidate {
            Ok(candidate) => {
                if record.failed_attempts != 0 {
                    record.failed_attempts = 0;
                    self.save_pin_record(&record)?;
                }
                Ok(candidate)
            }
            Err(AndroidRuntimeError::UnlockFailed) => {
                record.failed_attempts += 1;
                self.save_pin_record(&record)?;
                if record.failed_attempts >= FAILURE_LIMIT {
                    Err(AndroidRuntimeError::PinLocked)
                } else {
                    Err(AndroidRuntimeError::PinFailed)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn reset_pin_failures(&self) -> Result<(), AndroidRuntimeError> {
        let Some(mut record) = self.pin_record()? else {
            return Ok(());
        };
        if record.failed_attempts != 0 {
            record.failed_attempts = 0;
            self.save_pin_record(&record)?;
        }
        Ok(())
    }

    pub fn disable_pin_unlock(&self) -> Result<(), AndroidRuntimeError> {
        let path = self.vault_path.with_file_name(RECORD_FILE);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AndroidRuntimeError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeStatus;
    use uuid::Uuid;

    #[test]
    fn pin_failure_limit_master_reset_and_disable() {
        let dir = std::env::temp_dir().join(format!("vaultmesh-android-pin-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        let device_secret = STANDARD_NO_PAD.encode([42_u8; 32]);
        runtime.enable_pin_unlock("123456", &device_secret).unwrap();
        runtime.lock();
        for remaining in (0..FAILURE_LIMIT).rev() {
            assert_eq!(
                runtime
                    .unlock_with_pin("000000", &device_secret)
                    .unwrap_err(),
                if remaining == 0 {
                    AndroidRuntimeError::PinLocked
                } else {
                    AndroidRuntimeError::PinFailed
                }
            );
            assert_eq!(runtime.pin_status().unwrap().remaining_attempts, remaining);
            assert_eq!(runtime.status(), RuntimeStatus::Locked);
        }
        assert_eq!(
            runtime
                .unlock_with_pin("123456", &device_secret)
                .unwrap_err(),
            AndroidRuntimeError::PinLocked
        );
        runtime.unlock("master-password").unwrap();
        assert_eq!(
            runtime.pin_status().unwrap().remaining_attempts,
            FAILURE_LIMIT
        );
        runtime.lock();
        runtime.unlock_with_pin("123456", &device_secret).unwrap();
        runtime
            .change_master_password("master-password", "next-password")
            .unwrap();
        runtime.lock();
        runtime.unlock_with_pin("123456", &device_secret).unwrap();
        runtime.disable_pin_unlock().unwrap();
        runtime.lock();
        assert_eq!(
            runtime
                .unlock_with_pin("123456", &device_secret)
                .unwrap_err(),
            AndroidRuntimeError::ValueUnavailable
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pin_record_failure_does_not_publish_unlock() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-pin-fail-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        let device_secret = STANDARD_NO_PAD.encode([42_u8; 32]);
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .enable_pin_unlock("123456", &device_secret)
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(!runtime.pin_status().unwrap().enabled);
        runtime.enable_pin_unlock("123456", &device_secret).unwrap();
        runtime.lock();
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .unlock_with_pin("000000", &device_secret)
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_pin_record_is_rejected_without_unlock() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-pin-corrupt-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        let device_secret = STANDARD_NO_PAD.encode([42_u8; 32]);
        runtime.enable_pin_unlock("123456", &device_secret).unwrap();
        runtime.lock();
        let path = dir.join(RECORD_FILE);
        let original = fs::read(&path).unwrap();
        fs::write(&path, vec![b'X'; MAX_RECORD_BYTES as usize + 1]).unwrap();
        assert_eq!(
            runtime.pin_status().unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(
            runtime
                .unlock_with_pin("123456", &device_secret)
                .unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        fs::write(&path, original).unwrap();
        runtime.unlock_with_pin("123456", &device_secret).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
