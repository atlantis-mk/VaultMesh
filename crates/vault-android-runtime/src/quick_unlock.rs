//! Biometric quick-unlock wrapper. Android Keystore seals the random wrapper
//! secret; the Vault Key never crosses JNI.

use std::{fs, io::Read};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use vaultmesh_core::VaultSession;
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime, read_vault, write_vault};

const RECORD_FILE: &str = "vaultmesh-biometric-wrapper.json";
const AAD: &[u8] = b"vaultmesh-android-biometric-wrapper-v1";
const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QuickUnlockRecord {
    version: u8,
    nonce: String,
    wrapped_vault_key: String,
}

impl AndroidVaultRuntime {
    /// Returns a random wrapper secret for immediate Keystore sealing. This
    /// value is not the Vault Key and must not enter Compose state or storage.
    pub fn prepare_biometric_unlock(&self) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let vault_key = session.quick_unlock_key()?;
        let mut wrapper_secret = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(wrapper_secret.as_mut());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(wrapper_secret.as_ref())
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let wrapped = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: vault_key.as_ref(),
                    aad: AAD,
                },
            )
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let record = QuickUnlockRecord {
            version: 1,
            nonce: STANDARD_NO_PAD.encode(nonce),
            wrapped_vault_key: STANDARD_NO_PAD.encode(wrapped),
        };
        let serialized =
            serde_json::to_vec(&record).map_err(|_| AndroidRuntimeError::InvalidVault)?;
        write_vault(&self.vault_path.with_file_name(RECORD_FILE), &serialized)?;
        Ok(Zeroizing::new(
            STANDARD_NO_PAD.encode(wrapper_secret.as_ref()),
        ))
    }

    pub fn unlock_with_biometric_secret(
        &mut self,
        encoded_secret: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let candidate = self.biometric_session_from_secret(encoded_secret)?;
        self.replace_session(candidate);
        Ok(())
    }

    pub(crate) fn biometric_session_from_secret(
        &self,
        encoded_secret: &str,
    ) -> Result<VaultSession, AndroidRuntimeError> {
        if encoded_secret.len() > 64 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let secret = Zeroizing::new(
            STANDARD_NO_PAD
                .decode(encoded_secret)
                .map_err(|_| AndroidRuntimeError::InvalidInput)?,
        );
        if secret.len() != 32 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let path = self.vault_path.with_file_name(RECORD_FILE);
        let file = fs::File::open(&path).map_err(|_| AndroidRuntimeError::ValueUnavailable)?;
        let metadata = file.metadata().map_err(|_| AndroidRuntimeError::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let mut serialized = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut serialized)
            .map_err(|_| AndroidRuntimeError::Io)?;
        if serialized.len() as u64 > MAX_RECORD_BYTES {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let record: QuickUnlockRecord =
            serde_json::from_slice(&serialized).map_err(|_| AndroidRuntimeError::InvalidVault)?;
        if record.version != 1 {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let nonce = STANDARD_NO_PAD
            .decode(record.nonce)
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        let wrapped = STANDARD_NO_PAD
            .decode(record.wrapped_vault_key)
            .map_err(|_| AndroidRuntimeError::InvalidVault)?;
        if nonce.len() != 24 || wrapped.len() != 48 {
            return Err(AndroidRuntimeError::InvalidVault);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&secret)
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let vault_key = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &wrapped,
                        aad: AAD,
                    },
                )
                .map_err(|_| AndroidRuntimeError::UnlockFailed)?,
        );
        let encrypted = read_vault(&self.vault_path)?;
        VaultSession::unlock_with_vault_key(&vault_key, &encrypted).map_err(Into::into)
    }

    pub fn disable_biometric_unlock(&self) -> Result<(), AndroidRuntimeError> {
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
    use crate::{RuntimeStatus, VAULT_FILE_NAME};
    use uuid::Uuid;

    #[test]
    fn biometric_wrapper_unlocks_without_exporting_vault_key_and_fails_closed() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-biometric-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        runtime
            .add_login(
                "Synthetic".into(),
                "person".into(),
                "synthetic-password".into(),
                None,
            )
            .unwrap();
        let wrapper_secret = runtime.prepare_biometric_unlock().unwrap();
        assert_eq!(
            STANDARD_NO_PAD
                .decode(wrapper_secret.as_bytes())
                .unwrap()
                .len(),
            32
        );
        let wrapper_bytes = fs::read(dir.join(RECORD_FILE)).unwrap();
        assert!(!String::from_utf8_lossy(&wrapper_bytes).contains("synthetic-password"));
        assert!(!String::from_utf8_lossy(&wrapper_bytes).contains(wrapper_secret.as_str()));
        runtime.lock();
        assert_eq!(
            runtime.unlock_with_biometric_secret("bad").unwrap_err(),
            AndroidRuntimeError::InvalidInput
        );
        assert_eq!(
            runtime
                .unlock_with_biometric_secret(&STANDARD_NO_PAD.encode([7_u8; 32]))
                .unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        runtime
            .unlock_with_biometric_secret(&wrapper_secret)
            .unwrap();
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Synthetic");

        runtime
            .change_master_password("master-password", "next-password")
            .unwrap();
        runtime.lock();
        runtime
            .unlock_with_biometric_secret(&wrapper_secret)
            .unwrap();
        assert_eq!(
            runtime
                .copy_login_password(&runtime.list_logins().unwrap()[0].id, "next-password")
                .unwrap()
                .as_str(),
            "synthetic-password"
        );
        runtime.disable_biometric_unlock().unwrap();
        runtime.lock();
        assert_eq!(
            runtime
                .unlock_with_biometric_secret(&wrapper_secret)
                .unwrap_err(),
            AndroidRuntimeError::ValueUnavailable
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert!(dir.join(VAULT_FILE_NAME).is_file());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wrapper_write_failure_does_not_create_quick_unlock() {
        let dir = std::env::temp_dir().join(format!(
            "vaultmesh-android-biometric-fail-{}",
            Uuid::new_v4()
        ));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.prepare_biometric_unlock().unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(!dir.join(RECORD_FILE).exists());
        assert_eq!(runtime.status(), RuntimeStatus::Unlocked);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_wrapper_record_never_unlocks_or_replaces_the_session() {
        let dir = std::env::temp_dir().join(format!(
            "vaultmesh-android-biometric-corrupt-{}",
            Uuid::new_v4()
        ));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        let secret = runtime.prepare_biometric_unlock().unwrap();
        runtime.lock();
        let record_path = dir.join(RECORD_FILE);
        let original = fs::read(&record_path).unwrap();

        fs::write(
            &record_path,
            b"{\"version\":2,\"nonce\":\"bad\",\"wrapped_vault_key\":\"bad\"}",
        )
        .unwrap();
        assert_eq!(
            runtime.unlock_with_biometric_secret(&secret).unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);

        fs::write(&record_path, vec![b'X'; MAX_RECORD_BYTES as usize + 1]).unwrap();
        assert_eq!(
            runtime.unlock_with_biometric_secret(&secret).unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);

        fs::write(&record_path, original).unwrap();
        runtime.unlock_with_biometric_secret(&secret).unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Unlocked);
        fs::remove_dir_all(dir).unwrap();
    }
}
