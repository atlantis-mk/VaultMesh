//! App-private credential records sealed with a short-lived Android Keystore key.
//! Kotlin owns the non-exportable Keystore key; Rust never stores its wrapping key.

use std::{fs, io::Write, path::PathBuf};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use vaultmesh_lan_pairing::CredentialStore;
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const NONCE_SIZE: usize = 24;
const MAX_VALUE: usize = 16 * 1024;
const MAX_RECORD: usize = MAX_VALUE + 128;

pub(crate) struct AndroidLanCredentials {
    directory: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl AndroidLanCredentials {
    pub(crate) fn new(directory: PathBuf, key: [u8; 32]) -> Result<Self, ()> {
        let key = Zeroizing::new(key);
        if !directory.is_absolute() {
            return Err(());
        }
        fs::create_dir_all(&directory).map_err(|_| ())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
        Ok(Self { directory, key })
    }

    fn path(&self, account: &str) -> Result<PathBuf, ()> {
        if account.is_empty() || account.len() > 128 || !account.is_ascii() {
            return Err(());
        }
        let digest = Sha256::digest(account.as_bytes());
        let mut name = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            write!(&mut name, "{byte:02x}").map_err(|_| ())?;
        }
        Ok(self.directory.join(name))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.key.as_ref().into())
    }
}

impl CredentialStore for AndroidLanCredentials {
    fn set(&self, account: &str, value: &[u8]) -> Result<(), ()> {
        if value.is_empty() || value.len() > MAX_VALUE {
            return Err(());
        }
        let path = self.path(account)?;
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value,
                    aad: account.as_bytes(),
                },
            )
            .map_err(|_| ())?;
        let mut record = Zeroizing::new(Vec::with_capacity(1 + NONCE_SIZE + encrypted.len()));
        record.push(VERSION);
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&encrypted);
        let mut options = AtomicOpenOptions::new();
        #[cfg(unix)]
        {
            use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
            use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
            AtomicOpenOptionsExt::preserve_mode(&mut options, false);
            StandardOpenOptionsExt::mode(&mut options, 0o600);
        }
        let mut file = options.open(path).map_err(|_| ())?;
        file.write_all(&record)
            .and_then(|_| file.commit())
            .map_err(|_| ())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        let path = self.path(account)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if !metadata.is_file() || metadata.len() as usize > MAX_RECORD {
            return Err(());
        }
        let record = Zeroizing::new(fs::read(path).map_err(|_| ())?);
        if record.len() < 1 + NONCE_SIZE + 16 || record[0] != VERSION {
            return Err(());
        }
        let value = self
            .cipher()
            .decrypt(
                XNonce::from_slice(&record[1..1 + NONCE_SIZE]),
                Payload {
                    msg: &record[1 + NONCE_SIZE..],
                    aad: account.as_bytes(),
                },
            )
            .map_err(|_| ())?;
        if value.is_empty() || value.len() > MAX_VALUE {
            return Err(());
        }
        Ok(Some(Zeroizing::new(value)))
    }

    fn delete(&self, account: &str) -> Result<(), ()> {
        match fs::remove_file(self.path(account)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_sealed_bound_and_corruption_fails_closed() {
        let directory =
            std::env::temp_dir().join(format!("vaultmesh-lan-credential-{}", uuid::Uuid::new_v4()));
        let credentials = AndroidLanCredentials::new(directory.clone(), [7; 32]).unwrap();
        credentials
            .set("device-identity-v1", b"synthetic-private-key")
            .unwrap();
        let raw = fs::read(credentials.path("device-identity-v1").unwrap()).unwrap();
        assert!(
            !raw.windows(b"synthetic-private-key".len())
                .any(|w| w == b"synthetic-private-key")
        );
        assert_eq!(
            credentials
                .get("device-identity-v1")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"synthetic-private-key"
        );
        assert!(
            AndroidLanCredentials::new(directory.clone(), [8; 32])
                .unwrap()
                .get("device-identity-v1")
                .is_err()
        );
        fs::write(credentials.path("device-identity-v1").unwrap(), b"corrupt").unwrap();
        assert!(credentials.get("device-identity-v1").is_err());
        credentials.delete("device-identity-v1").unwrap();
        assert!(credentials.get("device-identity-v1").unwrap().is_none());
        fs::remove_dir_all(directory).unwrap();
    }
}
