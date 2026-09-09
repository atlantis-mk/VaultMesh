use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{VaultError, VaultPayload};

pub(crate) const FORMAT_VERSION: u16 = 4;
const SALT_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

pub(crate) type VaultKey = [u8; KEY_LEN];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Argon2idParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultHeader {
    pub format_version: u16,
    pub salt: Vec<u8>,
    pub kdf: Argon2idParameters,
    pub wrapped_vault_key_nonce: Vec<u8>,
    pub wrapped_vault_key_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultEnvelope {
    pub header: VaultHeader,
    pub payload_nonce: Vec<u8>,
    pub payload_ciphertext: Vec<u8>,
}

pub(crate) fn create_header(
    master_password: &str,
) -> Result<(VaultHeader, Zeroizing<VaultKey>), VaultError> {
    let mut vault_key = Zeroizing::new([0_u8; KEY_LEN]);
    OsRng.fill_bytes(vault_key.as_mut());

    let header = rewrap_header(master_password, &vault_key)?;
    Ok((header, vault_key))
}

/// Wraps an existing random vault key under new master-password material.
/// The payload must be re-encrypted because these header fields form its AAD.
pub(crate) fn rewrap_header(
    master_password: &str,
    vault_key: &VaultKey,
) -> Result<VaultHeader, VaultError> {
    rewrap_header_version(master_password, vault_key, FORMAT_VERSION)
}

fn rewrap_header_version(
    master_password: &str,
    vault_key: &VaultKey,
    version: u16,
) -> Result<VaultHeader, VaultError> {
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let kdf = default_kdf();
    let wrapping_key = Zeroizing::new(derive_key(master_password.as_bytes(), &salt, &kdf)?);
    let mut wrapping_nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut wrapping_nonce);

    let aad = header_aad(version, &salt, &kdf)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let wrapped_vault_key = cipher
        .encrypt(
            XNonce::from_slice(&wrapping_nonce),
            Payload {
                msg: vault_key.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;

    Ok(VaultHeader {
        format_version: version,
        salt: salt.to_vec(),
        kdf,
        wrapped_vault_key_nonce: wrapping_nonce.to_vec(),
        wrapped_vault_key_ciphertext: wrapped_vault_key,
    })
}

pub(crate) fn parse_envelope(encrypted_vault: &[u8]) -> Result<VaultEnvelope, VaultError> {
    let envelope =
        serde_json::from_slice(encrypted_vault).map_err(|_| VaultError::InvalidPayload)?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub(crate) fn unlock_key(
    master_password: &str,
    header: &VaultHeader,
) -> Result<Zeroizing<VaultKey>, VaultError> {
    let wrapping_key = Zeroizing::new(derive_key(
        master_password.as_bytes(),
        &header.salt,
        &header.kdf,
    )?);
    let aad = header_aad(header.format_version, &header.salt, &header.kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| VaultError::UnlockFailed)?;
    let decrypted_key = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header.wrapped_vault_key_nonce),
                Payload {
                    msg: &header.wrapped_vault_key_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::UnlockFailed)?,
    );
    if decrypted_key.len() != KEY_LEN {
        return Err(VaultError::UnlockFailed);
    }

    let mut vault_key = Zeroizing::new([0_u8; KEY_LEN]);
    vault_key.copy_from_slice(decrypted_key.as_slice());
    Ok(vault_key)
}

pub(crate) fn decrypt_payload(
    envelope: &VaultEnvelope,
    vault_key: &VaultKey,
) -> Result<VaultPayload, VaultError> {
    let aad = header_aad(
        envelope.header.format_version,
        &envelope.header.salt,
        &envelope.header.kdf,
    )?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(vault_key).map_err(|_| VaultError::UnlockFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope.payload_nonce),
                Payload {
                    msg: &envelope.payload_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::UnlockFailed)?,
    );
    if envelope.header.format_version == FORMAT_VERSION {
        #[derive(Deserialize)]
        struct Presence {
            #[serde(rename = "sync")]
            _sync: serde::de::IgnoredAny,
        }
        let _: Presence =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidPayload)?;
    }
    serde_json::from_slice(plaintext.as_slice()).map_err(|_| VaultError::InvalidPayload)
}

pub(crate) fn encrypt_payload(
    header: &VaultHeader,
    vault_key: &VaultKey,
    payload: &VaultPayload,
) -> Result<Vec<u8>, VaultError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(payload).map_err(|_| VaultError::Serialization)?);
    let mut payload_nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut payload_nonce);
    let aad = header_aad(header.format_version, &header.salt, &header.kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key).map_err(|_| VaultError::Crypto)?;
    let payload_ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;

    serde_json::to_vec(&VaultEnvelope {
        header: header.clone(),
        payload_nonce: payload_nonce.to_vec(),
        payload_ciphertext,
    })
    .map_err(|_| VaultError::Serialization)
}

fn default_kdf() -> Argon2idParameters {
    Argon2idParameters {
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    kdf: &Argon2idParameters,
) -> Result<VaultKey, VaultError> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| VaultError::Crypto)?;
    Ok(output)
}

fn header_aad(version: u16, salt: &[u8], kdf: &Argon2idParameters) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(&(b"vaultmesh-header-v1", version, salt, kdf))
        .map_err(|_| VaultError::Serialization)
}

fn validate_envelope(envelope: &VaultEnvelope) -> Result<(), VaultError> {
    validate_envelope_version(envelope, FORMAT_VERSION)
}

fn validate_envelope_version(envelope: &VaultEnvelope, version: u16) -> Result<(), VaultError> {
    if envelope.header.format_version != version {
        return Err(VaultError::UnsupportedFormat);
    }
    // Reject every non-current version and non-fixed KDF before Argon2 to
    // avoid unsupported compatibility paths and attacker-controlled work.
    if envelope.header.kdf != default_kdf() {
        return Err(VaultError::UnsupportedFormat);
    }
    if envelope.header.salt.len() != SALT_LEN
        || envelope.header.wrapped_vault_key_nonce.len() != NONCE_LEN
        || envelope.payload_nonce.len() != NONCE_LEN
        || envelope.header.wrapped_vault_key_ciphertext.len() != KEY_LEN + 16
        || envelope.payload_ciphertext.len() < 16
    {
        return Err(VaultError::InvalidPayload);
    }
    Ok(())
}

/// This parser is reachable only from the explicit password migration path.
pub(crate) fn parse_format3_for_upgrade(bytes: &[u8]) -> Result<VaultEnvelope, VaultError> {
    let envelope = serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidPayload)?;
    validate_envelope_version(&envelope, 3)?;
    Ok(envelope)
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn ct_lan_sync_format3_migration_fixture() {
        // Synthetic encrypted fixture generated by the original format-3 writer.
        let old: &[u8] = include_bytes!("../tests/fixtures/format3.vault");
        let key = [7_u8; KEY_LEN];
        assert!(crate::VaultSession::unlock("synthetic format3 master", &old).is_err());
        assert!(crate::VaultSession::unlock_with_vault_key(&key, &old).is_err());
        assert!(crate::VaultSession::upgrade_format3("wrong", &old).is_err());
        let mut upgraded =
            crate::VaultSession::upgrade_format3("synthetic format3 master", &old).unwrap();
        assert_eq!(upgraded.format_version().unwrap(), 4);
        assert_eq!(upgraded.list_items().unwrap()[0].title, "Migration test");
        let new = upgraded.save().unwrap();
        assert!(parse_format3_for_upgrade(&new).is_err());
        upgraded
            .change_master_password("synthetic format3 master", "new synthetic master")
            .unwrap();
        assert!(
            crate::VaultSession::unlock("new synthetic master", &upgraded.save().unwrap()).is_ok()
        );
    }
}
