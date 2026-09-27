//! Android-owned runtime boundary for VaultMesh.
//!
//! Kotlin owns Android lifecycle and supplies the application-private data
//! directory. This crate owns the in-process Vault session and atomic file
//! persistence. JNI exports are fixed operations rather than a generic router.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use vaultmesh_core::{LoginItemUpdate, NewLoginItem, VaultError, VaultSession};

mod assist_resume;
mod autofill;
mod health;
mod history;
mod items;
#[cfg(target_os = "android")]
mod jni_bridge;
mod lan_credentials;
mod lan_pairing;
mod lan_sync;
mod login_fields;
mod pin_unlock;
mod protected;
mod quick_unlock;
mod recovery;

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const VAULT_FILE_NAME: &str = "vaultmesh.vault";
pub const BACKUP_EXPORT_STAGE_FILE_NAME: &str = "vaultmesh-backup-export.vault";
pub const BACKUP_IMPORT_STAGE_FILE_NAME: &str = "vaultmesh-backup-import.vault";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStatus {
    Missing,
    Locked,
    Unlocked,
}

impl RuntimeStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AndroidRuntimeError {
    #[error("already_exists")]
    AlreadyExists,
    #[error("missing")]
    Missing,
    #[error("locked")]
    Locked,
    #[error("unlock_failed")]
    UnlockFailed,
    #[error("pin_failed")]
    PinFailed,
    #[error("pin_locked")]
    PinLocked,
    #[error("invalid_vault")]
    InvalidVault,
    #[error("io_error")]
    Io,
    #[error("lan_listener_unavailable")]
    LanListenerUnavailable,
    #[error("lan_discovery_unavailable")]
    LanDiscoveryUnavailable,
    #[error("lan_scan_unavailable")]
    LanScanUnavailable,
    #[error("lan_identity_unavailable")]
    LanIdentityUnavailable,
    #[error("invalid_input")]
    InvalidInput,
    #[error("item_not_found")]
    ItemNotFound,
    #[error("not_initialized")]
    NotInitialized,
    #[error("trash_item_not_found")]
    TrashItemNotFound,
    #[error("value_unavailable")]
    ValueUnavailable,
    #[error("revision_not_found")]
    RevisionNotFound,
}

impl AndroidRuntimeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadyExists => "already_exists",
            Self::Missing => "missing",
            Self::Locked => "locked",
            Self::UnlockFailed => "unlock_failed",
            Self::PinFailed => "pin_failed",
            Self::PinLocked => "pin_locked",
            Self::InvalidVault => "invalid_vault",
            Self::Io => "io_error",
            Self::LanListenerUnavailable => "lan_listener_unavailable",
            Self::LanDiscoveryUnavailable => "lan_discovery_unavailable",
            Self::LanScanUnavailable => "lan_scan_unavailable",
            Self::LanIdentityUnavailable => "lan_identity_unavailable",
            Self::InvalidInput => "invalid_input",
            Self::ItemNotFound => "item_not_found",
            Self::NotInitialized => "not_initialized",
            Self::TrashItemNotFound => "trash_item_not_found",
            Self::ValueUnavailable => "value_unavailable",
            Self::RevisionNotFound => "revision_not_found",
        }
    }
}

impl From<VaultError> for AndroidRuntimeError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::UnlockFailed | VaultError::MasterPasswordRequired => Self::UnlockFailed,
            VaultError::Locked => Self::Locked,
            VaultError::ItemNotFound => Self::ItemNotFound,
            VaultError::TrashItemNotFound => Self::TrashItemNotFound,
            VaultError::RevisionNotFound => Self::RevisionNotFound,
            VaultError::CardSecretUnavailable
            | VaultError::SshSecretUnavailable
            | VaultError::TotpUnavailable
            | VaultError::RecoveryCodesUnavailable => Self::ValueUnavailable,
            VaultError::UnsupportedFormat
            | VaultError::InvalidPayload
            | VaultError::Crypto
            | VaultError::Serialization => Self::InvalidVault,
            VaultError::InvalidUrl
            | VaultError::InvalidTotpSecret
            | VaultError::InvalidRecoveryCodes
            | VaultError::InvalidCardNumber
            | VaultError::InvalidCardExpiration
            | VaultError::InvalidCardSecurityCode
            | VaultError::InvalidCardPin
            | VaultError::InvalidSshCredential
            | VaultError::InvalidSshPublicKey
            | VaultError::InvalidSshPrivateKey
            | VaultError::InvalidIdentity
            | VaultError::InvalidSecretItem => Self::InvalidInput,
            _ => Self::InvalidVault,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidLoginSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub has_password: bool,
    pub has_totp_secret: bool,
    pub has_recovery_codes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTrashSummary {
    pub trash_id: String,
    pub item_id: String,
    pub title: String,
    pub username: String,
    pub deleted_at: u64,
}

pub struct AndroidVaultRuntime {
    vault_path: PathBuf,
    autofill_grant: Option<autofill::AutofillGrant>,
    session: Option<VaultSession>,
    persisted_fingerprint: Option<[u8; 32]>,
    assist_binding: Option<String>,
    assist_resume_credentials: Option<std::sync::Arc<lan_credentials::AndroidLanCredentials>>,
    relay: std::sync::Arc<vaultmesh_sync::relay::RelayHub>,
}

impl AndroidVaultRuntime {
    pub fn new(app_data_dir: impl AsRef<Path>) -> Result<Self, AndroidRuntimeError> {
        let app_data_dir = app_data_dir.as_ref();
        if !app_data_dir.is_absolute() {
            return Err(AndroidRuntimeError::Io);
        }
        Ok(Self {
            vault_path: app_data_dir.join(VAULT_FILE_NAME),
            session: None,
            autofill_grant: None,
            persisted_fingerprint: None,
            assist_binding: None,
            assist_resume_credentials: None,
            relay: vaultmesh_sync::relay::RelayHub::for_path(&app_data_dir.join(VAULT_FILE_NAME)),
        })
    }

    pub fn status(&self) -> RuntimeStatus {
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.is_locked())
        {
            RuntimeStatus::Unlocked
        } else if self.vault_path.is_file() {
            RuntimeStatus::Locked
        } else {
            RuntimeStatus::Missing
        }
    }

    pub fn create(&mut self, master_password: &str) -> Result<(), AndroidRuntimeError> {
        if self.vault_path.exists() {
            return Err(AndroidRuntimeError::AlreadyExists);
        }

        let candidate = VaultSession::create(master_password)?;
        let encrypted = candidate.save()?;
        write_vault(&self.vault_path, &encrypted)?;
        self.replace_session(candidate);
        Ok(())
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<(), AndroidRuntimeError> {
        let encrypted = read_vault(&self.vault_path)?;
        let candidate = VaultSession::unlock(master_password, &encrypted)?;
        self.replace_session(candidate);
        let _ = self.reset_pin_failures();
        Ok(())
    }

    pub fn change_master_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AndroidRuntimeError> {
        if self.session.as_ref().is_none_or(VaultSession::is_locked) {
            return Err(AndroidRuntimeError::Locked);
        }
        if current_password.is_empty() || new_password.is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let encrypted = read_vault(&self.vault_path)?;
        let mut candidate = VaultSession::unlock(current_password, &encrypted)?;
        candidate.change_master_password(current_password, new_password)?;
        let replacement = candidate.save()?;
        write_vault(&self.vault_path, &replacement)?;
        self.replace_session(candidate);
        Ok(())
    }

    pub fn prepare_encrypted_backup(&self) -> Result<(), AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let encrypted = zeroize::Zeroizing::new(session.save()?);
        write_vault(
            &self
                .vault_path
                .with_file_name(BACKUP_EXPORT_STAGE_FILE_NAME),
            &encrypted,
        )
    }

    pub fn restore_staged_backup(
        &mut self,
        master_password: &str,
    ) -> Result<(), AndroidRuntimeError> {
        if master_password.is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let encrypted = zeroize::Zeroizing::new(read_vault(
            &self
                .vault_path
                .with_file_name(BACKUP_IMPORT_STAGE_FILE_NAME),
        )?);
        let mut candidate = VaultSession::unlock(master_password, &encrypted)?;
        candidate.sync_reset_after_restore()?;
        candidate.sync_checkpoint(0)?;
        let replacement = zeroize::Zeroizing::new(candidate.save()?);
        write_vault(&self.vault_path, &replacement)?;
        self.replace_session(candidate);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.autofill_grant = None;
        if let Some(mut session) = self.session.take() {
            session.lock();
        }
    }

    pub fn sync_vault_id(&self) -> Result<Uuid, AndroidRuntimeError> {
        self.session
            .as_ref()
            .ok_or(AndroidRuntimeError::Locked)?
            .sync_state()
            .map(|state| state.vault_id)
            .map_err(AndroidRuntimeError::from)
    }

    pub fn sync_authorize_peer(
        &mut self,
        peer: &str,
        fingerprint: &str,
        enabled: bool,
    ) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| session.sync_authorize(peer, fingerprint, enabled))
    }

    pub fn list_logins(&self) -> Result<Vec<AndroidLoginSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_items()?
            .into_iter()
            .map(|item| AndroidLoginSummary {
                id: item.id.to_string(),
                title: item.title,
                username: item.username,
                url: item.url,
                has_password: item.has_password,
                has_totp_secret: item.has_totp_secret,
                has_recovery_codes: item.has_recovery_codes,
            })
            .collect())
    }

    pub fn add_login(
        &mut self,
        title: String,
        username: String,
        password: String,
        url: Option<String>,
    ) -> Result<(), AndroidRuntimeError> {
        if title.trim().is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        self.mutate_and_commit(|session| {
            session.add_item(NewLoginItem {
                title,
                username,
                password,
                url,
                notes: None,
                folder: None,
                favorite: false,
                totp_secret: None,
                recovery_codes: Vec::new(),
                additional_urls: Vec::new(),
                autofill_on_page_load: true,
                master_password_reprompt: false,
                custom_fields: Vec::new(),
            })?;
            Ok(())
        })
    }

    pub fn update_login(
        &mut self,
        id: &str,
        title: String,
        username: String,
        password: Option<String>,
        url: Option<String>,
    ) -> Result<(), AndroidRuntimeError> {
        if title.trim().is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            let current = session.item_detail(id)?;
            session.update_item(LoginItemUpdate {
                id,
                title,
                username,
                password,
                url,
                notes: current.notes,
                folder: current.folder,
                favorite: current.favorite,
                totp_secret: None,
                clear_totp_secret: false,
                recovery_codes: None,
                clear_recovery_codes: false,
                additional_urls: current.additional_urls,
                autofill_on_page_load: current.autofill_on_page_load,
                master_password_reprompt: current.master_password_reprompt,
                custom_fields: current.custom_fields,
            })?;
            Ok(())
        })
    }

    pub fn set_login_totp(
        &mut self,
        id: &str,
        secret: Option<String>,
        clear: bool,
    ) -> Result<(), AndroidRuntimeError> {
        let mut secret = zeroize::Zeroizing::new(secret);
        if clear == secret.is_some() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            let current = session.item_detail(id)?;
            session.update_item(LoginItemUpdate {
                id,
                title: current.title,
                username: current.username,
                password: None,
                url: current.url,
                notes: current.notes,
                folder: current.folder,
                favorite: current.favorite,
                totp_secret: std::mem::take(&mut *secret),
                clear_totp_secret: clear,
                recovery_codes: None,
                clear_recovery_codes: false,
                additional_urls: current.additional_urls,
                autofill_on_page_load: current.autofill_on_page_load,
                master_password_reprompt: current.master_password_reprompt,
                custom_fields: current.custom_fields,
            })?;
            Ok(())
        })
    }

    pub fn delete_login(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.delete_item(id)?;
            Ok(())
        })
    }

    pub fn list_trash(&self) -> Result<Vec<AndroidTrashSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_trash()?
            .into_iter()
            .map(|item| AndroidTrashSummary {
                trash_id: item.trash_id.to_string(),
                item_id: item.item_id.to_string(),
                title: item.title,
                username: item.username,
                deleted_at: item.deleted_at,
            })
            .collect())
    }

    pub fn restore_login(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = Uuid::parse_str(trash_id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.restore_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn purge_login(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = Uuid::parse_str(trash_id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.purge_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn empty_trash(&mut self) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.empty_trash()?;
            Ok(())
        })
    }

    fn mutate_and_commit<T>(
        &mut self,
        mutation: impl FnOnce(&mut VaultSession) -> Result<T, VaultError>,
    ) -> Result<T, AndroidRuntimeError> {
        let session = self.session.as_mut().ok_or(AndroidRuntimeError::Locked)?;
        use sha2::{Digest, Sha256};
        let disk = read_vault(&self.vault_path)?;
        if self.persisted_fingerprint.as_ref().is_none_or(|f| Sha256::digest(&disk).as_slice() != f) {
            return Err(AndroidRuntimeError::Io);
        }
        let snapshot = session.payload_snapshot()?;
        let result = mutation(session).and_then(|value| { session.sync_checkpoint(lan_sync::now())?; Ok(value) }).map_err(AndroidRuntimeError::from);
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                session.restore_payload_snapshot(snapshot)?;
                return Err(error);
            }
        };
        let commit = session
            .save()
            .map_err(AndroidRuntimeError::from)
            .and_then(|bytes| {
                write_vault(&self.vault_path, &bytes)?;
                self.persisted_fingerprint = Some(Sha256::digest(&bytes).into());
                Ok(())
            });
        if let Err(error) = commit {
            session.restore_payload_snapshot(snapshot)?;
            return Err(error);
        }
        self.assist_binding = session.sync_state().ok().map(|s| format!("{}:{}", s.vault_id, s.replica));
        self.checkpoint_assist_resume();
        self.publish_sync();
        Ok(value)
    }

    fn replace_session(&mut self, candidate: VaultSession) {
        self.lock();
        use sha2::{Digest, Sha256};
        self.persisted_fingerprint = read_vault(&self.vault_path).ok().map(|bytes| Sha256::digest(bytes).into());
        self.assist_binding = candidate.sync_state().ok().map(|s| format!("{}:{}", s.vault_id, s.replica));
        self.session = Some(candidate);
        self.checkpoint_assist_resume();
        self.publish_sync();
        let _ = vaultmesh_sync::SyncRuntime::sync_pump(self);
    }
}

impl Drop for AndroidVaultRuntime {
    fn drop(&mut self) {
        self.lock();
    }
}

fn read_vault(path: &Path) -> Result<Vec<u8>, AndroidRuntimeError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AndroidRuntimeError::Missing
        } else {
            AndroidRuntimeError::Io
        }
    })?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Err(AndroidRuntimeError::InvalidVault);
    }
    fs::read(path).map_err(|_| AndroidRuntimeError::Io)
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn write_vault(path: &Path, bytes: &[u8]) -> Result<(), AndroidRuntimeError> {
    #[cfg(test)]
    if FAIL_NEXT_WRITE.with(|flag| flag.replace(false)) {
        return Err(AndroidRuntimeError::Io);
    }

    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(AndroidRuntimeError::InvalidVault);
    }
    let parent = path.parent().ok_or(AndroidRuntimeError::Io)?;
    fs::create_dir_all(parent).map_err(|_| AndroidRuntimeError::Io)?;

    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;

        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options.open(path).map_err(|_| AndroidRuntimeError::Io)?;
    file.write_all(bytes).map_err(|_| AndroidRuntimeError::Io)?;
    file.commit().map_err(|_| AndroidRuntimeError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vaultmesh-android-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn create_unlock_lock_and_cold_start_are_fail_closed() {
        let dir = test_dir("lifecycle");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Missing);

        runtime.create("correct horse battery staple").unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Unlocked);
        assert_eq!(
            runtime.create("replacement").unwrap_err(),
            AndroidRuntimeError::AlreadyExists
        );

        runtime.lock();
        runtime.lock();
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert_eq!(
            runtime.unlock("wrong password").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        runtime.unlock("correct horse battery staple").unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Unlocked);

        drop(runtime);
        let restarted = AndroidVaultRuntime::new(&dir).unwrap();
        assert_eq!(restarted.status(), RuntimeStatus::Locked);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_create_does_not_publish_a_session() {
        let dir = test_dir("rollback");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.create("password").unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(runtime.status(), RuntimeStatus::Missing);
        assert!(!dir.join(VAULT_FILE_NAME).exists());
    }

    #[test]
    fn corrupt_and_oversized_files_are_rejected_without_unlocking() {
        let dir = test_dir("invalid");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(VAULT_FILE_NAME), b"not a vault").unwrap();
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        assert_eq!(
            runtime.unlock("password").unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn app_data_directory_must_be_absolute() {
        assert!(matches!(
            AndroidVaultRuntime::new("relative"),
            Err(AndroidRuntimeError::Io)
        ));
    }

    #[test]
    fn login_crud_commits_and_preserves_an_unreplaced_password() {
        let dir = test_dir("login-crud");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("vault-password").unwrap();
        runtime
            .add_login(
                "Example".into(),
                "person@example.test".into(),
                "item-password".into(),
                Some("https://example.test".into()),
            )
            .unwrap();
        let item = runtime.list_logins().unwrap().pop().unwrap();
        assert_eq!(item.title, "Example");
        assert!(item.has_password);

        runtime
            .update_login(
                &item.id,
                "Updated".into(),
                "new@example.test".into(),
                None,
                None,
            )
            .unwrap();
        let id = Uuid::parse_str(&item.id).unwrap();
        assert_eq!(
            runtime
                .session
                .as_ref()
                .unwrap()
                .password_for_copy(id)
                .unwrap(),
            "item-password"
        );

        runtime.lock();
        runtime.unlock("vault-password").unwrap();
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Updated");
        runtime.delete_login(&item.id).unwrap();
        assert!(runtime.list_logins().unwrap().is_empty());
        let trash = runtime.list_trash().unwrap().pop().unwrap();
        assert_eq!(trash.item_id, item.id);
        assert_eq!(trash.title, "Updated");
        runtime.restore_login(&trash.trash_id).unwrap();
        assert_eq!(runtime.list_logins().unwrap().len(), 1);
        assert!(runtime.list_trash().unwrap().is_empty());

        runtime.delete_login(&item.id).unwrap();
        let trash_id = runtime.list_trash().unwrap()[0].trash_id.clone();
        runtime.purge_login(&trash_id).unwrap();
        assert!(runtime.list_trash().unwrap().is_empty());
        runtime.lock();
        runtime.unlock("vault-password").unwrap();
        assert!(runtime.list_logins().unwrap().is_empty());
        assert!(runtime.list_trash().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn login_totp_is_core_owned_reauthenticated_and_atomic() {
        let dir = test_dir("login-totp");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        runtime
            .add_login("Login".into(), "user".into(), "item-password".into(), None)
            .unwrap();
        let id = runtime.list_logins().unwrap()[0].id.clone();
        assert!(!runtime.list_logins().unwrap()[0].has_totp_secret);
        assert_eq!(
            runtime
                .copy_login_totp_code(&id, "master-password")
                .unwrap_err(),
            AndroidRuntimeError::ValueUnavailable
        );
        assert_eq!(
            runtime
                .set_login_totp(&id, Some("invalid!".into()), false)
                .unwrap_err(),
            AndroidRuntimeError::InvalidInput
        );
        assert!(!runtime.list_logins().unwrap()[0].has_totp_secret);
        runtime
            .set_login_totp(&id, Some("JBSWY3DPEHPK3PXP".into()), false)
            .unwrap();
        assert!(runtime.list_logins().unwrap()[0].has_totp_secret);
        assert_eq!(
            runtime.copy_login_totp_code(&id, "wrong").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        let code = runtime
            .copy_login_totp_code(&id, "master-password")
            .unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|character| character.is_ascii_digit()));

        runtime
            .update_login(&id, "Renamed".into(), "user".into(), None, None)
            .unwrap();
        assert!(runtime.list_logins().unwrap()[0].has_totp_secret);
        assert_eq!(
            runtime
                .copy_login_password(&id, "master-password")
                .unwrap()
                .as_str(),
            "item-password"
        );

        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.set_login_totp(&id, None, true).unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);
        assert!(runtime.list_logins().unwrap()[0].has_totp_secret);
        runtime.set_login_totp(&id, None, true).unwrap();
        assert!(!runtime.list_logins().unwrap()[0].has_totp_secret);
        runtime.lock();
        assert_eq!(
            runtime
                .copy_login_totp_code(&id, "master-password")
                .unwrap_err(),
            AndroidRuntimeError::Locked
        );
        runtime.unlock("master-password").unwrap();
        assert!(!runtime.list_logins().unwrap()[0].has_totp_secret);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn complete_login_fields_preserve_protected_values_and_roll_back() {
        let dir = test_dir("login-complete");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        assert!(login_fields::parse_login_extras_json("{\"unknown\":1}").is_err());
        assert!(login_fields::parse_login_extras_json(&" ".repeat(512 * 1024 + 1)).is_err());
        let extras_json = serde_json::json!({
            "notes": "Synthetic note", "folder": "Personal", "favorite": true,
            "additionalUrls": ["https://secondary.example.test"],
            "autofillOnPageLoad": false, "masterPasswordReprompt": true,
            "customFields": [{"label": "account", "value": "synthetic-field"}],
        })
        .to_string();
        runtime
            .add_login_complete(
                "Login".into(),
                "user".into(),
                "synthetic-password".into(),
                Some("https://example.test".into()),
                login_fields::parse_login_extras_json(&extras_json).unwrap(),
            )
            .unwrap();
        let id = runtime.list_logins().unwrap()[0].id.clone();
        let detail = runtime.login_editor_detail(&id).unwrap();
        assert_eq!(detail.custom_fields[0].value, "synthetic-field");
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("synthetic-password")
        );
        runtime
            .set_login_totp(&id, Some("JBSWY3DPEHPK3PXP".into()), false)
            .unwrap();
        runtime
            .set_login_recovery_codes(&id, "1234-5678".into(), false)
            .unwrap();
        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .update_login_complete(
                    &id,
                    "Changed".into(),
                    "user".into(),
                    None,
                    Some("https://example.test".into()),
                    login_fields::AndroidLoginExtras::default(),
                )
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Login");
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);

        let replacement = extras_json.replace("Synthetic note", "Updated note");
        runtime
            .update_login_complete(
                &id,
                "Changed".into(),
                "user".into(),
                None,
                Some("https://example.test".into()),
                login_fields::parse_login_extras_json(&replacement).unwrap(),
            )
            .unwrap();
        runtime.lock();
        runtime.unlock("master-password").unwrap();
        assert_eq!(
            runtime.login_editor_detail(&id).unwrap().notes.as_deref(),
            Some("Updated note")
        );
        assert_eq!(
            runtime
                .copy_login_password(&id, "master-password")
                .unwrap()
                .as_str(),
            "synthetic-password"
        );
        assert!(runtime.list_logins().unwrap()[0].has_totp_secret);
        assert!(runtime.list_logins().unwrap()[0].has_recovery_codes);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn encrypted_backup_restore_validates_before_atomic_replacement() {
        let source_dir = test_dir("backup-source");
        let mut source = AndroidVaultRuntime::new(&source_dir).unwrap();
        source.create("source-password").unwrap();
        source
            .add_login(
                "Backed up".into(),
                "user".into(),
                "synthetic-secret".into(),
                None,
            )
            .unwrap();
        source.prepare_encrypted_backup().unwrap();
        let backup = fs::read(source_dir.join(BACKUP_EXPORT_STAGE_FILE_NAME)).unwrap();
        let recovered = VaultSession::unlock("source-password", &backup).unwrap();
        assert_eq!(recovered.list_items().unwrap()[0].title, "Backed up");
        source.lock();
        assert_eq!(
            source.prepare_encrypted_backup().unwrap_err(),
            AndroidRuntimeError::Locked
        );

        let target_dir = test_dir("backup-target");
        let mut target = AndroidVaultRuntime::new(&target_dir).unwrap();
        target.create("target-password").unwrap();
        target
            .add_login(
                "Current".into(),
                "other".into(),
                "current-secret".into(),
                None,
            )
            .unwrap();
        let old_file = fs::read(target_dir.join(VAULT_FILE_NAME)).unwrap();
        fs::write(target_dir.join(BACKUP_IMPORT_STAGE_FILE_NAME), b"broken").unwrap();
        assert_eq!(
            target.restore_staged_backup("source-password").unwrap_err(),
            AndroidRuntimeError::InvalidVault
        );
        assert_eq!(
            fs::read(target_dir.join(VAULT_FILE_NAME)).unwrap(),
            old_file
        );
        fs::write(target_dir.join(BACKUP_IMPORT_STAGE_FILE_NAME), &backup).unwrap();
        assert_eq!(
            target.restore_staged_backup("wrong-password").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        assert_eq!(target.list_logins().unwrap()[0].title, "Current");
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            target.restore_staged_backup("source-password").unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(
            fs::read(target_dir.join(VAULT_FILE_NAME)).unwrap(),
            old_file
        );
        assert_eq!(target.list_logins().unwrap()[0].title, "Current");

        target.restore_staged_backup("source-password").unwrap();
        assert_eq!(target.list_logins().unwrap()[0].title, "Backed up");
        assert_ne!(fs::read(target_dir.join(VAULT_FILE_NAME)).unwrap(), backup);
        target.lock();
        assert_eq!(
            target.unlock("target-password").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        target.unlock("source-password").unwrap();
        assert_eq!(target.list_logins().unwrap()[0].title, "Backed up");
        fs::remove_dir_all(source_dir).unwrap();
        fs::remove_dir_all(target_dir).unwrap();
    }

    #[test]
    fn failed_login_commit_restores_memory_and_file() {
        let dir = test_dir("login-rollback");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("vault-password").unwrap();
        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .add_login(
                    "Never committed".into(),
                    "person@example.test".into(),
                    "item-password".into(),
                    None,
                )
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(runtime.list_logins().unwrap().is_empty());
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_trash_restore_keeps_the_item_deleted() {
        let dir = test_dir("trash-rollback");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("vault-password").unwrap();
        runtime
            .add_login(
                "Deleted".into(),
                "person@example.test".into(),
                "item-password".into(),
                None,
            )
            .unwrap();
        let item_id = runtime.list_logins().unwrap()[0].id.clone();
        runtime.delete_login(&item_id).unwrap();
        let trash_id = runtime.list_trash().unwrap()[0].trash_id.clone();
        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();

        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.restore_login(&trash_id).unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(runtime.list_logins().unwrap().is_empty());
        assert_eq!(runtime.list_trash().unwrap().len(), 1);
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);

        runtime.empty_trash().unwrap();
        assert!(runtime.list_trash().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn password_rotation_commits_only_after_atomic_write() {
        let dir = test_dir("password-rotation");
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("old-vault-password").unwrap();
        runtime
            .add_login(
                "Preserved".into(),
                "alice".into(),
                "item-secret".into(),
                None,
            )
            .unwrap();
        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();

        assert_eq!(
            runtime
                .change_master_password("wrong", "new-vault-password")
                .unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Preserved");

        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .change_master_password("old-vault-password", "new-vault-password")
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Preserved");

        runtime
            .change_master_password("old-vault-password", "new-vault-password")
            .unwrap();
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Preserved");
        runtime.lock();
        assert_eq!(
            runtime.unlock("old-vault-password").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        drop(runtime);

        let mut restarted = AndroidVaultRuntime::new(&dir).unwrap();
        restarted.unlock("new-vault-password").unwrap();
        assert_eq!(restarted.list_logins().unwrap()[0].title, "Preserved");
        fs::remove_dir_all(dir).unwrap();
    }
}
