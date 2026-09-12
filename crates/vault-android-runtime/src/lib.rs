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

#[cfg(target_os = "android")]
mod jni_bridge;

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const VAULT_FILE_NAME: &str = "vaultmesh.vault";

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
    #[error("invalid_vault")]
    InvalidVault,
    #[error("io_error")]
    Io,
    #[error("invalid_input")]
    InvalidInput,
    #[error("item_not_found")]
    ItemNotFound,
    #[error("not_initialized")]
    NotInitialized,
    #[error("trash_item_not_found")]
    TrashItemNotFound,
}

impl AndroidRuntimeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadyExists => "already_exists",
            Self::Missing => "missing",
            Self::Locked => "locked",
            Self::UnlockFailed => "unlock_failed",
            Self::InvalidVault => "invalid_vault",
            Self::Io => "io_error",
            Self::InvalidInput => "invalid_input",
            Self::ItemNotFound => "item_not_found",
            Self::NotInitialized => "not_initialized",
            Self::TrashItemNotFound => "trash_item_not_found",
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
            VaultError::UnsupportedFormat
            | VaultError::InvalidPayload
            | VaultError::Crypto
            | VaultError::Serialization => Self::InvalidVault,
            VaultError::InvalidUrl
            | VaultError::InvalidTotpSecret
            | VaultError::InvalidRecoveryCodes => Self::InvalidInput,
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
    session: Option<VaultSession>,
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
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.lock();
        }
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
        let snapshot = session.payload_snapshot()?;
        let result = mutation(session).map_err(AndroidRuntimeError::from);
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
            .and_then(|bytes| write_vault(&self.vault_path, &bytes));
        if let Err(error) = commit {
            session.restore_payload_snapshot(snapshot)?;
            return Err(error);
        }
        Ok(value)
    }

    fn replace_session(&mut self, candidate: VaultSession) {
        self.lock();
        self.session = Some(candidate);
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
}
