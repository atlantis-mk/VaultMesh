//! Redacted history projections and fixed item-specific mutations.

use serde::Serialize;
use uuid::Uuid;

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidRevisionSummary {
    pub revision_id: String,
    pub title: String,
    pub subtitle: Option<String>,
    pub saved_at: u64,
}

fn parse_id(value: &str) -> Result<Uuid, AndroidRuntimeError> {
    Uuid::parse_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)
}

impl AndroidVaultRuntime {
    pub fn list_login_history(
        &self,
        id: &str,
    ) -> Result<Vec<AndroidRevisionSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .item_history(parse_id(id)?)?
            .into_iter()
            .map(|item| AndroidRevisionSummary {
                revision_id: item.revision_id.to_string(),
                title: item.title,
                subtitle: Some(item.username),
                saved_at: item.saved_at,
            })
            .collect())
    }

    pub fn restore_login_revision(
        &mut self,
        id: &str,
        revision_id: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let (id, revision_id) = (parse_id(id)?, parse_id(revision_id)?);
        self.mutate_and_commit(|session| {
            session.restore_revision(id, revision_id)?;
            Ok(())
        })
    }

    pub fn clear_login_history(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| session.clear_history(id))
    }

    pub fn list_card_history(
        &self,
        id: &str,
    ) -> Result<Vec<AndroidRevisionSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .card_history(parse_id(id)?)?
            .into_iter()
            .map(|item| AndroidRevisionSummary {
                revision_id: item.revision_id.to_string(),
                title: item.title,
                subtitle: Some(item.masked_number),
                saved_at: item.saved_at,
            })
            .collect())
    }

    pub fn restore_card_revision(
        &mut self,
        id: &str,
        revision_id: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let (id, revision_id) = (parse_id(id)?, parse_id(revision_id)?);
        self.mutate_and_commit(|session| {
            session.restore_card_revision(id, revision_id)?;
            Ok(())
        })
    }

    pub fn clear_card_history(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| session.clear_card_history(id))
    }

    pub fn list_ssh_history(
        &self,
        id: &str,
    ) -> Result<Vec<AndroidRevisionSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .ssh_history(parse_id(id)?)?
            .into_iter()
            .map(|item| AndroidRevisionSummary {
                revision_id: item.revision_id.to_string(),
                title: item.title,
                subtitle: item.host,
                saved_at: item.saved_at,
            })
            .collect())
    }

    pub fn restore_ssh_revision(
        &mut self,
        id: &str,
        revision_id: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let (id, revision_id) = (parse_id(id)?, parse_id(revision_id)?);
        self.mutate_and_commit(|session| {
            if session
                .ssh_credential_detail(id)?
                .managed_ssh_alias
                .is_some()
            {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            session.restore_ssh_revision(id, revision_id)?;
            if session
                .ssh_credential_detail(id)?
                .managed_ssh_alias
                .is_some()
            {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            Ok(())
        })
    }

    pub fn clear_ssh_history(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            if session
                .ssh_credential_detail(id)?
                .managed_ssh_alias
                .is_some()
            {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            session.clear_ssh_history(id)
        })
    }

    pub fn list_identity_history(
        &self,
        id: &str,
    ) -> Result<Vec<AndroidRevisionSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .identity_history(parse_id(id)?)?
            .into_iter()
            .map(|item| AndroidRevisionSummary {
                revision_id: item.revision_id.to_string(),
                title: item.title,
                subtitle: item.display_name,
                saved_at: item.saved_at,
            })
            .collect())
    }

    pub fn restore_identity_revision(
        &mut self,
        id: &str,
        revision_id: &str,
    ) -> Result<(), AndroidRuntimeError> {
        let (id, revision_id) = (parse_id(id)?, parse_id(revision_id)?);
        self.mutate_and_commit(|session| {
            session.restore_identity_revision(id, revision_id)?;
            Ok(())
        })
    }

    pub fn clear_identity_history(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| session.clear_identity_history(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FAIL_NEXT_WRITE, VAULT_FILE_NAME};
    use std::fs;

    #[test]
    fn four_item_histories_are_redacted_and_restores_are_atomic() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-history-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();

        runtime
            .add_login("Login".into(), "user".into(), "login-secret".into(), None)
            .unwrap();
        let login = runtime.list_logins().unwrap()[0].id.clone();
        runtime
            .update_login(&login, "Login new".into(), "user".into(), None, None)
            .unwrap();
        let login_history = runtime.list_login_history(&login).unwrap();
        assert_eq!(login_history.len(), 1);
        assert_eq!(login_history[0].title, "Login");
        assert!(
            !serde_json::to_string(&login_history)
                .unwrap()
                .contains("login-secret")
        );
        runtime
            .add_login(
                "Other login".into(),
                "other".into(),
                "other-secret".into(),
                None,
            )
            .unwrap();
        let other_login = runtime
            .list_logins()
            .unwrap()
            .into_iter()
            .find(|item| item.title == "Other login")
            .unwrap()
            .id;

        runtime
            .add_card(
                "Card".into(),
                "Holder".into(),
                "4111111111111111".into(),
                12,
                2030,
                Some("123".into()),
                None,
            )
            .unwrap();
        let card = runtime.list_cards().unwrap()[0].id.clone();
        runtime
            .update_card(
                &card,
                "Card new".into(),
                "Holder".into(),
                None,
                12,
                2030,
                None,
                false,
                None,
                false,
            )
            .unwrap();
        let card_history = runtime.list_card_history(&card).unwrap();
        assert_eq!(card_history.len(), 1);
        assert!(
            !serde_json::to_string(&card_history)
                .unwrap()
                .contains("4111111111111111")
        );
        assert!(
            !serde_json::to_string(&card_history)
                .unwrap()
                .contains("123")
        );

        runtime
            .add_ssh(
                "SSH".into(),
                "host.test".into(),
                22,
                "user".into(),
                Some("ssh-secret".into()),
                None,
                None,
                None,
            )
            .unwrap();
        let ssh = runtime.list_ssh().unwrap()[0].id.clone();
        runtime
            .update_ssh(
                &ssh,
                "SSH new".into(),
                "host.test".into(),
                22,
                "user".into(),
                None,
                false,
                None,
                false,
                None,
                false,
                None,
                false,
            )
            .unwrap();
        let ssh_history = runtime.list_ssh_history(&ssh).unwrap();
        assert_eq!(ssh_history.len(), 1);
        assert!(
            !serde_json::to_string(&ssh_history)
                .unwrap()
                .contains("ssh-secret")
        );

        runtime
            .add_identity(
                "Identity".into(),
                "Alice".into(),
                "Example".into(),
                "".into(),
            )
            .unwrap();
        let identity = runtime.list_identities().unwrap()[0].id.clone();
        runtime
            .update_identity(
                &identity,
                "Identity new".into(),
                "Alice".into(),
                "Example".into(),
                "".into(),
            )
            .unwrap();
        let identity_history = runtime.list_identity_history(&identity).unwrap();
        assert_eq!(identity_history.len(), 1);

        assert_eq!(
            runtime
                .restore_login_revision(&login, &Uuid::new_v4().to_string())
                .unwrap_err(),
            AndroidRuntimeError::RevisionNotFound
        );
        assert_eq!(
            runtime
                .restore_login_revision(&other_login, &login_history[0].revision_id)
                .unwrap_err(),
            AndroidRuntimeError::RevisionNotFound
        );
        let old_file = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .restore_login_revision(&login, &login_history[0].revision_id)
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), old_file);
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Login new");
        assert_eq!(runtime.list_login_history(&login).unwrap().len(), 1);

        runtime
            .restore_login_revision(&login, &login_history[0].revision_id)
            .unwrap();
        assert_eq!(runtime.list_logins().unwrap()[0].title, "Login");
        assert_eq!(runtime.list_login_history(&login).unwrap().len(), 2);
        runtime
            .restore_card_revision(&card, &card_history[0].revision_id)
            .unwrap();
        runtime
            .restore_ssh_revision(&ssh, &ssh_history[0].revision_id)
            .unwrap();
        runtime
            .restore_identity_revision(&identity, &identity_history[0].revision_id)
            .unwrap();
        assert_eq!(runtime.list_cards().unwrap()[0].title, "Card");
        assert_eq!(runtime.list_ssh().unwrap()[0].title, "SSH");
        assert_eq!(runtime.list_identities().unwrap()[0].title, "Identity");

        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.clear_card_history(&card).unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(!runtime.list_card_history(&card).unwrap().is_empty());
        runtime.clear_login_history(&login).unwrap();
        runtime.clear_card_history(&card).unwrap();
        runtime.clear_ssh_history(&ssh).unwrap();
        runtime.clear_identity_history(&identity).unwrap();
        runtime.lock();
        assert_eq!(
            runtime.list_login_history(&login).unwrap_err(),
            AndroidRuntimeError::Locked
        );
        runtime.unlock("master-password").unwrap();
        assert!(runtime.list_login_history(&login).unwrap().is_empty());
        assert!(runtime.list_card_history(&card).unwrap().is_empty());
        assert!(runtime.list_ssh_history(&ssh).unwrap().is_empty());
        assert!(runtime.list_identity_history(&identity).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
