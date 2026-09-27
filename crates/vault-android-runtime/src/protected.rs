//! Field-scoped protected access for the Android platform clipboard owner.

use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

const MAX_COPY_BYTES: usize = 1024 * 1024;

fn bounded(value: &str) -> Result<Zeroizing<String>, AndroidRuntimeError> {
    if value.is_empty() {
        return Err(AndroidRuntimeError::ValueUnavailable);
    }
    if value.len() > MAX_COPY_BYTES {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(Zeroizing::new(value.to_owned()))
}

macro_rules! protected_access {
    ($method:ident, $core_method:ident) => {
        pub fn $method(
            &self,
            id: &str,
            master_password: &str,
        ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
            let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
            let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
            session.verify_master_password(master_password)?;
            bounded(session.$core_method(id, Some(master_password))?)
        }
    };
}

impl AndroidVaultRuntime {
    protected_access!(copy_login_password, password_for_access);

    pub fn copy_login_totp_code(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        session.verify_master_password(master_password)?;
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AndroidRuntimeError::Io)?
            .as_secs();
        bounded(
            &session
                .totp_code_for_access(id, unix_time, Some(master_password))?
                .code,
        )
    }
    protected_access!(copy_card_number, card_number_for_access);
    protected_access!(copy_card_security_code, card_security_code_for_access);
    protected_access!(copy_card_pin, card_pin_for_access);
    protected_access!(copy_ssh_password, ssh_password_for_access);
    protected_access!(copy_ssh_private_key, ssh_private_key_for_access);
    protected_access!(copy_ssh_key_passphrase, ssh_key_passphrase_for_access);

    pub fn copy_ssh_public_key(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        session.verify_master_password(master_password)?;
        bounded(session.ssh_public_key_for_access(id)?)
    }

    pub fn copy_secret_value(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        session.verify_master_password(master_password)?;
        if session.secret_detail(id)?.is_passkey {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let value = session.secret_value_for_access(id, Some(master_password))?;
        bounded(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use vaultmesh_core::{NewSecretItem, SecretItemKind};

    #[test]
    fn protected_copy_requires_current_password_and_fails_closed_when_locked() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-protected-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("vault-password").unwrap();
        runtime
            .add_login(
                "Login".into(),
                "alice".into(),
                "synthetic-login-password".into(),
                None,
            )
            .unwrap();
        let login_id = runtime.list_logins().unwrap()[0].id.clone();
        assert_eq!(
            runtime.copy_login_password(&login_id, "wrong").unwrap_err(),
            AndroidRuntimeError::UnlockFailed
        );
        assert_eq!(
            runtime
                .copy_login_password(&login_id, "vault-password")
                .unwrap()
                .as_str(),
            "synthetic-login-password"
        );
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
        let card_id = runtime.list_cards().unwrap()[0].id.clone();
        assert_eq!(
            runtime
                .copy_card_number(&card_id, "vault-password")
                .unwrap()
                .as_str(),
            "4111111111111111"
        );
        assert_eq!(
            runtime
                .copy_card_security_code(&card_id, "vault-password")
                .unwrap()
                .as_str(),
            "123"
        );
        assert_eq!(
            runtime
                .copy_card_pin(&card_id, "vault-password")
                .unwrap_err(),
            AndroidRuntimeError::ValueUnavailable
        );
        runtime
            .add_secret(
                "Token".into(),
                "api-key",
                "Provider".into(),
                "Account".into(),
                "synthetic-token".into(),
            )
            .unwrap();
        let secret_id = runtime.list_secrets().unwrap()[0].id.clone();
        assert_eq!(
            runtime
                .copy_secret_value(&secret_id, "vault-password")
                .unwrap()
                .as_str(),
            "synthetic-token"
        );
        runtime
            .add_ssh(
                "SSH".into(),
                "host.test".into(),
                22,
                "alice".into(),
                Some("synthetic-ssh-password".into()),
                None,
                None,
                None,
            )
            .unwrap();
        let ssh_id = runtime.list_ssh().unwrap()[0].id.clone();
        assert_eq!(
            runtime
                .copy_ssh_password(&ssh_id, "vault-password")
                .unwrap()
                .as_str(),
            "synthetic-ssh-password"
        );
        let passkey = runtime
            .mutate_and_commit(|session| {
                Ok(session.add_secret(NewSecretItem {
                    title: "Passkey".into(),
                    kind: SecretItemKind::AuthenticatorKey,
                    provider: None,
                    account: None,
                    secret: "synthetic-passkey".into(),
                    environment: None,
                    scopes: vec!["vaultmesh:passkey:v1".into()],
                    expires_at: None,
                    website: None,
                    notes: None,
                    folder: None,
                    favorite: false,
                    master_password_reprompt: false,
                })?)
            })
            .unwrap();
        assert_eq!(
            runtime
                .copy_secret_value(&passkey.id.to_string(), "vault-password")
                .unwrap_err(),
            AndroidRuntimeError::InvalidInput
        );
        runtime.lock();
        assert_eq!(
            runtime
                .copy_secret_value(&secret_id, "vault-password")
                .unwrap_err(),
            AndroidRuntimeError::Locked
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
