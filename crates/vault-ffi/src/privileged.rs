use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use vaultmesh_core::{VaultError, VaultSession, VerifiedMasterPassword};
use zeroize::Zeroizing;

use crate::{
    VAULTMESH_ITEM_KIND_LOGIN, VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_ITEM_KIND_SECRET,
    VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VaultmeshVault,
};

pub const VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD: u32 = 1;
pub const VAULTMESH_PROTECTED_FIELD_LOGIN_TOTP: u32 = 2;
pub const VAULTMESH_PROTECTED_FIELD_CARD_NUMBER: u32 = 3;
pub const VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE: u32 = 4;
pub const VAULTMESH_PROTECTED_FIELD_CARD_PIN: u32 = 5;
pub const VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD: u32 = 6;
pub const VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY: u32 = 7;
pub const VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY: u32 = 8;
pub const VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE: u32 = 9;
pub const VAULTMESH_PROTECTED_FIELD_SECRET_VALUE: u32 = 10;

enum FieldAuth<'a> {
    Password(Option<&'a str>),
    Proof(Option<&'a VerifiedMasterPassword<'a>>),
}

fn read_protected_field(
    session: &VaultSession,
    item_kind: u32,
    protected_field: u32,
    id: Uuid,
    auth: FieldAuth<'_>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let bytes = match (item_kind, protected_field) {
        (VAULTMESH_ITEM_KIND_LOGIN, VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD) => match auth {
            FieldAuth::Password(pw) => session.password_for_access(id, pw)?,
            FieldAuth::Proof(proof) => session.password_for_access_with_proof(id, proof)?,
        }
        .as_bytes()
        .to_vec(),
        (VAULTMESH_ITEM_KIND_LOGIN, VAULTMESH_PROTECTED_FIELD_LOGIN_TOTP) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| VaultError::Crypto)?
                .as_secs();
            let totp = match auth {
                FieldAuth::Password(pw) => session.totp_code_for_access(id, now, pw)?,
                FieldAuth::Proof(proof) => session.totp_code_for_access_with_proof(id, now, proof)?,
            };
            Zeroizing::new(totp.code).as_bytes().to_vec()
        }
        (VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_PROTECTED_FIELD_CARD_NUMBER) => match auth {
            FieldAuth::Password(pw) => session.card_number_for_access(id, pw)?,
            FieldAuth::Proof(proof) => session.card_number_for_access_with_proof(id, proof)?,
        }
        .as_bytes()
        .to_vec(),
        (VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE) => {
            match auth {
                FieldAuth::Password(pw) => session.card_security_code_for_access(id, pw)?,
                FieldAuth::Proof(proof) => {
                    session.card_security_code_for_access_with_proof(id, proof)?
                }
            }
            .as_bytes()
            .to_vec()
        }
        (VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_PROTECTED_FIELD_CARD_PIN) => match auth {
            FieldAuth::Password(pw) => session.card_pin_for_access(id, pw)?,
            FieldAuth::Proof(proof) => session.card_pin_for_access_with_proof(id, proof)?,
        }
        .as_bytes()
        .to_vec(),
        (VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD) => {
            match auth {
                FieldAuth::Password(pw) => session.ssh_password_for_access(id, pw)?,
                FieldAuth::Proof(proof) => session.ssh_password_for_access_with_proof(id, proof)?,
            }
            .as_bytes()
            .to_vec()
        }
        (VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY) => {
            session.ssh_public_key_for_access(id)?.as_bytes().to_vec()
        }
        (VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY) => {
            match auth {
                FieldAuth::Password(pw) => session.ssh_private_key_for_access(id, pw)?,
                FieldAuth::Proof(proof) => {
                    session.ssh_private_key_for_access_with_proof(id, proof)?
                }
            }
            .as_bytes()
            .to_vec()
        }
        (VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE) => {
            match auth {
                FieldAuth::Password(pw) => session.ssh_key_passphrase_for_access(id, pw)?,
                FieldAuth::Proof(proof) => {
                    session.ssh_key_passphrase_for_access_with_proof(id, proof)?
                }
            }
            .as_bytes()
            .to_vec()
        }
        (VAULTMESH_ITEM_KIND_SECRET, VAULTMESH_PROTECTED_FIELD_SECRET_VALUE) => match auth {
            FieldAuth::Password(pw) => session.secret_value_for_access(id, pw)?,
            FieldAuth::Proof(proof) => session.secret_value_for_access_with_proof(id, proof)?,
        }
        .as_bytes()
        .to_vec(),
        _ => return Err(VaultError::ItemNotFound),
    };
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn protected_value(
    vault: &VaultmeshVault,
    item_kind: u32,
    protected_field: u32,
    id: Uuid,
    master_password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_protected_field(
        &vault.session,
        item_kind,
        protected_field,
        id,
        FieldAuth::Password(master_password),
    )
}

pub(crate) fn protected_values(
    vault: &VaultmeshVault,
    item_kind: u32,
    protected_fields: &[u32],
    id: Uuid,
    require_reprompt: bool,
    master_password: Option<&str>,
) -> Result<Vec<(u32, Zeroizing<String>)>, VaultError> {
    let session = &vault.session;
    if require_reprompt && master_password.is_none() {
        return Err(VaultError::MasterPasswordRequired);
    }
    let proof = master_password
        .map(|password| session.verify_master_password_for_access(password))
        .transpose()?;
    let mut values = Vec::with_capacity(protected_fields.len());
    for &field in protected_fields {
        let bytes = read_protected_field(
            session,
            item_kind,
            field,
            id,
            FieldAuth::Proof(proof.as_ref()),
        )?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| VaultError::Crypto)?;
        values.push((field, Zeroizing::new(text)));
    }
    Ok(values)
}
