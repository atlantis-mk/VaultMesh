//! Fixed Android item operations. Only safe projections leave this module.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vaultmesh_core::{
    IdentityValue, NewIdentityItem, NewPaymentCardItem, NewSecretItem, NewSshCredentialItem,
    PaymentCardItemUpdate, PostalAddress, SecretItemKind, SecretItemUpdate,
    SshCredentialItemUpdate,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidCardSummary {
    pub id: String,
    pub title: String,
    pub cardholder_name: String,
    pub masked_number: String,
    pub expiration_month: u8,
    pub expiration_year: u16,
    pub has_security_code: bool,
    pub has_pin: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidCardExtras {
    pub issuer: Option<String>,
    pub network: Option<String>,
    pub billing_address: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub master_password_reprompt: bool,
}

impl Drop for AndroidCardExtras {
    fn drop(&mut self) {
        self.issuer.zeroize();
        self.network.zeroize();
        self.billing_address.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_card_extras_json(
    value: &str,
) -> Result<AndroidCardExtras, AndroidRuntimeError> {
    if value.len() > 128 * 1024 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    serde_json::from_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidSecretSummary {
    pub id: String,
    pub title: String,
    pub kind: SecretItemKind,
    pub provider: Option<String>,
    pub account: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidSecretExtras {
    pub environment: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub website: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub master_password_reprompt: bool,
}

impl Drop for AndroidSecretExtras {
    fn drop(&mut self) {
        self.environment.zeroize();
        self.scopes.zeroize();
        self.expires_at.zeroize();
        self.website.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_secret_extras_json(
    value: &str,
) -> Result<AndroidSecretExtras, AndroidRuntimeError> {
    if value.len() > 128 * 1024 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    serde_json::from_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidSshSummary {
    pub id: String,
    pub title: String,
    pub host: Option<String>,
    pub port: u16,
    pub username: String,
    pub has_password: bool,
    pub has_public_key: bool,
    pub has_private_key: bool,
    pub has_key_passphrase: bool,
    pub managed: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidSshExtras {
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub master_password_reprompt: bool,
}

impl Drop for AndroidSshExtras {
    fn drop(&mut self) {
        self.notes.zeroize();
        self.folder.zeroize();
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_ssh_extras_json(value: &str) -> Result<AndroidSshExtras, AndroidRuntimeError> {
    if value.len() > 128 * 1024 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    serde_json::from_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidIdentitySummary {
    pub id: String,
    pub title: String,
    pub display_name: Option<String>,
    pub organization: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidIdentityBasic {
    pub title: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub organization: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidIdentityContact {
    pub id: Uuid,
    pub label: String,
    pub value: String,
    pub preferred: bool,
}

impl Drop for AndroidIdentityContact {
    fn drop(&mut self) {
        self.label.zeroize();
        self.value.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidIdentityAddress {
    pub id: Uuid,
    pub label: String,
    pub address_line1: String,
    pub address_line2: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub preferred: bool,
}

impl Drop for AndroidIdentityAddress {
    fn drop(&mut self) {
        self.label.zeroize();
        self.address_line1.zeroize();
        self.address_line2.zeroize();
        self.city.zeroize();
        self.region.zeroize();
        self.postal_code.zeroize();
        self.country_code.zeroize();
        self.country.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidIdentityInput {
    pub title: String,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub birth_date: Option<String>,
    pub emails: Vec<AndroidIdentityContact>,
    pub phones: Vec<AndroidIdentityContact>,
    pub addresses: Vec<AndroidIdentityAddress>,
    pub organization: Option<String>,
    pub department: Option<String>,
    pub job_title: Option<String>,
    pub website: Option<String>,
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub favorite: bool,
}

impl Drop for AndroidIdentityInput {
    fn drop(&mut self) {
        self.title.zeroize();
        self.first_name.zeroize();
        self.middle_name.zeroize();
        self.last_name.zeroize();
        self.birth_date.zeroize();
        self.organization.zeroize();
        self.department.zeroize();
        self.job_title.zeroize();
        self.website.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
    }
}

impl AndroidIdentityInput {
    fn into_core(mut self) -> NewIdentityItem {
        NewIdentityItem {
            title: std::mem::take(&mut self.title),
            first_name: self.first_name.take(),
            middle_name: self.middle_name.take(),
            last_name: self.last_name.take(),
            birth_date: self.birth_date.take(),
            emails: std::mem::take(&mut self.emails)
                .into_iter()
                .map(|mut entry| IdentityValue {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    value: std::mem::take(&mut entry.value),
                    preferred: entry.preferred,
                })
                .collect(),
            phones: std::mem::take(&mut self.phones)
                .into_iter()
                .map(|mut entry| IdentityValue {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    value: std::mem::take(&mut entry.value),
                    preferred: entry.preferred,
                })
                .collect(),
            addresses: std::mem::take(&mut self.addresses)
                .into_iter()
                .map(|mut entry| PostalAddress {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    address_line1: std::mem::take(&mut entry.address_line1),
                    address_line2: entry.address_line2.take(),
                    city: entry.city.take(),
                    region: entry.region.take(),
                    postal_code: entry.postal_code.take(),
                    country_code: entry.country_code.take(),
                    country: entry.country.take(),
                    preferred: entry.preferred,
                })
                .collect(),
            organization: self.organization.take(),
            department: self.department.take(),
            job_title: self.job_title.take(),
            website: self.website.take(),
            notes: self.notes.take(),
            folder: self.folder.take(),
            favorite: self.favorite,
        }
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_identity_input_json(
    value: &str,
) -> Result<AndroidIdentityInput, AndroidRuntimeError> {
    if value.len() > 256 * 1024 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    let input: AndroidIdentityInput =
        serde_json::from_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)?;
    if input.emails.len() > 20 || input.phones.len() > 20 || input.addresses.len() > 20 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(input)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidOtherTrashSummary {
    pub trash_id: String,
    pub item_id: String,
    pub title: String,
    pub subtitle: String,
    pub deleted_at: u64,
}

fn parse_id(value: &str) -> Result<Uuid, AndroidRuntimeError> {
    Uuid::parse_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)
}

fn optional(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

impl AndroidVaultRuntime {
    pub fn card_editor_detail(&self, id: &str) -> Result<AndroidCardExtras, AndroidRuntimeError> {
        let id = parse_id(id)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let current = session.card_detail(id)?;
        Ok(AndroidCardExtras {
            issuer: current.issuer,
            network: current.network,
            billing_address: current.billing_address,
            notes: current.notes,
            folder: current.folder,
            favorite: current.favorite,
            master_password_reprompt: current.master_password_reprompt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_card_complete(
        &mut self,
        title: String,
        cardholder_name: String,
        card_number: String,
        expiration_month: u8,
        expiration_year: u16,
        security_code: Option<String>,
        pin: Option<String>,
        mut extras: AndroidCardExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut card_number = Zeroizing::new(card_number);
        let mut security_code = Zeroizing::new(security_code);
        let mut pin = Zeroizing::new(pin);
        if title.trim().is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        self.mutate_and_commit(|session| {
            session.add_card(NewPaymentCardItem {
                title,
                cardholder_name,
                card_number: std::mem::take(&mut *card_number),
                expiration_month,
                expiration_year,
                security_code: std::mem::take(&mut *security_code),
                pin: std::mem::take(&mut *pin),
                issuer: extras.issuer.take(),
                network: extras.network.take(),
                billing_address: extras.billing_address.take(),
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_card_complete(
        &mut self,
        id: &str,
        title: String,
        cardholder_name: String,
        card_number: Option<String>,
        expiration_month: u8,
        expiration_year: u16,
        security_code: Option<String>,
        clear_security_code: bool,
        pin: Option<String>,
        clear_pin: bool,
        mut extras: AndroidCardExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut card_number = Zeroizing::new(card_number);
        let mut security_code = Zeroizing::new(security_code);
        let mut pin = Zeroizing::new(pin);
        if title.trim().is_empty()
            || (security_code.is_some() && clear_security_code)
            || (pin.is_some() && clear_pin)
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            session.update_card(PaymentCardItemUpdate {
                id,
                title,
                cardholder_name,
                card_number: std::mem::take(&mut *card_number),
                expiration_month,
                expiration_year,
                security_code: std::mem::take(&mut *security_code),
                clear_security_code,
                pin: std::mem::take(&mut *pin),
                clear_pin,
                issuer: extras.issuer.take(),
                network: extras.network.take(),
                billing_address: extras.billing_address.take(),
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn list_cards(&self) -> Result<Vec<AndroidCardSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_cards()?
            .into_iter()
            .map(|item| AndroidCardSummary {
                id: item.id.to_string(),
                title: item.title,
                cardholder_name: item.cardholder_name,
                masked_number: item.masked_number,
                expiration_month: item.expiration_month,
                expiration_year: item.expiration_year,
                has_security_code: item.has_security_code,
                has_pin: item.has_pin,
            })
            .collect())
    }

    pub fn add_card(
        &mut self,
        title: String,
        cardholder_name: String,
        card_number: String,
        expiration_month: u8,
        expiration_year: u16,
        security_code: Option<String>,
        pin: Option<String>,
    ) -> Result<(), AndroidRuntimeError> {
        let mut card_number = Zeroizing::new(card_number);
        let mut security_code = Zeroizing::new(security_code);
        let mut pin = Zeroizing::new(pin);
        if title.trim().is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        self.mutate_and_commit(|session| {
            session.add_card(NewPaymentCardItem {
                title,
                cardholder_name,
                card_number: std::mem::take(&mut *card_number),
                expiration_month,
                expiration_year,
                security_code: std::mem::take(&mut *security_code),
                pin: std::mem::take(&mut *pin),
                issuer: None,
                network: None,
                billing_address: None,
                notes: None,
                folder: None,
                favorite: false,
                master_password_reprompt: false,
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_card(
        &mut self,
        id: &str,
        title: String,
        cardholder_name: String,
        card_number: Option<String>,
        expiration_month: u8,
        expiration_year: u16,
        security_code: Option<String>,
        clear_security_code: bool,
        pin: Option<String>,
        clear_pin: bool,
    ) -> Result<(), AndroidRuntimeError> {
        let mut card_number = Zeroizing::new(card_number);
        let mut security_code = Zeroizing::new(security_code);
        let mut pin = Zeroizing::new(pin);
        if title.trim().is_empty()
            || (security_code.is_some() && clear_security_code)
            || (pin.is_some() && clear_pin)
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            let current = session.card_detail(id)?;
            session.update_card(PaymentCardItemUpdate {
                id,
                title,
                cardholder_name,
                card_number: std::mem::take(&mut *card_number),
                expiration_month,
                expiration_year,
                security_code: std::mem::take(&mut *security_code),
                clear_security_code,
                pin: std::mem::take(&mut *pin),
                clear_pin,
                issuer: current.issuer,
                network: current.network,
                billing_address: current.billing_address,
                notes: current.notes,
                folder: current.folder,
                favorite: current.favorite,
                master_password_reprompt: current.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn delete_card(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            session.delete_card(id)?;
            Ok(())
        })
    }

    pub fn list_card_trash(&self) -> Result<Vec<AndroidOtherTrashSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_card_trash()?
            .into_iter()
            .map(|item| AndroidOtherTrashSummary {
                trash_id: item.trash_id.to_string(),
                item_id: item.item_id.to_string(),
                title: item.title,
                subtitle: item.masked_number,
                deleted_at: item.deleted_at,
            })
            .collect())
    }

    pub fn restore_card(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.restore_card_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn purge_card(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.purge_card_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn empty_card_trash(&mut self) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.empty_card_trash()?;
            Ok(())
        })
    }

    pub fn list_secrets(&self) -> Result<Vec<AndroidSecretSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_secrets()?
            .into_iter()
            .filter(|item| !item.is_passkey)
            .map(|item| AndroidSecretSummary {
                id: item.id.to_string(),
                title: item.title,
                kind: item.kind,
                provider: item.provider,
                account: item.account,
            })
            .collect())
    }

    pub fn secret_editor_detail(
        &self,
        id: &str,
    ) -> Result<AndroidSecretExtras, AndroidRuntimeError> {
        let id = parse_id(id)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let current = session.secret_detail(id)?;
        if current.is_passkey {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        Ok(AndroidSecretExtras {
            environment: current.environment,
            scopes: current.scopes,
            expires_at: current.expires_at,
            website: current.website,
            notes: current.notes,
            folder: current.folder,
            favorite: current.favorite,
            master_password_reprompt: current.master_password_reprompt,
        })
    }

    pub fn add_secret_complete(
        &mut self,
        title: String,
        kind: &str,
        provider: String,
        account: String,
        secret: String,
        mut extras: AndroidSecretExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut secret = Zeroizing::new(secret);
        let kind: SecretItemKind = serde_json::from_value(serde_json::Value::String(kind.into()))
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.add_secret(NewSecretItem {
                title,
                kind,
                provider: optional(provider),
                account: optional(account),
                secret: std::mem::take(&mut *secret),
                environment: extras.environment.take(),
                scopes: std::mem::take(&mut extras.scopes),
                expires_at: extras.expires_at.take(),
                website: extras.website.take(),
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn update_secret_complete(
        &mut self,
        id: &str,
        title: String,
        provider: String,
        account: String,
        secret: Option<String>,
        mut extras: AndroidSecretExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut secret = Zeroizing::new(secret);
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            let current = session.secret_detail(id)?;
            if current.is_passkey {
                return Err(vaultmesh_core::VaultError::InvalidSecretItem);
            }
            session.update_secret(SecretItemUpdate {
                id,
                title,
                kind: current.kind,
                provider: optional(provider),
                account: optional(account),
                secret: std::mem::take(&mut *secret),
                environment: extras.environment.take(),
                scopes: std::mem::take(&mut extras.scopes),
                expires_at: extras.expires_at.take(),
                website: extras.website.take(),
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn add_secret(
        &mut self,
        title: String,
        kind: &str,
        provider: String,
        account: String,
        secret: String,
    ) -> Result<(), AndroidRuntimeError> {
        let mut secret = Zeroizing::new(secret);
        let kind: SecretItemKind = serde_json::from_value(serde_json::Value::String(kind.into()))
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.add_secret(NewSecretItem {
                title,
                kind,
                provider: optional(provider),
                account: optional(account),
                secret: std::mem::take(&mut *secret),
                environment: None,
                scopes: Vec::new(),
                expires_at: None,
                website: None,
                notes: None,
                folder: None,
                favorite: false,
                master_password_reprompt: false,
            })?;
            Ok(())
        })
    }

    pub fn update_secret(
        &mut self,
        id: &str,
        title: String,
        provider: String,
        account: String,
        secret: Option<String>,
    ) -> Result<(), AndroidRuntimeError> {
        let mut secret = Zeroizing::new(secret);
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            let current = session.secret_detail(id)?;
            if current.is_passkey {
                return Err(vaultmesh_core::VaultError::InvalidSecretItem);
            }
            let snapshot = session.payload_snapshot()?;
            let folder = snapshot
                .secrets
                .iter()
                .find(|item| item.id == id)
                .and_then(|item| item.folder.clone());
            session.update_secret(SecretItemUpdate {
                id,
                title,
                kind: current.kind,
                provider: optional(provider),
                account: optional(account),
                secret: std::mem::take(&mut *secret),
                environment: current.environment,
                scopes: current.scopes,
                expires_at: current.expires_at,
                website: current.website,
                notes: current.notes,
                folder,
                favorite: current.favorite,
                master_password_reprompt: current.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn delete_secret(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            if session.secret_detail(id)?.is_passkey {
                return Err(vaultmesh_core::VaultError::InvalidSecretItem);
            }
            session.delete_secret(id)?;
            Ok(())
        })
    }

    pub fn list_ssh(&self) -> Result<Vec<AndroidSshSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_ssh_credentials()?
            .into_iter()
            .map(|item| AndroidSshSummary {
                id: item.id.to_string(),
                title: item.title,
                host: item.host,
                port: item.port,
                username: item.username,
                has_password: item.has_password,
                has_public_key: item.has_public_key,
                has_private_key: item.has_private_key,
                has_key_passphrase: item.has_key_passphrase,
                managed: item.managed_ssh_alias.is_some(),
            })
            .collect())
    }

    pub fn ssh_editor_detail(&self, id: &str) -> Result<AndroidSshExtras, AndroidRuntimeError> {
        let id = parse_id(id)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let current = session.ssh_credential_detail(id)?;
        if current.managed_ssh_alias.is_some() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        Ok(AndroidSshExtras {
            notes: current.notes,
            folder: current.folder,
            favorite: current.favorite,
            master_password_reprompt: current.master_password_reprompt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_ssh_complete(
        &mut self,
        title: String,
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        key_passphrase: Option<String>,
        mut extras: AndroidSshExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        let mut public_key = Zeroizing::new(public_key);
        let mut private_key = Zeroizing::new(private_key);
        let mut key_passphrase = Zeroizing::new(key_passphrase);
        self.mutate_and_commit(|session| {
            session.add_ssh_credential(NewSshCredentialItem {
                title,
                host: optional(host),
                port,
                username,
                password: std::mem::take(&mut *password),
                public_key: std::mem::take(&mut *public_key),
                private_key: std::mem::take(&mut *private_key),
                key_passphrase: std::mem::take(&mut *key_passphrase),
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_ssh_complete(
        &mut self,
        id: &str,
        title: String,
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        clear_password: bool,
        public_key: Option<String>,
        clear_public_key: bool,
        private_key: Option<String>,
        clear_private_key: bool,
        key_passphrase: Option<String>,
        clear_key_passphrase: bool,
        mut extras: AndroidSshExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        let mut public_key = Zeroizing::new(public_key);
        let mut private_key = Zeroizing::new(private_key);
        let mut key_passphrase = Zeroizing::new(key_passphrase);
        if (password.is_some() && clear_password)
            || (public_key.is_some() && clear_public_key)
            || (private_key.is_some() && clear_private_key)
            || (key_passphrase.is_some() && clear_key_passphrase)
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            if session
                .ssh_credential_detail(id)?
                .managed_ssh_alias
                .is_some()
            {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            session.update_ssh_credential(SshCredentialItemUpdate {
                id,
                title,
                host: optional(host),
                port,
                username,
                password: std::mem::take(&mut *password),
                clear_password,
                public_key: std::mem::take(&mut *public_key),
                clear_public_key,
                private_key: std::mem::take(&mut *private_key),
                clear_private_key,
                key_passphrase: std::mem::take(&mut *key_passphrase),
                clear_key_passphrase,
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                master_password_reprompt: extras.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_ssh(
        &mut self,
        title: String,
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        key_passphrase: Option<String>,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        let mut public_key = Zeroizing::new(public_key);
        let mut private_key = Zeroizing::new(private_key);
        let mut key_passphrase = Zeroizing::new(key_passphrase);
        self.mutate_and_commit(|session| {
            session.add_ssh_credential(NewSshCredentialItem {
                title,
                host: optional(host),
                port,
                username,
                password: std::mem::take(&mut *password),
                public_key: std::mem::take(&mut *public_key),
                private_key: std::mem::take(&mut *private_key),
                key_passphrase: std::mem::take(&mut *key_passphrase),
                notes: None,
                folder: None,
                favorite: false,
                master_password_reprompt: false,
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_ssh(
        &mut self,
        id: &str,
        title: String,
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        clear_password: bool,
        public_key: Option<String>,
        clear_public_key: bool,
        private_key: Option<String>,
        clear_private_key: bool,
        key_passphrase: Option<String>,
        clear_key_passphrase: bool,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        let mut public_key = Zeroizing::new(public_key);
        let mut private_key = Zeroizing::new(private_key);
        let mut key_passphrase = Zeroizing::new(key_passphrase);
        if (password.is_some() && clear_password)
            || (public_key.is_some() && clear_public_key)
            || (private_key.is_some() && clear_private_key)
            || (key_passphrase.is_some() && clear_key_passphrase)
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            let current = session.ssh_credential_detail(id)?;
            if current.managed_ssh_alias.is_some() {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            session.update_ssh_credential(SshCredentialItemUpdate {
                id,
                title,
                host: optional(host),
                port,
                username,
                password: std::mem::take(&mut *password),
                clear_password,
                public_key: std::mem::take(&mut *public_key),
                clear_public_key,
                private_key: std::mem::take(&mut *private_key),
                clear_private_key,
                key_passphrase: std::mem::take(&mut *key_passphrase),
                clear_key_passphrase,
                notes: current.notes,
                folder: current.folder,
                favorite: current.favorite,
                master_password_reprompt: current.master_password_reprompt,
            })?;
            Ok(())
        })
    }

    pub fn delete_ssh(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            if session
                .ssh_credential_detail(id)?
                .managed_ssh_alias
                .is_some()
            {
                return Err(vaultmesh_core::VaultError::InvalidSshCredential);
            }
            session.delete_ssh_credential(id)?;
            Ok(())
        })
    }

    pub fn list_ssh_trash(&self) -> Result<Vec<AndroidOtherTrashSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_ssh_trash()?
            .into_iter()
            .map(|item| AndroidOtherTrashSummary {
                trash_id: item.trash_id.to_string(),
                item_id: item.item_id.to_string(),
                title: item.title,
                subtitle: item.host.unwrap_or_default(),
                deleted_at: item.deleted_at,
            })
            .collect())
    }

    pub fn restore_ssh(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.restore_ssh_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn purge_ssh(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.purge_ssh_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn empty_ssh_trash(&mut self) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.empty_ssh_trash()?;
            Ok(())
        })
    }

    pub fn list_identities(&self) -> Result<Vec<AndroidIdentitySummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_identities()?
            .into_iter()
            .map(|item| AndroidIdentitySummary {
                id: item.id.to_string(),
                title: item.title,
                display_name: item.display_name,
                organization: item.organization,
            })
            .collect())
    }

    pub fn identity_basic(&self, id: &str) -> Result<AndroidIdentityBasic, AndroidRuntimeError> {
        let id = parse_id(id)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let item = session.identity_detail(id)?;
        Ok(AndroidIdentityBasic {
            title: item.title,
            first_name: item.first_name,
            last_name: item.last_name,
            organization: item.organization,
        })
    }

    pub fn identity_editor_detail(
        &self,
        id: &str,
    ) -> Result<AndroidIdentityInput, AndroidRuntimeError> {
        let id = parse_id(id)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let item = session.identity_detail(id)?;
        Ok(AndroidIdentityInput {
            title: item.title,
            first_name: item.first_name,
            middle_name: item.middle_name,
            last_name: item.last_name,
            birth_date: item.birth_date,
            emails: item
                .emails
                .into_iter()
                .map(|mut entry| AndroidIdentityContact {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    value: std::mem::take(&mut entry.value),
                    preferred: entry.preferred,
                })
                .collect(),
            phones: item
                .phones
                .into_iter()
                .map(|mut entry| AndroidIdentityContact {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    value: std::mem::take(&mut entry.value),
                    preferred: entry.preferred,
                })
                .collect(),
            addresses: item
                .addresses
                .into_iter()
                .map(|mut entry| AndroidIdentityAddress {
                    id: entry.id,
                    label: std::mem::take(&mut entry.label),
                    address_line1: std::mem::take(&mut entry.address_line1),
                    address_line2: entry.address_line2.take(),
                    city: entry.city.take(),
                    region: entry.region.take(),
                    postal_code: entry.postal_code.take(),
                    country_code: entry.country_code.take(),
                    country: entry.country.take(),
                    preferred: entry.preferred,
                })
                .collect(),
            organization: item.organization,
            department: item.department,
            job_title: item.job_title,
            website: item.website,
            notes: item.notes,
            folder: item.folder,
            favorite: item.favorite,
        })
    }

    pub fn add_identity_complete(
        &mut self,
        input: AndroidIdentityInput,
    ) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.add_identity(input.into_core())?;
            Ok(())
        })
    }

    pub fn update_identity_complete(
        &mut self,
        id: &str,
        input: AndroidIdentityInput,
    ) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            session.update_identity(input.into_core(), id)?;
            Ok(())
        })
    }

    pub fn add_identity(
        &mut self,
        title: String,
        first_name: String,
        last_name: String,
        organization: String,
    ) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.add_identity(NewIdentityItem {
                title,
                first_name: optional(first_name),
                middle_name: None,
                last_name: optional(last_name),
                birth_date: None,
                emails: Vec::new(),
                phones: Vec::new(),
                addresses: Vec::new(),
                organization: optional(organization),
                department: None,
                job_title: None,
                website: None,
                notes: None,
                folder: None,
                favorite: false,
            })?;
            Ok(())
        })
    }

    pub fn update_identity(
        &mut self,
        id: &str,
        title: String,
        first_name: String,
        last_name: String,
        organization: String,
    ) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            let current = session.identity_detail(id)?;
            session.update_identity(
                NewIdentityItem {
                    title,
                    first_name: optional(first_name),
                    middle_name: current.middle_name,
                    last_name: optional(last_name),
                    birth_date: current.birth_date,
                    emails: current.emails,
                    phones: current.phones,
                    addresses: current.addresses,
                    organization: optional(organization),
                    department: current.department,
                    job_title: current.job_title,
                    website: current.website,
                    notes: current.notes,
                    folder: current.folder,
                    favorite: current.favorite,
                },
                id,
            )?;
            Ok(())
        })
    }

    pub fn delete_identity(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        let id = parse_id(id)?;
        self.mutate_and_commit(|session| {
            session.delete_identity(id)?;
            Ok(())
        })
    }

    pub fn list_identity_trash(
        &self,
    ) -> Result<Vec<AndroidOtherTrashSummary>, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        Ok(session
            .list_identity_trash()?
            .into_iter()
            .map(|item| AndroidOtherTrashSummary {
                trash_id: item.trash_id.to_string(),
                item_id: item.item_id.to_string(),
                title: item.title,
                subtitle: item.display_name.unwrap_or_default(),
                deleted_at: item.deleted_at,
            })
            .collect())
    }

    pub fn restore_identity(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.restore_identity_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn purge_identity(&mut self, trash_id: &str) -> Result<(), AndroidRuntimeError> {
        let trash_id = parse_id(trash_id)?;
        self.mutate_and_commit(|session| {
            session.purge_identity_trash(trash_id)?;
            Ok(())
        })
    }

    pub fn empty_identity_trash(&mut self) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|session| {
            session.empty_identity_trash()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use vaultmesh_core::IdentityValue;

    fn test_runtime(name: &str) -> (AndroidVaultRuntime, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("vaultmesh-android-{name}-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&path).unwrap();
        runtime.create("test-master-password").unwrap();
        (runtime, path)
    }

    #[test]
    fn card_update_preserves_number_and_card_trash_is_persistent() {
        let (mut runtime, path) = test_runtime("card");
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
        let card = runtime.list_cards().unwrap().pop().unwrap();
        assert!(
            !serde_json::to_string(&card)
                .unwrap()
                .contains("4111111111111111")
        );
        runtime
            .update_card(
                &card.id,
                "Renamed".into(),
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
        let id = Uuid::parse_str(&card.id).unwrap();
        assert_eq!(
            runtime
                .session
                .as_ref()
                .unwrap()
                .card_number_for_access(id, None)
                .unwrap(),
            "4111111111111111"
        );
        runtime.delete_card(&card.id).unwrap();
        let trash = runtime.list_card_trash().unwrap().pop().unwrap();
        runtime.lock();
        runtime.unlock("test-master-password").unwrap();
        assert_eq!(runtime.list_card_trash().unwrap().len(), 1);
        runtime.restore_card(&trash.trash_id).unwrap();
        assert_eq!(runtime.list_cards().unwrap()[0].title, "Renamed");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn complete_card_metadata_is_explicit_and_commits_with_the_card() {
        let (mut runtime, path) = test_runtime("card-complete");
        assert!(parse_card_extras_json("{\"issuer\":\"Synthetic\",\"unexpected\":1}").is_err());
        runtime
            .add_card_complete(
                "Card".into(),
                "Holder".into(),
                "4111111111111111".into(),
                12,
                2030,
                Some("123".into()),
                None,
                AndroidCardExtras {
                    issuer: Some("Issuer".into()),
                    network: Some("Visa".into()),
                    billing_address: Some("Synthetic Street".into()),
                    notes: Some("Test note".into()),
                    folder: Some("Personal".into()),
                    favorite: true,
                    master_password_reprompt: true,
                },
            )
            .unwrap();
        let card = runtime.list_cards().unwrap().pop().unwrap();
        let detail = runtime.card_editor_detail(&card.id).unwrap();
        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("Synthetic Street"));
        assert!(!json.contains("4111111111111111"));
        assert!(!json.contains("123"));
        assert!(detail.favorite);

        let before = fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap();
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.update_card_complete(
                &card.id,
                "Changed".into(),
                "Holder".into(),
                None,
                12,
                2030,
                None,
                false,
                None,
                false,
                AndroidCardExtras::default(),
            ),
            Err(AndroidRuntimeError::Io)
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);
        assert_eq!(
            runtime
                .card_editor_detail(&card.id)
                .unwrap()
                .issuer
                .as_deref(),
            Some("Issuer")
        );

        let mut replacement = AndroidCardExtras::default();
        replacement.issuer = Some("Other".into());
        runtime
            .update_card_complete(
                &card.id,
                "Changed".into(),
                "Holder".into(),
                None,
                12,
                2030,
                None,
                false,
                None,
                false,
                replacement,
            )
            .unwrap();
        runtime.lock();
        runtime.unlock("test-master-password").unwrap();
        assert_eq!(runtime.list_cards().unwrap()[0].title, "Changed");
        assert_eq!(
            runtime
                .card_editor_detail(&card.id)
                .unwrap()
                .issuer
                .as_deref(),
            Some("Other")
        );
        assert_eq!(
            runtime
                .copy_card_number(&card.id, "test-master-password")
                .unwrap()
                .as_str(),
            "4111111111111111"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn card_write_failure_rolls_back_memory_and_file() {
        let (mut runtime, path) = test_runtime("card-rollback");
        let before = fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap();
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .add_card(
                    "Card".into(),
                    "Holder".into(),
                    "4111111111111111".into(),
                    12,
                    2030,
                    None,
                    None
                )
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert!(runtime.list_cards().unwrap().is_empty());
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn complete_secret_metadata_preserves_value_and_rejects_invalid_updates() {
        let (mut runtime, path) = test_runtime("secret-complete");
        assert!(parse_secret_extras_json("{\"scopes\":[],\"unknown\":1}").is_err());
        let mut extras = AndroidSecretExtras::default();
        extras.environment = Some("test".into());
        extras.scopes = vec!["read".into(), "write".into()];
        extras.website = Some("https://example.test".into());
        extras.notes = Some("Synthetic note".into());
        extras.favorite = true;
        runtime
            .add_secret_complete(
                "Token".into(),
                "access-token",
                "Provider".into(),
                "Account".into(),
                "synthetic-secret".into(),
                extras,
            )
            .unwrap();
        let id = runtime.list_secrets().unwrap()[0].id.clone();
        let detail = runtime.secret_editor_detail(&id).unwrap();
        assert_eq!(detail.scopes, vec!["read", "write"]);
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("synthetic-secret")
        );

        let before = fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap();
        let mut bad = AndroidSecretExtras::default();
        bad.website = Some("ftp://bad.test".into());
        assert_eq!(
            runtime.update_secret_complete(
                &id,
                "Changed".into(),
                "Provider".into(),
                "Account".into(),
                None,
                bad,
            ),
            Err(AndroidRuntimeError::InvalidInput)
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);

        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.update_secret_complete(
                &id,
                "Changed".into(),
                "Provider".into(),
                "Account".into(),
                None,
                AndroidSecretExtras::default(),
            ),
            Err(AndroidRuntimeError::Io)
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);

        let mut replacement = AndroidSecretExtras::default();
        replacement.scopes = vec!["read".into()];
        runtime
            .update_secret_complete(
                &id,
                "Changed".into(),
                "Provider".into(),
                "Account".into(),
                None,
                replacement,
            )
            .unwrap();
        runtime.lock();
        runtime.unlock("test-master-password").unwrap();
        assert_eq!(runtime.list_secrets().unwrap()[0].title, "Changed");
        assert_eq!(
            runtime.secret_editor_detail(&id).unwrap().scopes,
            vec!["read"]
        );
        assert_eq!(
            runtime
                .copy_secret_value(&id, "test-master-password")
                .unwrap()
                .as_str(),
            "synthetic-secret"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn ssh_update_preserves_password_and_trash_restore() {
        let (mut runtime, path) = test_runtime("ssh");
        runtime
            .add_ssh(
                "Server".into(),
                "host.test".into(),
                22,
                "alice".into(),
                Some("synthetic-password".into()),
                None,
                None,
                None,
            )
            .unwrap();
        let ssh = runtime.list_ssh().unwrap().pop().unwrap();
        assert!(ssh.has_password);
        assert!(
            !serde_json::to_string(&ssh)
                .unwrap()
                .contains("synthetic-password")
        );
        runtime
            .update_ssh(
                &ssh.id,
                "Renamed".into(),
                "host.test".into(),
                22,
                "alice".into(),
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
        let id = Uuid::parse_str(&ssh.id).unwrap();
        assert_eq!(
            runtime
                .session
                .as_ref()
                .unwrap()
                .ssh_password_for_access(id, None)
                .unwrap(),
            "synthetic-password"
        );
        runtime.delete_ssh(&ssh.id).unwrap();
        let trash = runtime.list_ssh_trash().unwrap().pop().unwrap();
        runtime.restore_ssh(&trash.trash_id).unwrap();
        assert_eq!(runtime.list_ssh().unwrap()[0].title, "Renamed");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn complete_ssh_metadata_preserves_authentication_and_rolls_back() {
        let (mut runtime, path) = test_runtime("ssh-complete");
        assert!(parse_ssh_extras_json("{\"notes\":null,\"unknown\":1}").is_err());
        assert!(parse_ssh_extras_json(&" ".repeat(128 * 1024 + 1)).is_err());
        let mut extras = AndroidSshExtras::default();
        extras.notes = Some("Synthetic note".into());
        extras.folder = Some("Infrastructure".into());
        extras.favorite = true;
        extras.master_password_reprompt = true;
        runtime
            .add_ssh_complete(
                "Server".into(),
                "host.test".into(),
                22,
                "alice".into(),
                Some("synthetic-password".into()),
                None,
                None,
                None,
                extras,
            )
            .unwrap();
        let id = runtime.list_ssh().unwrap()[0].id.clone();
        let detail = runtime.ssh_editor_detail(&id).unwrap();
        assert_eq!(detail.notes.as_deref(), Some("Synthetic note"));
        assert_eq!(detail.folder.as_deref(), Some("Infrastructure"));
        assert!(detail.favorite && detail.master_password_reprompt);
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("synthetic-password")
        );

        let before = fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap();
        assert_eq!(
            runtime
                .update_ssh_complete(
                    &id,
                    "Invalid".into(),
                    "host.test".into(),
                    22,
                    "alice".into(),
                    Some("replacement".into()),
                    true,
                    None,
                    false,
                    None,
                    false,
                    None,
                    false,
                    AndroidSshExtras::default(),
                )
                .unwrap_err(),
            AndroidRuntimeError::InvalidInput
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .update_ssh_complete(
                    &id,
                    "Changed".into(),
                    "host.test".into(),
                    22,
                    "alice".into(),
                    None,
                    false,
                    None,
                    false,
                    None,
                    false,
                    None,
                    false,
                    AndroidSshExtras::default(),
                )
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(runtime.list_ssh().unwrap()[0].title, "Server");
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);

        let mut replacement = AndroidSshExtras::default();
        replacement.notes = Some("Updated note".into());
        runtime
            .update_ssh_complete(
                &id,
                "Changed".into(),
                "host.test".into(),
                22,
                "alice".into(),
                None,
                false,
                None,
                false,
                None,
                false,
                None,
                false,
                replacement,
            )
            .unwrap();
        runtime.lock();
        runtime.unlock("test-master-password").unwrap();
        assert_eq!(
            runtime.ssh_editor_detail(&id).unwrap().notes.as_deref(),
            Some("Updated note")
        );
        assert_eq!(
            runtime
                .copy_ssh_password(&id, "test-master-password")
                .unwrap()
                .as_str(),
            "synthetic-password"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn identity_basic_edit_preserves_structured_values_and_trash() {
        let (mut runtime, path) = test_runtime("identity");
        let email_id = Uuid::new_v4();
        runtime
            .mutate_and_commit(|session| {
                session.add_identity(NewIdentityItem {
                    title: "Identity".into(),
                    first_name: Some("Alice".into()),
                    middle_name: None,
                    last_name: Some("Example".into()),
                    birth_date: None,
                    emails: vec![IdentityValue {
                        id: email_id,
                        label: "work".into(),
                        value: "alice@example.test".into(),
                        preferred: true,
                    }],
                    phones: Vec::new(),
                    addresses: Vec::new(),
                    organization: None,
                    department: None,
                    job_title: None,
                    website: None,
                    notes: None,
                    folder: None,
                    favorite: false,
                })?;
                Ok(())
            })
            .unwrap();
        let id = runtime.list_identities().unwrap()[0].id.clone();
        runtime
            .update_identity(
                &id,
                "Renamed".into(),
                "Alice".into(),
                "Example".into(),
                "Org".into(),
            )
            .unwrap();
        let detail = runtime
            .session
            .as_ref()
            .unwrap()
            .identity_detail(Uuid::parse_str(&id).unwrap())
            .unwrap();
        assert_eq!(detail.emails[0].id, email_id);
        assert_eq!(detail.emails[0].value, "alice@example.test");
        runtime.delete_identity(&id).unwrap();
        let trash = runtime.list_identity_trash().unwrap().pop().unwrap();
        runtime.restore_identity(&trash.trash_id).unwrap();
        assert_eq!(
            runtime.list_identities().unwrap()[0]
                .organization
                .as_deref(),
            Some("Org")
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn complete_identity_edit_preserves_child_ids_and_rolls_back() {
        let (mut runtime, path) = test_runtime("identity-complete");
        let email_id = Uuid::new_v4();
        let address_id = Uuid::new_v4();
        let input = serde_json::json!({
            "title": "Synthetic identity", "firstName": "Ada", "middleName": null,
            "lastName": "Test", "birthDate": "1990-01-02",
            "emails": [{"id": email_id, "label": "work", "value": "ada@example.test", "preferred": true}],
            "phones": [],
            "addresses": [{"id": address_id, "label": "home", "addressLine1": "1 Test Street",
                "addressLine2": null, "city": "Test City", "region": null, "postalCode": null,
                "countryCode": "US", "country": null, "preferred": true}],
            "organization": "Example", "department": null, "jobTitle": null,
            "website": "https://example.test", "notes": "Synthetic note",
            "folder": "People", "favorite": true,
        }).to_string();
        assert!(
            parse_identity_input_json(
                &input.replace("\"favorite\":true", "\"favorite\":true,\"unexpected\":1")
            )
            .is_err()
        );
        assert!(parse_identity_input_json(&" ".repeat(256 * 1024 + 1)).is_err());
        runtime
            .add_identity_complete(parse_identity_input_json(&input).unwrap())
            .unwrap();
        let id = runtime.list_identities().unwrap()[0].id.clone();
        let detail = runtime.identity_editor_detail(&id).unwrap();
        assert_eq!(detail.emails[0].id, email_id);
        assert_eq!(detail.addresses[0].id, address_id);
        assert_eq!(detail.middle_name, None);
        assert_eq!(detail.folder.as_deref(), Some("People"));

        let before = fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap();
        let invalid = input.replace("ada@example.test", "invalid-email");
        assert!(
            runtime
                .update_identity_complete(&id, parse_identity_input_json(&invalid).unwrap())
                .is_err()
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);
        crate::FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .update_identity_complete(&id, parse_identity_input_json(&input).unwrap())
                .unwrap_err(),
            AndroidRuntimeError::Io
        );
        assert_eq!(fs::read(path.join(crate::VAULT_FILE_NAME)).unwrap(), before);

        let updated = input.replace("Synthetic note", "Updated note");
        runtime
            .update_identity_complete(&id, parse_identity_input_json(&updated).unwrap())
            .unwrap();
        runtime.lock();
        runtime.unlock("test-master-password").unwrap();
        let persisted = runtime.identity_editor_detail(&id).unwrap();
        assert_eq!(persisted.notes.as_deref(), Some("Updated note"));
        assert_eq!(persisted.emails[0].id, email_id);
        assert_eq!(persisted.addresses[0].id, address_id);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn secret_edit_preserves_value_and_passkey_records_are_inaccessible() {
        let (mut runtime, path) = test_runtime("secret");
        runtime
            .add_secret(
                "API token".into(),
                "api-key",
                "Provider".into(),
                "account".into(),
                "synthetic-token".into(),
            )
            .unwrap();
        let secret = runtime.list_secrets().unwrap().pop().unwrap();
        assert!(
            !serde_json::to_string(&secret)
                .unwrap()
                .contains("synthetic-token")
        );
        runtime
            .update_secret(
                &secret.id,
                "Renamed".into(),
                "Provider".into(),
                "account".into(),
                None,
            )
            .unwrap();
        let id = Uuid::parse_str(&secret.id).unwrap();
        assert_eq!(
            runtime
                .session
                .as_ref()
                .unwrap()
                .secret_value_for_access(id, None)
                .unwrap()
                .as_str(),
            "synthetic-token"
        );
        runtime.delete_secret(&secret.id).unwrap();
        assert!(runtime.list_secrets().unwrap().is_empty());
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
        assert!(runtime.list_secrets().unwrap().is_empty());
        assert_eq!(
            runtime.delete_secret(&passkey.id.to_string()).unwrap_err(),
            AndroidRuntimeError::InvalidInput
        );
        fs::remove_dir_all(path).unwrap();
    }
}
