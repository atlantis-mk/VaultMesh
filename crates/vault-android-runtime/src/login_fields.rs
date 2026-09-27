//! Explicit Login editor projection and complete regular-field mutations.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vaultmesh_core::{LoginCustomField, LoginItemUpdate, NewLoginItem};
use zeroize::{Zeroize, Zeroizing};

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidLoginCustomField {
    pub label: String,
    pub value: String,
}

impl Drop for AndroidLoginCustomField {
    fn drop(&mut self) {
        self.label.zeroize();
        self.value.zeroize();
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidLoginExtras {
    pub notes: Option<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub additional_urls: Vec<String>,
    pub autofill_on_page_load: bool,
    pub master_password_reprompt: bool,
    pub custom_fields: Vec<AndroidLoginCustomField>,
}

impl Drop for AndroidLoginExtras {
    fn drop(&mut self) {
        self.notes.zeroize();
        self.folder.zeroize();
        self.additional_urls.zeroize();
    }
}

impl AndroidLoginExtras {
    fn take_custom_fields(&mut self) -> Vec<LoginCustomField> {
        std::mem::take(&mut self.custom_fields)
            .into_iter()
            .map(|mut field| LoginCustomField {
                label: std::mem::take(&mut field.label),
                value: std::mem::take(&mut field.value),
            })
            .collect()
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_login_extras_json(
    value: &str,
) -> Result<AndroidLoginExtras, AndroidRuntimeError> {
    if value.len() > 512 * 1024 {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    let extras: AndroidLoginExtras =
        serde_json::from_str(value).map_err(|_| AndroidRuntimeError::InvalidInput)?;
    if extras
        .notes
        .as_ref()
        .is_some_and(|value| value.len() > 10_000)
        || extras
            .folder
            .as_ref()
            .is_some_and(|value| value.len() > 256)
        || extras.additional_urls.len() > 20
        || extras
            .additional_urls
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 10_000)
        || extras.custom_fields.len() > 50
        || extras.custom_fields.iter().any(|field| {
            field.label.trim().is_empty() || field.label.len() > 256 || field.value.len() > 10_000
        })
    {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(extras)
}

impl AndroidVaultRuntime {
    pub fn login_editor_detail(&self, id: &str) -> Result<AndroidLoginExtras, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let mut detail = session.item_detail(id)?;
        Ok(AndroidLoginExtras {
            notes: detail.notes.take(),
            folder: detail.folder.take(),
            favorite: detail.favorite,
            additional_urls: std::mem::take(&mut detail.additional_urls),
            autofill_on_page_load: detail.autofill_on_page_load,
            master_password_reprompt: detail.master_password_reprompt,
            custom_fields: std::mem::take(&mut detail.custom_fields)
                .into_iter()
                .map(|mut field| AndroidLoginCustomField {
                    label: std::mem::take(&mut field.label),
                    value: std::mem::take(&mut field.value),
                })
                .collect(),
        })
    }

    pub fn add_login_complete(
        &mut self,
        title: String,
        username: String,
        password: String,
        url: Option<String>,
        mut extras: AndroidLoginExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        if title.trim().is_empty()
            || title.len() > 256
            || username.len() > 2048
            || password.is_empty()
            || password.len() > 10_000
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        self.mutate_and_commit(|session| {
            session.add_item(NewLoginItem {
                title,
                username,
                password: std::mem::take(&mut *password),
                url,
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                totp_secret: None,
                recovery_codes: Vec::new(),
                additional_urls: std::mem::take(&mut extras.additional_urls),
                autofill_on_page_load: extras.autofill_on_page_load,
                master_password_reprompt: extras.master_password_reprompt,
                custom_fields: extras.take_custom_fields(),
            })?;
            Ok(())
        })
    }

    pub fn update_login_complete(
        &mut self,
        id: &str,
        title: String,
        username: String,
        password: Option<String>,
        url: Option<String>,
        mut extras: AndroidLoginExtras,
    ) -> Result<(), AndroidRuntimeError> {
        let mut password = Zeroizing::new(password);
        if title.trim().is_empty()
            || title.len() > 256
            || username.len() > 2048
            || password.as_ref().is_some_and(|value| value.len() > 10_000)
        {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            session.update_item(LoginItemUpdate {
                id,
                title,
                username,
                password: std::mem::take(&mut *password),
                url,
                notes: extras.notes.take(),
                folder: extras.folder.take(),
                favorite: extras.favorite,
                totp_secret: None,
                clear_totp_secret: false,
                recovery_codes: None,
                clear_recovery_codes: false,
                additional_urls: std::mem::take(&mut extras.additional_urls),
                autofill_on_page_load: extras.autofill_on_page_load,
                master_password_reprompt: extras.master_password_reprompt,
                custom_fields: extras.take_custom_fields(),
            })?;
            Ok(())
        })
    }
}
