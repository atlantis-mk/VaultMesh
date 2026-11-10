use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vaultmesh_ffi::DesktopRuntime;

use crate::device_credentials::ScopedCredentialStore;

pub const PREAUTH_PREVIEW_SERVICE: &str = "com.vaultmesh.desktop.browser-autofill-preview";
const PREAUTH_PREVIEW_ACCOUNT: &str = "preview-index-v1";
const PREAUTH_PREVIEW_VERSION: u32 = 1;
const MAX_PREVIEW_ITEMS_PER_KIND: usize = 500;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthLoginRecord {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    #[serde(default)]
    pub additional_urls: Vec<String>,
    #[serde(default)]
    pub has_totp_secret: bool,
    #[serde(default)]
    pub autofill_on_page_load: bool,
    #[serde(default)]
    pub master_password_reprompt: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthCardRecord {
    pub id: String,
    pub title: String,
    pub masked_number: String,
    #[serde(default)]
    pub master_password_reprompt: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthIdentityRecord {
    pub id: String,
    pub title: String,
    pub display_name: Option<String>,
    pub organization: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthSecretRecord {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub is_passkey: bool,
    pub website: Option<String>,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub environment: Option<String>,
    #[serde(default)]
    pub master_password_reprompt: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthSshRecord {
    pub id: String,
    pub title: String,
    pub host: Option<String>,
    pub username: String,
    #[serde(default)]
    pub master_password_reprompt: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserPreAuthPreviewSnapshot {
    pub version: u32,
    pub vault_path: String,
    pub vault_file_sha256: String,
    pub logins: Vec<PreAuthLoginRecord>,
    pub cards: Vec<PreAuthCardRecord>,
    pub identities: Vec<PreAuthIdentityRecord>,
    pub secrets: Vec<PreAuthSecretRecord>,
    pub ssh_credentials: Vec<PreAuthSshRecord>,
}

#[derive(Clone)]
enum StorageBackend {
    Credentials(ScopedCredentialStore),
    Memory(Arc<Mutex<Option<Vec<u8>>>>),
    Unavailable,
}

#[derive(Clone)]
pub struct BrowserPreAuthPreviewStore {
    backend: StorageBackend,
    last_synced: Arc<Mutex<Option<(String, String)>>>,
}

impl Default for BrowserPreAuthPreviewStore {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl BrowserPreAuthPreviewStore {
    pub fn new(credentials: ScopedCredentialStore) -> Self {
        Self {
            backend: StorageBackend::Credentials(credentials),
            last_synced: Arc::new(Mutex::new(None)),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            backend: StorageBackend::Memory(Arc::new(Mutex::new(None))),
            last_synced: Arc::new(Mutex::new(None)),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            backend: StorageBackend::Unavailable,
            last_synced: Arc::new(Mutex::new(None)),
        }
    }

    pub fn clear(&self) {
        if let Ok(mut last) = self.last_synced.lock() {
            *last = None;
        }
        match &self.backend {
            StorageBackend::Credentials(store) => {
                let _ = store.delete(PREAUTH_PREVIEW_ACCOUNT);
            }
            StorageBackend::Memory(memory) => {
                if let Ok(mut slot) = memory.lock() {
                    *slot = None;
                }
            }
            StorageBackend::Unavailable => {}
        }
    }

    pub fn sync_from_runtime(&self, runtime: &mut DesktopRuntime) -> Result<(), String> {
        if matches!(self.backend, StorageBackend::Unavailable) || !runtime.is_unlocked() {
            return Ok(());
        }
        let vault_path = runtime.current_path();
        let Some(vault_file_sha256) = compute_vault_sha256(&vault_path) else {
            self.clear();
            return Ok(());
        };
        let normalized_path = normalize_vault_path(&vault_path);
        if self
            .last_synced
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .as_ref()
            == Some(&(normalized_path.clone(), vault_file_sha256.clone()))
        {
            return Ok(());
        }

        let logins_raw = runtime
            .browser_login_metadata()
            .map_err(|error| error.public_message().to_owned())?;
        let cards_raw = runtime
            .execute("cards.list", json!({}))
            .map_err(|error| error.public_message().to_owned())?;
        let identities_raw = runtime
            .execute("identities.list", json!({}))
            .map_err(|error| error.public_message().to_owned())?;
        let secrets_raw = runtime
            .execute("secrets.list", json!({}))
            .map_err(|error| error.public_message().to_owned())?;
        let ssh_raw = runtime
            .execute("ssh.list", json!({}))
            .map_err(|error| error.public_message().to_owned())?;

        let snapshot = BrowserPreAuthPreviewSnapshot {
            version: PREAUTH_PREVIEW_VERSION,
            vault_path: normalized_path.clone(),
            vault_file_sha256: vault_file_sha256.clone(),
            logins: extract_logins(&logins_raw),
            cards: extract_cards(&cards_raw),
            identities: extract_identities(&identities_raw),
            secrets: extract_secrets(&secrets_raw),
            ssh_credentials: extract_ssh(&ssh_raw),
        };
        let encoded = serde_json::to_vec(&snapshot)
            .map_err(|error| format!("序列化自动填充预览索引失败: {error}"))?;
        self.write_bytes(&encoded)?;
        if let Ok(mut last) = self.last_synced.lock() {
            *last = Some((normalized_path, vault_file_sha256));
        }
        Ok(())
    }

    pub fn load_verified_snapshot(&self, vault_path: &Path) -> Option<BrowserPreAuthPreviewSnapshot> {
        let current_sha256 = compute_vault_sha256(vault_path)?;
        let expected_path = normalize_vault_path(vault_path);
        let bytes = self.read_bytes()?;
        let snapshot: BrowserPreAuthPreviewSnapshot = serde_json::from_slice(&bytes).ok()?;
        if snapshot.version != PREAUTH_PREVIEW_VERSION
            || snapshot.vault_path != expected_path
            || snapshot.vault_file_sha256 != current_sha256
        {
            return None;
        }
        Some(snapshot)
    }

    pub fn summaries_for_kind(&self, vault_path: &Path, field_kind: &str) -> Option<Value> {
        let snapshot = self.load_verified_snapshot(vault_path)?;
        let items: Vec<Value> = match field_kind {
            "login" => snapshot
                .logins
                .into_iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title,
                        "username": item.username,
                        "url": item.url,
                        "additionalUrls": item.additional_urls,
                        "hasTotpSecret": item.has_totp_secret,
                        "autofillOnPageLoad": item.autofill_on_page_load,
                        "masterPasswordReprompt": item.master_password_reprompt,
                    })
                })
                .collect(),
            "card" => snapshot
                .cards
                .into_iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title,
                        "maskedNumber": item.masked_number,
                        "masterPasswordReprompt": item.master_password_reprompt,
                    })
                })
                .collect(),
            "identity" => snapshot
                .identities
                .into_iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title,
                        "displayName": item.display_name,
                        "organization": item.organization,
                    })
                })
                .collect(),
            "secret" => snapshot
                .secrets
                .into_iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title,
                        "isPasskey": item.is_passkey,
                        "website": item.website,
                        "provider": item.provider,
                        "account": item.account,
                        "environment": item.environment,
                        "masterPasswordReprompt": item.master_password_reprompt,
                    })
                })
                .collect(),
            "ssh" => snapshot
                .ssh_credentials
                .into_iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title,
                        "host": item.host,
                        "username": item.username,
                        "masterPasswordReprompt": item.master_password_reprompt,
                    })
                })
                .collect(),
            _ => return None,
        };
        Some(Value::Array(items))
    }

    pub fn item_requires_master_password_reprompt(
        &self,
        vault_path: &Path,
        kind: &str,
        id: &Uuid,
    ) -> Option<bool> {
        let snapshot = self.load_verified_snapshot(vault_path)?;
        let id_str = id.to_string();
        match kind {
            "login" => snapshot
                .logins
                .iter()
                .find(|item| item.id == id_str)
                .map(|item| item.master_password_reprompt),
            "card" => Some(true),
            "identity" => Some(false),
            "secret" => snapshot
                .secrets
                .iter()
                .find(|item| item.id == id_str)
                .map(|item| item.master_password_reprompt),
            "ssh" => snapshot
                .ssh_credentials
                .iter()
                .find(|item| item.id == id_str)
                .map(|item| item.master_password_reprompt),
            _ => None,
        }
    }

    fn read_bytes(&self) -> Option<Vec<u8>> {
        match &self.backend {
            StorageBackend::Credentials(store) => store
                .get(PREAUTH_PREVIEW_ACCOUNT)
                .ok()
                .flatten()
                .map(|bytes| bytes.to_vec()),
            StorageBackend::Memory(memory) => memory.lock().ok().and_then(|slot| slot.clone()),
            StorageBackend::Unavailable => None,
        }
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        match &self.backend {
            StorageBackend::Credentials(store) => store.set(PREAUTH_PREVIEW_ACCOUNT, bytes),
            StorageBackend::Memory(memory) => {
                let mut slot = memory
                    .lock()
                    .map_err(|_| "内存预览索引锁不可用".to_owned())?;
                *slot = Some(bytes.to_vec());
                Ok(())
            }
            StorageBackend::Unavailable => Ok(()),
        }
    }
}

fn normalize_vault_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn compute_vault_sha256(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let digest = Sha256::digest(&bytes);
    Some(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

fn extract_logins(raw: &Value) -> Vec<PreAuthLoginRecord> {
    raw.as_array()
        .into_iter()
        .flatten()
        .take(MAX_PREVIEW_ITEMS_PER_KIND)
        .filter_map(|entry| {
            let id = entry.get("id")?.as_str()?.to_owned();
            let title = entry.get("title")?.as_str()?.to_owned();
            let username = entry
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let url = entry
                .get("url")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let additional_urls = entry
                .get("additionalUrls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .take(20)
                .map(str::to_owned)
                .collect();
            let has_totp_secret = entry
                .get("hasTotpSecret")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let autofill_on_page_load = entry
                .get("autofillOnPageLoad")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let master_password_reprompt = entry
                .get("masterPasswordReprompt")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(PreAuthLoginRecord {
                id,
                title,
                username,
                url,
                additional_urls,
                has_totp_secret,
                autofill_on_page_load,
                master_password_reprompt,
            })
        })
        .collect()
}

fn extract_cards(raw: &Value) -> Vec<PreAuthCardRecord> {
    raw.as_array()
        .into_iter()
        .flatten()
        .take(MAX_PREVIEW_ITEMS_PER_KIND)
        .filter_map(|entry| {
            let id = entry.get("id")?.as_str()?.to_owned();
            let title = entry.get("title")?.as_str()?.to_owned();
            let masked_number = entry
                .get("maskedNumber")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let master_password_reprompt = entry
                .get("masterPasswordReprompt")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(PreAuthCardRecord {
                id,
                title,
                masked_number,
                master_password_reprompt,
            })
        })
        .collect()
}

fn extract_identities(raw: &Value) -> Vec<PreAuthIdentityRecord> {
    raw.as_array()
        .into_iter()
        .flatten()
        .take(MAX_PREVIEW_ITEMS_PER_KIND)
        .filter_map(|entry| {
            let id = entry.get("id")?.as_str()?.to_owned();
            let title = entry.get("title")?.as_str()?.to_owned();
            let display_name = entry
                .get("displayName")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let organization = entry
                .get("organization")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            Some(PreAuthIdentityRecord {
                id,
                title,
                display_name,
                organization,
            })
        })
        .collect()
}

fn extract_secrets(raw: &Value) -> Vec<PreAuthSecretRecord> {
    raw.as_array()
        .into_iter()
        .flatten()
        .take(MAX_PREVIEW_ITEMS_PER_KIND)
        .filter_map(|entry| {
            let id = entry.get("id")?.as_str()?.to_owned();
            let title = entry.get("title")?.as_str()?.to_owned();
            let is_passkey = entry
                .get("isPasskey")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_passkey {
                return None;
            }
            let website = entry
                .get("website")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let provider = entry
                .get("provider")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let account = entry
                .get("account")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let environment = entry
                .get("environment")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let master_password_reprompt = entry
                .get("masterPasswordReprompt")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(PreAuthSecretRecord {
                id,
                title,
                is_passkey,
                website,
                provider,
                account,
                environment,
                master_password_reprompt,
            })
        })
        .collect()
}

fn extract_ssh(raw: &Value) -> Vec<PreAuthSshRecord> {
    raw.as_array()
        .into_iter()
        .flatten()
        .take(MAX_PREVIEW_ITEMS_PER_KIND)
        .filter_map(|entry| {
            let id = entry.get("id")?.as_str()?.to_owned();
            let title = entry.get("title")?.as_str()?.to_owned();
            let host = entry
                .get("host")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let username = entry
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let master_password_reprompt = entry
                .get("masterPasswordReprompt")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(PreAuthSshRecord {
                id,
                title,
                host,
                username,
                master_password_reprompt,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_browser_002_preauth_preview_excludes_all_secrets_and_binds_to_vault_sha256() {
        let dir = std::env::temp_dir().join(format!(
            "vaultmesh-preauth-preview-test-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        let vault_path = dir.join("vault.enc");
        let mut runtime = DesktopRuntime::new(vault_path.clone()).expect("runtime");
        runtime
            .create("correct horse battery staple".to_owned())
            .expect("create vault");
        runtime
            .execute(
                "items.add",
                json!({
                    "title": "GitHub",
                    "username": "octocat@github.com",
                    "password": "super-secret-password-value",
                    "url": "https://github.com/login",
                    "additionalUrls": ["https://gist.github.com"],
                    "totpSecret": "JBSWY3DPEHPK3PXP",
                    "notes": "private-note-should-not-leak",
                    "folder": null,
                    "favorite": true,
                    "autofillOnPageLoad": true,
                    "masterPasswordReprompt": true,
                    "customFields": [{ "label": "pin", "value": "custom-secret-value" }]
                }),
            )
            .expect("add login");

        let preview = BrowserPreAuthPreviewStore::in_memory();
        preview.sync_from_runtime(&mut runtime).expect("sync preview");
        runtime.lock();

        let bytes = preview.read_bytes().expect("stored preview bytes");
        let raw_json = String::from_utf8(bytes).expect("utf8 json");
        assert!(!raw_json.contains("super-secret-password-value"));
        assert!(!raw_json.contains("JBSWY3DPEHPK3PXP"));
        assert!(!raw_json.contains("private-note-should-not-leak"));
        assert!(!raw_json.contains("custom-secret-value"));

        let logins = preview
            .summaries_for_kind(&vault_path, "login")
            .expect("verified login summaries");
        let login = &logins.as_array().expect("array")[0];
        assert_eq!(login["title"], json!("GitHub"));
        assert_eq!(login["username"], json!("octocat@github.com"));
        assert_eq!(login["url"], json!("https://github.com/login"));
        assert_eq!(login["additionalUrls"], json!(["https://gist.github.com"]));
        assert_eq!(login["hasTotpSecret"], json!(true));
        assert_eq!(login["masterPasswordReprompt"], json!(true));

        // Tampering or external modification to vault.enc invalidates the preview until next unlock sync.
        fs::write(&vault_path, b"modified-vault-ciphertext").expect("modify vault");
        assert!(preview.summaries_for_kind(&vault_path, "login").is_none());
        let _ = fs::remove_dir_all(dir);
    }
}
