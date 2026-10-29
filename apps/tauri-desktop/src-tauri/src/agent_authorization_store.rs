use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use atomic_write_file::OpenOptions as AtomicOpenOptions;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::agent_broker::{PermissionEffect, PermissionScope};

const STORE_VERSION: u8 = 2;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_STORE_BYTES: u64 = 512 * 1024;
const MAX_RULES: usize = 500;
const KEYRING_SERVICE: &str = "com.vaultmesh.desktop.agent-authorization";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentAuthorizationRule {
    pub id: Uuid,
    pub client_key: String,
    pub account_ref: String,
    pub target_digest: String,
    pub tool: String,
    pub scope: PermissionScope,
    pub effect: PermissionEffect,
    pub parameters_digest: Option<String>,
    pub catalog_revision: Option<String>,
    #[serde(default)]
    pub http_method: Option<String>,
    #[serde(default)]
    pub path_pattern: Option<String>,
    #[serde(default)]
    pub matcher_revision: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

pub struct AgentAuthorizationMatch<'a> {
    pub user_id: &'a str,
    pub client_key: &'a str,
    pub account_ref: &'a str,
    pub target_digest: &'a str,
    pub tool: &'a str,
    pub parameters_digest: &'a str,
    pub safe: bool,
    pub catalog_revision: &'a str,
    pub http_method: Option<&'a str>,
    pub http_path: Option<&'a str>,
}

impl AgentAuthorizationRule {
    fn valid(&self) -> bool {
        !self.client_key.is_empty()
            && self.client_key.len() <= 128
            && Uuid::parse_str(&self.account_ref).is_ok()
            && valid_digest(&self.target_digest)
            && self.tool.starts_with("vaultmesh_")
            && self.tool.len() <= 128
            && match self.scope {
                PermissionScope::Exact => {
                    self.parameters_digest.as_deref().is_some_and(valid_digest)
                        && self.catalog_revision.is_none()
                        && self.http_method.is_none()
                        && self.path_pattern.is_none()
                        && self.matcher_revision.is_none()
                }
                PermissionScope::Path => {
                    self.tool == "vaultmesh_http_request"
                        && self.parameters_digest.is_none()
                        && self.catalog_revision.is_none()
                        && self.http_method.as_deref().is_some_and(|method| {
                            crate::agent_http_path_policy::method_risk(method).is_ok()
                        })
                        && self.path_pattern.as_deref().is_some_and(|pattern| {
                            crate::agent_http_path_policy::validate_pattern(pattern).is_ok()
                        })
                        && self.matcher_revision.as_deref()
                            == Some(crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION)
                }
                PermissionScope::Safe => {
                    self.parameters_digest.is_none()
                        && self.http_method.is_none()
                        && self.path_pattern.is_none()
                        && self.matcher_revision.is_none()
                        && self
                            .catalog_revision
                            .as_deref()
                            .is_some_and(|revision| !revision.is_empty() && revision.len() <= 128)
                }
                PermissionScope::All => {
                    self.parameters_digest.is_none()
                        && self.catalog_revision.is_none()
                        && self.http_method.is_none()
                        && self.path_pattern.is_none()
                        && self.matcher_revision.is_none()
                }
            }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizationPayload {
    rules: Vec<AgentAuthorizationRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizationEnvelope {
    version: u8,
    credential_ref: String,
    nonce: String,
    authentication_tag: String,
    ciphertext: String,
}

trait AuthorizationKeyStore: Send + Sync {
    fn set(&self, account: &str, key: &[u8]) -> Result<(), ()>;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()>;
}

struct PlatformAuthorizationKeyStore(crate::device_credentials::ScopedCredentialStore);

impl AuthorizationKeyStore for PlatformAuthorizationKeyStore {
    fn set(&self, account: &str, key: &[u8]) -> Result<(), ()> {
        self.0.set(account, key).map_err(|_| ())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        self.0.get(account).map_err(|_| ())
    }
}

#[cfg(test)]
#[derive(Default)]
struct MemoryAuthorizationKeyStore(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

#[cfg(test)]
impl AuthorizationKeyStore for MemoryAuthorizationKeyStore {
    fn set(&self, account: &str, key: &[u8]) -> Result<(), ()> {
        self.0
            .lock()
            .map_err(|_| ())?
            .insert(account.to_owned(), key.to_vec());
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
        Ok(self
            .0
            .lock()
            .map_err(|_| ())?
            .get(account)
            .cloned()
            .map(Zeroizing::new))
    }
}

#[derive(Clone)]
pub struct AgentAuthorizationStore {
    path: PathBuf,
    vault_namespace: String,
    keys: Arc<dyn AuthorizationKeyStore>,
}

impl AgentAuthorizationStore {
    pub fn platform(
        path: PathBuf,
        vault_path: &Path,
        credentials: &crate::device_credentials::DeviceCredentialStore,
    ) -> Self {
        Self {
            path,
            vault_namespace: vault_namespace(vault_path),
            keys: Arc::new(PlatformAuthorizationKeyStore(
                credentials.scoped(KEYRING_SERVICE),
            )),
        }
    }

    #[cfg(test)]
    pub fn memory(path: PathBuf, vault_namespace: &str) -> Self {
        Self {
            path,
            vault_namespace: vault_namespace.to_owned(),
            keys: Arc::new(MemoryAuthorizationKeyStore::default()),
        }
    }

    pub fn load(&self, user_id: &str) -> Result<Vec<AgentAuthorizationRule>, ()> {
        let bytes = match std::fs::metadata(&self.path) {
            Ok(metadata) if metadata.len() <= MAX_STORE_BYTES => std::fs::read(&self.path),
            Ok(_) => return Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
        }
        .map_err(|_| ())?;
        let envelope: AuthorizationEnvelope = serde_json::from_slice(&bytes).map_err(|_| ())?;
        let credential_ref = self.credential_ref(user_id);
        if envelope.version == 1 {
            return Ok(Vec::new());
        }
        if envelope.version != STORE_VERSION || envelope.credential_ref != credential_ref {
            return Err(());
        }
        let key = self.keys.get(&credential_ref)?.ok_or(())?;
        if key.len() != KEY_BYTES {
            return Err(());
        }
        let nonce = decode_exact::<NONCE_BYTES>(&envelope.nonce)?;
        let tag = decode_exact::<TAG_BYTES>(&envelope.authentication_tag)?;
        let mut ciphertext = Zeroizing::new(BASE64.decode(&envelope.ciphertext).map_err(|_| ())?);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ())?;
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &self.aad(user_id),
                ciphertext.as_mut(),
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| ())?;
        let payload: AuthorizationPayload =
            serde_json::from_slice(ciphertext.as_ref()).map_err(|_| ())?;
        if payload.rules.len() > MAX_RULES || payload.rules.iter().any(|rule| !rule.valid()) {
            return Err(());
        }
        Ok(payload.rules)
    }

    pub fn upsert(&self, user_id: &str, mut rule: AgentAuthorizationRule) -> Result<(), ()> {
        if !rule.valid() {
            return Err(());
        }
        let mut rules = self.load(user_id)?;
        if let Some(existing) = rules.iter_mut().find(|existing| {
            existing.client_key == rule.client_key
                && existing.account_ref == rule.account_ref
                && existing.target_digest == rule.target_digest
                && existing.tool == rule.tool
                && existing.scope == rule.scope
                && existing.parameters_digest == rule.parameters_digest
                && existing.catalog_revision == rule.catalog_revision
                && existing.http_method == rule.http_method
                && existing.path_pattern == rule.path_pattern
                && existing.matcher_revision == rule.matcher_revision
        }) {
            rule.id = existing.id;
            rule.created_at = existing.created_at;
            *existing = rule;
        } else {
            if rules.len() >= MAX_RULES {
                return Err(());
            }
            rules.push(rule);
        }
        self.save(user_id, &rules)
    }

    pub fn matching_rule(
        &self,
        query: AgentAuthorizationMatch<'_>,
    ) -> Result<Option<AgentAuthorizationRule>, ()> {
        let mut matches = self
            .load(query.user_id)?
            .into_iter()
            .filter(|rule| {
                rule.client_key == query.client_key
                    && rule.account_ref == query.account_ref
                    && rule.target_digest == query.target_digest
                    && rule.tool == query.tool
                    && match rule.scope {
                        PermissionScope::Exact => {
                            rule.parameters_digest.as_deref() == Some(query.parameters_digest)
                        }
                        PermissionScope::Path => {
                            rule.http_method.as_deref() == query.http_method
                                && rule.matcher_revision.as_deref()
                                    == Some(
                                        crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION,
                                    )
                                && rule.path_pattern.as_deref().is_some_and(|pattern| {
                                    query.http_path.is_some_and(|path| {
                                        crate::agent_http_path_policy::path_matches(pattern, path)
                                    })
                                })
                        }
                        PermissionScope::Safe => {
                            query.safe
                                && rule.catalog_revision.as_deref() == Some(query.catalog_revision)
                        }
                        PermissionScope::All => true,
                    }
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|rule| {
            let specificity = match rule.scope {
                PermissionScope::Exact => 4_u8,
                PermissionScope::Path => 3,
                PermissionScope::Safe => 2,
                PermissionScope::All => 1,
            };
            (rule.effect == PermissionEffect::Deny, specificity)
        });
        Ok(matches.pop())
    }

    pub fn remove_client(&self, user_id: &str, client_key: &str) -> Result<(), ()> {
        let mut rules = self.load(user_id)?;
        let previous_len = rules.len();
        rules.retain(|rule| rule.client_key != client_key);
        if rules.len() == previous_len {
            return Ok(());
        }
        self.save(user_id, &rules)
    }

    pub fn remove_rule(&self, user_id: &str, rule_id: Uuid) -> Result<bool, ()> {
        let mut rules = self.load(user_id)?;
        let previous_len = rules.len();
        rules.retain(|rule| rule.id != rule_id);
        if rules.len() == previous_len {
            return Ok(false);
        }
        self.save(user_id, &rules)?;
        Ok(true)
    }

    fn save(&self, user_id: &str, rules: &[AgentAuthorizationRule]) -> Result<(), ()> {
        if rules.len() > MAX_RULES || rules.iter().any(|rule| !rule.valid()) {
            return Err(());
        }
        let credential_ref = self.credential_ref(user_id);
        let key = match self.keys.get(&credential_ref)? {
            Some(key) if key.len() == KEY_BYTES => key,
            Some(_) => return Err(()),
            None => {
                let mut key = Zeroizing::new(vec![0_u8; KEY_BYTES]);
                OsRng.fill_bytes(key.as_mut());
                self.keys.set(&credential_ref, key.as_ref())?;
                key
            }
        };
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(&AuthorizationPayload {
                rules: rules.to_vec(),
            })
            .map_err(|_| ())?,
        );
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ())?;
        let tag = cipher
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &self.aad(user_id),
                plaintext.as_mut(),
            )
            .map_err(|_| ())?;
        let envelope = AuthorizationEnvelope {
            version: STORE_VERSION,
            credential_ref,
            nonce: BASE64.encode(nonce),
            authentication_tag: BASE64.encode(tag),
            ciphertext: BASE64.encode(plaintext.as_slice()),
        };
        write_private(&self.path, &serde_json::to_vec(&envelope).map_err(|_| ())?)
    }

    fn credential_ref(&self, user_id: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"vaultmesh-agent-authorization-key-v2");
        digest.update(self.vault_namespace.as_bytes());
        digest.update(user_id.as_bytes());
        format!("agent-authorization-v2-{:x}", digest.finalize())
    }

    fn aad(&self, user_id: &str) -> Vec<u8> {
        format!(
            "vaultmesh-agent-authorization-store-v2\0protocol-v2\0{}\0{}",
            self.vault_namespace, user_id
        )
        .into_bytes()
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn vault_namespace(path: &Path) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .and_then(|parent| path.file_name().map(|name| parent.join(name)))
            .unwrap_or_else(|| path.to_path_buf())
    });
    let mut digest = Sha256::new();
    digest.update(b"vaultmesh-vault-path-v1");
    digest.update(canonical.to_string_lossy().as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    BASE64
        .decode(value)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| ())?;
    }
    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    file.write_all(bytes)
        .and_then(|()| file.commit())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> AgentAuthorizationRule {
        AgentAuthorizationRule {
            id: Uuid::new_v4(),
            client_key: "codex".to_owned(),
            account_ref: Uuid::new_v4().to_string(),
            target_digest: format!("sha256:{}", "a".repeat(64)),
            tool: "vaultmesh_ssh_exec".to_owned(),
            scope: PermissionScope::Safe,
            effect: PermissionEffect::Allow,
            parameters_digest: None,
            catalog_revision: Some("ssh-safe-v1".to_owned()),
            http_method: None,
            path_pattern: None,
            matcher_revision: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn ct_agent_authz_persistent_store_is_encrypted_bound_and_fail_closed() {
        let directory = std::env::temp_dir().join(format!("vaultmesh-authz-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("authorization.v1");
        let keys = Arc::new(MemoryAuthorizationKeyStore::default());
        let store = AgentAuthorizationStore {
            path: path.clone(),
            vault_namespace: "vault-a".to_owned(),
            keys: keys.clone(),
        };
        let expected = rule();
        store.upsert("501", expected.clone()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(5).any(|window| window == b"codex"));
        assert_eq!(store.load("501").unwrap(), vec![expected]);

        let other_vault = AgentAuthorizationStore {
            path: path.clone(),
            vault_namespace: "vault-b".to_owned(),
            keys,
        };
        assert!(other_vault.load("501").is_err());
        let mut tampered = bytes;
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        std::fs::write(&path, tampered).unwrap();
        assert!(store.load("501").is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn ct_agent_authz_persistent_rule_specificity_deny_and_client_revoke_are_deterministic() {
        let directory = std::env::temp_dir().join(format!("vaultmesh-authz-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let store = AgentAuthorizationStore::memory(directory.join("authorization.v1"), "vault-a");
        let mut broad = rule();
        broad.scope = PermissionScope::All;
        broad.catalog_revision = None;
        let account_ref = broad.account_ref.clone();
        let target_digest = broad.target_digest.clone();
        store.upsert("501", broad).unwrap();
        let mut exact_deny = rule();
        exact_deny.account_ref = account_ref.clone();
        exact_deny.target_digest = target_digest.clone();
        exact_deny.scope = PermissionScope::Exact;
        exact_deny.effect = PermissionEffect::Deny;
        exact_deny.parameters_digest = Some(format!("sha256:{}", "b".repeat(64)));
        exact_deny.catalog_revision = None;
        store.upsert("501", exact_deny).unwrap();

        let matched = store
            .matching_rule(AgentAuthorizationMatch {
                user_id: "501",
                client_key: "codex",
                account_ref: &account_ref,
                target_digest: &target_digest,
                tool: "vaultmesh_ssh_exec",
                parameters_digest: &format!("sha256:{}", "b".repeat(64)),
                safe: true,
                catalog_revision: "ssh-safe-v1",
                http_method: None,
                http_path: None,
            })
            .unwrap()
            .unwrap();
        assert_eq!(matched.scope, PermissionScope::Exact);
        assert_eq!(matched.effect, PermissionEffect::Deny);
        store.remove_client("501", "codex").unwrap();
        assert!(store.load("501").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn ct_agent_http_path_001_persistent_rules_bind_method_pattern_and_prioritize_deny() {
        let directory = std::env::temp_dir().join(format!("vaultmesh-authz-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let store = AgentAuthorizationStore::memory(directory.join("authorization.v2"), "vault-a");
        let mut path_allow = rule();
        path_allow.tool = "vaultmesh_http_request".to_owned();
        path_allow.scope = PermissionScope::Path;
        path_allow.catalog_revision = None;
        path_allow.http_method = Some("GET".to_owned());
        path_allow.path_pattern = Some("/projects/**".to_owned());
        path_allow.matcher_revision =
            Some(crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION.to_owned());
        let account_ref = path_allow.account_ref.clone();
        let target_digest = path_allow.target_digest.clone();
        store.upsert("501", path_allow).unwrap();

        let parameters_digest = format!("sha256:{}", "b".repeat(64));
        let query = |method, path| AgentAuthorizationMatch {
            user_id: "501",
            client_key: "codex",
            account_ref: &account_ref,
            target_digest: &target_digest,
            tool: "vaultmesh_http_request",
            parameters_digest: &parameters_digest,
            safe: false,
            catalog_revision: "none",
            http_method: Some(method),
            http_path: Some(path),
        };
        assert!(
            store
                .matching_rule(query("GET", "/projects/42"))
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .matching_rule(query("POST", "/projects/42"))
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .matching_rule(query("GET", "/admin/42"))
                .unwrap()
                .is_none()
        );

        let mut deny = rule();
        deny.account_ref = account_ref.clone();
        deny.target_digest = target_digest.clone();
        deny.tool = "vaultmesh_http_request".to_owned();
        deny.scope = PermissionScope::All;
        deny.effect = PermissionEffect::Deny;
        deny.catalog_revision = None;
        store.upsert("501", deny).unwrap();
        let matched = store
            .matching_rule(query("GET", "/projects/42"))
            .unwrap()
            .unwrap();
        assert_eq!(matched.effect, PermissionEffect::Deny);
        let _ = std::fs::remove_dir_all(directory);
    }
}
