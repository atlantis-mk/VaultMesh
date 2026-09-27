//! Request-scoped Android Autofill authority. No general UI unlock is granted.
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use vaultmesh_core::{LoginItemDetail, LoginItemUpdate, NewLoginItem, VaultSession};
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError as Error, AndroidVaultRuntime, read_vault};

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutofillTarget {
    pub package_name: String,
    pub signer_digest: String,
    pub web_origin: Option<String>,
}

impl AutofillTarget {
    fn validate(&self) -> Result<(), Error> {
        if self.package_name.len() > 256
            || !self.package_name.contains('.')
            || self.package_name.split('.').any(|part| {
                part.is_empty() || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
            || self.signer_digest.len() != 64
            || !self
                .signer_digest
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || self.web_origin.as_ref().is_some_and(|origin| {
                origin.len() > 2048 || https_origin(origin).as_ref() != Some(origin)
            })
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn binding(&self) -> String {
        let mut binding = format!(
            "androidapp://{}/sha256/{}",
            self.package_name, self.signer_digest
        );
        if let Some(origin) = &self.web_origin {
            binding.push('?');
            binding.push_str(
                &url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("origin", origin)
                    .finish(),
            );
        }
        binding
    }

    fn matches(&self, item: &LoginItemDetail) -> (bool, bool) {
        let binding = self.binding();
        let urls = item.url.iter().chain(item.additional_urls.iter());
        let bound = urls.clone().any(|value| value == &binding);
        let suggested = self.web_origin.as_ref().is_some_and(|origin| {
            urls.clone()
                .any(|value| https_origin(value).as_ref() == Some(origin))
        });
        (bound, suggested)
    }
}

fn related_name_hint(item: &LoginItemDetail, app_label: &str, package_name: &str) -> bool {
    let mut hints = Vec::new();
    let label: String = app_label
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if (2..=32).contains(&label.chars().count()) {
        hints.push(label);
    }
    for segment in package_name.split('.') {
        let segment = segment.to_ascii_lowercase();
        let suffix = ["mobile", "android", "client", "app"]
            .iter()
            .find_map(|prefix| segment.strip_prefix(prefix))
            .unwrap_or(&segment);
        for hint in [segment.as_str(), suffix] {
            if (2..=32).contains(&hint.len())
                && !["com", "org", "net", "app", "android", "mobile", "client"].contains(&hint)
                && !hints.iter().any(|known| known == hint)
            {
                hints.push(hint.to_owned());
            }
        }
    }
    let title: String = item
        .title
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if hints.iter().any(|hint| title.contains(hint)) {
        return true;
    }
    item.url
        .iter()
        .chain(item.additional_urls.iter())
        .any(|value| {
            Url::parse(value)
                .ok()
                .filter(|url| url.scheme() == "https")
                .and_then(|url| url.host_str().map(str::to_owned))
                .is_some_and(|host| {
                    host.split('.')
                        .any(|label| hints.iter().any(|hint| label.eq_ignore_ascii_case(hint)))
                })
        })
}

fn https_origin(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    (parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none())
    .then(|| parsed.origin().ascii_serialization())
}

pub(crate) struct AutofillGrant {
    token: String,
    request_id: String,
    target: AutofillTarget,
    session: VaultSession,
    password: Option<Zeroizing<String>>,
    fingerprint: [u8; 32],
    expires: Instant,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillCandidate {
    id: String,
    title: String,
    username: String,
    matched: bool,
    suggested: bool,
    related_hint: bool,
}

impl AndroidVaultRuntime {
    pub fn autofill_preview_fingerprint(&self, app_data_dir: &str) -> Result<String, Error> {
        if !std::path::Path::new(app_data_dir).is_absolute()
            || self.vault_path != std::path::Path::new(app_data_dir).join(crate::VAULT_FILE_NAME)
        {
            return Err(Error::InvalidInput);
        }
        let digest = Sha256::digest(read_vault(&self.vault_path)?);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn autofill_begin(
        &mut self,
        request_id: &str,
        target: AutofillTarget,
        password: &str,
    ) -> Result<String, Error> {
        self.autofill_validate_begin(request_id, &target)?;
        if password.is_empty() || password.len() > 4096 {
            return Err(Error::InvalidInput);
        }
        let disk = read_vault(&self.vault_path)?;
        let session = VaultSession::unlock(password, &disk)?;
        let fingerprint = Sha256::digest(&disk).into();
        Ok(self.autofill_store_grant(request_id, target, session, Some(password), fingerprint))
    }

    pub fn autofill_begin_biometric(
        &mut self,
        request_id: &str,
        target: AutofillTarget,
        secret: &str,
    ) -> Result<String, Error> {
        self.autofill_validate_begin(request_id, &target)?;
        let fingerprint: [u8; 32] = Sha256::digest(read_vault(&self.vault_path)?).into();
        let session = self.biometric_session_from_secret(secret)?;
        self.autofill_verify_snapshot(&fingerprint)?;
        Ok(self.autofill_store_grant(request_id, target, session, None, fingerprint))
    }

    pub fn autofill_begin_pin(
        &mut self,
        request_id: &str,
        target: AutofillTarget,
        pin: &str,
        device_secret: &str,
    ) -> Result<String, Error> {
        self.autofill_validate_begin(request_id, &target)?;
        let fingerprint: [u8; 32] = Sha256::digest(read_vault(&self.vault_path)?).into();
        let session = self.pin_session_from_secret(pin, device_secret)?;
        self.autofill_verify_snapshot(&fingerprint)?;
        Ok(self.autofill_store_grant(request_id, target, session, None, fingerprint))
    }

    fn autofill_validate_begin(
        &mut self,
        request_id: &str,
        target: &AutofillTarget,
    ) -> Result<(), Error> {
        self.lock();
        target.validate()?;
        Uuid::parse_str(request_id).map_err(|_| Error::InvalidInput)?;
        Ok(())
    }

    fn autofill_verify_snapshot(&self, fingerprint: &[u8; 32]) -> Result<(), Error> {
        if Sha256::digest(read_vault(&self.vault_path)?).as_slice() != fingerprint {
            return Err(Error::InvalidVault);
        }
        Ok(())
    }

    fn autofill_store_grant(
        &mut self,
        request_id: &str,
        target: AutofillTarget,
        session: VaultSession,
        password: Option<&str>,
        fingerprint: [u8; 32],
    ) -> String {
        let token = Uuid::new_v4().to_string();
        self.autofill_grant = Some(AutofillGrant {
            token: token.clone(),
            request_id: request_id.to_owned(),
            target,
            session,
            password: password.map(|value| Zeroizing::new(value.to_owned())),
            fingerprint,
            expires: Instant::now() + Duration::from_secs(120),
        });
        token
    }

    fn autofill_grant(&mut self, token: &str) -> Result<&AutofillGrant, Error> {
        if self
            .autofill_grant
            .as_ref()
            .is_some_and(|g| Instant::now() >= g.expires)
        {
            self.autofill_grant = None;
        }
        self.autofill_grant
            .as_ref()
            .filter(|g| g.token == token)
            .ok_or(Error::Locked)
    }

    fn take_autofill_grant(
        &mut self,
        token: &str,
        request_id: &str,
    ) -> Result<AutofillGrant, Error> {
        let grant = self.autofill_grant(token)?;
        if grant.request_id != request_id {
            return Err(Error::InvalidInput);
        }
        let grant = self.autofill_grant.take().ok_or(Error::Locked)?;
        if Sha256::digest(read_vault(&self.vault_path)?).as_slice() != grant.fingerprint {
            return Err(Error::InvalidInput);
        }
        Ok(grant)
    }

    pub fn autofill_cancel(&mut self, token: &str) {
        if self
            .autofill_grant
            .as_ref()
            .is_some_and(|grant| grant.token == token)
        {
            self.autofill_grant = None;
        }
    }

    pub fn autofill_candidates(
        &mut self,
        token: &str,
        query: &str,
        app_label: &str,
        recent_ids: &[String],
    ) -> Result<Vec<AutofillCandidate>, Error> {
        if query.chars().count() > 256
            || app_label.chars().count() > 64
            || recent_ids.len() > 20
            || recent_ids.iter().any(|id| Uuid::parse_str(id).is_err())
        {
            return Err(Error::InvalidInput);
        }
        let grant = self.autofill_grant(token)?;
        let query = query.to_lowercase();
        let mut candidates = Vec::new();
        for summary in grant.session.list_items()? {
            if !summary.has_password {
                continue;
            }
            let detail = grant.session.item_detail(summary.id)?;
            let (matched, suggested) = grant.target.matches(&detail);
            let related_hint = related_name_hint(&detail, app_label, &grant.target.package_name);
            if !query.is_empty()
                && !summary.title.to_lowercase().contains(&query)
                && !summary.username.to_lowercase().contains(&query)
                && !detail
                    .url
                    .as_ref()
                    .is_some_and(|url| url.to_lowercase().contains(&query))
                && !detail
                    .additional_urls
                    .iter()
                    .any(|url| url.to_lowercase().contains(&query))
            {
                continue;
            }
            candidates.push(AutofillCandidate {
                id: summary.id.to_string(),
                title: summary.title.chars().take(256).collect(),
                username: summary.username.chars().take(256).collect(),
                matched,
                suggested,
                related_hint,
            });
        }
        candidates.sort_by(|a, b| {
            (
                recent_ids
                    .iter()
                    .position(|id| id == &a.id)
                    .unwrap_or(usize::MAX),
                !a.matched,
                !a.suggested,
                !a.related_hint,
                &a.title,
                &a.id,
            )
                .cmp(&(
                    recent_ids
                        .iter()
                        .position(|id| id == &b.id)
                        .unwrap_or(usize::MAX),
                    !b.matched,
                    !b.suggested,
                    !b.related_hint,
                    &b.title,
                    &b.id,
                ))
        });
        candidates.truncate(100);
        Ok(candidates)
    }

    /// The returned JSON goes straight to the platform Dataset builder, never UI state.
    pub fn autofill_fill(
        &mut self,
        token: &str,
        request_id: &str,
        id: &str,
        confirm_unmatched: bool,
        remember_association: bool,
        include_password: bool,
    ) -> Result<Zeroizing<String>, Error> {
        let grant = self.take_autofill_grant(token, request_id)?;
        let id = Uuid::parse_str(id).map_err(|_| Error::InvalidInput)?;
        let detail = grant.session.item_detail(id)?;
        let matched = grant.target.matches(&detail).0;
        if !matched && !confirm_unmatched {
            return Err(Error::InvalidInput);
        }
        if remember_association && (matched || !confirm_unmatched) {
            return Err(Error::InvalidInput);
        }
        let password = if include_password {
            grant
                .session
                .password_for_access(id, grant.password.as_deref().map(String::as_str))?
        } else {
            ""
        };
        if (include_password && password.is_empty())
            || password.len() > 16384
            || detail.username.len() > 1024
        {
            return Err(Error::InvalidInput);
        }
        #[derive(Serialize)]
        struct Values<'a> {
            username: &'a str,
            password: &'a str,
        }
        let values = Zeroizing::new(
            serde_json::to_string(&Values {
                username: &detail.username,
                password,
            })
            .map_err(|_| Error::Io)?,
        );
        if remember_association {
            let binding = grant.target.binding();
            let mut urls = detail.additional_urls;
            if urls.len() >= 20 {
                return Err(Error::InvalidInput);
            }
            urls.push(binding);
            self.session = Some(grant.session);
            self.persisted_fingerprint = Some(grant.fingerprint);
            let result = self.mutate_and_commit(|session| {
                session.update_item(LoginItemUpdate {
                    id: detail.id,
                    title: detail.title,
                    username: detail.username,
                    password: None,
                    url: detail.url,
                    notes: detail.notes,
                    folder: detail.folder,
                    favorite: detail.favorite,
                    totp_secret: None,
                    clear_totp_secret: false,
                    recovery_codes: None,
                    clear_recovery_codes: false,
                    additional_urls: urls,
                    autofill_on_page_load: detail.autofill_on_page_load,
                    master_password_reprompt: detail.master_password_reprompt,
                    custom_fields: detail.custom_fields,
                })?;
                Ok(())
            });
            self.lock();
            result?;
        }
        Ok(values)
    }

    pub fn autofill_save(
        &mut self,
        token: &str,
        request_id: &str,
        update_id: &str,
        title: &str,
        username: &str,
        password: &str,
    ) -> Result<(), Error> {
        let grant = self.take_autofill_grant(token, request_id)?;
        if title.trim().is_empty()
            || title.chars().count() > 256
            || username.chars().count() > 256
            || password.is_empty()
            || password.chars().count() > 4096
        {
            return Err(Error::InvalidInput);
        }
        let binding = grant.target.binding();
        let selected = if update_id.is_empty() {
            None
        } else {
            let id = Uuid::parse_str(update_id).map_err(|_| Error::InvalidInput)?;
            let detail = grant.session.item_detail(id)?;
            let (matched, suggested) = grant.target.matches(&detail);
            if (!matched && !suggested) || (!username.is_empty() && detail.username != username) {
                return Err(Error::InvalidInput);
            }
            Some(detail)
        };
        // Identical repeated submissions are a no-op, including an explicit new save.
        for summary in grant.session.list_items()? {
            if selected.as_ref().is_some_and(|item| item.id != summary.id) {
                continue;
            }
            let detail = grant.session.item_detail(summary.id)?;
            let effective_username = if username.is_empty() && selected.is_some() {
                &detail.username
            } else {
                username
            };
            if grant.target.matches(&detail).0
                && detail.username == effective_username
                && grant.session.password_for_access(
                    summary.id,
                    grant.password.as_deref().map(String::as_str),
                )? == password
            {
                return Ok(());
            }
        }
        // The runtime mutex surrounds this transient use of the common commit path.
        // No general unlock can be observed, and every outcome clears this session.
        self.session = Some(grant.session);
        self.persisted_fingerprint = Some(grant.fingerprint);
        let result = self.mutate_and_commit(|session| {
            if let Some(mut item) = selected {
                if !item.additional_urls.contains(&binding) {
                    if item.additional_urls.len() >= 20 {
                        return Err(vaultmesh_core::VaultError::InvalidUrl);
                    }
                    item.additional_urls.push(binding);
                }
                session.update_item(LoginItemUpdate {
                    id: item.id,
                    title: item.title,
                    username: if username.is_empty() {
                        item.username
                    } else {
                        username.to_owned()
                    },
                    password: Some(password.to_owned()),
                    url: item.url,
                    notes: item.notes,
                    folder: item.folder,
                    favorite: item.favorite,
                    totp_secret: None,
                    clear_totp_secret: false,
                    recovery_codes: None,
                    clear_recovery_codes: false,
                    additional_urls: item.additional_urls,
                    autofill_on_page_load: item.autofill_on_page_load,
                    master_password_reprompt: item.master_password_reprompt,
                    custom_fields: item.custom_fields,
                })?;
            } else {
                session.add_item(NewLoginItem {
                    title: title.trim().to_owned(),
                    username: username.to_owned(),
                    password: password.to_owned(),
                    url: grant.target.web_origin,
                    additional_urls: vec![binding],
                    notes: None,
                    folder: None,
                    favorite: false,
                    totp_secret: None,
                    recovery_codes: vec![],
                    autofill_on_page_load: true,
                    master_password_reprompt: false,
                    custom_fields: vec![],
                })?;
            }
            Ok(())
        });
        self.lock();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FAIL_NEXT_WRITE, RuntimeStatus};
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

    const MASTER: &str = "synthetic-autofill-master";
    fn target() -> AutofillTarget {
        AutofillTarget {
            package_name: "com.example.login".into(),
            signer_digest: "ab".repeat(32),
            web_origin: Some("https://example.test".into()),
        }
    }
    fn runtime() -> (AndroidVaultRuntime, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("vaultmesh-autofill-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create(MASTER).unwrap();
        runtime
            .add_login(
                "Existing".into(),
                "alice".into(),
                "synthetic-secret".into(),
                Some("https://example.test/login".into()),
            )
            .unwrap();
        runtime.lock();
        (runtime, dir)
    }
    fn begin(runtime: &mut AndroidVaultRuntime, target: AutofillTarget) -> (String, String) {
        let request = Uuid::new_v4().to_string();
        (
            runtime.autofill_begin(&request, target, MASTER).unwrap(),
            request,
        )
    }
    #[test]
    fn preview_fingerprint_tracks_encrypted_vault_without_unlocking() {
        let (mut runtime, dir) = runtime();
        let expected_dir = dir.to_str().unwrap();
        let first = runtime.autofill_preview_fingerprint(expected_dir).unwrap();
        assert!(runtime.autofill_preview_fingerprint("/other/runtime").is_err());
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|value| value.is_ascii_hexdigit()));
        runtime.unlock(MASTER).unwrap();
        runtime.add_login("Second".into(), "bob".into(), "synthetic-secret".into(), None).unwrap();
        runtime.lock();
        assert_ne!(first, runtime.autofill_preview_fingerprint(expected_dir).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn package_segments_hint_qq_and_remembered_binding_is_atomic_and_signer_bound() {
        let (mut runtime, dir) = runtime();
        runtime.unlock(MASTER).unwrap();
        runtime
            .add_login(
                "QQ account".into(),
                "qq-user".into(),
                "qq-secret".into(),
                Some("https://qq.com/login".into()),
            )
            .unwrap();
        runtime.lock();
        let qq = AutofillTarget {
            package_name: "com.tencent.mobileqq".into(),
            signer_digest: "ab".repeat(32),
            web_origin: None,
        };
        let (token, request) = begin(&mut runtime, qq.clone());
        let candidates = runtime.autofill_candidates(&token, "", "", &[]).unwrap();
        assert_eq!(candidates[0].title, "QQ account");
        assert!(candidates[0].related_hint);
        assert!(!candidates[0].matched);
        let id = candidates[0].id.clone();
        let previous = candidates
            .iter()
            .find(|item| item.title == "Existing")
            .unwrap()
            .id
            .clone();
        assert_eq!(
            runtime
                .autofill_candidates(&token, "", "", &[previous.clone()])
                .unwrap()[0]
                .id,
            previous
        );
        let before = std::fs::read(&runtime.vault_path).unwrap();
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &id, false, true, true)
                .unwrap_err(),
            Error::InvalidInput
        );
        let (token, request) = begin(&mut runtime, qq.clone());
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &id, true, true, true)
                .unwrap_err(),
            Error::Io
        );
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), before);
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        let (token, request) = begin(&mut runtime, qq.clone());
        assert!(
            runtime
                .autofill_fill(&token, &request, &id, true, false, true)
                .unwrap()
                .contains("qq-secret")
        );
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), before);
        let (token, request) = begin(&mut runtime, qq.clone());
        assert!(
            runtime
                .autofill_fill(&token, &request, &id, true, true, true)
                .unwrap()
                .contains("qq-secret")
        );
        let (token, _) = begin(&mut runtime, qq.clone());
        assert!(runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0].matched);
        let mut impersonator = qq;
        impersonator.signer_digest = "cd".repeat(32);
        let (token, _) = begin(&mut runtime, impersonator);
        assert!(!runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0].matched);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn quick_auth_grants_fill_and_save_without_unlocking_or_bypassing_pin_limit() {
        let (mut runtime, dir) = runtime();
        runtime.unlock(MASTER).unwrap();
        let biometric_secret = runtime.prepare_biometric_unlock().unwrap();
        let device_secret = STANDARD_NO_PAD.encode([17_u8; 32]);
        runtime.enable_pin_unlock("123456", &device_secret).unwrap();
        runtime.lock();

        let request = Uuid::new_v4().to_string();
        let token = runtime
            .autofill_begin_biometric(&request, target(), &biometric_secret)
            .unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert_eq!(runtime.list_logins().unwrap_err(), Error::Locked);
        let id = runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0]
            .id
            .clone();
        runtime
            .autofill_save(&token, &request, "", "Saved", "saved-user", "saved-secret")
            .unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        let saved_disk = std::fs::read(&runtime.vault_path).unwrap();
        let duplicate = runtime
            .autofill_begin_pin(&request, target(), "123456", &device_secret)
            .unwrap();
        runtime
            .autofill_save(
                &duplicate,
                &request,
                "",
                "Saved",
                "saved-user",
                "saved-secret",
            )
            .unwrap();
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), saved_disk);
        assert_eq!(
            runtime.autofill_candidates(&token, "", "", &[]).err(),
            Some(Error::Locked)
        );

        let token = runtime
            .autofill_begin_pin(&request, target(), "123456", &device_secret)
            .unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert!(
            runtime
                .autofill_fill(&token, &request, &id, true, false, true)
                .unwrap()
                .contains("synthetic-secret")
        );
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &id, true, false, true)
                .unwrap_err(),
            Error::Locked
        );
        let token = runtime
            .autofill_begin_pin(&request, target(), "123456", &device_secret)
            .unwrap();
        let saved = runtime
            .autofill_candidates(&token, "saved-user", "", &[])
            .unwrap()
            .pop()
            .unwrap();
        assert!(
            runtime
                .autofill_fill(&token, &request, &saved.id, false, false, true)
                .unwrap()
                .contains("saved-secret")
        );
        assert_eq!(
            runtime
                .autofill_begin_pin(&request, target(), "000000", &device_secret)
                .unwrap_err(),
            Error::PinFailed
        );
        assert_eq!(runtime.pin_status().unwrap().remaining_attempts, 4);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quick_auth_does_not_bypass_item_master_password_reprompt() {
        let (mut runtime, dir) = runtime();
        let request = Uuid::new_v4().to_string();
        let token = runtime.autofill_begin(&request, target(), MASTER).unwrap();
        runtime
            .autofill_save(
                &token,
                &request,
                "",
                "Protected",
                "protected-user",
                "protected-secret",
            )
            .unwrap();
        runtime.unlock(MASTER).unwrap();
        let id = runtime
            .list_logins()
            .unwrap()
            .into_iter()
            .find(|item| item.username == "protected-user")
            .unwrap()
            .id
            .to_string();
        let mut extras = runtime.login_editor_detail(&id).unwrap();
        extras.master_password_reprompt = true;
        runtime
            .update_login_complete(
                &id,
                "Protected".into(),
                "protected-user".into(),
                None,
                Some("https://example.test".into()),
                extras,
            )
            .unwrap();
        let secret = runtime.prepare_biometric_unlock().unwrap();
        runtime.lock();
        let token = runtime
            .autofill_begin_biometric(&request, target(), &secret)
            .unwrap();
        let item = runtime
            .autofill_candidates(&token, "protected-user", "", &[])
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &item.id, false, false, true)
                .unwrap_err(),
            Error::UnlockFailed
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        let token = runtime
            .autofill_begin_biometric(&request, target(), &secret)
            .unwrap();
        assert_eq!(
            runtime
                .autofill_save(
                    &token,
                    &request,
                    &id,
                    "Protected",
                    "protected-user",
                    "new-secret"
                )
                .unwrap_err(),
            Error::UnlockFailed
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn autofill_authority_is_isolated_target_bound_single_use_and_expiring() {
        let (mut runtime, dir) = runtime();
        assert_eq!(
            runtime
                .autofill_begin(&Uuid::new_v4().to_string(), target(), "wrong")
                .unwrap_err(),
            Error::UnlockFailed
        );
        let (token, request) = begin(&mut runtime, target());
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert_eq!(runtime.list_logins().unwrap_err(), Error::Locked);
        let candidates = runtime.autofill_candidates(&token, "", "", &[]).unwrap();
        assert!(candidates[0].suggested && !candidates[0].matched);
        assert!(
            !serde_json::to_string(&candidates)
                .unwrap()
                .contains("synthetic-secret")
        );
        let id = &candidates[0].id;
        assert_eq!(
            runtime
                .autofill_fill(&token, &Uuid::new_v4().to_string(), id, true, false, true)
                .unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, id, false, false, true)
                .unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, id, true, false, true)
                .unwrap_err(),
            Error::Locked
        );
        let (token, request) = begin(&mut runtime, target());
        let response = runtime
            .autofill_fill(&token, &request, id, true, false, true)
            .unwrap();
        assert!(response.contains("synthetic-secret"));
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, id, true, false, true)
                .unwrap_err(),
            Error::Locked
        );
        let (token, request) = begin(&mut runtime, target());
        let response = runtime
            .autofill_fill(&token, &request, id, true, false, false)
            .unwrap();
        assert!(!response.contains("synthetic-secret"));
        let (token, _) = begin(&mut runtime, target());
        runtime.autofill_grant.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            runtime.autofill_candidates(&token, "", "", &[]).err(),
            Some(Error::Locked)
        );
        let (token, _) = begin(&mut runtime, target());
        runtime.autofill_cancel(&token);
        assert_eq!(
            runtime.autofill_candidates(&token, "", "", &[]).err(),
            Some(Error::Locked)
        );
        let (token, _) = begin(&mut runtime, target());
        runtime.lock();
        assert_eq!(
            runtime.autofill_candidates(&token, "", "", &[]).err(),
            Some(Error::Locked)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn autofill_save_preserves_metadata_rolls_back_and_deduplicates() {
        let (mut runtime, dir) = runtime();
        runtime.unlock(MASTER).unwrap();
        let id = runtime.list_logins().unwrap()[0].id.clone();
        runtime
            .set_login_totp(&id, Some("JBSWY3DPEHPK3PXP".into()), false)
            .unwrap();
        runtime
            .set_login_recovery_codes(&id, "synthetic-recovery".into(), false)
            .unwrap();
        let before = std::fs::read(&runtime.vault_path).unwrap();
        let (token, request) = begin(&mut runtime, target());
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime
                .autofill_save(&token, &request, &id, "Ignored", "alice", "replacement")
                .unwrap_err(),
            Error::Io
        );
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), before);
        let (token, request) = begin(&mut runtime, target());
        runtime
            .autofill_save(&token, &request, &id, "Ignored", "alice", "replacement")
            .unwrap();
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        runtime.unlock(MASTER).unwrap();
        let item = runtime.list_logins().unwrap().remove(0);
        assert!(item.has_totp_secret && item.has_recovery_codes);
        assert_eq!(item.title, "Existing");
        assert_eq!(
            runtime.copy_login_password(&id, MASTER).unwrap().as_str(),
            "replacement"
        );
        let after = std::fs::read(&runtime.vault_path).unwrap();
        let (token, request) = begin(&mut runtime, target());
        assert!(runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0].matched);
        runtime
            .autofill_save(&token, &request, "", "Duplicate", "alice", "replacement")
            .unwrap();
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), after);
        let (token, request) = begin(&mut runtime, target());
        assert_eq!(
            runtime
                .autofill_save(&token, &request, &id, "Ignored", "bob", "other")
                .unwrap_err(),
            Error::InvalidInput
        );
        let mut impersonator = target();
        impersonator.signer_digest = "cd".repeat(32);
        let (token, request) = begin(&mut runtime, impersonator);
        assert!(!runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0].matched);
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &id, false, false, true)
                .unwrap_err(),
            Error::InvalidInput
        );
        let mut other = target();
        other.web_origin = Some("https://evil.test".into());
        let (token, request) = begin(&mut runtime, other);
        assert_eq!(
            runtime
                .autofill_save(&token, &request, &id, "Ignored", "alice", "other")
                .unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), after);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn autofill_rejects_disk_changes_malformed_targets_and_out_of_scope_updates() {
        let (mut runtime, dir) = runtime();
        let mut unsafe_target = target();
        unsafe_target.web_origin = Some("http://example.test".into());
        assert_eq!(
            runtime
                .autofill_begin(&Uuid::new_v4().to_string(), unsafe_target, MASTER)
                .unwrap_err(),
            Error::InvalidInput
        );
        let mut unsafe_target = target();
        unsafe_target.package_name = "evil/../app".into();
        assert_eq!(
            runtime
                .autofill_begin(&Uuid::new_v4().to_string(), unsafe_target, MASTER)
                .unwrap_err(),
            Error::InvalidInput
        );
        let (token, request) = begin(&mut runtime, target());
        let id = runtime.autofill_candidates(&token, "", "", &[]).unwrap()[0]
            .id
            .clone();
        let mut second = AndroidVaultRuntime::new(&dir).unwrap();
        second.unlock(MASTER).unwrap();
        second
            .add_login("Concurrent".into(), "b".into(), "new".into(), None)
            .unwrap();
        assert_eq!(
            runtime
                .autofill_fill(&token, &request, &id, true, false, true)
                .unwrap_err(),
            Error::InvalidInput
        );
        let (token, request) = begin(&mut runtime, target());
        runtime
            .autofill_save(&token, &request, "", "New", "bob", "new-secret")
            .unwrap();
        runtime.unlock(MASTER).unwrap();
        assert_eq!(runtime.list_logins().unwrap().len(), 3);
        let (token, request) = begin(&mut runtime, target());
        assert_eq!(
            runtime
                .autofill_save(&token, &request, "", "New", "bob", "")
                .unwrap_err(),
            Error::InvalidInput
        );
        let candidates = {
            let (token, _) = begin(&mut runtime, target());
            runtime.autofill_candidates(&token, "bob", "", &[]).unwrap()
        };
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].matched);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn autofill_association_respects_existing_editor_url_limit() {
        let (mut runtime, dir) = runtime();
        runtime.unlock(MASTER).unwrap();
        let id = runtime.list_logins().unwrap()[0].id.clone();
        runtime
            .mutate_and_commit(|session| {
                let item_id = Uuid::parse_str(&id).unwrap();
                let item = session.item_detail(item_id)?;
                session.update_item(LoginItemUpdate {
                    id: item_id,
                    title: item.title,
                    username: item.username,
                    password: None,
                    url: item.url,
                    notes: item.notes,
                    folder: item.folder,
                    favorite: item.favorite,
                    totp_secret: None,
                    clear_totp_secret: false,
                    recovery_codes: None,
                    clear_recovery_codes: false,
                    additional_urls: (0..20).map(|i| format!("https://site{i}.test")).collect(),
                    autofill_on_page_load: item.autofill_on_page_load,
                    master_password_reprompt: item.master_password_reprompt,
                    custom_fields: item.custom_fields,
                })?;
                Ok(())
            })
            .unwrap();
        let before = std::fs::read(&runtime.vault_path).unwrap();
        let (token, request) = begin(&mut runtime, target());
        assert_eq!(
            runtime
                .autofill_save(&token, &request, &id, "Existing", "alice", "replacement")
                .unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(std::fs::read(&runtime.vault_path).unwrap(), before);
        assert_eq!(runtime.status(), RuntimeStatus::Locked);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
