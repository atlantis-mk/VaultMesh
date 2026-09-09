use super::*;
use crate::model::{
    api_environment_policy_digest, api_environment_refs_live, credential_ref_live,
    normalize_api_environment,
};

const MAX_API_ENVIRONMENT_REVISIONS: usize = 20;

impl VaultSession {
    pub fn list_api_environments(
        &self,
        service_id: Uuid,
    ) -> Result<Vec<ApiEnvironmentSummary>, VaultError> {
        self.require_live_service(service_id)?;
        let mut items = self
            .payload()?
            .api_environments
            .iter()
            .filter(|item| item.service_id == service_id)
            .map(api_environment_summary)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        Ok(items)
    }

    pub fn api_environment_detail(&self, id: Uuid) -> Result<ApiEnvironmentDetail, VaultError> {
        let item = self
            .payload()?
            .api_environments
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        self.require_live_service(item.service_id)?;
        Ok(api_environment_detail(item))
    }

    pub fn add_api_environment(
        &mut self,
        mut input: NewApiEnvironment,
    ) -> Result<ApiEnvironmentSummary, VaultError> {
        normalize_api_environment(&mut input)?;
        self.validate_environment_input(&input)?;
        let now = unix_time_now();
        let revision = 1;
        let policy_digest = api_environment_policy_digest(&input, revision)?;
        let record = ApiEnvironmentRecord {
            id: Uuid::new_v4(),
            service_id: input.service_id,
            name: input.name,
            kind: input.kind,
            origin: input.origin,
            base_path: input.base_path,
            openapi_url: input.openapi_url,
            auth: input.auth,
            fixed_headers: input.fixed_headers,
            revision,
            policy_digest,
            created_at: now,
            updated_at: now,
        };
        let summary = api_environment_summary(&record);
        self.payload_mut()?.api_environments.push(record);
        Ok(summary)
    }

    pub fn update_api_environment(
        &mut self,
        mut update: ApiEnvironmentUpdate,
    ) -> Result<ApiEnvironmentSummary, VaultError> {
        normalize_api_environment(&mut update.input)?;
        self.validate_environment_input(&update.input)?;
        let existing = self
            .payload()?
            .api_environments
            .iter()
            .find(|item| item.id == update.id)
            .cloned()
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        let unchanged_digest = api_environment_policy_digest(&update.input, existing.revision)?;
        if unchanged_digest == existing.policy_digest {
            return Ok(api_environment_summary(&existing));
        }
        let next_revision = existing.revision.saturating_add(1);
        let next_digest = api_environment_policy_digest(&update.input, next_revision)?;
        let now = unix_time_now();
        self.push_api_environment_history(existing, now)?;
        let item = self
            .payload_mut()?
            .api_environments
            .iter_mut()
            .find(|item| item.id == update.id)
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        item.service_id = update.input.service_id;
        item.name = update.input.name;
        item.kind = update.input.kind;
        item.origin = update.input.origin;
        item.base_path = update.input.base_path;
        item.openapi_url = update.input.openapi_url;
        item.auth = update.input.auth;
        item.fixed_headers = update.input.fixed_headers;
        item.revision = next_revision;
        item.policy_digest = next_digest;
        item.updated_at = now;
        Ok(api_environment_summary(item))
    }

    pub fn delete_api_environment(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .api_environments
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        let mut item = payload.api_environments.remove(index);
        bump_record_revision(&mut item)?;
        payload.api_environment_trash.push(TrashedApiEnvironment {
            trash_id: Uuid::new_v4(),
            deleted_at: unix_time_now(),
            item,
        });
        Ok(())
    }

    pub fn list_api_environment_trash(
        &self,
        service_id: Uuid,
    ) -> Result<Vec<ApiEnvironmentTrashSummary>, VaultError> {
        self.require_live_service(service_id)?;
        Ok(self
            .payload()?
            .api_environment_trash
            .iter()
            .filter(|entry| entry.item.service_id == service_id)
            .map(|entry| ApiEnvironmentTrashSummary {
                trash_id: entry.trash_id,
                environment_id: entry.item.id,
                service_id: entry.item.service_id,
                name: entry.item.name.clone(),
                deleted_at: entry.deleted_at,
            })
            .collect())
    }

    pub fn restore_api_environment_trash(
        &mut self,
        trash_id: Uuid,
    ) -> Result<ApiEnvironmentSummary, VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .api_environment_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let mut entry = payload.api_environment_trash.remove(index);
        if !payload
            .services
            .iter()
            .any(|service| service.id == entry.item.service_id)
        {
            payload.api_environment_trash.insert(index, entry);
            return Err(VaultError::ServiceNotFound);
        }
        bump_record_revision(&mut entry.item)?;
        let summary = api_environment_summary(&entry.item);
        payload.api_environments.push(entry.item);
        Ok(summary)
    }

    pub fn purge_api_environment_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .api_environment_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let id = payload.api_environment_trash[index].item.id;
        payload.api_environment_trash.remove(index);
        payload
            .api_environment_history
            .retain(|revision| revision.environment_id != id);
        Ok(())
    }

    pub fn api_environment_history(
        &self,
        id: Uuid,
    ) -> Result<Vec<ApiEnvironmentRevisionSummary>, VaultError> {
        if !self
            .payload()?
            .api_environments
            .iter()
            .any(|item| item.id == id)
        {
            return Err(VaultError::ApiEnvironmentNotFound);
        }
        let mut revisions = self
            .payload()?
            .api_environment_history
            .iter()
            .filter(|revision| revision.environment_id == id)
            .map(|revision| ApiEnvironmentRevisionSummary {
                revision_id: revision.revision_id,
                environment_id: revision.environment_id,
                name: revision.item.name.clone(),
                revision: revision.item.revision,
                saved_at: revision.saved_at,
            })
            .collect::<Vec<_>>();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_api_environment_revision(
        &mut self,
        id: Uuid,
        revision_id: Uuid,
    ) -> Result<ApiEnvironmentSummary, VaultError> {
        let current = self
            .payload()?
            .api_environments
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        let mut replacement = self
            .payload()?
            .api_environment_history
            .iter()
            .find(|revision| revision.revision_id == revision_id && revision.environment_id == id)
            .map(|revision| revision.item.clone())
            .ok_or(VaultError::RevisionNotFound)?;
        let input = record_input(&replacement);
        self.validate_environment_input(&input)?;
        let now = unix_time_now();
        self.push_api_environment_history(current.clone(), now)?;
        replacement.revision = current.revision.saturating_add(1);
        replacement.policy_digest =
            api_environment_policy_digest(&record_input(&replacement), replacement.revision)?;
        replacement.updated_at = now;
        let item = self
            .payload_mut()?
            .api_environments
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(VaultError::ApiEnvironmentNotFound)?;
        *item = replacement;
        Ok(api_environment_summary(item))
    }

    pub fn clear_api_environment_history(&mut self, id: Uuid) -> Result<(), VaultError> {
        if !self
            .payload()?
            .api_environments
            .iter()
            .any(|item| item.id == id)
        {
            return Err(VaultError::ApiEnvironmentNotFound);
        }
        crate::sync::record_history_clear(self.payload_mut()?, "api_environment_history", id)?;
        self.payload_mut()?
            .api_environment_history
            .retain(|revision| revision.environment_id != id);
        Ok(())
    }

    pub fn agent_api_environments(&self) -> Result<Vec<AgentApiEnvironmentSummary>, VaultError> {
        let payload = self.payload()?;
        let mut result = payload
            .api_environments
            .iter()
            .filter(|environment| {
                payload
                    .services
                    .iter()
                    .any(|service| service.id == environment.service_id)
            })
            .filter(|environment| api_environment_refs_live(payload, environment))
            .map(|environment| {
                let service = payload
                    .services
                    .iter()
                    .find(|service| service.id == environment.service_id)
                    .expect("filtered live service");
                AgentApiEnvironmentSummary {
                    environment_ref: environment.id,
                    label: format!("{} · {}", service.name, environment.name),
                    environment: environment.kind,
                    capability: "http".to_owned(),
                    openapi_url: environment.openapi_url.clone(),
                    revision: environment.revision,
                    policy_digest: environment.policy_digest.clone(),
                }
            })
            .collect::<Vec<_>>();
        result.sort_by(|left, right| {
            left.label
                .cmp(&right.label)
                .then(left.environment_ref.cmp(&right.environment_ref))
        });
        Ok(result)
    }

    fn validate_environment_input(&self, input: &NewApiEnvironment) -> Result<(), VaultError> {
        self.require_live_service(input.service_id)?;
        let payload = self.payload()?;
        let refs_valid = match &input.auth {
            ApiEnvironmentAuth::None => true,
            ApiEnvironmentAuth::Bearer { credential }
            | ApiEnvironmentAuth::ApiKey { credential, .. } => {
                credential_ref_live(payload, credential)
            }
            ApiEnvironmentAuth::Basic { username, password } => {
                credential_ref_live(payload, username) && credential_ref_live(payload, password)
            }
        } && input
            .fixed_headers
            .iter()
            .all(|header| match &header.source {
                ApiHeaderSource::Literal { .. } => true,
                ApiHeaderSource::Protected { credential } => {
                    credential_ref_live(payload, credential)
                }
            });
        if refs_valid {
            Ok(())
        } else {
            Err(VaultError::InvalidApiEnvironment)
        }
    }

    fn require_live_service(&self, service_id: Uuid) -> Result<(), VaultError> {
        if self
            .payload()?
            .services
            .iter()
            .any(|service| service.id == service_id)
        {
            Ok(())
        } else {
            Err(VaultError::ServiceNotFound)
        }
    }

    fn push_api_environment_history(
        &mut self,
        item: ApiEnvironmentRecord,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let environment_id = item.id;
        let history = &mut self.payload_mut()?.api_environment_history;
        history.push(ApiEnvironmentRevision {
            revision_id: Uuid::new_v4(),
            environment_id,
            saved_at,
            item,
        });
        while history
            .iter()
            .filter(|revision| revision.environment_id == environment_id)
            .count()
            > MAX_API_ENVIRONMENT_REVISIONS
        {
            let index = history
                .iter()
                .enumerate()
                .filter(|(_, revision)| revision.environment_id == environment_id)
                .min_by_key(|(_, revision)| revision.saved_at)
                .map(|(index, _)| index)
                .expect("history count checked");
            history.remove(index);
        }
        Ok(())
    }
}

pub(crate) fn bump_api_environments_for_service(payload: &mut VaultPayload, service_id: Uuid) {
    for item in payload
        .api_environments
        .iter_mut()
        .filter(|item| item.service_id == service_id)
    {
        let _ = bump_record_revision(item);
    }
}

pub(crate) fn bump_api_environments_for_credential(
    payload: &mut VaultPayload,
    item_kind: ApiCredentialItemKind,
    item_id: Uuid,
) {
    for item in &mut payload.api_environments {
        let matches_ref = |reference: &ApiCredentialRef| {
            reference.item_kind == item_kind && reference.item_id == item_id
        };
        let referenced = match &item.auth {
            ApiEnvironmentAuth::None => false,
            ApiEnvironmentAuth::Bearer { credential }
            | ApiEnvironmentAuth::ApiKey { credential, .. } => matches_ref(credential),
            ApiEnvironmentAuth::Basic { username, password } => {
                matches_ref(username) || matches_ref(password)
            }
        } || item
            .fixed_headers
            .iter()
            .any(|header| match &header.source {
                ApiHeaderSource::Literal { .. } => false,
                ApiHeaderSource::Protected { credential } => matches_ref(credential),
            });
        if referenced {
            let _ = bump_record_revision(item);
        }
    }
}

pub(crate) fn purge_api_environments_for_service(payload: &mut VaultPayload, service_id: Uuid) {
    let ids = payload
        .api_environments
        .iter()
        .filter(|item| item.service_id == service_id)
        .map(|item| item.id)
        .chain(
            payload
                .api_environment_trash
                .iter()
                .filter(|entry| entry.item.service_id == service_id)
                .map(|entry| entry.item.id),
        )
        .collect::<HashSet<_>>();
    payload
        .api_environments
        .retain(|item| item.service_id != service_id);
    payload
        .api_environment_trash
        .retain(|entry| entry.item.service_id != service_id);
    payload
        .api_environment_history
        .retain(|revision| !ids.contains(&revision.environment_id));
}

fn bump_record_revision(item: &mut ApiEnvironmentRecord) -> Result<(), VaultError> {
    item.revision = item.revision.saturating_add(1);
    item.policy_digest = api_environment_policy_digest(&record_input(item), item.revision)?;
    item.updated_at = unix_time_now();
    Ok(())
}

fn record_input(item: &ApiEnvironmentRecord) -> NewApiEnvironment {
    NewApiEnvironment {
        service_id: item.service_id,
        name: item.name.clone(),
        kind: item.kind,
        origin: item.origin.clone(),
        base_path: item.base_path.clone(),
        openapi_url: item.openapi_url.clone(),
        auth: item.auth.clone(),
        fixed_headers: item.fixed_headers.clone(),
    }
}

fn api_environment_summary(item: &ApiEnvironmentRecord) -> ApiEnvironmentSummary {
    ApiEnvironmentSummary {
        id: item.id,
        service_id: item.service_id,
        name: item.name.clone(),
        kind: item.kind,
        auth_kind: item.auth.kind_name().to_owned(),
        fixed_header_count: item.fixed_headers.len() as u32,
        revision: item.revision,
        policy_digest: item.policy_digest.clone(),
        created_at: item.created_at,
        updated_at: item.updated_at,
    }
}

fn api_environment_detail(item: &ApiEnvironmentRecord) -> ApiEnvironmentDetail {
    ApiEnvironmentDetail {
        id: item.id,
        service_id: item.service_id,
        name: item.name.clone(),
        kind: item.kind,
        origin: item.origin.clone(),
        base_path: item.base_path.clone(),
        openapi_url: item.openapi_url.clone(),
        auth: item.auth.clone(),
        fixed_headers: item.fixed_headers.clone(),
        revision: item.revision,
        policy_digest: item.policy_digest.clone(),
        created_at: item.created_at,
        updated_at: item.updated_at,
    }
}
