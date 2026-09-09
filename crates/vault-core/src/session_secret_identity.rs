use super::*;
use crate::SecretItemKind;

impl VaultSession {
    pub fn add_secret(&mut self, input: NewSecretItem) -> Result<SecretItemSummary, VaultError> {
        let item = input.into_secret_item()?;
        let summary = SecretItemSummary::from(&item);
        self.payload_mut()?.secrets.push(item);
        Ok(summary)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretItemSummary>, VaultError> {
        Ok(self
            .payload()?
            .secrets
            .iter()
            .map(SecretItemSummary::from)
            .collect())
    }

    pub fn secret_detail(&self, id: Uuid) -> Result<SecretItemDetail, VaultError> {
        self.payload()?
            .secrets
            .iter()
            .find(|item| item.id == id)
            .map(SecretItemDetail::from)
            .ok_or(VaultError::ItemNotFound)
    }

    pub fn update_secret(
        &mut self,
        mut update: SecretItemUpdate,
    ) -> Result<SecretItemSummary, VaultError> {
        let index = self
            .payload()?
            .secrets
            .iter()
            .position(|item| item.id == update.id)
            .ok_or(VaultError::ItemNotFound)?;
        let existing_secret = self.payload()?.secrets[index].secret.clone();
        let lifecycle_scopes = self.payload()?.secrets[index]
            .scopes
            .iter()
            .filter(|scope| scope.starts_with("vaultmesh:credential-lifecycle:"))
            .cloned()
            .collect::<Vec<_>>();
        if !lifecycle_scopes.is_empty() && update.kind != SecretItemKind::AccessToken {
            return Err(VaultError::InvalidSecretItem);
        }
        let input = NewSecretItem {
            title: std::mem::take(&mut update.title),
            kind: update.kind.clone(),
            provider: update.provider.take(),
            account: update.account.take(),
            secret: update.secret.take().unwrap_or(existing_secret),
            environment: update.environment.take(),
            scopes: std::mem::take(&mut update.scopes),
            expires_at: update.expires_at.take(),
            website: update.website.take(),
            notes: update.notes.take(),
            folder: update.folder.take(),
            favorite: update.favorite,
            master_password_reprompt: update.master_password_reprompt,
        };
        let mut replacement = input.into_secret_item()?;
        replacement.scopes.extend(lifecycle_scopes);
        replacement.id = update.id;
        let item = &mut self.payload_mut()?.secrets[index];
        item.zeroize();
        *item = replacement;
        let summary = SecretItemSummary::from(&*item);
        session_api_environment::bump_api_environments_for_credential(
            self.payload_mut()?,
            ApiCredentialItemKind::Secret,
            update.id,
        );
        Ok(summary)
    }

    pub fn delete_secret(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .secrets
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        payload.secrets.remove(index);
        session_api_environment::bump_api_environments_for_credential(
            payload,
            ApiCredentialItemKind::Secret,
            id,
        );
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Secret,
            &HashSet::from([id]),
        );
        Ok(())
    }

    pub fn secret_value_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<Zeroizing<String>, VaultError> {
        let item = self
            .payload()?
            .secrets
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        self.enforce_reprompt(item.master_password_reprompt, master_password)?;
        Ok(Zeroizing::new(item.secret.clone()))
    }

    /// Browser-fill access is governed by the browser broker. Unlike copy,
    /// non-card fills do not apply an item-level master-password re-prompt.
    pub fn secret_value_for_fill(&self, id: Uuid) -> Result<Zeroizing<String>, VaultError> {
        let item = self
            .payload()?
            .secrets
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        Ok(Zeroizing::new(item.secret.clone()))
    }

    pub fn add_identity(&mut self, input: NewIdentityItem) -> Result<IdentitySummary, VaultError> {
        let item = input.into_identity()?;
        let summary = IdentitySummary::from(&item);
        self.payload_mut()?.identities.push(item);
        Ok(summary)
    }

    pub fn list_identities(&self) -> Result<Vec<IdentitySummary>, VaultError> {
        Ok(self
            .payload()?
            .identities
            .iter()
            .map(IdentitySummary::from)
            .collect())
    }

    /// Searches decrypted identity fields inside the trusted vault boundary and
    /// returns only renderer-safe summaries.
    pub fn search_identities(&self, query: &str) -> Result<Vec<IdentitySummary>, VaultError> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return self.list_identities();
        }
        Ok(self
            .payload()?
            .identities
            .iter()
            .filter(|item| identity_matches_query(item, &query))
            .map(IdentitySummary::from)
            .collect())
    }

    pub fn identity_detail(&self, id: Uuid) -> Result<IdentityDetail, VaultError> {
        self.payload()?
            .identities
            .iter()
            .find(|item| item.id == id)
            .map(IdentityDetail::from)
            .ok_or(VaultError::ItemNotFound)
    }

    pub fn update_identity(
        &mut self,
        input: NewIdentityItem,
        id: Uuid,
    ) -> Result<IdentitySummary, VaultError> {
        let mut replacement = input.into_identity()?;
        let index = self
            .payload()?
            .identities
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let previous = self.payload()?.identities[index].clone();
        self.push_identity_history(previous, unix_time_now())?;
        replacement.id = id;
        let item = &mut self.payload_mut()?.identities[index];
        item.zeroize();
        *item = replacement;
        Ok(IdentitySummary::from(&*item))
    }

    pub fn delete_identity(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .identities
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let item = payload.identities.remove(index);
        payload.identity_trash.push(TrashedIdentity {
            trash_id: Uuid::new_v4(),
            deleted_at: unix_time_now(),
            item,
        });
        Ok(())
    }

    pub fn list_identity_trash(&self) -> Result<Vec<IdentityTrashSummary>, VaultError> {
        Ok(self
            .payload()?
            .identity_trash
            .iter()
            .map(IdentityTrashSummary::from)
            .collect())
    }

    pub fn restore_identity_trash(
        &mut self,
        trash_id: Uuid,
    ) -> Result<IdentitySummary, VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .identity_trash
            .iter()
            .position(|item| item.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let entry = payload.identity_trash.remove(index);
        let item = entry.item.clone();
        let summary = IdentitySummary::from(&item);
        payload.identities.push(item);
        Ok(summary)
    }

    pub fn purge_identity_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .identity_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let item_id = payload.identity_trash[index].item.id;
        payload.identity_trash.remove(index);
        payload
            .identity_history
            .retain(|revision| revision.item_id != item_id);
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Identity,
            &HashSet::from([item_id]),
        );
        Ok(())
    }

    pub fn empty_identity_trash(&mut self) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let trashed_ids: HashSet<_> = payload
            .identity_trash
            .iter()
            .map(|entry| entry.item.id)
            .collect();
        payload.identity_trash.clear();
        payload
            .identity_history
            .retain(|revision| !trashed_ids.contains(&revision.item_id));
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Identity,
            &trashed_ids,
        );
        Ok(())
    }

    pub fn identity_history(
        &self,
        item_id: Uuid,
    ) -> Result<Vec<IdentityRevisionSummary>, VaultError> {
        if !self
            .payload()?
            .identities
            .iter()
            .any(|item| item.id == item_id)
        {
            return Err(VaultError::ItemNotFound);
        }
        let mut revisions: Vec<_> = self
            .payload()?
            .identity_history
            .iter()
            .filter(|revision| revision.item_id == item_id)
            .map(IdentityRevisionSummary::from)
            .collect();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_identity_revision(
        &mut self,
        item_id: Uuid,
        revision_id: Uuid,
    ) -> Result<IdentitySummary, VaultError> {
        let payload = self.payload()?;
        let item_index = payload
            .identities
            .iter()
            .position(|item| item.id == item_id)
            .ok_or(VaultError::ItemNotFound)?;
        let revision = payload
            .identity_history
            .iter()
            .find(|revision| revision.item_id == item_id && revision.revision_id == revision_id)
            .ok_or(VaultError::RevisionNotFound)?
            .item
            .clone();
        let current = payload.identities[item_index].clone();
        self.push_identity_history(current, unix_time_now())?;
        let item = &mut self.payload_mut()?.identities[item_index];
        item.zeroize();
        *item = revision;
        Ok(IdentitySummary::from(&*item))
    }

    pub fn clear_identity_history(&mut self, item_id: Uuid) -> Result<(), VaultError> {
        if !self
            .payload()?
            .identities
            .iter()
            .any(|item| item.id == item_id)
        {
            return Err(VaultError::ItemNotFound);
        }
        crate::sync::record_history_clear(self.payload_mut()?, "identity_history", item_id)?;
        self.payload_mut()?
            .identity_history
            .retain(|revision| revision.item_id != item_id);
        Ok(())
    }
}
