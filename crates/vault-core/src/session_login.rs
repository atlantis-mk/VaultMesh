use super::*;

impl VaultSession {
    pub fn add_item(&mut self, input: NewLoginItem) -> Result<LoginItemSummary, VaultError> {
        let payload = self.payload_mut()?;
        let mut item = input.into_login_item()?;
        item.password_changed_at = unix_time_now();
        let summary = LoginItemSummary::from(&item);
        payload.items.push(item);
        Ok(summary)
    }

    pub fn update_item(
        &mut self,
        mut update: LoginItemUpdate,
    ) -> Result<LoginItemSummary, VaultError> {
        let normalized_totp_secret = update
            .totp_secret
            .as_deref()
            .map(crate::normalize_totp_secret)
            .transpose()?;
        if let Some(codes) = update.recovery_codes.as_deref() {
            if codes.is_empty() || update.clear_recovery_codes {
                return Err(VaultError::InvalidRecoveryCodes);
            }
            crate::model::validate_recovery_codes(codes)?;
        }
        let item_index = self
            .payload()?
            .items
            .iter()
            .position(|item| item.id == update.id)
            .ok_or(VaultError::ItemNotFound)?;
        let previous = self.payload()?.items[item_index].clone();
        let changed_at = unix_time_now();
        self.push_history(previous, changed_at)?;
        let item = &mut self.payload_mut()?.items[item_index];

        item.title.zeroize();
        item.title = std::mem::take(&mut update.title);
        item.username.zeroize();
        item.username = std::mem::take(&mut update.username);
        if let Some(mut password) = update.password.take() {
            item.password.zeroize();
            item.password = std::mem::take(&mut password);
            item.password_changed_at = changed_at;
        }
        zeroize_option(&mut item.url);
        item.url = update.url.take();
        zeroize_option(&mut item.notes);
        item.notes = update.notes.take();
        zeroize_option(&mut item.folder);
        item.folder = update.folder.take();
        item.favorite = update.favorite;
        if update.clear_totp_secret {
            zeroize_option(&mut item.totp_secret);
            item.totp_secret = None;
        } else if let Some(mut totp_secret) = normalized_totp_secret {
            zeroize_option(&mut item.totp_secret);
            item.totp_secret = Some(std::mem::take(&mut totp_secret));
        }
        if update.clear_recovery_codes {
            item.recovery_codes.zeroize();
            item.recovery_codes.clear();
        } else if let Some(mut recovery_codes) = update.recovery_codes.take() {
            item.recovery_codes.zeroize();
            item.recovery_codes = std::mem::take(&mut recovery_codes);
        }
        item.additional_urls.zeroize();
        item.additional_urls = std::mem::take(&mut update.additional_urls);
        item.autofill_on_page_load = update.autofill_on_page_load;
        item.master_password_reprompt = update.master_password_reprompt;
        item.custom_fields.zeroize();
        item.custom_fields = std::mem::take(&mut update.custom_fields);

        let summary = LoginItemSummary::from(&*item);
        session_api_environment::bump_api_environments_for_credential(
            self.payload_mut()?,
            ApiCredentialItemKind::Login,
            update.id,
        );
        Ok(summary)
    }

    pub fn delete_item(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .items
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let item = payload.items.remove(index);
        session_api_environment::bump_api_environments_for_credential(
            payload,
            ApiCredentialItemKind::Login,
            id,
        );
        payload.trash.push(TrashedLoginItem {
            trash_id: Uuid::new_v4(),
            deleted_at: unix_time_now(),
            item,
        });
        Ok(())
    }

    pub fn list_trash(&self) -> Result<Vec<TrashItemSummary>, VaultError> {
        Ok(self
            .payload()?
            .trash
            .iter()
            .map(TrashItemSummary::from)
            .collect())
    }

    pub fn restore_trash(&mut self, trash_id: Uuid) -> Result<LoginItemSummary, VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let entry = payload.trash.remove(index);
        let item = entry.item.clone();
        session_api_environment::bump_api_environments_for_credential(
            payload,
            ApiCredentialItemKind::Login,
            item.id,
        );
        let summary = LoginItemSummary::from(&item);
        payload.items.push(item);
        Ok(summary)
    }

    pub fn purge_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let item_id = payload.trash[index].item.id;
        payload.trash.remove(index);
        session_api_environment::bump_api_environments_for_credential(
            payload,
            ApiCredentialItemKind::Login,
            item_id,
        );
        payload
            .history
            .retain(|revision| revision.item_id != item_id);
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Login,
            &HashSet::from([item_id]),
        );
        Ok(())
    }

    pub fn empty_trash(&mut self) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let trashed_ids: HashSet<_> = payload.trash.iter().map(|entry| entry.item.id).collect();
        payload.trash.clear();
        for id in &trashed_ids {
            session_api_environment::bump_api_environments_for_credential(
                payload,
                ApiCredentialItemKind::Login,
                *id,
            );
        }
        payload
            .history
            .retain(|revision| !trashed_ids.contains(&revision.item_id));
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Login,
            &trashed_ids,
        );
        Ok(())
    }

    pub fn item_history(&self, item_id: Uuid) -> Result<Vec<LoginItemRevisionSummary>, VaultError> {
        if !self.payload()?.items.iter().any(|item| item.id == item_id) {
            return Err(VaultError::ItemNotFound);
        }
        let mut revisions: Vec<_> = self
            .payload()?
            .history
            .iter()
            .filter(|revision| revision.item_id == item_id)
            .map(LoginItemRevisionSummary::from)
            .collect();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_revision(
        &mut self,
        item_id: Uuid,
        revision_id: Uuid,
    ) -> Result<LoginItemSummary, VaultError> {
        let payload = self.payload()?;
        let item_index = payload
            .items
            .iter()
            .position(|item| item.id == item_id)
            .ok_or(VaultError::ItemNotFound)?;
        let revision = payload
            .history
            .iter()
            .find(|revision| revision.item_id == item_id && revision.revision_id == revision_id)
            .ok_or(VaultError::RevisionNotFound)?
            .item
            .clone();
        let current = payload.items[item_index].clone();
        let saved_at = unix_time_now();
        self.push_history(current, saved_at)?;
        let item = &mut self.payload_mut()?.items[item_index];
        item.zeroize();
        *item = revision;
        let summary = LoginItemSummary::from(&*item);
        session_api_environment::bump_api_environments_for_credential(
            self.payload_mut()?,
            ApiCredentialItemKind::Login,
            item_id,
        );
        Ok(summary)
    }

    pub fn clear_history(&mut self, item_id: Uuid) -> Result<(), VaultError> {
        if !self.payload()?.items.iter().any(|item| item.id == item_id) {
            return Err(VaultError::ItemNotFound);
        }
        crate::sync::record_history_clear(self.payload_mut()?, "history", item_id)?;
        self.payload_mut()?
            .history
            .retain(|revision| revision.item_id != item_id);
        Ok(())
    }

    pub fn list_items(&self) -> Result<Vec<LoginItemSummary>, VaultError> {
        Ok(self
            .payload()?
            .items
            .iter()
            .map(LoginItemSummary::from)
            .collect())
    }

    /// Returns the renderer-safe login metadata needed to match browser
    /// candidates in one pass. Protected values remain excluded.
    pub fn list_item_details(&self) -> Result<Vec<LoginItemDetail>, VaultError> {
        Ok(self
            .payload()?
            .items
            .iter()
            .map(LoginItemDetail::from)
            .collect())
    }

    pub fn item_detail(&self, id: Uuid) -> Result<LoginItemDetail, VaultError> {
        self.payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .map(LoginItemDetail::from)
            .ok_or(VaultError::ItemNotFound)
    }

    /// Returns a password for a privileged platform operation such as copying
    /// to the clipboard. It must never be exposed by the renderer list API.
    pub fn password_for_copy(&self, id: Uuid) -> Result<&str, VaultError> {
        self.payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.password.as_str())
            .ok_or(VaultError::ItemNotFound)
    }

    pub fn password_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        let item = self
            .payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        self.enforce_reprompt(item.master_password_reprompt, master_password)?;
        Ok(item.password.as_str())
    }

    /// Produces a current TOTP code without returning the long-lived seed.
    pub fn totp_code(&self, id: Uuid, unix_time: u64) -> Result<TotpCode, VaultError> {
        let secret = self
            .payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?
            .totp_secret
            .as_deref()
            .ok_or(VaultError::TotpUnavailable)?;
        crate::totp::generate_totp(secret, unix_time)
    }

    pub fn totp_code_for_access(
        &self,
        id: Uuid,
        unix_time: u64,
        master_password: Option<&str>,
    ) -> Result<TotpCode, VaultError> {
        let item = self
            .payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        self.enforce_reprompt(item.master_password_reprompt, master_password)?;
        let secret = item
            .totp_secret
            .as_deref()
            .ok_or(VaultError::TotpUnavailable)?;
        crate::totp::generate_totp(secret, unix_time)
    }

    /// Returns recovery codes only after unconditional master-password
    /// verification. This policy is independent of the Login re-prompt flag.
    pub fn recovery_codes_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&[String], VaultError> {
        let master_password = master_password.ok_or(VaultError::MasterPasswordRequired)?;
        self.verify_master_password(master_password)?;
        let item = self
            .payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        if item.recovery_codes.is_empty() {
            return Err(VaultError::RecoveryCodesUnavailable);
        }
        Ok(&item.recovery_codes)
    }

    /// Selects one recovery code for a broker-owned, freshly confirmed
    /// protected action. This API is intentionally not exposed through the C
    /// ABI or renderer operation dispatcher.
    pub fn agent_recovery_code_for_consumption(&self, id: Uuid) -> Result<&str, VaultError> {
        self.payload()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?
            .recovery_codes
            .first()
            .map(String::as_str)
            .ok_or(VaultError::RecoveryCodesUnavailable)
    }

    /// Removes exactly the recovery code whose digest was submitted and
    /// accepted by the remote target. A changed or already-consumed code
    /// fails closed instead of removing another entry.
    pub fn consume_agent_recovery_code(
        &mut self,
        id: Uuid,
        expected_sha256: &[u8; 32],
    ) -> Result<usize, VaultError> {
        let item_index = self
            .payload()?
            .items
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let code_index = self.payload()?.items[item_index]
            .recovery_codes
            .iter()
            .position(|code| Sha256::digest(code.as_bytes()).as_slice() == expected_sha256)
            .ok_or(VaultError::RecoveryCodesUnavailable)?;
        let previous = self.payload()?.items[item_index].clone();
        self.push_history(previous, unix_time_now())?;
        let item = &mut self.payload_mut()?.items[item_index];
        let mut consumed = item.recovery_codes.remove(code_index);
        consumed.zeroize();
        Ok(item.recovery_codes.len())
    }

    pub fn verify_master_password(&self, master_password: &str) -> Result<(), VaultError> {
        let candidate = unlock_key(master_password, &self.header)?;
        let current = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        if candidate.as_ref() == current.as_ref() {
            Ok(())
        } else {
            Err(VaultError::UnlockFailed)
        }
    }

    pub fn change_master_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), VaultError> {
        self.verify_master_password(current_password)?;
        let vault_key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        self.header = rewrap_header(new_password, vault_key)?;
        Ok(())
    }

    pub fn autofill_candidates(&self, page_url: &str) -> Result<Vec<LoginItemSummary>, VaultError> {
        let host = normalized_http_host(page_url).ok_or(VaultError::InvalidUrl)?;
        Ok(self
            .payload()?
            .items
            .iter()
            .filter(|item| item.autofill_on_page_load)
            .filter(|item| {
                item.url
                    .iter()
                    .chain(item.additional_urls.iter())
                    .any(|url| normalized_http_host(url).as_deref() == Some(host.as_str()))
            })
            .map(LoginItemSummary::from)
            .collect())
    }

    pub fn password_health(&self, unix_time: u64) -> Result<PasswordHealthReport, VaultError> {
        let items = &self.payload()?.items;
        let weak_item_ids: Vec<Uuid> = items
            .iter()
            .filter(|item| is_weak(&item.password))
            .map(|item| item.id)
            .collect();
        let old_item_ids: Vec<Uuid> = items
            .iter()
            .filter(|item| {
                item.password_changed_at > 0
                    && unix_time.saturating_sub(item.password_changed_at) >= OLD_PASSWORD_SECONDS
            })
            .map(|item| item.id)
            .collect();
        let mut by_password: HashMap<&str, Vec<Uuid>> = HashMap::new();
        for item in items {
            by_password
                .entry(item.password.as_str())
                .or_default()
                .push(item.id);
        }
        let reused_item_ids: Vec<Uuid> = by_password
            .values()
            .filter(|ids| ids.len() > 1)
            .flatten()
            .copied()
            .collect();
        let mut affected = HashSet::new();
        for id in weak_item_ids
            .iter()
            .chain(old_item_ids.iter())
            .chain(reused_item_ids.iter())
        {
            affected.insert(*id);
        }
        let score = if items.is_empty() {
            100
        } else {
            (((items.len() - affected.len()) * 100) / items.len()) as u32
        };
        Ok(PasswordHealthReport {
            weak_item_ids,
            reused_item_ids,
            old_item_ids,
            score,
        })
    }
}
