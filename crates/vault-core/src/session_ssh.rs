use super::*;

impl VaultSession {
    pub fn add_ssh_credential(
        &mut self,
        input: NewSshCredentialItem,
    ) -> Result<SshCredentialSummary, VaultError> {
        let item = input.into_ssh_credential()?;
        let summary = SshCredentialSummary::from(&item);
        self.payload_mut()?.ssh_items.push(item);
        Ok(summary)
    }

    /// Validates the complete batch before mutating and skips credentials whose
    /// public or private key material is already active in the vault.
    pub fn import_ssh_credentials(
        &mut self,
        inputs: Vec<NewSshCredentialItem>,
    ) -> Result<(Vec<SshCredentialSummary>, usize), VaultError> {
        let candidates: Vec<SshCredentialItem> = inputs
            .into_iter()
            .map(NewSshCredentialItem::into_ssh_credential)
            .collect::<Result<_, _>>()?;
        let payload = self.payload_mut()?;
        let mut imported = Vec::new();
        let mut skipped = 0;
        for candidate in candidates {
            let duplicate = payload.ssh_items.iter().any(|existing| {
                same_optional_public_key(
                    existing.public_key.as_deref(),
                    candidate.public_key.as_deref(),
                ) || same_optional_key(
                    existing.private_key.as_deref(),
                    candidate.private_key.as_deref(),
                )
            });
            if duplicate {
                skipped += 1;
            } else {
                imported.push(SshCredentialSummary::from(&candidate));
                payload.ssh_items.push(candidate);
            }
        }
        Ok((imported, skipped))
    }

    /// Checks active SSH records for matching key material without returning
    /// any stored key content to the caller.
    pub fn has_ssh_key_material(
        &self,
        public_key: Option<&str>,
        private_key: Option<&str>,
    ) -> Result<bool, VaultError> {
        Ok(self.payload()?.ssh_items.iter().any(|existing| {
            same_optional_public_key(existing.public_key.as_deref(), public_key)
                || same_optional_key(existing.private_key.as_deref(), private_key)
        }))
    }

    /// Resolves the encrypted owner of a managed OpenSSH alias. Aliases are
    /// globally unique because they share one per-user OpenSSH namespace.
    /// Any target or host-key drift fails closed instead of rebinding an
    /// existing local identity.
    pub fn managed_ssh_host_key_id(
        &self,
        account_id: Uuid,
        alias: &str,
        host_key_sha256: &str,
    ) -> Result<Option<Uuid>, VaultError> {
        validate_managed_ssh_alias(alias)?;
        validate_managed_ssh_host_key(host_key_sha256)?;
        let payload = self.payload()?;
        let account = payload
            .ssh_items
            .iter()
            .find(|item| item.id == account_id)
            .ok_or(VaultError::ItemNotFound)?;
        let account_host = account
            .host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .ok_or(VaultError::InvalidSshCredential)?;
        let account_username = account.username.trim();
        if account_username.is_empty() || account.port == 0 {
            return Err(VaultError::InvalidSshCredential);
        }
        let Some(item) = payload.ssh_items.iter().find(|item| {
            item.managed_ssh_host
                .as_ref()
                .is_some_and(|binding| binding.alias == alias)
        }) else {
            if payload
                .ssh_trash
                .iter()
                .any(|entry| managed_alias(&entry.item) == Some(alias))
                || payload
                    .ssh_history
                    .iter()
                    .any(|revision| managed_alias(&revision.item) == Some(alias))
            {
                return Err(VaultError::InvalidSshCredential);
            }
            return Ok(None);
        };
        let binding = item
            .managed_ssh_host
            .as_ref()
            .expect("managed binding was selected");
        if binding.account_id != account_id
            || !binding.host.trim().eq_ignore_ascii_case(account_host)
            || binding.port != account.port
            || binding.username.trim() != account_username
            || binding.host_key_sha256 != host_key_sha256
            || item.public_key.is_none()
            || item.private_key.is_none()
            || item.key_passphrase.is_some()
            || item
                .host
                .as_deref()
                .is_some_and(|host| !host.trim().is_empty())
            || !item.username.trim().is_empty()
        {
            return Err(VaultError::InvalidSshCredential);
        }
        Ok(Some(item.id))
    }

    /// Adds the generated key and its alias binding to the encrypted payload.
    /// Persistence remains owned by the runtime transaction surrounding this
    /// mutation.
    pub fn add_managed_ssh_host_key(
        &mut self,
        account_id: Uuid,
        alias: String,
        host_key_sha256: String,
        public_key: String,
        private_key: String,
    ) -> Result<Uuid, VaultError> {
        if self
            .managed_ssh_host_key_id(account_id, &alias, &host_key_sha256)?
            .is_some()
        {
            return Err(VaultError::InvalidSshCredential);
        }
        let (account_title, host, port, username) = {
            let account = self
                .payload()?
                .ssh_items
                .iter()
                .find(|item| item.id == account_id)
                .ok_or(VaultError::ItemNotFound)?;
            (
                account.title.trim().to_owned(),
                account
                    .host
                    .as_deref()
                    .map(str::trim)
                    .filter(|host| !host.is_empty())
                    .ok_or(VaultError::InvalidSshCredential)?
                    .to_owned(),
                account.port,
                account.username.trim().to_owned(),
            )
        };
        let mut item = NewSshCredentialItem {
            title: format!("{account_title} · {alias}"),
            host: None,
            port: 22,
            username: String::new(),
            password: None,
            public_key: Some(public_key),
            private_key: Some(private_key),
            key_passphrase: None,
            notes: None,
            folder: None,
            favorite: false,
            master_password_reprompt: false,
        }
        .into_ssh_credential()?;
        let id = item.id;
        item.managed_ssh_host = Some(ManagedSshHostBinding {
            account_id,
            alias,
            host,
            port,
            username,
            host_key_sha256,
        });
        self.payload_mut()?.ssh_items.push(item);
        Ok(id)
    }

    pub fn update_ssh_credential(
        &mut self,
        mut update: SshCredentialItemUpdate,
    ) -> Result<SshCredentialSummary, VaultError> {
        let item_index = self
            .payload()?
            .ssh_items
            .iter()
            .position(|item| item.id == update.id)
            .ok_or(VaultError::ItemNotFound)?;
        {
            let current = &self.payload()?.ssh_items[item_index];
            if current.managed_ssh_host.is_some()
                && (update.clear_public_key
                    || update.clear_private_key
                    || update.clear_key_passphrase
                    || update
                        .host
                        .as_deref()
                        .is_some_and(|host| !host.trim().is_empty())
                    || !update.username.trim().is_empty()
                    || update.port != current.port
                    || update.password.is_some()
                    || update.master_password_reprompt
                    || update
                        .public_key
                        .as_deref()
                        .is_some_and(|value| current.public_key.as_deref() != Some(value))
                    || update
                        .private_key
                        .as_deref()
                        .is_some_and(|value| current.private_key.as_deref() != Some(value))
                    || update.key_passphrase.is_some())
            {
                return Err(VaultError::InvalidSshCredential);
            }
            let password = if update.clear_password {
                None
            } else {
                update.password.as_deref().or(current.password.as_deref())
            };
            let public_key = if update.clear_public_key {
                None
            } else {
                update
                    .public_key
                    .as_deref()
                    .or(current.public_key.as_deref())
            };
            let private_key = if update.clear_private_key {
                None
            } else {
                update
                    .private_key
                    .as_deref()
                    .or(current.private_key.as_deref())
            };
            let key_passphrase = if update.clear_key_passphrase {
                None
            } else {
                update
                    .key_passphrase
                    .as_deref()
                    .or(current.key_passphrase.as_deref())
            };
            crate::model::validate_ssh_fields(
                &update.title,
                update.port,
                password,
                public_key,
                private_key,
                key_passphrase,
            )?;
        }
        let previous = self.payload()?.ssh_items[item_index].clone();
        self.push_ssh_history(previous, unix_time_now())?;
        let item = &mut self.payload_mut()?.ssh_items[item_index];
        item.title.zeroize();
        item.title = std::mem::take(&mut update.title);
        zeroize_option(&mut item.host);
        item.host = update.host.take();
        item.port = update.port;
        item.username.zeroize();
        item.username = std::mem::take(&mut update.username);
        replace_optional_secret(
            &mut item.password,
            update.password.take(),
            update.clear_password,
        );
        replace_optional_secret(
            &mut item.public_key,
            update.public_key.take(),
            update.clear_public_key,
        );
        replace_optional_secret(
            &mut item.private_key,
            update.private_key.take(),
            update.clear_private_key,
        );
        replace_optional_secret(
            &mut item.key_passphrase,
            update.key_passphrase.take(),
            update.clear_key_passphrase,
        );
        zeroize_option(&mut item.notes);
        item.notes = update.notes.take();
        zeroize_option(&mut item.folder);
        item.folder = update.folder.take();
        item.favorite = update.favorite;
        item.master_password_reprompt = update.master_password_reprompt;
        Ok(SshCredentialSummary::from(&*item))
    }

    pub fn delete_ssh_credential(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .ssh_items
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let item = payload.ssh_items.remove(index);
        payload.ssh_trash.push(TrashedSshCredential {
            trash_id: Uuid::new_v4(),
            deleted_at: unix_time_now(),
            item,
        });
        Ok(())
    }

    pub fn list_ssh_trash(&self) -> Result<Vec<SshCredentialTrashSummary>, VaultError> {
        Ok(self
            .payload()?
            .ssh_trash
            .iter()
            .map(SshCredentialTrashSummary::from)
            .collect())
    }

    pub fn restore_ssh_trash(
        &mut self,
        trash_id: Uuid,
    ) -> Result<SshCredentialSummary, VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .ssh_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let entry = payload.ssh_trash.remove(index);
        let item = entry.item.clone();
        let summary = SshCredentialSummary::from(&item);
        payload.ssh_items.push(item);
        Ok(summary)
    }

    pub fn purge_ssh_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .ssh_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let item_id = payload.ssh_trash[index].item.id;
        payload.ssh_trash.remove(index);
        payload
            .ssh_history
            .retain(|revision| revision.item_id != item_id);
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Ssh,
            &HashSet::from([item_id]),
        );
        Ok(())
    }

    pub fn empty_ssh_trash(&mut self) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let trashed_ids: HashSet<_> = payload
            .ssh_trash
            .iter()
            .map(|entry| entry.item.id)
            .collect();
        payload.ssh_trash.clear();
        payload
            .ssh_history
            .retain(|revision| !trashed_ids.contains(&revision.item_id));
        session_service::remove_service_relationships_in_payload(
            payload,
            ServiceItemKind::Ssh,
            &trashed_ids,
        );
        Ok(())
    }

    pub fn ssh_history(
        &self,
        item_id: Uuid,
    ) -> Result<Vec<SshCredentialRevisionSummary>, VaultError> {
        if !self
            .payload()?
            .ssh_items
            .iter()
            .any(|item| item.id == item_id)
        {
            return Err(VaultError::ItemNotFound);
        }
        let mut revisions: Vec<_> = self
            .payload()?
            .ssh_history
            .iter()
            .filter(|revision| revision.item_id == item_id)
            .map(SshCredentialRevisionSummary::from)
            .collect();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_ssh_revision(
        &mut self,
        item_id: Uuid,
        revision_id: Uuid,
    ) -> Result<SshCredentialSummary, VaultError> {
        let payload = self.payload()?;
        let item_index = payload
            .ssh_items
            .iter()
            .position(|item| item.id == item_id)
            .ok_or(VaultError::ItemNotFound)?;
        let revision = payload
            .ssh_history
            .iter()
            .find(|revision| revision.item_id == item_id && revision.revision_id == revision_id)
            .ok_or(VaultError::RevisionNotFound)?
            .item
            .clone();
        let current = payload.ssh_items[item_index].clone();
        self.push_ssh_history(current, unix_time_now())?;
        let item = &mut self.payload_mut()?.ssh_items[item_index];
        item.zeroize();
        *item = revision;
        Ok(SshCredentialSummary::from(&*item))
    }

    pub fn clear_ssh_history(&mut self, item_id: Uuid) -> Result<(), VaultError> {
        if !self
            .payload()?
            .ssh_items
            .iter()
            .any(|item| item.id == item_id)
        {
            return Err(VaultError::ItemNotFound);
        }
        crate::sync::record_history_clear(self.payload_mut()?, "ssh_history", item_id)?;
        self.payload_mut()?
            .ssh_history
            .retain(|revision| revision.item_id != item_id);
        Ok(())
    }

    pub fn list_ssh_credentials(&self) -> Result<Vec<SshCredentialSummary>, VaultError> {
        Ok(self
            .payload()?
            .ssh_items
            .iter()
            .map(SshCredentialSummary::from)
            .collect())
    }

    pub fn ssh_credential_detail(&self, id: Uuid) -> Result<SshCredentialDetail, VaultError> {
        self.payload()?
            .ssh_items
            .iter()
            .find(|item| item.id == id)
            .map(SshCredentialDetail::from)
            .ok_or(VaultError::ItemNotFound)
    }

    pub fn ssh_password_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        self.ssh_for_access(id, master_password)?
            .password
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_public_key_for_access(&self, id: Uuid) -> Result<&str, VaultError> {
        self.payload()?
            .ssh_items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?
            .public_key
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_private_key_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        self.ssh_for_access(id, master_password)?
            .private_key
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_key_passphrase_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        self.ssh_for_access(id, master_password)?
            .key_passphrase
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_password_for_fill(&self, id: Uuid) -> Result<&str, VaultError> {
        self.ssh_for_fill(id)?
            .password
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_private_key_for_fill(&self, id: Uuid) -> Result<&str, VaultError> {
        self.ssh_for_fill(id)?
            .private_key
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }

    pub fn ssh_key_passphrase_for_fill(&self, id: Uuid) -> Result<&str, VaultError> {
        self.ssh_for_fill(id)?
            .key_passphrase
            .as_deref()
            .ok_or(VaultError::SshSecretUnavailable)
    }
}

fn validate_managed_ssh_alias(alias: &str) -> Result<(), VaultError> {
    let bytes = alias.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
        || bytes.iter().any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && !matches!(byte, b'.' | b'_' | b'-')
        })
        || matches!(alias, "." | "..")
    {
        return Err(VaultError::InvalidSshCredential);
    }
    Ok(())
}

fn managed_alias(item: &SshCredentialItem) -> Option<&str> {
    item.managed_ssh_host
        .as_ref()
        .map(|binding| binding.alias.as_str())
}

fn validate_managed_ssh_host_key(value: &str) -> Result<(), VaultError> {
    let valid = value.strip_prefix("SHA256:").is_some_and(|digest| {
        digest.len() == 43
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    });
    if valid {
        Ok(())
    } else {
        Err(VaultError::InvalidSshCredential)
    }
}
