use super::*;

impl VaultSession {
    /// Creates a new, empty, unlocked session.
    pub fn create(master_password: &str) -> Result<Self, VaultError> {
        Self::create_with_payload(master_password, VaultPayload::default())
    }

    pub(crate) fn create_with_payload(
        master_password: &str,
        payload: VaultPayload,
    ) -> Result<Self, VaultError> {
        let (header, vault_key) = create_header(master_password)?;
        Ok(Self {
            header,
            vault_key: Some(vault_key),
            payload: Some(payload),
        })
    }

    /// Unlocks encrypted bytes and retains the vault key only until `lock` or
    /// drop.
    pub fn unlock(master_password: &str, encrypted_vault: &[u8]) -> Result<Self, VaultError> {
        let envelope = parse_envelope(encrypted_vault)?;
        let vault_key = unlock_key(master_password, &envelope.header)?;
        Self::unlock_envelope_with_key(envelope, vault_key)
    }

    /// Explicit, master-password-only migration. The runtime must preserve the
    /// original encrypted bytes before committing the returned format-4 session.
    pub fn upgrade_format3(master_password: &str, bytes: &[u8]) -> Result<Self, VaultError> {
        let envelope = crate::format::parse_format3_for_upgrade(bytes)?;
        let key = unlock_key(master_password, &envelope.header)?;
        let payload = decrypt_payload(&envelope, &key)?;
        let header = rewrap_header(master_password, &key)?;
        let mut session = Self {
            header,
            vault_key: Some(key),
            payload: Some(payload),
        };
        session.sync_reset_after_restore()?;
        session.sync_checkpoint(0)?;
        Ok(session)
    }

    /// Unlocks encrypted bytes using the random vault key rather than the
    /// master password. Platform integrations use this only after a local
    /// user-presence check has released their device-bound quick-unlock
    /// wrapper; it must never be exposed to untrusted UI code.
    pub fn unlock_with_vault_key(
        vault_key: &[u8],
        encrypted_vault: &[u8],
    ) -> Result<Self, VaultError> {
        if vault_key.len() != KEY_LEN {
            return Err(VaultError::UnlockFailed);
        }
        let envelope = parse_envelope(encrypted_vault)?;
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        key.copy_from_slice(vault_key);
        Self::unlock_envelope_with_key(envelope, key)
    }

    /// Makes a short-lived copy of the random vault key for a privileged
    /// platform quick-unlock wrapper. The caller is responsible for storing
    /// it only in an OS-protected credential store and zeroizing its copy.
    pub fn quick_unlock_key(&self) -> Result<Zeroizing<VaultKey>, VaultError> {
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        key.copy_from_slice(self.vault_key.as_ref().ok_or(VaultError::Locked)?.as_ref());
        Ok(key)
    }

    pub(super) fn unlock_envelope_with_key(
        envelope: crate::VaultEnvelope,
        vault_key: Zeroizing<VaultKey>,
    ) -> Result<Self, VaultError> {
        let payload = decrypt_payload(&envelope, &vault_key)?;
        Ok(Self {
            header: envelope.header,
            vault_key: Some(vault_key),
            payload: Some(payload),
        })
    }

    pub fn is_locked(&self) -> bool {
        self.vault_key.is_none() || self.payload.is_none()
    }

    pub fn format_version(&self) -> Result<u16, VaultError> {
        self.payload()?;
        Ok(self.header.format_version)
    }

    /// Serializes a fresh authenticated payload while retaining the same
    /// wrapped vault key and KDF parameters.
    pub fn save(&self) -> Result<Vec<u8>, VaultError> {
        let vault_key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        encrypt_payload(&self.header, vault_key, self.payload()?)
    }

    /// Creates a short-lived transaction snapshot. Callers must drop it as
    /// soon as persistence has succeeded or rollback is complete.
    pub fn payload_snapshot(&self) -> Result<VaultPayload, VaultError> {
        Ok(self.payload()?.clone())
    }

    pub fn restore_payload_snapshot(&mut self, snapshot: VaultPayload) -> Result<(), VaultError> {
        let current = self.payload.as_mut().ok_or(VaultError::Locked)?;
        current.zeroize();
        *current = snapshot;
        Ok(())
    }

    /// Clears the vault key and all decrypted item fields. Idempotent.
    pub fn lock(&mut self) {
        if let Some(mut payload) = self.payload.take() {
            payload.zeroize();
        }
        self.vault_key.take();
    }

    pub(crate) fn payload(&self) -> Result<&VaultPayload, VaultError> {
        self.payload.as_ref().ok_or(VaultError::Locked)
    }

    pub(crate) fn payload_mut(&mut self) -> Result<&mut VaultPayload, VaultError> {
        self.payload.as_mut().ok_or(VaultError::Locked)
    }

    pub(super) fn push_history(
        &mut self,
        item: crate::LoginItem,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let item_id = item.id;
        let payload = self.payload_mut()?;
        payload.history.push(LoginItemRevision {
            revision_id: Uuid::new_v4(),
            item_id,
            saved_at,
            item,
        });
        let matching: Vec<_> = payload
            .history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.item_id == item_id)
            .map(|(index, revision)| (index, revision.saved_at))
            .collect();
        if matching.len() > MAX_REVISIONS_PER_ITEM
            && let Some((oldest, _)) = matching.into_iter().min_by_key(|(_, saved_at)| *saved_at)
        {
            payload.history.remove(oldest);
        }
        Ok(())
    }

    pub(super) fn push_card_history(
        &mut self,
        item: PaymentCardItem,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let item_id = item.id;
        let payload = self.payload_mut()?;
        payload.card_history.push(PaymentCardRevision {
            revision_id: Uuid::new_v4(),
            item_id,
            saved_at,
            item,
        });
        let matching: Vec<_> = payload
            .card_history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.item_id == item_id)
            .map(|(index, revision)| (index, revision.saved_at))
            .collect();
        if matching.len() > MAX_REVISIONS_PER_ITEM
            && let Some((oldest, _)) = matching.into_iter().min_by_key(|(_, saved_at)| *saved_at)
        {
            payload.card_history.remove(oldest);
        }
        Ok(())
    }

    pub(super) fn push_identity_history(
        &mut self,
        item: crate::IdentityItem,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let item_id = item.id;
        let payload = self.payload_mut()?;
        payload.identity_history.push(IdentityRevision {
            revision_id: Uuid::new_v4(),
            item_id,
            saved_at,
            item,
        });
        let matching: Vec<_> = payload
            .identity_history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.item_id == item_id)
            .map(|(index, revision)| (index, revision.saved_at))
            .collect();
        if matching.len() > MAX_REVISIONS_PER_ITEM
            && let Some((oldest, _)) = matching.into_iter().min_by_key(|(_, saved_at)| *saved_at)
        {
            payload.identity_history.remove(oldest);
        }
        Ok(())
    }

    pub(super) fn push_ssh_history(
        &mut self,
        item: SshCredentialItem,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let item_id = item.id;
        let payload = self.payload_mut()?;
        payload.ssh_history.push(SshCredentialRevision {
            revision_id: Uuid::new_v4(),
            item_id,
            saved_at,
            item,
        });
        let matching: Vec<_> = payload
            .ssh_history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.item_id == item_id)
            .map(|(index, revision)| (index, revision.saved_at))
            .collect();
        if matching.len() > MAX_REVISIONS_PER_ITEM
            && let Some((oldest, _)) = matching.into_iter().min_by_key(|(_, saved_at)| *saved_at)
        {
            payload.ssh_history.remove(oldest);
        }
        Ok(())
    }

    pub(super) fn card_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&PaymentCardItem, VaultError> {
        let item = self
            .payload()?
            .cards
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        self.enforce_reprompt(item.master_password_reprompt, master_password)?;
        Ok(item)
    }

    pub(super) fn ssh_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&SshCredentialItem, VaultError> {
        let item = self
            .payload()?
            .ssh_items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        self.enforce_reprompt(item.master_password_reprompt, master_password)?;
        Ok(item)
    }

    pub(super) fn ssh_for_fill(&self, id: Uuid) -> Result<&SshCredentialItem, VaultError> {
        self.payload()?
            .ssh_items
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)
    }

    pub(super) fn enforce_reprompt(
        &self,
        required: bool,
        master_password: Option<&str>,
    ) -> Result<(), VaultError> {
        if !required {
            return Ok(());
        }
        let password = master_password.ok_or(VaultError::MasterPasswordRequired)?;
        self.verify_master_password(password)
    }
}
