impl DesktopRuntime {
    pub fn managed_ssh_host_key(
        &mut self,
        account_id: Uuid,
        alias: &str,
        host_key_sha256: &str,
    ) -> Result<Option<ManagedSshHostKeyMaterial>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        managed_ssh_host_key_material(&vault.session, account_id, alias, host_key_sha256)
            .map_err(map_runtime_core_error)
    }

    pub fn add_managed_ssh_host_key(
        &mut self,
        account_id: Uuid,
        alias: String,
        host_key_sha256: String,
        public_key: Zeroizing<String>,
        private_key: Zeroizing<String>,
    ) -> Result<ManagedSshHostKeyMaterial, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let lookup_alias = alias.clone();
        let lookup_host_key = host_key_sha256.clone();
        let result = transaction(vault, |session| {
            session
                .add_managed_ssh_host_key(
                    account_id,
                    alias,
                    host_key_sha256,
                    public_key.to_string(),
                    private_key.to_string(),
                )
                .map(|id| json!({ "id": id }))
                .map_err(map_core_error)
        });
        result.map_err(DesktopRuntimeError::from)?;
        managed_ssh_host_key_material(
            &vault.session,
            account_id,
            &lookup_alias,
            &lookup_host_key,
        )
        .map_err(map_runtime_core_error)?
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_CORE_ERROR))
    }

pub fn record_agent_audit(
        &mut self,
        event: NewAgentAuditEvent,
    ) -> Result<AgentAuditEvent, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |session| {
            session
                .record_agent_audit(event)
                .map_err(map_core_error)
                .and_then(|event| {
                    serde_json::to_value(event).map_err(|_| VAULTMESH_STATUS_CORE_ERROR)
                })
        })
        .and_then(|value| serde_json::from_value(value).map_err(|_| VAULTMESH_STATUS_CORE_ERROR))
        .map_err(Into::into)
    }

    pub fn clear_agent_audit(&mut self) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |session| {
            session
                .clear_agent_audit()
                .map(|()| json!({}))
                .map_err(map_core_error)
        })
        .map(|_| ())
        .map_err(Into::into)
    }

    pub fn add_agent_connector_definition(
        &mut self,
        input: NewAgentConnectorDefinition,
        now: u64,
    ) -> Result<AgentConnectorDefinitionSummary, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let result = transaction(vault, |session| {
            session
                .add_agent_connector_definition(input, now)
                .map_err(map_core_error)
                .and_then(|summary| {
                    serde_json::to_value(summary).map_err(|_| VAULTMESH_STATUS_CORE_ERROR)
                })
        });
        result
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| VAULTMESH_STATUS_CORE_ERROR)
            })
            .map_err(Into::into)
    }

    pub fn update_agent_connector_definition(
        &mut self,
        id: Uuid,
        input: NewAgentConnectorDefinition,
        now: u64,
    ) -> Result<AgentConnectorDefinitionSummary, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |session| {
            session
                .update_agent_connector_definition(id, input, now)
                .map_err(map_core_error)
                .and_then(|summary| {
                    serde_json::to_value(summary).map_err(|_| VAULTMESH_STATUS_CORE_ERROR)
                })
        })
        .and_then(|value| serde_json::from_value(value).map_err(|_| VAULTMESH_STATUS_CORE_ERROR))
        .map_err(Into::into)
    }

    pub fn delete_agent_connector_definition(&mut self, id: Uuid) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |session| {
            session
                .delete_agent_connector_definition(id)
                .map(|()| json!({}))
                .map_err(map_core_error)
        })
        .map(|_| ())
        .map_err(Into::into)
    }

    pub fn protected_value(
        &self,
        item_kind: u32,
        protected_field: u32,
        item_id: &str,
        master_password: Option<&str>,
    ) -> Result<Zeroizing<String>, DesktopRuntimeError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let id = Uuid::parse_str(item_id)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
        let value = protected_value(vault, item_kind, protected_field, id, master_password)
            .map_err(map_runtime_core_error)?;
        String::from_utf8(value.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| VAULTMESH_STATUS_CORE_ERROR.into())
    }

    pub fn totp_value(
        &self,
        item_id: &str,
        master_password: Option<&str>,
    ) -> Result<Value, DesktopRuntimeError> {
        let value = self.protected_value(
            VAULTMESH_ITEM_KIND_LOGIN,
            VAULTMESH_PROTECTED_FIELD_LOGIN_TOTP,
            item_id,
            master_password,
        )?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_CORE_ERROR))?
            .as_secs();
        Ok(json!({ "code": value.as_str(), "period": 30, "remainingSeconds": 30 - now % 30 }))
    }

    pub fn recovery_codes(
        &self,
        item_id: &str,
        master_password: Option<&str>,
    ) -> Result<Vec<String>, DesktopRuntimeError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let id = Uuid::parse_str(item_id)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
        vault
            .session
            .recovery_codes_for_access(id, master_password)
            .map(|codes| codes.to_vec())
            .map_err(map_runtime_core_error)
    }

    /// Returns a short-lived TOTP code only to the Rust Agent adapter. The
    /// seed remains owned by vault-core and no renderer/C ABI operation maps
    /// to this method.
    pub fn agent_totp_code(
        &mut self,
        item_id: Uuid,
    ) -> Result<(Zeroizing<String>, u64), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_CORE_ERROR))?
            .as_secs();
        let code = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .totp_code(item_id, now)
            .map_err(map_runtime_core_error)?;
        Ok((Zeroizing::new(code.code), 30 - now % 30))
    }

    /// Reserves the current first recovery code for a freshly confirmed
    /// broker action and returns a digest used for compare-and-consume after
    /// remote success.
    pub fn agent_recovery_code(
        &mut self,
        item_id: Uuid,
    ) -> Result<(Zeroizing<String>, [u8; 32]), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let code = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_recovery_code_for_consumption(item_id)
            .map_err(map_runtime_core_error)?;
        let digest = Sha256::digest(code.as_bytes()).into();
        Ok((Zeroizing::new(code.to_owned()), digest))
    }

    pub fn consume_agent_recovery_code(
        &mut self,
        item_id: Uuid,
        expected_sha256: [u8; 32],
    ) -> Result<usize, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |session| {
            session
                .consume_agent_recovery_code(item_id, &expected_sha256)
                .map(|remaining| json!({ "remaining": remaining }))
                .map_err(map_core_error)
        })
        .and_then(|value| {
            value
                .get("remaining")
                .and_then(Value::as_u64)
                .and_then(|remaining| usize::try_from(remaining).ok())
                .ok_or(VAULTMESH_STATUS_CORE_ERROR)
        })
        .map_err(Into::into)
    }

    pub fn agent_access_token_enabled(
        &mut self,
        item_id: Uuid,
    ) -> Result<bool, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_access_token_enabled(item_id)
            .map_err(map_core_error)
            .map_err(Into::into)
    }

    /// Verifies the current master password without changing either the
    /// desktop or browser authorization state. Browser card disclosure uses
    /// this as an unconditional re-prompt boundary.
    pub fn verify_master_password(&self, master_password: &str) -> Result<(), DesktopRuntimeError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        vault
            .session
            .verify_master_password(master_password)
            .map_err(map_runtime_core_error)
    }

    pub fn backup_to(&self, destination: &std::path::Path) -> Result<(), DesktopRuntimeError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let encrypted = Zeroizing::new(vault.session.save().map_err(map_runtime_core_error)?);
        write_vault(destination, encrypted.as_slice())
            .map_err(|()| VAULTMESH_STATUS_IO_ERROR.into())
    }

    pub fn restore_from(
        &mut self,
        source: &std::path::Path,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.restore_from_with_source(source, master_password, UnlockEventSource::Desktop)
    }

    pub fn restore_from_for_browser(
        &mut self,
        source: &std::path::Path,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.restore_from_with_source(
            source,
            master_password,
            UnlockEventSource::ExtensionMasterPassword,
        )
    }

    pub fn unlock_for_browser_with_biometric_key(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_with_quick_key_from_source(
            path,
            vault_key,
            UnlockEventSource::ExtensionBiometric,
        )
    }

    fn restore_from_with_source(
        &mut self,
        source: &std::path::Path,
        mut master_password: String,
        unlock_source: UnlockEventSource,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        let encrypted = Zeroizing::new(
            read_vault(source)
                .map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?,
        );
        let session = match VaultSession::unlock(&master_password, encrypted.as_slice()) {
            Err(vaultmesh_core::VaultError::UnsupportedFormat) if matches!(unlock_source, UnlockEventSource::Desktop) => {
                VaultSession::upgrade_format3(&master_password, &encrypted).and_then(|session| {
                    let backup = self.path.with_file_name(format!("{}.format3-{}.backup",self.path.file_name().unwrap_or_default().to_string_lossy(),Uuid::new_v4()));
                    write_vault(&backup,&encrypted).map_err(|_|vaultmesh_core::VaultError::Serialization)?;
                    Ok(session)
                })
            },
            other => other,
        }.map_err(map_runtime_core_error);
        master_password.zeroize();
        let mut session = session?;
        session.sync_reset_after_restore().map_err(map_runtime_core_error)?;
        session.sync_checkpoint(0).map_err(map_runtime_core_error)?;
        let canonical = Zeroizing::new(session.save().map_err(map_runtime_core_error)?);
        let mutation_lock = crate::vault::mutation_lock(&self.path);
        let _guard = mutation_lock.lock().map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
        write_vault(&self.path, canonical.as_slice())
            .map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
        session
            .record_unlock_event(unlock_source)
            .map_err(map_runtime_core_error)?;
        // Revoke the old mailbox while the restored file is still under its
        // writer lock. `replace` then acquires that lock to publish the new
        // epoch; retaining this guard would deadlock the restore path.
        self.relay.invalidate();
        drop(_guard);
        self.replace(session, canonical.as_slice());
        Ok(self.status())
    }

    pub fn item_kind_login() -> u32 {
        VAULTMESH_ITEM_KIND_LOGIN
    }
    pub fn item_kind_card() -> u32 {
        VAULTMESH_ITEM_KIND_PAYMENT_CARD
    }
    pub fn item_kind_ssh() -> u32 {
        VAULTMESH_ITEM_KIND_SSH_CREDENTIAL
    }
    pub fn item_kind_secret() -> u32 {
        VAULTMESH_ITEM_KIND_SECRET
    }

    fn replace(&mut self, mut session: VaultSession, encrypted: &[u8]) {
        self.lock();
        self.relay = crate::sync_relay::RelayHub::for_path(&self.path);
        if crate::sync_relay::system_locked() { session.lock(); return; }
        self.vault = Some(VaultmeshVault {
            session,
            path: self.path.clone(),
            persisted_fingerprint: vault_fingerprint(encrypted),
        });
        if let Some(vault) = self.vault.as_mut() {
            crate::sync_relay::publish(vault);
            let _ = crate::sync_relay::pump(vault);
        }
    }
}

fn managed_ssh_host_key_material(
    session: &VaultSession,
    account_id: Uuid,
    alias: &str,
    host_key_sha256: &str,
) -> Result<Option<ManagedSshHostKeyMaterial>, VaultError> {
    let Some(key_item_id) =
        session.managed_ssh_host_key_id(account_id, alias, host_key_sha256)?
    else {
        return Ok(None);
    };
    Ok(Some(ManagedSshHostKeyMaterial {
        key_item_id,
        public_key: Zeroizing::new(session.ssh_public_key_for_access(key_item_id)?.to_owned()),
        private_key: Zeroizing::new(
            session
                .ssh_private_key_for_access(key_item_id, None)?
                .to_owned(),
        ),
    }))
}

impl Drop for DesktopRuntime {
    fn drop(&mut self) {
        self.lock();
    }
}

fn serialize<T: Serialize>(result: Result<T, VaultError>) -> Result<Value, DesktopRuntimeError> {
    let value = result.map_err(map_runtime_core_error)?;
    serde_json::to_value(value).map_err(|_| VAULTMESH_STATUS_CORE_ERROR.into())
}

fn parse_id(input: &Value) -> Result<Uuid, DesktopRuntimeError> {
    input
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT.into())
}

fn map_runtime_core_error(error: VaultError) -> DesktopRuntimeError {
    let message = match &error {
        VaultError::UnsupportedFormat => Some("此解锁方式不支持当前保险库格式。旧版保险库请先在桌面使用主密码解锁，完成升级后再使用 PIN 或指纹。"),
        VaultError::InvalidPayload => Some("保险库数据格式无法读取。"),
        _ => None,
    };
    DesktopRuntimeError { status: map_core_error(error), message }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
