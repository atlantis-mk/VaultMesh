/// Safe, Rust-native owner used by the Tauri privileged process. The C ABI
/// remains available to frozen platform previews, while Tauri never calls it.
pub struct DesktopRuntime {
    path: PathBuf,
    vault: Option<VaultmeshVault>,
}

impl DesktopRuntime {
    pub fn new(path: PathBuf) -> Result<Self, DesktopRuntimeError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        Ok(Self {
            path,
            vault: None,
        })
    }

    pub fn status(&self) -> DesktopRuntimeStatus {
        let session = self
            .vault
            .as_ref()
            .filter(|vault| !vault.session.is_locked());
        let item_count = session.map_or(0, |vault| {
            let session = &vault.session;
            session.list_items().map_or(0, |items| items.len() as u32)
                + session.list_cards().map_or(0, |items| items.len() as u32)
                + session
                    .list_ssh_credentials()
                    .map_or(0, |items| items.len() as u32)
                + session
                    .list_identities()
                    .map_or(0, |items| items.len() as u32)
                + session.list_secrets().map_or(0, |items| items.len() as u32)
        });
        DesktopRuntimeStatus {
            unlocked: session.is_some(),
            has_vault: self.path.is_file(),
            item_count,
        }
    }

    pub fn create(
        &mut self,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.create_with_source(master_password, UnlockEventSource::Desktop)
    }

    pub fn create_for_browser(
        &mut self,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.create_with_source(master_password, UnlockEventSource::ExtensionMasterPassword)
    }

    fn create_with_source(
        &mut self,
        mut master_password: String,
        unlock_source: UnlockEventSource,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        if self
            .path
            .try_exists()
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?
        {
            master_password.zeroize();
            return Err(VAULTMESH_STATUS_VAULT_EXISTS.into());
        }
        let session = VaultSession::create(&master_password).map_err(map_runtime_core_error);
        master_password.zeroize();
        let mut session = session?;
        session
            .record_unlock_event(unlock_source)
            .map_err(map_runtime_core_error)?;
        session.sync_checkpoint(0).map_err(map_runtime_core_error)?;
        let encrypted = Zeroizing::new(session.save().map_err(map_runtime_core_error)?);
        write_vault(&self.path, encrypted.as_slice())
            .map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
        self.replace(session, encrypted.as_slice());
        Ok(self.status())
    }

    pub fn unlock(
        &mut self,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_from_with_source(
            self.path.clone(),
            master_password,
            UnlockEventSource::Desktop,
        )
    }

    /// Unlocks an independent browser-owned runtime and records the browser
    /// authorization source without granting or borrowing desktop authority.
    pub fn unlock_for_browser(
        &mut self,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_from_with_source(
            self.path.clone(),
            master_password,
            UnlockEventSource::ExtensionMasterPassword,
        )
    }

    /// Unlocks the Agent-only runtime without borrowing desktop/browser
    /// authorization and without extending the persisted unlock-history enum.
    /// Agent unlock auditing is owned by the privileged Agent broker.
    pub fn unlock_for_agent(
        &mut self,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_for_agent_from(self.path.clone(), master_password)
    }

    /// Unlocks the Agent-only runtime against the Vault currently selected by
    /// the desktop shell, without inheriting the desktop unlock session.
    pub fn unlock_for_agent_from(
        &mut self,
        path: PathBuf,
        mut master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            master_password.zeroize();
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        let unlocked = unlock_current_format(&path, &master_password, false);
        master_password.zeroize();
        let (session, encrypted) = unlocked?;
        self.path = path;
        self.replace(session, encrypted.as_slice());
        Ok(self.status())
    }

    pub fn unlock_from(
        &mut self,
        path: PathBuf,
        master_password: String,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_from_with_source(path, master_password, UnlockEventSource::Desktop)
    }

    fn unlock_from_with_source(
        &mut self,
        path: PathBuf,
        mut master_password: String,
        source: UnlockEventSource,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            master_password.zeroize();
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        let unlocked = unlock_current_format(&path, &master_password, matches!(source, UnlockEventSource::Desktop));
        master_password.zeroize();
        let (mut session, encrypted) = unlocked?;
        session
            .record_unlock_event(source)
            .map_err(map_runtime_core_error)?;
        self.path = path;
        self.replace(session, encrypted.as_slice());
        Ok(self.status())
    }

    /// Returns the current Vault path and a short-lived copy of the random
    /// Vault Key for a privileged desktop quick-unlock adapter. Neither value
    /// is serialized into a renderer response.
    pub fn quick_unlock_material(
        &self,
    ) -> Result<(PathBuf, Zeroizing<[u8; 32]>), DesktopRuntimeError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let key = vault
            .session
            .quick_unlock_key()
            .map_err(map_runtime_core_error)?;
        Ok((self.path.clone(), key))
    }

    /// Unlocks with a Vault Key released by a privileged platform adapter and
    /// records the desktop PIN source only after decryption succeeds.
    pub fn unlock_with_quick_key(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_with_quick_key_from_source(path, vault_key, UnlockEventSource::DesktopPin)
    }

    /// Unlocks the desktop runtime with a Vault Key released only after the
    /// platform biometric adapter succeeds. Keep the existing desktop audit
    /// source so this additive adapter does not change the encrypted payload
    /// enum or Vault format compatibility.
    pub fn unlock_with_biometric_key(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_with_quick_key_from_source(path, vault_key, UnlockEventSource::Desktop)
    }

    pub fn unlock_for_browser_with_quick_key(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        self.unlock_with_quick_key_from_source(path, vault_key, UnlockEventSource::ExtensionPin)
    }

    pub fn unlock_for_agent_with_quick_key(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        let encrypted = Zeroizing::new(
            read_vault(&path).map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?,
        );
        let session = VaultSession::unlock_with_vault_key(vault_key, encrypted.as_slice())
            .map_err(map_runtime_core_error)?;
        self.path = path;
        self.replace(session, encrypted.as_slice());
        Ok(self.status())
    }

    fn unlock_with_quick_key_from_source(
        &mut self,
        path: PathBuf,
        vault_key: &[u8],
        source: UnlockEventSource,
    ) -> Result<DesktopRuntimeStatus, DesktopRuntimeError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        let encrypted = Zeroizing::new(
            read_vault(&path).map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?,
        );
        let mut session = VaultSession::unlock_with_vault_key(vault_key, encrypted.as_slice())
            .map_err(map_runtime_core_error)?;
        session
            .record_unlock_event(source)
            .map_err(map_runtime_core_error)?;
        self.path = path;
        self.replace(session, encrypted.as_slice());
        Ok(self.status())
    }

    pub fn current_path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn lock(&mut self) -> DesktopRuntimeStatus {
        if let Some(mut vault) = self.vault.take() {
            vault.session.lock();
        }
        self.status()
    }

    /// Reloads a newer atomic Vault file through the current session key.
    /// A replacement with a different Vault Key invalidates this authorization.
    pub fn refresh_from_disk(&mut self) -> Result<(), DesktopRuntimeError> {
        let Some(vault) = self.vault.as_mut() else {
            return Ok(());
        };
        if vault.session.is_locked() {
            return Ok(());
        }
        let encrypted = match read_vault(&vault.path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(()) => {
                vault.session.lock();
                return Err(VAULTMESH_STATUS_IO_ERROR.into());
            }
        };
        let fingerprint = vault_fingerprint(encrypted.as_slice());
        if fingerprint == vault.persisted_fingerprint {
            return Ok(());
        }
        let key = vault
            .session
            .quick_unlock_key()
            .map_err(map_runtime_core_error)?;
        match VaultSession::unlock_with_vault_key(key.as_slice(), encrypted.as_slice()) {
            Ok(session) => {
                vault.session = session;
                vault.persisted_fingerprint = fingerprint;
                Ok(())
            }
            Err(error) => {
                vault.session.lock();
                Err(map_runtime_core_error(error))
            }
        }
    }

    pub fn execute(&mut self, operation: &str, input: Value) -> Result<Value, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let direct = match operation {
            "items.list" => Some(serialize(vault.session.list_items())),
            "cards.list" => Some(serialize(vault.session.list_cards())),
            "identities.list" => Some(serialize(vault.session.list_identities())),
            "ssh.list" => Some(serialize(vault.session.list_ssh_credentials())),
            "secrets.list" => Some(serialize(vault.session.list_secrets())),
            "services.list" => Some(serialize(vault.session.list_services(
                input.get("query").and_then(Value::as_str),
            ))),
            "items.copy-username" => Some(serialize(
                vault
                    .session
                    .item_detail(parse_id(&input)?)
                    .map(|item| item.username),
            )),
            _ => None,
        };
        if let Some(result) = direct {
            return result.map(camel_value);
        }
        execute_core_operation(vault, operation, input).map_err(Into::into)
    }

    /// Returns the complete renderer-safe browser workspace after one disk
    /// freshness check. Keeping the five lists in one runtime operation avoids
    /// rereading and hashing the encrypted Vault once per list.
    pub fn workspace_snapshot(&mut self) -> Result<Value, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let status = self.status();
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let items = camel_value(serialize(vault.session.list_items())?);
        let cards = camel_value(serialize(vault.session.list_cards())?);
        let identities = camel_value(serialize(vault.session.list_identities())?);
        let ssh_credentials = camel_value(serialize(vault.session.list_ssh_credentials())?);
        let secrets = camel_value(serialize(vault.session.list_secrets())?);
        Ok(json!({
            "status": status,
            "items": items,
            "cards": cards,
            "identities": identities,
            "sshCredentials": ssh_credentials,
            "secrets": secrets,
        }))
    }

    /// Returns all renderer-safe login matching metadata after one disk
    /// freshness check. Browser candidate filtering must not perform one
    /// runtime round trip per Vault item.
    pub fn browser_login_metadata(&mut self) -> Result<Value, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        serialize(vault.session.list_item_details()).map(camel_value)
    }

    pub fn agent_items_metadata(
        &mut self,
        kind_filter: Option<&str>,
    ) -> Result<Value, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let mut items = Vec::new();
        let accepts = |kind: &str| kind_filter.is_none_or(|filter| filter == kind);
        if accepts("login") {
            items.extend(
                vault
                    .session
                    .list_items()
                    .map_err(map_runtime_core_error)?
                    .into_iter()
                    .map(
                        |item| json!({ "itemRef": item.id, "kind": "login", "label": item.title }),
                    ),
            );
        }
        if accepts("card") {
            items.extend(
                vault
                    .session
                    .list_cards()
                    .map_err(map_runtime_core_error)?
                    .into_iter()
                    .map(|item| json!({ "itemRef": item.id, "kind": "card", "label": item.title })),
            );
        }
        if accepts("identity") {
            items.extend(
                vault
                    .session
                    .list_identities()
                    .map_err(map_runtime_core_error)?
                    .into_iter()
                    .map(|item| json!({ "itemRef": item.id, "kind": "identity", "label": item.title })),
            );
        }
        if accepts("ssh") {
            items.extend(
                vault
                    .session
                    .list_ssh_credentials()
                    .map_err(map_runtime_core_error)?
                    .into_iter()
                    .map(|item| json!({ "itemRef": item.id, "kind": "ssh", "label": item.title })),
            );
        }
        if accepts("secret") {
            items.extend(
                vault
                    .session
                    .list_secrets()
                    .map_err(map_runtime_core_error)?
                    .into_iter()
                    .map(
                        |item| json!({ "itemRef": item.id, "kind": "secret", "label": item.title }),
                    ),
            );
        }
        let truncated = items.len() > 1_000;
        if truncated {
            items.truncate(1_000);
        }
        Ok(json!({ "items": items, "truncated": truncated }))
    }

    /// Returns the complete renderer-safe set of Vault records that can be used
    /// as Agent accounts. Pagination is applied by the privileged broker.
    pub fn agent_account_candidates(&mut self) -> Result<Vec<Value>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let mut items = Vec::new();
        items.extend(
            vault
                .session
                .list_items()
                .map_err(map_runtime_core_error)?
                .into_iter()
                .map(|item| {
                    json!({
                        "accountRef": item.id,
                        "kind": "login",
                        "label": item.title
                    })
                }),
        );
        items.extend(
            vault
                .session
                .list_ssh_credentials()
                .map_err(map_runtime_core_error)?
                .into_iter()
                .filter(|item| item.record_kind == SshCredentialRecordKind::Account)
                .map(|item| {
                    json!({
                        "accountRef": item.id,
                        "kind": "ssh",
                        "label": item.title
                    })
                }),
        );
        items.extend(
            vault
                .session
                .list_secrets()
                .map_err(map_runtime_core_error)?
                .into_iter()
                .filter(|item| !item.is_passkey && item.kind == SecretItemKind::AccessToken)
                .map(|item| {
                    json!({
                        "accountRef": item.id,
                        "kind": "secret",
                        "label": item.title
                    })
                }),
        );
        Ok(items)
    }

    /// Returns the Agent-safe allowlist projection of enabled API
    /// environments. It intentionally omits target, auth, headers and refs.
    pub fn agent_api_environment_candidates(
        &mut self,
    ) -> Result<Vec<Value>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let items = vault
            .session
            .agent_api_environments()
            .map_err(map_runtime_core_error)?;
        let value = serde_json::to_value(items)
            .map(camel_value)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_CORE_ERROR))?;
        value
            .as_array()
            .cloned()
            .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_CORE_ERROR))
    }

    /// Compiles renderer-safe canonical request metadata without materializing
    /// any credential value. The short-lived execution reference is owned by
    /// the Tauri privileged runtime, not by this core wrapper.
    pub fn prepare_api_request(
        &mut self,
        input: ApiRequestInput,
    ) -> Result<ApiRequestPlanSummary, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        vault
            .session
            .prepare_api_request(input)
            .map_err(map_runtime_core_error)
    }

    /// Recompiles the immutable plan from the live Vault immediately before
    /// the Tauri network adapter uses protected material.
    pub fn compile_api_request(
        &mut self,
        input: ApiRequestInput,
        expected_environment_revision: u64,
        expected_environment_policy_digest: &str,
        expected_request_digest: &str,
    ) -> Result<ApiRequestExecutionPlan, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        vault
            .session
            .compile_api_request(
                input,
                expected_environment_revision,
                expected_environment_policy_digest,
                expected_request_digest,
            )
            .map_err(map_runtime_core_error)
    }

    pub fn agent_item_metadata(&mut self, item_id: Uuid) -> Result<Value, DesktopRuntimeError> {
        let metadata = self.agent_items_metadata(None)?;
        let item_id = item_id.to_string();
        metadata["items"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("itemRef").and_then(Value::as_str) == Some(item_id.as_str())
                })
            })
            .cloned()
            .ok_or(VAULTMESH_STATUS_NOT_FOUND.into())
    }

    pub fn agent_connector_definitions(&mut self) -> Result<Vec<AgentConnectorDefinitionSummary>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_connector_definitions()
            .map_err(map_runtime_core_error)
    }

    pub fn agent_connector_definition(&mut self, id: Uuid) -> Result<AgentConnectorDefinition, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_connector_definition(id)
            .map_err(map_runtime_core_error)
    }

    pub fn agent_connector_definition_records(&mut self) -> Result<Vec<AgentConnectorDefinition>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_connector_definition_records()
            .map_err(map_runtime_core_error)
    }

    pub fn agent_audit_events(&mut self) -> Result<Vec<AgentAuditEvent>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .agent_audit_events()
            .map_err(map_runtime_core_error)
    }
}

fn unlock_current_format(
    path: &std::path::Path,
    master_password: &str,
    allow_upgrade: bool,
) -> Result<(VaultSession, Zeroizing<Vec<u8>>), DesktopRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
    if !metadata.file_type().is_file() {
        return Err(VAULTMESH_STATUS_IO_ERROR.into());
    }
    let encrypted = Zeroizing::new(
        read_vault(path).map_err(|()| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?,
    );
    match VaultSession::unlock(master_password, encrypted.as_slice()) {
        Ok(session) => Ok((session, encrypted)),
        Err(vaultmesh_core::VaultError::UnsupportedFormat) if allow_upgrade => {
            let lock = crate::vault::mutation_lock(path);
            let _guard = lock.lock().map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
            let current = Zeroizing::new(read_vault(path).map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?);
            if *current != *encrypted { return Err(VAULTMESH_STATUS_CONFLICT.into()); }
            let session = VaultSession::upgrade_format3(master_password, &encrypted).map_err(map_runtime_core_error)?;
            let backup = path.with_file_name(format!("{}.format3-{}.backup", path.file_name().unwrap_or_default().to_string_lossy(), Uuid::new_v4()));
            write_vault(&backup, &encrypted).map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
            let upgraded = Zeroizing::new(session.save().map_err(map_runtime_core_error)?);
            write_vault(path, &upgraded).map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))?;
            Ok((session, upgraded))
        },
        Err(error) => Err(map_runtime_core_error(error)),
    }
}
