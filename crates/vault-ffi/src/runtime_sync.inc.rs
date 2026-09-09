// Typed privileged entrypoints. None are registered as generic core operations.
impl DesktopRuntime {
    pub fn sync_state(&mut self) -> Result<vaultmesh_core::SyncState, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        vault
            .session
            .sync_state()
            .cloned()
            .map_err(map_runtime_core_error)
    }
    pub fn sync_authorize(
        &mut self,
        peer: &str,
        fingerprint: &str,
        enabled: bool,
    ) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |s| {
            s.sync_authorize(peer, fingerprint, enabled)
                .map_err(map_core_error)?;
            Ok(json!({}))
        })?;
        Ok(())
    }
    pub fn sync_bind(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
    ) -> Result<Uuid, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        let state = vault.session.sync_state().map_err(map_runtime_core_error)?;
        if state.vault_id != local {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        if state.authorizations.iter().any(|a| {
            a.peer == peer
                && a.fingerprint == fingerprint
                && a.enabled
                && a.remote_vault == Some(remote)
        }) {
            return Ok(local);
        }
        transaction(vault, |s| {
            s.sync_bind(peer, fingerprint, remote)
                .map_err(map_core_error)?;
            Ok(json!({}))
        })?;
        Ok(vault
            .session
            .sync_state()
            .map_err(map_runtime_core_error)?
            .vault_id)
    }
    fn require_sync_peer(
        &self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
    ) -> Result<(), DesktopRuntimeError> {
        let s = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .sync_state()
            .map_err(map_runtime_core_error)?;
        if s.vault_id != local
            || !s.authorizations.iter().any(|a| {
                a.enabled
                    && a.peer == peer
                    && a.fingerprint == fingerprint
                    && a.remote_vault == Some(remote)
            })
        {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        Ok(())
    }
    pub fn sync_manifest(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
    ) -> Result<vaultmesh_core::SyncManifest, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.require_sync_peer(peer, fingerprint, remote, local)?;
        Ok(self
            .vault
            .as_ref()
            .unwrap()
            .session
            .sync_state()
            .map_err(map_runtime_core_error)?
            .entries
            .clone())
    }
    pub fn sync_export(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
        manifest: &vaultmesh_core::SyncManifest,
    ) -> Result<Vec<vaultmesh_core::SyncRecord>, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.require_sync_peer(peer, fingerprint, remote, local)?;
        self.vault
            .as_ref()
            .unwrap()
            .session
            .sync_export(manifest)
            .map_err(map_runtime_core_error)
    }
    pub fn sync_merge(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
        records: &[vaultmesh_core::SyncRecord],
    ) -> Result<usize, DesktopRuntimeError> {
        self.sync_merge_cancellable(
            peer,
            fingerprint,
            remote,
            local,
            records,
            &std::sync::atomic::AtomicBool::new(false),
        )
    }
    pub fn sync_merge_cancellable(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
        records: &[vaultmesh_core::SyncRecord],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<usize, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.require_sync_peer(peer, fingerprint, remote, local)?;
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(VAULTMESH_STATUS_LOCKED.into());
        }
        let vault = self.vault.as_mut().unwrap();
        let result = crate::browser_ops::transaction_guarded(
            vault,
            |s| {
                let changed = s
                    .sync_merge(
                        records,
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                    )
                    .map_err(map_core_error)?;
                Ok(json!({"changed":changed}))
            },
            || !cancelled.load(std::sync::atomic::Ordering::Acquire),
        )?;
        Ok(result["changed"].as_u64().unwrap_or(0) as usize)
    }
    pub fn sync_confirm_manifest(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
        manifest: &vaultmesh_core::SyncManifest,
    ) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        self.require_sync_peer(peer, fingerprint, remote, local)?;
        let vault = self.vault.as_mut().unwrap();
        // Probe a rollback-safe snapshot to avoid rewriting an unchanged Vault every heartbeat.
        let snapshot = vault
            .session
            .payload_snapshot()
            .map_err(map_runtime_core_error)?;
        let result = vault.session.sync_confirm_manifest(manifest);
        vault
            .session
            .restore_payload_snapshot(snapshot)
            .map_err(map_runtime_core_error)?;
        if result.map_err(map_runtime_core_error)? {
            transaction(vault, |s| {
                s.sync_confirm_manifest(manifest).map_err(map_core_error)?;
                Ok(json!({}))
            })?;
        }
        Ok(())
    }
    pub fn sync_mark_backed_up(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        local: Uuid,
        records: &[vaultmesh_core::SyncRecord],
    ) -> Result<(), DesktopRuntimeError> {
        if records.is_empty() {
            return Ok(());
        }
        self.refresh_from_disk()?;
        self.require_sync_peer(peer, fingerprint, remote, local)?;
        let vault = self.vault.as_mut().unwrap();
        // Avoid a new file write for ordinary sync receipts without a Passkey.
        let has_passkey = records.iter().any(|r| {
            r.key.starts_with("secret/")
                && r.body
                    .as_ref()
                    .is_some_and(|b| b.contains("vaultmesh:passkey:v1"))
        });
        if !has_passkey {
            return Ok(());
        }
        transaction(vault, |s| {
            s.sync_mark_backed_up(records).map_err(map_core_error)?;
            Ok(json!({}))
        })?;
        Ok(())
    }
    pub fn sync_conflicts(&mut self) -> Result<Value, DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let state = self
            .vault
            .as_ref()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?
            .session
            .sync_state()
            .map_err(map_runtime_core_error)?;
        // No titles or protected bodies need to cross the renderer boundary.
        Ok(Value::Array(state.conflicts.iter().map(|(id,r)| json!({"id":id,"kind":r.key.split('/').next().unwrap_or("item"),"savedAt":r.entry.version.millis})).collect()))
    }
    pub fn sync_restore_conflict(&mut self, id: &str) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |s| {
            s.sync_restore_conflict(id).map_err(map_core_error)?;
            Ok(json!({}))
        })?;
        Ok(())
    }
    pub fn sync_clear_conflicts(&mut self) -> Result<(), DesktopRuntimeError> {
        self.refresh_from_disk()?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(DesktopRuntimeError::from(VAULTMESH_STATUS_LOCKED))?;
        transaction(vault, |s| {
            s.sync_clear_conflicts().map_err(map_core_error)?;
            Ok(json!({}))
        })?;
        Ok(())
    }
}
