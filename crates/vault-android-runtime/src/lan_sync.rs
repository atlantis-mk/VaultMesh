//! Android atomic Vault adapter for the shared ciphertext transport.
use super::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vaultmesh_core::{SyncChannel, SyncState};
use vaultmesh_sync::{SyncRuntime, relay::RelayHub};

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl AndroidVaultRuntime {
    pub(crate) fn publish_sync(&self) {
        if let (Some(session), Some(fingerprint)) = (&self.session, &self.persisted_fingerprint) {
            if self.relay.publish(session, fingerprint).is_err() {
                self.relay.mark_failed();
            }
        }
    }
    fn pump_mailbox(&mut self) -> Result<(), AndroidRuntimeError> {
        if self.session.is_none() {
            return Ok(());
        }
        let fingerprint = self.persisted_fingerprint.ok_or(AndroidRuntimeError::Io)?;
        if self.relay.failed() || !self.relay.matches_vault() {
            self.publish_sync();
            if self.relay.failed() {
                return Err(AndroidRuntimeError::Io);
            }
        }
        if Sha256::digest(read_vault(&self.vault_path)?).as_slice() != fingerprint {
            return Err(AndroidRuntimeError::Io);
        }
        let routes = self.session.as_ref().unwrap().sync_routes()?;
        for route in routes {
            if route.incoming.is_none() {
                continue;
            }
            let peer = self
                .relay
                .peer(&route.peer)
                .map_err(|_| AndroidRuntimeError::Io)?;
            if let Some(receipt) = peer.incoming_receipt {
                let seen = self
                    .session
                    .as_ref()
                    .unwrap()
                    .sync_state()?
                    .authorizations
                    .iter()
                    .find(|a| a.peer == route.peer)
                    .and_then(|a| a.confirmed_packet.as_ref());
                if seen != Some(&receipt.id) {
                    self.mutate_and_commit(|s| s.sync_mailbox_confirm(&route.peer, &receipt))?;
                }
            }
            if let Some(packet) = peer.incoming {
                let applied = self
                    .session
                    .as_ref()
                    .unwrap()
                    .sync_state()?
                    .authorizations
                    .iter()
                    .find(|a| a.peer == route.peer)
                    .and_then(|a| a.applied_packet.as_ref());
                if applied != Some(&packet.id) || peer.outgoing_receipt.is_none() {
                    let (changed, receipt) = self
                        .mutate_and_commit(|s| s.sync_mailbox_apply(&route.peer, &packet, now()))?;
                    if changed > 0 {
                        self.relay.mark_merged();
                    }
                    self.relay
                        .applied_receipt(&route.peer, receipt)
                        .map_err(|_| AndroidRuntimeError::Io)?;
                }
            }
        }
        Ok(())
    }
    pub fn sync_conflicts(&self) -> Result<serde_json::Value, AndroidRuntimeError> {
        let state = self
            .session
            .as_ref()
            .ok_or(AndroidRuntimeError::Locked)?
            .sync_state()?;
        Ok(serde_json::Value::Array(state.conflicts.iter().map(|(id,r)| serde_json::json!({
            "id": id, "kind": r.key.split('/').next().unwrap_or("item"), "savedAt": r.entry.version.millis
        })).collect()))
    }
    pub fn sync_restore_conflict(&mut self, id: &str) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|s| s.sync_restore_conflict(id))
    }
    pub fn sync_clear_conflicts(&mut self) -> Result<(), AndroidRuntimeError> {
        self.mutate_and_commit(|s| s.sync_clear_conflicts())
    }
}
impl SyncRuntime for AndroidVaultRuntime {
    type Error = AndroidRuntimeError;
    fn current_path(&self) -> PathBuf {
        self.vault_path.clone()
    }
    fn is_unlocked(&self) -> bool {
        self.status() == RuntimeStatus::Unlocked
    }
    fn sync_relay(&self) -> Arc<RelayHub> {
        self.relay.clone()
    }
    fn sync_state(&mut self) -> Result<SyncState, Self::Error> {
        Ok(self
            .session
            .as_ref()
            .ok_or(AndroidRuntimeError::Locked)?
            .sync_state()?
            .clone())
    }
    fn sync_pump(&mut self) -> Result<(), Self::Error> {
        let result = self.pump_mailbox();
        if result.is_err() {
            self.relay.mark_failed();
        }
        result
    }
    fn sync_channel_offer(&self, peer: &str) -> Result<SyncChannel, Self::Error> {
        Ok(self
            .session
            .as_ref()
            .ok_or(AndroidRuntimeError::Locked)?
            .sync_channel_offer(peer)?)
    }
    fn sync_accept_channel(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        offer: &SyncChannel,
    ) -> Result<(), Self::Error> {
        self.mutate_and_commit(|s| s.sync_accept_channel(peer, fingerprint, remote, offer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "lan-peer-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "lan-peer-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn pair() -> (PathBuf, AndroidVaultRuntime, AndroidVaultRuntime) {
        let dir = std::env::temp_dir().join(format!("vaultmesh-mailbox-{}", Uuid::new_v4()));
        let mut a = AndroidVaultRuntime::new(dir.join("a")).unwrap();
        let mut b = AndroidVaultRuntime::new(dir.join("b")).unwrap();
        a.create("synthetic-a").unwrap();
        b.create("synthetic-b").unwrap();
        a.sync_authorize_peer(B, &"b".repeat(64), true).unwrap();
        b.sync_authorize_peer(A, &"a".repeat(64), true).unwrap();
        a.sync_accept_channel(
            B,
            &"b".repeat(64),
            b.sync_vault_id().unwrap(),
            &b.sync_channel_offer(A).unwrap(),
        )
        .unwrap();
        b.sync_accept_channel(
            A,
            &"a".repeat(64),
            a.sync_vault_id().unwrap(),
            &a.sync_channel_offer(B).unwrap(),
        )
        .unwrap();
        (dir, a, b)
    }
    #[test]
    fn locked_mailbox_merges_only_after_unlock_and_retry_is_idempotent() {
        let (dir, mut a, mut b) = pair();
        a.add_login(
            "Synthetic title".into(),
            "test".into(),
            "never-in-cache".into(),
            None,
        )
        .unwrap();
        let packet = a.relay.peer(B).unwrap().outgoing.unwrap();
        b.lock();
        let disk = fs::read(&b.vault_path).unwrap();
        b.relay.store(A, packet.clone(), false).unwrap();
        b.sync_pump().unwrap();
        assert_eq!(fs::read(&b.vault_path).unwrap(), disk);
        assert!(b.relay.summary(A).unwrap().receipt.is_none());
        let cache =
            fs::read_to_string(b.vault_path.with_file_name("vaultmesh.vault.lan-mailbox")).unwrap();
        assert!(!cache.contains("never-in-cache") && !cache.contains("Synthetic title"));
        b.unlock("synthetic-b").unwrap();
        assert_eq!(b.list_logins().unwrap().len(), 1);
        b.relay.store(A, packet, false).unwrap();
        b.sync_pump().unwrap();
        assert_eq!(b.list_logins().unwrap().len(), 1);
        assert!(b.relay.summary(A).unwrap().receipt.is_some());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn cold_runtime_keeps_received_ciphertext_locked_until_unlock() {
        let (dir, mut a, mut b) = pair();
        a.add_login(
            "Cold restart".into(),
            "test".into(),
            "synthetic".into(),
            None,
        )
        .unwrap();
        b.lock();
        b.relay
            .store(A, a.relay.peer(B).unwrap().outgoing.unwrap(), false)
            .unwrap();
        let disk = fs::read(&b.vault_path).unwrap();
        drop(b);
        let mut restarted = AndroidVaultRuntime::new(dir.join("b")).unwrap();
        assert_eq!(restarted.status(), RuntimeStatus::Locked);
        assert!(!restarted.relay.profile().unwrap().1);
        restarted.sync_pump().unwrap();
        assert_eq!(fs::read(&restarted.vault_path).unwrap(), disk);
        assert!(restarted.relay.summary(A).unwrap().receipt.is_none());
        restarted.unlock("synthetic-b").unwrap();
        assert_eq!(restarted.list_logins().unwrap().len(), 1);
        assert_eq!(restarted.list_logins().unwrap()[0].title, "Cold restart");
        assert!(restarted.relay.summary(A).unwrap().receipt.is_some());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_merge_preserves_file_and_no_receipt_then_retries() {
        let (dir, mut a, mut b) = pair();
        a.add_login(
            "Synthetic title".into(),
            "test".into(),
            "synthetic".into(),
            None,
        )
        .unwrap();
        b.relay
            .store(A, a.relay.peer(B).unwrap().outgoing.unwrap(), false)
            .unwrap();
        // Replacement on disk must fence a stale decrypted session.
        let original = fs::read(&b.vault_path).unwrap();
        fs::write(&b.vault_path, b"invalid replacement").unwrap();
        assert!(b.sync_pump().is_err());
        assert!(b.list_logins().unwrap().is_empty());
        assert!(b.relay.summary(A).unwrap().receipt.is_none());
        fs::write(&b.vault_path, &original).unwrap();
        b.sync_pump().unwrap();
        assert_eq!(b.list_logins().unwrap().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn cache_failure_does_not_undo_mutation_and_rebuilds_on_retry() {
        let (dir, mut a, _b) = pair();
        vaultmesh_sync::relay::FAIL_CACHE.with(|f| f.set(true));
        let result = a.add_login("Committed".into(), "test".into(), "synthetic".into(), None);
        vaultmesh_sync::relay::FAIL_CACHE.with(|f| f.set(false));
        result.unwrap();
        assert!(a.relay.failed());
        assert_eq!(a.list_logins().unwrap().len(), 1);
        a.sync_pump().unwrap();
        assert!(!a.relay.failed());
        assert!(a.relay.peer(B).unwrap().outgoing.is_some());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn backup_restore_clears_authority_and_rejects_old_packets() {
        let (dir, mut a, mut b) = pair();
        a.add_login("Original".into(), "test".into(), "synthetic".into(), None)
            .unwrap();
        let old = a.relay.peer(B).unwrap().outgoing.unwrap();
        let replacement = VaultSession::create("synthetic-replacement")
            .unwrap()
            .save()
            .unwrap();
        write_vault(
            &b.vault_path.with_file_name(BACKUP_IMPORT_STAGE_FILE_NAME),
            &replacement,
        )
        .unwrap();
        b.restore_staged_backup("synthetic-replacement").unwrap();
        assert!(b.sync_state().unwrap().authorizations.is_empty());
        assert!(b.relay.route(A).is_err());
        assert!(b.relay.store(A, old, false).is_err());
        assert!(
            !b.vault_path
                .with_file_name("vaultmesh.vault.lan-mailbox")
                .exists()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
