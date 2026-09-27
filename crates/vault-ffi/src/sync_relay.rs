use crate::VaultmeshVault;
pub use vaultmesh_sync::relay::*;
/// Publication failure is a sync error, never a failed user mutation after a
/// successful Vault commit. The next unlocked refresh reconstructs the cache.
pub(crate) fn publish(vault: &VaultmeshVault) {
    let lock = crate::vault::mutation_lock(&vault.path);
    let Ok(_guard) = lock.lock() else { return };
    publish_committed(vault);
}
/// Called only while holding the same per-Vault writer lock as the file commit.
pub(crate) fn publish_committed(vault: &VaultmeshVault) {
    let hub = RelayHub::for_path(&vault.path);
    if hub.publish(&vault.session, &vault.persisted_fingerprint).is_err() {
        hub.mark_failed();
    }
}
pub(crate) fn pump(vault: &mut VaultmeshVault) -> Result<(), ()> {
    if system_locked() {
        return Ok(());
    }
    let result = pump_inner(vault);
    if result.is_err() {
        RelayHub::for_path(&vault.path).mark_failed();
    }
    result
}
fn pump_inner(vault: &mut VaultmeshVault) -> Result<(), ()> {
    let hub = RelayHub::for_path(&vault.path);
    if hub.failed()
        || hub.profile()?.0.vault_fingerprint
            != vault
                .persisted_fingerprint
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
    {
        publish(vault);
        if hub.failed() {
            return Err(());
        }
    }
    for route in vault.session.sync_routes().map_err(|_| ())? {
        let Some(_) = route.incoming else { continue };
        let peer = hub.peer(&route.peer)?;
        if let Some(receipt) = peer.incoming_receipt {
            let seen = vault
                .session
                .sync_state()
                .map_err(|_| ())?
                .authorizations
                .iter()
                .find(|a| a.peer == route.peer)
                .and_then(|a| a.confirmed_packet.as_ref());
            if seen != Some(&receipt.id) {
                crate::browser_ops::transaction(vault, |s| {
                    s.sync_mailbox_confirm(&route.peer, &receipt)
                        .map_err(crate::vault::map_core_error)?;
                    Ok(serde_json::json!({}))
                })
                .map_err(|_| ())?;
            }
        }
        if let Some(packet) = peer.incoming {
            let applied = vault
                .session
                .sync_state()
                .map_err(|_| ())?
                .authorizations
                .iter()
                .find(|a| a.peer == route.peer)
                .and_then(|a| a.applied_packet.as_ref());
            // A lost receipt cache is safely recreated from the same packet.
            if applied != Some(&packet.id) || peer.outgoing_receipt.is_none() {
                let mut receipt = None;
                let mut changes = 0;
                crate::browser_ops::transaction(vault, |s| {
                    let (count, ack) = s
                        .sync_mailbox_apply(
                            &route.peer,
                            &packet,
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        )
                        .map_err(crate::vault::map_core_error)?;
                    changes = count;
                    receipt = Some(ack);
                    Ok(serde_json::json!({}))
                })
                .map_err(|_| ())?;
                if changes > 0 {
                    hub.mark_merged();
                }
                hub.applied_receipt(&route.peer, receipt.unwrap())?;
            }
        }
    }
    Ok(())
}
