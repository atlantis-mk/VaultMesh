//! Fixed JNI operations; neither transport frames nor channel keys cross JNI.
use super::*;
use crate::lan_credentials::AndroidLanCredentials;
use std::{path::PathBuf, sync::Arc};
use vaultmesh_core::{SyncChannel, SyncState};
use vaultmesh_lan_pairing::LanSyncService;
use vaultmesh_sync::{SyncRuntime, relay::RelayHub};

struct AndroidSyncAccess {
    path: PathBuf,
    relay: Arc<RelayHub>,
}
impl AndroidSyncAccess {
    fn with<T>(
        &self,
        operation: impl FnOnce(&mut AndroidVaultRuntime) -> Result<T, AndroidRuntimeError>,
    ) -> Result<T, AndroidRuntimeError> {
        with_runtime_result(|runtime| {
            if runtime.vault_path != self.path {
                return Err(AndroidRuntimeError::Locked);
            }
            operation(runtime)
        })
    }
}
impl SyncRuntime for AndroidSyncAccess {
    type Error = AndroidRuntimeError;
    fn current_path(&self) -> PathBuf {
        self.path.clone()
    }
    fn is_unlocked(&self) -> bool {
        self.with(|r| Ok(r.is_unlocked())).unwrap_or(false)
    }
    fn sync_relay(&self) -> Arc<RelayHub> {
        self.relay.clone()
    }
    fn sync_state(&mut self) -> Result<SyncState, Self::Error> {
        self.with(|r| r.sync_state())
    }
    fn sync_pump(&mut self) -> Result<(), Self::Error> {
        self.with(|r| r.sync_pump())
    }
    fn sync_channel_offer(&self, peer: &str) -> Result<SyncChannel, Self::Error> {
        self.with(|r| r.sync_channel_offer(peer))
    }
    fn sync_accept_channel(
        &mut self,
        peer: &str,
        fp: &str,
        remote: uuid::Uuid,
        offer: &SyncChannel,
    ) -> Result<(), Self::Error> {
        self.with(|r| r.sync_accept_channel(peer, fp, remote, offer))
    }
}
static SYNC: OnceLock<Mutex<Option<LanSyncService<AndroidSyncAccess>>>> = OnceLock::new();
fn service() -> &'static Mutex<Option<LanSyncService<AndroidSyncAccess>>> {
    SYNC.get_or_init(|| Mutex::new(None))
}
pub(super) fn lock_vault() -> Result<(), AndroidRuntimeError> {
    let service = service().lock().map_err(|_| AndroidRuntimeError::Io)?;
    with_runtime_result(|r| {
        // Freeze offers under the same mutex as the core session, then close all
        // key-exchange sockets before releasing its decryption authority.
        r.lock();
        if let Some(sync) = service.as_ref() {
            sync.lock_sensitive();
        }
        Ok(())
    })
}
pub(super) fn close() {
    if let Ok(mut guard) = service().lock() {
        guard.take();
    }
}
fn with_sync<T>(
    operation: impl FnOnce(&mut LanSyncService<AndroidSyncAccess>) -> Result<T, AndroidRuntimeError>,
) -> Result<T, AndroidRuntimeError> {
    let mut guard = service().lock().map_err(|_| AndroidRuntimeError::Io)?;
    operation(guard.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    wrapping_key: JByteArray<'_>,
) -> jstring {
    let result = (|| {
        let key = Zeroizing::new(
            env.convert_byte_array(&wrapping_key)
                .map_err(|_| AndroidRuntimeError::InvalidInput)?,
        );
        if key.len() != 32 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let mut fixed = Zeroizing::new([0; 32]);
        fixed.copy_from_slice(&key);
        let mut guard = service().lock().map_err(|_| AndroidRuntimeError::Io)?;
        if guard.is_some() {
            return Ok(());
        }
        let access = with_runtime_result(|r| {
            Ok(AndroidSyncAccess {
                path: r.vault_path.clone(),
                relay: r.sync_relay(),
            })
        })?;
        let directory = access.path.parent().ok_or(AndroidRuntimeError::Io)?;
        let credentials = AndroidLanCredentials::new(directory.join("lan-pairing-secrets"), *fixed)
            .map_err(|_| AndroidRuntimeError::Io)?;
        let trust = directory.join("lan-pairing-peers.json");
        *guard = Some(LanSyncService::new_with_credentials(
            Arc::new(Mutex::new(access)),
            trust,
            Arc::new(credentials),
        ));
        Ok::<_, AndroidRuntimeError>(())
    })();
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncTick(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    network_allowed: jboolean,
) -> jstring {
    let result = with_sync(|s| {
        if network_allowed != 0 {
            s.tick();
        } else {
            s.stop();
        }
        Ok(())
    });
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    close();
    return_string(&mut env, "ok")
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncRetry(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_sync(|s| {
        s.retry();
        Ok(())
    });
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_sync(|s| {
        let status = s.status().map_err(|_| AndroidRuntimeError::Locked)?;
        let generation = with_runtime_result(|r| Ok(r.sync_relay().merged_generation()))?;
        Ok(serde_json::json!({"peers": status.peers, "conflictCount": status.conflict_count, "generation": generation}))
    }).or_else(|error| {
        if error != AndroidRuntimeError::NotInitialized { return Err(error); }
        // Pausing the service must not change or hide the persisted authorization.
        with_lan_result(|lan, r| {
            let trusted = lan.status(r)?.trusted;
            let state = r.sync_state()?;
            let peers: Vec<_> = trusted.into_iter().map(|peer| {
                let enabled = state.authorizations.iter().any(|a| a.peer == peer.pairing_ref && a.enabled && a.outgoing.is_some());
                serde_json::json!({"peerRef":peer.pairing_ref,"enabled":enabled,"state":if enabled {"offline"} else {"disabled"},"lastSuccessAt":null})
            }).collect();
            Ok(serde_json::json!({"peers":peers,"conflictCount":state.conflicts.len(),"generation":r.sync_relay().merged_generation()}))
        })
    });
    return_string(&mut env, &json_result(result))
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncSetEnabled(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    peer: JString<'_>,
    enabled: jboolean,
) -> jstring {
    let result = (|| {
        let peer = read_string(&mut env, peer).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        // Fence all in-flight handshakes before changing the core authorization.
        let _ = with_sync(|s| {
            s.interrupt_peer(&peer);
            Ok(())
        });
        let result = with_lan_result(|lan, r| lan.set_sync_enabled(r, &peer, enabled != 0));
        let _ = with_sync(|s| {
            s.interrupt_peer(&peer);
            Ok(())
        });
        result
    })();
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncConflicts(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    return_string(
        &mut env,
        &json_result(with_runtime_result(|r| r.sync_conflicts())),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncRestoreConflict(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
) -> jstring {
    let result = read_string(&mut env, id)
        .map_err(|_| AndroidRuntimeError::InvalidInput)
        .and_then(|id| with_runtime_result(|r| r.sync_restore_conflict(&id)));
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncClearConflicts(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|r| r.sync_clear_conflicts());
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_syncNeeded(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|r| {
        Ok(
            if r.sync_state()?
                .authorizations
                .iter()
                .any(|a| a.enabled && a.outgoing.is_some())
            {
                "yes"
            } else {
                "no"
            },
        )
    });
    return_string(&mut env, result.unwrap_or_else(AndroidRuntimeError::code))
}
