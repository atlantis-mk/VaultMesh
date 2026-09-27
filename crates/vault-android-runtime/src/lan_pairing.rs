//! Android adapter for the desktop-compatible LAN protocol 2.0 state machine.
//! Only fixed operations and renderer-safe status leave this module.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;
use vaultmesh_lan_pairing::{LanPairingService, LanPairingStatus};
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime, lan_credentials::AndroidLanCredentials};

pub(crate) struct AndroidLanPairing {
    vault: Uuid,
    service: LanPairingService,
}

impl AndroidLanPairing {
    pub(crate) fn open(
        runtime: &AndroidVaultRuntime,
        key: [u8; 32],
    ) -> Result<Self, AndroidRuntimeError> {
        let vault = runtime.sync_vault_id()?;
        let directory = runtime.vault_path.parent().ok_or(AndroidRuntimeError::Io)?;
        let credentials = AndroidLanCredentials::new(directory.join("lan-pairing-secrets"), key)
            .map_err(|_| AndroidRuntimeError::Io)?;
        let service = LanPairingService::new_with_credentials(
            PathBuf::from(directory).join("lan-pairing-peers.json"),
            Arc::new(credentials),
        );
        Ok(Self { vault, service })
    }

    fn require_vault(&mut self, runtime: &AndroidVaultRuntime) -> Result<(), AndroidRuntimeError> {
        if runtime.sync_vault_id()? != self.vault {
            self.service.stop();
            return Err(AndroidRuntimeError::Locked);
        }
        Ok(())
    }

    pub(crate) fn status(
        &mut self,
        runtime: &mut AndroidVaultRuntime,
    ) -> Result<LanPairingStatus, AndroidRuntimeError> {
        self.require_vault(runtime)?;
        let expected = self.vault;
        let status = self.service.status_with_authorization(
            Instant::now(),
            unix_millis(),
            |vault, peer, fingerprint, enabled| {
                vault == expected
                    && runtime
                        .sync_authorize_peer(peer, fingerprint, enabled)
                        .is_ok()
            },
        );
        let _ = self.service.take_sync_authorizations();
        Ok(status)
    }

    pub(crate) fn start(
        &mut self,
        runtime: &mut AndroidVaultRuntime,
    ) -> Result<LanPairingStatus, AndroidRuntimeError> {
        self.require_vault(runtime)?;
        let expected = self.vault;
        self.service
            .start_for_vault_with_authorization(
                Instant::now(),
                self.vault,
                |vault, peer, fingerprint, enabled| {
                    vault == expected
                        && runtime
                            .sync_authorize_peer(peer, fingerprint, enabled)
                            .is_ok()
                },
            )
            .map_err(|message| match message.as_str() {
                "无法启动局域网配对监听。" => {
                    AndroidRuntimeError::LanListenerUnavailable
                }
                "无法启动局域网发现。" => AndroidRuntimeError::LanDiscoveryUnavailable,
                "无法启动局域网扫描。" => AndroidRuntimeError::LanScanUnavailable,
                "无法读取局域网设备身份。"
                | "局域网设备身份已损坏。"
                | "局域网设备身份版本不兼容。"
                | "无法生成局域网设备身份。"
                | "无法保存局域网设备身份。" => {
                    AndroidRuntimeError::LanIdentityUnavailable
                }
                _ => AndroidRuntimeError::Io,
            })?;
        self.status(runtime)
    }

    pub(crate) fn begin(
        &mut self,
        runtime: &AndroidVaultRuntime,
        peer: &str,
        code: Zeroizing<String>,
    ) -> Result<(), AndroidRuntimeError> {
        self.require_vault(runtime)?;
        self.service
            .begin(peer, code)
            .map_err(|_| AndroidRuntimeError::InvalidInput)
    }

    pub(crate) fn set_sync_enabled(&mut self, runtime: &mut AndroidVaultRuntime, peer: &str, enabled: bool) -> Result<(), AndroidRuntimeError> {
        self.require_vault(runtime)?;
        let fingerprint = self.service.peer_fingerprint(peer).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        runtime.sync_authorize_peer(peer, &fingerprint, enabled)
    }

    pub(crate) fn revoke(
        &mut self,
        runtime: &mut AndroidVaultRuntime,
        peer: &str,
    ) -> Result<(), AndroidRuntimeError> {
        self.require_vault(runtime)?;
        let fingerprint = self
            .service
            .peer_fingerprint(peer)
            .map_err(|_| AndroidRuntimeError::InvalidInput)?;
        runtime.sync_authorize_peer(peer, &fingerprint, false)?;
        self.service
            .revoke(peer)
            .map_err(|_| AndroidRuntimeError::Io)
    }

    pub(crate) fn rename(
        &mut self,
        runtime: &AndroidVaultRuntime,
        peer: &str,
        label: &str,
    ) -> Result<(), AndroidRuntimeError> {
        self.require_vault(runtime)?;
        self.service
            .rename(peer, label)
            .map_err(|_| AndroidRuntimeError::InvalidInput)
    }

    pub(crate) fn stop(&mut self, runtime: &mut AndroidVaultRuntime) {
        let expected = self.vault;
        self.service
            .stop_with_authorization(|vault, peer, fingerprint, enabled| {
                vault == expected
                    && runtime
                        .sync_authorize_peer(peer, fingerprint, enabled)
                        .is_ok()
            });
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex, thread, time::Duration};
    use vaultmesh_lan_pairing::CredentialStore;

    #[derive(Default)]
    struct DesktopTestCredentials(Mutex<HashMap<String, Vec<u8>>>);
    impl CredentialStore for DesktopTestCredentials {
        fn set(&self, account: &str, value: &[u8]) -> Result<(), ()> {
            self.0
                .lock()
                .map_err(|_| ())?
                .insert(account.into(), value.into());
            Ok(())
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
            Ok(self
                .0
                .lock()
                .map_err(|_| ())?
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }
        fn delete(&self, account: &str) -> Result<(), ()> {
            self.0.lock().map_err(|_| ())?.remove(account);
            Ok(())
        }
    }

    #[test]
    fn android_pairing_requires_unlocked_vault_and_sync_authorization_is_persistent() {
        let directory =
            std::env::temp_dir().join(format!("vaultmesh-android-lan-{}", Uuid::new_v4()));
        let mut vault = AndroidVaultRuntime::new(&directory).unwrap();
        assert!(matches!(
            AndroidLanPairing::open(&vault, [7; 32]),
            Err(AndroidRuntimeError::Locked)
        ));
        vault.create("synthetic-master-password").unwrap();
        let id = vault.sync_vault_id().unwrap();
        let mut lan = AndroidLanPairing::open(&vault, [7; 32]).unwrap();
        let status = lan.status(&mut vault).unwrap();
        assert!(!status.discoverable);
        assert!(status.nearby.is_empty());
        assert!(status.trusted.is_empty());
        let peer = format!("lan-peer-{}", "a".repeat(32));
        let fingerprint = "b".repeat(64);
        vault
            .sync_authorize_peer(&peer, &fingerprint, true)
            .unwrap();
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .any(|authorization| authorization.peer == peer && authorization.enabled)
        );
        lan.stop(&mut vault);
        vault.lock();
        assert!(matches!(
            lan.status(&mut vault),
            Err(AndroidRuntimeError::Locked)
        ));
        vault.unlock("synthetic-master-password").unwrap();
        assert_eq!(vault.sync_vault_id().unwrap(), id);
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .any(|authorization| authorization.peer == peer && authorization.enabled)
        );
        vault
            .sync_authorize_peer(&peer, &fingerprint, false)
            .unwrap();
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .any(|authorization| authorization.peer == peer && !authorization.enabled)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires host multicast support; run explicitly for desktop↔Android protocol smoke"]
    fn desktop_and_android_adapters_pair_over_real_mdns_tls_and_pake() {
        let directory = std::env::temp_dir().join(format!(
            "vaultmesh-android-lan-integration-{}",
            Uuid::new_v4()
        ));
        let mut vault = AndroidVaultRuntime::new(directory.join("android")).unwrap();
        vault.create("synthetic-master-password").unwrap();
        let mut android = AndroidLanPairing::open(&vault, [7; 32]).unwrap();
        let mut desktop = LanPairingService::new_with_credentials(
            directory.join("desktop-peers.json"),
            Arc::new(DesktopTestCredentials::default()),
        );
        let desktop_vault = Uuid::new_v4();
        desktop
            .start_for_vault(Instant::now(), desktop_vault)
            .unwrap();
        android.start(&mut vault).unwrap();
        let expected_desktop = desktop.local_pairing_ref().unwrap();
        let mut target = None;
        for _ in 0..60 {
            let status = android.status(&mut vault).unwrap();
            let desktop_status =
                desktop.status_with_authorization(Instant::now(), unix_millis(), |id, _, _, _| {
                    id == desktop_vault
                });
            if let (Some(peer), Some(code)) = (
                status
                    .nearby
                    .iter()
                    .find(|peer| peer.pairing_ref == expected_desktop),
                desktop_status.pairing_code,
            ) {
                target = Some((peer.pairing_ref.clone(), code));
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let (peer, code) =
            target.expect("desktop advertisement must be visible to Android adapter");
        android.begin(&vault, &peer, Zeroizing::new(code)).unwrap();
        let mut paired = false;
        let mut last = String::new();
        for _ in 0..100 {
            let status = android.status(&mut vault).unwrap();
            let desktop_status =
                desktop.status_with_authorization(Instant::now(), unix_millis(), |id, _, _, _| {
                    id == desktop_vault
                });
            last = format!(
                "android nearby={:?} trusted={} desktop nearby={:?} trusted={}",
                status
                    .nearby
                    .iter()
                    .map(|peer| peer.status)
                    .collect::<Vec<_>>(),
                status.trusted.len(),
                desktop_status
                    .nearby
                    .iter()
                    .map(|peer| peer.status)
                    .collect::<Vec<_>>(),
                desktop_status.trusted.len()
            );
            if status.trusted.len() == 1 && desktop_status.trusted.len() == 1 {
                paired = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            paired,
            "both adapters must persist the same authenticated peer session: {last}"
        );
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .any(|auth| auth.enabled)
        );
        let trusted = android
            .status(&mut vault)
            .unwrap()
            .trusted
            .into_iter()
            .next()
            .unwrap();
        let desktop_peer = desktop
            .status_with_authorization(Instant::now(), unix_millis(), |id, _, _, _| {
                id == desktop_vault
            })
            .trusted[0]
            .pairing_ref
            .clone();
        android
            .rename(&vault, &trusted.pairing_ref, "Synthetic desktop")
            .unwrap();
        assert_eq!(
            android.status(&mut vault).unwrap().trusted[0].label,
            "Synthetic desktop"
        );
        android.revoke(&mut vault, &trusted.pairing_ref).unwrap();
        assert!(android.status(&mut vault).unwrap().trusted.is_empty());
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .all(|auth| !auth.enabled)
        );
        desktop.revoke(&desktop_peer).unwrap();
        android.stop(&mut vault);
        desktop.stop();

        desktop
            .start_for_vault(Instant::now(), desktop_vault)
            .unwrap();
        android.start(&mut vault).unwrap();
        let expected_android = android.service.local_pairing_ref().unwrap();
        let mut reverse_target = None;
        for _ in 0..60 {
            let status = android.status(&mut vault).unwrap();
            let desktop_status =
                desktop.status_with_authorization(Instant::now(), unix_millis(), |id, _, _, _| {
                    id == desktop_vault
                });
            if let (Some(peer), Some(code)) = (
                desktop_status
                    .nearby
                    .iter()
                    .find(|peer| peer.pairing_ref == expected_android),
                status.pairing_code,
            ) {
                reverse_target = Some((peer.pairing_ref.clone(), code));
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let (peer, code) =
            reverse_target.expect("Android advertisement must be visible to desktop adapter");
        desktop.begin(&peer, Zeroizing::new(code)).unwrap();
        let mut reverse_paired = false;
        let mut reverse_last = String::new();
        for _ in 0..100 {
            let status = android.status(&mut vault).unwrap();
            let desktop_status =
                desktop.status_with_authorization(Instant::now(), unix_millis(), |id, _, _, _| {
                    id == desktop_vault
                });
            reverse_last = format!(
                "android nearby={:?} trusted={} desktop nearby={:?} trusted={}",
                status
                    .nearby
                    .iter()
                    .map(|peer| peer.status)
                    .collect::<Vec<_>>(),
                status.trusted.len(),
                desktop_status
                    .nearby
                    .iter()
                    .map(|peer| peer.status)
                    .collect::<Vec<_>>(),
                desktop_status.trusted.len()
            );
            if status.trusted.len() == 1 && desktop_status.trusted.len() == 1 {
                reverse_paired = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            reverse_paired,
            "desktop-initiated pairing must persist on both adapters: {reverse_last}"
        );
        assert!(
            vault
                .session
                .as_ref()
                .unwrap()
                .sync_state()
                .unwrap()
                .authorizations
                .iter()
                .any(|auth| auth.enabled)
        );
        android.stop(&mut vault);
        desktop.stop();
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    #[ignore = "requires LAN multicast; CT-ANDROID-LAN-SYNC-001 explicit host integration"]
    fn android_desktop_sync_survives_stopped_pairing_lock_and_reconnect() {
        use vaultmesh_sync::SyncRuntime;
        use vaultmesh_lan_pairing::LanSyncService;
        let directory = std::env::temp_dir().join(format!("vaultmesh-android-sync-{}", Uuid::new_v4()));
        let mut android = AndroidVaultRuntime::new(directory.join("android")).unwrap();
        android.create("synthetic-android-master").unwrap();
        let mut desktop = vaultmesh_ffi::DesktopRuntime::new(directory.join("desktop.vault")).unwrap();
        desktop.create("synthetic-desktop-master".into()).unwrap();
        let credentials = Arc::new(DesktopTestCredentials::default());
        let mut pair_a = AndroidLanPairing::open(&android, [9; 32]).unwrap();
        let mut pair_b = LanPairingService::new_with_credentials(directory.join("desktop-peers.json"), credentials.clone());
        let id_b = desktop.sync_state().unwrap().vault_id;
        pair_b.start_for_vault(Instant::now(), id_b).unwrap();
        pair_a.start(&mut android).unwrap();
        let desktop_ref = pair_b.local_pairing_ref().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut began = false;
        loop {
            let a = pair_a.status(&mut android).unwrap();
            let b = pair_b.status_with_authorization(Instant::now(), unix_millis(), |id, peer, fp, enabled| {
                id == id_b && desktop.sync_authorize(peer, fp, enabled).is_ok()
            });
            if !began && a.nearby.iter().any(|p| p.pairing_ref == desktop_ref) {
                pair_a.begin(&android, &desktop_ref, Zeroizing::new(b.pairing_code.unwrap())).unwrap();
                began = true;
            }
            if a.trusted.len() == 1 && b.trusted.len() == 1 { break; }
            assert!(Instant::now() < deadline, "pairing did not complete");
            thread::sleep(Duration::from_millis(100));
        }
        let desktop_ref = pair_a.status(&mut android).unwrap().trusted[0].pairing_ref.clone();
        // Regression: all discovery, code and pairing connections are now gone.
        pair_a.stop(&mut android);
        pair_b.stop();
        assert!(!pair_a.status(&mut android).unwrap().discoverable);
        let android = Arc::new(Mutex::new(android));
        let desktop = Arc::new(Mutex::new(desktop));
        let mut a = LanSyncService::new_with_credentials(android.clone(), directory.join("android/lan-pairing-peers.json"),
            Arc::new(AndroidLanCredentials::new(directory.join("android/lan-pairing-secrets"), [9;32]).unwrap()));
        let mut b = LanSyncService::new_with_credentials(desktop.clone(), directory.join("desktop-peers.json"), credentials);
        let wait = |a: &mut LanSyncService<AndroidVaultRuntime>, b: &mut LanSyncService<vaultmesh_ffi::DesktopRuntime>, condition: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(35);
            loop { a.tick(); b.tick(); if condition() { break; }
                assert!(Instant::now() < deadline, "sync did not converge: android={} desktop={}", a.status().ok().and_then(|s|serde_json::to_string(&s).ok()).unwrap_or_else(||"locked".into()), b.status().ok().and_then(|s|serde_json::to_string(&s).ok()).unwrap_or_else(||"locked".into()));
                thread::sleep(Duration::from_millis(100));
            }
        };
        android.lock().unwrap().add_login("Android entry".into(), "synthetic".into(), "synthetic-secret".into(), None).unwrap();
        wait(&mut a, &mut b, &|| desktop.lock().unwrap().status().item_count == 1);
        eprintln!("initial Android -> desktop completed");
        // Lock Android, then mutate the desktop. Receipt must be ciphertext-only until unlock.
        a.lock_sensitive();
        android.lock().unwrap().lock();
        desktop.lock().unwrap().execute("items.add", serde_json::json!({"title":"Desktop entry","username":"synthetic","password":"synthetic-secret","url":null,"notes":null,"folder":null,"favorite":false,"totpSecret":null,"recoveryCodes":[],"additionalUrls":[],"autofillOnPageLoad":false,"masterPasswordReprompt":false,"customFields":[]})).unwrap();
        wait(&mut a, &mut b, &|| android.lock().unwrap().sync_relay().summary(&desktop_ref).ok().is_some_and(|s| s.received.is_some()));
        eprintln!("locked ciphertext delivered");
        assert_eq!(android.lock().unwrap().status(), crate::RuntimeStatus::Locked);
        assert!(android.lock().unwrap().list_logins().is_err());
        android.lock().unwrap().unlock("synthetic-android-master").unwrap();
        wait(&mut a, &mut b, &|| android.lock().unwrap().list_logins().unwrap().len() == 2);
        eprintln!("unlock merge completed");
        a.stop(); b.stop();
        let id = android.lock().unwrap().list_logins().unwrap().into_iter().find(|p| p.title == "Android entry").unwrap().id;
        android.lock().unwrap().delete_login(&id).unwrap();
        wait(&mut a, &mut b, &|| desktop.lock().unwrap().status().item_count == 1);
        // Revocation removes the route before any further publish.
        a.interrupt_peer(&desktop_ref);
        let fp = pair_a.service.peer_fingerprint(&desktop_ref).unwrap();
        android.lock().unwrap().sync_authorize_peer(&desktop_ref, &fp, false).unwrap();
        assert!(android.lock().unwrap().sync_relay().route(&desktop_ref).is_err());
        a.stop(); b.stop();
        drop(a); drop(b); drop(android); drop(desktop);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "AT-ANDROID-022 companion: requires instrumented Android device and VM_SYNC_TEST_DIR"]
    fn desktop_companion_for_android_sync_instrumentation() {
        use vaultmesh_lan_pairing::LanSyncService;
        let directory = PathBuf::from(std::env::var("VM_SYNC_TEST_DIR").expect("synthetic test directory required"));
        assert!(directory.file_name().unwrap().to_string_lossy().starts_with("vaultmesh-sync-device-"));
        std::fs::create_dir_all(&directory).unwrap();
        let mut desktop = vaultmesh_ffi::DesktopRuntime::new(directory.join("synthetic.vault")).unwrap();
        desktop.create("synthetic-device-companion".into()).unwrap();
        fn add(r: &mut vaultmesh_ffi::DesktopRuntime, title: &str) {
            r.execute("items.add", serde_json::json!({"title":title,"username":"synthetic","password":"synthetic-secret","url":null,"notes":null,"folder":null,"favorite":false,"totpSecret":null,"recoveryCodes":[],"additionalUrls":[],"autofillOnPageLoad":false,"masterPasswordReprompt":false,"customFields":[]})).unwrap();
        }
        add(&mut desktop,"Desktop seed");
        let id = desktop.sync_state().unwrap().vault_id;
        let credentials = Arc::new(DesktopTestCredentials::default());
        let mut pairing = LanPairingService::new_with_credentials(directory.join("peers.json"),credentials.clone());
        pairing.start_for_vault(Instant::now(),id).unwrap();
        let status = pairing.status(Instant::now(),unix_millis());
        std::fs::write(directory.join("pairing.json"),serde_json::to_vec(&serde_json::json!({"peer":pairing.local_pairing_ref().unwrap(),"code":status.pairing_code.unwrap()})).unwrap()).unwrap();
        let deadline = Instant::now()+Duration::from_secs(180);
        loop {
            let status = pairing.status_with_authorization(Instant::now(),unix_millis(),|vault,peer,fp,enabled|vault==id && desktop.sync_authorize(peer,fp,enabled).is_ok());
            if status.trusted.len()==1 { break; }
            assert!(Instant::now()<deadline,"device pairing timeout");
            thread::sleep(Duration::from_millis(100));
        }
        pairing.stop();
        let desktop=Arc::new(Mutex::new(desktop));
        let mut sync=LanSyncService::new_with_credentials(desktop.clone(),directory.join("peers.json"),credentials);
        let mut response=false; let mut locked_response=false;
        loop {
            sync.tick();
            let mut r=desktop.lock().unwrap();
            let items=r.execute("items.list",serde_json::json!({})).unwrap();
            let text=items.to_string();
            assert!(!text.contains("Revoked change"), "revoked authorization must not deliver changes");
            if text.contains("Android outbound") && !response { add(&mut r,"Desktop response"); response=true; }
            if text.contains("Lock trigger") && directory.join("locked").exists() && !locked_response { add(&mut r,"Locked response"); locked_response=true; }
            if text.contains("Android reconnect") {
                std::fs::write(directory.join("success"),"paired; scan stopped; bidirectional; locked delivery; reconnect").unwrap();
            }
            drop(r);
            std::fs::write(directory.join("status.json"),serde_json::to_vec(&sync.status().unwrap()).unwrap()).unwrap();
            if directory.join("stop").exists() { break; }
            assert!(Instant::now()<deadline,"device sync timeout");
            thread::sleep(Duration::from_millis(100));
        }
        sync.stop();
        assert!(response && locked_response && directory.join("success").exists());
    }

    #[test]
    #[ignore = "AT-DEVICE-ASSIST-001 transport slice: requires Android and VM_ASSIST_TEST_DIR"]
    fn desktop_companion_for_android_assist_instrumentation() {
        use vaultmesh_lan_pairing::assist::{AssistClient, Kind};
        let origin = std::env::var("VM_ASSIST_TEST_ORIGIN").unwrap_or_else(|_| "https://synthetic.example".into());
        assert!(["https://synthetic.example", "http://synthetic.example", "http://localhost:4173"].contains(&origin.as_str()));
        let directory = PathBuf::from(std::env::var("VM_ASSIST_TEST_DIR").expect("synthetic test directory"));
        assert!(directory.file_name().unwrap().to_string_lossy().starts_with("vaultmesh-assist-device-"));
        let mut desktop = vaultmesh_ffi::DesktopRuntime::new(directory.join("synthetic.vault")).unwrap();
        desktop.create("synthetic-device-companion".into()).unwrap();
        let vault = desktop.sync_state().unwrap().vault_id;
        let credentials = Arc::new(DesktopTestCredentials::default());
        let mut pairing = LanPairingService::new_with_credentials(directory.join("peers.json"), credentials.clone());
        pairing.start_for_vault(Instant::now(), vault).unwrap();
        let status = pairing.status(Instant::now(), unix_millis());
        std::fs::write(directory.join("pairing.json"), serde_json::to_vec(&serde_json::json!({"peer":pairing.local_pairing_ref().unwrap(), "code":status.pairing_code.unwrap()})).unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let status = pairing.status_with_authorization(Instant::now(), unix_millis(), |id, peer, fp, enabled| id == vault && desktop.sync_authorize(peer, fp, enabled).is_ok());
            if status.trusted.len() == 1 { break; }
            assert!(Instant::now() < deadline, "pair timeout");
            thread::sleep(Duration::from_millis(100));
        }
        pairing.stop();
        let mut client = AssistClient::with_credentials(directory.join("peers.json"), credentials).unwrap();
        let pushed = std::env::var("VM_ASSIST_TEST_PUSH").as_deref() == Ok("1");
        if pushed {client.enable_registration("synthetic-device-vault").unwrap();}
        while !directory.join("locked").exists() {
            assert!(Instant::now() < deadline, "lock timeout");
            thread::sleep(Duration::from_millis(100));
        }
        if pushed {
            while !directory.join("offline").exists() {
                assert!(Instant::now() < deadline, "offline marker timeout");
                thread::sleep(Duration::from_millis(100));
            }
        }
        for (kind, expected) in [(Kind::Phone, "+12025550123"), (Kind::Sms, "123456")] {
            let id = client.begin(kind, &origin).unwrap();
            if pushed {assert!(!client.status(&id).unwrap()["candidates"].as_array().unwrap().is_empty(), "passive candidate unavailable after phone stopped");}
            loop {
                let state = client.status(&id).unwrap();
                assert!(!state.to_string().contains(expected), "ordinary DTO leaked value");
                if let Some(candidate) = state["candidates"].as_array().unwrap().first() {
                    client.consume(&id, candidate["id"].as_str().unwrap()).unwrap();
                    if pushed {assert_eq!(client.status(&id).unwrap()["ready"], true, "cached selection waited for phone");}
                    break;
                }
                client.refresh(&id).unwrap();
                assert!(Instant::now() < deadline, "candidate timeout");
                thread::sleep(Duration::from_millis(200));
            }
            loop {
                let state = client.status(&id).unwrap();
                assert!(!state["failed"].as_bool().unwrap(), "delivery failed");
                if state["ready"] == true {
                    assert!(client.take(&id).unwrap().as_str() == expected, "unexpected synthetic value");
                    assert!(client.take(&id).is_err()); break;
                }
                assert!(Instant::now() < deadline, "result timeout");
                thread::sleep(Duration::from_millis(100));
            }
        }
        std::fs::write(directory.join("success"), "locked native phone and request-bound manual SMS delivery").unwrap();
        while !directory.join("stop").exists() {
            assert!(Instant::now() < deadline, "device completion timeout");
            thread::sleep(Duration::from_millis(100));
        }
    }

}
