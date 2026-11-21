use std::{
    fmt::Debug,
    path::Path,
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{PinSetupInput, RuntimeState, pin_service::PinQuickUnlockService, require_empty_object};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinDomainKind {
    Desktop,
    Browser,
    Agent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinDomainAction {
    Status,
    Enable,
    Disable,
}

pub(crate) trait PinDomainAdapter: Send + Sync + Debug {
    fn kind(&self) -> PinDomainKind;
    fn service<'a>(&self, state: &'a RuntimeState) -> &'a Arc<Mutex<PinQuickUnlockService>>;
    fn unavailable_error(&self) -> &'static str;
    fn status_requires_desktop_unlock(&self) -> bool;
    fn resets_failures_on_desktop_master_unlock(&self) -> bool;

    fn mismatch_error(&self) -> &'static str {
        match self.kind() {
            PinDomainKind::Desktop => "桌面端 PIN 不属于当前保险库，请使用主密码解锁。",
            PinDomainKind::Browser => "浏览器插件 PIN 不属于当前保险库，请使用主密码解锁。",
            PinDomainKind::Agent => "Agent PIN 不属于当前保险库，请使用主密码解锁。",
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct DesktopPinDomainAdapter;

impl PinDomainAdapter for DesktopPinDomainAdapter {
    fn kind(&self) -> PinDomainKind {
        PinDomainKind::Desktop
    }

    fn service<'a>(&self, state: &'a RuntimeState) -> &'a Arc<Mutex<PinQuickUnlockService>> {
        &state.pin
    }

    fn unavailable_error(&self) -> &'static str {
        "PIN 快速解锁暂时不可用。"
    }

    fn status_requires_desktop_unlock(&self) -> bool {
        false
    }

    fn resets_failures_on_desktop_master_unlock(&self) -> bool {
        true
    }
}

#[derive(Debug, Default)]
pub(crate) struct BrowserPinDomainAdapter;

impl PinDomainAdapter for BrowserPinDomainAdapter {
    fn kind(&self) -> PinDomainKind {
        PinDomainKind::Browser
    }

    fn service<'a>(&self, state: &'a RuntimeState) -> &'a Arc<Mutex<PinQuickUnlockService>> {
        &state.browser_pin
    }

    fn unavailable_error(&self) -> &'static str {
        "浏览器插件 PIN 快速解锁暂时不可用。"
    }

    fn status_requires_desktop_unlock(&self) -> bool {
        true
    }

    fn resets_failures_on_desktop_master_unlock(&self) -> bool {
        false
    }
}

#[derive(Debug, Default)]
pub(crate) struct AgentPinDomainAdapter;

impl PinDomainAdapter for AgentPinDomainAdapter {
    fn kind(&self) -> PinDomainKind {
        PinDomainKind::Agent
    }

    fn service<'a>(&self, state: &'a RuntimeState) -> &'a Arc<Mutex<PinQuickUnlockService>> {
        &state.agent_pin
    }

    fn unavailable_error(&self) -> &'static str {
        "Agent PIN 快速解锁暂时不可用。"
    }

    fn status_requires_desktop_unlock(&self) -> bool {
        true
    }

    fn resets_failures_on_desktop_master_unlock(&self) -> bool {
        false
    }
}

static DESKTOP_PIN_ADAPTER: DesktopPinDomainAdapter = DesktopPinDomainAdapter;
static BROWSER_PIN_ADAPTER: BrowserPinDomainAdapter = BrowserPinDomainAdapter;
static AGENT_PIN_ADAPTER: AgentPinDomainAdapter = AgentPinDomainAdapter;

pub(crate) struct PinDomainFactory;

impl PinDomainFactory {
    pub(crate) fn all() -> [&'static dyn PinDomainAdapter; 3] {
        [&DESKTOP_PIN_ADAPTER, &BROWSER_PIN_ADAPTER, &AGENT_PIN_ADAPTER]
    }

    pub(crate) fn create_for(kind: PinDomainKind) -> &'static dyn PinDomainAdapter {
        match kind {
            PinDomainKind::Desktop => &DESKTOP_PIN_ADAPTER,
            PinDomainKind::Browser => &BROWSER_PIN_ADAPTER,
            PinDomainKind::Agent => &AGENT_PIN_ADAPTER,
        }
    }
}

pub(crate) fn execute_pin_domain_action(
    state: &RuntimeState,
    adapter: &dyn PinDomainAdapter,
    action: PinDomainAction,
    input: Value,
) -> Result<Value, String> {
    match action {
        PinDomainAction::Status => {
            require_empty_object(&input)?;
            if adapter.status_requires_desktop_unlock() {
                let unlocked = state
                    .runtime
                    .lock()
                    .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                    .status()
                    .unlocked;
                if !unlocked {
                    return Err("请先在桌面端解锁保险库。".to_owned());
                }
            }
            let pin = adapter
                .service(state)
                .lock()
                .map_err(|_| adapter.unavailable_error().to_owned())?;
            Ok(json!(pin.status()))
        }
        PinDomainAction::Enable => {
            let setup: PinSetupInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let pin_value = Zeroizing::new(setup.pin);
            let mut runtime = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?;
            runtime
                .refresh_from_disk()
                .map_err(|_| "请先在桌面端解锁保险库。".to_owned())?;
            let (vault_path, vault_key) = runtime
                .quick_unlock_material()
                .map_err(|_| "请先在桌面端解锁保险库。".to_owned())?;
            let pin = adapter
                .service(state)
                .lock()
                .map_err(|_| adapter.unavailable_error().to_owned())?;
            pin.enable(
                vault_path,
                vault_key.as_ref(),
                pin_value.as_str(),
                setup.failure_limit,
            )
            .map(|status| json!(status))
        }
        PinDomainAction::Disable => {
            require_empty_object(&input)?;
            let unlocked = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .status()
                .unlocked;
            if !unlocked {
                return Err("请先在桌面端解锁保险库。".to_owned());
            }
            let pin = adapter
                .service(state)
                .lock()
                .map_err(|_| adapter.unavailable_error().to_owned())?;
            pin.disable()?;
            Ok(json!(pin.status()))
        }
    }
}

pub(crate) async fn execute_pin_domain_action_async(
    state: &RuntimeState,
    kind: PinDomainKind,
    action: PinDomainAction,
    input: Value,
) -> Result<Value, String> {
    let state = state.clone();
    tauri::async_runtime::spawn_blocking(move || {
        execute_pin_domain_action(&state, PinDomainFactory::create_for(kind), action, input)
    })
    .await
    .map_err(|_| "PIN 快速解锁操作未能完成。".to_owned())?
}

pub(crate) fn disable_all_domain_pins_sync(state: &RuntimeState) -> Result<(), String> {
    for adapter in PinDomainFactory::all() {
        adapter
            .service(state)
            .lock()
            .map_err(|_| adapter.unavailable_error().to_owned())?
            .disable()?;
    }
    Ok(())
}

pub(crate) async fn disable_all_domain_pins(state: &RuntimeState) -> Result<(), String> {
    let state = state.clone();
    tauri::async_runtime::spawn_blocking(move || disable_all_domain_pins_sync(&state))
        .await
        .map_err(|_| "PIN 快速解锁操作未能完成。".to_owned())?
}

pub(crate) fn reconcile_pins_after_desktop_master_unlock(
    state: &RuntimeState,
    vault_path: &Path,
) -> Result<(), String> {
    for adapter in PinDomainFactory::all() {
        let pin = adapter
            .service(state)
            .lock()
            .map_err(|_| adapter.unavailable_error().to_owned())?;
        pin.disable_if_for_different_vault(vault_path)?;
        if adapter.resets_failures_on_desktop_master_unlock() {
            pin.reset_failures(vault_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_runtime_state(root: &Path) -> RuntimeState {
    use std::sync::atomic::AtomicU64;
    use vaultmesh_ffi::DesktopRuntime;

    struct TestRootSecret;
    impl crate::device_credentials::RootSecretStore for TestRootSecret {
        fn get_or_create_root_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
            Ok(Zeroizing::new([0x37_u8; 32]))
        }
    }

    std::fs::create_dir_all(root).expect("test root");
    let credentials_store = Arc::new(
        crate::device_credentials::DeviceCredentialStore::with_stores(
            root.join("device-credentials.enc"),
            Arc::new(TestRootSecret),
        )
        .expect("test credential store"),
    );
    let vault_path = root.join("vaultmesh.vault");
    let runtime = Arc::new(Mutex::new(
        DesktopRuntime::new(vault_path.clone()).expect("runtime"),
    ));
    let agent_vault_access =
        crate::AgentVaultAccess::new(vault_path.clone(), root.join("agent-access-settings.json"))
            .expect("agent access");
    let mut agent_broker_core = crate::AgentBrokerCore::new_with_pairing_proofs(
        crate::AgentPairingProofs::platform(root.join("agent-pairings.json"), &credentials_store),
    )
    .expect("agent broker");
    agent_broker_core.set_authorization_store(crate::AgentAuthorizationStore::platform(
        root.join("agent-authorizations.v1"),
        &vault_path,
        &credentials_store,
    ));
    let lan_credentials: Arc<dyn crate::lan_pairing::CredentialStore> =
        Arc::new(credentials_store.scoped("com.vaultmesh.desktop.lan-pairing"));
    let lan_sync = Arc::new(Mutex::new(crate::LanSyncService::new_with_credentials(
        Arc::clone(&runtime),
        root.join("lan-peer-trust.json"),
        Arc::clone(&lan_credentials),
    )));
    RuntimeState {
        runtime,
        agent_vault_access,
        agent_pin: Arc::new(Mutex::new(
            PinQuickUnlockService::new_agent_with_credentials(
                root.join("agent-pin-unlock.json"),
                &credentials_store,
            ),
        )),
        agent_biometric: Arc::new(Mutex::new(
            crate::BiometricQuickUnlockService::new_with_credentials(
                root.join("agent-biometric-unlock.json"),
                credentials_store.scoped("com.vaultmesh.desktop.agent-biometric"),
                "agent-biometric",
            ),
        )),
        agent_broker: Arc::new(Mutex::new(agent_broker_core)),
        agent_pairing_window_request: Arc::new(Mutex::new(None)),
        agent_unlock_window_request: Arc::new(Mutex::new(None)),
        browser_unlocks: Arc::new(Mutex::new(
            crate::agent_unlock_window::BrowserUnlockQueue::default(),
        )),
        agent_authorization_window_request: Arc::new(Mutex::new(None)),
        agent_authorization_window_deadline: Arc::new(AtomicU64::new(0)),
        agent_resources: Arc::new(Mutex::new(crate::AgentResourceStore::default())),
        agent_managed_web: Arc::new(Mutex::new(crate::AgentManagedWebStore::default())),
        agent_ssh_sessions: Arc::new(Mutex::new(crate::AgentSshSessionStore::default())),
        agent_ssh_agent_registry: Arc::new(Mutex::new(
            crate::agent_ssh_agent::SshAgentRegistry::new_with_device_id("test-device".into()),
        )),
        #[cfg(unix)]
        _agent_listener: None,
        #[cfg(target_os = "windows")]
        _agent_pipe_listener: None,
        #[cfg(unix)]
        _browser_listener: None,
        #[cfg(unix)]
        _browser_http_listener: None,
        _bitwarden_development_listener: None,
        #[cfg(target_os = "windows")]
        browser_integration: Arc::new(Mutex::new(
            crate::browser_integration_windows::WindowsBrowserIntegration::new(
                root.to_path_buf(),
                Arc::new(|| Err(crate::browser_integration_windows::BrowserIntegrationError::BrokerUnavailable)),
            ),
        )),
        app_data: root.to_path_buf(),
        settings: Arc::new(Mutex::new(crate::SecuritySettings::default())),
        settings_path: root.join("security-settings.json"),
        last_activity: Arc::new(AtomicU64::new(1)),
        native_dialog_focus: Arc::new(crate::NativeDialogFocusState::default()),
        clipboard_value: Arc::new(Mutex::new(None)),
        imports: Arc::new(Mutex::new(crate::ImportService::default())),
        api_requests: Arc::new(Mutex::new(crate::DesktopApiRequestStore::default())),
        ssh_directory: root.join(".ssh"),
        ssh_launch_directory: root.join("ssh-launches"),
        ssh_scan: Arc::new(Mutex::new(crate::SshScanService::default())),
        email_otp: Arc::new(Mutex::new(crate::EmailOtpService::new(
            root.join("email-otp-settings.json"),
        ))),
        biometric: Arc::new(Mutex::new(
            crate::BiometricQuickUnlockService::new_with_credentials(
                root.join("desktop-biometric-unlock.json"),
                credentials_store.scoped("com.vaultmesh.desktop.desktop-biometric"),
                "desktop-biometric",
            ),
        )),
        desktop_authentication: Arc::new(Mutex::new(
            crate::desktop_authentication::Coordinator::default(),
        )),
        pin: Arc::new(Mutex::new(PinQuickUnlockService::new_with_credentials(
            root.join("desktop-pin-unlock.json"),
            &credentials_store,
        ))),
        browser_pin: Arc::new(Mutex::new(
            PinQuickUnlockService::new_browser_with_credentials(
                root.join("browser-pin-unlock.json"),
                &credentials_store,
            ),
        )),
        browser_preauth_preview: crate::BrowserPreAuthPreviewStore::in_memory(),
        lan_pairing: Arc::new(Mutex::new(crate::LanPairingService::new_with_credentials(
            root.join("lan-peer-trust.json"),
            lan_credentials,
        ))),
        lan_sync,
        vault_path_record: root.join("vault-path"),
        main_window_layout: Arc::new(Mutex::new(
            crate::window_layout_adapter::MainWindowLayoutState::default(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vaultmesh_ffi::DesktopRuntime;

    #[test]
    fn pin_domain_factory_covers_all_three_isolated_domains_and_lifecycle_rules() {
        let all = PinDomainFactory::all();
        assert_eq!(all.len(), 3);

        let desktop = PinDomainFactory::create_for(PinDomainKind::Desktop);
        assert_eq!(desktop.kind(), PinDomainKind::Desktop);
        assert!(!desktop.status_requires_desktop_unlock());
        assert!(desktop.resets_failures_on_desktop_master_unlock());

        let browser = PinDomainFactory::create_for(PinDomainKind::Browser);
        assert_eq!(browser.kind(), PinDomainKind::Browser);
        assert!(browser.status_requires_desktop_unlock());
        assert!(!browser.resets_failures_on_desktop_master_unlock());

        let agent = PinDomainFactory::create_for(PinDomainKind::Agent);
        assert_eq!(agent.kind(), PinDomainKind::Agent);
        assert!(agent.status_requires_desktop_unlock());
        assert!(!agent.resets_failures_on_desktop_master_unlock());
    }

    #[test]
    fn pin_domain_actions_enforce_isolation_disable_all_and_reset_only_desktop_failures() {
        let root = std::env::temp_dir().join(format!("vaultmesh-pin-domain-{}", Uuid::new_v4()));
        let state = test_runtime_state(&root);
        let password = "correct horse battery staple";
        let vault_path = root.join("vaultmesh.vault");
        state
            .runtime
            .lock()
            .unwrap()
            .create(password.to_owned())
            .expect("create vault");
        state.runtime.lock().unwrap().lock();

        // When locked: desktop status allowed, browser/agent status and all enable/disable rejected.
        assert_eq!(
            execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(PinDomainKind::Desktop),
                PinDomainAction::Status,
                json!({}),
            )
            .expect("desktop status while locked")["enabled"],
            false
        );
        for kind in [PinDomainKind::Browser, PinDomainKind::Agent] {
            assert!(
                execute_pin_domain_action(
                    &state,
                    PinDomainFactory::create_for(kind),
                    PinDomainAction::Status,
                    json!({}),
                )
                .is_err()
            );
        }
        for kind in [PinDomainKind::Desktop, PinDomainKind::Browser, PinDomainKind::Agent] {
            let err = execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(kind),
                PinDomainAction::Enable,
                json!({ "pin": "111111", "failureLimit": 5 }),
            )
            .unwrap_err();
            assert_eq!(err, "请先在桌面端解锁保险库。");
            assert!(
                execute_pin_domain_action(
                    &state,
                    PinDomainFactory::create_for(kind),
                    PinDomainAction::Disable,
                    json!({}),
                )
                .is_err()
            );
        }

        let (_, quick_key) = {
            let mut runtime = state.runtime.lock().unwrap();
            runtime.unlock(password.to_owned()).unwrap();
            let material = runtime.quick_unlock_material().unwrap();
            runtime.lock();
            material
        };
        for (biometric, pin_code) in [(false, "111111"), (true, "222222")] {
            let mut runtime = state.runtime.lock().unwrap();
            if biometric {
                runtime
                    .unlock_with_biometric_key(vault_path.clone(), quick_key.as_slice())
                    .unwrap();
            } else {
                runtime
                    .unlock_with_quick_key(vault_path.clone(), quick_key.as_slice())
                    .unwrap();
            }
            drop(runtime);
            for adapter in PinDomainFactory::all() {
                let status = execute_pin_domain_action(
                    &state,
                    adapter,
                    PinDomainAction::Enable,
                    json!({ "pin": pin_code, "failureLimit": 5 }),
                )
                .expect("any desktop unlock method can enable all 3 PIN domains");
                assert_eq!(status["enabled"], true);
            }
            state.runtime.lock().unwrap().lock();
        }

        // Unlock desktop and configure distinct PINs for all 3 domains.
        state
            .runtime
            .lock()
            .unwrap()
            .unlock(password.to_owned())
            .expect("unlock");
        for (kind, pin) in [
            (PinDomainKind::Desktop, "111111"),
            (PinDomainKind::Browser, "222222"),
            (PinDomainKind::Agent, "333333"),
        ] {
            let status = execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(kind),
                PinDomainAction::Enable,
                json!({ "pin": pin, "failureLimit": 3 }),
            )
            .expect("enable pin");
            assert_eq!(status["enabled"], true);
        }

        // Cross-check isolation: desktop PIN fails on browser/agent, each domain accepts only its own PIN.
        assert!(state.pin.lock().unwrap().unlock("222222").is_err());
        assert!(state.browser_pin.lock().unwrap().unlock("333333").is_err());
        assert!(state.agent_pin.lock().unwrap().unlock("111111").is_err());

        // Record a second failure across all three domains, then verify desktop master unlock resets ONLY desktop failures.
        assert!(state.pin.lock().unwrap().unlock("000000").is_err());
        assert!(state.browser_pin.lock().unwrap().unlock("000000").is_err());
        assert!(state.agent_pin.lock().unwrap().unlock("000000").is_err());
        reconcile_pins_after_desktop_master_unlock(&state, &vault_path).expect("reconcile");
        assert_eq!(
            execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(PinDomainKind::Desktop),
                PinDomainAction::Status,
                json!({}),
            )
            .unwrap()["failedAttempts"],
            0
        );
        assert_eq!(
            execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(PinDomainKind::Browser),
                PinDomainAction::Status,
                json!({}),
            )
            .unwrap()["failedAttempts"],
            2
        );
        assert_eq!(
            execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Status,
                json!({}),
            )
            .unwrap()["failedAttempts"],
            2
        );

        // Switching to a different vault path disables all three domains.
        let other_vault = root.join("other.vault");
        let mut other = DesktopRuntime::new(other_vault.clone()).expect("other");
        other.create(password.to_owned()).expect("create other");
        reconcile_pins_after_desktop_master_unlock(&state, &other_vault).expect("reconcile other");
        for kind in [PinDomainKind::Desktop, PinDomainKind::Browser, PinDomainKind::Agent] {
            assert_eq!(
                execute_pin_domain_action(
                    &state,
                    PinDomainFactory::create_for(kind),
                    PinDomainAction::Status,
                    json!({}),
                )
                .unwrap()["enabled"],
                false
            );
        }

        // Re-enable all three and verify disable_all_domain_pins_sync clears all three.
        for (kind, pin) in [
            (PinDomainKind::Desktop, "111111"),
            (PinDomainKind::Browser, "222222"),
            (PinDomainKind::Agent, "333333"),
        ] {
            execute_pin_domain_action(
                &state,
                PinDomainFactory::create_for(kind),
                PinDomainAction::Enable,
                json!({ "pin": pin, "failureLimit": 5 }),
            )
            .expect("re-enable");
        }
        disable_all_domain_pins_sync(&state).expect("disable all");
        for kind in [PinDomainKind::Desktop, PinDomainKind::Browser, PinDomainKind::Agent] {
            assert_eq!(
                execute_pin_domain_action(
                    &state,
                    PinDomainFactory::create_for(kind),
                    PinDomainAction::Status,
                    json!({}),
                )
                .unwrap()["enabled"],
                false
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }
}
