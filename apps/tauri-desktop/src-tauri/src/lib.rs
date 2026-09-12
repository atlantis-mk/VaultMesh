use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(any(target_os = "macos", test))]
use tauri::image::Image;
#[cfg(any(target_os = "windows", test))]
use tauri::menu::Submenu;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
#[cfg(test)]
use vaultmesh_ffi::NewAgentConnectorDefinition;
use vaultmesh_ffi::{
    AgentConnectorKind, AgentCredentialKind, AgentHttpAuthStrategy, AgentHttpBodyMode,
    AgentHttpOperationPolicy, AgentRiskTier, AgentTargetPolicy, DesktopRuntime,
    DesktopRuntimeError, VAULTMESH_ITEM_KIND_LOGIN, VAULTMESH_ITEM_KIND_PAYMENT_CARD,
    VAULTMESH_ITEM_KIND_SECRET, VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
    VAULTMESH_PROTECTED_FIELD_CARD_NUMBER, VAULTMESH_PROTECTED_FIELD_CARD_PIN,
    VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE, VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD,
    VAULTMESH_PROTECTED_FIELD_SECRET_VALUE, VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE,
    VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD, VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY,
    VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY, VAULTMESH_STATUS_CONFLICT,
    VAULTMESH_STATUS_CORE_ERROR, VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_IO_ERROR,
    VAULTMESH_STATUS_LOCKED,
};
use zeroize::Zeroizing;

mod agent_admin;
mod agent_authorization_store;
mod agent_authorization_window;
mod agent_broker;
#[cfg(target_os = "windows")]
mod agent_broker_windows;
mod agent_direct_policy;
mod agent_http;
mod agent_http_path_policy;
mod agent_http_runtime;
mod agent_managed_web;
mod agent_operation_plans;
mod agent_pairing;
mod agent_pairing_window;
mod agent_resources;
mod agent_ssh_command_policy;
mod agent_ssh_runtime;
mod agent_ssh_sessions;
mod agent_tool_executor;
mod agent_unlock_window;
mod agent_vault_access;
mod app_setup;
mod app_update;
mod biometric_service;
mod browser_broker;
#[cfg(target_os = "windows")]
mod browser_broker_windows;
#[allow(dead_code)]
mod browser_development_identity;
mod browser_fill;
#[cfg(any(target_os = "windows", test))]
mod browser_host_registration;
#[cfg(target_os = "windows")]
mod browser_integration_windows;
mod browser_pairing;
mod browser_platform;
mod desktop_api_request;
mod desktop_email;
mod desktop_import;
mod desktop_runtime;
mod desktop_ssh_commands;
mod desktop_startup;
mod electron_migration;
mod email_otp;
mod import_service;
mod lan_pairing;
mod passkey_service;
mod pin_service;
mod recovery_code_command;
mod recovery_code_file;
mod ssh_external;
mod ssh_host_setup;
mod ssh_scan;
mod ssh_service;
mod ssh_tools;
#[cfg(any(target_os = "windows", test))]
mod windows_tray_theme;

use agent_admin::*;
use agent_authorization_store::AgentAuthorizationStore;
use agent_authorization_window::{
    DisplayedAgentAuthorization, agent_authorization_resolve_confirmation,
    agent_authorization_resolve_permission, agent_authorization_status,
};
#[cfg(unix)]
use agent_broker::AgentBrokerUnixListener;
use agent_broker::{
    AUTHORIZATION_TTL_MILLIS, AgentAccountCatalog, AgentAccountCatalogSnapshot,
    AgentApiEnvironmentCandidate, AgentApiEnvironmentCatalog, AgentAuditSink, AgentBrokerCore,
    AgentBrokerError, AgentCleanupScope, AgentExecutionScope, AgentNativeUiSurface,
    AgentToolExecutor, AgentVaultAccountCandidate, PermissionChoice, PermissionDuration,
    PermissionEffect, PermissionScope,
};
#[cfg(target_os = "windows")]
use agent_broker_windows::AgentBrokerWindowsListener;
use agent_http_runtime::collect_direct_agent_http_request;
use agent_managed_web::{
    AgentManagedWebOpenPlan, AgentManagedWebProtectedKind, AgentManagedWebStore,
};
use agent_operation_plans::{
    agent_managed_web_credential, agent_managed_web_passkey_binding,
    collect_direct_agent_managed_web_open_plan, validate_direct_agent_connector_policy,
};
use agent_pairing::AgentPairingProofs;
use agent_pairing_window::{agent_pairing_resolve, agent_pairing_status};
use agent_resources::{
    AgentInputFileSelection, AgentResourceStore, load_selected_file, save_result_bytes,
};
use agent_ssh_runtime::{
    collect_direct_agent_ssh_exec_request, collect_direct_agent_ssh_host_setup_request,
    collect_direct_agent_ssh_pty_request, collect_direct_agent_ssh_public_key_install_request,
    collect_direct_agent_ssh_transfer_request, collect_direct_agent_ssh_tunnel_request,
    collect_ssh_external_launch_material,
};
use agent_ssh_sessions::AgentSshSessionStore;
use agent_tool_executor::{AgentToolContext, execute_agent_tool};
use agent_unlock_window::{
    DisplayedAgentUnlock, agent_unlock_cancel, agent_unlock_password, agent_unlock_pin,
    agent_unlock_set_scope, agent_unlock_status,
};
use agent_vault_access::{AgentAccessSettings, AgentUnlockScope, AgentVaultAccess};
pub use app_setup::run;
use biometric_service::BiometricQuickUnlockService;
use browser_pairing::BrowserPairingService;
use browser_platform::TauriBrowserPlatform;
use desktop_api_request::*;
use desktop_email::*;
use desktop_import::*;
use desktop_runtime::*;
use desktop_ssh_commands::*;
use electron_migration::{
    finalize_legacy_electron_migration, migrate_legacy_electron_data, should_migrate_legacy,
};
use email_otp::{EmailOtpService, EmailScanExecution, EmailScanPlan};
use import_service::{ImportService, MAX_IMPORT_FILE_BYTES, validate_source};
use lan_pairing::{LanPairingService, LanSyncService};
use pin_service::PinQuickUnlockService;
use recovery_code_command::import_recovery_code_file;
use recovery_code_file::PreparedRecoveryCodeFile;
use ssh_scan::SshScanService;
use ssh_service::{
    AgentSshExecRequest, AgentSshPtyRequest, AgentSshTransferRequest, AgentSshTunnelRequest,
    AuthenticationMaterial, PrivateKeyMaterial, PublicKeyInstallRequest, SshTarget,
};

#[cfg(unix)]
pub use browser_broker::BrowserBrokerUnixListener;
pub use browser_broker::{
    BrowserBrokerCore, BrowserBrokerPlatform, BrowserPlatformError, TAURI_BROWSER_SLICE_OPERATIONS,
};
#[cfg(target_os = "windows")]
use browser_integration_windows::{BrowserIntegrationError, WindowsBrowserIntegration};

const MAX_COMMAND_BYTES: usize = 1024 * 1024;
#[cfg(any(target_os = "macos", target_os = "windows"))]
const DESKTOP_TRAY_ID: &str = "vaultmesh-status-bar";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const TRAY_SHOW_ID: &str = "vaultmesh-tray-show";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const TRAY_QUIT_ID: &str = "vaultmesh-tray-quit";

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayAction {
    Show,
    Quit,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl TrayAction {
    fn parse(id: &str) -> Option<Self> {
        match id {
            TRAY_SHOW_ID => Some(Self::Show),
            TRAY_QUIT_ID => Some(Self::Quit),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct RuntimeState {
    runtime: Arc<Mutex<DesktopRuntime>>,
    agent_vault_access: AgentVaultAccess,
    agent_pin: Arc<Mutex<PinQuickUnlockService>>,
    agent_broker: Arc<Mutex<AgentBrokerCore>>,
    agent_pairing_window_request: Arc<Mutex<Option<String>>>,
    agent_unlock_window_request: Arc<Mutex<Option<DisplayedAgentUnlock>>>,
    agent_authorization_window_request: Arc<Mutex<Option<DisplayedAgentAuthorization>>>,
    agent_authorization_window_deadline: Arc<AtomicU64>,
    agent_resources: Arc<Mutex<AgentResourceStore>>,
    agent_managed_web: Arc<Mutex<AgentManagedWebStore>>,
    agent_ssh_sessions: Arc<Mutex<AgentSshSessionStore>>,
    #[cfg(unix)]
    _agent_listener: Option<Arc<AgentBrokerUnixListener>>,
    #[cfg(target_os = "windows")]
    _agent_pipe_listener: Option<Arc<AgentBrokerWindowsListener>>,
    #[cfg(unix)]
    _browser_listener: Option<Arc<BrowserBrokerUnixListener>>,
    #[cfg(unix)]
    _bitwarden_development_listener: Option<Arc<BrowserBrokerUnixListener>>,
    #[cfg(target_os = "windows")]
    _bitwarden_development_listener:
        Option<Arc<browser_broker_windows::BrowserBrokerWindowsListener>>,
    #[cfg(target_os = "windows")]
    browser_integration: Arc<Mutex<browser_integration_windows::WindowsBrowserIntegration>>,
    app_data: PathBuf,
    settings: Arc<Mutex<SecuritySettings>>,
    settings_path: PathBuf,
    last_activity: Arc<AtomicU64>,
    native_dialog_focus: Arc<NativeDialogFocusState>,
    clipboard_value: Arc<Mutex<Option<Zeroizing<String>>>>,
    imports: Arc<Mutex<ImportService>>,
    api_requests: Arc<Mutex<DesktopApiRequestStore>>,
    ssh_directory: PathBuf,
    ssh_launch_directory: PathBuf,
    ssh_scan: Arc<Mutex<SshScanService>>,
    email_otp: Arc<Mutex<EmailOtpService>>,
    biometric: Arc<Mutex<BiometricQuickUnlockService>>,
    pin: Arc<Mutex<PinQuickUnlockService>>,
    lan_pairing: Arc<Mutex<LanPairingService>>,
    lan_sync: Arc<Mutex<LanSyncService>>,
    vault_path_record: PathBuf,
}

#[derive(Default)]
pub(crate) struct NativeDialogFocusState {
    depth: AtomicU64,
}

impl NativeDialogFocusState {
    pub(crate) fn begin(self: &Arc<Self>) -> NativeDialogFocusGuard {
        self.depth.fetch_add(1, Ordering::AcqRel);
        NativeDialogFocusGuard {
            state: Arc::clone(self),
        }
    }

    fn is_active(&self) -> bool {
        self.depth.load(Ordering::Acquire) > 0
    }
}

pub(crate) struct NativeDialogFocusGuard {
    state: Arc<NativeDialogFocusState>,
}

impl Drop for NativeDialogFocusGuard {
    fn drop(&mut self) {
        let previous = self.state.depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "native dialog focus guard underflow");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImportOperation {
    Select,
    Commit,
    Cancel,
}

impl ImportOperation {
    fn parse(operation: &str) -> Option<Self> {
        match operation {
            "imports.select" => Some(Self::Select),
            "imports.commit" => Some(Self::Commit),
            "imports.cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DesktopRequest {
    operation: String,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinInput {
    pin: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinSetupInput {
    pin: String,
    failure_limit: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentClientIdInput {
    client_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LanPeerRenameInput {
    pairing_ref: String,
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LanPairingRefInput {
    pairing_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LanPairingBeginInput {
    pairing_ref: String,
    pairing_code: String,
}

impl Drop for LanPairingBeginInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.pairing_code.zeroize();
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentPermissionActionResolveInput {
    permission_ref: String,
    choice: PermissionChoice,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentConfirmationInput {
    confirmation_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentPermissionResolveInput {
    permission_ref: String,
    choice: PermissionChoice,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentAuthorizationRuleDeleteInput {
    rule_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshHostKeyInspectInput {
    account_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum SshInstallAuthentication {
    StoredPassword,
    SshAgent,
    AuthenticationKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshPublicKeyInstallInput {
    account_id: String,
    key_id: String,
    authentication: SshInstallAuthentication,
    authentication_key_id: Option<String>,
    host_key_fingerprint: String,
    master_password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshRuntimeDetail {
    id: String,
    host: Option<String>,
    port: u16,
    username: String,
    has_password: bool,
    has_public_key: bool,
    has_private_key: bool,
    has_key_passphrase: bool,
    master_password_reprompt: bool,
    record_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentLoginDetail {
    id: String,
    username: String,
    master_password_reprompt: bool,
}

#[derive(Debug)]
struct SshExternalLaunchMaterial {
    target: ssh_external::LaunchTarget,
    private_key: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    password_copy_skipped: bool,
    authentication: &'static str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecuritySettings {
    lock_on_blur: bool,
    idle_timeout_ms: u64,
    lock_on_sleep: bool,
    clipboard_clear_timeout_ms: u64,
    copy_ssh_password_on_launch: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            lock_on_blur: true,
            idle_timeout_ms: 5 * 60_000,
            lock_on_sleep: true,
            clipboard_clear_timeout_ms: 30_000,
            copy_ssh_password_on_launch: true,
        }
    }
}

impl SecuritySettings {
    fn validate(&self) -> bool {
        (60_000..=30 * 60_000).contains(&self.idle_timeout_ms)
            && (10_000..=2 * 60_000).contains(&self.clipboard_clear_timeout_ms)
    }
}

#[tauri::command]
async fn desktop_invoke(
    app: AppHandle,
    state: State<'_, RuntimeState>,
    request: DesktopRequest,
) -> Result<Value, String> {
    validate_request(&request)?;
    let operation = request.operation;
    let input = request.input;

    if operation.starts_with("agent.") {
        return handle_agent_admin(&state, &operation, input);
    }
    if operation.starts_with("lan.") {
        return handle_lan_pairing(&state, &operation, input);
    }

    if let Some(import_operation) = ImportOperation::parse(&operation) {
        return handle_import(&app, &state, import_operation, input).await;
    }
    if operation.starts_with("email.") {
        return handle_email(&app, &state, &operation, input).await;
    }
    if operation.starts_with("api-requests.") {
        return match operation.as_str() {
            "api-requests.prepare" => prepare_desktop_api_request(&state, input).await,
            "api-requests.execute" => execute_desktop_api_request(&app, &state, input).await,
            "api-requests.cancel" => cancel_desktop_api_request(&state, input),
            _ => Err("不支持该桌面操作。".to_owned()),
        };
    }
    if matches!(
        operation.as_str(),
        "ssh.scan" | "ssh.scan.commit" | "ssh.scan.cancel"
    ) {
        return handle_ssh_scan(&state, &operation, input).await;
    }
    if matches!(
        operation.as_str(),
        "ssh.inspect-host-key" | "ssh.install-public-key"
    ) {
        return handle_ssh_privileged(&state, &operation, input).await;
    }
    if matches!(operation.as_str(), "ssh.external-clients" | "ssh.launch") {
        return handle_ssh_external(&app, &state, &operation, input).await;
    }
    if matches!(
        operation.as_str(),
        "ssh.import-clipboard" | "ssh.generate-key-pair"
    ) {
        return handle_ssh_tools(&app, &state, &operation, input).await;
    }

    match operation.as_str() {
        "vault.status" => with_runtime(&state, |runtime| Ok(json!(runtime.status()))).await,
        "vault.create" => {
            let password = required_string(&input, "masterPassword")?;
            let result = with_runtime(&state, move |runtime| {
                runtime
                    .create(password)
                    .map(|status| json!({ "cancelled": false, "status": status }))
            })
            .await?;
            with_pin(&state, |pin| pin.disable()).await?;
            with_biometric(&state, |biometric| biometric.disable().map(|_| ())).await?;
            Ok(result)
        }
        "vault.unlock" => {
            let password = required_string(&input, "masterPassword")?;
            unlock_vault(&app, &state, password).await
        }
        "vault.lock" => {
            let result = with_runtime(&state, |runtime| Ok(json!(runtime.lock()))).await?;
            finish_policy_lock(&app, &state);
            Ok(result)
        }
        "vault.backup" => backup_vault(&app, &state).await,
        "vault.restore" => {
            let password = required_string(&input, "masterPassword")?;
            restore_vault(&app, &state, password).await
        }
        "vault.change-password" => {
            let result = with_runtime(&state, move |runtime| {
                runtime.execute("vault.change-password", input)
            })
            .await?;
            with_pin(&state, |pin| pin.disable()).await?;
            with_biometric(&state, |biometric| biometric.disable().map(|_| ())).await?;
            Ok(result)
        }
        "biometric.status" => {
            require_empty_object(&input)?;
            with_biometric(&state, |biometric| Ok(json!(biometric.status()))).await
        }
        "biometric.enable" => {
            require_empty_object(&input)?;
            let (vault_path, vault_key) =
                with_runtime(&state, |runtime| runtime.quick_unlock_material())
                    .await
                    .map_err(|_| "请先在桌面端使用主密码解锁保险库。".to_owned())?;
            with_biometric(&state, move |biometric| {
                biometric
                    .enable(vault_path, vault_key.as_slice())
                    .map(|status| json!(status))
            })
            .await
        }
        "biometric.disable" => {
            require_empty_object(&input)?;
            with_biometric(&state, |biometric| {
                biometric.disable().map(|status| json!(status))
            })
            .await
        }
        "biometric.unlock" => {
            require_empty_object(&input)?;
            let credential = with_biometric(&state, |biometric| biometric.unlock()).await?;
            let vault_path = credential.0.clone();
            let result = with_runtime(&state, move |runtime| {
                runtime
                    .unlock_with_biometric_key(credential.0, credential.1.as_slice())
                    .map(|status| json!({ "cancelled": false, "status": status }))
            })
            .await?;
            persist_vault_path(&state.vault_path_record, &vault_path)?;
            Ok(result)
        }
        "pin.status" => {
            require_empty_object(&input)?;
            with_pin(&state, |pin| Ok(json!(pin.status()))).await
        }
        "pin.enable" => {
            let setup: PinSetupInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let pin_value = Zeroizing::new(setup.pin);
            let (vault_path, vault_key) =
                with_runtime(&state, |runtime| runtime.quick_unlock_material())
                    .await
                    .map_err(|_| "请先在桌面端使用主密码解锁保险库。".to_owned())?;
            with_pin(&state, move |pin| {
                pin.enable(
                    vault_path,
                    vault_key.as_ref(),
                    pin_value.as_str(),
                    setup.failure_limit,
                )
                .map(|status| json!(status))
            })
            .await
        }
        "pin.disable" => {
            require_empty_object(&input)?;
            let unlocked = with_runtime(&state, |runtime| Ok(runtime.status().unlocked)).await?;
            if !unlocked {
                return Err("请先在桌面端解锁保险库。".to_owned());
            }
            with_pin(&state, |pin| {
                pin.disable()?;
                Ok(json!(pin.status()))
            })
            .await
        }
        "pin.unlock" => {
            let input: PinInput = serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let pin_value = Zeroizing::new(input.pin);
            let credential = with_pin(&state, move |pin| pin.unlock(pin_value.as_str())).await?;
            let vault_path = credential.vault_path.clone();
            let result = with_runtime(&state, move |runtime| {
                runtime
                    .unlock_with_quick_key(credential.vault_path, credential.vault_key.as_slice())
                    .map(|status| json!({ "cancelled": false, "status": status }))
            })
            .await?;
            persist_vault_path(&state.vault_path_record, &vault_path)?;
            Ok(result)
        }
        "security.settings.get" => state
            .settings
            .lock()
            .map(|settings| json!(settings.clone()))
            .map_err(|_| "安全设置暂时不可用。".to_owned()),
        "security.settings.update" => update_settings(&state, input),
        "desktop.startup.get" => {
            require_empty_object(&input)?;
            desktop_startup_settings(&app)
        }
        "desktop.startup.update" => update_desktop_startup(&app, &state, input),
        "desktop.browser-integration.get" => {
            require_empty_object(&input)?;
            browser_integration_status(&state, false)
        }
        "desktop.browser-integration.retry" => {
            require_empty_object(&input)?;
            browser_integration_status(&state, true)
        }
        "services.open-site" => {
            let service_id = required_string(&input, "serviceId")?;
            let site = required_string(&input, "site")?;
            with_runtime(&state, move |runtime| {
                let detail = runtime.execute("services.detail", json!({ "id": service_id }))?;
                let allowed = detail
                    .get("sites")
                    .and_then(Value::as_array)
                    .is_some_and(|sites| {
                        sites
                            .iter()
                            .any(|candidate| candidate.as_str() == Some(site.as_str()))
                    });
                if !allowed {
                    return Err(DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT));
                }
                open::that_detached(&site)
                    .map(|()| json!({ "opened": true }))
                    .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_IO_ERROR))
            })
            .await
        }
        operation if is_core_operation(operation) => {
            if operation_invalidates_api_requests(operation)
                && let Ok(mut requests) = state.api_requests.lock()
            {
                requests.clear();
            }
            let core_operation = operation.to_owned();
            with_runtime(&state, move |runtime| {
                runtime.execute(&core_operation, input)
            })
            .await
        }
        operation if protected_spec(operation).is_some() => {
            let id = required_string(&input, "id")?;
            let master_password = optional_string(&input, "masterPassword")?;
            let spec = protected_spec(operation).expect("guarded operation");
            let value = with_runtime(&state, move |runtime| {
                runtime
                    .protected_value(spec.0, spec.1, &id, master_password.as_deref())
                    .map(|value| value.to_string())
            })
            .await?;
            if operation == "items.reveal-password" {
                return Ok(json!({ "password": value }));
            }
            copy_with_expiry(&app, &state, value)
        }
        "items.totp-code" => {
            let id = required_string(&input, "id")?;
            let master_password = optional_string(&input, "masterPassword")?;
            with_runtime(&state, move |runtime| {
                runtime.totp_value(&id, master_password.as_deref())
            })
            .await
        }
        "items.copy-totp" => {
            let id = required_string(&input, "id")?;
            let master_password = optional_string(&input, "masterPassword")?;
            let result = with_runtime(&state, move |runtime| {
                runtime.totp_value(&id, master_password.as_deref())
            })
            .await?;
            let code = result
                .get("code")
                .and_then(Value::as_str)
                .ok_or("无法生成验证码。")?
                .to_owned();
            copy_with_expiry(&app, &state, code)
        }
        "items.recovery-codes" => {
            let id = required_string(&input, "id")?;
            let master_password = bounded_required_string(&input, "masterPassword", 8, 1_024)?;
            with_runtime(&state, move |runtime| {
                runtime
                    .recovery_codes(&id, Some(master_password.as_str()))
                    .map(|codes| json!({ "codes": codes }))
            })
            .await
        }
        "items.copy-recovery-code" => {
            let id = required_string(&input, "id")?;
            let master_password = bounded_required_string(&input, "masterPassword", 8, 1_024)?;
            let index = input
                .get("index")
                .and_then(Value::as_u64)
                .filter(|index| *index < 100)
                .ok_or("请求参数无效。")? as usize;
            let codes = with_runtime(&state, move |runtime| {
                runtime.recovery_codes(&id, Some(master_password.as_str()))
            })
            .await?;
            let code = codes.get(index).ok_or("恢复码不存在。")?.to_owned();
            copy_with_expiry(&app, &state, code)
        }
        "items.recovery-codes.import-file" => {
            require_empty_object(&input)?;
            import_recovery_code_file(&app, &state).await
        }
        "items.copy-username" => {
            let value = with_runtime(&state, move |runtime| {
                runtime.execute("items.copy-username", input)
            })
            .await?;
            let username = value.as_str().ok_or("用户名不可用。")?.to_owned();
            copy_with_expiry(&app, &state, username)
        }
        _ => Err("该桌面操作不被允许。".into()),
    }
}

fn handle_lan_pairing(
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    if operation.starts_with("lan.sync.") {
        return handle_lan_sync(state, operation, input);
    }
    if operation != "lan.discovery.stop"
        && !state
            .runtime
            .lock()
            .map_err(|_| "保险库不可用。")?
            .status()
            .unlocked
    {
        return Err("请先解锁保险库。".into());
    }
    let mut service = state
        .lan_pairing
        .lock()
        .map_err(|_| "局域网配对服务暂时不可用。".to_owned())?;
    match operation {
        "lan.pairing.status" | "lan.discovery.scan" => {
            require_empty_object(&input)?;
            let status = service.status(std::time::Instant::now(), unix_millis());
            for (vault, peer, fingerprint) in service.take_sync_authorizations() {
                let mut runtime = state.runtime.lock().map_err(|_| "保险库不可用。")?;
                if runtime
                    .sync_state()
                    .map_err(|_| "请先解锁保险库。")?
                    .vault_id
                    != vault
                {
                    return Err("保险库已切换，请重新授权同步。".into());
                }
                runtime
                    .sync_authorize(&peer, &fingerprint, true)
                    .map_err(|_| "设备已配对，但同步授权保存失败，请重新授权同步。")?;
            }
            serde_json::to_value(status).map_err(|_| "局域网配对服务暂时不可用。".to_owned())
        }
        "lan.discovery.start" => {
            require_empty_object(&input)?;
            let vault = state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .sync_state()
                .map_err(|_| "请先解锁保险库。")?
                .vault_id;
            service.start_for_vault(std::time::Instant::now(), vault)?;
            serde_json::to_value(service.status(std::time::Instant::now(), unix_millis()))
                .map_err(|_| "局域网配对服务暂时不可用。".to_owned())
        }
        "lan.discovery.stop" => {
            require_empty_object(&input)?;
            service.stop();
            serde_json::to_value(service.status(std::time::Instant::now(), unix_millis()))
                .map_err(|_| "局域网配对服务暂时不可用。".to_owned())
        }
        "lan.pairing.list" => {
            require_empty_object(&input)?;
            serde_json::to_value(service.list_trusted()?)
                .map_err(|_| "局域网配对服务暂时不可用。".to_owned())
        }
        "lan.pairing.begin" => {
            let mut input: LanPairingBeginInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let pairing_code = zeroize::Zeroizing::new(std::mem::take(&mut input.pairing_code));
            service.begin(&input.pairing_ref, pairing_code)?;
            Ok(json!({ "started": true }))
        }
        "lan.pairing.revoke" => {
            let input: LanPairingRefInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let fingerprint = service.peer_fingerprint(&input.pairing_ref)?;
            state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .sync_authorize(&input.pairing_ref, &fingerprint, false)
                .map_err(|_| "无法撤销同步授权。")?;
            service.revoke(&input.pairing_ref)?;
            state
                .lan_sync
                .lock()
                .map_err(|_| "同步不可用。")?
                .interrupt_peer(&input.pairing_ref);
            Ok(json!({ "revoked": true }))
        }
        "lan.pairing.rename" => {
            let rename: LanPeerRenameInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let label = rename.label.trim();
            if rename.pairing_ref.len() > 64
                || label.is_empty()
                || label.chars().count() > 64
                || label.len() > 256
            {
                return Err("请求参数无效。".to_owned());
            }
            service.rename(&rename.pairing_ref, label)?;
            Ok(json!({ "renamed": true }))
        }
        _ => Err("不支持该桌面操作。".to_owned()),
    }
}

fn prune_imports(state: &RuntimeState) {
    if let Ok(mut imports) = state.imports.lock() {
        imports.prune_expired(unix_millis());
    }
}

fn browser_integration_status(state: &RuntimeState, repair: bool) -> Result<Value, String> {
    #[cfg(target_os = "windows")]
    {
        let mut integration = state
            .browser_integration
            .lock()
            .map_err(|_| "浏览器集成状态暂时不可用。".to_owned())?;
        let status = if repair {
            integration.repair()
        } else {
            integration.status()
        };
        serde_json::to_value(status).map_err(|_| "浏览器集成状态暂时不可用。".to_owned())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state, repair);
        Ok(json!({
            "supported": false,
            "ready": false,
            "brokerReady": false,
            "hostRegistered": false,
            "extensionId": "",
            "errorCode": null,
        }))
    }
}

#[tauri::command]
fn desktop_activity(state: State<'_, RuntimeState>) {
    state.last_activity.store(unix_millis(), Ordering::Relaxed);
}

#[cfg(test)]
mod lib_tests;

fn handle_lan_sync(state: &RuntimeState, operation: &str, input: Value) -> Result<Value, String> {
    match operation {
        "lan.sync.status" => {
            require_empty_object(&input)?;
            serde_json::to_value(
                state
                    .lan_sync
                    .lock()
                    .map_err(|_| "同步不可用。")?
                    .status()?,
            )
            .map_err(|_| "同步不可用。".into())
        }
        "lan.sync.enable" | "lan.sync.disable" | "lan.sync.retry" => {
            let input: LanPairingRefInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let fingerprint = state
                .lan_pairing
                .lock()
                .map_err(|_| "设备信任不可用。")?
                .peer_fingerprint(&input.pairing_ref)?;
            if operation != "lan.sync.retry" {
                state
                    .runtime
                    .lock()
                    .map_err(|_| "保险库不可用。")?
                    .sync_authorize(
                        &input.pairing_ref,
                        &fingerprint,
                        operation == "lan.sync.enable",
                    )
                    .map_err(|_| "无法更新同步授权，请先解锁保险库。")?;
            } else if !state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .status()
                .unlocked
            {
                return Err("请先解锁保险库。".into());
            }
            state.lan_sync.lock().map_err(|_| "同步不可用。")?.retry();
            Ok(json!({"ok":true}))
        }
        "lan.sync.conflicts.list" => {
            require_empty_object(&input)?;
            state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .sync_conflicts()
                .map_err(|_| "无法读取冲突历史。".into())
        }
        "lan.sync.conflicts.restore" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                id: String,
            }
            let input: Input = serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            if input.id.len() > 100 {
                return Err("请求参数无效。".into());
            }
            state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .sync_restore_conflict(&input.id)
                .map_err(|_| "无法恢复冲突历史。")?;
            state
                .lan_sync
                .lock()
                .map_err(|_| "同步不可用。")?
                .notify_change();
            Ok(json!({"ok":true}))
        }
        "lan.sync.conflicts.clear" => {
            require_empty_object(&input)?;
            state
                .runtime
                .lock()
                .map_err(|_| "保险库不可用。")?
                .sync_clear_conflicts()
                .map_err(|_| "无法清理冲突历史。")?;
            Ok(json!({"ok":true}))
        }
        _ => Err("不支持该桌面操作。".into()),
    }
}
