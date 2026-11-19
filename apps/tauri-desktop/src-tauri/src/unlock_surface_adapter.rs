use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::Ordering},
};

use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    DesktopRuntime, RuntimeState,
    agent_unlock_window::{
        AGENT_UNLOCK_WINDOW_LABEL, DisplayedAgentUnlock, complete_browser_unlock,
        finish_agent_unlock, reject_displayed_unlock,
    },
    biometric_service::BiometricQuickUnlockService,
    browser_broker::{BrowserUnlockFactor, BrowserUnlockResolution},
    desktop_runtime::prune_expired_agent_access,
    pin_domain_adapter::{PinDomainFactory, PinDomainKind, reconcile_pins_after_desktop_master_unlock},
    pin_service::PinCredential,
    unix_millis,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnlockDomainKind {
    DesktopMain,
    BrowserSession,
    BrowserReprompt,
    AgentMcp,
}

#[derive(Clone, Debug)]
pub(crate) struct UnlockSurfaceContext {
    pub(crate) vault_path: PathBuf,
    pub(crate) unlock_ref: Option<String>,
    pub(crate) agent_client_id: Option<Uuid>,
}

pub(crate) trait UnlockSurfaceAdapter: Send + Sync + Debug {
    fn kind(&self) -> UnlockDomainKind;
    fn window_label(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn allows_quick_unlock(&self) -> bool;
    fn pin_domain(&self) -> Option<PinDomainKind>;
    fn biometric_service<'a>(
        &self,
        state: &'a RuntimeState,
    ) -> Option<&'a Arc<Mutex<BiometricQuickUnlockService>>>;

    fn pin_status(&self, state: &RuntimeState, ctx: &UnlockSurfaceContext) -> Result<Value, String> {
        if !self.allows_quick_unlock() {
            return Ok(json!({
                "enabled": false,
                "locked": false,
                "remainingAttempts": 0
            }));
        }
        let Some(domain) = self.pin_domain() else {
            return Ok(json!({
                "enabled": false,
                "locked": false,
                "remainingAttempts": 0
            }));
        };
        read_domain_pin_status(domain, state, &ctx.vault_path)
    }

    fn biometric_binding(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
    ) -> Result<(PathBuf, String), String> {
        if !self.allows_quick_unlock() {
            return Err("此条目受主密码保护，请使用主密码确认填充。".to_owned());
        }
        let service = self
            .biometric_service(state)
            .ok_or_else(|| "此条目受主密码保护，请使用主密码确认填充。".to_owned())?;
        read_biometric_binding(service, &ctx.vault_path)
    }

    fn biometric_status(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
    ) -> Result<Value, String> {
        if !self.allows_quick_unlock() {
            return Ok(json!({
                "available": false,
                "enabled": false,
                "kind": Value::Null
            }));
        }
        let Some(service) = self.biometric_service(state) else {
            return Ok(json!({
                "available": false,
                "enabled": false,
                "kind": Value::Null
            }));
        };
        read_biometric_status(service, &ctx.vault_path)
    }

    fn unlock_with_password(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        password: Zeroizing<String>,
    ) -> Result<Value, String>;

    fn unlock_with_pin(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        pin: Zeroizing<String>,
    ) -> Result<Value, String>;

    fn complete_biometric_unlock(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        vault_path: PathBuf,
        vault_key: Zeroizing<Vec<u8>>,
    ) -> Result<Value, String>;

    fn cancel(&self, state: &RuntimeState, ctx: &UnlockSurfaceContext) -> Result<Value, String>;
}

#[derive(Debug, Default)]
pub(crate) struct DesktopMainUnlockAdapter;

#[derive(Debug, Default)]
pub(crate) struct BrowserSessionUnlockAdapter;

#[derive(Debug, Default)]
pub(crate) struct BrowserRepromptUnlockAdapter;

#[derive(Debug, Default)]
pub(crate) struct AgentMcpUnlockAdapter;

static DESKTOP_MAIN_ADAPTER: DesktopMainUnlockAdapter = DesktopMainUnlockAdapter;
static BROWSER_SESSION_ADAPTER: BrowserSessionUnlockAdapter = BrowserSessionUnlockAdapter;
static BROWSER_REPROMPT_ADAPTER: BrowserRepromptUnlockAdapter = BrowserRepromptUnlockAdapter;
static AGENT_MCP_ADAPTER: AgentMcpUnlockAdapter = AgentMcpUnlockAdapter;

pub(crate) struct UnlockSurfaceFactory;

impl UnlockSurfaceFactory {
    pub(crate) fn create_for(kind: UnlockDomainKind) -> &'static dyn UnlockSurfaceAdapter {
        match kind {
            UnlockDomainKind::DesktopMain => &DESKTOP_MAIN_ADAPTER,
            UnlockDomainKind::BrowserSession => &BROWSER_SESSION_ADAPTER,
            UnlockDomainKind::BrowserReprompt => &BROWSER_REPROMPT_ADAPTER,
            UnlockDomainKind::AgentMcp => &AGENT_MCP_ADAPTER,
        }
    }

    pub(crate) fn resolve_for_request(
        displayed: &DisplayedAgentUnlock,
    ) -> &'static dyn UnlockSurfaceAdapter {
        match displayed {
            DisplayedAgentUnlock::BrowserUnlock {
                master_password_reprompt: false,
                ..
            } => Self::create_for(UnlockDomainKind::BrowserSession),
            DisplayedAgentUnlock::BrowserUnlock {
                master_password_reprompt: true,
                ..
            } => Self::create_for(UnlockDomainKind::BrowserReprompt),
            DisplayedAgentUnlock::Agent { .. } => Self::create_for(UnlockDomainKind::AgentMcp),
        }
    }

    pub(crate) fn resolve_for_window(
        window_label: &str,
        state: &RuntimeState,
    ) -> Result<(&'static dyn UnlockSurfaceAdapter, UnlockSurfaceContext), String> {
        match window_label {
            "main" => {
                let runtime = state
                    .runtime
                    .lock()
                    .map_err(|_| "保险库暂时不可用。".to_owned())?;
                if runtime.status().unlocked || !runtime.status().has_vault {
                    return Err("当前无需解锁。".to_owned());
                }
                let vault_path = runtime.current_path();
                Ok((
                    Self::create_for(UnlockDomainKind::DesktopMain),
                    UnlockSurfaceContext {
                        vault_path,
                        unlock_ref: None,
                        agent_client_id: None,
                    },
                ))
            }
            AGENT_UNLOCK_WINDOW_LABEL => {
                let displayed = state
                    .agent_unlock_window_request
                    .lock()
                    .map_err(|_| "临时解锁窗口状态暂时不可用。".to_owned())?
                    .clone()
                    .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
                match &displayed {
                    DisplayedAgentUnlock::BrowserUnlock {
                        unlock_ref,
                        vault_path,
                        ..
                    } => {
                        let adapter = Self::resolve_for_request(&displayed);
                        Ok((
                            adapter,
                            UnlockSurfaceContext {
                                vault_path: vault_path.clone(),
                                unlock_ref: Some(unlock_ref.clone()),
                                agent_client_id: None,
                            },
                        ))
                    }
                    DisplayedAgentUnlock::Agent {
                        unlock_ref,
                        client_id,
                    } => {
                        let vault_path = state
                            .runtime
                            .lock()
                            .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                            .current_path();
                        Ok((
                            Self::create_for(UnlockDomainKind::AgentMcp),
                            UnlockSurfaceContext {
                                vault_path,
                                unlock_ref: Some(unlock_ref.clone()),
                                agent_client_id: Some(*client_id),
                            },
                        ))
                    }
                }
            }
            _ => Err("此认证只允许解锁窗口使用。".to_owned()),
        }
    }
}

fn read_domain_pin_status(
    domain: PinDomainKind,
    state: &RuntimeState,
    vault_path: &Path,
) -> Result<Value, String> {
    let adapter = PinDomainFactory::create_for(domain);
    let pin = adapter
        .service(state)
        .lock()
        .map_err(|_| adapter.unavailable_error().to_owned())?;
    if vault_path.is_file() {
        pin.disable_if_for_different_vault(vault_path)?;
    }
    Ok(json!(pin.status()))
}

fn verify_adapter_pin_credential(
    adapter: &dyn UnlockSurfaceAdapter,
    state: &RuntimeState,
    vault_path: &Path,
    pin: Zeroizing<String>,
) -> Result<PinCredential, String> {
    if !adapter.allows_quick_unlock() {
        return Err("此条目受主密码保护，请使用主密码确认填充。".to_owned());
    }
    let domain = adapter
        .pin_domain()
        .ok_or_else(|| "此条目受主密码保护，请使用主密码确认填充。".to_owned())?;
    let pin_adapter = PinDomainFactory::create_for(domain);
    let credential = pin_adapter
        .service(state)
        .lock()
        .map_err(|_| pin_adapter.unavailable_error().to_owned())?
        .unlock(pin.as_str())?;
    let canonical = vault_path
        .canonicalize()
        .map_err(|_| "无法定位当前保险库。".to_owned())?;
    if credential.vault_path != canonical {
        return Err(pin_adapter.mismatch_error().to_owned());
    }
    Ok(credential)
}

fn read_biometric_binding(
    service: &Arc<Mutex<BiometricQuickUnlockService>>,
    vault_path: &Path,
) -> Result<(PathBuf, String), String> {
    let canonical = vault_path
        .canonicalize()
        .map_err(|_| "无法定位当前保险库。".to_owned())?;
    let biometric = service
        .lock()
        .map_err(|_| "Touch ID 状态暂时不可用。".to_owned())?;
    let (credential_vault, credential_id) = biometric.credential_binding()?;
    if credential_vault != canonical {
        return Err("Touch ID 凭据不属于当前保险库。".to_owned());
    }
    Ok((credential_vault, credential_id))
}

fn read_biometric_status(
    service: &Arc<Mutex<BiometricQuickUnlockService>>,
    vault_path: &Path,
) -> Result<Value, String> {
    let biometric = service
        .lock()
        .map_err(|_| "Touch ID 状态暂时不可用。".to_owned())?;
    if vault_path.is_file() {
        biometric.disable_if_for_different_vault(vault_path)?;
    }
    let mut status = json!(biometric.status());
    let canonical = vault_path.canonicalize().ok();
    if biometric
        .credential_binding()
        .ok()
        .is_none_or(|(bound_path, _)| Some(bound_path) != canonical)
    {
        status["enabled"] = json!(false);
    }
    Ok(status)
}

fn reset_browser_pin_failures_for_vault(
    domain: Option<PinDomainKind>,
    state: &RuntimeState,
    vault_path: &Path,
) {
    let Some(domain) = domain else {
        return;
    };
    if !vault_path.is_file() {
        return;
    }
    let browser_pin_adapter = PinDomainFactory::create_for(domain);
    if let Ok(browser_pin) = browser_pin_adapter.service(state).lock() {
        let _ = browser_pin
            .disable_if_for_different_vault(vault_path)
            .and_then(|()| browser_pin.reset_failures(vault_path));
    }
}

fn verify_browser_master_password_material(
    state: &RuntimeState,
    vault_path: &Path,
    password: &Zeroizing<String>,
) -> Result<(PathBuf, Zeroizing<Vec<u8>>), String> {
    let mut temp_runtime = DesktopRuntime::new(vault_path.to_path_buf())
        .map_err(|error| error.public_message().to_owned())?;
    temp_runtime
        .unlock_for_agent_from(vault_path.to_path_buf(), password.as_str().to_owned())
        .map_err(|error| error.public_message().to_owned())?;
    let (canonical_vault, vault_key) = temp_runtime
        .quick_unlock_material()
        .map_err(|error| error.public_message().to_owned())?;
    let _ = state.browser_preauth_preview.sync_from_runtime(&mut temp_runtime);
    temp_runtime.lock();
    Ok((canonical_vault, Zeroizing::new(vault_key.to_vec())))
}

fn finish_agent_or_rollback(
    state: &RuntimeState,
    unlock_ref: &str,
    client_id: Uuid,
) -> Result<Value, String> {
    if let Err(error) = finish_agent_unlock(state, unlock_ref, client_id) {
        state.agent_vault_access.lock_client(client_id);
        return Err(error);
    }
    Ok(json!({ "unlocked": true }))
}

impl UnlockSurfaceAdapter for DesktopMainUnlockAdapter {
    fn kind(&self) -> UnlockDomainKind {
        UnlockDomainKind::DesktopMain
    }

    fn window_label(&self) -> &'static str {
        "main"
    }

    fn title(&self) -> &'static str {
        "解锁 VaultMesh"
    }

    fn allows_quick_unlock(&self) -> bool {
        true
    }

    fn pin_domain(&self) -> Option<PinDomainKind> {
        Some(PinDomainKind::Desktop)
    }

    fn biometric_service<'a>(
        &self,
        state: &'a RuntimeState,
    ) -> Option<&'a Arc<Mutex<BiometricQuickUnlockService>>> {
        Some(&state.biometric)
    }

    fn unlock_with_password(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        password: Zeroizing<String>,
    ) -> Result<Value, String> {
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "保险库暂时不可用。".to_owned())?;
        let status = runtime
            .unlock_from(ctx.vault_path.clone(), password.as_str().to_owned())
            .map_err(|error| error.public_message().to_owned())?;
        let vault_path = runtime.current_path();
        drop(runtime);
        state.last_activity.store(unix_millis(), Ordering::Relaxed);
        reconcile_pins_after_desktop_master_unlock(state, &vault_path)?;
        Ok(json!({ "cancelled": false, "status": status }))
    }

    fn unlock_with_pin(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        pin: Zeroizing<String>,
    ) -> Result<Value, String> {
        let credential = verify_adapter_pin_credential(self, state, &ctx.vault_path, pin)?;
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "保险库暂时不可用。".to_owned())?;
        let status = runtime
            .unlock_with_quick_key(credential.vault_path, credential.vault_key.as_slice())
            .map_err(|error| error.public_message().to_owned())?;
        drop(runtime);
        state.last_activity.store(unix_millis(), Ordering::Relaxed);
        Ok(json!({ "cancelled": false, "status": status }))
    }

    fn complete_biometric_unlock(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        vault_path: PathBuf,
        vault_key: Zeroizing<Vec<u8>>,
    ) -> Result<Value, String> {
        let canonical = ctx
            .vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        if vault_path != canonical {
            return Err("保险库已切换。".to_owned());
        }
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "保险库暂时不可用。".to_owned())?;
        if runtime.current_path().canonicalize().ok().as_ref() != Some(&canonical)
            || runtime.status().unlocked
        {
            return Err("认证会话已失效。".to_owned());
        }
        let status = runtime
            .unlock_with_biometric_key(vault_path, vault_key.as_slice())
            .map_err(|error| error.public_message().to_owned())?;
        drop(runtime);
        state.last_activity.store(unix_millis(), Ordering::Relaxed);
        Ok(json!({ "cancelled": false, "status": status }))
    }

    fn cancel(&self, _state: &RuntimeState, _ctx: &UnlockSurfaceContext) -> Result<Value, String> {
        Ok(json!({ "cancelled": true }))
    }
}

impl UnlockSurfaceAdapter for BrowserSessionUnlockAdapter {
    fn kind(&self) -> UnlockDomainKind {
        UnlockDomainKind::BrowserSession
    }

    fn window_label(&self) -> &'static str {
        AGENT_UNLOCK_WINDOW_LABEL
    }

    fn title(&self) -> &'static str {
        "解锁 VaultMesh 浏览器插件"
    }

    fn allows_quick_unlock(&self) -> bool {
        true
    }

    fn pin_domain(&self) -> Option<PinDomainKind> {
        Some(PinDomainKind::Browser)
    }

    fn biometric_service<'a>(
        &self,
        state: &'a RuntimeState,
    ) -> Option<&'a Arc<Mutex<BiometricQuickUnlockService>>> {
        Some(&state.biometric)
    }

    fn unlock_with_password(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        password: Zeroizing<String>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let (canonical_vault, vault_key) =
            verify_browser_master_password_material(state, &ctx.vault_path, &password)?;
        reset_browser_pin_failures_for_vault(self.pin_domain(), state, &canonical_vault);
        complete_browser_unlock(
            state,
            unlock_ref,
            BrowserUnlockResolution {
                factor: BrowserUnlockFactor::MasterPassword,
                vault_path: canonical_vault,
                vault_key,
                master_password: Some(password),
            },
        )
    }

    fn unlock_with_pin(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        pin: Zeroizing<String>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let credential = verify_adapter_pin_credential(self, state, &ctx.vault_path, pin)?;
        let mut temp_runtime = DesktopRuntime::new(ctx.vault_path.clone())
            .map_err(|error| error.public_message().to_owned())?;
        temp_runtime
            .unlock_for_agent_with_quick_key(
                credential.vault_path.clone(),
                credential.vault_key.as_slice(),
            )
            .map_err(|error| error.public_message().to_owned())?;
        let _ = state.browser_preauth_preview.sync_from_runtime(&mut temp_runtime);
        temp_runtime.lock();
        complete_browser_unlock(
            state,
            unlock_ref,
            BrowserUnlockResolution {
                factor: BrowserUnlockFactor::Pin,
                vault_path: credential.vault_path,
                vault_key: credential.vault_key,
                master_password: None,
            },
        )
    }

    fn complete_biometric_unlock(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        vault_path: PathBuf,
        vault_key: Zeroizing<Vec<u8>>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let canonical = ctx
            .vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        if vault_path != canonical {
            return Err("Touch ID 不属于当前保险库，请使用主密码解锁。".to_owned());
        }
        let mut temp_runtime = DesktopRuntime::new(ctx.vault_path.clone())
            .map_err(|error| error.public_message().to_owned())?;
        temp_runtime
            .unlock_for_agent_with_quick_key(vault_path.clone(), vault_key.as_slice())
            .map_err(|error| error.public_message().to_owned())?;
        let _ = state.browser_preauth_preview.sync_from_runtime(&mut temp_runtime);
        temp_runtime.lock();
        complete_browser_unlock(
            state,
            unlock_ref,
            BrowserUnlockResolution {
                factor: BrowserUnlockFactor::Biometric,
                vault_path,
                vault_key,
                master_password: None,
            },
        )
    }

    fn cancel(&self, state: &RuntimeState, _ctx: &UnlockSurfaceContext) -> Result<Value, String> {
        reject_displayed_unlock(state);
        Ok(json!({ "cancelled": true }))
    }
}

impl UnlockSurfaceAdapter for BrowserRepromptUnlockAdapter {
    fn kind(&self) -> UnlockDomainKind {
        UnlockDomainKind::BrowserReprompt
    }

    fn window_label(&self) -> &'static str {
        AGENT_UNLOCK_WINDOW_LABEL
    }

    fn title(&self) -> &'static str {
        "解锁 VaultMesh 浏览器插件"
    }

    fn allows_quick_unlock(&self) -> bool {
        false
    }

    fn pin_domain(&self) -> Option<PinDomainKind> {
        None
    }

    fn biometric_service<'a>(
        &self,
        _state: &'a RuntimeState,
    ) -> Option<&'a Arc<Mutex<BiometricQuickUnlockService>>> {
        None
    }

    fn unlock_with_password(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        password: Zeroizing<String>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let (canonical_vault, vault_key) =
            verify_browser_master_password_material(state, &ctx.vault_path, &password)?;
        reset_browser_pin_failures_for_vault(Some(PinDomainKind::Browser), state, &canonical_vault);
        complete_browser_unlock(
            state,
            unlock_ref,
            BrowserUnlockResolution {
                factor: BrowserUnlockFactor::MasterPassword,
                vault_path: canonical_vault,
                vault_key,
                master_password: Some(password),
            },
        )
    }

    fn unlock_with_pin(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        pin: Zeroizing<String>,
    ) -> Result<Value, String> {
        let _ = verify_adapter_pin_credential(self, state, &ctx.vault_path, pin)?;
        Err("此条目受主密码保护，请使用主密码确认填充。".to_owned())
    }

    fn complete_biometric_unlock(
        &self,
        _state: &RuntimeState,
        _ctx: &UnlockSurfaceContext,
        _vault_path: PathBuf,
        _vault_key: Zeroizing<Vec<u8>>,
    ) -> Result<Value, String> {
        Err("此条目受主密码保护，请使用主密码确认填充。".to_owned())
    }

    fn cancel(&self, state: &RuntimeState, _ctx: &UnlockSurfaceContext) -> Result<Value, String> {
        reject_displayed_unlock(state);
        Ok(json!({ "cancelled": true }))
    }
}

impl UnlockSurfaceAdapter for AgentMcpUnlockAdapter {
    fn kind(&self) -> UnlockDomainKind {
        UnlockDomainKind::AgentMcp
    }

    fn window_label(&self) -> &'static str {
        AGENT_UNLOCK_WINDOW_LABEL
    }

    fn title(&self) -> &'static str {
        "解锁 VaultMesh Agent工具"
    }

    fn allows_quick_unlock(&self) -> bool {
        true
    }

    fn pin_domain(&self) -> Option<PinDomainKind> {
        Some(PinDomainKind::Agent)
    }

    fn biometric_service<'a>(
        &self,
        state: &'a RuntimeState,
    ) -> Option<&'a Arc<Mutex<BiometricQuickUnlockService>>> {
        Some(&state.agent_biometric)
    }

    fn unlock_with_password(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        password: Zeroizing<String>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let client_id = ctx
            .agent_client_id
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        prune_expired_agent_access(state, unix_millis())?;
        state.agent_vault_access.unlock_with_password(
            client_id,
            ctx.vault_path.clone(),
            password.as_str().to_owned(),
        )?;
        let result = (|| {
            let vault_path = state
                .agent_vault_access
                .runtime()
                .lock()
                .map_err(|_| "Agent 保险库暂时不可用。".to_owned())?
                .current_path();
            let agent_domain = self
                .pin_domain()
                .ok_or_else(|| "Agent PIN 状态暂时不可用。".to_owned())?;
            let agent_pin_adapter = PinDomainFactory::create_for(agent_domain);
            agent_pin_adapter
                .service(state)
                .lock()
                .map_err(|_| agent_pin_adapter.unavailable_error().to_owned())?
                .disable_if_for_different_vault(&vault_path)?;
            finish_agent_unlock(state, unlock_ref, client_id)
        })();
        if let Err(error) = result {
            state.agent_vault_access.lock_client(client_id);
            return Err(error);
        }
        Ok(json!({ "unlocked": true }))
    }

    fn unlock_with_pin(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        pin: Zeroizing<String>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let client_id = ctx
            .agent_client_id
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        prune_expired_agent_access(state, unix_millis())?;
        let credential = verify_adapter_pin_credential(self, state, &ctx.vault_path, pin)?;
        state.agent_vault_access.unlock_with_quick_key(
            client_id,
            credential.vault_path,
            credential.vault_key.as_slice(),
        )?;
        finish_agent_or_rollback(state, unlock_ref, client_id)
    }

    fn complete_biometric_unlock(
        &self,
        state: &RuntimeState,
        ctx: &UnlockSurfaceContext,
        vault_path: PathBuf,
        vault_key: Zeroizing<Vec<u8>>,
    ) -> Result<Value, String> {
        let unlock_ref = ctx
            .unlock_ref
            .as_deref()
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        let client_id = ctx
            .agent_client_id
            .ok_or_else(|| "当前解锁申请已经结束。".to_owned())?;
        prune_expired_agent_access(state, unix_millis())?;
        let canonical = ctx
            .vault_path
            .canonicalize()
            .map_err(|_| "无法定位当前保险库。".to_owned())?;
        if vault_path != canonical {
            return Err("Agent Touch ID 不属于当前保险库，请使用主密码解锁。".to_owned());
        }
        state.agent_vault_access.unlock_with_quick_key(
            client_id,
            vault_path,
            vault_key.as_slice(),
        )?;
        finish_agent_or_rollback(state, unlock_ref, client_id)
    }

    fn cancel(&self, state: &RuntimeState, _ctx: &UnlockSurfaceContext) -> Result<Value, String> {
        reject_displayed_unlock(state);
        Ok(json!({ "cancelled": true }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_broker::{AgentAccountCatalogSnapshot, ClientHello, PeerIdentity},
        agent_unlock_window::{BrowserUnlockPurpose, PendingBrowserUnlock},
        browser_broker::{BrowserPlatformError, BrowserUnlockSource},
        pin_domain_adapter::test_runtime_state,
    };

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let path = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create test dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn remaining_attempts(status: &crate::pin_service::PinStatus) -> u64 {
        json!(status)["remainingAttempts"]
            .as_u64()
            .expect("remainingAttempts")
    }

    fn create_test_vault(state: &RuntimeState, password: &str) {
        state
            .runtime
            .lock()
            .unwrap()
            .create(password.to_owned())
            .expect("create test vault");
    }

    fn setup_paired_agent_broker(state: &RuntimeState, now: u64) -> Uuid {
        let access_check = state.agent_vault_access.clone();
        let access_register = state.agent_vault_access.clone();
        let access_lock = state.agent_vault_access.clone();
        let mut broker = state.agent_broker.lock().unwrap();
        broker.set_access_check(Arc::new(move |client_id| access_check.is_unlocked(client_id)));
        broker.set_access_register(Arc::new(move |client_id, pairing_identity| {
            access_register.register_client(client_id, pairing_identity);
        }));
        broker.set_access_lock(Arc::new(move |client_id| access_lock.lock_client(client_id)));
        broker.set_account_catalog(Arc::new(|| {
            Ok(AgentAccountCatalogSnapshot {
                connector_definitions: Vec::new(),
                candidates: Vec::new(),
            })
        }));
        let client = broker
            .register_client(
                PeerIdentity {
                    user_id: "501".into(),
                    process_id: 99,
                    executable: "/Applications/Codex.app/Contents/MacOS/codex".into(),
                    binary_identity: format!("sha256:{}", "a".repeat(64)),
                },
                ClientHello {
                    client_key: "codex".into(),
                },
                now,
            )
            .expect("register agent client");
        broker
            .approve_pairing_at(&client.client_id, now + 1)
            .expect("approve agent pairing");
        Uuid::parse_str(&client.client_id).expect("client uuid")
    }

    fn trigger_agent_unlock_request(state: &RuntimeState, client_id: Uuid, now: u64) -> String {
        let request = serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "tool": "vaultmesh_accounts_list",
            "toolVersion": 2,
            "parameters": {}
        }))
        .unwrap();
        let mut broker = state.agent_broker.lock().unwrap();
        let locked = broker.handle_json(client_id, &request, now);
        assert_eq!(locked["error"]["code"], "mcp-locked");
        broker
            .pending_unlock_request(now)
            .expect("pending agent unlock request")
            .unlock_ref
    }

    #[test]
    fn factory_resolves_all_four_unlock_domain_adapters() {
        let desktop = UnlockSurfaceFactory::create_for(UnlockDomainKind::DesktopMain);
        assert_eq!(desktop.window_label(), "main");
        assert_eq!(desktop.title(), "解锁 VaultMesh");
        assert!(desktop.allows_quick_unlock());
        assert_eq!(desktop.pin_domain(), Some(PinDomainKind::Desktop));

        let browser_session = UnlockSurfaceFactory::create_for(UnlockDomainKind::BrowserSession);
        assert_eq!(browser_session.window_label(), AGENT_UNLOCK_WINDOW_LABEL);
        assert_eq!(browser_session.title(), "解锁 VaultMesh 浏览器插件");
        assert!(browser_session.allows_quick_unlock());
        assert_eq!(browser_session.pin_domain(), Some(PinDomainKind::Browser));

        let browser_reprompt = UnlockSurfaceFactory::create_for(UnlockDomainKind::BrowserReprompt);
        assert_eq!(browser_reprompt.window_label(), AGENT_UNLOCK_WINDOW_LABEL);
        assert!(!browser_reprompt.allows_quick_unlock());
        assert_eq!(browser_reprompt.pin_domain(), None);

        let agent = UnlockSurfaceFactory::create_for(UnlockDomainKind::AgentMcp);
        assert_eq!(agent.window_label(), AGENT_UNLOCK_WINDOW_LABEL);
        assert_eq!(agent.title(), "解锁 VaultMesh Agent工具");
        assert!(agent.allows_quick_unlock());
        assert_eq!(agent.pin_domain(), Some(PinDomainKind::Agent));
    }

    #[test]
    fn browser_session_uses_browser_pin_and_master_password_and_rejects_wrong_vault() {
        let dir = TestDir::new("vaultmesh-unlock-surface-browser");
        let state = test_runtime_state(dir.path());
        create_test_vault(&state, "master-pass-123");

        let (vault_path, vault_key) = state
            .runtime
            .lock()
            .unwrap()
            .quick_unlock_material()
            .expect("quick unlock material");
        state
            .pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "111111", 3)
            .expect("enable desktop pin");
        state
            .browser_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "222222", 3)
            .expect("enable browser pin");
        state
            .agent_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "333333", 3)
            .expect("enable agent pin");
        state.runtime.lock().unwrap().lock();

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let now = unix_millis();
        state.browser_unlocks.lock().unwrap().enqueue(PendingBrowserUnlock {
            unlock_ref: "session-ref".to_owned(),
            purpose: BrowserUnlockPurpose::Session,
            source: BrowserUnlockSource::Popup,
            vault_path: vault_path.clone(),
            origin: String::new(),
            item_title: String::new(),
            item_kind: String::new(),
            master_password_reprompt: false,
            created_at: now,
            expires_at: now + 30_000,
            responders: vec![(1, tx)],
        });

        let displayed = DisplayedAgentUnlock::BrowserUnlock {
            unlock_ref: "session-ref".to_owned(),
            vault_path: vault_path.clone(),
            master_password_reprompt: false,
        };
        let adapter = UnlockSurfaceFactory::resolve_for_request(&displayed);
        assert_eq!(adapter.kind(), UnlockDomainKind::BrowserSession);
        let ctx = UnlockSurfaceContext {
            vault_path: vault_path.clone(),
            unlock_ref: Some("session-ref".to_owned()),
            agent_client_id: None,
        };

        // Desktop PIN must be rejected by BrowserSessionUnlockAdapter and increment ONLY browser_pin failures.
        assert!(
            adapter
                .unlock_with_pin(&state, &ctx, Zeroizing::new("111111".to_owned()))
                .is_err()
        );
        assert_eq!(remaining_attempts(&state.pin.lock().unwrap().status()), 3);
        assert_eq!(
            remaining_attempts(&state.agent_pin.lock().unwrap().status()),
            3
        );
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            2
        );

        // Wrong-vault context must reject Browser PIN when bound vault differs.
        let other_vault = dir.path().join("other.vault");
        let mut other = DesktopRuntime::new(other_vault.clone()).expect("other runtime");
        other.create("other-master-123".to_owned()).expect("create other");
        let wrong_vault_ctx = UnlockSurfaceContext {
            vault_path: other_vault,
            unlock_ref: Some("session-ref".to_owned()),
            agent_client_id: None,
        };
        assert!(
            adapter
                .unlock_with_pin(&state, &wrong_vault_ctx, Zeroizing::new("222222".to_owned()))
                .is_err()
        );

        // Correct Browser PIN succeeds, emits BrowserUnlockFactor::Pin, and resets browser_pin attempts.
        let outcome = adapter
            .unlock_with_pin(&state, &ctx, Zeroizing::new("222222".to_owned()))
            .expect("browser pin unlock succeeds");
        assert_eq!(outcome, json!({ "unlocked": true }));
        let resolution = rx
            .try_recv()
            .expect("resolution delivered")
            .expect("ok resolution");
        assert_eq!(resolution.factor, BrowserUnlockFactor::Pin);
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            3
        );

        // Positive BrowserSessionUnlockAdapter::unlock_with_password resets ONLY browser_pin failures (not desktop pin).
        assert!(state.pin.lock().unwrap().unlock("000000").is_err());
        assert!(state.browser_pin.lock().unwrap().unlock("000000").is_err());
        assert_eq!(remaining_attempts(&state.pin.lock().unwrap().status()), 2);
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            2
        );

        let (pw_tx, pw_rx) = std::sync::mpsc::sync_channel(1);
        state.browser_unlocks.lock().unwrap().enqueue(PendingBrowserUnlock {
            unlock_ref: "session-pw-ref".to_owned(),
            purpose: BrowserUnlockPurpose::Session,
            source: BrowserUnlockSource::Popup,
            vault_path: vault_path.clone(),
            origin: String::new(),
            item_title: String::new(),
            item_kind: String::new(),
            master_password_reprompt: false,
            created_at: now + 100,
            expires_at: now + 60_000,
            responders: vec![(2, pw_tx)],
        });
        let pw_ctx = UnlockSurfaceContext {
            vault_path,
            unlock_ref: Some("session-pw-ref".to_owned()),
            agent_client_id: None,
        };
        let pw_outcome = adapter
            .unlock_with_password(&state, &pw_ctx, Zeroizing::new("master-pass-123".to_owned()))
            .expect("browser master password unlock succeeds");
        assert_eq!(pw_outcome, json!({ "unlocked": true }));
        let pw_res = pw_rx
            .try_recv()
            .expect("pw resolution delivered")
            .expect("ok resolution");
        assert_eq!(pw_res.factor, BrowserUnlockFactor::MasterPassword);
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            3
        );
        assert_eq!(remaining_attempts(&state.pin.lock().unwrap().status()), 2);
    }

    #[test]
    fn browser_reprompt_rejects_quick_unlock_and_verifies_master_password() {
        let dir = TestDir::new("vaultmesh-unlock-surface-reprompt");
        let state = test_runtime_state(dir.path());
        create_test_vault(&state, "master-pass-123");

        let (vault_path, vault_key) = state
            .runtime
            .lock()
            .unwrap()
            .quick_unlock_material()
            .expect("quick unlock material");
        state
            .browser_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "222222", 3)
            .expect("enable browser pin");
        state.runtime.lock().unwrap().lock();

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let now = unix_millis();
        state.browser_unlocks.lock().unwrap().enqueue(PendingBrowserUnlock {
            unlock_ref: "reprompt-ref".to_owned(),
            purpose: BrowserUnlockPurpose::MasterPasswordReprompt,
            source: BrowserUnlockSource::Autofill,
            vault_path: vault_path.clone(),
            origin: "https://pay.example".to_owned(),
            item_title: "Visa".to_owned(),
            item_kind: "card".to_owned(),
            master_password_reprompt: true,
            created_at: now,
            expires_at: now + 30_000,
            responders: vec![(1, tx)],
        });

        let displayed = DisplayedAgentUnlock::BrowserUnlock {
            unlock_ref: "reprompt-ref".to_owned(),
            vault_path: vault_path.clone(),
            master_password_reprompt: true,
        };
        let adapter = UnlockSurfaceFactory::resolve_for_request(&displayed);
        assert_eq!(adapter.kind(), UnlockDomainKind::BrowserReprompt);
        let ctx = UnlockSurfaceContext {
            vault_path,
            unlock_ref: Some("reprompt-ref".to_owned()),
            agent_client_id: None,
        };

        assert_eq!(adapter.pin_status(&state, &ctx).unwrap()["enabled"], false);
        assert_eq!(
            adapter.biometric_status(&state, &ctx).unwrap()["enabled"],
            false
        );
        assert!(
            adapter
                .unlock_with_pin(&state, &ctx, Zeroizing::new("222222".to_owned()))
                .is_err()
        );
        assert!(
            adapter
                .complete_biometric_unlock(
                    &state,
                    &ctx,
                    ctx.vault_path.clone(),
                    Zeroizing::new(vec![1u8; 32]),
                )
                .is_err()
        );

        adapter
            .unlock_with_password(&state, &ctx, Zeroizing::new("master-pass-123".to_owned()))
            .expect("reprompt master password succeeds");
        let resolution = rx
            .try_recv()
            .expect("resolution delivered")
            .expect("ok resolution");
        assert_eq!(resolution.factor, BrowserUnlockFactor::MasterPassword);
        assert_eq!(
            resolution.master_password.as_deref().map(String::as_str),
            Some("master-pass-123")
        );
    }

    #[test]
    fn desktop_master_password_unlock_keeps_browser_pin_failures_isolated_and_wrong_browser_password_fails() {
        let dir = TestDir::new("vaultmesh-unlock-surface-isolation");
        let state = test_runtime_state(dir.path());
        create_test_vault(&state, "master-pass-123");

        let (vault_path, vault_key) = state
            .runtime
            .lock()
            .unwrap()
            .quick_unlock_material()
            .expect("quick unlock material");
        state
            .browser_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "222222", 3)
            .expect("enable browser pin");
        assert!(state.browser_pin.lock().unwrap().unlock("999999").is_err());
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            2
        );
        state.runtime.lock().unwrap().lock();

        let desktop = UnlockSurfaceFactory::create_for(UnlockDomainKind::DesktopMain);
        desktop
            .unlock_with_password(
                &state,
                &UnlockSurfaceContext {
                    vault_path: vault_path.clone(),
                    unlock_ref: None,
                    agent_client_id: None,
                },
                Zeroizing::new("master-pass-123".to_owned()),
            )
            .expect("desktop unlock succeeds");
        // Desktop master unlock MUST NOT reset browser_pin failures.
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            2
        );

        let browser = UnlockSurfaceFactory::create_for(UnlockDomainKind::BrowserSession);
        assert!(
            browser
                .unlock_with_password(
                    &state,
                    &UnlockSurfaceContext {
                        vault_path,
                        unlock_ref: Some("missing".to_owned()),
                        agent_client_id: None,
                    },
                    Zeroizing::new("wrong-password".to_owned()),
                )
                .is_err()
        );
        let err = BrowserPlatformError {
            code: "cancelled",
            message: String::new(),
        };
        assert_eq!(err.code, "cancelled");
    }

    #[test]
    fn agent_mcp_unlock_adapter_supports_password_pin_isolation_cancel_and_rollbacks_on_broker_failure() {
        let dir = TestDir::new("vaultmesh-unlock-surface-agent");
        let state = test_runtime_state(dir.path());
        create_test_vault(&state, "master-pass-123");

        let (vault_path, vault_key) = state
            .runtime
            .lock()
            .unwrap()
            .quick_unlock_material()
            .expect("quick unlock material");
        state
            .pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "111111", 3)
            .expect("enable desktop pin");
        state
            .browser_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "222222", 3)
            .expect("enable browser pin");
        state
            .agent_pin
            .lock()
            .unwrap()
            .enable(vault_path.clone(), vault_key.as_slice(), "333333", 3)
            .expect("enable agent pin");
        state.runtime.lock().unwrap().lock();

        let client_id = setup_paired_agent_broker(&state, unix_millis());
        let adapter = UnlockSurfaceFactory::resolve_for_request(&DisplayedAgentUnlock::Agent {
            unlock_ref: "unused".to_owned(),
            client_id,
        });
        assert_eq!(adapter.kind(), UnlockDomainKind::AgentMcp);

        // 1. Positive password unlock unlocks agent client and clears pending broker unlock request.
        let pw_ref = trigger_agent_unlock_request(&state, client_id, unix_millis());
        *state.agent_unlock_window_request.lock().unwrap() = Some(DisplayedAgentUnlock::Agent {
            unlock_ref: pw_ref.clone(),
            client_id,
        });
        let pw_ctx = UnlockSurfaceContext {
            vault_path: vault_path.clone(),
            unlock_ref: Some(pw_ref),
            agent_client_id: Some(client_id),
        };
        assert_eq!(
            adapter
                .unlock_with_password(&state, &pw_ctx, Zeroizing::new("master-pass-123".to_owned()))
                .expect("agent password unlock succeeds"),
            json!({ "unlocked": true })
        );
        assert!(state.agent_vault_access.is_unlocked(client_id));
        assert!(state.agent_unlock_window_request.lock().unwrap().is_none());
        assert!(
            state
                .agent_broker
                .lock()
                .unwrap()
                .pending_unlock_request(unix_millis())
                .is_none()
        );

        // 2. Lock client, test 3-PIN isolation, wrong-vault rejection, and positive Agent PIN unlock.
        state.agent_vault_access.lock_client(client_id);
        assert!(!state.agent_vault_access.is_unlocked(client_id));
        let pin_ref = trigger_agent_unlock_request(&state, client_id, unix_millis());
        *state.agent_unlock_window_request.lock().unwrap() = Some(DisplayedAgentUnlock::Agent {
            unlock_ref: pin_ref.clone(),
            client_id,
        });
        let pin_ctx = UnlockSurfaceContext {
            vault_path: vault_path.clone(),
            unlock_ref: Some(pin_ref.clone()),
            agent_client_id: Some(client_id),
        };

        // Desktop and Browser PINs must fail and increment ONLY agent_pin failures.
        assert!(
            adapter
                .unlock_with_pin(&state, &pin_ctx, Zeroizing::new("111111".to_owned()))
                .is_err()
        );
        assert!(
            adapter
                .unlock_with_pin(&state, &pin_ctx, Zeroizing::new("222222".to_owned()))
                .is_err()
        );
        assert_eq!(remaining_attempts(&state.pin.lock().unwrap().status()), 3);
        assert_eq!(
            remaining_attempts(&state.browser_pin.lock().unwrap().status()),
            3
        );
        assert_eq!(
            remaining_attempts(&state.agent_pin.lock().unwrap().status()),
            1
        );
        assert!(!state.agent_vault_access.is_unlocked(client_id));

        // Wrong vault path rejects Agent PIN without unlocking client.
        let other_vault = dir.path().join("other-agent.vault");
        let mut other = DesktopRuntime::new(other_vault.clone()).expect("other runtime");
        other.create("other-master-123".to_owned()).expect("create other");
        let wrong_vault_ctx = UnlockSurfaceContext {
            vault_path: other_vault,
            unlock_ref: Some(pin_ref),
            agent_client_id: Some(client_id),
        };
        assert!(
            adapter
                .unlock_with_pin(&state, &wrong_vault_ctx, Zeroizing::new("333333".to_owned()))
                .is_err()
        );
        assert!(!state.agent_vault_access.is_unlocked(client_id));

        // Correct Agent PIN succeeds and unlocks client + clears remaining failure counter.
        assert_eq!(
            adapter
                .unlock_with_pin(&state, &pin_ctx, Zeroizing::new("333333".to_owned()))
                .expect("agent pin unlock succeeds"),
            json!({ "unlocked": true })
        );
        assert!(state.agent_vault_access.is_unlocked(client_id));
        assert_eq!(
            remaining_attempts(&state.agent_pin.lock().unwrap().status()),
            3
        );

        // 3. `finish_agent_unlock` failure MUST roll back `state.agent_vault_access.lock_client(client_id)` on BOTH password and PIN paths.
        state.agent_vault_access.lock_client(client_id);
        let stale_ctx = UnlockSurfaceContext {
            vault_path: vault_path.clone(),
            unlock_ref: Some("nonexistent-unlock-ref".to_owned()),
            agent_client_id: Some(client_id),
        };
        assert!(
            adapter
                .unlock_with_password(&state, &stale_ctx, Zeroizing::new("master-pass-123".to_owned()))
                .is_err()
        );
        assert!(
            !state.agent_vault_access.is_unlocked(client_id),
            "password unlock must lock client when finish_agent_unlock fails"
        );
        assert!(
            adapter
                .unlock_with_pin(&state, &stale_ctx, Zeroizing::new("333333".to_owned()))
                .is_err()
        );
        assert!(
            !state.agent_vault_access.is_unlocked(client_id),
            "pin unlock must lock client when finish_agent_unlock fails"
        );

        // 4. `AgentMcpUnlockAdapter::cancel` clears displayed slot and rejects pending unlock request in broker.
        let cancel_ref = trigger_agent_unlock_request(&state, client_id, unix_millis());
        *state.agent_unlock_window_request.lock().unwrap() = Some(DisplayedAgentUnlock::Agent {
            unlock_ref: cancel_ref.clone(),
            client_id,
        });
        let cancel_ctx = UnlockSurfaceContext {
            vault_path,
            unlock_ref: Some(cancel_ref),
            agent_client_id: Some(client_id),
        };
        assert_eq!(
            adapter.cancel(&state, &cancel_ctx).expect("cancel succeeds"),
            json!({ "cancelled": true })
        );
        assert!(state.agent_unlock_window_request.lock().unwrap().is_none());
        assert!(
            state
                .agent_broker
                .lock()
                .unwrap()
                .pending_unlock_request(unix_millis())
                .is_none()
        );
        assert!(!state.agent_vault_access.is_unlocked(client_id));
    }
}
