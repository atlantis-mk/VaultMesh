use super::*;
use crate::browser_broker::OneShotUnlockedRuntime;
use std::sync::mpsc::SyncSender;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use uuid::Uuid;

pub(super) const AGENT_UNLOCK_WINDOW_LABEL: &str = "agent-unlock";
pub(crate) const TEMPORARY_UNLOCK_WAIT_MILLIS: u64 = 30_000;

fn should_wake_unlock_window(visible: bool, minimized: bool) -> bool {
    !visible || minimized
}

pub(crate) struct PendingBrowserAutofillUnlock {
    pub unlock_ref: String,
    pub vault_path: PathBuf,
    pub origin: String,
    pub item_title: String,
    pub item_kind: String,
    pub master_password_reprompt: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub responder: SyncSender<Result<OneShotUnlockedRuntime, BrowserPlatformError>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserAutofillUnlockSnapshot {
    pub unlock_ref: String,
    pub vault_path: PathBuf,
    pub origin: String,
    pub item_title: String,
    pub item_kind: String,
    pub master_password_reprompt: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Default)]
pub(crate) struct BrowserAutofillUnlockQueue {
    requests: Vec<PendingBrowserAutofillUnlock>,
}

impl BrowserAutofillUnlockQueue {
    pub fn enqueue(&mut self, request: PendingBrowserAutofillUnlock) {
        self.prune_expired(request.created_at);
        self.requests.push(request);
    }

    pub fn prune_expired(&mut self, now_millis: u64) {
        let mut remaining = Vec::with_capacity(self.requests.len());
        for entry in self.requests.drain(..) {
            if entry.expires_at > now_millis {
                remaining.push(entry);
            } else {
                let _ = entry.responder.send(Err(BrowserPlatformError {
                    code: "cancelled",
                    message: "自动填充临时解锁已超时。".to_owned(),
                }));
            }
        }
        self.requests = remaining;
    }

    pub fn peek_oldest(&mut self, now_millis: u64) -> Option<BrowserAutofillUnlockSnapshot> {
        self.prune_expired(now_millis);
        self.requests
            .iter()
            .min_by_key(|entry| entry.created_at)
            .map(|entry| BrowserAutofillUnlockSnapshot {
                unlock_ref: entry.unlock_ref.clone(),
                vault_path: entry.vault_path.clone(),
                origin: entry.origin.clone(),
                item_title: entry.item_title.clone(),
                item_kind: entry.item_kind.clone(),
                master_password_reprompt: entry.master_password_reprompt,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
            })
    }

    pub fn take(&mut self, unlock_ref: &str) -> Option<PendingBrowserAutofillUnlock> {
        let index = self
            .requests
            .iter()
            .position(|entry| entry.unlock_ref == unlock_ref)?;
        Some(self.requests.remove(index))
    }

    pub fn clear_all(&mut self) {
        for entry in self.requests.drain(..) {
            let _ = entry.responder.send(Err(BrowserPlatformError {
                code: "cancelled",
                message: "已取消本次自动填充。".to_owned(),
            }));
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DisplayedAgentUnlock {
    Agent {
        unlock_ref: String,
        client_id: Uuid,
    },
    BrowserAutofill {
        unlock_ref: String,
        vault_path: PathBuf,
        master_password_reprompt: bool,
    },
}

impl DisplayedAgentUnlock {
    pub(super) fn unlock_ref(&self) -> &str {
        match self {
            Self::Agent { unlock_ref, .. } | Self::BrowserAutofill { unlock_ref, .. } => unlock_ref,
        }
    }
}

fn require_unlock_window(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == AGENT_UNLOCK_WINDOW_LABEL {
        Ok(())
    } else {
        Err("临时解锁只能从 VaultMesh 临时解锁窗口发起。".to_owned())
    }
}

fn current_request(state: &RuntimeState) -> Result<DisplayedAgentUnlock, String> {
    state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "临时解锁窗口状态暂时不可用。".to_owned())?
        .clone()
        .ok_or_else(|| "当前解锁申请已经结束。".to_owned())
}

#[tauri::command]
pub(super) fn agent_unlock_status(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let now = unix_millis();
    let agent_request = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?
        .pending_unlock_request(now);
    let browser_request = state
        .browser_autofill_unlocks
        .lock()
        .map_err(|_| "浏览器自动填充临时解锁队列暂时不可用。".to_owned())?
        .peek_oldest(now);

    let prefer_browser = match (&agent_request, &browser_request) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(agent), Some(browser)) => browser.created_at < agent.created_at,
    };

    if prefer_browser && let Some(request) = browser_request {
        let displayed = DisplayedAgentUnlock::BrowserAutofill {
            unlock_ref: request.unlock_ref.clone(),
            vault_path: request.vault_path.clone(),
            master_password_reprompt: request.master_password_reprompt,
        };
        *state
            .agent_unlock_window_request
            .lock()
            .map_err(|_| "临时解锁窗口状态暂时不可用。".to_owned())? = Some(displayed);

        let has_vault = request.vault_path.is_file();
        let access = json!({
            "hasVault": has_vault,
            "clientUnlocked": false,
            "settings": { "unlockScope": "connection" }
        });
        let (pin, biometric) = if request.master_password_reprompt {
            (
                json!({
                    "enabled": false,
                    "locked": false,
                    "remainingAttempts": 0
                }),
                json!({
                    "available": false,
                    "enabled": false,
                    "kind": Value::Null
                }),
            )
        } else {
            let desktop_pin = state
                .pin
                .lock()
                .map_err(|_| "桌面 PIN 状态暂时不可用。".to_owned())?;
            desktop_pin.disable_if_for_different_vault(&request.vault_path)?;
            let pin_status = json!(desktop_pin.status());
            drop(desktop_pin);

            let desktop_biometric = state
                .biometric
                .lock()
                .map_err(|_| "Touch ID 状态暂时不可用。".to_owned())?;
            desktop_biometric.disable_if_for_different_vault(&request.vault_path)?;
            let mut biometric_status = json!(desktop_biometric.status());
            let canonical_vault = request.vault_path.canonicalize().ok();
            if desktop_biometric
                .credential_binding()
                .ok()
                .is_none_or(|(bound_path, _)| Some(bound_path) != canonical_vault)
            {
                biometric_status["enabled"] = json!(false);
            }
            drop(desktop_biometric);
            (pin_status, biometric_status)
        };

        return Ok(json!({
            "now": now,
            "request": {
                "kind": "browser-autofill",
                "unlockRef": request.unlock_ref,
                "origin": request.origin,
                "itemTitle": request.item_title,
                "itemKind": request.item_kind,
                "masterPasswordReprompt": request.master_password_reprompt,
                "createdAt": request.created_at,
                "expiresAt": request.expires_at,
            },
            "access": access,
            "pin": pin,
            "biometric": biometric
        }));
    }

    let displayed = agent_request.as_ref().and_then(|request| {
        Uuid::parse_str(&request.client_id)
            .ok()
            .map(|client_id| DisplayedAgentUnlock::Agent {
                unlock_ref: request.unlock_ref.clone(),
                client_id,
            })
    });
    *state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "临时解锁窗口状态暂时不可用。".to_owned())? = displayed;
    let selected_vault_path = state
        .runtime
        .lock()
        .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
        .current_path();
    let access = state.agent_vault_access.status(
        agent_request
            .as_ref()
            .and_then(|request| Uuid::parse_str(&request.client_id).ok()),
        &selected_vault_path,
    )?;
    let agent_pin = state
        .agent_pin
        .lock()
        .map_err(|_| "Agent PIN 状态暂时不可用。".to_owned())?;
    agent_pin.disable_if_for_different_vault(&selected_vault_path)?;
    let pin = agent_pin.status();
    let agent_biometric = state
        .agent_biometric
        .lock()
        .map_err(|_| "Agent Touch ID 状态暂时不可用。".to_owned())?;
    agent_biometric.disable_if_for_different_vault(&selected_vault_path)?;
    let biometric = agent_biometric.status();
    let serialized_request = agent_request.map(|request| {
        let mut value = json!(request);
        if let Some(object) = value.as_object_mut() {
            object.insert("kind".to_owned(), json!("agent"));
        }
        value
    });
    Ok(json!({
        "now": now,
        "request": serialized_request,
        "access": access,
        "pin": pin,
        "biometric": biometric
    }))
}

#[tauri::command]
pub(super) fn agent_unlock_set_scope(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    scope: AgentUnlockScope,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    if matches!(
        current_request(&state)?,
        DisplayedAgentUnlock::BrowserAutofill { .. }
    ) {
        return Err("浏览器单次自动填充不支持修改 Agent 解锁范围。".to_owned());
    }
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    let (settings, affected_clients) = state
        .agent_vault_access
        .update_unlock_scope(scope, unix_millis())?;
    for client_id in affected_clients {
        broker.expire_agent_client_authority(client_id);
    }
    Ok(json!(settings))
}

fn finish_agent_unlock(
    state: &RuntimeState,
    unlock_ref: &str,
    client_id: Uuid,
) -> Result<(), String> {
    let connector_definitions = state
        .agent_vault_access
        .runtime()
        .lock()
        .map_err(|_| "Agent 保险库暂时不可用。".to_owned())?
        .agent_connector_definition_records()
        .map_err(|error| error.public_message())?;
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    broker
        .sync_connector_definitions(connector_definitions)
        .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    broker
        .resolve_unlock_request(unlock_ref, client_id, true, unix_millis())
        .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    *state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "临时解锁窗口状态暂时不可用。".to_owned())? = None;
    Ok(())
}

fn complete_browser_autofill_unlock(
    state: &RuntimeState,
    unlock_ref: &str,
    mut temp_runtime: DesktopRuntime,
    master_password: Option<Zeroizing<String>>,
) -> Result<Value, String> {
    let _ = state.browser_preauth_preview.sync_from_runtime(&mut temp_runtime);
    let now = unix_millis();
    let pending = state
        .browser_autofill_unlocks
        .lock()
        .map_err(|_| "浏览器自动填充临时解锁队列暂时不可用。".to_owned())?
        .take(unlock_ref);
    if let Ok(mut slot) = state.agent_unlock_window_request.lock()
        && slot.as_ref().map(DisplayedAgentUnlock::unlock_ref) == Some(unlock_ref)
    {
        *slot = None;
    }
    let Some(pending) = pending.filter(|item| item.expires_at > now) else {
        temp_runtime.lock();
        return Err("本次自动填充解锁已超时，请在网页重新点击候选填充。".to_owned());
    };
    if pending
        .responder
        .send(Ok(OneShotUnlockedRuntime {
            runtime: temp_runtime,
            master_password,
        }))
        .is_err()
    {
        return Err("本次自动填充请求已失效，请在网页重新点击候选填充。".to_owned());
    }
    Ok(json!({ "unlocked": true }))
}

#[tauri::command]
pub(super) fn agent_unlock_password(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    password: String,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    match current_request(&state)? {
        DisplayedAgentUnlock::BrowserAutofill {
            unlock_ref,
            vault_path,
            ..
        } => {
            let password = Zeroizing::new(password);
            let mut temp_runtime = DesktopRuntime::new(vault_path.clone())
                .map_err(|error| error.public_message().to_owned())?;
            temp_runtime
                .unlock_for_agent_from(vault_path.clone(), password.as_str().to_owned())
                .map_err(|error| error.public_message().to_owned())?;
            if let Ok(pin) = state.pin.lock() {
                let _ = pin
                    .disable_if_for_different_vault(&vault_path)
                    .and_then(|()| pin.reset_failures(&vault_path));
            }
            complete_browser_autofill_unlock(&state, &unlock_ref, temp_runtime, Some(password))
        }
        DisplayedAgentUnlock::Agent {
            unlock_ref,
            client_id,
        } => {
            prune_expired_agent_access(&state, unix_millis())?;
            let selected_vault_path = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .current_path();
            state
                .agent_vault_access
                .unlock_with_password(client_id, selected_vault_path, password)?;
            let result = (|| {
                let vault_path = state
                    .agent_vault_access
                    .runtime()
                    .lock()
                    .map_err(|_| "Agent 保险库暂时不可用。".to_owned())?
                    .current_path();
                state
                    .agent_pin
                    .lock()
                    .map_err(|_| "Agent PIN 状态暂时不可用。".to_owned())?
                    .disable_if_for_different_vault(&vault_path)?;
                finish_agent_unlock(&state, &unlock_ref, client_id)
            })();
            if let Err(error) = result {
                state.agent_vault_access.lock_client(client_id);
                return Err(error);
            }
            Ok(json!({ "unlocked": true }))
        }
    }
}

#[tauri::command]
pub(super) fn agent_unlock_pin(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    pin: String,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    match current_request(&state)? {
        DisplayedAgentUnlock::BrowserAutofill {
            unlock_ref,
            vault_path,
            master_password_reprompt,
        } => {
            if master_password_reprompt {
                return Err("此条目受主密码保护，请使用主密码确认填充。".to_owned());
            }
            let pin = Zeroizing::new(pin);
            let credential = state
                .pin
                .lock()
                .map_err(|_| "桌面 PIN 状态暂时不可用。".to_owned())?
                .unlock(pin.as_str())?;
            let canonical_vault = vault_path
                .canonicalize()
                .map_err(|_| "无法定位当前保险库。".to_owned())?;
            if credential.vault_path != canonical_vault {
                return Err("桌面端 PIN 不属于当前保险库，请使用主密码解锁。".to_owned());
            }
            let mut temp_runtime = DesktopRuntime::new(vault_path)
                .map_err(|error| error.public_message().to_owned())?;
            temp_runtime
                .unlock_for_agent_with_quick_key(
                    credential.vault_path,
                    credential.vault_key.as_slice(),
                )
                .map_err(|error| error.public_message().to_owned())?;
            complete_browser_autofill_unlock(&state, &unlock_ref, temp_runtime, None)
        }
        DisplayedAgentUnlock::Agent {
            unlock_ref,
            client_id,
        } => {
            prune_expired_agent_access(&state, unix_millis())?;
            let pin = Zeroizing::new(pin);
            let credential = state
                .agent_pin
                .lock()
                .map_err(|_| "Agent PIN 状态暂时不可用。".to_owned())?
                .unlock(pin.as_str())?;
            let selected_vault_path = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .current_path()
                .canonicalize()
                .map_err(|_| "无法定位当前保险库。".to_owned())?;
            if credential.vault_path != selected_vault_path {
                return Err("Agent PIN 不属于当前保险库，请使用主密码解锁。".to_owned());
            }
            state.agent_vault_access.unlock_with_quick_key(
                client_id,
                credential.vault_path,
                credential.vault_key.as_slice(),
            )?;
            if let Err(error) = finish_agent_unlock(&state, &unlock_ref, client_id) {
                state.agent_vault_access.lock_client(client_id);
                return Err(error);
            }
            Ok(json!({ "unlocked": true }))
        }
    }
}

#[tauri::command]
pub(super) async fn agent_unlock_biometric(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    match current_request(&state)? {
        DisplayedAgentUnlock::BrowserAutofill {
            unlock_ref,
            vault_path,
            master_password_reprompt,
        } => {
            if master_password_reprompt {
                return Err("此条目受主密码保护，请使用主密码确认填充。".to_owned());
            }
            let credential = with_biometric(&state, |biometric| biometric.unlock()).await?;
            let canonical_vault = vault_path
                .canonicalize()
                .map_err(|_| "无法定位当前保险库。".to_owned())?;
            if credential.0 != canonical_vault {
                return Err("Touch ID 不属于当前保险库，请使用主密码解锁。".to_owned());
            }
            let mut temp_runtime = DesktopRuntime::new(vault_path)
                .map_err(|error| error.public_message().to_owned())?;
            temp_runtime
                .unlock_for_agent_with_quick_key(credential.0, credential.1.as_slice())
                .map_err(|error| error.public_message().to_owned())?;
            complete_browser_autofill_unlock(&state, &unlock_ref, temp_runtime, None)
        }
        DisplayedAgentUnlock::Agent {
            unlock_ref,
            client_id,
        } => {
            prune_expired_agent_access(&state, unix_millis())?;
            let credential = with_agent_biometric(&state, |biometric| biometric.unlock()).await?;
            let selected_vault_path = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .current_path()
                .canonicalize()
                .map_err(|_| "无法定位当前保险库。".to_owned())?;
            if credential.0 != selected_vault_path {
                return Err("Agent Touch ID 不属于当前保险库，请使用主密码解锁。".to_owned());
            }
            state.agent_vault_access.unlock_with_quick_key(
                client_id,
                credential.0,
                credential.1.as_slice(),
            )?;
            if let Err(error) = finish_agent_unlock(&state, &unlock_ref, client_id) {
                state.agent_vault_access.lock_client(client_id);
                return Err(error);
            }
            Ok(json!({ "unlocked": true }))
        }
    }
}

#[tauri::command]
pub(super) fn agent_unlock_cancel(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    reject_displayed_unlock(&state);
    Ok(json!({ "cancelled": true }))
}

fn build_agent_unlock_window(app: &AppHandle, visible: bool) -> Option<WebviewWindow> {
    WebviewWindowBuilder::new(
        app,
        AGENT_UNLOCK_WINDOW_LABEL,
        WebviewUrl::App("index.html?surface=agent-unlock".into()),
    )
    .title("VaultMesh 临时解锁")
    .inner_size(600.0, 440.0)
    .min_inner_size(520.0, 420.0)
    .resizable(false)
    .always_on_top(true)
    .content_protected(true)
    .visible(visible)
    .center()
    .build()
    .ok()
}

pub(super) fn prepare_agent_unlock_window(app: &AppHandle) {
    if app.get_webview_window(AGENT_UNLOCK_WINDOW_LABEL).is_none() {
        let _ = build_agent_unlock_window(app, false);
    }
}

pub(super) fn show_agent_unlock_window(app: &AppHandle) {
    let has_displayed_request = app
        .try_state::<RuntimeState>()
        .and_then(|state| {
            state
                .agent_unlock_window_request
                .lock()
                .ok()
                .map(|request| request.is_some())
        })
        .unwrap_or(false);
    if let Some(window) = app.get_webview_window(AGENT_UNLOCK_WINDOW_LABEL)
        && has_displayed_request
        && !should_wake_unlock_window(
            window.is_visible().unwrap_or(false),
            window.is_minimized().unwrap_or(false),
        )
    {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    let window = app
        .get_webview_window(AGENT_UNLOCK_WINDOW_LABEL)
        .or_else(|| build_agent_unlock_window(app, true));
    let Some(window) = window else { return };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit_to(AGENT_UNLOCK_WINDOW_LABEL, "agent-unlock-requested", ());
}

pub(super) fn expire_agent_unlock_window(app: &AppHandle, reference: &str) {
    let Some(state) = app.try_state::<RuntimeState>() else {
        return;
    };
    let matches_displayed = state
        .agent_unlock_window_request
        .lock()
        .ok()
        .and_then(|request| request.as_ref().map(|item| item.unlock_ref() == reference))
        .unwrap_or(false);
    if !matches_displayed {
        return;
    }
    reject_displayed_unlock(&state);
    let now = unix_millis();
    let has_next = state
        .agent_broker
        .lock()
        .ok()
        .and_then(|mut broker| broker.pending_unlock_request(now))
        .is_some()
        || state
            .browser_autofill_unlocks
            .lock()
            .ok()
            .and_then(|mut queue| queue.peek_oldest(now))
            .is_some();
    if has_next {
        let _ = app.emit_to(AGENT_UNLOCK_WINDOW_LABEL, "agent-unlock-requested", ());
    } else {
        let _ = app.emit_to(AGENT_UNLOCK_WINDOW_LABEL, "agent-unlock-expired", ());
        if let Some(window) = app.get_webview_window(AGENT_UNLOCK_WINDOW_LABEL) {
            let _ = window.hide();
        }
    }
}

pub(super) fn reject_displayed_unlock(state: &RuntimeState) {
    let displayed = state
        .agent_unlock_window_request
        .lock()
        .ok()
        .and_then(|mut request| request.take());
    let Some(displayed) = displayed else { return };
    match displayed {
        DisplayedAgentUnlock::Agent {
            unlock_ref,
            client_id,
        } => {
            if let Ok(mut broker) = state.agent_broker.lock() {
                let _ = broker.resolve_unlock_request(&unlock_ref, client_id, false, unix_millis());
            }
        }
        DisplayedAgentUnlock::BrowserAutofill { unlock_ref, .. } => {
            if let Ok(mut queue) = state.browser_autofill_unlocks.lock()
                && let Some(pending) = queue.take(&unlock_ref)
            {
                let _ = pending.responder.send(Err(BrowserPlatformError {
                    code: "cancelled",
                    message: "已取消本次自动填充。".to_owned(),
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_window_has_a_dedicated_minimum_capability() {
        let capability: Value =
            serde_json::from_str(include_str!("../capabilities/agent-unlock.json")).unwrap();
        assert_eq!(capability["windows"], json!([AGENT_UNLOCK_WINDOW_LABEL]));
        assert_eq!(
            capability["permissions"],
            json!([
                "core:event:default",
                "core:window:allow-hide",
                "allow-agent-unlock-status",
                "allow-agent-unlock-set-scope",
                "allow-agent-unlock-password",
                "allow-agent-unlock-pin",
                "allow-agent-unlock-biometric",
                "allow-agent-unlock-cancel"
            ])
        );
    }

    #[test]
    fn visible_unlock_window_is_not_repeatedly_focused_or_refreshed() {
        assert!(!should_wake_unlock_window(true, false));
        assert!(should_wake_unlock_window(false, false));
        assert!(should_wake_unlock_window(true, true));
    }

    #[test]
    fn ct_browser_002_browser_autofill_unlock_queue_orders_fifo_and_prunes_expired() {
        let mut queue = BrowserAutofillUnlockQueue::default();
        let (tx_expired, rx_expired) = std::sync::mpsc::sync_channel(1);
        let (tx_first, _rx_first) = std::sync::mpsc::sync_channel(1);
        let (tx_second, rx_second) = std::sync::mpsc::sync_channel(1);

        queue.enqueue(PendingBrowserAutofillUnlock {
            unlock_ref: "expired-ref".to_owned(),
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://expired.example".to_owned(),
            item_title: "Expired".to_owned(),
            item_kind: "login".to_owned(),
            master_password_reprompt: false,
            created_at: 1_000,
            expires_at: 31_000,
            responder: tx_expired,
        });
        queue.enqueue(PendingBrowserAutofillUnlock {
            unlock_ref: "second-ref".to_owned(),
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://second.example".to_owned(),
            item_title: "Second".to_owned(),
            item_kind: "card".to_owned(),
            master_password_reprompt: true,
            created_at: 20_000,
            expires_at: 50_000,
            responder: tx_second,
        });
        queue.enqueue(PendingBrowserAutofillUnlock {
            unlock_ref: "first-ref".to_owned(),
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://first.example".to_owned(),
            item_title: "First".to_owned(),
            item_kind: "login".to_owned(),
            master_password_reprompt: false,
            created_at: 10_000,
            expires_at: 40_000,
            responder: tx_first,
        });

        let oldest = queue.peek_oldest(31_000).expect("oldest active request");
        assert_eq!(oldest.unlock_ref, "first-ref");
        assert_eq!(
            rx_expired.try_recv().expect("expired response").err().map(|e| e.code),
            Some("cancelled")
        );
        assert!(queue.take("first-ref").is_some());
        assert_eq!(
            queue.peek_oldest(31_000).map(|item| item.unlock_ref),
            Some("second-ref".to_owned())
        );
        queue.clear_all();
        assert_eq!(
            rx_second.try_recv().expect("cleared response").err().map(|e| e.code),
            Some("cancelled")
        );
        assert!(queue.peek_oldest(31_000).is_none());
    }
}
