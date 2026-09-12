use super::*;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use uuid::Uuid;

pub(super) const AGENT_UNLOCK_WINDOW_LABEL: &str = "agent-unlock";

fn should_wake_unlock_window(visible: bool, minimized: bool) -> bool {
    !visible || minimized
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DisplayedAgentUnlock {
    pub unlock_ref: String,
    pub client_id: Uuid,
}

fn require_unlock_window(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == AGENT_UNLOCK_WINDOW_LABEL {
        Ok(())
    } else {
        Err("MCP 解锁只能从 VaultMesh Agent 解锁窗口发起。".to_owned())
    }
}

fn current_request(state: &RuntimeState) -> Result<DisplayedAgentUnlock, String> {
    state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "Agent 解锁窗口状态暂时不可用。".to_owned())?
        .clone()
        .ok_or_else(|| "MCP 解锁申请已经结束。".to_owned())
}

#[tauri::command]
pub(super) fn agent_unlock_status(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let now = unix_millis();
    let request = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?
        .pending_unlock_request(now);
    let displayed = request.as_ref().and_then(|request| {
        Uuid::parse_str(&request.client_id)
            .ok()
            .map(|client_id| DisplayedAgentUnlock {
                unlock_ref: request.unlock_ref.clone(),
                client_id,
            })
    });
    *state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "Agent 解锁窗口状态暂时不可用。".to_owned())? = displayed;
    let selected_vault_path = state
        .runtime
        .lock()
        .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
        .current_path();
    let access = state.agent_vault_access.status(
        request
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
    Ok(json!({
        "now": now,
        "request": request,
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
    current_request(&state)?;
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

fn finish_unlock(state: &RuntimeState, displayed: &DisplayedAgentUnlock) -> Result<(), String> {
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
        .resolve_unlock_request(
            &displayed.unlock_ref,
            displayed.client_id,
            true,
            unix_millis(),
        )
        .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    *state
        .agent_unlock_window_request
        .lock()
        .map_err(|_| "Agent 解锁窗口状态暂时不可用。".to_owned())? = None;
    Ok(())
}

#[tauri::command]
pub(super) fn agent_unlock_password(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    password: String,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let displayed = current_request(&state)?;
    prune_expired_agent_access(&state, unix_millis())?;
    let selected_vault_path = state
        .runtime
        .lock()
        .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
        .current_path();
    state.agent_vault_access.unlock_with_password(
        displayed.client_id,
        selected_vault_path,
        password,
    )?;
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
        finish_unlock(&state, &displayed)
    })();
    if let Err(error) = result {
        state.agent_vault_access.lock_client(displayed.client_id);
        return Err(error);
    }
    Ok(json!({ "unlocked": true }))
}

#[tauri::command]
pub(super) fn agent_unlock_pin(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    pin: String,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let displayed = current_request(&state)?;
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
        displayed.client_id,
        credential.vault_path,
        credential.vault_key.as_slice(),
    )?;
    if let Err(error) = finish_unlock(&state, &displayed) {
        state.agent_vault_access.lock_client(displayed.client_id);
        return Err(error);
    }
    Ok(json!({ "unlocked": true }))
}

#[tauri::command]
pub(super) async fn agent_unlock_biometric(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let displayed = current_request(&state)?;
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
        displayed.client_id,
        credential.0,
        credential.1.as_slice(),
    )?;
    if let Err(error) = finish_unlock(&state, &displayed) {
        state.agent_vault_access.lock_client(displayed.client_id);
        return Err(error);
    }
    Ok(json!({ "unlocked": true }))
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
    .title("VaultMesh MCP 解锁")
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
    if let Some(window) = app.get_webview_window(AGENT_UNLOCK_WINDOW_LABEL)
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
    let displayed = state
        .agent_unlock_window_request
        .lock()
        .ok()
        .and_then(|request| request.clone());
    if displayed
        .as_ref()
        .map(|request| request.unlock_ref.as_str())
        != Some(reference)
    {
        return;
    }
    let _ = app.emit_to(AGENT_UNLOCK_WINDOW_LABEL, "agent-unlock-expired", ());
}

pub(super) fn reject_displayed_unlock(state: &RuntimeState) {
    let displayed = state
        .agent_unlock_window_request
        .lock()
        .ok()
        .and_then(|mut request| request.take());
    let Some(displayed) = displayed else { return };
    if let Ok(mut broker) = state.agent_broker.lock() {
        let _ = broker.resolve_unlock_request(
            &displayed.unlock_ref,
            displayed.client_id,
            false,
            unix_millis(),
        );
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
}
