use super::*;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

pub(super) const AGENT_AUTHORIZATION_WINDOW_LABEL: &str = "agent-authorization";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DisplayedAgentAuthorization {
    Permission(String),
    Confirmation(String),
}

impl DisplayedAgentAuthorization {
    fn matches_reference(&self, reference: &str) -> bool {
        match self {
            Self::Permission(current) | Self::Confirmation(current) => current == reference,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgentAuthorizationPermissionInput {
    permission_ref: String,
    choice: PermissionChoice,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgentAuthorizationConfirmationInput {
    confirmation_ref: String,
    approved: bool,
}

fn require_authorization_window(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == AGENT_AUTHORIZATION_WINDOW_LABEL {
        Ok(())
    } else {
        Err("授权操作只能从 VaultMesh 系统授权窗口发起。".to_owned())
    }
}

fn client_key_for(state: &AgentBrokerCore, client_id: &str) -> String {
    state
        .admin_clients()
        .into_iter()
        .find(|client| {
            client
                .activities
                .iter()
                .any(|activity| activity.client_id == client_id)
        })
        .map(|client| client.client_key)
        .unwrap_or_else(|| "未知 MCP 集成".to_owned())
}

#[tauri::command]
pub(super) fn agent_authorization_status(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_authorization_window(&window)?;
    let now = unix_millis();
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    broker.prune(now);
    let permission = broker.permission_requests().into_iter().next();
    let confirmation = broker
        .confirmations()
        .into_iter()
        .find(|candidate| !candidate.approved);
    let next = match (permission, confirmation) {
        (Some(permission), Some(confirmation))
            if confirmation.created_at < permission.created_at =>
        {
            let client_key = client_key_for(&broker, &confirmation.client_id);
            *state
                .agent_authorization_window_request
                .lock()
                .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = Some(
                DisplayedAgentAuthorization::Confirmation(confirmation.confirmation_ref.clone()),
            );
            json!({
                "kind": "confirmation",
                "clientKey": client_key,
                "expiresAt": confirmation.expires_at,
                "confirmation": confirmation
            })
        }
        (Some(permission), _) => {
            let client_key = client_key_for(&broker, &permission.client_id);
            *state
                .agent_authorization_window_request
                .lock()
                .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = Some(
                DisplayedAgentAuthorization::Permission(permission.permission_ref.clone()),
            );
            json!({
                "kind": "permission",
                "clientKey": client_key,
                "expiresAt": permission.expires_at,
                "permission": permission
            })
        }
        (None, Some(confirmation)) => {
            let client_key = client_key_for(&broker, &confirmation.client_id);
            *state
                .agent_authorization_window_request
                .lock()
                .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = Some(
                DisplayedAgentAuthorization::Confirmation(confirmation.confirmation_ref.clone()),
            );
            json!({
                "kind": "confirmation",
                "clientKey": client_key,
                "expiresAt": confirmation.expires_at,
                "confirmation": confirmation
            })
        }
        (None, None) => {
            *state
                .agent_authorization_window_request
                .lock()
                .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = None;
            Value::Null
        }
    };
    Ok(json!({
        "now": now,
        "executionExpiresAt": state
            .agent_authorization_window_deadline
            .load(Ordering::Acquire),
        "request": next
    }))
}

#[tauri::command]
pub(super) fn agent_authorization_resolve_permission(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    input: AgentAuthorizationPermissionInput,
) -> Result<Value, String> {
    require_authorization_window(&window)?;
    let displayed = state
        .agent_authorization_window_request
        .lock()
        .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())?
        .clone();
    if displayed
        != Some(DisplayedAgentAuthorization::Permission(
            input.permission_ref.clone(),
        ))
    {
        return Err("授权申请已经变化，请重试。".to_owned());
    }
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    if input.choice.effect == PermissionEffect::Allow {
        let _ = broker
            .activate_pending_direct_action(&input.permission_ref, unix_millis())
            .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    }
    let resolution = broker
        .resolve_permission_choice(&input.permission_ref, input.choice, unix_millis())
        .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    *state
        .agent_authorization_window_request
        .lock()
        .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = None;
    state
        .agent_authorization_window_deadline
        .store(0, Ordering::Release);
    Ok(json!({
        "request": resolution.request,
        "choice": resolution.choice
    }))
}

#[tauri::command]
pub(super) fn agent_authorization_resolve_confirmation(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    input: AgentAuthorizationConfirmationInput,
) -> Result<Value, String> {
    require_authorization_window(&window)?;
    let displayed = state
        .agent_authorization_window_request
        .lock()
        .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())?
        .clone();
    if displayed
        != Some(DisplayedAgentAuthorization::Confirmation(
            input.confirmation_ref.clone(),
        ))
    {
        return Err("动作确认已经变化，请重试。".to_owned());
    }
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    let result = if input.approved {
        broker
            .approve_confirmation(&input.confirmation_ref, unix_millis())
            .map(|confirmation| json!(confirmation))
    } else {
        broker
            .reject_confirmation(&input.confirmation_ref, unix_millis())
            .map(|()| json!({ "rejected": true }))
    }
    .map_err(|error| format!("Agent 操作被拒绝：{}", error.code))?;
    *state
        .agent_authorization_window_request
        .lock()
        .map_err(|_| "Agent 授权窗口状态暂时不可用。".to_owned())? = None;
    state
        .agent_authorization_window_deadline
        .store(0, Ordering::Release);
    Ok(result)
}

fn build_agent_authorization_window(app: &AppHandle, visible: bool) -> Option<WebviewWindow> {
    WebviewWindowBuilder::new(
        app,
        AGENT_AUTHORIZATION_WINDOW_LABEL,
        WebviewUrl::App("index.html?surface=agent-authorization".into()),
    )
    .title("VaultMesh Agent 授权")
    .inner_size(520.0, 670.0)
    .min_inner_size(480.0, 610.0)
    .resizable(false)
    .always_on_top(true)
    .content_protected(true)
    .visible(visible)
    .center()
    .build()
    .ok()
}

pub(super) fn prepare_agent_authorization_window(app: &AppHandle) {
    if app
        .get_webview_window(AGENT_AUTHORIZATION_WINDOW_LABEL)
        .is_none()
    {
        let _ = build_agent_authorization_window(app, false);
    }
}

pub(super) fn show_agent_authorization_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    let window = app
        .get_webview_window(AGENT_AUTHORIZATION_WINDOW_LABEL)
        .or_else(|| build_agent_authorization_window(app, true));
    let Some(window) = window else { return };
    let was_visible = window.is_visible().unwrap_or(false);
    let deadline = unix_millis().saturating_add(AUTHORIZATION_TTL_MILLIS);
    if let Some(state) = app.try_state::<RuntimeState>() {
        state
            .agent_authorization_window_deadline
            .store(deadline, Ordering::Release);
    }
    if !was_visible {
        crate::window_layout_adapter::center_window_on_current_monitor(
            &window,
            Some(crate::window_layout_adapter::LogicalWindowSize {
                width: 520.0,
                height: 670.0,
            }),
        );
    }
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit_to(
        AGENT_AUTHORIZATION_WINDOW_LABEL,
        "agent-authorization-requested",
        (),
    );
}

pub(super) fn expire_agent_authorization_window(app: &AppHandle, reference: &str) {
    let Some(state) = app.try_state::<RuntimeState>() else {
        return;
    };
    let matches_displayed_request = state
        .agent_authorization_window_request
        .lock()
        .ok()
        .and_then(|request| {
            request
                .as_ref()
                .map(|request| request.matches_reference(reference))
        })
        .unwrap_or(false);
    if !matches_displayed_request {
        return;
    }
    state
        .agent_authorization_window_deadline
        .store(unix_millis(), Ordering::Release);
    let _ = app.emit_to(
        AGENT_AUTHORIZATION_WINDOW_LABEL,
        "agent-authorization-expired",
        (),
    );
}

pub(super) fn reject_displayed_authorization_on_window_close(state: &RuntimeState) {
    let displayed = state
        .agent_authorization_window_request
        .lock()
        .ok()
        .and_then(|mut request| request.take());
    state
        .agent_authorization_window_deadline
        .store(0, Ordering::Release);
    let Some(displayed) = displayed else { return };
    let Ok(mut broker) = state.agent_broker.lock() else {
        return;
    };
    match displayed {
        DisplayedAgentAuthorization::Permission(permission_ref) => {
            let _ = broker.resolve_permission_choice(
                &permission_ref,
                PermissionChoice {
                    effect: PermissionEffect::Deny,
                    scope: PermissionScope::Exact,
                    duration: PermissionDuration::Once,
                    path_pattern: None,
                },
                unix_millis(),
            );
        }
        DisplayedAgentAuthorization::Confirmation(confirmation_ref) => {
            let _ = broker.reject_confirmation(&confirmation_ref, unix_millis());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_window_has_a_dedicated_minimum_capability() {
        let capability: Value =
            serde_json::from_str(include_str!("../capabilities/agent-authorization.json")).unwrap();
        assert_eq!(
            capability["windows"],
            json!([AGENT_AUTHORIZATION_WINDOW_LABEL])
        );
        assert_eq!(
            capability["permissions"],
            json!([
                "core:event:default",
                "core:window:allow-hide",
                "allow-agent-authorization-status",
                "allow-agent-authorization-resolve-permission",
                "allow-agent-authorization-resolve-confirmation"
            ])
        );
        let main: Value = serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
        assert!(
            main["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|permission| {
                    !permission
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("allow-agent-authorization-")
                })
        );
    }
}
