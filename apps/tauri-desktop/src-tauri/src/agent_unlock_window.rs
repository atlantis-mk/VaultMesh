use std::sync::{Arc, mpsc::SyncSender};

use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::*;
use crate::{
    browser_broker::{
        BrowserRepromptRequest, BrowserSessionUnlockRequest, BrowserUnlockResolution,
        BrowserUnlockSource,
    },
    unlock_surface_adapter::{
        UnlockDomainKind, UnlockSurfaceAdapter, UnlockSurfaceContext, UnlockSurfaceFactory,
    },
};

pub(crate) const AGENT_UNLOCK_WINDOW_LABEL: &str = "agent-unlock";
pub(crate) const TEMPORARY_UNLOCK_WAIT_MILLIS: u64 = 30_000;

fn should_wake_unlock_window(visible: bool, minimized: bool) -> bool {
    !visible || minimized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrowserUnlockPurpose {
    Session,
    MasterPasswordReprompt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoveResponderOutcome {
    NotFound,
    RemainingWaiters,
    EntryRemoved,
}

pub(crate) struct PendingBrowserUnlock {
    pub unlock_ref: String,
    pub purpose: BrowserUnlockPurpose,
    pub source: BrowserUnlockSource,
    pub vault_path: PathBuf,
    pub origin: String,
    pub item_title: String,
    pub item_kind: String,
    pub master_password_reprompt: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub responders: Vec<(
        u64,
        SyncSender<Result<BrowserUnlockResolution, BrowserPlatformError>>,
    )>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserUnlockSnapshot {
    pub unlock_ref: String,
    pub purpose: BrowserUnlockPurpose,
    pub source: BrowserUnlockSource,
    pub vault_path: PathBuf,
    pub origin: String,
    pub item_title: String,
    pub item_kind: String,
    pub master_password_reprompt: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Default)]
pub(crate) struct BrowserUnlockQueue {
    requests: Vec<PendingBrowserUnlock>,
    next_responder_id: u64,
}

impl BrowserUnlockQueue {
    fn allocate_responder_id(&mut self) -> u64 {
        self.next_responder_id = self.next_responder_id.wrapping_add(1).max(1);
        self.next_responder_id
    }

    #[cfg(test)]
    pub fn enqueue(&mut self, request: PendingBrowserUnlock) {
        self.prune_expired(request.created_at);
        self.requests.push(request);
    }

    pub fn enqueue_session_or_merge(
        &mut self,
        request: BrowserSessionUnlockRequest,
        now_millis: u64,
        expires_at: u64,
        responder: SyncSender<Result<BrowserUnlockResolution, BrowserPlatformError>>,
    ) -> (String, u64) {
        self.prune_expired(now_millis);
        let responder_id = self.allocate_responder_id();

        if !request.master_password_reprompt
            && let Some(existing) = self.requests.iter_mut().find(|entry| {
                entry.purpose == BrowserUnlockPurpose::Session
                    && !entry.master_password_reprompt
                    && entry.vault_path == request.vault_path
                    && entry.expires_at > now_millis
            })
        {
            existing.expires_at = existing.expires_at.max(expires_at);
            existing.responders.push((responder_id, responder));
            return (existing.unlock_ref.clone(), responder_id);
        }

        let unlock_ref = Uuid::new_v4().to_string();
        self.requests.push(PendingBrowserUnlock {
            unlock_ref: unlock_ref.clone(),
            purpose: BrowserUnlockPurpose::Session,
            source: request.source,
            vault_path: request.vault_path,
            origin: request.origin.unwrap_or_default(),
            item_title: request.item_title.unwrap_or_default(),
            item_kind: request.item_kind.unwrap_or_default(),
            master_password_reprompt: request.master_password_reprompt,
            created_at: now_millis,
            expires_at,
            responders: vec![(responder_id, responder)],
        });
        (unlock_ref, responder_id)
    }

    pub fn enqueue_reprompt(
        &mut self,
        request: BrowserRepromptRequest,
        now_millis: u64,
        expires_at: u64,
        responder: SyncSender<Result<BrowserUnlockResolution, BrowserPlatformError>>,
    ) -> (String, u64) {
        self.prune_expired(now_millis);
        let responder_id = self.allocate_responder_id();
        let unlock_ref = Uuid::new_v4().to_string();
        self.requests.push(PendingBrowserUnlock {
            unlock_ref: unlock_ref.clone(),
            purpose: BrowserUnlockPurpose::MasterPasswordReprompt,
            source: BrowserUnlockSource::Autofill,
            vault_path: request.vault_path,
            origin: request.origin,
            item_title: request.item_title,
            item_kind: request.item_kind,
            master_password_reprompt: true,
            created_at: now_millis,
            expires_at,
            responders: vec![(responder_id, responder)],
        });
        (unlock_ref, responder_id)
    }

    pub fn entry_expires_at(&self, unlock_ref: &str) -> Option<u64> {
        self.requests
            .iter()
            .find(|entry| entry.unlock_ref == unlock_ref)
            .map(|entry| entry.expires_at)
    }

    pub fn remove_responder(
        &mut self,
        unlock_ref: &str,
        responder_id: u64,
    ) -> RemoveResponderOutcome {
        let Some(index) = self
            .requests
            .iter()
            .position(|entry| entry.unlock_ref == unlock_ref)
        else {
            return RemoveResponderOutcome::NotFound;
        };
        let entry = &mut self.requests[index];
        entry.responders.retain(|(id, _)| *id != responder_id);
        if entry.responders.is_empty() {
            self.requests.remove(index);
            RemoveResponderOutcome::EntryRemoved
        } else {
            RemoveResponderOutcome::RemainingWaiters
        }
    }

    pub fn prune_expired(&mut self, now_millis: u64) {
        let mut remaining = Vec::with_capacity(self.requests.len());
        for entry in self.requests.drain(..) {
            if entry.expires_at > now_millis {
                remaining.push(entry);
            } else {
                for (_, sender) in entry.responders {
                    let _ = sender.send(Err(BrowserPlatformError {
                        code: "cancelled",
                        message: "解锁请求已超时，请重试。".to_owned(),
                    }));
                }
            }
        }
        self.requests = remaining;
    }

    pub fn peek_oldest(&mut self, now_millis: u64) -> Option<BrowserUnlockSnapshot> {
        self.prune_expired(now_millis);
        self.requests
            .iter()
            .min_by_key(|entry| entry.created_at)
            .map(|entry| BrowserUnlockSnapshot {
                unlock_ref: entry.unlock_ref.clone(),
                purpose: entry.purpose,
                source: entry.source,
                vault_path: entry.vault_path.clone(),
                origin: entry.origin.clone(),
                item_title: entry.item_title.clone(),
                item_kind: entry.item_kind.clone(),
                master_password_reprompt: entry.master_password_reprompt,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
            })
    }

    pub fn take(&mut self, unlock_ref: &str) -> Option<PendingBrowserUnlock> {
        let index = self
            .requests
            .iter()
            .position(|entry| entry.unlock_ref == unlock_ref)?;
        Some(self.requests.remove(index))
    }

    pub fn clear_all(&mut self) {
        for entry in self.requests.drain(..) {
            for (_, sender) in entry.responders {
                let _ = sender.send(Err(BrowserPlatformError {
                    code: "cancelled",
                    message: "已取消本次解锁。".to_owned(),
                }));
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DisplayedAgentUnlock {
    Agent {
        unlock_ref: String,
        client_id: Uuid,
    },
    BrowserUnlock {
        unlock_ref: String,
        vault_path: PathBuf,
        master_password_reprompt: bool,
    },
}

impl DisplayedAgentUnlock {
    pub(crate) fn unlock_ref(&self) -> &str {
        match self {
            Self::Agent { unlock_ref, .. } | Self::BrowserUnlock { unlock_ref, .. } => unlock_ref,
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

fn resolve_for_unlock_window(
    window: &WebviewWindow,
    state: &RuntimeState,
) -> Result<(&'static dyn UnlockSurfaceAdapter, UnlockSurfaceContext), String> {
    let (adapter, ctx) = UnlockSurfaceFactory::resolve_for_window(window.label(), state)?;
    if adapter.window_label() != window.label() {
        return Err("临时解锁只能从对应窗口发起。".to_owned());
    }
    Ok((adapter, ctx))
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
        .browser_unlocks
        .lock()
        .map_err(|_| "浏览器解锁队列暂时不可用。".to_owned())?
        .peek_oldest(now);

    let prefer_browser = match (&agent_request, &browser_request) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(agent), Some(browser)) => browser.created_at < agent.created_at,
    };

    if prefer_browser && let Some(request) = browser_request {
        let displayed = DisplayedAgentUnlock::BrowserUnlock {
            unlock_ref: request.unlock_ref.clone(),
            vault_path: request.vault_path.clone(),
            master_password_reprompt: request.master_password_reprompt,
        };
        let adapter = UnlockSurfaceFactory::resolve_for_request(&displayed);
        if adapter.window_label() != window.label() {
            return Err("临时解锁只能从对应窗口发起。".to_owned());
        }
        let _ = window.set_title(adapter.title());
        let ctx = UnlockSurfaceContext {
            vault_path: request.vault_path.clone(),
            unlock_ref: Some(request.unlock_ref.clone()),
            agent_client_id: None,
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
        let pin = adapter.pin_status(&state, &ctx)?;
        let biometric = adapter.biometric_status(&state, &ctx)?;
        let kind = match request.purpose {
            BrowserUnlockPurpose::Session => "browser-session",
            BrowserUnlockPurpose::MasterPasswordReprompt => "browser-autofill",
        };

        return Ok(json!({
            "now": now,
            "request": {
                "kind": kind,
                "source": request.source,
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
    let parsed_client_id = agent_request
        .as_ref()
        .and_then(|request| Uuid::parse_str(&request.client_id).ok());
    let access = state
        .agent_vault_access
        .status(parsed_client_id, &selected_vault_path)?;
    let adapter = UnlockSurfaceFactory::create_for(UnlockDomainKind::AgentMcp);
    if adapter.window_label() != window.label() {
        return Err("临时解锁只能从对应窗口发起。".to_owned());
    }
    if agent_request.is_some() {
        let _ = window.set_title(adapter.title());
    } else {
        let _ = window.set_title("VaultMesh 临时解锁");
    }
    let ctx = UnlockSurfaceContext {
        vault_path: selected_vault_path,
        unlock_ref: agent_request.as_ref().map(|request| request.unlock_ref.clone()),
        agent_client_id: parsed_client_id,
    };
    let pin = adapter.pin_status(&state, &ctx)?;
    let biometric = adapter.biometric_status(&state, &ctx)?;
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
        DisplayedAgentUnlock::BrowserUnlock { .. }
    ) {
        return Err("浏览器解锁申请不支持修改 Agent 解锁范围。".to_owned());
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

pub(crate) fn finish_agent_unlock(
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

pub(crate) fn complete_browser_unlock(
    state: &RuntimeState,
    unlock_ref: &str,
    resolution: BrowserUnlockResolution,
) -> Result<Value, String> {
    let now = unix_millis();
    let pending = state
        .browser_unlocks
        .lock()
        .map_err(|_| "浏览器解锁队列暂时不可用。".to_owned())?
        .take(unlock_ref);
    if let Ok(mut slot) = state.agent_unlock_window_request.lock()
        && slot.as_ref().map(DisplayedAgentUnlock::unlock_ref) == Some(unlock_ref)
    {
        *slot = None;
    }
    let Some(pending) = pending else {
        return Err("本次解锁请求已失效，请在浏览器中重试。".to_owned());
    };
    if pending.expires_at <= now {
        for (_, sender) in pending.responders {
            let _ = sender.send(Err(BrowserPlatformError {
                code: "cancelled",
                message: "解锁请求已超时，请重试。".to_owned(),
            }));
        }
        return Err("本次解锁已超时，请在浏览器中重试。".to_owned());
    }
    let total = pending.responders.len();
    let mut delivered = 0usize;
    for (_, sender) in pending.responders {
        if sender.send(Ok(resolution.clone())).is_ok() {
            delivered += 1;
        }
    }
    if total > 0 && delivered == 0 {
        return Err("本次解锁请求已失效，请在浏览器中重试。".to_owned());
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
    desktop_authentication::invalidate_window(
        window.app_handle(),
        &state,
        AGENT_UNLOCK_WINDOW_LABEL,
    );
    let (adapter, ctx) = resolve_for_unlock_window(&window, &state)?;
    adapter.unlock_with_password(&state, &ctx, Zeroizing::new(password))
}

#[tauri::command]
pub(super) fn agent_unlock_pin(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    pin: String,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    desktop_authentication::invalidate_window(
        window.app_handle(),
        &state,
        AGENT_UNLOCK_WINDOW_LABEL,
    );
    let (adapter, ctx) = resolve_for_unlock_window(&window, &state)?;
    adapter.unlock_with_pin(&state, &ctx, Zeroizing::new(pin))
}

#[tauri::command]
pub(super) async fn agent_unlock_biometric(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    desktop_authentication::invalidate_window(
        window.app_handle(),
        &state,
        AGENT_UNLOCK_WINDOW_LABEL,
    );
    let (adapter, ctx) = resolve_for_unlock_window(&window, &state)?;
    if !adapter.allows_quick_unlock() {
        return Err("此条目受主密码保护，请使用主密码确认填充。".to_owned());
    }
    let biometric = Arc::clone(
        adapter
            .biometric_service(&state)
            .ok_or_else(|| "此条目受主密码保护，请使用主密码确认填充。".to_owned())?,
    );
    let (vault_path, vault_key) = tauri::async_runtime::spawn_blocking(move || {
        biometric
            .lock()
            .map_err(|_| "Touch ID 快速解锁暂时不可用。".to_owned())?
            .unlock()
    })
    .await
    .map_err(|_| "Touch ID 解锁任务未能完成。".to_owned())??;
    adapter.complete_biometric_unlock(&state, &ctx, vault_path, vault_key)
}

#[tauri::command]
pub(super) fn agent_unlock_cancel(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
) -> Result<Value, String> {
    require_unlock_window(&window)?;
    desktop_authentication::invalidate_window(
        window.app_handle(),
        &state,
        AGENT_UNLOCK_WINDOW_LABEL,
    );
    if let Ok((adapter, ctx)) = resolve_for_unlock_window(&window, &state) {
        return adapter.cancel(&state, &ctx);
    }
    reject_displayed_unlock(&state);
    Ok(json!({ "cancelled": true }))
}

fn build_agent_unlock_window(app: &AppHandle, visible: bool) -> Option<WebviewWindow> {
    let initial_height =
        crate::window_layout_adapter::WindowChromeFactory::create().initial_compact_height();
    WebviewWindowBuilder::new(
        app,
        AGENT_UNLOCK_WINDOW_LABEL,
        WebviewUrl::App("index.html?surface=agent-unlock".into()),
    )
    .title("VaultMesh 临时解锁")
    .inner_size(
        crate::window_layout_adapter::COMPACT_WINDOW_WIDTH,
        initial_height,
    )
    .min_inner_size(
        crate::window_layout_adapter::COMPACT_WINDOW_MIN_WIDTH,
        crate::window_layout_adapter::COMPACT_WINDOW_MIN_HEIGHT,
    )
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
        if !window.is_focused().unwrap_or(false) {
            let _ = window.set_focus();
        }
        let _ = app.emit_to(AGENT_UNLOCK_WINDOW_LABEL, "agent-unlock-requested", ());
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    let window = app
        .get_webview_window(AGENT_UNLOCK_WINDOW_LABEL)
        .or_else(|| build_agent_unlock_window(app, true));
    let Some(window) = window else { return };
    let was_visible = window.is_visible().unwrap_or(false);
    if !was_visible {
        crate::window_layout_adapter::center_window_on_current_monitor(&window, None);
    }
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
    desktop_authentication::invalidate_window(app, &state, AGENT_UNLOCK_WINDOW_LABEL);
    reject_displayed_unlock(&state);
    let now = unix_millis();
    let has_next = state
        .agent_broker
        .lock()
        .ok()
        .and_then(|mut broker| broker.pending_unlock_request(now))
        .is_some()
        || state
            .browser_unlocks
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

pub(crate) fn reject_displayed_unlock(state: &RuntimeState) {
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
        DisplayedAgentUnlock::BrowserUnlock { unlock_ref, .. } => {
            if let Ok(mut queue) = state.browser_unlocks.lock()
                && let Some(pending) = queue.take(&unlock_ref)
            {
                for (_, sender) in pending.responders {
                    let _ = sender.send(Err(BrowserPlatformError {
                        code: "cancelled",
                        message: "已取消本次解锁。".to_owned(),
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_broker::BrowserUnlockFactor;

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
                "allow-desktop-authentication",
                "allow-desktop-window-layout",
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
        let mut queue = BrowserUnlockQueue::default();
        let (tx_expired, rx_expired) = std::sync::mpsc::sync_channel(1);
        let (tx_first, _rx_first) = std::sync::mpsc::sync_channel(1);
        let (tx_second, rx_second) = std::sync::mpsc::sync_channel(1);

        queue.enqueue(PendingBrowserUnlock {
            unlock_ref: "expired-ref".to_owned(),
            purpose: BrowserUnlockPurpose::MasterPasswordReprompt,
            source: BrowserUnlockSource::Autofill,
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://expired.example".to_owned(),
            item_title: "Expired".to_owned(),
            item_kind: "login".to_owned(),
            master_password_reprompt: false,
            created_at: 1_000,
            expires_at: 31_000,
            responders: vec![(1, tx_expired)],
        });
        queue.enqueue(PendingBrowserUnlock {
            unlock_ref: "second-ref".to_owned(),
            purpose: BrowserUnlockPurpose::MasterPasswordReprompt,
            source: BrowserUnlockSource::Autofill,
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://second.example".to_owned(),
            item_title: "Second".to_owned(),
            item_kind: "card".to_owned(),
            master_password_reprompt: true,
            created_at: 20_000,
            expires_at: 50_000,
            responders: vec![(2, tx_second)],
        });
        queue.enqueue(PendingBrowserUnlock {
            unlock_ref: "first-ref".to_owned(),
            purpose: BrowserUnlockPurpose::Session,
            source: BrowserUnlockSource::Autofill,
            vault_path: PathBuf::from("/tmp/vault.enc"),
            origin: "https://first.example".to_owned(),
            item_title: "First".to_owned(),
            item_kind: "login".to_owned(),
            master_password_reprompt: false,
            created_at: 10_000,
            expires_at: 40_000,
            responders: vec![(3, tx_first)],
        });

        let oldest = queue.peek_oldest(31_000).expect("oldest active request");
        assert_eq!(oldest.unlock_ref, "first-ref");
        assert_eq!(
            rx_expired
                .try_recv()
                .expect("expired response")
                .err()
                .map(|e| e.code),
            Some("cancelled")
        );
        assert!(queue.take("first-ref").is_some());
        assert_eq!(
            queue.peek_oldest(31_000).map(|item| item.unlock_ref),
            Some("second-ref".to_owned())
        );
        queue.clear_all();
        assert_eq!(
            rx_second
                .try_recv()
                .expect("cleared response")
                .err()
                .map(|e| e.code),
            Some("cancelled")
        );
        assert!(queue.peek_oldest(31_000).is_none());
    }

    #[test]
    fn browser_unlock_queue_merges_concurrent_sessions_and_extends_expiry() {
        let mut queue = BrowserUnlockQueue::default();
        let (tx1, rx1) = std::sync::mpsc::sync_channel(1);
        let (tx2, rx2) = std::sync::mpsc::sync_channel(1);
        let (tx_reprompt, _rx_reprompt) = std::sync::mpsc::sync_channel(1);

        let (ref1, id1) = queue.enqueue_session_or_merge(
            BrowserSessionUnlockRequest {
                vault_path: PathBuf::from("/tmp/vault.enc"),
                source: BrowserUnlockSource::Popup,
                origin: None,
                item_title: None,
                item_kind: None,
                master_password_reprompt: false,
            },
            1_000,
            31_000,
            tx1,
        );
        let (ref2, id2) = queue.enqueue_session_or_merge(
            BrowserSessionUnlockRequest {
                vault_path: PathBuf::from("/tmp/vault.enc"),
                source: BrowserUnlockSource::Passkey,
                origin: Some("https://login.example".to_owned()),
                item_title: Some("Passkey · login.example".to_owned()),
                item_kind: Some("secret".to_owned()),
                master_password_reprompt: false,
            },
            15_000,
            45_000,
            tx2,
        );
        assert_eq!(ref1, ref2);
        assert_ne!(id1, id2);
        assert_eq!(queue.entry_expires_at(&ref1), Some(45_000));

        // Reprompt requests never merge into session entries.
        let (reprompt_ref, reprompt_id) = queue.enqueue_reprompt(
            BrowserRepromptRequest {
                vault_path: PathBuf::from("/tmp/vault.enc"),
                origin: "https://pay.example".to_owned(),
                item_title: "Card".to_owned(),
                item_kind: "card".to_owned(),
            },
            16_000,
            46_000,
            tx_reprompt,
        );
        assert_ne!(reprompt_ref, ref1);

        // Timed-out first waiter removes only itself while second waiter stays active.
        assert_eq!(
            queue.remove_responder(&ref1, id1),
            RemoveResponderOutcome::RemainingWaiters
        );
        assert!(rx1.try_recv().is_err());
        assert_eq!(queue.entry_expires_at(&ref1), Some(45_000));

        // Completing merged entry delivers to remaining responder.
        let pending = queue.take(&ref1).expect("merged session still queued");
        let resolution = BrowserUnlockResolution {
            factor: BrowserUnlockFactor::Pin,
            vault_path: PathBuf::from("/tmp/vault.enc"),
            vault_key: Zeroizing::new(vec![7u8; 32]),
            master_password: None,
        };
        for (_, sender) in pending.responders {
            sender.send(Ok(resolution.clone())).expect("deliver");
        }
        assert_eq!(
            rx2.try_recv()
                .expect("second waiter receives")
                .expect("ok resolution")
                .factor,
            BrowserUnlockFactor::Pin
        );

        assert_eq!(
            queue.remove_responder(&reprompt_ref, reprompt_id),
            RemoveResponderOutcome::EntryRemoved
        );
        assert!(queue.entry_expires_at(&reprompt_ref).is_none());
    }
}
