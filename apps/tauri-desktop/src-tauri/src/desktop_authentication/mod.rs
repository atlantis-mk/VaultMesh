//! Embedded platform authentication shared across `main` and `agent-unlock` windows.
use std::collections::HashMap;

use tauri::WebviewWindow;
use uuid::Uuid;

use super::*;
use crate::{
    agent_unlock_window::AGENT_UNLOCK_WINDOW_LABEL,
    unlock_surface_adapter::{UnlockDomainKind, UnlockSurfaceContext, UnlockSurfaceFactory},
};
use platform::DesktopAuthPlatformFactory;

mod platform;

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Bounds {
    fn valid(self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.x >= 0.0
            && self.y >= 0.0
            && (24.0..=128.0).contains(&self.width)
            && (24.0..=128.0).contains(&self.height)
            && self.x <= 10_000.0
            && self.y <= 10_000.0
    }
}

#[derive(Clone)]
pub(super) struct WindowPage {
    pub(super) window_label: String,
    pub(super) id: String,
    pub(super) bounds: Bounds,
    pub(super) domain: UnlockDomainKind,
    pub(super) vault: PathBuf,
    pub(super) credential_id: String,
    pub(super) unlock_ref: Option<String>,
    pub(super) agent_client_id: Option<Uuid>,
}

#[derive(Default)]
pub(super) struct Coordinator {
    pub(super) pages: HashMap<String, WindowPage>,
    pub(super) active_window: Option<String>,
    pub(super) generation: u64,
    pub(super) listening: bool,
}

impl Coordinator {
    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.listening = false;
    }

    fn register(&mut self, page: WindowPage) -> Option<(String, String)> {
        if self.active_window.as_deref() == Some(page.window_label.as_str())
            && self.pages.get(&page.window_label).is_some_and(|current| {
                current.id == page.id
                    && current.domain == page.domain
                    && current.vault == page.vault
                    && current.credential_id == page.credential_id
                    && current.unlock_ref == page.unlock_ref
                    && current.agent_client_id == page.agent_client_id
            })
        {
            return None;
        }
        let preempted = self
            .active_window
            .as_deref()
            .filter(|active| *active != page.window_label && self.listening)
            .and_then(|active| self.pages.get(active))
            .map(|prev| (prev.window_label.clone(), prev.id.clone()));
        self.invalidate();
        self.active_window = Some(page.window_label.clone());
        self.pages.insert(page.window_label.clone(), page);
        preempted
    }

    fn accepts(&self, window_label: &str, generation: u64) -> Option<WindowPage> {
        if !self.listening || self.generation != generation {
            return None;
        }
        if self.active_window.as_deref() != Some(window_label) {
            return None;
        }
        self.pages.get(window_label).cloned()
    }
}

fn allowed_unlock_window_label(label: &str) -> Option<&'static str> {
    match label {
        "main" => Some("main"),
        AGENT_UNLOCK_WINDOW_LABEL => Some(AGENT_UNLOCK_WINDOW_LABEL),
        _ => None,
    }
}

fn require_unlock_window(window: &WebviewWindow) -> Result<&'static str, String> {
    allowed_unlock_window_label(window.label())
        .ok_or_else(|| "此认证只允许解锁窗口使用。".to_owned())
}

fn emit(window: &WebviewWindow, id: &str, status: &str) {
    emit_with_message(window, id, status, None);
}

fn emit_with_message(window: &WebviewWindow, id: &str, status: &str, message: Option<&str>) {
    let _ = window.emit(
        "desktop-authentication",
        json!({"sessionId": id, "status": status, "message": message}),
    );
}

#[tauri::command]
pub(super) fn desktop_authentication_status(window: WebviewWindow) -> Result<Value, String> {
    require_unlock_window(&window)?;
    let platform = DesktopAuthPlatformFactory::create();
    Ok(json!({ "supported": platform.supported(), "label": platform.label() }))
}

#[tauri::command]
pub(super) fn desktop_authentication_begin(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    session_id: String,
    bounds: Bounds,
) -> Result<(), String> {
    let window_label = require_unlock_window(&window)?;
    if Uuid::parse_str(&session_id).is_err() || !bounds.valid() {
        return Err("认证参数无效。".into());
    }
    let platform = DesktopAuthPlatformFactory::create();
    if !platform.supported() {
        return Err(platform.label().into());
    }
    let (adapter, ctx) = UnlockSurfaceFactory::resolve_for_window(window_label, &state)?;
    if adapter.window_label() != window_label {
        return Err("此认证只允许对应的解锁窗口使用。".into());
    }
    if !adapter.allows_quick_unlock() {
        return Err("此条目受主密码保护，请使用主密码确认填充。".into());
    }
    let (vault, credential_id) = adapter.biometric_binding(&state, &ctx)?;
    let preempted = {
        let mut coordinator = state
            .desktop_authentication
            .lock()
            .map_err(|_| "认证暂时不可用。")?;
        coordinator.register(WindowPage {
            window_label: window_label.to_owned(),
            id: session_id,
            bounds,
            domain: adapter.kind(),
            vault,
            credential_id,
            unlock_ref: ctx.unlock_ref,
            agent_client_id: ctx.agent_client_id,
        })
    };
    if let Some((prev_label, prev_session)) = preempted {
        if let Some(prev_window) = window.app_handle().get_webview_window(&prev_label) {
            emit(&prev_window, &prev_session, "paused");
        }
        let app = window.app_handle().clone();
        let _ = window.run_on_main_thread(move || {
            if let Some(state) = app.try_state::<RuntimeState>()
                && let Ok(coordinator) = state.desktop_authentication.lock()
                && !coordinator.listening
            {
                DesktopAuthPlatformFactory::create().cancel();
            }
        });
    }
    resume(&window);
    Ok(())
}

#[tauri::command]
pub(super) fn desktop_authentication_layout(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    session_id: String,
    bounds: Bounds,
) -> Result<(), String> {
    let window_label = require_unlock_window(&window)?;
    if !bounds.valid() {
        return Err("认证布局无效。".into());
    }
    {
        let mut coordinator = state
            .desktop_authentication
            .lock()
            .map_err(|_| "认证暂时不可用。")?;
        if let Some(page) = coordinator
            .pages
            .get_mut(window_label)
            .filter(|p| p.id == session_id)
        {
            page.bounds = bounds;
        } else {
            return Ok(());
        }
    }
    let app = window.app_handle().clone();
    let label_owned = window_label.to_owned();
    window
        .run_on_main_thread(move || {
            if let Some(state) = app.try_state::<RuntimeState>() {
                let Ok(coordinator) = state.desktop_authentication.lock() else {
                    return;
                };
                if coordinator.listening
                    && coordinator.active_window.as_deref() == Some(label_owned.as_str())
                    && coordinator
                        .pages
                        .get(&label_owned)
                        .is_some_and(|p| p.id == session_id)
                {
                    DesktopAuthPlatformFactory::create().layout(bounds);
                }
            }
        })
        .map_err(|_| "无法更新认证布局。".into())
}

#[tauri::command]
pub(super) fn desktop_authentication_cancel(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    session_id: String,
) -> Result<(), String> {
    require_unlock_window(&window)?;
    cancel(&window, &state, Some(&session_id), true);
    Ok(())
}

fn cancel(window: &WebviewWindow, state: &RuntimeState, id: Option<&str>, remove: bool) {
    let window_label = window.label();
    let mut paused_session: Option<String> = None;
    let mut should_cancel_platform = false;

    if let Ok(mut coordinator) = state.desktop_authentication.lock() {
        let Some(page_id) = coordinator.pages.get(window_label).map(|p| p.id.clone()) else {
            return;
        };
        if id.is_some_and(|expected| page_id != expected) {
            return;
        }
        let is_active = coordinator.active_window.as_deref() == Some(window_label);
        if is_active && coordinator.listening {
            coordinator.invalidate();
            paused_session = Some(page_id);
            should_cancel_platform = true;
        } else if !remove {
            // Do not cancel or pause another window's active Touch ID view when an inactive
            // window delivers a delayed Focus(false) event.
            return;
        }
        if remove {
            coordinator.pages.remove(window_label);
            if is_active {
                coordinator.active_window = None;
            }
        }
    }

    if let Some(session_id) = paused_session {
        emit(window, &session_id, "paused");
    }
    if !should_cancel_platform {
        return;
    }
    // Preserve ordering with a following begin. A queued old cancel must not remove a new view.
    let app = window.app_handle().clone();
    let _ = window.run_on_main_thread(move || {
        if let Some(state) = app.try_state::<RuntimeState>() {
            if let Ok(coordinator) = state.desktop_authentication.lock() {
                if !coordinator.listening {
                    DesktopAuthPlatformFactory::create().cancel();
                }
            }
        }
    });
}

pub(super) fn invalidate_window(app: &AppHandle, state: &RuntimeState, window_label: &str) {
    if let Some(window) = app.get_webview_window(window_label) {
        cancel(&window, state, None, true);
        return;
    }
    let mut should_cancel_platform = false;
    if let Ok(mut coordinator) = state.desktop_authentication.lock() {
        coordinator.pages.remove(window_label);
        if coordinator.active_window.as_deref() == Some(window_label) {
            coordinator.active_window = None;
            if coordinator.listening {
                coordinator.invalidate();
                should_cancel_platform = true;
            }
        }
    }
    if should_cancel_platform {
        let app_handle = app.clone();
        let _ = app.run_on_main_thread(move || {
            if let Some(state) = app_handle.try_state::<RuntimeState>()
                && let Ok(coordinator) = state.desktop_authentication.lock()
                && !coordinator.listening
            {
                DesktopAuthPlatformFactory::create().cancel();
            }
        });
    }
}

pub(super) fn invalidate(app: &AppHandle, state: &RuntimeState) {
    invalidate_window(app, state, "main");
}

pub(super) fn suspend(app: &AppHandle, state: &RuntimeState) {
    for label in ["main", AGENT_UNLOCK_WINDOW_LABEL] {
        if let Some(window) = app.get_webview_window(label) {
            cancel(&window, state, None, false);
        }
    }
}

pub(super) fn window_event(window: &tauri::Window, event: &WindowEvent) {
    let Some(label) = allowed_unlock_window_label(window.label()) else {
        return;
    };
    let app = window.app_handle();
    let Some(webview) = app.get_webview_window(label) else {
        return;
    };
    let Some(state) = app.try_state::<RuntimeState>() else {
        return;
    };
    match event {
        WindowEvent::Focused(true) => {
            resume(&webview);
        }
        WindowEvent::Focused(false) => cancel(&webview, &state, None, false),
        WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed => {
            cancel(&webview, &state, None, true)
        }
        _ => {}
    }
}

fn resume(window: &WebviewWindow) {
    let window = window.clone();
    let dispatcher = window.clone();
    let _ = dispatcher.run_on_main_thread(move || {
        let Some(state) = window.app_handle().try_state::<RuntimeState>() else {
            return;
        };
        if !window.is_focused().unwrap_or(false) || !window.is_visible().unwrap_or(false) {
            return;
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        if app_setup::system_session_locked() {
            return;
        }
        let window_label = window.label().to_owned();
        let (page, generation, preempted) = {
            let Ok(mut coordinator) = state.desktop_authentication.lock() else {
                return;
            };
            if coordinator.listening && coordinator.active_window.as_deref() == Some(&window_label) {
                return;
            }
            let Some(page) = coordinator.pages.get(&window_label).cloned() else {
                return;
            };
            let preempted = coordinator
                .active_window
                .as_deref()
                .filter(|active| *active != window_label && coordinator.listening)
                .and_then(|active| coordinator.pages.get(active))
                .map(|prev| (prev.window_label.clone(), prev.id.clone()));
            coordinator.invalidate();
            coordinator.active_window = Some(window_label);
            coordinator.listening = true;
            (page, coordinator.generation, preempted)
        };
        if let Some((prev_label, prev_session)) = preempted {
            if let Some(prev_window) = window.app_handle().get_webview_window(&prev_label) {
                emit(&prev_window, &prev_session, "paused");
            }
            DesktopAuthPlatformFactory::create().cancel();
        }
        emit(&window, &page.id, "listening");
        let completed_window = window.clone();
        let reply =
            Box::new(move |outcome| complete(completed_window.clone(), generation, outcome));
        if let Err(error) = DesktopAuthPlatformFactory::create().begin(&window, page.bounds, reply)
        {
            complete(window, generation, Err(error));
        }
    });
}

fn complete(window: WebviewWindow, generation: u64, outcome: Result<(), String>) {
    tauri::async_runtime::spawn_blocking(move || {
        let Some(state) = window.app_handle().try_state::<RuntimeState>() else {
            return;
        };
        let window_label = window.label().to_owned();
        let page = {
            let Ok(coordinator) = state.desktop_authentication.lock() else {
                return;
            };
            let Some(page) = coordinator.accepts(&window_label, generation) else {
                return;
            };
            page
        };
        if outcome.is_ok() {
            emit(&window, &page.id, "opening");
        }
        let adapter = UnlockSurfaceFactory::create_for(page.domain);
        let ctx = UnlockSurfaceContext {
            vault_path: page.vault.clone(),
            unlock_ref: page.unlock_ref.clone(),
            agent_client_id: page.agent_client_id,
        };
        // No coordinator/credential guard is held while OS authentication waits.
        // Keychain access also stays outside the coordinator: cancellation may win
        // while credentials are being read, in which case the local key is zeroized.
        let credential = (|| -> Result<_, String> {
            outcome?;
            let service = adapter
                .biometric_service(&state)
                .ok_or_else(|| "当前解锁请求不支持 Touch ID。".to_owned())?;
            let binding = adapter.biometric_binding(&state, &ctx)?;
            if binding != (page.vault.clone(), page.credential_id.clone()) {
                return Err("Touch ID 凭据已变化。".into());
            }
            let guard = service.lock().map_err(|_| "认证暂时不可用。".to_owned())?;
            guard.credential_after_authentication()
        })();
        // Query AppKit before taking the coordinator; main-thread focus events
        // must remain able to invalidate the generation.
        let foreground =
            window.is_focused().unwrap_or(false) && window.is_visible().unwrap_or(false);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let foreground = foreground && !app_setup::system_session_locked();

        {
            let Ok(mut coordinator) = state.desktop_authentication.lock() else {
                return;
            };
            if coordinator.accepts(&window_label, generation).is_none() {
                return;
            }
            coordinator.invalidate();
        }

        let result = (|| -> Result<(), String> {
            if !foreground {
                return Err("认证完成时窗口已失去激活状态，请重新激活后重试。".into());
            }
            let (path, key) = credential?;
            adapter
                .complete_biometric_unlock(&state, &ctx, path, key)
                .map(|_| ())
        })();

        if result.is_ok()
            && let Ok(mut coordinator) = state.desktop_authentication.lock()
        {
            if coordinator
                .pages
                .get(&window_label)
                .is_some_and(|current| current.id == page.id)
            {
                coordinator.pages.remove(&window_label);
            }
            if coordinator.active_window.as_deref() == Some(window_label.as_str()) {
                coordinator.active_window = None;
            }
        }
        emit_with_message(
            &window,
            &page.id,
            if result.is_ok() { "unlocked" } else { "failed" },
            result.as_ref().err().map(String::as_str),
        );

        // Destroy the completed context, but never a newer attempt's context.
        let app = window.app_handle().clone();
        let _ = window.run_on_main_thread(move || {
            if let Some(state) = app.try_state::<RuntimeState>() {
                if let Ok(coordinator) = state.desktop_authentication.lock() {
                    if !coordinator.listening {
                        DesktopAuthPlatformFactory::create().cancel();
                    }
                }
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bounds() -> Bounds {
        Bounds {
            x: 0.,
            y: 0.,
            width: 64.,
            height: 64.,
        }
    }

    fn test_page(window_label: &str, domain: UnlockDomainKind) -> WindowPage {
        WindowPage {
            window_label: window_label.to_owned(),
            id: Uuid::new_v4().to_string(),
            bounds: test_bounds(),
            domain,
            vault: PathBuf::from("/test"),
            credential_id: "test-credential".into(),
            unlock_ref: None,
            agent_client_id: None,
        }
    }

    #[test]
    fn ct_desktop_auth_001_cancel_and_replacement_reject_late_callbacks() {
        let mut c = Coordinator::default();
        c.register(test_page("main", UnlockDomainKind::DesktopMain));
        c.listening = true;
        let original = c.generation;
        assert!(c.accepts("main", original).is_some());
        c.invalidate();
        assert!(c.accepts("main", original).is_none());
        c.listening = true;
        assert!(c.accepts("main", c.generation).is_some());
        assert!(c.accepts("main", original).is_none());
        c.pages.remove("main");
        assert!(c.accepts("main", c.generation).is_none());
    }

    #[test]
    fn ct_desktop_auth_001_duplicate_registration_preserves_current_attempt() {
        let mut c = Coordinator::default();
        let page = test_page("main", UnlockDomainKind::DesktopMain);
        assert!(c.register(page.clone()).is_none());
        c.listening = true;
        let generation = c.generation;
        assert!(c.register(page.clone()).is_none());
        assert!(c.accepts("main", generation).is_some());
        c.register(WindowPage {
            credential_id: "replacement-credential".into(),
            ..page.clone()
        });
        assert!(c.accepts("main", generation).is_none());
        c.listening = true;
        let generation = c.generation;
        c.register(WindowPage {
            id: Uuid::new_v4().to_string(),
            ..page
        });
        assert!(c.accepts("main", generation).is_none());
    }

    #[test]
    fn ct_desktop_auth_001_native_commands_are_not_granted_to_agent_windows() {
        let main = include_str!("../../capabilities/main.json");
        assert!(main.contains("allow-desktop-authentication"));
        assert!(main.contains("allow-desktop-window-layout"));

        let unlock = include_str!("../../capabilities/agent-unlock.json");
        assert!(unlock.contains("allow-desktop-authentication"));
        assert!(unlock.contains("allow-desktop-window-layout"));

        for isolated in [
            include_str!("../../capabilities/agent-pairing.json"),
            include_str!("../../capabilities/agent-authorization.json"),
        ] {
            assert!(!isolated.contains("allow-desktop-authentication"));
            assert!(!isolated.contains("allow-desktop-window-layout"));
        }
    }

    #[test]
    fn ct_desktop_auth_001_bounds_reject_non_finite_and_unbounded_native_views() {
        let b = Bounds {
            x: 1.,
            y: 2.,
            width: 64.,
            height: 64.,
        };
        assert!(b.valid());
        assert!(!Bounds { x: f64::NAN, ..b }.valid());
        assert!(!Bounds { width: 5000., ..b }.valid());
        assert!(!Bounds { y: -1., ..b }.valid());
    }

    #[test]
    fn multi_window_preemption_invalidates_prior_window_and_rejects_unlisted_windows() {
        assert_eq!(allowed_unlock_window_label("main"), Some("main"));
        assert_eq!(
            allowed_unlock_window_label(AGENT_UNLOCK_WINDOW_LABEL),
            Some(AGENT_UNLOCK_WINDOW_LABEL)
        );
        assert_eq!(allowed_unlock_window_label("agent-pairing"), None);
        assert_eq!(allowed_unlock_window_label("agent-authorization"), None);

        let mut c = Coordinator::default();
        let main_page = test_page("main", UnlockDomainKind::DesktopMain);
        let main_id = main_page.id.clone();
        assert!(c.register(main_page).is_none());
        c.listening = true;
        let main_gen = c.generation;

        // Preempting `main` with `agent-unlock` must pause `main`, invalidate old generation, and switch active_window.
        let agent_page = test_page(AGENT_UNLOCK_WINDOW_LABEL, UnlockDomainKind::BrowserSession);
        let preempted = c.register(agent_page);
        assert_eq!(preempted, Some(("main".to_owned(), main_id)));
        assert_eq!(
            c.active_window.as_deref(),
            Some(AGENT_UNLOCK_WINDOW_LABEL)
        );
        assert!(c.accepts("main", main_gen).is_none());

        c.listening = true;
        let agent_gen = c.generation;
        assert!(c.accepts(AGENT_UNLOCK_WINDOW_LABEL, agent_gen).is_some());
        assert!(c.accepts("main", agent_gen).is_none());
    }
}
