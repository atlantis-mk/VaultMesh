use std::fmt;

use tauri::{LogicalSize, State, WebviewWindow};

use crate::{agent_unlock_window::AGENT_UNLOCK_WINDOW_LABEL, RuntimeState};

pub(crate) const COMPACT_WINDOW_WIDTH: f64 = 460.0;
pub(crate) const COMPACT_WINDOW_DEFAULT_HEIGHT: f64 = 440.0;
pub(crate) const COMPACT_WINDOW_MACOS_TITLEBAR_RESERVE: f64 = 32.0;
pub(crate) const COMPACT_WINDOW_MIN_WIDTH: f64 = 420.0;
pub(crate) const COMPACT_WINDOW_MIN_HEIGHT: f64 = 300.0;
pub(crate) const COMPACT_CONTENT_HEIGHT_MIN: f64 = 280.0;
pub(crate) const COMPACT_CONTENT_HEIGHT_MAX: f64 = 760.0;
pub(crate) const COMPACT_CHROME_TOP_INSET_MAX: f64 = 128.0;
pub(crate) const WINDOW_FRAME_DELTA_WIDTH_MAX: f64 = 64.0;
pub(crate) const WINDOW_FRAME_DELTA_HEIGHT_MAX: f64 = 128.0;

pub(crate) const MAIN_WINDOW_DEFAULT_WIDTH: f64 = 1180.0;
pub(crate) const MAIN_WINDOW_DEFAULT_HEIGHT: f64 = 760.0;
pub(crate) const MAIN_WINDOW_MIN_WIDTH: f64 = 780.0;
pub(crate) const MAIN_WINDOW_MIN_HEIGHT: f64 = 560.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowChromeOs {
    MacOs,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkAreaBounds {
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) scale_factor: f64,
}

impl WorkAreaBounds {
    pub(crate) fn from_monitor(monitor: &tauri::Monitor) -> Self {
        let area = monitor.work_area();
        Self {
            x: area.position.x,
            y: area.position.y,
            width: area.size.width,
            height: area.size.height,
            scale_factor: monitor.scale_factor(),
        }
    }

    fn sanitized_scale(self) -> f64 {
        if self.scale_factor.is_finite() && self.scale_factor > 0.0 {
            self.scale_factor
        } else {
            1.0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowFrameDelta {
    pub(crate) width: f64,
    pub(crate) height: f64,
}

impl WindowFrameDelta {
    pub(crate) const fn zero() -> Self {
        Self {
            width: 0.0,
            height: 0.0,
        }
    }

    pub(crate) fn from_outer_and_inner(
        outer: LogicalWindowSize,
        inner: LogicalWindowSize,
    ) -> Self {
        let sanitize_axis = |outer_v: f64, inner_v: f64, max: f64| -> f64 {
            if !outer_v.is_finite() || !inner_v.is_finite() {
                return 0.0;
            }
            let delta = outer_v - inner_v;
            if delta.is_finite() && delta > 0.0 {
                delta.min(max)
            } else {
                0.0
            }
        };
        Self {
            width: sanitize_axis(outer.width, inner.width, WINDOW_FRAME_DELTA_WIDTH_MAX),
            height: sanitize_axis(outer.height, inner.height, WINDOW_FRAME_DELTA_HEIGHT_MAX),
        }
    }

    pub(crate) fn outer_size_for_inner(self, inner: LogicalWindowSize) -> LogicalWindowSize {
        let delta_w = if self.width.is_finite() && self.width > 0.0 {
            self.width.min(WINDOW_FRAME_DELTA_WIDTH_MAX)
        } else {
            0.0
        };
        let delta_h = if self.height.is_finite() && self.height > 0.0 {
            self.height.min(WINDOW_FRAME_DELTA_HEIGHT_MAX)
        } else {
            0.0
        };
        let inner_w = if inner.width.is_finite() && inner.width > 0.0 {
            inner.width
        } else {
            0.0
        };
        let inner_h = if inner.height.is_finite() && inner.height > 0.0 {
            inner.height
        } else {
            0.0
        };
        LogicalWindowSize {
            width: inner_w + delta_w,
            height: inner_h + delta_h,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CenteredWindowPosition {
    Logical { x: f64, y: f64 },
    Physical { x: i32, y: i32 },
}

impl From<CenteredWindowPosition> for tauri::Position {
    fn from(pos: CenteredWindowPosition) -> Self {
        match pos {
            CenteredWindowPosition::Logical { x, y } => {
                tauri::Position::Logical(tauri::LogicalPosition::new(x, y))
            }
            CenteredWindowPosition::Physical { x, y } => {
                tauri::Position::Physical(tauri::PhysicalPosition::new(x, y))
            }
        }
    }
}

pub(crate) fn compute_centered_logical_origin(
    area_origin: f64,
    area_extent: f64,
    window_extent: f64,
) -> f64 {
    let origin = if area_origin.is_finite() {
        area_origin
    } else {
        0.0
    };
    if !area_extent.is_finite() || !window_extent.is_finite() {
        return origin;
    }
    let safe_area = area_extent.max(0.0);
    let safe_window = window_extent.max(0.0);
    origin + ((safe_area - safe_window) / 2.0).max(0.0)
}

fn centered_logical_position(
    work_area: WorkAreaBounds,
    outer_size: LogicalWindowSize,
) -> CenteredWindowPosition {
    let scale = work_area.sanitized_scale();
    let area_x = f64::from(work_area.x) / scale;
    let area_y = f64::from(work_area.y) / scale;
    let area_w = f64::from(work_area.width) / scale;
    let area_h = f64::from(work_area.height) / scale;
    CenteredWindowPosition::Logical {
        x: compute_centered_logical_origin(area_x, area_w, outer_size.width),
        y: compute_centered_logical_origin(area_y, area_h, outer_size.height),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowChromeInsets {
    pub(crate) top_content_inset: f64,
}

impl WindowChromeInsets {
    pub(crate) const fn zero() -> Self {
        Self {
            top_content_inset: 0.0,
        }
    }

    pub(crate) fn sanitized(self) -> Self {
        let top_content_inset =
            if self.top_content_inset.is_finite() && self.top_content_inset > 0.0 {
                self.top_content_inset.min(COMPACT_CHROME_TOP_INSET_MAX)
            } else {
                0.0
            };
        Self { top_content_inset }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn compute_content_chrome_inset(content_height: f64, layout_height: f64) -> f64 {
    if !content_height.is_finite() || !layout_height.is_finite() {
        return 0.0;
    }
    let inset = content_height - layout_height;
    if inset.is_finite() && inset > 0.0 {
        inset.clamp(0.0, COMPACT_CHROME_TOP_INSET_MAX)
    } else {
        0.0
    }
}

pub(crate) trait WindowChromeAdapter: Send + Sync + fmt::Debug {
    #[cfg(test)]
    fn os_kind(&self) -> WindowChromeOs;

    fn content_insets(&self, window: &WebviewWindow) -> WindowChromeInsets;

    fn initial_compact_height(&self) -> f64;

    fn requires_temporary_resizable_for_resize(&self) -> bool;

    fn centered_position(
        &self,
        work_area: WorkAreaBounds,
        outer_size: LogicalWindowSize,
    ) -> CenteredWindowPosition;
}

#[derive(Debug, Default)]
pub(crate) struct MacOsWindowChromeAdapter;

#[derive(Debug, Default)]
pub(crate) struct WindowsWindowChromeAdapter;

#[derive(Debug, Default)]
pub(crate) struct LinuxWindowChromeAdapter;

static MACOS_WINDOW_CHROME_ADAPTER: MacOsWindowChromeAdapter = MacOsWindowChromeAdapter;
static WINDOWS_WINDOW_CHROME_ADAPTER: WindowsWindowChromeAdapter = WindowsWindowChromeAdapter;
static LINUX_WINDOW_CHROME_ADAPTER: LinuxWindowChromeAdapter = LinuxWindowChromeAdapter;

pub(crate) struct WindowChromeFactory;

impl WindowChromeFactory {
    pub(crate) fn current_os() -> WindowChromeOs {
        if cfg!(target_os = "macos") {
            WindowChromeOs::MacOs
        } else if cfg!(target_os = "windows") {
            WindowChromeOs::Windows
        } else {
            WindowChromeOs::Linux
        }
    }

    pub(crate) fn create_for(os: WindowChromeOs) -> &'static dyn WindowChromeAdapter {
        match os {
            WindowChromeOs::MacOs => &MACOS_WINDOW_CHROME_ADAPTER,
            WindowChromeOs::Windows => &WINDOWS_WINDOW_CHROME_ADAPTER,
            WindowChromeOs::Linux => &LINUX_WINDOW_CHROME_ADAPTER,
        }
    }

    pub(crate) fn create() -> &'static dyn WindowChromeAdapter {
        Self::create_for(Self::current_os())
    }
}

#[cfg(target_os = "macos")]
fn read_macos_content_chrome_inset(window: &WebviewWindow) -> f64 {
    let Ok(ns_window_ptr) = window.ns_window() else {
        return 0.0;
    };
    if ns_window_ptr.is_null() {
        return 0.0;
    }
    unsafe {
        let Some(ns_window) =
            objc2::rc::Retained::retain(ns_window_ptr.cast::<objc2::runtime::AnyObject>())
        else {
            return 0.0;
        };
        let frame: objc2_foundation::NSRect = objc2::msg_send![&*ns_window, frame];
        let content_rect: objc2_foundation::NSRect =
            objc2::msg_send![&*ns_window, contentRectForFrameRect: frame];
        let layout_rect: objc2_foundation::NSRect =
            objc2::msg_send![&*ns_window, contentLayoutRect];
        compute_content_chrome_inset(content_rect.size.height, layout_rect.size.height)
    }
}

impl WindowChromeAdapter for MacOsWindowChromeAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> WindowChromeOs {
        WindowChromeOs::MacOs
    }

    fn content_insets(&self, window: &WebviewWindow) -> WindowChromeInsets {
        #[cfg(target_os = "macos")]
        {
            let (tx, rx) = std::sync::mpsc::sync_channel::<f64>(1);
            let main_window = window.clone();
            if window
                .run_on_main_thread(move || {
                    let inset = read_macos_content_chrome_inset(&main_window);
                    let _ = tx.send(inset);
                })
                .is_err()
            {
                return WindowChromeInsets::zero();
            }
            let inset = rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .unwrap_or(0.0);
            WindowChromeInsets {
                top_content_inset: inset,
            }
            .sanitized()
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = window;
            WindowChromeInsets::zero()
        }
    }

    fn initial_compact_height(&self) -> f64 {
        COMPACT_WINDOW_DEFAULT_HEIGHT + COMPACT_WINDOW_MACOS_TITLEBAR_RESERVE
    }

    fn requires_temporary_resizable_for_resize(&self) -> bool {
        false
    }

    fn centered_position(
        &self,
        work_area: WorkAreaBounds,
        outer_size: LogicalWindowSize,
    ) -> CenteredWindowPosition {
        centered_logical_position(work_area, outer_size)
    }
}

impl WindowChromeAdapter for WindowsWindowChromeAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> WindowChromeOs {
        WindowChromeOs::Windows
    }

    fn content_insets(&self, _window: &WebviewWindow) -> WindowChromeInsets {
        WindowChromeInsets::zero()
    }

    fn initial_compact_height(&self) -> f64 {
        COMPACT_WINDOW_DEFAULT_HEIGHT
    }

    fn requires_temporary_resizable_for_resize(&self) -> bool {
        false
    }

    fn centered_position(
        &self,
        work_area: WorkAreaBounds,
        outer_size: LogicalWindowSize,
    ) -> CenteredWindowPosition {
        let scale = work_area.sanitized_scale();
        let safe_w = if outer_size.width.is_finite() && outer_size.width > 0.0 {
            outer_size.width * scale
        } else {
            0.0
        };
        let safe_h = if outer_size.height.is_finite() && outer_size.height > 0.0 {
            outer_size.height * scale
        } else {
            0.0
        };
        let x = compute_centered_logical_origin(
            f64::from(work_area.x),
            f64::from(work_area.width),
            safe_w,
        )
        .round() as i32;
        let y = compute_centered_logical_origin(
            f64::from(work_area.y),
            f64::from(work_area.height),
            safe_h,
        )
        .round() as i32;
        CenteredWindowPosition::Physical { x, y }
    }
}

impl WindowChromeAdapter for LinuxWindowChromeAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> WindowChromeOs {
        WindowChromeOs::Linux
    }

    fn content_insets(&self, _window: &WebviewWindow) -> WindowChromeInsets {
        WindowChromeInsets::zero()
    }

    fn initial_compact_height(&self) -> f64 {
        COMPACT_WINDOW_DEFAULT_HEIGHT
    }

    fn requires_temporary_resizable_for_resize(&self) -> bool {
        true
    }

    fn centered_position(
        &self,
        work_area: WorkAreaBounds,
        outer_size: LogicalWindowSize,
    ) -> CenteredWindowPosition {
        centered_logical_position(work_area, outer_size)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WindowApplyStep {
    SetResizable(bool),
    SetMinSize,
    SetSize,
    SetPosition,
}

pub(crate) fn plan_resize_steps(
    current_resizable: Option<bool>,
    target_resizable: bool,
    requires_temporary_resizable_for_resize: bool,
    recenter: bool,
) -> Vec<WindowApplyStep> {
    let mut steps = if target_resizable {
        let mut steps = Vec::with_capacity(4);
        if current_resizable != Some(true) {
            steps.push(WindowApplyStep::SetResizable(true));
        }
        steps.push(WindowApplyStep::SetMinSize);
        steps.push(WindowApplyStep::SetSize);
        steps
    } else if requires_temporary_resizable_for_resize {
        let mut steps = Vec::with_capacity(5);
        if current_resizable != Some(true) {
            steps.push(WindowApplyStep::SetResizable(true));
        }
        steps.push(WindowApplyStep::SetMinSize);
        steps.push(WindowApplyStep::SetSize);
        steps.push(WindowApplyStep::SetResizable(false));
        steps
    } else {
        let mut steps = Vec::with_capacity(4);
        steps.push(WindowApplyStep::SetMinSize);
        if current_resizable != Some(false) {
            steps.push(WindowApplyStep::SetResizable(false));
        }
        steps.push(WindowApplyStep::SetSize);
        steps
    };
    if recenter {
        steps.push(WindowApplyStep::SetPosition);
    }
    steps
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockWindowKind {
    Main,
    StandaloneAgentUnlock,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct LogicalWindowSize {
    pub(crate) width: f64,
    pub(crate) height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CompactLayoutTarget {
    pub(crate) width: f64,
    pub(crate) height: f64,
    pub(crate) min_width: f64,
    pub(crate) min_height: f64,
    pub(crate) resizable: bool,
    pub(crate) recenter: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MainWindowLayoutState {
    pub(crate) is_compact: bool,
    pub(crate) saved_normal_size: Option<LogicalWindowSize>,
}

impl Default for MainWindowLayoutState {
    fn default() -> Self {
        // `tauri.conf.json` opens `main` in compact mode (`460x472`, `resizable: false`).
        Self {
            is_compact: true,
            saved_normal_size: None,
        }
    }
}

impl MainWindowLayoutState {
    fn capture_normal_size_if_eligible(&mut self, current_logical_size: Option<LogicalWindowSize>) {
        if self.is_compact {
            return;
        }
        if let Some(size) = current_logical_size {
            if size.width.is_finite()
                && size.height.is_finite()
                && size.width >= MAIN_WINDOW_MIN_WIDTH
                && size.height >= MAIN_WINDOW_MIN_HEIGHT
            {
                self.saved_normal_size = Some(size);
            }
        }
    }

    pub(crate) fn transition_to_compact(
        &mut self,
        current_logical_size: Option<LogicalWindowSize>,
        height: f64,
    ) -> LogicalWindowSize {
        self.capture_normal_size_if_eligible(current_logical_size);
        self.is_compact = true;
        LogicalWindowSize {
            width: COMPACT_WINDOW_WIDTH,
            height,
        }
    }

    pub(crate) fn transition_to_normal(&mut self) -> Option<LogicalWindowSize> {
        if !self.is_compact {
            return None;
        }
        self.is_compact = false;
        Some(self.saved_normal_size.unwrap_or(LogicalWindowSize {
            width: MAIN_WINDOW_DEFAULT_WIDTH,
            height: MAIN_WINDOW_DEFAULT_HEIGHT,
        }))
    }

    pub(crate) fn record_closing(&mut self, current_logical_size: Option<LogicalWindowSize>) {
        self.capture_normal_size_if_eligible(current_logical_size);
        // Destroying `main` causes tray reopen to recreate it at `tauri.conf.json` compact bounds.
        self.is_compact = true;
    }
}

pub(crate) fn clamp_compact_height(content_height: Option<f64>) -> Result<f64, String> {
    match content_height {
        None => Ok(COMPACT_WINDOW_DEFAULT_HEIGHT),
        Some(height) if !height.is_finite() => Err("紧凑窗口高度必须是有限数字。".to_owned()),
        Some(height) => Ok(height.clamp(COMPACT_CONTENT_HEIGHT_MIN, COMPACT_CONTENT_HEIGHT_MAX)),
    }
}

pub(crate) trait WindowLayoutAdapter: Send + Sync + fmt::Debug {
    #[cfg(test)]
    fn kind(&self) -> UnlockWindowKind;

    fn compute_target(
        &self,
        layout_state: &mut MainWindowLayoutState,
        current_logical_size: Option<LogicalWindowSize>,
        chrome: WindowChromeInsets,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<Option<CompactLayoutTarget>, String>;

    fn apply_compact_mode(
        &self,
        window: &WebviewWindow,
        state: &RuntimeState,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub(crate) struct MainWindowLayoutAdapter;

#[derive(Debug, Default)]
pub(crate) struct StandaloneUnlockWindowLayoutAdapter;

static MAIN_WINDOW_LAYOUT_ADAPTER: MainWindowLayoutAdapter = MainWindowLayoutAdapter;
static STANDALONE_UNLOCK_WINDOW_LAYOUT_ADAPTER: StandaloneUnlockWindowLayoutAdapter =
    StandaloneUnlockWindowLayoutAdapter;

pub(crate) struct WindowLayoutFactory;

impl WindowLayoutFactory {
    pub(crate) fn create_for(kind: UnlockWindowKind) -> &'static dyn WindowLayoutAdapter {
        match kind {
            UnlockWindowKind::Main => &MAIN_WINDOW_LAYOUT_ADAPTER,
            UnlockWindowKind::StandaloneAgentUnlock => &STANDALONE_UNLOCK_WINDOW_LAYOUT_ADAPTER,
        }
    }

    pub(crate) fn resolve_label(label: &str) -> Result<&'static dyn WindowLayoutAdapter, String> {
        let kind = match label {
            "main" => UnlockWindowKind::Main,
            AGENT_UNLOCK_WINDOW_LABEL => UnlockWindowKind::StandaloneAgentUnlock,
            other => return Err(format!("窗口 {other} 不允许调整紧凑解锁布局。")),
        };
        Ok(Self::create_for(kind))
    }
}

impl WindowLayoutAdapter for MainWindowLayoutAdapter {
    #[cfg(test)]
    fn kind(&self) -> UnlockWindowKind {
        UnlockWindowKind::Main
    }

    fn compute_target(
        &self,
        layout_state: &mut MainWindowLayoutState,
        current_logical_size: Option<LogicalWindowSize>,
        chrome: WindowChromeInsets,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<Option<CompactLayoutTarget>, String> {
        if compact {
            let was_compact = layout_state.is_compact;
            let viewport_height = clamp_compact_height(content_height)?;
            let top_inset = chrome.sanitized().top_content_inset;
            let window_height = viewport_height + top_inset;
            let min_height = viewport_height.min(COMPACT_WINDOW_MIN_HEIGHT) + top_inset;
            let target = layout_state.transition_to_compact(current_logical_size, window_height);
            return Ok(Some(CompactLayoutTarget {
                width: target.width,
                height: target.height,
                min_width: COMPACT_WINDOW_MIN_WIDTH,
                min_height,
                resizable: false,
                recenter: !was_compact,
            }));
        }

        let Some(target) = layout_state.transition_to_normal() else {
            return Ok(None);
        };
        Ok(Some(CompactLayoutTarget {
            width: target.width,
            height: target.height,
            min_width: MAIN_WINDOW_MIN_WIDTH,
            min_height: MAIN_WINDOW_MIN_HEIGHT,
            resizable: true,
            recenter: true,
        }))
    }

    fn apply_compact_mode(
        &self,
        window: &WebviewWindow,
        state: &RuntimeState,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<(), String> {
        let chrome_adapter = WindowChromeFactory::create();
        let chrome = if compact {
            chrome_adapter.content_insets(window)
        } else {
            WindowChromeInsets::zero()
        };
        let current_size = read_logical_window_size(window);
        let target = {
            let mut layout_state = state
                .main_window_layout
                .lock()
                .map_err(|_| "主窗口布局状态暂时不可用。".to_owned())?;
            self.compute_target(
                &mut layout_state,
                current_size,
                chrome,
                compact,
                content_height,
            )?
        };
        let Some(target) = target else {
            return Ok(());
        };
        apply_target_to_window(window, target, chrome_adapter)
    }
}

impl StandaloneUnlockWindowLayoutAdapter {
    pub(crate) fn compute_target_for_visibility(
        &self,
        chrome: WindowChromeInsets,
        compact: bool,
        content_height: Option<f64>,
        is_visible: bool,
    ) -> Result<CompactLayoutTarget, String> {
        if !compact {
            return Err("独立解锁窗口仅支持紧凑模式尺寸。".to_owned());
        }
        let viewport_height = clamp_compact_height(content_height)?;
        let top_inset = chrome.sanitized().top_content_inset;
        let window_height = viewport_height + top_inset;
        let min_height = viewport_height.min(COMPACT_WINDOW_MIN_HEIGHT) + top_inset;
        Ok(CompactLayoutTarget {
            width: COMPACT_WINDOW_WIDTH,
            height: window_height,
            min_width: COMPACT_WINDOW_MIN_WIDTH,
            min_height,
            resizable: false,
            recenter: !is_visible,
        })
    }
}

impl WindowLayoutAdapter for StandaloneUnlockWindowLayoutAdapter {
    #[cfg(test)]
    fn kind(&self) -> UnlockWindowKind {
        UnlockWindowKind::StandaloneAgentUnlock
    }

    fn compute_target(
        &self,
        _layout_state: &mut MainWindowLayoutState,
        _current_logical_size: Option<LogicalWindowSize>,
        chrome: WindowChromeInsets,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<Option<CompactLayoutTarget>, String> {
        self.compute_target_for_visibility(chrome, compact, content_height, true)
            .map(Some)
    }

    fn apply_compact_mode(
        &self,
        window: &WebviewWindow,
        _state: &RuntimeState,
        compact: bool,
        content_height: Option<f64>,
    ) -> Result<(), String> {
        let chrome_adapter = WindowChromeFactory::create();
        let chrome = chrome_adapter.content_insets(window);
        let is_visible = window.is_visible().unwrap_or(true);
        let target =
            self.compute_target_for_visibility(chrome, compact, content_height, is_visible)?;
        apply_target_to_window(window, target, chrome_adapter)
    }
}

fn read_logical_window_size(window: &WebviewWindow) -> Option<LogicalWindowSize> {
    let physical = window.inner_size().ok()?;
    let scale = window.scale_factor().ok().filter(|s| s.is_finite() && *s > 0.0)?;
    Some(LogicalWindowSize {
        width: f64::from(physical.width) / scale,
        height: f64::from(physical.height) / scale,
    })
}

fn read_window_frame_delta(window: &WebviewWindow) -> WindowFrameDelta {
    let (Ok(outer), Ok(inner), Ok(scale)) = (
        window.outer_size(),
        window.inner_size(),
        window.scale_factor(),
    ) else {
        return WindowFrameDelta::zero();
    };
    if !scale.is_finite() || scale <= 0.0 {
        return WindowFrameDelta::zero();
    }
    WindowFrameDelta::from_outer_and_inner(
        LogicalWindowSize {
            width: f64::from(outer.width) / scale,
            height: f64::from(outer.height) / scale,
        },
        LogicalWindowSize {
            width: f64::from(inner.width) / scale,
            height: f64::from(inner.height) / scale,
        },
    )
}

fn compute_centered_position_for_window(
    window: &WebviewWindow,
    chrome_adapter: &dyn WindowChromeAdapter,
    inner_size: LogicalWindowSize,
) -> Option<tauri::Position> {
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten())?;
    let work_area = WorkAreaBounds::from_monitor(&monitor);
    let frame_delta = read_window_frame_delta(window);
    let outer_size = frame_delta.outer_size_for_inner(inner_size);
    Some(tauri::Position::from(
        chrome_adapter.centered_position(work_area, outer_size),
    ))
}

pub(crate) fn center_window_on_current_monitor(
    window: &WebviewWindow,
    inner_size_override: Option<LogicalWindowSize>,
) {
    let Some(inner_size) = inner_size_override.or_else(|| read_logical_window_size(window)) else {
        return;
    };
    let chrome_adapter = WindowChromeFactory::create();
    if let Some(position) = compute_centered_position_for_window(window, chrome_adapter, inner_size)
    {
        let _ = window.set_position(position);
    }
}

fn apply_target_to_window(
    window: &WebviewWindow,
    target: CompactLayoutTarget,
    chrome_adapter: &dyn WindowChromeAdapter,
) -> Result<(), String> {
    let current_resizable = window.is_resizable().ok();
    for step in plan_resize_steps(
        current_resizable,
        target.resizable,
        chrome_adapter.requires_temporary_resizable_for_resize(),
        target.recenter,
    ) {
        match step {
            WindowApplyStep::SetResizable(resizable) => {
                window
                    .set_resizable(resizable)
                    .map_err(|error| format!("更新窗口可调整状态失败：{error}"))?;
            }
            WindowApplyStep::SetMinSize => {
                window
                    .set_min_size(Some(LogicalSize::new(target.min_width, target.min_height)))
                    .map_err(|error| format!("更新窗口最小尺寸失败：{error}"))?;
            }
            WindowApplyStep::SetSize => {
                window
                    .set_size(LogicalSize::new(target.width, target.height))
                    .map_err(|error| format!("调整窗口尺寸失败：{error}"))?;
            }
            WindowApplyStep::SetPosition => {
                let inner_size = LogicalWindowSize {
                    width: target.width,
                    height: target.height,
                };
                if let Some(position) =
                    compute_centered_position_for_window(window, chrome_adapter, inner_size)
                {
                    window
                        .set_position(position)
                        .map_err(|error| format!("居中窗口位置失败：{error}"))?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn record_main_window_closing(window: &WebviewWindow, state: &RuntimeState) {
    let current_size = read_logical_window_size(window);
    if let Ok(mut layout_state) = state.main_window_layout.lock() {
        layout_state.record_closing(current_size);
    }
}

#[tauri::command]
pub(crate) fn desktop_window_set_compact_mode(
    window: WebviewWindow,
    state: State<'_, RuntimeState>,
    compact: bool,
    content_height: Option<f64>,
) -> Result<(), String> {
    let adapter = WindowLayoutFactory::resolve_label(window.label())?;
    adapter.apply_compact_mode(&window, &state, compact, content_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_chrome_factory_covers_all_os_adapters_unconditionally() {
        let mac = WindowChromeFactory::create_for(WindowChromeOs::MacOs);
        assert_eq!(mac.os_kind(), WindowChromeOs::MacOs);
        assert_eq!(mac.initial_compact_height(), 472.0);
        assert!(!mac.requires_temporary_resizable_for_resize());

        let windows = WindowChromeFactory::create_for(WindowChromeOs::Windows);
        assert_eq!(windows.os_kind(), WindowChromeOs::Windows);
        assert_eq!(windows.initial_compact_height(), 440.0);
        assert!(!windows.requires_temporary_resizable_for_resize());

        let linux = WindowChromeFactory::create_for(WindowChromeOs::Linux);
        assert_eq!(linux.os_kind(), WindowChromeOs::Linux);
        assert_eq!(linux.initial_compact_height(), 440.0);
        assert!(linux.requires_temporary_resizable_for_resize());

        assert_eq!(
            WindowChromeFactory::create().os_kind(),
            WindowChromeFactory::current_os()
        );
    }

    #[test]
    fn compute_content_chrome_inset_handles_valid_negative_non_finite_and_clamped_values() {
        assert_eq!(compute_content_chrome_inset(472.0, 440.0), 32.0);
        assert_eq!(compute_content_chrome_inset(468.0, 440.0), 28.0);
        assert_eq!(compute_content_chrome_inset(440.0, 440.0), 0.0);
        assert_eq!(compute_content_chrome_inset(430.0, 440.0), 0.0);
        assert_eq!(compute_content_chrome_inset(f64::NAN, 440.0), 0.0);
        assert_eq!(compute_content_chrome_inset(472.0, f64::INFINITY), 0.0);
        assert_eq!(compute_content_chrome_inset(f64::NEG_INFINITY, 440.0), 0.0);
        assert_eq!(
            compute_content_chrome_inset(700.0, 440.0),
            COMPACT_CHROME_TOP_INSET_MAX
        );

        assert_eq!(WindowChromeInsets::zero().top_content_inset, 0.0);
        assert_eq!(
            WindowChromeInsets {
                top_content_inset: -12.0,
            }
            .sanitized()
            .top_content_inset,
            0.0
        );
        assert_eq!(
            WindowChromeInsets {
                top_content_inset: f64::NAN,
            }
            .sanitized()
            .top_content_inset,
            0.0
        );
        assert_eq!(
            WindowChromeInsets {
                top_content_inset: 240.0,
            }
            .sanitized()
            .top_content_inset,
            COMPACT_CHROME_TOP_INSET_MAX
        );
    }

    #[test]
    fn factory_resolves_only_main_and_agent_unlock_windows() {
        assert_eq!(
            WindowLayoutFactory::create_for(UnlockWindowKind::Main).kind(),
            UnlockWindowKind::Main
        );
        assert_eq!(
            WindowLayoutFactory::create_for(UnlockWindowKind::StandaloneAgentUnlock).kind(),
            UnlockWindowKind::StandaloneAgentUnlock
        );
        assert_eq!(
            WindowLayoutFactory::resolve_label("main")
                .expect("main window should resolve")
                .kind(),
            UnlockWindowKind::Main
        );
        assert_eq!(
            WindowLayoutFactory::resolve_label(AGENT_UNLOCK_WINDOW_LABEL)
                .expect("agent-unlock window should resolve")
                .kind(),
            UnlockWindowKind::StandaloneAgentUnlock
        );
        assert!(WindowLayoutFactory::resolve_label("agent-pairing").is_err());
        assert!(WindowLayoutFactory::resolve_label("agent-authorization").is_err());
    }

    #[test]
    fn clamp_compact_height_validates_finite_and_clamps_bounds() {
        assert_eq!(
            clamp_compact_height(None).expect("default height"),
            COMPACT_WINDOW_DEFAULT_HEIGHT
        );
        assert_eq!(clamp_compact_height(Some(120.0)).expect("min clamp"), 280.0);
        assert_eq!(clamp_compact_height(Some(999.0)).expect("max clamp"), 760.0);
        assert_eq!(clamp_compact_height(Some(412.5)).expect("in-range"), 412.5);
        assert!(clamp_compact_height(Some(f64::NAN)).is_err());
        assert!(clamp_compact_height(Some(f64::INFINITY)).is_err());
        assert!(clamp_compact_height(Some(f64::NEG_INFINITY)).is_err());
    }

    #[test]
    fn main_window_adapter_preserves_normal_size_across_repeated_compact_updates() {
        let adapter = MainWindowLayoutAdapter;
        let mut state = MainWindowLayoutState::default();
        let no_chrome = WindowChromeInsets::zero();

        // First unlock expands to default 1180x760 because no prior normal size existed.
        let unlocked = adapter
            .compute_target(&mut state, None, no_chrome, false, None)
            .expect("expand should succeed")
            .expect("should produce normal target");
        assert_eq!(unlocked.width, MAIN_WINDOW_DEFAULT_WIDTH);
        assert_eq!(unlocked.height, MAIN_WINDOW_DEFAULT_HEIGHT);
        assert_eq!(unlocked.min_width, MAIN_WINDOW_MIN_WIDTH);
        assert_eq!(unlocked.min_height, MAIN_WINDOW_MIN_HEIGHT);
        assert!(unlocked.resizable);

        // User resizes to 1440x900, then locks again -> saved_normal_size captures 1440x900.
        let compact_first = adapter
            .compute_target(
                &mut state,
                Some(LogicalWindowSize {
                    width: 1440.0,
                    height: 900.0,
                }),
                no_chrome,
                true,
                Some(440.0),
            )
            .expect("compact transition")
            .expect("target");
        assert_eq!(compact_first.width, 460.0);
        assert_eq!(compact_first.height, 440.0);
        assert_eq!(compact_first.min_width, 420.0);
        assert_eq!(compact_first.min_height, 300.0);
        assert!(!compact_first.resizable);

        // Switching unlock tab height inside compact mode must NOT overwrite saved_normal_size.
        let compact_second = adapter
            .compute_target(
                &mut state,
                Some(LogicalWindowSize {
                    width: 460.0,
                    height: 440.0,
                }),
                no_chrome,
                true,
                Some(510.0),
            )
            .expect("repeated compact transition")
            .expect("target");
        assert_eq!(compact_second.width, 460.0);
        assert_eq!(compact_second.height, 510.0);

        // Next unlock restores 1440x900 instead of 460x440 or 1180x760.
        let restored = adapter
            .compute_target(&mut state, None, no_chrome, false, None)
            .expect("restore transition")
            .expect("target");
        assert_eq!(restored.width, 1440.0);
        assert_eq!(restored.height, 900.0);
        assert!(restored.resizable);

        // Calling compact=false again while already in normal mode is an idempotent no-op.
        assert_eq!(
            adapter
                .compute_target(&mut state, None, no_chrome, false, None)
                .expect("idempotent normal"),
            None
        );
    }

    #[test]
    fn main_window_adapter_compensates_chrome_inset_in_compact_without_drifting_normal_size() {
        let adapter = MainWindowLayoutAdapter;
        let mut state = MainWindowLayoutState::default();
        let mac_chrome = WindowChromeInsets {
            top_content_inset: 32.0,
        };

        // First unlock restores 1180x760 without adding top_content_inset.
        let first_normal = adapter
            .compute_target(&mut state, None, mac_chrome, false, None)
            .expect("normal expand")
            .expect("target");
        assert_eq!(first_normal.width, MAIN_WINDOW_DEFAULT_WIDTH);
        assert_eq!(first_normal.height, MAIN_WINDOW_DEFAULT_HEIGHT);

        // Compact mode adds 32.0 to both window height and min_height.
        let compact_default = adapter
            .compute_target(
                &mut state,
                Some(LogicalWindowSize {
                    width: 1440.0,
                    height: 900.0,
                }),
                mac_chrome,
                true,
                Some(440.0),
            )
            .expect("compact with mac chrome")
            .expect("target");
        assert_eq!(compact_default.width, 460.0);
        assert_eq!(compact_default.height, 472.0);
        assert_eq!(compact_default.min_width, 420.0);
        assert_eq!(compact_default.min_height, 332.0);
        assert!(!compact_default.resizable);

        // Small viewport height (280.0) keeps min_height <= window height.
        let compact_small = adapter
            .compute_target(&mut state, None, mac_chrome, true, Some(280.0))
            .expect("compact small with mac chrome")
            .expect("target");
        assert_eq!(compact_small.height, 312.0);
        assert_eq!(compact_small.min_height, 312.0);

        // Restoring normal size never adds top_content_inset.
        let restored = adapter
            .compute_target(&mut state, None, mac_chrome, false, None)
            .expect("restore without drift")
            .expect("target");
        assert_eq!(restored.width, 1440.0);
        assert_eq!(restored.height, 900.0);
        assert!(restored.resizable);
    }

    #[test]
    fn standalone_unlock_adapter_accepts_only_compact_and_clamps_height() {
        let adapter = StandaloneUnlockWindowLayoutAdapter;
        let mut state = MainWindowLayoutState::default();

        let target = adapter
            .compute_target(&mut state, None, WindowChromeInsets::zero(), true, Some(480.0))
            .expect("compact on standalone")
            .expect("target");
        assert_eq!(target.width, 460.0);
        assert_eq!(target.height, 480.0);
        assert_eq!(target.min_width, 420.0);
        assert_eq!(target.min_height, 300.0);
        assert!(!target.resizable);

        let mac_target = adapter
            .compute_target(
                &mut state,
                None,
                WindowChromeInsets {
                    top_content_inset: 32.0,
                },
                true,
                Some(480.0),
            )
            .expect("compact on standalone with mac chrome")
            .expect("target");
        assert_eq!(mac_target.width, 460.0);
        assert_eq!(mac_target.height, 512.0);
        assert_eq!(mac_target.min_height, 332.0);
        assert!(!mac_target.resizable);

        assert!(
            adapter
                .compute_target(&mut state, None, WindowChromeInsets::zero(), false, None)
                .is_err()
        );
    }

    #[test]
    fn plan_resize_steps_covers_macos_windows_and_linux_branches() {
        // Normal restore (target_resizable = true)
        for temp_resizable in [false, true] {
            assert_eq!(
                plan_resize_steps(Some(false), true, temp_resizable, false),
                vec![
                    WindowApplyStep::SetResizable(true),
                    WindowApplyStep::SetMinSize,
                    WindowApplyStep::SetSize,
                ]
            );
            assert_eq!(
                plan_resize_steps(None, true, temp_resizable, false),
                vec![
                    WindowApplyStep::SetResizable(true),
                    WindowApplyStep::SetMinSize,
                    WindowApplyStep::SetSize,
                ]
            );
            assert_eq!(
                plan_resize_steps(Some(true), true, temp_resizable, false),
                vec![WindowApplyStep::SetMinSize, WindowApplyStep::SetSize]
            );
        }

        // Compact mode on macOS & Windows (requires_temporary_resizable_for_resize = false)
        assert_eq!(
            plan_resize_steps(Some(true), false, false, false),
            vec![
                WindowApplyStep::SetMinSize,
                WindowApplyStep::SetResizable(false),
                WindowApplyStep::SetSize,
            ]
        );
        assert_eq!(
            plan_resize_steps(None, false, false, false),
            vec![
                WindowApplyStep::SetMinSize,
                WindowApplyStep::SetResizable(false),
                WindowApplyStep::SetSize,
            ]
        );
        assert_eq!(
            plan_resize_steps(Some(false), false, false, false),
            vec![WindowApplyStep::SetMinSize, WindowApplyStep::SetSize]
        );

        // Compact mode on Linux GTK 3 (requires_temporary_resizable_for_resize = true)
        assert_eq!(
            plan_resize_steps(Some(false), false, true, false),
            vec![
                WindowApplyStep::SetResizable(true),
                WindowApplyStep::SetMinSize,
                WindowApplyStep::SetSize,
                WindowApplyStep::SetResizable(false),
            ]
        );
        assert_eq!(
            plan_resize_steps(None, false, true, false),
            vec![
                WindowApplyStep::SetResizable(true),
                WindowApplyStep::SetMinSize,
                WindowApplyStep::SetSize,
                WindowApplyStep::SetResizable(false),
            ]
        );
        assert_eq!(
            plan_resize_steps(Some(true), false, true, false),
            vec![
                WindowApplyStep::SetMinSize,
                WindowApplyStep::SetSize,
                WindowApplyStep::SetResizable(false),
            ]
        );
    }

    #[test]
    fn window_chrome_centered_position_handles_all_os_multi_dpi_frame_delta_and_small_screen_clamping() {
        let delta = WindowFrameDelta::from_outer_and_inner(
            LogicalWindowSize {
                width: 476.0,
                height: 502.0,
            },
            LogicalWindowSize {
                width: 460.0,
                height: 440.0,
            },
        );
        assert_eq!(
            delta,
            WindowFrameDelta {
                width: 16.0,
                height: 62.0,
            }
        );
        assert_eq!(
            WindowFrameDelta::from_outer_and_inner(
                LogicalWindowSize {
                    width: 600.0,
                    height: 800.0,
                },
                LogicalWindowSize {
                    width: 460.0,
                    height: 440.0,
                },
            ),
            WindowFrameDelta {
                width: 64.0,
                height: 128.0,
            }
        );
        assert_eq!(
            WindowFrameDelta::from_outer_and_inner(
                LogicalWindowSize {
                    width: f64::NAN,
                    height: 400.0,
                },
                LogicalWindowSize {
                    width: 460.0,
                    height: 440.0,
                },
            ),
            WindowFrameDelta::zero()
        );

        let outer = delta.outer_size_for_inner(LogicalWindowSize {
            width: 460.0,
            height: 440.0,
        });
        assert_eq!(
            outer,
            LogicalWindowSize {
                width: 476.0,
                height: 502.0,
            }
        );

        let hidpi_area = WorkAreaBounds {
            x: 3840,
            y: 200,
            width: 3840,
            height: 2160,
            scale_factor: 2.0,
        };
        let mac_pos = WindowChromeFactory::create_for(WindowChromeOs::MacOs)
            .centered_position(hidpi_area, outer);
        assert_eq!(
            mac_pos,
            CenteredWindowPosition::Logical {
                x: 1920.0 + (1920.0 - 476.0) / 2.0,
                y: 100.0 + (1080.0 - 502.0) / 2.0,
            }
        );
        assert!(matches!(
            tauri::Position::from(mac_pos),
            tauri::Position::Logical(_)
        ));

        let linux_pos = WindowChromeFactory::create_for(WindowChromeOs::Linux)
            .centered_position(hidpi_area, outer);
        assert_eq!(linux_pos, mac_pos);
        assert!(matches!(
            tauri::Position::from(linux_pos),
            tauri::Position::Logical(_)
        ));

        let windows_pos = WindowChromeFactory::create_for(WindowChromeOs::Windows)
            .centered_position(hidpi_area, outer);
        assert_eq!(
            windows_pos,
            CenteredWindowPosition::Physical {
                x: 3840 + ((3840.0_f64 - 476.0_f64 * 2.0_f64) / 2.0_f64).round() as i32,
                y: 200 + ((2160.0_f64 - 502.0_f64 * 2.0_f64) / 2.0_f64).round() as i32,
            }
        );
        assert!(matches!(
            tauri::Position::from(windows_pos),
            tauri::Position::Physical(_)
        ));

        let small_hidpi_area = WorkAreaBounds {
            x: 200,
            y: 120,
            width: 1600,
            height: 1200,
            scale_factor: 2.0,
        };
        let oversized = LogicalWindowSize {
            width: 1180.0,
            height: 760.0,
        };
        assert_eq!(
            WindowChromeFactory::create_for(WindowChromeOs::MacOs)
                .centered_position(small_hidpi_area, oversized),
            CenteredWindowPosition::Logical { x: 100.0, y: 60.0 }
        );
        assert_eq!(
            WindowChromeFactory::create_for(WindowChromeOs::Linux)
                .centered_position(small_hidpi_area, oversized),
            CenteredWindowPosition::Logical { x: 100.0, y: 60.0 }
        );
        assert_eq!(
            WindowChromeFactory::create_for(WindowChromeOs::Windows)
                .centered_position(small_hidpi_area, oversized),
            CenteredWindowPosition::Physical { x: 200, y: 120 }
        );
    }

    #[test]
    fn main_window_compute_target_sets_recenter_only_on_mode_transitions() {
        let adapter = MainWindowLayoutAdapter;
        let mut state = MainWindowLayoutState::default();
        let chrome = WindowChromeInsets::zero();

        let to_normal = adapter
            .compute_target(&mut state, None, chrome, false, None)
            .expect("compact -> normal")
            .expect("target");
        assert!(to_normal.recenter);

        assert_eq!(
            adapter
                .compute_target(&mut state, None, chrome, false, None)
                .expect("normal -> normal"),
            None
        );

        let to_compact = adapter
            .compute_target(
                &mut state,
                Some(LogicalWindowSize {
                    width: 1280.0,
                    height: 820.0,
                }),
                chrome,
                true,
                Some(440.0),
            )
            .expect("normal -> compact")
            .expect("target");
        assert!(to_compact.recenter);

        let intra_compact = adapter
            .compute_target(
                &mut state,
                Some(LogicalWindowSize {
                    width: 460.0,
                    height: 440.0,
                }),
                chrome,
                true,
                Some(510.0),
            )
            .expect("compact -> compact")
            .expect("target");
        assert!(!intra_compact.recenter);

        let second_normal = adapter
            .compute_target(&mut state, None, chrome, false, None)
            .expect("second compact -> normal")
            .expect("target");
        assert!(second_normal.recenter);
    }

    #[test]
    fn standalone_unlock_adapter_recenters_when_hidden_and_plan_appends_set_position() {
        let adapter = StandaloneUnlockWindowLayoutAdapter;
        let hidden_target = adapter
            .compute_target_for_visibility(WindowChromeInsets::zero(), true, Some(480.0), false)
            .expect("hidden standalone target");
        assert!(hidden_target.recenter);

        let visible_target = adapter
            .compute_target_for_visibility(WindowChromeInsets::zero(), true, Some(480.0), true)
            .expect("visible standalone target");
        assert!(!visible_target.recenter);

        let mut state = MainWindowLayoutState::default();
        let default_target = adapter
            .compute_target(&mut state, None, WindowChromeInsets::zero(), true, Some(480.0))
            .expect("trait compute_target")
            .expect("target");
        assert!(!default_target.recenter);

        for (steps, label) in [
            (plan_resize_steps(Some(false), true, false, true), "normal"),
            (plan_resize_steps(Some(true), false, false, true), "mac/win compact"),
            (plan_resize_steps(Some(false), false, true, true), "linux compact"),
        ] {
            let size_idx = steps
                .iter()
                .position(|step| *step == WindowApplyStep::SetSize)
                .unwrap_or_else(|| panic!("{label} should include SetSize"));
            let pos_idx = steps
                .iter()
                .position(|step| *step == WindowApplyStep::SetPosition)
                .unwrap_or_else(|| panic!("{label} should include SetPosition"));
            assert!(
                pos_idx > size_idx,
                "{label}: SetPosition ({pos_idx}) must appear after SetSize ({size_idx})"
            );
            assert_eq!(steps.last(), Some(&WindowApplyStep::SetPosition));
        }
    }
}
