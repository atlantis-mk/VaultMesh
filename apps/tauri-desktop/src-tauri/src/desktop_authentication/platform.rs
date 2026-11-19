use std::fmt::Debug;

use tauri::WebviewWindow;

use super::Bounds;

pub(super) type Reply = Box<dyn Fn(Result<(), String>) + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DesktopAuthOs {
    MacOs,
    Windows,
    Linux,
}

/// Platform code owns OS authentication and its native presentation, never Vault keys.
pub(super) trait AuthenticationAdapter: Send + Sync + Debug {
    #[cfg(test)]
    fn os_kind(&self) -> DesktopAuthOs;
    fn supported(&self) -> bool;
    fn label(&self) -> &'static str;
    fn begin(&self, window: &WebviewWindow, bounds: Bounds, reply: Reply) -> Result<(), String>;
    fn layout(&self, bounds: Bounds);
    fn cancel(&self);
}

#[derive(Debug, Default)]
pub(super) struct MacOsTouchIdAdapter;

impl AuthenticationAdapter for MacOsTouchIdAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> DesktopAuthOs {
        DesktopAuthOs::MacOs
    }

    fn supported(&self) -> bool {
        true
    }

    fn label(&self) -> &'static str {
        "Touch ID"
    }

    fn begin(&self, window: &WebviewWindow, bounds: Bounds, reply: Reply) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            macos_impl::begin(window, bounds, reply)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (window, bounds, reply);
            Err("Touch ID 仅在 macOS 上可用。".to_owned())
        }
    }

    fn layout(&self, bounds: Bounds) {
        #[cfg(target_os = "macos")]
        macos_impl::layout(bounds);
        #[cfg(not(target_os = "macos"))]
        let _ = bounds;
    }

    fn cancel(&self) {
        #[cfg(target_os = "macos")]
        macos_impl::cancel();
    }
}

#[derive(Debug, Default)]
pub(super) struct WindowsHelloAdapter;

impl AuthenticationAdapter for WindowsHelloAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> DesktopAuthOs {
        DesktopAuthOs::Windows
    }

    fn supported(&self) -> bool {
        false
    }

    fn label(&self) -> &'static str {
        "Windows Hello 暂不支持"
    }

    fn begin(&self, _window: &WebviewWindow, _bounds: Bounds, _reply: Reply) -> Result<(), String> {
        Err(self.label().to_owned())
    }

    fn layout(&self, _bounds: Bounds) {}

    fn cancel(&self) {}
}

#[derive(Debug, Default)]
pub(super) struct LinuxUnsupportedAdapter;

impl AuthenticationAdapter for LinuxUnsupportedAdapter {
    #[cfg(test)]
    fn os_kind(&self) -> DesktopAuthOs {
        DesktopAuthOs::Linux
    }

    fn supported(&self) -> bool {
        false
    }

    fn label(&self) -> &'static str {
        "Linux 暂不支持嵌入式生物识别"
    }

    fn begin(&self, _window: &WebviewWindow, _bounds: Bounds, _reply: Reply) -> Result<(), String> {
        Err(self.label().to_owned())
    }

    fn layout(&self, _bounds: Bounds) {}

    fn cancel(&self) {}
}

pub(super) struct DesktopAuthPlatformFactory;

impl DesktopAuthPlatformFactory {
    pub(super) fn current_os() -> DesktopAuthOs {
        if cfg!(target_os = "macos") {
            DesktopAuthOs::MacOs
        } else if cfg!(target_os = "windows") {
            DesktopAuthOs::Windows
        } else {
            DesktopAuthOs::Linux
        }
    }

    pub(super) fn create_for(os: DesktopAuthOs) -> Box<dyn AuthenticationAdapter> {
        match os {
            DesktopAuthOs::MacOs => Box::new(MacOsTouchIdAdapter),
            DesktopAuthOs::Windows => Box::new(WindowsHelloAdapter),
            DesktopAuthOs::Linux => Box::new(LinuxUnsupportedAdapter),
        }
    }

    pub(super) fn create() -> Box<dyn AuthenticationAdapter> {
        Self::create_for(Self::current_os())
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use block2::RcBlock;
    use objc2::{
        class, msg_send,
        rc::Retained,
        runtime::{AnyObject, Bool},
    };
    use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::cell::RefCell;

    // AppKit objects are main-thread-only, never put behind an unsafe Send/Sync.
    thread_local! { static VIEW: RefCell<Option<AuthenticationView>> = const { RefCell::new(None) }; }

    struct AuthenticationView {
        context: Retained<LAContext>,
        view: Retained<AnyObject>,
        parent: Retained<AnyObject>,
    }

    impl Drop for AuthenticationView {
        fn drop(&mut self) {
            unsafe {
                self.context.invalidate();
                let _: () = msg_send![&*self.view, removeFromSuperview];
            }
        }
    }

    fn frame(parent: &AnyObject, b: Bounds) -> NSRect {
        unsafe {
            let flipped: Bool = msg_send![parent, isFlipped];
            let rect: NSRect = msg_send![parent, bounds];
            NSRect::new(
                NSPoint::new(
                    b.x,
                    if flipped.as_bool() {
                        b.y
                    } else {
                        rect.size.height - b.y - b.height
                    },
                ),
                NSSize::new(b.width, b.height),
            )
        }
    }

    pub(super) fn begin(window: &WebviewWindow, bounds: Bounds, reply: Reply) -> Result<(), String> {
        cancel();
        let pointer = window.ns_view().map_err(|_| "无法连接原生认证视图。")?;
        let parent = unsafe { Retained::retain(pointer.cast::<AnyObject>()) }
            .ok_or("无法连接原生认证视图。")?;
        let context = unsafe { LAContext::new() };
        unsafe {
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .map_err(|_| "Touch ID 当前不可用，请使用主密码或 PIN。")?;
            let allocated: *mut AnyObject = msg_send![class!(LAAuthenticationView), alloc];
            let initialized: *mut AnyObject = msg_send![allocated, initWithContext: &*context];
            let view = Retained::from_raw(initialized).ok_or("无法创建原生认证视图。")?;
            let _: () = msg_send![&*view, setFrame: frame(&parent, bounds)];
            // Positioned above WKWebView; only this bounded native icon receives native input.
            let _: () = msg_send![&*parent, addSubview: &*view, positioned: 1_isize, relativeTo: std::ptr::null::<AnyObject>()];
            let block = RcBlock::new(move |success: Bool, error: *mut NSError| {
                let result = if success.as_bool() {
                    Ok(())
                } else {
                    let code = error.as_ref().map(|error| error.code());
                    Err(match code {
                        Some(code) => format!(
                            "Touch ID 验证未完成（系统错误码 {code}），请重试或使用密码。"
                        ),
                        None => "Touch ID 验证未完成，请重试或使用密码。".to_owned(),
                    })
                };
                reply(result)
            });
            VIEW.with(|slot| {
                *slot.borrow_mut() = Some(AuthenticationView {
                    context: context.clone(),
                    view,
                    parent,
                })
            });
            // Apple: attaching LAAuthenticationView before evaluatePolicy selects embedded UI.
            // https://developer.apple.com/documentation/localauthenticationembeddedui/laauthenticationview
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str("解锁保险库"),
                &block,
            );
        }
        Ok(())
    }

    pub(super) fn layout(bounds: Bounds) {
        VIEW.with(|slot| {
            if let Some(current) = slot.borrow().as_ref() {
                unsafe {
                    let _: () =
                        msg_send![&*current.view, setFrame: frame(&current.parent, bounds)];
                }
            }
        });
    }

    pub(super) fn cancel() {
        VIEW.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_desktop_auth_001_factory_covers_all_os_adapters_unconditionally() {
        let mac = DesktopAuthPlatformFactory::create_for(DesktopAuthOs::MacOs);
        assert_eq!(mac.os_kind(), DesktopAuthOs::MacOs);
        assert!(mac.supported());
        assert_eq!(mac.label(), "Touch ID");

        let windows = DesktopAuthPlatformFactory::create_for(DesktopAuthOs::Windows);
        assert_eq!(windows.os_kind(), DesktopAuthOs::Windows);
        assert!(!windows.supported());
        assert_eq!(windows.label(), "Windows Hello 暂不支持");

        let linux = DesktopAuthPlatformFactory::create_for(DesktopAuthOs::Linux);
        assert_eq!(linux.os_kind(), DesktopAuthOs::Linux);
        assert!(!linux.supported());
        assert_eq!(linux.label(), "Linux 暂不支持嵌入式生物识别");

        let current = DesktopAuthPlatformFactory::create();
        assert_eq!(current.os_kind(), DesktopAuthPlatformFactory::current_os());
    }

    #[test]
    fn ct_desktop_auth_001_windows_adapter_is_explicitly_unsupported() {
        let windows = WindowsHelloAdapter;
        assert!(!windows.supported());
        assert_eq!(windows.label(), "Windows Hello 暂不支持");
    }

    #[test]
    fn ct_desktop_auth_001_unsupported_adapters_layout_and_cancel_are_safe_noops() {
        let bounds = Bounds {
            x: 10.0,
            y: 20.0,
            width: 48.0,
            height: 48.0,
        };
        for os in [DesktopAuthOs::Windows, DesktopAuthOs::Linux] {
            let adapter = DesktopAuthPlatformFactory::create_for(os);
            adapter.layout(bounds);
            adapter.cancel();
        }
    }
}
