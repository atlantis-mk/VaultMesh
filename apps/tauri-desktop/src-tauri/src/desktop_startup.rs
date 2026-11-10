use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::write_private_file;

pub const AUTOSTART_ARGUMENT: &str = "--autostart";
const INITIALIZED_MARKER: &str = "desktop-autostart-initialized";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupSettings {
    pub enabled: bool,
    #[serde(default = "default_can_open_system_settings")]
    pub can_open_system_settings: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_settings_hint: Option<String>,
}

fn default_can_open_system_settings() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

pub fn open_system_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
            .spawn()
            .map_err(|e| format!("无法打开 macOS 登录项设置: {e}"))?;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "ms-settings:startupapps"])
            .spawn()
            .map_err(|e| format!("无法打开 Windows 启动应用设置: {e}"))?;
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err("当前平台不支持打开系统设置。".to_owned())
    }
}

pub fn marker_path(app_data: &Path) -> PathBuf {
    app_data.join(INITIALIZED_MARKER)
}

pub fn launched_by_autostart<I, S>(arguments: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    arguments
        .into_iter()
        .any(|argument| argument.as_ref() == AUTOSTART_ARGUMENT)
}

pub fn initialize_default<Q, E>(
    marker: &Path,
    mut is_enabled: Q,
    mut enable: E,
) -> Result<(), String>
where
    Q: FnMut() -> Result<bool, String>,
    E: FnMut() -> Result<(), String>,
{
    if marker.is_file() {
        return Ok(());
    }
    if !is_enabled()? {
        enable()?;
        if !is_enabled()? {
            return Err("系统没有接受登录时启动设置。".to_owned());
        }
    }
    mark_initialized(marker)
}

pub fn update<Q, E, D>(
    marker: &Path,
    requested: bool,
    mut is_enabled: Q,
    mut enable: E,
    mut disable: D,
) -> Result<StartupSettings, String>
where
    Q: FnMut() -> Result<bool, String>,
    E: FnMut() -> Result<(), String>,
    D: FnMut() -> Result<(), String>,
{
    // Record that the user has made an explicit choice before touching the OS
    // registration, so a failed disable is never overwritten by default setup.
    mark_initialized(marker)?;
    let current = is_enabled()?;
    if current != requested {
        if requested {
            enable()?;
        } else {
            disable()?;
        }
    }
    let enabled = is_enabled()?;
    if enabled != requested {
        return Err("系统没有应用登录时启动设置。".to_owned());
    }
    Ok(StartupSettings {
        enabled,
        can_open_system_settings: default_can_open_system_settings(),
        system_settings_hint: None,
    })
}

fn mark_initialized(marker: &Path) -> Result<(), String> {
    write_private_file(marker, b"1", "无法保存登录时启动设置。")
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, ffi::OsString};

    use super::*;

    fn temporary_marker() -> PathBuf {
        std::env::temp_dir()
            .join(format!("vaultmesh-autostart-{}", uuid::Uuid::new_v4()))
            .join(INITIALIZED_MARKER)
    }

    #[test]
    fn detects_only_the_fixed_autostart_argument() {
        assert!(launched_by_autostart([
            OsString::from("VaultMesh"),
            OsString::from(AUTOSTART_ARGUMENT),
        ]));
        assert!(!launched_by_autostart([
            OsString::from("VaultMesh"),
            OsString::from("--autostart=true"),
        ]));
    }

    #[test]
    fn first_run_enables_once_and_an_initialized_install_preserves_user_choice() {
        let marker = temporary_marker();
        let enabled = Cell::new(false);
        let enable_calls = Cell::new(0);

        initialize_default(
            &marker,
            || Ok(enabled.get()),
            || {
                enable_calls.set(enable_calls.get() + 1);
                enabled.set(true);
                Ok(())
            },
        )
        .expect("first-run initialization");
        assert!(marker.is_file());
        assert!(enabled.get());
        assert_eq!(enable_calls.get(), 1);

        enabled.set(false);
        initialize_default(
            &marker,
            || Ok(enabled.get()),
            || {
                enable_calls.set(enable_calls.get() + 1);
                enabled.set(true);
                Ok(())
            },
        )
        .expect("preserve explicit choice");
        assert!(!enabled.get());
        assert_eq!(enable_calls.get(), 1);
        std::fs::remove_dir_all(marker.parent().expect("marker parent")).expect("cleanup");
    }

    #[test]
    fn explicit_update_verifies_the_system_state_and_marks_the_choice() {
        let marker = temporary_marker();
        let enabled = Cell::new(true);
        let result = update(
            &marker,
            false,
            || Ok(enabled.get()),
            || {
                enabled.set(true);
                Ok(())
            },
            || {
                enabled.set(false);
                Ok(())
            },
        )
        .expect("disable autostart");
        assert!(!result.enabled);
        assert!(marker.is_file());
        std::fs::remove_dir_all(marker.parent().expect("marker parent")).expect("cleanup");
    }

    #[test]
    fn repeated_update_is_idempotent() {
        let marker = temporary_marker();
        let enable_calls = Cell::new(0);
        let disable_calls = Cell::new(0);
        let result = update(
            &marker,
            true,
            || Ok(true),
            || {
                enable_calls.set(enable_calls.get() + 1);
                Ok(())
            },
            || {
                disable_calls.set(disable_calls.get() + 1);
                Ok(())
            },
        )
        .expect("keep enabled autostart");
        assert!(result.enabled);
        assert_eq!(enable_calls.get(), 0);
        assert_eq!(disable_calls.get(), 0);
        std::fs::remove_dir_all(marker.parent().expect("marker parent")).expect("cleanup");
    }
}
