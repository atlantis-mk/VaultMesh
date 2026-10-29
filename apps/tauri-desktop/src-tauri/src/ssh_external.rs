use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use url::Host;
use uuid::Uuid;

const LAUNCH_DIRECTORY_NAME: &str = "ssh-launch";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ExternalClientId {
    SystemTerminal,
    Vscode,
    CopyCommand,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchInput {
    pub account_id: String,
    pub client_id: ExternalClientId,
    #[serde(default)]
    pub copy_password: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchTarget {
    host: String,
    port: u16,
    username: String,
}

impl LaunchTarget {
    pub fn new(host: &str, port: u16, username: &str) -> Result<Self, String> {
        let host = host.trim();
        let username = username.trim();
        if port == 0
            || host.is_empty()
            || host.len() > 253
            || username.is_empty()
            || username.len() > 255
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err("SSH 账号的主机、端口或用户名无效。".to_owned());
        }
        let host = Host::parse(host)
            .map_err(|_| "SSH 账号的主机、端口或用户名无效。".to_owned())?
            .to_string();
        Ok(Self {
            host,
            port,
            username: username.to_owned(),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    fn destination(&self) -> String {
        format!("{}@{}", self.username, self.host)
    }

    pub fn display_command(&self) -> String {
        format!(
            "ssh -p {} -- {}",
            self.port,
            shell_quote(&self.destination())
        )
    }

    fn vscode_uri(&self) -> String {
        format!("vscode://vscode-remote/ssh-remote+{}/", self.destination())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalClient {
    id: &'static str,
    label: &'static str,
    available: bool,
}

pub fn clients() -> Vec<ExternalClient> {
    vec![
        ExternalClient {
            id: "systemTerminal",
            label: "系统终端",
            available: system_terminal_available(),
        },
        ExternalClient {
            id: "vscode",
            label: "VS Code",
            available: vscode_available(),
        },
        ExternalClient {
            id: "copyCommand",
            label: "复制 SSH 命令",
            available: true,
        },
    ]
}

pub fn launch_root(app_data: &Path) -> PathBuf {
    app_data.join(LAUNCH_DIRECTORY_NAME)
}

pub fn clear_launches(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

pub fn launch(
    client: ExternalClientId,
    target: &LaunchTarget,
    root: &Path,
    socket_path: Option<&str>,
) -> Result<(), String> {
    match client {
        ExternalClientId::CopyCommand => Ok(()),
        ExternalClientId::Vscode => {
            if !vscode_available() {
                return Err("未找到 VS Code。".to_owned());
            }
            open::that_detached(target.vscode_uri())
                .map_err(|_| "无法通过 VS Code 打开 SSH 目标。".to_owned())
        }
        ExternalClientId::SystemTerminal => launch_system_terminal(target, root, socket_path),
    }
}

#[cfg(target_os = "macos")]
fn launch_system_terminal(
    target: &LaunchTarget,
    root: &Path,
    socket_path: Option<&str>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let launch_directory = prepare_launch_directory(root)?;
    let launcher_path = launch_directory.join("connect.command");
    let mut script = String::from("#!/bin/sh\n");
    if let Some(socket_path) = socket_path {
        script.push_str(&format!("export SSH_AUTH_SOCK={}\n", shell_quote(socket_path)));
    }
    script.push_str(&format!(
        "/usr/bin/ssh -p {} -- {}\nstatus=$?\n/bin/rm -rf -- {}\nexit \"$status\"\n",
        target.port,
        shell_quote(&target.destination()),
        shell_quote(&launch_directory.to_string_lossy()),
    ));
    std::fs::write(&launcher_path, script)
        .map_err(|_| cleanup_error(&launch_directory, "无法准备 SSH 终端启动器。"))?;
    std::fs::set_permissions(&launcher_path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| cleanup_error(&launch_directory, "无法保护 SSH 终端启动器。"))?;
    let status = Command::new("/usr/bin/open")
        .args(["-a", "Terminal"])
        .arg(&launcher_path)
        .status()
        .map_err(|_| cleanup_error(&launch_directory, "无法打开系统终端。"))?;
    if !status.success() {
        clear_launches(&launch_directory);
        return Err("无法打开系统终端。".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn launch_system_terminal(
    target: &LaunchTarget,
    root: &Path,
    socket_path: Option<&str>,
) -> Result<(), String> {
    let launch_directory = prepare_launch_directory(root)?;
    let launcher_path = launch_directory.join("connect.cmd");
    let mut script = String::from("@echo off\r\n");
    if let Some(socket_path) = socket_path {
        script.push_str(&format!("set \"SSH_AUTH_SOCK={}\"\r\n", socket_path));
    }
    script.push_str(&format!(
        "ssh -p {} -- {}\r\nset \"VAULTMESH_SSH_STATUS=%ERRORLEVEL%\"\r\nexit /b %VAULTMESH_SSH_STATUS%\r\n",
        target.port,
        windows_quote(&target.destination()),
    ));
    std::fs::write(&launcher_path, script)
        .map_err(|_| cleanup_error(&launch_directory, "无法准备 SSH 终端启动器。"))?;
    Command::new("cmd.exe")
        .args(["/K"])
        .arg(&launcher_path)
        .spawn()
        .map(|_| ())
        .map_err(|_| cleanup_error(&launch_directory, "无法打开系统终端。"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launch_system_terminal(
    _target: &LaunchTarget,
    _root: &Path,
    _socket_path: Option<&str>,
) -> Result<(), String> {
    Err("当前平台不支持打开系统终端。".to_owned())
}

fn prepare_launch_directory(root: &Path) -> Result<PathBuf, String> {
    let directory = root.join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&directory).map_err(|_| "无法准备 SSH 临时会话。".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| cleanup_error(&directory, "无法保护 SSH 临时会话。"))?;
    }
    Ok(directory)
}

fn cleanup_error(directory: &Path, message: &str) -> String {
    clear_launches(directory);
    message.to_owned()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "windows")]
fn windows_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(target_os = "macos")]
fn system_terminal_available() -> bool {
    Path::new("/usr/bin/open").is_file()
        && (Path::new("/System/Applications/Utilities/Terminal.app").is_dir()
            || Path::new("/Applications/Utilities/Terminal.app").is_dir())
}

#[cfg(target_os = "windows")]
fn system_terminal_available() -> bool {
    executable_on_path("cmd.exe")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn system_terminal_available() -> bool {
    false
}

fn vscode_available() -> bool {
    if executable_on_path(if cfg!(target_os = "windows") {
        "code.cmd"
    } else {
        "code"
    }) {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new("/Applications/Visual Studio Code.app").is_dir() {
            return true;
        }
        if let Some(home) = std::env::var_os("HOME")
            && Path::new(&home)
                .join("Applications/Visual Studio Code.app")
                .is_dir()
        {
            return true;
        }
    }
    #[cfg(target_os = "windows")]
    {
        for variable in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(root) = std::env::var_os(variable) {
                let candidate = if variable == "LOCALAPPDATA" {
                    Path::new(&root)
                        .join("Programs")
                        .join("Microsoft VS Code")
                        .join("Code.exe")
                } else {
                    Path::new(&root).join("Microsoft VS Code").join("Code.exe")
                };
                if candidate.is_file() {
                    return true;
                }
            }
        }
    }
    false
}

fn executable_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(name).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_target_builds_a_fixed_command_and_rejects_shell_input() {
        let target = LaunchTarget::new("10.0.0.2", 2222, "deploy-user").expect("target");
        assert_eq!(
            target.display_command(),
            "ssh -p 2222 -- 'deploy-user@10.0.0.2'"
        );
        assert_eq!(
            target.vscode_uri(),
            "vscode://vscode-remote/ssh-remote+deploy-user@10.0.0.2/"
        );
        assert!(LaunchTarget::new("example.com;touch /tmp/pwned", 22, "user").is_err());
        assert!(LaunchTarget::new("example.com", 22, "user;whoami").is_err());
        assert!(LaunchTarget::new("example.com", 0, "user").is_err());
    }

    #[test]
    fn external_client_list_is_fixed_and_copy_is_always_available() {
        let clients = serde_json::to_value(clients()).expect("clients");
        assert_eq!(clients.as_array().map(Vec::len), Some(3));
        assert_eq!(clients[2]["id"], "copyCommand");
        assert_eq!(clients[2]["available"], true);
    }

    #[test]
    fn launch_directory_is_owner_only_and_cleanup_is_bounded() {
        let root = std::env::temp_dir().join(format!("vaultmesh-ssh-external-{}", Uuid::new_v4()));
        let directory = prepare_launch_directory(&root).expect("directory");
        assert!(directory.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        clear_launches(&root);
        assert!(!root.exists());
    }
}
