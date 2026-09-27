use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssh2::{OpenFlags, OpenType, RenameFlags, Session};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_RESOLVED_ADDRESSES: usize = 8;
const MAX_AGENT_TRANSFER_BYTES: usize = 32 * 1024 * 1024;

const INSTALL_PUBLIC_KEY_COMMAND: &str = r#"umask 077 &&
mkdir -p "$HOME/.ssh" &&
touch "$HOME/.ssh/authorized_keys" &&
chmod 700 "$HOME/.ssh" &&
chmod 600 "$HOME/.ssh/authorized_keys" &&
key=$(cat) &&
if grep -qxF "$key" "$HOME/.ssh/authorized_keys"; then
  exit 20
else
  printf '%s\n' "$key" >> "$HOME/.ssh/authorized_keys"
fi"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl SshTarget {
    pub fn endpoint(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}@{}:{}", self.username, host, self.port)
    }
}

pub struct PrivateKeyMaterial {
    pub public_key: Option<Zeroizing<String>>,
    pub private_key: Zeroizing<String>,
    pub passphrase: Option<Zeroizing<String>>,
}

pub enum AuthenticationMaterial {
    StoredPassword(Zeroizing<String>),
    SshAgent,
    AuthenticationKey(PrivateKeyMaterial),
}

pub struct PublicKeyInstallRequest {
    pub target: SshTarget,
    pub expected_host_key_fingerprint: String,
    pub public_key: Zeroizing<String>,
    pub authentication: AuthenticationMaterial,
    pub verification_key: Option<PrivateKeyMaterial>,
}

pub struct AgentSshExecRequest {
    pub target: SshTarget,
    pub expected_host_key_fingerprint: String,
    pub command: String,
    pub authentication: AuthenticationMaterial,
    pub allowed_fields: Vec<String>,
    pub max_output_bytes: usize,
}

pub struct AgentSshTransferRequest {
    pub target: SshTarget,
    pub expected_host_key_fingerprint: String,
    pub remote_path: String,
    pub remote_path_prefixes: Vec<String>,
    pub authentication: AuthenticationMaterial,
}

pub struct AgentSshPtyRequest {
    pub target: SshTarget,
    pub expected_host_key_fingerprint: String,
    pub authentication: AuthenticationMaterial,
    pub max_output_bytes: usize,
}

impl AgentSshPtyRequest {
    pub fn authentication_canaries(&self) -> Vec<String> {
        authentication_canaries(&self.authentication)
    }
}

pub struct AgentSshPtySession {
    connection: SshConnection,
    channel: ssh2::Channel,
}

pub struct AgentSshTunnelRequest {
    pub target: SshTarget,
    pub expected_host_key_fingerprint: String,
    pub authentication: AuthenticationMaterial,
    pub local_host: String,
    pub local_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
    pub max_connections: u8,
    pub ttl_millis: u64,
}

pub struct AgentSshTunnel {
    pub local_host: String,
    pub local_port: u16,
    pub expires_at: u64,
    cancellation: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for AgentSshTunnel {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn open_agent_tunnel(
    request: AgentSshTunnelRequest,
    now_millis: u64,
    cancellation: &AtomicBool,
) -> Result<AgentSshTunnel, String> {
    if !matches!(request.local_host.as_str(), "127.0.0.1" | "::1")
        || request.local_port == 0
        || request.destination_port == 0
        || !(1..=8).contains(&request.max_connections)
        || !(1_000..=300_000).contains(&request.ttl_millis)
    {
        return Err("SSH tunnel policy 无效。".to_owned());
    }
    let connection = approved_connection(
        &request.target,
        &request.expected_host_key_fingerprint,
        &request.authentication,
        cancellation,
    )?;
    let listener = TcpListener::bind((request.local_host.as_str(), request.local_port))
        .map_err(|_| "无法绑定已批准的 SSH tunnel 本地端点。".to_owned())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "无法配置 SSH tunnel listener。".to_owned())?;
    connection.session.set_blocking(false);
    let tunnel_cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&tunnel_cancellation);
    let destination_host = request.destination_host;
    let destination_port = request.destination_port;
    let max_connections = request.max_connections;
    let expires_at = now_millis.saturating_add(request.ttl_millis);
    let worker = std::thread::spawn(move || {
        let mut accepted = 0_u8;
        while !worker_cancellation.load(Ordering::Acquire)
            && accepted < max_connections
            && current_millis() < expires_at
        {
            match crate::socket_wait::wait_for_connection(&listener, Duration::from_millis(250)) {
                Ok(crate::socket_wait::Readiness::Ready) => {}
                Ok(_) => continue,
                Err(_) => break,
            }
            match listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    accepted = accepted.saturating_add(1);
                    let _ = bridge_direct_tcpip(
                        &connection.session,
                        stream,
                        &destination_host,
                        destination_port,
                        expires_at,
                        &worker_cancellation,
                    );
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        let _ = connection
            .session
            .disconnect(None, "VaultMesh Agent tunnel closed", None);
    });
    Ok(AgentSshTunnel {
        local_host: request.local_host,
        local_port: request.local_port,
        expires_at,
        cancellation: tunnel_cancellation,
        worker: Some(worker),
    })
}

fn bridge_direct_tcpip(
    session: &Session,
    mut local: TcpStream,
    destination_host: &str,
    destination_port: u16,
    expires_at: u64,
    cancellation: &AtomicBool,
) -> Result<(), String> {
    local
        .set_nonblocking(true)
        .map_err(|_| "无法配置 SSH tunnel connection。".to_owned())?;
    session.set_blocking(true);
    let remote = session
        .channel_direct_tcpip(destination_host, destination_port, None)
        .map_err(|_| "SSH server 拒绝已批准的 tunnel endpoint。".to_owned())?;
    session.set_blocking(false);
    let mut remote = remote;
    let mut local_eof = false;
    let mut to_remote = Vec::new();
    let mut to_local = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    while !cancellation.load(Ordering::Acquire) && current_millis() < expires_at {
        let mut progressed = false;
        if to_remote.is_empty() && !local_eof {
            match local.read(&mut buffer) {
                Ok(0) => {
                    local_eof = true;
                    let _ = remote.send_eof();
                }
                Ok(count) => {
                    to_remote.extend_from_slice(&buffer[..count]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        if !to_remote.is_empty() {
            match remote.write(&to_remote) {
                Ok(count) => {
                    to_remote.drain(..count);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        if to_local.is_empty() && !remote.eof() {
            match remote.read(&mut buffer) {
                Ok(0) => {}
                Ok(count) => {
                    to_local.extend_from_slice(&buffer[..count]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        if !to_local.is_empty() {
            match local.write(&to_local) {
                Ok(count) => {
                    to_local.drain(..count);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        if remote.eof() && to_local.is_empty() && (local_eof || to_remote.is_empty()) {
            break;
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let _ = remote.close();
    Ok(())
}

fn current_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

impl AgentSshPtySession {
    pub fn open(
        request: AgentSshPtyRequest,
        terminal: &str,
        columns: u32,
        rows: u32,
        cancellation: &AtomicBool,
    ) -> Result<Self, String> {
        let connection = approved_connection(
            &request.target,
            &request.expected_host_key_fingerprint,
            &request.authentication,
            cancellation,
        )?;
        let mut channel = connection
            .session
            .channel_session()
            .map_err(|_| "无法打开 SSH PTY 通道。".to_owned())?;
        channel
            .request_pty(terminal, None, Some((columns, rows, 0, 0)))
            .and_then(|()| channel.shell())
            .map_err(|_| "服务器拒绝打开 SSH PTY。".to_owned())?;
        connection.session.set_blocking(false);
        Ok(Self {
            connection,
            channel,
        })
    }

    pub fn read_available(
        &mut self,
        maximum: usize,
    ) -> Result<(Vec<u8>, bool, Option<i32>), String> {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        while output.len() < maximum {
            let available = maximum.saturating_sub(output.len()).min(buffer.len());
            match self.channel.read(&mut buffer[..available]) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("无法读取 SSH PTY 输出。".to_owned()),
            }
        }
        let eof = self.channel.eof();
        let exit_status = if eof {
            self.channel.exit_status().ok()
        } else {
            None
        };
        Ok((output, eof, exit_status))
    }

    pub fn write_all(&mut self, input: &[u8], cancellation: &AtomicBool) -> Result<(), String> {
        let mut written = 0;
        let deadline = Instant::now() + IO_TIMEOUT;
        while written < input.len() {
            if cancellation.load(Ordering::Acquire) {
                return Err("SSH PTY 写入已取消。".to_owned());
            }
            if Instant::now() >= deadline {
                return Err("SSH PTY 写入超时。".to_owned());
            }
            match self.channel.write(&input[written..]) {
                Ok(0) => return Err("SSH PTY 已关闭。".to_owned()),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err("无法写入 SSH PTY。".to_owned()),
            }
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("SSH PTY 写入已取消。".to_owned());
        }
        self.channel
            .flush()
            .map_err(|_| "无法提交 SSH PTY 输入。".to_owned())
    }

    pub fn resize(&mut self, columns: u32, rows: u32) -> Result<(), String> {
        self.channel
            .request_pty_size(columns, rows, None, None)
            .map_err(|_| "无法调整 SSH PTY。".to_owned())
    }

    pub fn close(&mut self) -> Option<i32> {
        let _ = self.channel.send_eof();
        let _ = self.channel.close();
        let status = if self.channel.eof() {
            self.channel.exit_status().ok()
        } else {
            None
        };
        let _ = self
            .connection
            .session
            .disconnect(None, "VaultMesh Agent PTY closed", None);
        status
    }
}

impl Drop for AgentSshPtySession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub struct AgentSshDownload {
    pub basename: String,
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPreview {
    pub endpoint: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyInstallResult {
    pub endpoint: String,
    pub fingerprint: String,
    pub status: &'static str,
    pub key_login_verified: bool,
    pub key_login_verification: KeyLoginVerification,
}
