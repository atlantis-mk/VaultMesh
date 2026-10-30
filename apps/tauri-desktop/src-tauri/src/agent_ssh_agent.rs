use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixListener;

use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, PrivateKey};
use uuid::Uuid;
use zeroize::Zeroizing;

const SSH2_AGENT_FAILURE: u8 = 30;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentSessionInfo {
    pub session_ref: String,
    pub socket_path: String,
    pub export_command: String,
    pub expires_at: String,
    pub account_label: String,
    pub fingerprint: String,
}

#[allow(dead_code)]
pub struct ActiveAgentSession {
    pub session_ref: String,
    pub account_ref: String,
    pub account_label: String,
    pub socket_path: PathBuf,
    pub expires_at_epoch_ms: u64,
    pub cancelled: Arc<AtomicBool>,
    pub config_fragment: Option<PathBuf>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EphemeralKeyMaterial {
    pub private_key: Zeroizing<String>,
    pub public_key: Zeroizing<String>,
    pub host_key_sha256: String,
}

pub struct SshAgentRegistry {
    sessions: HashMap<String, ActiveAgentSession>,
    ephemeral_keys: HashMap<String, EphemeralKeyMaterial>,
    device_id: String,
}

impl Default for SshAgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub type SharedSshAgentRegistry = Arc<Mutex<SshAgentRegistry>>;

impl SshAgentRegistry {
    pub fn new() -> Self {
        Self::new_with_device_id(Uuid::new_v4().simple().to_string())
    }

    pub fn new_with_device_id(device_id: String) -> Self {
        Self {
            sessions: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            device_id,
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn get_ephemeral_key(
        &self,
        account_ref: &str,
        host_key_sha256: &str,
    ) -> Option<Zeroizing<String>> {
        self.ephemeral_keys.get(account_ref).and_then(|mat| {
            if mat.host_key_sha256 == host_key_sha256 {
                Some(mat.private_key.clone())
            } else {
                None
            }
        })
    }

    pub fn store_ephemeral_key(
        &mut self,
        account_ref: &str,
        host_key_sha256: &str,
        public_key: Zeroizing<String>,
        private_key: Zeroizing<String>,
    ) {
        self.ephemeral_keys.insert(
            account_ref.to_owned(),
            EphemeralKeyMaterial {
                private_key,
                public_key,
                host_key_sha256: host_key_sha256.to_owned(),
            },
        );
    }

    #[allow(dead_code)]
    pub fn clear_ephemeral_key(&mut self, account_ref: &str) {
        self.ephemeral_keys.remove(account_ref);
    }

    pub fn start_session(
        &mut self,
        #[cfg(windows)] base_dir: &Path,
        #[cfg(not(windows))] _base_dir: &Path,
        account_ref: &str,
        account_label: &str,
        private_key_pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
        duration_minutes: u64,
    ) -> Result<SshAgentSessionInfo, String> {
        let mut key = PrivateKey::from_openssh(private_key_pem.as_str())
            .map_err(|e| format!("Invalid private key: {e}"))?;
        if let Some(passphrase) = passphrase {
            if !passphrase.is_empty() {
                key = key
                    .decrypt(passphrase.as_bytes())
                    .map_err(|e| format!("Failed to decrypt private key: {e}"))?;
            }
        }

        let duration_minutes = duration_minutes.clamp(1, 60);
        let duration = Duration::from_secs(duration_minutes * 60);
        let now = SystemTime::now();
        let expires_system_time = now + duration;
        let expires_at_epoch_ms = expires_system_time
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64;
        let expires_at = chrono::DateTime::<chrono::Utc>::from(expires_system_time).to_rfc3339();

        let session_uuid = Uuid::new_v4();
        let session_ref = format!("sess_{}", session_uuid.simple());
        let public_key = key.public_key();
        let fingerprint = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        #[cfg(unix)]
        let session_dir = {
            let uid = unsafe { libc::getuid() };
            let dir = PathBuf::from(format!("/tmp/vaultmesh-{}", uid));
            fs::create_dir_all(&dir)
                .map_err(|e| format!("Failed to create agent sessions directory: {e}"))?;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            dir
        };
        #[cfg(windows)]
        let session_dir = {
            let dir = base_dir.join("agent-sessions");
            fs::create_dir_all(&dir)
                .map_err(|e| format!("Failed to create agent sessions directory: {e}"))?;
            dir
        };

        #[cfg(unix)]
        let socket_path = session_dir.join(format!("{session_ref}.sock"));
        #[cfg(windows)]
        let socket_path = PathBuf::from(format!(r"\\.\pipe\VaultMesh.SshAgent.{session_ref}"));

        let cancelled = Arc::new(AtomicBool::new(false));

        #[cfg(unix)]
        {
            if socket_path.exists() {
                let _ = fs::remove_file(&socket_path);
            }
            let listener = UnixListener::bind(&socket_path)
                .map_err(|e| format!("Failed to bind SSH agent socket: {e}"))?;
            let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));

            let cancelled_clone = Arc::clone(&cancelled);
            let socket_path_clone = socket_path.clone();
            let key_clone = key.clone();

            thread::Builder::new()
                .name(format!("ssh-agent-{}", &session_ref[..8]))
                .spawn(move || {
                    run_unix_agent_listener(
                        listener,
                        socket_path_clone,
                        key_clone,
                        duration,
                        cancelled_clone,
                    );
                })
                .map_err(|e| format!("Failed to spawn agent thread: {e}"))?;
        }

        let socket_str = socket_path.to_string_lossy().to_string();
        let export_command = format!(r#"export SSH_AUTH_SOCK="{socket_str}""#);

        let info = SshAgentSessionInfo {
            session_ref: session_ref.clone(),
            socket_path: socket_str,
            export_command,
            expires_at,
            account_label: account_label.to_owned(),
            fingerprint,
        };

        self.sessions.insert(
            session_ref.clone(),
            ActiveAgentSession {
                session_ref,
                account_ref: account_ref.to_owned(),
                account_label: account_label.to_owned(),
                socket_path,
                expires_at_epoch_ms,
                cancelled,
                config_fragment: None,
            },
        );

        Ok(info)
    }

    pub fn attach_config_fragment(&mut self, session_ref: &str, fragment_path: PathBuf) {
        if let Some(session) = self.sessions.get_mut(session_ref) {
            session.config_fragment = Some(fragment_path);
        }
    }

    pub fn close_session(&mut self, session_ref: &str) -> bool {
        if let Some(session) = self.sessions.remove(session_ref) {
            session.cancelled.store(true, Ordering::Release);
            #[cfg(unix)]
            {
                let _ = fs::remove_file(&session.socket_path);
            }
            if let Some(fragment) = &session.config_fragment {
                let _ = fs::remove_file(fragment);
            }
            true
        } else {
            false
        }
    }

    pub fn close_all(&mut self) {
        self.ephemeral_keys.clear();
        for (_, session) in self.sessions.drain() {
            session.cancelled.store(true, Ordering::Release);
            #[cfg(unix)]
            {
                let _ = fs::remove_file(&session.socket_path);
            }
            if let Some(fragment) = &session.config_fragment {
                let _ = fs::remove_file(fragment);
            }
        }
    }
}

#[cfg(unix)]
fn run_unix_agent_listener(
    listener: UnixListener,
    socket_path: PathBuf,
    key: PrivateKey,
    ttl: Duration,
    cancelled: Arc<AtomicBool>,
) {
    let deadline = Instant::now() + ttl;
    let _ = listener.set_nonblocking(true);

    while !cancelled.load(Ordering::Acquire) && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                handle_agent_stream(&mut stream, &key, deadline, &cancelled);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    let _ = fs::remove_file(&socket_path);
}

fn put_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    put_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn send_agent_msg(stream: &mut impl Write, msg_type: u8, payload: &[u8]) -> std::io::Result<()> {
    let len = (1 + payload.len()) as u32;
    let mut header = [0u8; 5];
    header[0..4].copy_from_slice(&len.to_be_bytes());
    header[4] = msg_type;
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

pub fn handle_agent_stream(
    stream: &mut (impl Read + Write),
    key: &PrivateKey,
    deadline: Instant,
    cancelled: &AtomicBool,
) {
    let pubkey_bytes = match key.public_key().to_bytes() {
        Ok(b) => b,
        Err(_) => return,
    };

    loop {
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            let _ = send_agent_msg(stream, SSH2_AGENT_FAILURE, &[]);
            break;
        }

        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            break;
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 256 * 1024 {
            let _ = send_agent_msg(stream, SSH2_AGENT_FAILURE, &[]);
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).is_err() {
            break;
        }

        let msg_type = msg_buf[0];
        let payload = &msg_buf[1..];

        match msg_type {
            SSH2_AGENTC_REQUEST_IDENTITIES => {
                let mut answer = Vec::new();
                put_u32(&mut answer, 1);
                put_string(&mut answer, &pubkey_bytes);
                put_string(&mut answer, b"vaultmesh-agent");
                if send_agent_msg(stream, SSH2_AGENT_IDENTITIES_ANSWER, &answer).is_err() {
                    break;
                }
            }
            SSH2_AGENTC_SIGN_REQUEST => {
                if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
                    let _ = send_agent_msg(stream, SSH2_AGENT_FAILURE, &[]);
                    break;
                }

                if let Some(signature_payload) = process_sign_request(payload, key) {
                    if send_agent_msg(stream, SSH2_AGENT_SIGN_RESPONSE, &signature_payload).is_err() {
                        break;
                    }
                } else {
                    let _ = send_agent_msg(stream, SSH2_AGENT_FAILURE, &[]);
                }
            }
            _ => {
                let _ = send_agent_msg(stream, SSH2_AGENT_FAILURE, &[]);
            }
        }
    }
}

fn process_sign_request(payload: &[u8], key: &PrivateKey) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }
    let key_len = u32::from_be_bytes(payload[0..4].try_into().ok()?) as usize;
    let offset1 = 4 + key_len;
    if payload.len() < offset1 + 4 {
        return None;
    }
    let data_len = u32::from_be_bytes(payload[offset1..offset1 + 4].try_into().ok()?) as usize;
    let offset2 = offset1 + 4;
    if payload.len() < offset2 + data_len {
        return None;
    }
    let data = &payload[offset2..offset2 + data_len];

    let sig: ssh_key::Signature = key.try_sign(data).ok()?;
    let alg_name = match key.algorithm() {
        Algorithm::Ed25519 => "ssh-ed25519",
        Algorithm::Rsa { .. } => "ssh-rsa",
        _ => "ssh-ed25519",
    };

    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, alg_name.as_bytes());
    put_string(&mut sig_blob, sig.as_bytes());

    let mut response_payload = Vec::new();
    put_string(&mut response_payload, &sig_blob);
    Some(response_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_protocol_request_identities_and_sign() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("key");
        let pubkey_bytes = key.public_key().to_bytes().expect("pubkey");

        // 1. Test REQUEST_IDENTITIES
        let mut client_req = Vec::new();
        put_u32(&mut client_req, 1);
        client_req.push(SSH2_AGENTC_REQUEST_IDENTITIES);

        // 2. Test SIGN_REQUEST
        let data_to_sign = b"authentication-challenge-bytes-123456";
        let mut sign_req = Vec::new();
        let mut sign_payload = Vec::new();
        sign_payload.push(SSH2_AGENTC_SIGN_REQUEST);
        put_string(&mut sign_payload, &pubkey_bytes);
        put_string(&mut sign_payload, data_to_sign);
        put_u32(&mut sign_payload, 0); // flags

        put_u32(&mut sign_req, sign_payload.len() as u32);
        sign_req.extend_from_slice(&sign_payload);

        // Simulate stream with both requests
        let mut input = client_req;
        input.extend_from_slice(&sign_req);

        let mut output = Vec::new();
        let cursor = std::io::Cursor::new(input);
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(60);

        struct MockStream<'a> {
            reader: std::io::Cursor<Vec<u8>>,
            writer: &'a mut Vec<u8>,
        }
        impl Read for MockStream<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reader.read(buf)
            }
        }
        impl Write for MockStream<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writer.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.writer.flush()
            }
        }

        let mut mock = MockStream {
            reader: cursor,
            writer: &mut output,
        };

        handle_agent_stream(&mut mock, &key, deadline, &cancelled);

        // Parse responses in output
        assert!(output.len() > 5);
        // First response must be IDENTITIES_ANSWER (12)
        let resp1_len = u32::from_be_bytes(output[0..4].try_into().unwrap()) as usize;
        assert_eq!(output[4], SSH2_AGENT_IDENTITIES_ANSWER);

        // Second response starts at 4 + resp1_len
        let offset2 = 4 + resp1_len;
        assert!(output.len() > offset2 + 5);
        let _resp2_len = u32::from_be_bytes(output[offset2..offset2 + 4].try_into().unwrap()) as usize;
        assert_eq!(output[offset2 + 4], SSH2_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn test_start_and_close_session_socket_path_length_within_limits() {
        let mut registry = SshAgentRegistry::new();
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let private_key_pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let temp_dir = std::env::temp_dir().join(format!("vm-test-{}", Uuid::new_v4()));
        let session_info = registry
            .start_session(
                &temp_dir,
                "account-123",
                "Test Account",
                private_key_pem,
                None,
                15,
            )
            .expect("session must start successfully");

        #[cfg(windows)]
        {
            assert!(
                temp_dir.join("agent-sessions").is_dir(),
                "Windows SSH agent sessions directory must be created under the provided base directory"
            );
            let _ = std::fs::remove_dir_all(&temp_dir);
        }

        #[cfg(unix)]
        {
            // On Darwin/macOS, sockaddr_un.sun_path is strictly 104 bytes
            assert!(
                session_info.socket_path.len() < 104,
                "Socket path must be under 104 bytes for macOS AF_UNIX: {}",
                session_info.socket_path
            );
            assert!(std::path::Path::new(&session_info.socket_path).exists());
        }

        let closed = registry.close_session(&session_info.session_ref);
        assert!(closed);
        #[cfg(unix)]
        {
            assert!(!std::path::Path::new(&session_info.socket_path).exists());
        }
    }

    #[test]
    fn test_ephemeral_key_cache_operations_and_close_all_clears() {
        let mut registry = SshAgentRegistry::new_with_device_id("dev-12345678".to_owned());
        assert_eq!(registry.device_id(), "dev-12345678");

        let acc_ref = "acc-001";
        let fp = "SHA256:fingerprint1";
        let alt_fp = "SHA256:fingerprint2";

        assert!(registry.get_ephemeral_key(acc_ref, fp).is_none());

        let priv_key = Zeroizing::new("fake_priv_key".to_owned());
        let pub_key = Zeroizing::new("fake_pub_key".to_owned());
        registry.store_ephemeral_key(acc_ref, fp, pub_key, priv_key);

        // Matching fingerprint hits
        let hit = registry.get_ephemeral_key(acc_ref, fp);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().as_str(), "fake_priv_key");

        // Mismatched fingerprint misses
        assert!(registry.get_ephemeral_key(acc_ref, alt_fp).is_none());

        // close_all clears the cache
        registry.close_all();
        assert!(registry.get_ephemeral_key(acc_ref, fp).is_none());
    }
}
