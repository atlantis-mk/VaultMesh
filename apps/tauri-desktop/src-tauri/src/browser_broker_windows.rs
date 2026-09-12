#![cfg(target_os = "windows")]

use std::{
    ffi::{OsStr, c_void},
    io,
    os::windows::ffi::OsStrExt,
    ptr::{null, null_mut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        WriteFile,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            PeekNamedPipe,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use crate::{browser_broker::BrowserBrokerCore, browser_host_registration::BROWSER_PIPE_NAME};

const MAX_REQUEST_BYTES: usize = 384 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 16;
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

struct ActivePipeGuard(Arc<AtomicUsize>);

impl Drop for ActivePipeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub struct BrowserBrokerWindowsListener {
    broker: std::sync::Weak<Mutex<BrowserBrokerCore>>,
    pipe_name: String,
    stopping: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl BrowserBrokerWindowsListener {
    pub fn start(broker: Arc<Mutex<BrowserBrokerCore>>) -> io::Result<Self> {
        Self::start_with_pipe_name(BROWSER_PIPE_NAME.to_owned(), broker)
    }

    pub(crate) fn start_with_pipe_name(
        pipe_name: String,
        broker: Arc<Mutex<BrowserBrokerCore>>,
    ) -> io::Result<Self> {
        if !valid_pipe_name(&pipe_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid browser broker pipe name",
            ));
        }
        // Hold the first-instance handle across worker startup so no same-user
        // process can claim the fixed broker name between validation and bind.
        let first_pipe = create_pipe(&pipe_name, true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let owned_broker = Arc::downgrade(&broker);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_healthy = Arc::clone(&healthy);
        let worker_pipe_name = pipe_name.clone();
        let active_connections = Arc::new(AtomicUsize::new(0));
        let thread = thread::spawn(move || {
            let mut first_pipe = Some(first_pipe);
            while !worker_stopping.load(Ordering::Acquire) {
                let pipe = match first_pipe
                    .take()
                    .map(Ok)
                    .unwrap_or_else(|| create_pipe(&worker_pipe_name, false))
                {
                    Ok(pipe) => pipe,
                    Err(_) => break,
                };
                let connected = unsafe { ConnectNamedPipe(pipe.0, null_mut()) };
                if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                    break;
                }
                if worker_stopping.load(Ordering::Acquire) {
                    unsafe {
                        DisconnectNamedPipe(pipe.0);
                    }
                    break;
                }
                if active_connections
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < MAX_CONNECTIONS).then_some(active + 1)
                    })
                    .is_err()
                {
                    unsafe {
                        DisconnectNamedPipe(pipe.0);
                    }
                    continue;
                }
                let guard = ActivePipeGuard(Arc::clone(&active_connections));
                let connection_broker = Arc::clone(&broker);
                let connection_stopping = Arc::clone(&worker_stopping);
                thread::spawn(move || {
                    let _guard = guard;
                    let _ = serve_connection(pipe, connection_broker, &connection_stopping);
                });
            }
            worker_healthy.store(false, Ordering::Release);
        });
        Ok(Self {
            broker: owned_broker,
            pipe_name,
            stopping,
            healthy,
            thread: Mutex::new(Some(thread)),
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && !self.stopping.load(Ordering::Acquire)
    }

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.healthy.store(false, Ordering::Release);
        wake_listener(&self.pipe_name);
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
    pub(crate) fn lock_vault(&self) {
        if let Some(broker) = self.broker.upgrade() {
            if let Ok(mut b) = broker.lock() {
                b.lock_for_system();
            }
        }
    }
}

impl Drop for BrowserBrokerWindowsListener {
    fn drop(&mut self) {
        self.stop();
    }
}

fn valid_pipe_name(value: &str) -> bool {
    value.starts_with(r"\\.\pipe\VaultMesh.")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'\\' | b'.' | b'-'))
}

fn create_pipe(pipe_name: &str, first_instance: bool) -> io::Result<OwnedHandle> {
    let pipe_name = wide(pipe_name);
    let (security, _descriptor) = current_user_security()?;
    let open_mode = PIPE_ACCESS_DUPLEX
        | if first_instance {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            MAX_RESPONSE_BYTES as u32,
            MAX_REQUEST_BYTES as u32,
            1_000,
            &security,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle(handle))
    }
}

fn serve_connection(
    pipe: OwnedHandle,
    broker: Arc<Mutex<BrowserBrokerCore>>,
    stopping: &AtomicBool,
) -> io::Result<()> {
    let request = read_line(pipe.0, stopping)?;
    let response = broker
        .lock()
        .ok()
        .map(|mut broker| broker.handle_line(&request))
        .unwrap_or_else(|| host_status("desktop-unavailable", None));
    write_response(pipe.0, response)?;
    unsafe {
        DisconnectNamedPipe(pipe.0);
    }
    Ok(())
}

fn read_line(pipe: HANDLE, stopping: &AtomicBool) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let mut pending = Vec::new();
    loop {
        if stopping.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "browser broker is stopping",
            ));
        }
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "browser broker request deadline exceeded",
            ));
        }
        let mut available = 0_u32;
        if unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), &mut available, null_mut()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if available == 0 {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let mut chunk = [0_u8; 8 * 1024];
        let requested = available.min(chunk.len() as u32);
        let mut read = 0_u32;
        if unsafe { ReadFile(pipe, chunk.as_mut_ptr(), requested, &mut read, null_mut()) } == 0
            || read == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(newline) = chunk[..read as usize]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            pending.extend_from_slice(&chunk[..newline]);
            if pending.len() > MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "browser broker request too large",
                ));
            }
            return Ok(pending);
        }
        pending.extend_from_slice(&chunk[..read as usize]);
        if pending.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "browser broker request too large",
            ));
        }
    }
}

fn write_response(pipe: HANDLE, response: Value) -> io::Result<()> {
    let request_id = response
        .get("requestId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded = serde_json::to_vec(&host_status("response-too-large", request_id.as_deref()))
            .map_err(io::Error::other)?;
    }
    encoded.push(b'\n');
    let mut offset = 0;
    while offset < encoded.len() {
        let mut written = 0_u32;
        if unsafe {
            WriteFile(
                pipe,
                encoded[offset..].as_ptr(),
                (encoded.len() - offset) as u32,
                &mut written,
                null_mut(),
            )
        } == 0
            || written == 0
        {
            return Err(io::Error::last_os_error());
        }
        offset += written as usize;
    }
    Ok(())
}

fn host_status(status: &str, request_id: Option<&str>) -> Value {
    let mut object = Map::from_iter([
        ("kind".into(), json!("vaultmesh.host-status")),
        ("status".into(), json!(status)),
    ]);
    if let Some(request_id) = request_id {
        object.insert("requestId".into(), Value::String(request_id.to_owned()));
    }
    Value::Object(object)
}

fn current_user_security() -> io::Result<(SECURITY_ATTRIBUTES, SecurityDescriptor)> {
    let sid = current_user_sid_string()?;
    let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
    let mut descriptor = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(io::Error::last_os_error());
    }
    let owner = SecurityDescriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: owner.0,
        bInheritHandle: 0,
    };
    Ok((attributes, owner))
}

struct TokenUserBuffer {
    storage: Vec<usize>,
}

impl TokenUserBuffer {
    fn as_ptr(&self) -> *const TOKEN_USER {
        self.storage.as_ptr().cast()
    }
}

fn token_user() -> io::Result<TokenUserBuffer> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = TokenUserBuffer {
        storage: vec![0_usize; words],
    };
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

fn current_user_sid_string() -> io::Result<String> {
    let buffer = token_user()?;
    let sid = unsafe { (*buffer.as_ptr()).User.Sid };
    let mut value = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid user SID"));
    unsafe {
        LocalFree(value.cast());
    }
    result
}

fn wake_listener(pipe_name: &str) {
    let pipe_name = wide(pipe_name);
    let handle = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle != INVALID_HANDLE_VALUE {
        drop(OwnedHandle(handle));
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    #[test]
    fn windows_named_pipe_round_trip_reaches_browser_broker() {
        let pipe_name = format!(r"\\.\pipe\VaultMesh.BrowserBroker.test.{}", Uuid::new_v4());
        let vault =
            std::env::temp_dir().join(format!("vaultmesh-browser-{}.vault", Uuid::new_v4()));
        let broker = BrowserBrokerCore::new(vault, Zeroizing::new([7_u8; 32])).expect("broker");
        let listener = BrowserBrokerWindowsListener::start_with_pipe_name(
            pipe_name.clone(),
            Arc::new(Mutex::new(broker)),
        )
        .expect("listener");
        assert!(listener.is_healthy());
        let handle = connect_for_test(&pipe_name).expect("connect");
        let request = b"{}\n";
        let mut written = 0_u32;
        assert_ne!(
            unsafe {
                WriteFile(
                    handle.0,
                    request.as_ptr(),
                    request.len() as u32,
                    &mut written,
                    null_mut(),
                )
            },
            0
        );
        let mut response = [0_u8; 1024];
        let mut read = 0_u32;
        assert_ne!(
            unsafe {
                ReadFile(
                    handle.0,
                    response.as_mut_ptr(),
                    response.len() as u32,
                    &mut read,
                    null_mut(),
                )
            },
            0
        );
        let newline = response[..read as usize]
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("newline");
        let value: Value = serde_json::from_slice(&response[..newline]).expect("response");
        assert_eq!(value["kind"], "vaultmesh.host-status");
        assert_eq!(value["status"], "invalid-message");
        listener.stop();
        assert!(!listener.is_healthy());
    }

    fn connect_for_test(pipe_name: &str) -> io::Result<OwnedHandle> {
        use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
        let wide_name = wide(pipe_name);
        if unsafe { WaitNamedPipeW(wide_name.as_ptr(), 2_000) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedHandle(handle))
        }
    }
}
