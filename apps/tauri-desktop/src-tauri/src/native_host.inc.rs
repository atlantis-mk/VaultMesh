#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    macos_host::run_host();
}

#[cfg(target_os = "windows")]
fn main() {
    windows_host::run_host();
}

#[cfg(target_os = "windows")]
mod windows_host {
    use crate::{BITWARDEN_DEVELOPMENT_HOST as DEV, development_identity as dev};
    use std::{
        ffi::OsStr,
        fs,
        io::{self, Read, Write},
        os::windows::ffi::OsStrExt,
        path::PathBuf,
        ptr::{null, null_mut},
        time::{Duration, Instant},
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac as _};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value, json};
    use sha2::Sha256;
    use uuid::Uuid;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, HANDLE,
            INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED},
            Pipes::WaitNamedPipeW,
            Threading::CreateEventW,
        },
    };
    use zeroize::Zeroizing;

    const CONFIG_NAME: &str = if DEV { dev::CONFIG_NAME } else { "browser-host-config.json" };
    const APP_DATA_NAME: &str = "com.vaultmesh.desktop";
    const DEFAULT_EXTENSION_ID: &str = "dmmjcaemejijgkpginfccokjmbknbgif";
    const DEFAULT_FIREFOX_EXTENSION_ID: &str = "vaultmesh@atlantis-mk.github.io";
    const FIREFOX_MANIFEST_NAME: &str = if DEV { "com.vaultmesh.bitwarden.dev.firefox.json" } else { "com.vaultmesh.browser.firefox.json" };
    const EXPECTED_PIPE: &str = if DEV { dev::PIPE_NAME } else { r"\\.\pipe\VaultMesh.BrowserBroker.v2" };
    const EXPECTED_KEYCHAIN_SERVICE: &str = if DEV { dev::PAIRING_SERVICE } else { "com.vaultmesh.desktop.browser-pairing" };
    const EXPECTED_KEYCHAIN_ACCOUNT: &str = if DEV { dev::PAIRING_ACCOUNT } else { "native-host-hmac-v1" };
    const MAX_CONFIG_BYTES: u64 = 4096;
    const MAX_NATIVE_REQUEST_BYTES: usize = 256 * 1024;
    const MAX_NATIVE_RESPONSE_BYTES: usize = 1024 * 1024;
    const MAX_BROKER_LINE_BYTES: usize = 1024 * 1024;
    const BROKER_WRITE_DEADLINE: Duration = Duration::from_secs(5);
    const BROKER_RESPONSE_DEADLINE: Duration = Duration::from_secs(70);

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct HostConfig {
        version: u8,
        broker_pipe: String,
        keychain_service: String,
        keychain_account: String,
        chromium_allowed_origin: String,
        firefox_extension_id: String,
        firefox_manifest_path: PathBuf,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthenticatedBody<'a> {
        request_id: &'a str,
        payload: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BrokerEnvelope<'a> {
        request_id: &'a str,
        auth: String,
        payload: &'a str,
    }

    struct OwnedHandle(HANDLE);

    unsafe impl Send for OwnedHandle {}

    #[cfg(test)]
    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub fn run_host() {
        if run().is_err() {
            let _ = write_native_message(&host_status("unpaired", None));
        }
    }

    fn run() -> Result<(), ()> {
        if DEV && !cfg!(debug_assertions) { return Err(()); }
        let config = load_config().map_err(|_| ())?;
        let launch_arguments: Vec<String> = std::env::args().skip(1).collect();
        if !valid_browser_launch(&config, &launch_arguments) {
            return Err(());
        }
        let secret = load_pairing_secret(&config).map_err(|_| ())?;
        loop {
            let message = match read_native_message() {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(()),
                Err(_) => {
                    write_native_message(&host_status("invalid-message", None)).map_err(|_| ())?;
                    return Ok(());
                }
            };
            let request_id = request_id_for(&message);
            let response = forward(&config, &secret, &request_id, &message)
                .unwrap_or_else(|status| host_status(status, Some(&request_id)));
            let response = correlate_response(&message, &request_id, response);
            write_native_message(&response).map_err(|_| ())?;
        }
    }

    fn load_config() -> io::Result<HostConfig> {
        let app_data = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing APPDATA"))?;
        let path = app_data.join(APP_DATA_NAME).join(CONFIG_NAME);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid host configuration",
            ));
        }
        let bytes = fs::read(path)?;
        let config: HostConfig = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid host configuration")
        })?;
        let expected_origin = format!("chrome-extension://{}/", compiled_extension_id()?);
        let expected_firefox_manifest = app_data.join(APP_DATA_NAME).join(FIREFOX_MANIFEST_NAME);
        if config.version != 2
            || config.broker_pipe != EXPECTED_PIPE
            || config.keychain_service != EXPECTED_KEYCHAIN_SERVICE
            || config.keychain_account != EXPECTED_KEYCHAIN_ACCOUNT
            || config.chromium_allowed_origin != expected_origin
            || config.firefox_extension_id != compiled_firefox_extension_id()?
            || config.firefox_manifest_path != expected_firefox_manifest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid host configuration",
            ));
        }
        Ok(config)
    }

    fn compiled_extension_id() -> io::Result<&'static str> {
        if DEV { return Ok(dev::EXTENSION_ID); }
        let value = option_env!("VAULTMESH_BROWSER_EXTENSION_ID").unwrap_or(DEFAULT_EXTENSION_ID);
        (value.len() == 32 && value.bytes().all(|byte| (b'a'..=b'p').contains(&byte)))
            .then_some(value)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid extension ID"))
    }

    fn compiled_firefox_extension_id() -> io::Result<&'static str> {
        if DEV { return Ok(dev::FIREFOX_ID); }
        let value =
            option_env!("VAULTMESH_FIREFOX_EXTENSION_ID").unwrap_or(DEFAULT_FIREFOX_EXTENSION_ID);
        (value == DEFAULT_FIREFOX_EXTENSION_ID)
            .then_some(value)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Firefox extension ID")
            })
    }

    fn valid_browser_launch(config: &HostConfig, arguments: &[String]) -> bool {
        if matches!(arguments, [origin] | [origin, _] if origin == &config.chromium_allowed_origin)
        {
            return true;
        }
        matches!(arguments, [manifest_path, extension_id]
            if PathBuf::from(manifest_path) == config.firefox_manifest_path
                && extension_id == &config.firefox_extension_id)
    }

    fn load_pairing_secret(config: &HostConfig) -> Result<Zeroizing<[u8; 32]>, ()> {
        let encoded = Zeroizing::new(
            keyring::Entry::new(&config.keychain_service, &config.keychain_account)
                .and_then(|entry| entry.get_password())
                .map_err(|_| ())?,
        );
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?);
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded.as_str() {
            return Err(());
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(decoded.as_slice());
        Ok(secret)
    }

    fn read_native_message() -> io::Result<Option<Value>> {
        let mut length = [0_u8; 4];
        let mut stdin = io::stdin().lock();
        match stdin.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_NATIVE_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native message length",
            ));
        }
        let mut payload = vec![0_u8; length];
        stdin.read_exact(&mut payload)?;
        let value: Value = serde_json::from_slice(&payload)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid native message"))?;
        if !value.is_object() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native message",
            ));
        }
        Ok(Some(value))
    }

    fn write_native_message(message: &Value) -> io::Result<()> {
        let payload = serde_json::to_vec(message).map_err(io::Error::other)?;
        if payload.is_empty() || payload.len() > MAX_NATIVE_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native response exceeds limit",
            ));
        }
        let mut stdout = io::stdout().lock();
        stdout.write_all(&(payload.len() as u32).to_le_bytes())?;
        stdout.write_all(&payload)?;
        stdout.flush()
    }

    fn request_id_for(message: &Value) -> String {
        message
            .as_object()
            .filter(|object| object.get("kind").and_then(Value::as_str) == Some("vaultmesh.rpc"))
            .and_then(|object| object.get("requestId").and_then(Value::as_str))
            .and_then(|value| Uuid::parse_str(value).ok().map(|_| value.to_owned()))
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    }

    fn forward(
        config: &HostConfig,
        secret: &[u8; 32],
        request_id: &str,
        message: &Value,
    ) -> Result<Value, &'static str> {
        let encoded_message = serde_json::to_vec(message).map_err(|_| "invalid-message")?;
        let payload = URL_SAFE_NO_PAD.encode(encoded_message);
        let body = serde_json::to_vec(&AuthenticatedBody {
            request_id,
            payload: &payload,
        })
        .map_err(|_| "invalid-message")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "unpaired")?;
        mac.update(&body);
        let auth = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let mut envelope = serde_json::to_vec(&BrokerEnvelope {
            request_id,
            auth,
            payload: &payload,
        })
        .map_err(|_| "invalid-message")?;
        envelope.push(b'\n');
        if envelope.len() > MAX_BROKER_LINE_BYTES {
            return Err("invalid-message");
        }

        let pipe = connect_pipe(&config.broker_pipe).map_err(|_| "desktop-unavailable")?;
        write_all(pipe.0, &envelope).map_err(|_| "desktop-unavailable")?;
        let response = read_response(pipe.0).map_err(|_| "desktop-unavailable")?;
        serde_json::from_slice(&response).map_err(|_| "invalid-broker-response")
    }

    fn connect_pipe(pipe_name: &str) -> io::Result<OwnedHandle> {
        let name = wide(pipe_name);
        if unsafe { WaitNamedPipeW(name.as_ptr(), 2_000) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedHandle(handle))
        }
    }

    fn write_all(pipe: HANDLE, bytes: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + BROKER_WRITE_DEADLINE;
        let mut offset = 0;
        while offset < bytes.len() {
            let written = write_chunk(pipe, &bytes[offset..], deadline)?;
            offset += written as usize;
        }
        Ok(())
    }

    fn read_response(pipe: HANDLE) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + BROKER_RESPONSE_DEADLINE;
        let mut response = Vec::new();
        let mut chunk = vec![0_u8; MAX_BROKER_LINE_BYTES + 1];
        loop {
            let read = read_chunk(pipe, &mut chunk, deadline)?;
            if let Some(completed) = append_response_chunk(&mut response, &chunk[..read as usize])?
            {
                return Ok(completed);
            }
        }
    }

    fn write_chunk(pipe: HANDLE, bytes: &[u8], deadline: Instant) -> io::Result<u32> {
        let event = create_io_event()?;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0;
        let started = unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                bytes.len() as u32,
                null_mut(),
                &mut overlapped,
            )
        };
        complete_overlapped(
            pipe,
            &mut overlapped,
            started,
            deadline,
            "broker write timed out",
        )
    }

    fn read_chunk(pipe: HANDLE, bytes: &mut [u8], deadline: Instant) -> io::Result<u32> {
        let event = create_io_event()?;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0;
        let started = unsafe {
            ReadFile(
                pipe,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                null_mut(),
                &mut overlapped,
            )
        };
        complete_overlapped(
            pipe,
            &mut overlapped,
            started,
            deadline,
            "broker response deadline exceeded",
        )
    }

    fn create_io_event() -> io::Result<OwnedHandle> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedHandle(event))
        }
    }

    fn complete_overlapped(
        pipe: HANDLE,
        overlapped: &mut OVERLAPPED,
        started: i32,
        deadline: Instant,
        timeout_message: &'static str,
    ) -> io::Result<u32> {
        if started == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, timeout_message))?;
        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        let mut transferred = 0_u32;
        if unsafe { GetOverlappedResultEx(pipe, overlapped, &mut transferred, timeout_ms, 0) } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                unsafe {
                    CancelIoEx(pipe, overlapped);
                    GetOverlappedResult(pipe, overlapped, &mut transferred, 1);
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
            }
            return Err(error);
        }
        if transferred == 0 {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker pipe closed without data",
            ))
        } else {
            Ok(transferred)
        }
    }

    fn append_response_chunk(response: &mut Vec<u8>, chunk: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
            response.extend_from_slice(&chunk[..newline]);
            if response.is_empty() || response.len() > MAX_BROKER_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid broker response",
                ));
            }
            return Ok(Some(std::mem::take(response)));
        }
        response.extend_from_slice(chunk);
        if response.len() > MAX_BROKER_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker response too large",
            ));
        }
        Ok(None)
    }

    fn correlate_response(message: &Value, request_id: &str, response: Value) -> Value {
        if message.get("kind").and_then(Value::as_str) != Some("vaultmesh.rpc") {
            return response;
        }
        if response.get("kind").and_then(Value::as_str) == Some("vaultmesh.rpc-result")
            && response.get("requestId").and_then(Value::as_str) == Some(request_id)
        {
            return response;
        }
        if response.get("kind").and_then(Value::as_str) == Some("vaultmesh.host-status")
            && response.get("status").and_then(Value::as_str).is_some()
        {
            let mut object = response.as_object().cloned().unwrap_or_default();
            object.insert("requestId".into(), Value::String(request_id.to_owned()));
            return Value::Object(object);
        }
        host_status("invalid-broker-response", Some(request_id))
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

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{ptr::null_mut, thread};
        use windows_sys::Win32::{
            Foundation::{ERROR_PIPE_CONNECTED, GetLastError},
            Storage::FileSystem::PIPE_ACCESS_DUPLEX,
            System::Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
                PIPE_TYPE_BYTE, PIPE_WAIT,
            },
        };

        #[test]
        fn browser_launch_requires_exact_chromium_origin_or_firefox_manifest_and_id() {
            let config = HostConfig {
                version: 2,
                broker_pipe: EXPECTED_PIPE.to_owned(),
                keychain_service: EXPECTED_KEYCHAIN_SERVICE.to_owned(),
                keychain_account: EXPECTED_KEYCHAIN_ACCOUNT.to_owned(),
                chromium_allowed_origin: format!("chrome-extension://{DEFAULT_EXTENSION_ID}/"),
                firefox_extension_id: DEFAULT_FIREFOX_EXTENSION_ID.to_owned(),
                firefox_manifest_path: PathBuf::from(
                    r"C:\Users\test\AppData\Roaming\com.vaultmesh.desktop\com.vaultmesh.browser.firefox.json",
                ),
            };
            assert!(valid_browser_launch(
                &config,
                &[config.chromium_allowed_origin.clone()]
            ));
            assert!(valid_browser_launch(
                &config,
                &[
                    config.firefox_manifest_path.display().to_string(),
                    config.firefox_extension_id.clone(),
                ]
            ));
            assert!(!valid_browser_launch(
                &config,
                &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".to_owned()]
            ));
            assert!(!valid_browser_launch(
                &config,
                &[
                    config.firefox_manifest_path.display().to_string(),
                    "other@example.test".to_owned(),
                ]
            ));
        }

        #[test]
        fn reads_chunked_response_when_broker_disconnects_after_write() {
            let pipe_name = format!(r"\\.\pipe\VaultMesh.NativeHost.test.{}", Uuid::new_v4());
            let encoded_pipe_name = wide(&pipe_name);
            let server = unsafe {
                CreateNamedPipeW(
                    encoded_pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    64 * 1024,
                    64 * 1024,
                    1_000,
                    null_mut(),
                )
            };
            assert_ne!(server, INVALID_HANDLE_VALUE);
            let server = OwnedHandle(server);
            let mut expected = br#"{"kind":"vaultmesh.rpc-result","padding":""#.to_vec();
            expected.extend(std::iter::repeat_n(b'x', 16 * 1024));
            expected.extend_from_slice(br#"","ok":true}"#);
            let mut framed = expected.clone();
            framed.push(b'\n');

            let worker = thread::spawn(move || {
                let connected = unsafe { ConnectNamedPipe(server.raw(), null_mut()) };
                assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
                thread::sleep(Duration::from_millis(2));
                let mut offset = 0;
                while offset < framed.len() {
                    let chunk_len = (framed.len() - offset).min(8 * 1024);
                    let mut written = 0_u32;
                    assert_ne!(
                        unsafe {
                            WriteFile(
                                server.raw(),
                                framed[offset..].as_ptr(),
                                chunk_len as u32,
                                &mut written,
                                null_mut(),
                            )
                        },
                        0
                    );
                    assert_ne!(written, 0);
                    offset += written as usize;
                    if offset < framed.len() {
                        thread::sleep(Duration::from_millis(2));
                    }
                }
                unsafe {
                    DisconnectNamedPipe(server.raw());
                }
            });

            let client = connect_pipe(&pipe_name).expect("connect client");
            assert_eq!(read_response(client.0).expect("read response"), expected);
            worker.join().expect("server worker");
        }

        #[test]
        fn response_chunks_remain_bounded_and_require_content() {
            let mut response = Vec::new();
            assert!(append_response_chunk(&mut response, b"\n").is_err());

            let mut response = vec![b'x'; MAX_BROKER_LINE_BYTES];
            assert!(append_response_chunk(&mut response, b"x").is_err());
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_host {
    use crate::{BITWARDEN_DEVELOPMENT_HOST as DEV, development_identity as dev};
    use std::{
        fs,
        io::{self, Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        path::{Path, PathBuf},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac as _};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value, json};
    use sha2::Sha256;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    const CONFIG_NAME: &str = if DEV { dev::CONFIG_NAME } else { "browser-host-config.json" };
    const APP_DATA_NAME: &str = "com.vaultmesh.desktop";
    const DEFAULT_FIREFOX_EXTENSION_ID: &str = "vaultmesh@atlantis-mk.github.io";
    const FIREFOX_MANIFEST_NAME: &str = if DEV { "com.vaultmesh.bitwarden.dev.json" } else { "com.vaultmesh.browser.json" };
    const MAX_CONFIG_BYTES: u64 = 4096;
    const MAX_NATIVE_REQUEST_BYTES: usize = 256 * 1024;
    const MAX_NATIVE_RESPONSE_BYTES: usize = 1024 * 1024;
    const MAX_BROKER_LINE_BYTES: usize = 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct HostConfig {
        version: u8,
        broker_socket: PathBuf,
        keychain_service: String,
        keychain_account: String,
        chromium_allowed_origin: String,
        firefox_extension_id: String,
        firefox_manifest_path: PathBuf,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthenticatedBody<'a> {
        request_id: &'a str,
        payload: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BrokerEnvelope<'a> {
        request_id: &'a str,
        auth: String,
        payload: &'a str,
    }

    pub fn run_host() {
        if run().is_err() {
            let _ = write_native_message(&host_status("unpaired", None));
        }
    }

    fn run() -> Result<(), ()> {
        if DEV && !cfg!(debug_assertions) { return Err(()); }
        let config = load_config().map_err(|_| ())?;
        let launch_arguments: Vec<String> = std::env::args().skip(1).collect();
        if !valid_browser_launch(&config, &launch_arguments) {
            return Err(());
        }
        let secret = load_pairing_secret(&config).map_err(|_| ())?;

        loop {
            let message = match read_native_message() {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(()),
                Err(_) => {
                    write_native_message(&host_status("invalid-message", None)).map_err(|_| ())?;
                    return Ok(());
                }
            };
            let request_id = request_id_for(&message);
            let response = forward(&config, &secret, &request_id, &message)
                .unwrap_or_else(|status| host_status(status, Some(&request_id)));
            let response = correlate_response(&message, &request_id, response);
            write_native_message(&response).map_err(|_| ())?;
        }
    }

    fn load_config() -> io::Result<HostConfig> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing home directory"))?;
        let path = home
            .join("Library")
            .join("Application Support")
            .join(APP_DATA_NAME)
            .join(CONFIG_NAME);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid host configuration",
            ));
        }
        let bytes = fs::read(path)?;
        let config: HostConfig = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid host configuration")
        })?;
        let expected_firefox_manifest = home
            .join("Library")
            .join("Application Support")
            .join("Mozilla")
            .join("NativeMessagingHosts")
            .join(FIREFOX_MANIFEST_NAME);
        if config.version != 2
            || !valid_service_component(&config.keychain_service)
            || !valid_service_component(&config.keychain_account)
            || !valid_extension_origin(&config.chromium_allowed_origin)
            || config.firefox_extension_id != compiled_firefox_extension_id()?
            || config.firefox_manifest_path != expected_firefox_manifest
            || !valid_socket_path(&config.broker_socket)
            || (DEV && (config.keychain_service != dev::PAIRING_SERVICE
                || config.keychain_account != dev::PAIRING_ACCOUNT
                || config.chromium_allowed_origin != format!("chrome-extension://{}/", dev::EXTENSION_ID)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid host configuration",
            ));
        }
        Ok(config)
    }

    fn valid_service_component(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    }

    fn valid_extension_origin(value: &str) -> bool {
        value
            .strip_prefix("chrome-extension://")
            .and_then(|value| value.strip_suffix('/'))
            .is_some_and(|id| {
                id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
            })
    }

    fn compiled_firefox_extension_id() -> io::Result<&'static str> {
        if DEV { return Ok(dev::FIREFOX_ID); }
        let value =
            option_env!("VAULTMESH_FIREFOX_EXTENSION_ID").unwrap_or(DEFAULT_FIREFOX_EXTENSION_ID);
        (value == DEFAULT_FIREFOX_EXTENSION_ID)
            .then_some(value)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Firefox extension ID")
            })
    }

    fn valid_browser_launch(config: &HostConfig, arguments: &[String]) -> bool {
        if matches!(arguments, [origin] if origin == &config.chromium_allowed_origin) {
            return true;
        }
        matches!(arguments, [manifest_path, extension_id]
            if PathBuf::from(manifest_path) == config.firefox_manifest_path
                && extension_id == &config.firefox_extension_id)
    }

    #[cfg(test)]
    mod launch_tests {
        use super::*;

        #[test]
        fn requires_exact_chromium_origin_or_firefox_manifest_and_id() {
            let config = HostConfig {
                version: 2,
                broker_socket: PathBuf::from("/tmp/vaultmesh-tauri-browser.sock"),
                keychain_service: "com.vaultmesh.desktop.browser-pairing".to_owned(),
                keychain_account: "native-host-hmac-v1".to_owned(),
                chromium_allowed_origin: "chrome-extension://dmmjcaemejijgkpginfccokjmbknbgif/"
                    .to_owned(),
                firefox_extension_id: DEFAULT_FIREFOX_EXTENSION_ID.to_owned(),
                firefox_manifest_path: PathBuf::from(
                    "/Users/test/Library/Application Support/Mozilla/NativeMessagingHosts/com.vaultmesh.browser.json",
                ),
            };
            assert!(valid_browser_launch(
                &config,
                &[config.chromium_allowed_origin.clone()]
            ));
            assert!(valid_browser_launch(
                &config,
                &[
                    config.firefox_manifest_path.display().to_string(),
                    config.firefox_extension_id.clone(),
                ]
            ));
            assert!(!valid_browser_launch(
                &config,
                &[
                    config.firefox_manifest_path.display().to_string(),
                    "other@example.test".to_owned(),
                ]
            ));
            assert!(!valid_browser_launch(
                &config,
                &[
                    config.chromium_allowed_origin.clone(),
                    config.firefox_extension_id.clone(),
                ]
            ));
        }
    }

    fn valid_socket_path(path: &Path) -> bool {
        path.is_absolute()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value == if DEV { dev::SOCKET_NAME } else { "vaultmesh-tauri-browser.sock" })
    }

    fn load_pairing_secret(config: &HostConfig) -> Result<Zeroizing<[u8; 32]>, ()> {
        let encoded = Zeroizing::new(
            keyring::Entry::new(&config.keychain_service, &config.keychain_account)
                .and_then(|entry| entry.get_password())
                .map_err(|_| ())?,
        );
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?);
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded.as_str() {
            return Err(());
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(decoded.as_slice());
        Ok(secret)
    }

    fn read_native_message() -> io::Result<Option<Value>> {
        let mut length = [0_u8; 4];
        let mut stdin = io::stdin().lock();
        match stdin.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_NATIVE_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native message length",
            ));
        }
        let mut payload = vec![0_u8; length];
        stdin.read_exact(&mut payload)?;
        let value: Value = serde_json::from_slice(&payload)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid native message"))?;
        if !value.is_object() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native message",
            ));
        }
        Ok(Some(value))
    }

    fn write_native_message(message: &Value) -> io::Result<()> {
        let payload = serde_json::to_vec(message).map_err(io::Error::other)?;
        if payload.is_empty() || payload.len() > MAX_NATIVE_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native response exceeds limit",
            ));
        }
        let mut stdout = io::stdout().lock();
        stdout.write_all(&(payload.len() as u32).to_le_bytes())?;
        stdout.write_all(&payload)?;
        stdout.flush()
    }

    fn request_id_for(message: &Value) -> String {
        message
            .as_object()
            .filter(|object| object.get("kind").and_then(Value::as_str) == Some("vaultmesh.rpc"))
            .and_then(|object| object.get("requestId").and_then(Value::as_str))
            .and_then(|value| Uuid::parse_str(value).ok().map(|_| value.to_owned()))
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    }

    fn forward(
        config: &HostConfig,
        secret: &[u8; 32],
        request_id: &str,
        message: &Value,
    ) -> Result<Value, &'static str> {
        let encoded_message = serde_json::to_vec(message).map_err(|_| "invalid-message")?;
        let payload = URL_SAFE_NO_PAD.encode(encoded_message);
        let body = serde_json::to_vec(&AuthenticatedBody {
            request_id,
            payload: &payload,
        })
        .map_err(|_| "invalid-message")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "unpaired")?;
        mac.update(&body);
        let auth = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let mut envelope = serde_json::to_vec(&BrokerEnvelope {
            request_id,
            auth,
            payload: &payload,
        })
        .map_err(|_| "invalid-message")?;
        envelope.push(b'\n');

        let mut stream =
            UnixStream::connect(&config.broker_socket).map_err(|_| "desktop-unavailable")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(70)))
            .map_err(|_| "desktop-unavailable")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| "desktop-unavailable")?;
        stream
            .write_all(&envelope)
            .map_err(|_| "desktop-unavailable")?;

        let mut response = Vec::new();
        stream
            .take((MAX_BROKER_LINE_BYTES + 2) as u64)
            .read_to_end(&mut response)
            .map_err(|_| "desktop-unavailable")?;
        let newline = response
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("invalid-broker-response")?;
        if newline == 0 || newline > MAX_BROKER_LINE_BYTES {
            return Err("invalid-broker-response");
        }
        serde_json::from_slice(&response[..newline]).map_err(|_| "invalid-broker-response")
    }

    fn correlate_response(message: &Value, request_id: &str, response: Value) -> Value {
        if message.get("kind").and_then(Value::as_str) != Some("vaultmesh.rpc") {
            return response;
        }
        if response.get("kind").and_then(Value::as_str) == Some("vaultmesh.rpc-result")
            && response.get("requestId").and_then(Value::as_str) == Some(request_id)
        {
            return response;
        }
        if response.get("kind").and_then(Value::as_str) == Some("vaultmesh.host-status")
            && response.get("status").and_then(Value::as_str).is_some()
        {
            let mut object = response.as_object().cloned().unwrap_or_default();
            object.insert("requestId".into(), Value::String(request_id.to_owned()));
            return Value::Object(object);
        }
        host_status("invalid-broker-response", Some(request_id))
    }

    fn host_status(status: &str, request_id: Option<&str>) -> Value {
        let mut object = Map::from_iter([
            ("kind".into(), json!("vaultmesh.host-status")),
            ("status".into(), json!(status)),
        ]);
        if let Some(request_id) = request_id {
            object.insert("requestId".into(), json!(request_id));
        }
        Value::Object(object)
    }
}
