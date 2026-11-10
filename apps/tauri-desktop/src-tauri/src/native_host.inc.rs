// native_host.inc.rs
// Stateless Loopback HTTP Discovery Relay for Browser Native Messaging (ADR-0056)

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::{BITWARDEN_DEVELOPMENT_HOST as DEV, development_identity as dev};

const DEFAULT_EXTENSION_ID: &str = "bdneegbnjbheblmamalplnddbodcghbg";
const DEFAULT_FIREFOX_EXTENSION_ID: &str = "vaultmesh@atlantis-mk.github.io";
const HTTP_PORT_RANGE_START: u16 = 42800;
const HTTP_PORT_RANGE_END: u16 = 42850;
const MAX_NATIVE_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_NATIVE_RESPONSE_BYTES: usize = 1024 * 1024;

fn main() {
    run_host();
}

fn expected_chromium_origin() -> String {
    if DEV {
        format!("chrome-extension://{}/", dev::EXTENSION_ID)
    } else if let Some(id) = option_env!("VAULTMESH_BROWSER_EXTENSION_ID") {
        format!("chrome-extension://{id}/")
    } else {
        format!("chrome-extension://{DEFAULT_EXTENSION_ID}/")
    }
}

fn expected_firefox_extension_id() -> String {
    if DEV {
        dev::FIREFOX_ID.to_owned()
    } else if let Some(id) = option_env!("VAULTMESH_FIREFOX_EXTENSION_ID") {
        id.to_owned()
    } else {
        DEFAULT_FIREFOX_EXTENSION_ID.to_owned()
    }
}

fn validate_browser_launch(arguments: &[String]) -> Option<String> {
    let expected_chromium = expected_chromium_origin();
    let expected_firefox = expected_firefox_extension_id();

    // Chromium launch: [origin] or [origin, parent_window]
    if let [origin] | [origin, _] = arguments {
        let clean_origin = origin.trim_end_matches('/');
        let clean_expected = expected_chromium.trim_end_matches('/');
        if clean_origin == clean_expected {
            return Some(expected_chromium);
        }
    }

    // Firefox launch: [manifest_path, extension_id]
    if let [manifest_path, extension_id] = arguments {
        if extension_id == &expected_firefox && !manifest_path.is_empty() {
            return Some(expected_firefox);
        }
    }

    None
}

pub fn run_host() {
    let launch_arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(browser_origin) = validate_browser_launch(&launch_arguments) else {
        let _ = write_native_message(&host_status("unpaired", None));
        return;
    };

    let mut cached_port: Option<u16> = None;

    loop {
        let message = match read_native_message() {
            Ok(Some(msg)) => msg,
            Ok(None) => return,
            Err(_) => {
                let _ = write_native_message(&host_status("invalid-message", None));
                return;
            }
        };

        let request_id = request_id_for(&message);
        let raw_body = serde_json::to_vec(&message).unwrap_or_default();

        let response = match send_with_retry(&mut cached_port, &browser_origin, &raw_body) {
            Ok(resp) => resp,
            Err(status) => host_status(status, Some(&request_id)),
        };

        let correlated = correlate_response(&message, &request_id, response);
        if write_native_message(&correlated).is_err() {
            return;
        }
    }
}

fn check_port(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
    let req = format!("GET /discover HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut resp = Vec::new();
    if stream.read_to_end(&mut resp).is_err() {
        return false;
    }
    let resp_str = String::from_utf8_lossy(&resp);
    resp_str.contains("200 OK") && resp_str.contains("\"service\":\"vaultmesh-desktop\"")
}

fn discover_port() -> Option<u16> {
    if let Ok(override_port) = std::env::var("VAULTMESH_BROWSER_HTTP_PORT") {
        if let Ok(p) = override_port.trim().parse::<u16>() {
            if check_port(p) {
                return Some(p);
            }
        }
    }
    for p in HTTP_PORT_RANGE_START..=HTTP_PORT_RANGE_END {
        if check_port(p) {
            return Some(p);
        }
    }
    None
}

fn send_with_retry(
    cached_port: &mut Option<u16>,
    browser_origin: &str,
    body: &[u8],
) -> Result<Value, &'static str> {
    let port = match *cached_port {
        Some(p) => p,
        None => {
            let p = discover_port().ok_or("desktop-unavailable")?;
            *cached_port = Some(p);
            p
        }
    };

    match post_rpc(port, browser_origin, body) {
        Ok(val) => Ok(val),
        Err(status) => {
            if status == "unpaired" {
                return Err("unpaired");
            }
            // Invalidate cache and retry discovery once in case desktop restarted
            *cached_port = None;
            let new_port = discover_port().ok_or("desktop-unavailable")?;
            *cached_port = Some(new_port);
            post_rpc(new_port, browser_origin, body)
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn post_rpc(port: u16, browser_origin: &str, body: &[u8]) -> Result<Value, &'static str> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|_| "desktop-unavailable")?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(70)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let request_header = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nX-VaultMesh-Browser-Origin: {browser_origin}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request_header.as_bytes()).map_err(|_| "desktop-unavailable")?;
    stream.write_all(body).map_err(|_| "desktop-unavailable")?;
    stream.flush().map_err(|_| "desktop-unavailable")?;

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).map_err(|_| "desktop-unavailable")?;

    let header_end = find_subslice(&resp_bytes, b"\r\n\r\n")
        .map(|pos| (pos, pos + 4))
        .or_else(|| find_subslice(&resp_bytes, b"\n\n").map(|pos| (pos, pos + 2)))
        .ok_or("desktop-unavailable")?;

    let header_text = std::str::from_utf8(&resp_bytes[..header_end.0]).map_err(|_| "desktop-unavailable")?;
    let status_line = header_text.lines().next().ok_or("desktop-unavailable")?;
    if status_line.contains("403") {
        return Err("unpaired");
    }
    if !status_line.contains("200") {
        return Err("desktop-unavailable");
    }

    let body_bytes = &resp_bytes[header_end.1..];
    let val: Value = serde_json::from_slice(body_bytes).map_err(|_| "invalid-message")?;
    Ok(val)
}

fn read_native_message() -> io::Result<Option<Value>> {
    let mut length_bytes = [0u8; 4];
    let mut stdin = io::stdin().lock();
    match stdin.read_exact(&mut length_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_NATIVE_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native request exceeds limit",
        ));
    }
    let mut buffer = vec![0u8; length];
    stdin.read_exact(&mut buffer)?;
    let value: Value = serde_json::from_slice(&buffer).map_err(io::Error::other)?;
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

fn host_status(status: &str, request_id: Option<&str>) -> Value {
    let mut payload = json!({
        "kind": "vaultmesh.host-status",
        "status": status,
    });
    if let Some(id) = request_id {
        payload["requestId"] = json!(id);
    }
    payload
}

fn correlate_response(request: &Value, request_id: &str, mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        if !object.contains_key("requestId") {
            object.insert("requestId".to_owned(), json!(request_id));
        }
        if let Some(input) = request.as_object() {
            if let Some(user_gesture_id) = input.get("userGestureId") {
                if !object.contains_key("userGestureId") {
                    object.insert("userGestureId".to_owned(), user_gesture_id.clone());
                }
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_launch_requires_exact_chromium_origin_or_firefox_manifest_and_id() {
        let expected_chromium = expected_chromium_origin();
        let expected_firefox = expected_firefox_extension_id();

        // Chromium: single arg or with --parent-window
        assert_eq!(
            validate_browser_launch(&[expected_chromium.clone()]),
            Some(expected_chromium.clone())
        );
        assert_eq!(
            validate_browser_launch(&[expected_chromium.trim_end_matches('/').to_owned()]),
            Some(expected_chromium.clone())
        );
        assert_eq!(
            validate_browser_launch(&[
                expected_chromium.clone(),
                "--parent-window=12345".to_owned()
            ]),
            Some(expected_chromium.clone())
        );

        // Firefox: manifest path and gecko ID
        assert_eq!(
            validate_browser_launch(&[
                "/path/to/manifest.json".to_owned(),
                expected_firefox.to_owned()
            ]),
            Some(expected_firefox.to_owned())
        );

        // Invalid origins
        assert_eq!(
            validate_browser_launch(&["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".to_owned()]),
            None
        );
        assert_eq!(
            validate_browser_launch(&[
                "/path/to/manifest.json".to_owned(),
                "other@example.com".to_owned()
            ]),
            None
        );
        assert_eq!(
            validate_browser_launch(&["https://example.com".to_owned()]),
            None
        );
    }

    #[test]
    fn correlates_response_preserves_gesture_and_request_id() {
        let req = json!({
            "kind": "vaultmesh.rpc",
            "requestId": "11111111-1111-1111-1111-111111111111",
            "userGestureId": "22222222-2222-2222-2222-222222222222",
        });
        let resp = json!({
            "ok": true,
            "result": {},
        });
        let correlated = correlate_response(&req, "11111111-1111-1111-1111-111111111111", resp);
        assert_eq!(correlated["requestId"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(correlated["userGestureId"], "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn host_status_formatting() {
        let status = host_status("desktop-unavailable", Some("test-id"));
        assert_eq!(status["kind"], "vaultmesh.host-status");
        assert_eq!(status["status"], "desktop-unavailable");
        assert_eq!(status["requestId"], "test-id");
    }
}
