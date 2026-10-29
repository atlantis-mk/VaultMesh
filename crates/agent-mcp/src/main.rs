#[cfg(not(any(unix, windows)))]
fn main() {
    std::process::exit(78);
}

#[cfg(any(unix, windows))]
fn main() {
    if server::run().is_err() {
        eprintln!("VaultMesh Agent MCP shim failed to start.");
        std::process::exit(1);
    }
}

#[cfg(any(unix, windows))]
mod server {
    use std::{
        env,
        io::{self, BufRead, Write},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(windows)]
    use std::fs::{File, OpenOptions};
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixStream,
        },
        path::{Path, PathBuf},
    };

    use serde_json::{Map, Value, json};
    use uuid::Uuid;

    const MCP_VERSION: &str = "2025-06-18";
    const AGENT_PROTOCOL_VERSION: u32 = 2;
    const MAX_MCP_LINE_BYTES: usize = 384 * 1024;
    const MAX_BROKER_LINE_BYTES: usize = 384 * 1024;
    const BROKER_RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const BROKER_RECONNECT_DELAY: Duration = Duration::from_millis(100);
    #[cfg(unix)]
    const BROKER_RESPONSE_TIMEOUT_SECS: u64 = 30;
    #[cfg(unix)]
    const _: () = assert!(BROKER_RESPONSE_TIMEOUT_SECS == 30);
    #[cfg(unix)]
    const APP_DATA_NAME: &str = "com.vaultmesh.desktop";
    #[cfg(windows)]
    const AGENT_PIPE_NAME: &str = r"\\.\pipe\VaultMesh.AgentBroker.v1";

    #[cfg(unix)]
    type BrokerStream = UnixStream;
    #[cfg(windows)]
    type BrokerStream = File;

    struct BrokerConnection {
        stream: BrokerStream,
        pending: Vec<u8>,
    }

    struct BrokerClient {
        client_key: String,
        connection: Option<BrokerConnection>,
    }

    enum BrokerCallError {
        Unavailable,
        ExecutionUnknown,
    }

    impl BrokerClient {
        fn new(client_key: String) -> Self {
            Self {
                client_key,
                connection: None,
            }
        }

        fn reconnect_once(&mut self) -> Result<(), ()> {
            self.connection = None;
            let mut connection = connect_broker()?;
            let hello_id = Uuid::new_v4();
            write_broker(
                &mut connection,
                &json!({
                    "protocolVersion": AGENT_PROTOCOL_VERSION,
                    "requestId": hello_id,
                    "kind": "hello",
                    "client": {
                        "clientKey": self.client_key
                    }
                }),
            )?;
            let hello = read_broker(&mut connection)?;
            if hello["ok"] != true {
                return Err(());
            }
            self.connection = Some(connection);
            Ok(())
        }

        fn reconnect_bounded(&mut self) -> Result<(), ()> {
            let deadline = Instant::now() + BROKER_RECONNECT_TIMEOUT;
            loop {
                if self.reconnect_once().is_ok() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(());
                }
                thread::sleep(BROKER_RECONNECT_DELAY);
            }
        }

        fn call(&mut self, request: &Value, replay_safe: bool) -> Result<Value, BrokerCallError> {
            if self.connection.is_none() {
                self.reconnect_bounded()
                    .map_err(|_| BrokerCallError::Unavailable)?;
            }

            if self.write_current(request).is_err() {
                self.connection = None;
                self.reconnect_bounded()
                    .map_err(|_| BrokerCallError::Unavailable)?;
                self.write_current(request).map_err(|_| {
                    self.connection = None;
                    BrokerCallError::Unavailable
                })?;
                return self.read_after_delivery(request, replay_safe);
            }

            self.read_after_delivery(request, replay_safe)
        }

        fn write_current(&mut self, request: &Value) -> Result<(), ()> {
            write_broker(self.connection.as_mut().ok_or(())?, request)
        }

        fn read_current(&mut self) -> Result<Value, ()> {
            read_broker(self.connection.as_mut().ok_or(())?)
        }

        fn read_after_delivery(
            &mut self,
            request: &Value,
            replay_safe: bool,
        ) -> Result<Value, BrokerCallError> {
            match self.read_current() {
                Ok(response) => Ok(response),
                Err(_) if !replay_safe => {
                    self.connection = None;
                    let _ = self.reconnect_bounded();
                    Err(BrokerCallError::ExecutionUnknown)
                }
                Err(_) => {
                    self.connection = None;
                    self.reconnect_bounded()
                        .map_err(|_| BrokerCallError::Unavailable)?;
                    self.retry_replay_safe(request)
                }
            }
        }

        fn retry_replay_safe(&mut self, request: &Value) -> Result<Value, BrokerCallError> {
            self.write_current(request).map_err(|_| {
                self.connection = None;
                BrokerCallError::Unavailable
            })?;
            self.read_current().map_err(|_| {
                self.connection = None;
                BrokerCallError::Unavailable
            })
        }
    }

    pub fn run() -> Result<(), ()> {
        let client_key = parse_arguments(env::args().skip(1))?;
        let registry: Value = serde_json::from_str(include_str!(
            "../../../apps/tauri-desktop/src/shared/agent-capabilities.json"
        ))
        .map_err(|_| ())?;
        let mut broker = BrokerClient::new(client_key);
        let _ = broker.reconnect_once();

        let stdin = io::stdin();
        let mut initialized = false;
        for line in stdin.lock().lines() {
            let line = line.map_err(|_| ())?;
            if line.len() > MAX_MCP_LINE_BYTES || line.contains(['\n', '\r']) {
                return Err(());
            }
            let message: Value = match serde_json::from_str::<Value>(&line) {
                Ok(value) if value.is_object() => value,
                _ => {
                    write_mcp(&json_rpc_error(Value::Null, -32700, "Parse error"))?;
                    continue;
                }
            };
            let Some(method) = message.get("method").and_then(Value::as_str) else {
                continue;
            };
            let id = message.get("id").cloned();
            if id.is_none() {
                if method == "notifications/initialized" {
                    initialized = true;
                }
                continue;
            }
            let id = id.unwrap_or(Value::Null);
            let response = match method {
                "initialize" => initialize_response(id, &message),
                "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
                _ if !initialized => json_rpc_error(id, -32002, "Server is not initialized"),
                "tools/list" => tools_list_response(id, &registry),
                "tools/call" => tools_call_response(id, &registry, &message, &mut broker),
                _ => json_rpc_error(id, -32601, "Method not found"),
            };
            write_mcp(&response)?;
        }
        Ok(())
    }

    fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<String, ()> {
        let arguments = arguments.collect::<Vec<_>>();
        let mut client = None;
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--client" if index + 1 < arguments.len() => {
                    let value = arguments[index + 1].clone();
                    if !valid_client_key(&value) {
                        return Err(());
                    }
                    client = Some(value);
                    index += 2;
                }
                _ => return Err(()),
            }
        }
        client.ok_or(())
    }

    fn valid_client_key(value: &str) -> bool {
        (3..=128).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
            })
    }

    #[cfg(unix)]
    fn connect_broker() -> Result<BrokerConnection, ()> {
        let endpoint = broker_endpoint()?;
        validate_endpoint(&endpoint)?;
        let stream = UnixStream::connect(endpoint).map_err(|_| ())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(BROKER_RESPONSE_TIMEOUT_SECS)))
            .map_err(|_| ())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ())?;
        Ok(BrokerConnection {
            stream,
            pending: Vec::new(),
        })
    }

    #[cfg(windows)]
    fn connect_broker() -> Result<BrokerConnection, ()> {
        let stream = OpenOptions::new()
            .read(true)
            .write(true)
            .open(AGENT_PIPE_NAME)
            .map_err(|_| ())?;
        Ok(BrokerConnection {
            stream,
            pending: Vec::new(),
        })
    }

    #[cfg(unix)]
    fn broker_endpoint() -> Result<PathBuf, ()> {
        let home = env::var_os("HOME").map(PathBuf::from).ok_or(())?;
        #[cfg(target_os = "macos")]
        return Ok(home
            .join("Library")
            .join("Application Support")
            .join(APP_DATA_NAME)
            .join("agent")
            .join("broker-v1.sock"));
        #[cfg(not(target_os = "macos"))]
        Ok(home
            .join(".local")
            .join("share")
            .join(APP_DATA_NAME)
            .join("agent")
            .join("broker-v1.sock"))
    }

    #[cfg(unix)]
    fn validate_endpoint(path: &Path) -> Result<(), ()> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        let parent = path.parent().ok_or(())?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != uid
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(());
        }
        Ok(())
    }

    fn initialize_response(id: Value, message: &Value) -> Value {
        let requested = message
            .pointer("/params/protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(MCP_VERSION);
        let protocol_version = if matches!(requested, "2025-06-18" | "2025-03-26") {
            requested
        } else {
            MCP_VERSION
        };
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": protocol_version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "vaultmesh-agent", "title": "VaultMesh Agent Capability Broker", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "VaultMesh exposes a stable action catalog, but tool visibility never grants authority. On pairing-required/approve-pairing, tell the user to approve the MCP client pairing window; this is pairing, not action authorization. After pairing, retry the same tool call unchanged. Search or filter vaultmesh_accounts_list for safe account metadata; its capabilities filter uses semantic capability names from the public catalog, such as ssh-exec, while actions[].tools contains callable tool names. Accounts never need preauthorization to appear. Select the exact accountRef and call the desired action tool directly so VaultMesh can request action authorization. Never look for or require an already-authorized account. During action authorization, wait for the same tool call for up to 30 seconds while VaultMesh shows its separate global authorization window; approval continues that call automatically. On authorization-timeout, report that the current call failed; the window remains open, and any later authorization applies to an explicit retry. If the user selects allow once after timeout, it allows only the next matching call once. On vault-locked, tell the user to unlock VaultMesh locally, then retry the same tool call unchanged; do not reconnect or pair again. After a VaultMesh restart, the shim reconnects automatically with the same paired client key and a new connection session. On broker-restarting, wait for VaultMesh to finish starting and retry. On execution-unknown, do not automatically repeat the operation; check the target state before an explicit retry. VaultMesh builds the target and policy and never returns credentials. Do not request or invent a second account configuration. Never supply target, host key, policy, risk, permission scope, or display fields."
            }
        })
    }

    fn tools_list_response(id: Value, registry: &Value) -> Value {
        let tools = registry["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(mcp_tool)
            .collect::<Vec<_>>();
        json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": tools } })
    }

    fn tools_call_response(
        id: Value,
        registry: &Value,
        message: &Value,
        broker: &mut BrokerClient,
    ) -> Value {
        let Some(name) = message.pointer("/params/name").and_then(Value::as_str) else {
            return json_rpc_error(id, -32602, "Invalid tool request");
        };
        let Some(tool) = registry["tools"]
            .as_array()
            .and_then(|tools| tools.iter().find(|tool| tool["name"] == name))
        else {
            return json_rpc_error(id, -32602, "Unknown tool");
        };
        let mut arguments = message
            .pointer("/params/arguments")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let account_ref = arguments.remove("accountRef");
        let confirmation_ticket = arguments.remove("confirmationTicket");
        let mut request = Map::from_iter([
            ("protocolVersion".into(), json!(AGENT_PROTOCOL_VERSION)),
            ("requestId".into(), json!(Uuid::new_v4())),
            ("tool".into(), json!(name)),
            ("toolVersion".into(), tool["version"].clone()),
            ("parameters".into(), Value::Object(arguments)),
        ]);
        if let Some(account_ref) = account_ref {
            request.insert("accountRef".into(), account_ref);
        }
        if let Some(confirmation_ticket) = confirmation_ticket {
            request.insert("confirmationTicket".into(), confirmation_ticket);
        }
        let request = Value::Object(request);
        let replay_safe = tool["risk"] == "R0";
        let response = match broker.call(&request, replay_safe) {
            Ok(response) => response,
            Err(BrokerCallError::Unavailable) => return broker_unavailable_error(id),
            Err(BrokerCallError::ExecutionUnknown) => return execution_unknown_error(id),
        };
        if response["ok"] == true {
            let structured = response.get("result").cloned().unwrap_or_else(|| json!({}));
            let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".into());
            json!({ "jsonrpc": "2.0", "id": id, "result": {
                "content": [{ "type": "text", "text": text }],
                "structuredContent": structured,
                "isError": false
            } })
        } else {
            broker_tool_error(id, &response)
        }
    }

    fn mcp_tool(tool: &Value) -> Option<Value> {
        let name = tool["name"].as_str()?;
        let requires_account = tool["requiresAccount"].as_bool()?;
        let mut properties = Map::new();
        let mut required = Vec::new();
        for parameter in tool["parameters"].as_array()? {
            let parameter_name = parameter["name"].as_str()?;
            let parameter_schema = match parameter["type"].as_str()? {
                "integer" => json!({ "type": "integer", "minimum": 0 }),
                "object" => json!({ "type": "object" }),
                "string-array" => json!({
                    "type": "array",
                    "items": { "type": "string", "maxLength": parameter.get("maxLength") },
                    "maxItems": parameter.get("maxItems")
                }),
                "string" => json!({ "type": "string", "maxLength": parameter.get("maxLength") }),
                _ => return None,
            };
            properties.insert(parameter_name.into(), parameter_schema);
            if parameter["required"] == true {
                required.push(parameter_name);
            }
        }
        if requires_account {
            properties.insert(
                "accountRef".into(),
                json!({ "type": "string", "maxLength": 128 }),
            );
            required.push("accountRef");
        }
        if tool["confirmation"] != "none" {
            properties.insert(
                "confirmationTicket".into(),
                json!({ "type": "string", "maxLength": 128 }),
            );
        }
        let is_deprecated = tool.get("deprecated").and_then(Value::as_bool).unwrap_or(false);
        let description = if name == "vaultmesh_accounts_list" {
            "Search non-secret account metadata. Filter capabilities with semantic catalog names such as ssh-agent; use actions[].tools for callable tool names. Accounts do not need prior action authorization to appear."
                .to_owned()
        } else if is_deprecated {
            format!(
                "[已废弃 / Deprecated: 推荐使用 vaultmesh_ssh_agent_open] VaultMesh {} capability ({}); credentials are never returned.",
                tool["capability"].as_str()?,
                tool["risk"].as_str()?
            )
        } else if name == "vaultmesh_ssh_agent_open" {
            "Open an ephemeral local OpenSSH agent session (Unix socket / Windows named pipe) for native SSH tools (ssh, rsync, scp, sftp, git). No private keys are ever returned to the agent.".to_owned()
        } else if name == "vaultmesh_ssh_agent_close" {
            "Close an active ephemeral local OpenSSH agent session early and remove its socket.".to_owned()
        } else {
            format!(
                "VaultMesh {} capability ({}); credentials are never returned.",
                tool["capability"].as_str()?,
                tool["risk"].as_str()?
            )
        };
        let mut tool_obj = json!({
            "name": name,
            "title": name.trim_start_matches("vaultmesh_").replace('_', " "),
            "description": description,
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": properties,
                "required": required
            }
        });
        if is_deprecated {
            tool_obj["annotations"] = json!({ "deprecated": true });
        }
        Some(tool_obj)
    }

    fn write_broker(connection: &mut BrokerConnection, value: &Value) -> Result<(), ()> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| ())?;
        if bytes.len() > MAX_BROKER_LINE_BYTES {
            return Err(());
        }
        bytes.push(b'\n');
        connection.stream.write_all(&bytes).map_err(|_| ())
    }

    fn read_broker(connection: &mut BrokerConnection) -> Result<Value, ()> {
        loop {
            if let Some(newline) = connection.pending.iter().position(|byte| *byte == b'\n') {
                let frame = connection.pending.drain(..=newline).collect::<Vec<_>>();
                return serde_json::from_slice(&frame[..frame.len() - 1]).map_err(|_| ());
            }
            if connection.pending.len() > MAX_BROKER_LINE_BYTES {
                return Err(());
            }
            let mut chunk = [0_u8; 8 * 1024];
            let read = io::Read::read(&mut connection.stream, &mut chunk).map_err(|_| ())?;
            if read == 0 {
                return Err(());
            }
            connection.pending.extend_from_slice(&chunk[..read]);
        }
    }

    fn write_mcp(value: &Value) -> Result<(), ()> {
        let mut stdout = io::stdout().lock();
        serde_json::to_writer(&mut stdout, value).map_err(|_| ())?;
        stdout.write_all(b"\n").map_err(|_| ())?;
        stdout.flush().map_err(|_| ())
    }

    fn json_rpc_error(id: Value, code: i32, message: &'static str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
    }

    fn broker_unavailable_error(id: Value) -> Value {
        tool_error_with_structured(
            id,
            "broker-restarting",
            "VaultMesh is restarting or its Agent broker is not ready. Retry the call after VaultMesh finishes starting.",
            json!({
                "code": "broker-restarting",
                "message": "VaultMesh is restarting or its Agent broker is not ready. Retry the call after VaultMesh finishes starting.",
                "retryable": true
            }),
        )
    }

    fn execution_unknown_error(id: Value) -> Value {
        tool_error_with_structured(
            id,
            "execution-unknown",
            "The Agent broker connection closed after the operation was sent, so VaultMesh cannot prove whether it completed. Check the target state before explicitly retrying.",
            json!({
                "code": "execution-unknown",
                "message": "The Agent broker connection closed after the operation was sent, so VaultMesh cannot prove whether it completed. Check the target state before explicitly retrying.",
                "retryable": false,
                "executionUnknown": true,
                "details": {
                    "retryHint": "Check the target state before explicitly retrying this operation."
                }
            }),
        )
    }

    fn broker_tool_error(id: Value, response: &Value) -> Value {
        let code = response
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("operation-failed");
        let message = response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("VaultMesh denied the Agent operation.");
        let mut structured = Map::from_iter([
            ("code".into(), json!(code)),
            ("message".into(), json!(message)),
        ]);
        if let Some(retryable) = response
            .pointer("/error/retryable")
            .and_then(Value::as_bool)
        {
            structured.insert("retryable".into(), json!(retryable));
        }
        for field in ["nativeActionRequired", "confirmationRef"] {
            if let Some(value) = response
                .pointer(&format!("/error/{field}"))
                .and_then(Value::as_str)
            {
                structured.insert(field.into(), json!(value));
            }
        }
        if let Some(source) = response
            .pointer("/error/details")
            .and_then(Value::as_object)
        {
            let mut details = Map::new();
            for field in ["missingFields", "allowedSources"] {
                if let Some(values) = source.get(field).and_then(Value::as_array) {
                    let values = values
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|value| value.len() <= 256)
                        .take(16)
                        .map(|value| json!(value))
                        .collect::<Vec<_>>();
                    if !values.is_empty() {
                        details.insert(field.into(), Value::Array(values));
                    }
                }
            }
            if let Some(retry_hint) = source
                .get("retryHint")
                .and_then(Value::as_str)
                .filter(|value| value.len() <= 512)
            {
                details.insert("retryHint".into(), json!(retry_hint));
            }
            if !details.is_empty() {
                structured.insert("details".into(), Value::Object(details));
            }
        }
        tool_error_with_structured(id, code, message, Value::Object(structured))
    }

    fn tool_error_with_structured(
        id: Value,
        code: &str,
        message: &str,
        structured: Value,
    ) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "result": {
            "content": [{ "type": "text", "text": format!("{code}: {message}") }],
            "structuredContent": structured,
            "isError": true
        } })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ct_agent_codex_registry_generates_strict_mcp_tools_without_secret_getters() {
            let registry: Value = serde_json::from_str(include_str!(
                "../../../apps/tauri-desktop/src/shared/agent-capabilities.json"
            ))
            .unwrap();
            let tools = registry["tools"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(mcp_tool)
                .collect::<Vec<_>>();
            assert_eq!(tools.len(), 30);
            let serialized = serde_json::to_string(&tools).unwrap();
            assert!(!serialized.contains("get_password"));
            assert!(!serialized.contains("export_secret"));
            assert!(
                tools
                    .iter()
                    .all(|tool| tool["inputSchema"]["additionalProperties"] == false)
            );
            let accounts = tools
                .iter()
                .find(|tool| tool["name"] == "vaultmesh_accounts_list")
                .unwrap();
            assert!(
                accounts["description"]
                    .as_str()
                    .unwrap()
                    .contains("semantic catalog names such as ssh-agent")
            );
            let ssh_exec = tools
                .iter()
                .find(|tool| tool["name"] == "vaultmesh_ssh_exec")
                .unwrap();
            assert!(
                ssh_exec["description"]
                    .as_str()
                    .unwrap()
                    .contains("[已废弃 / Deprecated: 推荐使用 vaultmesh_ssh_agent_open]")
            );
            assert_eq!(ssh_exec["annotations"]["deprecated"], true);
            let ssh_agent_open = tools
                .iter()
                .find(|tool| tool["name"] == "vaultmesh_ssh_agent_open")
                .unwrap();
            assert!(
                ssh_agent_open["description"]
                    .as_str()
                    .unwrap()
                    .contains("Open an ephemeral local OpenSSH agent session")
            );
            assert!(accounts["inputSchema"]["properties"]["permission"].is_null());
        }

        #[test]
        fn ct_agent_custom_client_key_is_the_only_supported_identity_argument() {
            let client =
                parse_arguments(vec!["--client".into(), "cursor.team-a".into()].into_iter())
                    .unwrap();
            assert_eq!(client, "cursor.team-a");
            assert!(
                parse_arguments(vec!["--client".into(), "bad key".into()].into_iter()).is_err()
            );
            assert!(
                parse_arguments(
                    vec![
                        "--client".into(),
                        "cursor.team-a".into(),
                        "--workspace".into(),
                        "/tmp".into()
                    ]
                    .into_iter()
                )
                .is_err()
            );
            assert!(
                parse_arguments(vec!["--endpoint".into(), "/tmp/evil".into()].into_iter()).is_err()
            );
        }

        #[test]
        fn ct_agent_initialize_uses_direct_actions_without_a_configuration_prerequisite() {
            let response = initialize_response(
                json!(1),
                &json!({ "params": { "protocolVersion": "2025-06-18" } }),
            );
            let instructions = response["result"]["instructions"].as_str().unwrap();
            assert!(instructions.contains("call the desired action tool directly"));
            assert!(instructions.contains("Accounts never need preauthorization to appear"));
            assert!(instructions.contains("such as ssh-exec"));
            assert!(instructions.contains("wait for the same tool call for up to 30 seconds"));
            assert!(instructions.contains("On vault-locked"));
            assert!(instructions.contains("do not reconnect or pair again"));
            assert!(instructions.contains("the shim reconnects automatically"));
            assert!(instructions.contains("On execution-unknown"));
            assert!(
                instructions.contains("Do not request or invent a second account configuration")
            );
            assert!(!instructions.contains("vaultmesh_permission_request"));
        }

        #[test]
        fn ct_agent_permission_error_forwards_only_bounded_retry_details() {
            let response = broker_tool_error(
                json!(7),
                &json!({
                    "error": {
                        "code": "action-input-insufficient",
                        "message": "The account does not contain enough metadata for a direct action plan.",
                        "retryable": true,
                        "details": {
                            "missingFields": ["login.url (exact HTTPS URL)"],
                            "allowedSources": ["vault-item", "built-in-rule"],
                            "retryHint": "Update the Vault item, then retry the same action.",
                            "unsafeTarget": "https://attacker.invalid"
                        }
                    }
                }),
            );

            let structured = &response["result"]["structuredContent"];
            assert_eq!(structured["code"], "action-input-insufficient");
            assert_eq!(structured["retryable"], true);
            assert_eq!(
                structured["details"]["missingFields"],
                json!(["login.url (exact HTTPS URL)"])
            );
            assert_eq!(
                structured["details"]["allowedSources"],
                json!(["vault-item", "built-in-rule"])
            );
            assert!(
                structured["details"]["retryHint"]
                    .as_str()
                    .unwrap()
                    .contains("retry the same action")
            );
            assert!(structured["details"].get("unsafeTarget").is_none());
        }
    }
}
