#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use serde_json::{Value, json};
use uuid::Uuid;

fn broker_endpoint(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    return home
        .join("Library")
        .join("Application Support")
        .join("com.vaultmesh.desktop")
        .join("agent")
        .join("broker-v1.sock");
    #[cfg(not(target_os = "macos"))]
    home.join(".local")
        .join("share")
        .join("com.vaultmesh.desktop")
        .join("agent")
        .join("broker-v1.sock")
}

fn read_json(reader: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("broker request");
    assert!(line.len() < 384 * 1024);
    serde_json::from_str(&line).expect("broker request JSON")
}

fn write_json(stream: &mut UnixStream, value: Value) {
    serde_json::to_writer(&mut *stream, &value).expect("broker response JSON");
    stream.write_all(b"\n").expect("broker response newline");
    stream.flush().expect("broker response flush");
}

fn rebind_broker(endpoint: &Path) -> UnixListener {
    if endpoint.exists() {
        fs::remove_file(endpoint).expect("remove stale broker socket");
    }
    let listener = UnixListener::bind(endpoint).expect("replacement broker socket");
    fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))
        .expect("replacement broker socket permissions");
    listener
}

fn start_broker(listener: UnixListener) -> thread::JoinHandle<Vec<Value>> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("shim connection");
        let mut reader = BufReader::new(stream.try_clone().expect("broker reader"));
        let mut requests = Vec::new();

        requests.push(read_json(&mut reader));
        write_json(&mut stream, json!({ "ok": true, "result": {} }));

        let metadata_action = read_json(&mut reader);
        assert_eq!(metadata_action["tool"], "vaultmesh_items_list_metadata");
        assert!(metadata_action.get("sessionId").is_none());
        requests.push(metadata_action);
        write_json(
            &mut stream,
            json!({
                "ok": false,
                "error": {
                    "code": "pairing-required",
                    "message": "VaultMesh requires approval of this local MCP client pairing.",
                    "retryable": true,
                    "nativeActionRequired": "approve-pairing"
                }
            }),
        );

        let retried_metadata_action = read_json(&mut reader);
        assert_eq!(
            retried_metadata_action["tool"],
            "vaultmesh_items_list_metadata"
        );
        assert!(retried_metadata_action.get("sessionId").is_none());
        requests.push(retried_metadata_action);
        write_json(
            &mut stream,
            json!({
                "ok": true,
                "result": { "items": [], "truncated": false }
            }),
        );

        let confirmation_ref = Uuid::new_v4();
        for approved in [false, true] {
            let protected_action = read_json(&mut reader);
            assert_eq!(protected_action["tool"], "vaultmesh_ssh_upload");
            assert!(protected_action.get("sessionId").is_none());
            requests.push(protected_action);
            if approved {
                assert_eq!(
                    requests.last().unwrap()["confirmationTicket"],
                    json!(confirmation_ref)
                );
                write_json(
                    &mut stream,
                    json!({ "ok": true, "result": { "status": "uploaded" } }),
                );
            } else {
                assert!(requests.last().unwrap().get("confirmationTicket").is_none());
                write_json(
                    &mut stream,
                    json!({
                        "ok": false,
                        "error": {
                            "code": "confirmation-required",
                            "message": "VaultMesh requires confirmation in the local app.",
                            "retryable": true,
                            "nativeActionRequired": "approve-confirmation",
                            "confirmationRef": confirmation_ref
                        }
                    }),
                );
            }
        }

        let revoked_action = read_json(&mut reader);
        assert_eq!(revoked_action["tool"], "vaultmesh_items_list_metadata");
        assert!(revoked_action.get("sessionId").is_none());
        requests.push(revoked_action);
        write_json(
            &mut stream,
            json!({
                "ok": false,
                "error": {
                    "code": "session-required",
                    "message": "The VaultMesh connection session is unavailable.",
                    "retryable": true
                }
            }),
        );
        requests
    })
}

fn send_mcp(stdin: &mut impl Write, value: Value) {
    serde_json::to_writer(&mut *stdin, &value).expect("MCP request JSON");
    stdin.write_all(b"\n").expect("MCP newline");
    stdin.flush().expect("MCP flush");
}

fn read_mcp(stdout: &mut impl BufRead) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).expect("MCP response");
    serde_json::from_str(&line).expect("MCP response JSON")
}

fn initialize_mcp(stdin: &mut impl Write, stdout: &mut impl BufRead, client: &str) {
    send_mcp(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": client, "version": "test" } }
        }),
    );
    let initialized = read_mcp(stdout);
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    send_mcp(
        stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
}

fn run_client(client_argument: &str, expected_wire_key: &str) {
    let root = PathBuf::from("/tmp").join(format!(
        "vm-mcp-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let home = root.join("home");
    let endpoint = broker_endpoint(&home);
    fs::create_dir_all(endpoint.parent().expect("broker parent")).expect("broker directory");
    fs::set_permissions(
        endpoint.parent().expect("broker parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("broker directory permissions");
    let listener = UnixListener::bind(&endpoint).expect("broker socket");
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
        .expect("broker socket permissions");
    let broker = start_broker(listener);

    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultmesh-agent-mcp"))
        .args(["--client", client_argument])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP shim");
    let mut stdin = child.stdin.take().expect("shim stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("shim stdout"));

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": client_argument, "version": "test" } }
        }),
    );
    let initialized = read_mcp(&mut stdout);
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    send_mcp(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    send_mcp(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    let listed = read_mcp(&mut stdout);
    let tools = listed["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 30);
    assert!(
        tools
            .iter()
            .all(|tool| tool["name"] != "vaultmesh_permission_request")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "vaultmesh_items_list_metadata")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "vaultmesh_ssh_upload")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool["inputSchema"]["additionalProperties"] == false)
    );

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": { "kind": "login" } }
        }),
    );
    let pairing = read_mcp(&mut stdout);
    assert_eq!(pairing["result"]["isError"], true);
    assert_eq!(
        pairing["result"]["structuredContent"]["code"],
        "pairing-required"
    );
    assert_eq!(
        pairing["result"]["structuredContent"]["nativeActionRequired"],
        "approve-pairing"
    );

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": { "kind": "login" } }
        }),
    );
    let called = read_mcp(&mut stdout);
    assert_eq!(called["result"]["isError"], false);
    assert_eq!(called["result"]["structuredContent"]["items"], json!([]));
    assert!(!called.to_string().contains("password"));

    let account_ref = Uuid::new_v4();
    let file_ref = Uuid::new_v4();
    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "vaultmesh_ssh_upload",
                "arguments": {
                    "accountRef": account_ref,
                    "fileRef": file_ref,
                    "remotePath": "/srv/app.bin"
                }
            }
        }),
    );
    let confirmation = read_mcp(&mut stdout);
    assert_eq!(confirmation["result"]["isError"], true);
    assert_eq!(
        confirmation["result"]["structuredContent"]["code"],
        "confirmation-required"
    );
    assert_eq!(
        confirmation["result"]["structuredContent"]["nativeActionRequired"],
        "approve-confirmation"
    );
    assert_eq!(
        confirmation["result"]["structuredContent"]["retryable"],
        true
    );
    let confirmation_ref = confirmation["result"]["structuredContent"]["confirmationRef"]
        .as_str()
        .expect("confirmation reference")
        .to_owned();

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "vaultmesh_ssh_upload",
                "arguments": {
                    "accountRef": account_ref,
                    "fileRef": file_ref,
                    "remotePath": "/srv/app.bin",
                    "confirmationTicket": confirmation_ref
                }
            }
        }),
    );
    let approved = read_mcp(&mut stdout);
    assert_eq!(approved["result"]["isError"], false);
    assert_eq!(
        approved["result"]["structuredContent"]["status"],
        "uploaded"
    );

    send_mcp(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {} }),
    );
    let revoked = read_mcp(&mut stdout);
    assert_eq!(revoked["result"]["tools"].as_array().unwrap().len(), 30);

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": {} }
        }),
    );
    let revoked_call = read_mcp(&mut stdout);
    assert_eq!(
        revoked_call["result"]["structuredContent"]["code"],
        "session-required"
    );

    drop(stdin);
    let output = child.wait_with_output().expect("shim exit");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let requests = broker.join().expect("broker thread");
    assert_eq!(requests[0]["kind"], "hello");
    assert_eq!(requests[0]["client"]["clientKey"], expected_wire_key);
    assert_eq!(requests[0]["client"].as_object().unwrap().len(), 1);
    assert_eq!(requests[1]["parameters"], json!({ "kind": "login" }));
    assert_eq!(requests[2]["parameters"], json!({ "kind": "login" }));
    assert_eq!(requests[3]["accountRef"], json!(account_ref));
    assert_eq!(requests[4]["confirmationTicket"], json!(confirmation_ref));
    assert!(
        requests[1..]
            .iter()
            .all(|request| request["protocolVersion"] == 2 && request.get("sessionId").is_none())
    );
    let broker_transcript =
        serde_json::to_string(&[&requests[1], &requests[2], &requests[3], &requests[4]])
            .expect("broker actions");
    for forbidden in ["masterPassword", "password", "privateKey", "credential"] {
        assert!(!broker_transcript.contains(forbidden));
    }

    fs::remove_dir_all(root).expect("cleanup E2E root");
}

#[test]
fn ct_agent_codex_stdio_process_discovers_calls_and_observes_revoke() {
    run_client("codex", "codex");
}

#[test]
fn ct_agent_opencode_stdio_process_discovers_calls_and_observes_revoke() {
    run_client("opencode", "opencode");
}

#[test]
fn ct_agent_custom_client_key_uses_the_same_stdio_contract() {
    run_client("cursor.team-a", "cursor.team-a");
}

#[test]
fn ct_agent_stdio_stays_alive_when_the_broker_starts_after_the_shim() {
    let root = PathBuf::from("/tmp").join(format!(
        "vm-late-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let home = root.join("home");
    let endpoint = broker_endpoint(&home);
    fs::create_dir_all(endpoint.parent().expect("broker parent")).expect("broker directory");
    fs::set_permissions(
        endpoint.parent().expect("broker parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("broker directory permissions");

    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultmesh-agent-mcp"))
        .args(["--client", "codex.late-broker"])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP shim");
    let mut stdin = child.stdin.take().expect("shim stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("shim stdout"));
    initialize_mcp(&mut stdin, &mut stdout, "codex.late-broker");

    let listener = rebind_broker(&endpoint);
    let broker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("late broker connection");
        let mut reader = BufReader::new(stream.try_clone().expect("late broker reader"));
        let hello = read_json(&mut reader);
        write_json(&mut stream, json!({ "ok": true, "result": {} }));
        let request = read_json(&mut reader);
        assert_eq!(request["tool"], "vaultmesh_items_list_metadata");
        write_json(
            &mut stream,
            json!({ "ok": true, "result": { "items": [], "connectedLate": true } }),
        );
        (hello, request)
    });

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": {} }
        }),
    );
    let response = read_mcp(&mut stdout);
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["connectedLate"],
        true
    );

    drop(stdin);
    let output = child.wait_with_output().expect("shim exit");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let (hello, request) = broker.join().expect("broker thread");
    assert_eq!(hello["client"]["clientKey"], "codex.late-broker");
    assert_eq!(request["tool"], "vaultmesh_items_list_metadata");
    fs::remove_dir_all(root).expect("cleanup E2E root");
}

#[test]
fn ct_agent_stdio_reconnects_after_app_restart_and_replays_r0_with_the_same_request_id() {
    let root = PathBuf::from("/tmp").join(format!(
        "vm-r0-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let home = root.join("home");
    let endpoint = broker_endpoint(&home);
    fs::create_dir_all(endpoint.parent().expect("broker parent")).expect("broker directory");
    fs::set_permissions(
        endpoint.parent().expect("broker parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("broker directory permissions");
    let listener = rebind_broker(&endpoint);
    let replacement_endpoint = endpoint.clone();
    let broker = thread::spawn(move || {
        let (mut first_stream, _) = listener.accept().expect("initial shim connection");
        let mut first_reader =
            BufReader::new(first_stream.try_clone().expect("initial broker reader"));
        let first_hello = read_json(&mut first_reader);
        write_json(&mut first_stream, json!({ "ok": true, "result": {} }));

        let first_request = read_json(&mut first_reader);
        assert_eq!(first_request["tool"], "vaultmesh_items_list_metadata");
        drop(first_reader);
        drop(first_stream);
        drop(listener);

        let replacement = rebind_broker(&replacement_endpoint);
        let (mut second_stream, _) = replacement.accept().expect("reconnected shim");
        let mut second_reader = BufReader::new(
            second_stream
                .try_clone()
                .expect("replacement broker reader"),
        );
        let second_hello = read_json(&mut second_reader);
        write_json(&mut second_stream, json!({ "ok": true, "result": {} }));
        let replayed_request = read_json(&mut second_reader);
        assert_eq!(replayed_request["tool"], "vaultmesh_items_list_metadata");
        assert_eq!(replayed_request["requestId"], first_request["requestId"]);
        write_json(
            &mut second_stream,
            json!({ "ok": true, "result": { "items": [], "reconnected": true } }),
        );
        (first_hello, second_hello)
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultmesh-agent-mcp"))
        .args(["--client", "codex.restart-r0"])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP shim");
    let mut stdin = child.stdin.take().expect("shim stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("shim stdout"));
    initialize_mcp(&mut stdin, &mut stdout, "codex.restart-r0");

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": {} }
        }),
    );
    let response = read_mcp(&mut stdout);
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["reconnected"], true);

    drop(stdin);
    let output = child.wait_with_output().expect("shim exit");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let (first_hello, second_hello) = broker.join().expect("broker thread");
    assert_eq!(first_hello["client"]["clientKey"], "codex.restart-r0");
    assert_eq!(second_hello["client"]["clientKey"], "codex.restart-r0");
    fs::remove_dir_all(root).expect("cleanup E2E root");
}

#[test]
fn ct_agent_stdio_does_not_replay_an_action_after_an_ambiguous_restart() {
    let root = PathBuf::from("/tmp").join(format!(
        "vm-act-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let home = root.join("home");
    let endpoint = broker_endpoint(&home);
    fs::create_dir_all(endpoint.parent().expect("broker parent")).expect("broker directory");
    fs::set_permissions(
        endpoint.parent().expect("broker parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("broker directory permissions");
    let listener = rebind_broker(&endpoint);
    let replacement_endpoint = endpoint.clone();
    let broker = thread::spawn(move || {
        let (mut first_stream, _) = listener.accept().expect("initial shim connection");
        let mut first_reader =
            BufReader::new(first_stream.try_clone().expect("initial broker reader"));
        let first_hello = read_json(&mut first_reader);
        write_json(&mut first_stream, json!({ "ok": true, "result": {} }));

        let action = read_json(&mut first_reader);
        assert_eq!(action["tool"], "vaultmesh_ssh_exec");
        drop(first_reader);
        drop(first_stream);
        drop(listener);

        let replacement = rebind_broker(&replacement_endpoint);
        let (mut second_stream, _) = replacement.accept().expect("reconnected shim");
        let mut second_reader = BufReader::new(
            second_stream
                .try_clone()
                .expect("replacement broker reader"),
        );
        let second_hello = read_json(&mut second_reader);
        write_json(&mut second_stream, json!({ "ok": true, "result": {} }));

        let next_request = read_json(&mut second_reader);
        assert_eq!(next_request["tool"], "vaultmesh_items_list_metadata");
        assert_ne!(next_request["requestId"], action["requestId"]);
        write_json(
            &mut second_stream,
            json!({ "ok": true, "result": { "items": [], "connectionReady": true } }),
        );
        (first_hello, second_hello, action)
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultmesh-agent-mcp"))
        .args(["--client", "codex.restart-action"])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP shim");
    let mut stdin = child.stdin.take().expect("shim stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("shim stdout"));
    initialize_mcp(&mut stdin, &mut stdout, "codex.restart-action");

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "vaultmesh_ssh_exec",
                "arguments": {
                    "accountRef": Uuid::new_v4(),
                    "program": "hostname",
                    "arguments": []
                }
            }
        }),
    );
    let unknown = read_mcp(&mut stdout);
    assert_eq!(unknown["result"]["isError"], true);
    assert_eq!(
        unknown["result"]["structuredContent"]["code"],
        "execution-unknown"
    );
    assert_eq!(
        unknown["result"]["structuredContent"]["executionUnknown"],
        true
    );
    assert_eq!(unknown["result"]["structuredContent"]["retryable"], false);

    send_mcp(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "vaultmesh_items_list_metadata", "arguments": {} }
        }),
    );
    let recovered = read_mcp(&mut stdout);
    assert_eq!(recovered["result"]["isError"], false);
    assert_eq!(
        recovered["result"]["structuredContent"]["connectionReady"],
        true
    );

    drop(stdin);
    let output = child.wait_with_output().expect("shim exit");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let (first_hello, second_hello, action) = broker.join().expect("broker thread");
    assert_eq!(first_hello["client"]["clientKey"], "codex.restart-action");
    assert_eq!(second_hello["client"]["clientKey"], "codex.restart-action");
    assert_eq!(action["tool"], "vaultmesh_ssh_exec");
    fs::remove_dir_all(root).expect("cleanup E2E root");
}
