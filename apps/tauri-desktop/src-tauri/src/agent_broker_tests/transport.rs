use super::super::agent_broker_transport::{
    UnixMonitorEvent, configure_unix_connection, read_line, read_line_with_deadline,
    signal_unix_monitor, wait_for_unix_monitor_event, write_json_line,
};
use super::*;

#[cfg(unix)]
#[test]
fn ct_agent_transport_clears_inherited_nonblocking_mode_before_idle_read() {
    let (mut reader, _writer) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();

    configure_unix_connection(&reader).unwrap();
    let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(flags & libc::O_NONBLOCK, 0);

    let started = Instant::now();
    let error = reader.read_exact(&mut [0_u8; 1]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[cfg(unix)]
#[test]
fn ct_agent_transport_disconnect_monitor_parks_until_a_frame_is_consumed() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let (wake_reader, wake_writer) = UnixStream::pair().unwrap();
    wake_reader.set_nonblocking(true).unwrap();
    wake_writer.set_nonblocking(true).unwrap();
    writer.write_all(b"x").unwrap();

    assert_eq!(
        wait_for_unix_monitor_event(&reader, &wake_reader, true).unwrap(),
        UnixMonitorEvent::PeerReadable
    );

    let (event_sender, event_receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let event = wait_for_unix_monitor_event(&reader, &wake_reader, false).unwrap();
        let _ = event_sender.send(event);
    });
    assert!(
        event_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err()
    );
    signal_unix_monitor(&wake_writer);
    assert_eq!(
        event_receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
        UnixMonitorEvent::Wake
    );
}

#[cfg(unix)]
#[test]
fn ct_agent_transport_disconnect_monitor_detects_hup_while_read_is_disarmed() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let (wake_reader, wake_writer) = UnixStream::pair().unwrap();
    wake_reader.set_nonblocking(true).unwrap();
    wake_writer.set_nonblocking(true).unwrap();
    writer.write_all(b"x").unwrap();

    assert_eq!(
        wait_for_unix_monitor_event(&reader, &wake_reader, true).unwrap(),
        UnixMonitorEvent::PeerReadable
    );
    drop(writer);
    assert_eq!(
        wait_for_unix_monitor_event(&reader, &wake_reader, false).unwrap(),
        UnixMonitorEvent::PeerDisconnected
    );
}

#[cfg(unix)]
#[test]
fn ct_agent_auth_owner_only_unix_transport_registers_and_delivers_connection_session() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let suffix = Uuid::new_v4().simple().to_string();
    let directory = PathBuf::from("/tmp").join(format!("vma-{}", &suffix[..12]));
    let endpoint = directory.join("broker.sock");
    let broker = Arc::new(Mutex::new(AgentBrokerCore::new().unwrap()));
    let notifications = Arc::new(AtomicUsize::new(0));
    let surfaces = Arc::new(Mutex::new(Vec::new()));
    let callback_notifications = Arc::clone(&notifications);
    let callback_surfaces = Arc::clone(&surfaces);
    let listener = AgentBrokerUnixListener::start(
        endpoint.clone(),
        Arc::clone(&broker),
        Arc::new(|_| Ok(Uuid::new_v4().to_string())),
        Arc::new(|_, _, _, _, _| {
            Err(AgentBrokerError::new(
                "adapter-unavailable",
                "This approved Agent adapter is not available in this build.",
                false,
            ))
        }),
        Arc::new(move |surface| {
            callback_surfaces.lock().unwrap().push(surface);
            callback_notifications.fetch_add(1, Ordering::Relaxed);
        }),
    )
    .unwrap();
    let mut stream = UnixStream::connect(&endpoint).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let hello_id = Uuid::new_v4();
    write_json_line(
        &mut stream,
        &json!({
            "protocolVersion": 2,
            "requestId": hello_id,
            "kind": "hello",
            "client": {
                "clientKey": "codex"
            }
        }),
    )
    .unwrap();
    let hello: Value =
        serde_json::from_slice(&read_line(&mut stream, &AtomicBool::new(false)).unwrap()).unwrap();
    assert_eq!(hello["ok"], true);
    let client_id = hello["result"]["client"]["clientId"]
        .as_str()
        .unwrap()
        .to_owned();
    {
        let mut broker = broker.lock().unwrap();
        broker.approve_pairing(&client_id).unwrap();
    }
    let session_id = Uuid::new_v4();
    write_json_line(
        &mut stream,
        &json!({ "protocolVersion": 2, "requestId": session_id, "kind": "session" }),
    )
    .unwrap();
    let session: Value =
        serde_json::from_slice(&read_line(&mut stream, &AtomicBool::new(false)).unwrap()).unwrap();
    assert_eq!(session["ok"], true);
    assert_eq!(session["result"]["client"]["pairingState"], "paired");
    let allowed_tools = session["result"]["session"]["allowedTools"]
        .as_array()
        .unwrap();
    assert_eq!(allowed_tools.len(), 30);
    assert!(allowed_tools.contains(&json!("vaultmesh_ssh_exec")));
    assert!(allowed_tools.contains(&json!("vaultmesh_ssh_agent_open")));
    assert!(allowed_tools.contains(&json!("vaultmesh_ssh_agent_close")));
    assert_eq!(notifications.load(Ordering::Relaxed), 1);
    assert_eq!(
        surfaces.lock().unwrap().as_slice(),
        &[AgentNativeUiSurface::Pairing]
    );

    let local_ui_request_id = Uuid::new_v4();
    write_json_line(
        &mut stream,
        &json!({
            "protocolVersion": 2,
            "requestId": local_ui_request_id,
            "sessionId": session["result"]["session"]["sessionId"],
            "tool": "vaultmesh_request_local_ui",
            "toolVersion": 1,
            "parameters": { "purpose": "manage-agent-access" }
        }),
    )
    .unwrap();
    let local_ui_response: Value =
        serde_json::from_slice(&read_line(&mut stream, &AtomicBool::new(false)).unwrap()).unwrap();
    assert_eq!(local_ui_response["ok"], true);
    assert_eq!(local_ui_response["requestId"], json!(local_ui_request_id));
    assert_eq!(local_ui_response["result"], json!({ "accepted": true }));
    assert_eq!(notifications.load(Ordering::Relaxed), 2);
    assert_eq!(
        surfaces.lock().unwrap().as_slice(),
        &[AgentNativeUiSurface::Pairing, AgentNativeUiSurface::LocalUi]
    );

    let mode = fs::metadata(&endpoint).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    drop(stream);

    let disconnected_at = Instant::now();
    while !broker.lock().unwrap().clients().is_empty()
        && disconnected_at.elapsed() < Duration::from_secs(1)
    {
        thread::sleep(Duration::from_millis(10));
    }
    let mut reconnected = UnixStream::connect(&endpoint).unwrap();
    reconnected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_json_line(
        &mut reconnected,
        &json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "kind": "hello",
            "client": {
                "clientKey": "codex"
            }
        }),
    )
    .unwrap();
    let reconnected_hello: Value =
        serde_json::from_slice(&read_line(&mut reconnected, &AtomicBool::new(false)).unwrap())
            .unwrap();
    assert_eq!(
        reconnected_hello["result"]["client"]["pairingState"],
        "paired"
    );
    assert_eq!(notifications.load(Ordering::Relaxed), 2);
    drop(reconnected);
    listener.stop();
    let _ = fs::remove_dir(&directory);
}

#[cfg(unix)]
#[test]
fn ct_agent_transport_rejects_a_slow_partial_frame() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    writer.write_all(b"{").unwrap();

    let error = read_line_with_deadline(
        &mut reader,
        &AtomicBool::new(false),
        Duration::from_millis(30),
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "Agent IPC frame deadline exceeded");
}

#[cfg(unix)]
#[test]
fn ct_agent_transport_shutdown_interrupts_an_idle_connection() {
    let (mut reader, _writer) = UnixStream::pair().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let reader_stopping = Arc::clone(&stopping);
    let reader_thread = thread::spawn(move || read_line(&mut reader, &reader_stopping));

    thread::sleep(Duration::from_millis(20));
    stopping.store(true, Ordering::Release);
    let error = reader_thread.join().unwrap().unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
}

#[cfg(unix)]
#[test]
fn ct_agent_lifecycle_disconnect_cancels_an_active_executor() {
    let suffix = Uuid::new_v4().simple().to_string();
    let directory = PathBuf::from("/tmp").join(format!("vma-{}", &suffix[..12]));
    let endpoint = directory.join("broker.sock");
    let broker = Arc::new(Mutex::new(AgentBrokerCore::new().unwrap()));
    let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
    let (cancelled_sender, cancelled_receiver) = std::sync::mpsc::sync_channel(1);
    let executor: AgentToolExecutor = Arc::new(move |tool, _, _, cancellation, _| {
        assert_eq!(tool, "vaultmesh_items_list_metadata");
        let _ = started_sender.send(());
        let started = Instant::now();
        while !cancellation.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(2));
        }
        if cancellation.load(Ordering::Acquire) {
            let _ = cancelled_sender.send(());
            Err(AgentBrokerError::new(
                "session-cancelled",
                "The connection session was revoked or expired.",
                false,
            ))
        } else {
            Ok(json!({ "status": "too-late" }))
        }
    });
    let listener = AgentBrokerUnixListener::start(
        endpoint.clone(),
        Arc::clone(&broker),
        Arc::new(|_| Ok(Uuid::new_v4().to_string())),
        executor,
        Arc::new(|_| {}),
    )
    .unwrap();
    let mut stream = UnixStream::connect(&endpoint).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_json_line(
        &mut stream,
        &json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "kind": "hello",
            "client": {
                "clientKey": "codex"
            }
        }),
    )
    .unwrap();
    let hello: Value =
        serde_json::from_slice(&read_line(&mut stream, &AtomicBool::new(false)).unwrap()).unwrap();
    let client_id = hello["result"]["client"]["clientId"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = {
        let mut broker = broker.lock().unwrap();
        broker.approve_pairing(&client_id).unwrap();
        broker
            .issue_session(
                &client_id,
                vec!["vaultmesh_items_list_metadata".into()],
                vec![],
                60_000,
                10,
                unix_millis(),
            )
            .unwrap()
    };
    write_json_line(
        &mut stream,
        &json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "sessionId": session.session_id,
            "tool": "vaultmesh_items_list_metadata",
            "toolVersion": 1,
            "parameters": {}
        }),
    )
    .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    drop(stream);

    cancelled_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    assert!(broker.lock().unwrap().clients().is_empty());
    listener.stop();
    let _ = fs::remove_dir(&directory);
}
