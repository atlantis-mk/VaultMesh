use super::*;

#[test]
fn ct_agent_protocol_rejects_unknown_fields_versions_and_replay() {
    let (mut broker, client_id, session) = paired_broker(&["vaultmesh_accounts_list"]);
    let request_id = Uuid::new_v4();
    let first = broker.handle_json(
        client_id,
        &request(&session, request_id, "vaultmesh_accounts_list", json!({})),
        1_002,
    );
    assert_eq!(first["ok"], true);
    let replay = broker.handle_json(
        client_id,
        &request(&session, request_id, "vaultmesh_accounts_list", json!({})),
        1_003,
    );
    assert_eq!(replay["error"]["code"], "request-replayed");

    let unknown = serde_json::to_vec(&json!({
        "protocolVersion": 2, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
        "tool": "vaultmesh_accounts_list", "toolVersion": 2, "parameters": {}, "surprise": true
    }))
    .unwrap();
    assert_eq!(
        broker.handle_json(client_id, &unknown, 1_004)["error"]["code"],
        "invalid-request"
    );

    let version = serde_json::to_vec(&json!({
        "protocolVersion": 1, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
        "tool": "vaultmesh_accounts_list", "toolVersion": 2, "parameters": {}
    }))
    .unwrap();
    assert_eq!(
        broker.handle_json(client_id, &version, 1_005)["error"]["code"],
        "update-required"
    );

    let malformed = br#"{"requestId":"SECRET-CANARY","surprise":true}"#;
    let response = broker.handle_json(client_id, malformed, 1_006);
    assert_eq!(response["requestId"], Value::Null);
    assert!(!response.to_string().contains("SECRET-CANARY"));
}

#[test]
fn ct_agent_connection_session_rotates_after_expiry_without_reconnecting_transport() {
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let initial_session = broker.sessions().into_iter().next().unwrap();
    let initial_session_id = Uuid::parse_str(&initial_session.session_id).unwrap();
    broker
        .grant_permission(
            initial_session_id,
            PermissionGrantInput {
                account_ref: "00000000-0000-4000-8000-000000000099",
                tool: "vaultmesh_ssh_exec",
                operation: Some("hostname"),
                scope: PermissionScope::Exact,
                parameters_digest: Some("sha256:old-session-authority"),
                catalog_revision: None,
                effect: PermissionEffect::Allow,
                fresh_confirmation_required: false,
                remaining_uses: None,
            },
        )
        .unwrap();

    let before_expiry = broker.handle_json(
        client_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_001,
    );
    assert_eq!(before_expiry["ok"], true);

    let after_expiry = broker.handle_json(
        client_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        initial_session.expires_at,
    );
    assert_eq!(after_expiry["ok"], true);
    let rotated = broker.sessions();
    assert_eq!(rotated.len(), 1);
    assert_ne!(rotated[0].session_id, initial_session.session_id);
    assert_eq!(rotated[0].client_id, client.client_id);
    assert!(
        rotated[0]
            .allowed_accounts
            .contains(&"00000000-0000-4000-8000-000000000099".to_owned())
    );
    assert!(
        broker
            .transport_permission_grants
            .get(&client_id)
            .unwrap()
            .iter()
            .any(|grant| grant.tool == "vaultmesh_ssh_exec"),
        "an explicit connection grant must survive internal anti-replay session rotation"
    );
}

#[test]
fn ct_agent_vault_lock_clears_authority_but_preserves_the_verified_transport() {
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let session_id = Uuid::parse_str(&broker.sessions()[0].session_id).unwrap();
    broker
        .grant_permission(
            session_id,
            PermissionGrantInput {
                account_ref: "00000000-0000-4000-8000-000000000099",
                tool: "vaultmesh_ssh_exec",
                operation: Some("hostname"),
                scope: PermissionScope::Exact,
                parameters_digest: Some("sha256:vault-lock-authority"),
                catalog_revision: None,
                effect: PermissionEffect::Allow,
                fresh_confirmation_required: false,
                remaining_uses: None,
            },
        )
        .unwrap();

    broker.suspend_for_vault_lock();
    assert_eq!(broker.clients().len(), 1);
    assert!(broker.sessions().is_empty());
    assert!(broker.transport_permission_grants.is_empty());

    let response = broker.handle_json(
        client_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        2_000,
    );
    assert_eq!(response["ok"], true);
    assert_eq!(broker.sessions().len(), 1);
}

#[test]
fn ct_agent_unlock_is_per_transport_and_required_before_vault_tools() {
    let unlocked_clients = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    let access = Arc::clone(&unlocked_clients);
    broker.set_access_check(Arc::new(move |client_id| {
        access
            .lock()
            .is_ok_and(|clients| clients.contains(&client_id))
    }));
    broker.set_account_catalog(Arc::new(|| {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: Vec::new(),
        })
    }));
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();

    let request_id = Uuid::new_v4();
    let request = connection_request(request_id, "vaultmesh_accounts_list", json!({}));
    let locked = broker.handle_json(first_id, &request, 1_002);
    assert_eq!(locked["error"]["code"], "mcp-locked");
    assert_eq!(locked["error"]["nativeActionRequired"], "unlock-agent");
    let pending = broker.pending_unlock_request(1_002).unwrap();

    unlocked_clients.lock().unwrap().insert(first_id);
    broker
        .resolve_unlock_request(&pending.unlock_ref, first_id, true, 1_003)
        .unwrap();
    assert_eq!(
        broker.unlock_wait_outcome(&pending.unlock_ref, first_id, 1_003),
        AgentUnlockWaitOutcome::Allowed
    );
    let continued = broker
        .continue_json_for_dispatch(first_id, &request, 1_004)
        .0;
    assert_eq!(continued["ok"], true, "{continued}");
    assert_eq!(continued["result"]["accounts"], json!([]));

    let mut other_hello = hello(&[]);
    other_hello.client_key = "opencode".into();
    let second = broker.register_client(peer(), other_hello, 2_000).unwrap();
    broker.approve_pairing_at(&second.client_id, 2_001).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();
    let second_locked = broker.handle_json(
        second_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        2_002,
    );
    assert_eq!(second_locked["error"]["code"], "mcp-locked");
}

#[test]
fn ct_agent_client_shared_unlock_continues_all_pending_same_identity_calls() {
    let shared_unlocked = Arc::new(AtomicBool::new(false));
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    let access = Arc::clone(&shared_unlocked);
    broker.set_access_check(Arc::new(move |_| access.load(Ordering::Acquire)));
    broker.set_access_shares_unlock(Arc::new(|_, _| true));
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let second = broker.register_client(peer(), hello(&[]), 1_002).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();
    let first_response = broker.handle_json(
        first_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_003,
    );
    let second_response = broker.handle_json(
        second_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_004,
    );
    let first_ref = first_response["error"]["details"]["unlockRef"]
        .as_str()
        .unwrap();
    let second_ref = second_response["error"]["details"]["unlockRef"]
        .as_str()
        .unwrap();
    assert_eq!(
        first_ref, second_ref,
        "parallel transports in the same configured unlock scope must share one prompt"
    );

    shared_unlocked.store(true, Ordering::Release);
    broker
        .resolve_unlock_request(first_ref, first_id, true, 1_005)
        .unwrap();
    assert_eq!(
        broker.unlock_wait_outcome(first_ref, first_id, 1_005),
        AgentUnlockWaitOutcome::Allowed
    );
    assert_eq!(
        broker.unlock_wait_outcome(second_ref, second_id, 1_005),
        AgentUnlockWaitOutcome::Allowed
    );
    assert!(broker.pending_unlock_request(1_005).is_none());

    shared_unlocked.store(false, Ordering::Release);
    let relocked = broker.handle_json(
        second_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_006,
    );
    assert_ne!(
        relocked["error"]["details"]["unlockRef"],
        json!(first_ref),
        "a completed prompt must not be reused after the lease is locked again"
    );
}

#[test]
fn ct_agent_client_shared_unlock_prompt_survives_displayed_transport_disconnect() {
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    broker.set_access_check(Arc::new(|_| false));
    broker.set_access_shares_unlock(Arc::new(|_, _| true));
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let second = broker.register_client(peer(), hello(&[]), 1_002).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();
    let first_response = broker.handle_json(
        first_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_003,
    );
    let second_response = broker.handle_json(
        second_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_004,
    );
    assert_eq!(
        first_response["error"]["details"]["unlockRef"],
        second_response["error"]["details"]["unlockRef"]
    );

    broker.disconnect(first_id);

    let pending = broker.pending_unlock_request(1_005).unwrap();
    assert_eq!(pending.client_id, second_id.to_string());
    broker
        .resolve_unlock_request(&pending.unlock_ref, second_id, false, 1_006)
        .unwrap();
    assert_eq!(
        broker.unlock_wait_outcome(&pending.unlock_ref, second_id, 1_006),
        AgentUnlockWaitOutcome::Denied
    );
}

#[test]
fn ct_agent_unlock_request_survives_transport_timeout_for_the_next_retry() {
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    broker.set_access_check(Arc::new(|_| false));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();

    let response = broker.handle_json(
        client_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_002,
    );
    let unlock_ref = response["error"]["details"]["unlockRef"]
        .as_str()
        .unwrap()
        .to_owned();

    assert_eq!(
        broker.unlock_wait_outcome(&unlock_ref, client_id, 31_003),
        AgentUnlockWaitOutcome::Pending,
        "the native unlock remains actionable after the 30-second transport wait"
    );
    assert_eq!(
        broker.pending_unlock_request(31_003).unwrap().unlock_ref,
        unlock_ref
    );
    broker
        .resolve_unlock_request(&unlock_ref, client_id, true, 31_004)
        .unwrap();
    assert_eq!(
        broker.unlock_wait_outcome(&unlock_ref, client_id, 31_004),
        AgentUnlockWaitOutcome::Allowed
    );
}

#[test]
fn ct_agent_access_expiry_clears_authority_but_preserves_the_new_unlock_request() {
    let cleaned_clients = Arc::new(Mutex::new(Vec::<Uuid>::new()));
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    broker.set_access_check(Arc::new(|_| false));
    let cleaned = Arc::clone(&cleaned_clients);
    broker.set_resource_cleanup(Arc::new(move |scope| {
        if let AgentCleanupScope::Client(client_id) = scope
            && let Ok(mut clients) = cleaned.lock()
        {
            clients.push(client_id);
        }
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let response = broker.handle_json(
        client_id,
        &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
        1_002,
    );
    let unlock_ref = response["error"]["details"]["unlockRef"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(broker.sessions().len(), 1);

    broker.expire_agent_client_authority(client_id);

    assert!(broker.sessions().is_empty());
    assert_eq!(cleaned_clients.lock().unwrap().as_slice(), &[client_id]);
    assert_eq!(
        broker.pending_unlock_request(1_003).unwrap().unlock_ref,
        unlock_ref,
        "the unlock prompted by the expired lease must remain actionable"
    );
    broker
        .resolve_unlock_request(&unlock_ref, client_id, true, 1_004)
        .unwrap();
}

#[test]
fn ct_agent_unlock_window_advances_across_concurrent_transport_requests() {
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    broker.set_access_check(Arc::new(|_| false));
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();
    let mut second_hello = hello(&[]);
    second_hello.client_key = "opencode".into();
    let second = broker.register_client(peer(), second_hello, 1_002).unwrap();
    broker.approve_pairing_at(&second.client_id, 1_003).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();

    for (client_id, now) in [(first_id, 1_004), (second_id, 1_005)] {
        let response = broker.handle_json(
            client_id,
            &connection_request(Uuid::new_v4(), "vaultmesh_accounts_list", json!({})),
            now,
        );
        assert_eq!(response["error"]["code"], "mcp-locked");
    }
    let displayed = broker.pending_unlock_request(1_006).unwrap();
    let displayed_client = Uuid::parse_str(&displayed.client_id).unwrap();
    broker
        .resolve_unlock_request(&displayed.unlock_ref, displayed_client, true, 1_007)
        .unwrap();

    let next = broker.pending_unlock_request(1_008).unwrap();
    assert_ne!(next.client_id, displayed.client_id);
    assert_eq!(
        Uuid::parse_str(&next.client_id).unwrap(),
        if displayed_client == first_id {
            second_id
        } else {
            first_id
        }
    );
}

#[test]
fn ct_agent_software_lock_clears_only_the_calling_transport() {
    let unlocked_clients = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    let access = Arc::clone(&unlocked_clients);
    broker.set_access_check(Arc::new(move |client_id| {
        access
            .lock()
            .is_ok_and(|clients| clients.contains(&client_id))
    }));
    let locked = Arc::clone(&unlocked_clients);
    broker.set_access_lock(Arc::new(move |client_id| {
        if let Ok(mut clients) = locked.lock() {
            clients.remove(&client_id);
        }
        vec![client_id]
    }));
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();
    let mut other_hello = hello(&[]);
    other_hello.client_key = "opencode".into();
    let second = broker.register_client(peer(), other_hello, 1_002).unwrap();
    broker.approve_pairing_at(&second.client_id, 1_003).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();
    unlocked_clients
        .lock()
        .unwrap()
        .extend([first_id, second_id]);

    broker.lock_agent_client(first_id);
    let clients = unlocked_clients.lock().unwrap();
    assert!(!clients.contains(&first_id));
    assert!(clients.contains(&second_id));
}

#[test]
fn ct_agent_unlock_registration_groups_pairing_identity_and_disconnects_per_transport() {
    let registrations = Arc::new(Mutex::new(Vec::<(Uuid, String)>::new()));
    let disconnects = Arc::new(Mutex::new(Vec::<Uuid>::new()));
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    let registered = Arc::clone(&registrations);
    broker.set_access_register(Arc::new(move |client_id, identity| {
        registered.lock().unwrap().push((client_id, identity));
    }));
    let disconnected = Arc::clone(&disconnects);
    broker.set_access_disconnect(Arc::new(move |client_id| {
        disconnected.lock().unwrap().push(client_id);
    }));

    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();
    let second = broker.register_client(peer(), hello(&[]), 1_002).unwrap();
    let first_id = Uuid::parse_str(&first.client_id).unwrap();
    let second_id = Uuid::parse_str(&second.client_id).unwrap();
    let registered = registrations.lock().unwrap();
    assert_eq!(registered.len(), 2);
    assert_eq!(registered[0].0, first_id);
    assert_eq!(registered[1].0, second_id);
    assert_eq!(registered[0].1, registered[1].1);
    drop(registered);

    broker.disconnect(first_id);
    assert_eq!(*disconnects.lock().unwrap(), vec![first_id]);
    assert!(
        broker
            .clients()
            .iter()
            .any(|client| client.client_id == second.client_id)
    );
}

#[test]
fn ct_agent_auth_rejects_untrusted_executable_controls_and_noncanonical_binary_hashes() {
    let mut broker = AgentBrokerCore::new().unwrap();
    let mut invalid_display = peer();
    invalid_display.executable = "trusted\nspoofed".into();
    assert_eq!(
        broker
            .register_client(invalid_display, hello(&["vaultmesh_accounts_list"]), 1_000)
            .unwrap_err()
            .code,
        "invalid-client"
    );
    let mut invalid_hash = peer();
    invalid_hash.binary_identity = "sha256:not-a-digest".into();
    assert_eq!(
        broker
            .register_client(invalid_hash, hello(&["vaultmesh_accounts_list"]), 1_000)
            .unwrap_err()
            .code,
        "invalid-client"
    );
}

#[test]
fn ct_agent_policy_canonical_digest_is_order_independent_and_substitution_sensitive() {
    let client_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let target = json!({ "origin": "https://api.example.test", "path": "/v1/status" });
    let first = canonical_action_digest(CanonicalActionInput {
        client_id,
        session_id,
        account_ref: Some("00000000-0000-4000-8000-000000000099"),
        tool: "vaultmesh_http_request",
        tool_version: 1,
        canonical_target: &target,
        parameters: &json!({ "body": { "z": 2, "a": 1 }, "method": "POST" }),
        risk: "R2",
    })
    .unwrap();
    let reordered = canonical_action_digest(CanonicalActionInput {
        client_id,
        session_id,
        account_ref: Some("00000000-0000-4000-8000-000000000099"),
        tool: "vaultmesh_http_request",
        tool_version: 1,
        canonical_target: &json!({ "path": "/v1/status", "origin": "https://api.example.test" }),
        parameters: &json!({ "method": "POST", "body": { "a": 1, "z": 2 } }),
        risk: "R2",
    })
    .unwrap();
    assert_eq!(first, reordered);

    let substituted = canonical_action_digest(CanonicalActionInput {
        client_id,
        session_id,
        account_ref: Some("00000000-0000-4000-8000-000000000099"),
        tool: "vaultmesh_http_request",
        tool_version: 1,
        canonical_target: &target,
        parameters: &json!({ "body": { "a": 1, "z": 3 }, "method": "POST" }),
        risk: "R2",
    })
    .unwrap();
    assert_ne!(first, substituted);
    assert_eq!(
        canonicalize_json(&json!({ "fraction": 1.5 }))
            .unwrap_err()
            .code,
        "invalid-parameters"
    );
}

#[test]
fn ct_agent_http_method_drives_risk_without_separate_confirmation() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let tool = "vaultmesh_http_request";
    let mut broker = AgentBrokerCore::new().unwrap();
    configure_test_direct_http_account(&mut broker, Uuid::parse_str(account_ref).unwrap());
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec![tool.into()],
            vec![account_ref.into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let executor: AgentToolExecutor = Arc::new(|_, _, _, _, _| Ok(json!({ "status": "ok" })));
    let call = |method: &str, path: &str| {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "sessionId": session.session_id,
            "tool": tool,
            "toolVersion": 2,
            "accountRef": account_ref,
            "parameters": { "method": method, "path": path }
        }))
        .unwrap()
    };

    let read_parameters = json!({ "method": "GET", "path": "/status" });
    seed_test_direct_action(&mut broker, client_id, account_ref, tool, &read_parameters);
    let read =
        broker.handle_json_with_executor(client_id, &call("GET", "/status"), 1_002, &executor);
    assert_eq!(read["ok"], true, "{read}");
    assert_eq!(broker.take_audit().unwrap().risk, AgentRiskTier::R1);

    let write_parameters = json!({ "method": "POST", "path": "/restart" });
    seed_test_direct_action(&mut broker, client_id, account_ref, tool, &write_parameters);
    let write =
        broker.handle_json_with_executor(client_id, &call("POST", "/restart"), 1_003, &executor);
    assert_eq!(write["ok"], true, "{write}");
    assert_eq!(broker.take_audit().unwrap().risk, AgentRiskTier::R2);
    assert!(broker.confirmations().is_empty());

    let unknown = broker.handle_json_with_executor(
        client_id,
        &call("GET", "/agent-selected"),
        1_004,
        &executor,
    );
    assert_eq!(unknown["error"]["code"], "action-plan-unavailable");
}

#[test]
fn ct_agent_ssh_named_command_drives_risk_without_separate_confirmation() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let tool = "vaultmesh_ssh_exec";
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    broker
        .sync_connector_definitions(vec![test_agent_connector_definition(account_ref, &[tool])])
        .unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec![tool.into()],
            vec![account_ref.into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let executor: AgentToolExecutor = Arc::new(|_, _, _, _, _| Ok(json!({ "status": "ok" })));
    let call = |command: &str| {
        serde_json::to_vec(&json!({
            "protocolVersion": 2, "requestId": Uuid::new_v4(),
            "sessionId": session.session_id, "tool": tool, "toolVersion": 2,
            "accountRef": account_ref, "parameters": { "program": command }
        }))
        .unwrap()
    };
    let status_parameters = json!({ "program": "hostname" });
    seed_test_direct_action(
        &mut broker,
        client_id,
        account_ref,
        tool,
        &status_parameters,
    );
    assert_eq!(
        broker.handle_json_with_executor(client_id, &call("hostname"), 1_002, &executor)["ok"],
        true
    );
    assert_eq!(broker.take_audit().unwrap().risk, AgentRiskTier::R1);
    let restart_parameters = json!({ "program": "sudo" });
    seed_test_direct_action(
        &mut broker,
        client_id,
        account_ref,
        tool,
        &restart_parameters,
    );
    let restart = broker.handle_json_with_executor(client_id, &call("sudo"), 1_003, &executor);
    assert_eq!(restart["ok"], true, "{restart}");
    assert_eq!(broker.take_audit().unwrap().risk, AgentRiskTier::R3);
    assert!(broker.confirmations().is_empty());
}

#[test]
fn ct_agent_lifecycle_enforces_cumulative_output_quota_before_publishing_result() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let tool = "vaultmesh_http_request";
    let mut broker = AgentBrokerCore::new().unwrap();
    configure_test_direct_http_account(&mut broker, Uuid::parse_str(account_ref).unwrap());
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec![tool.into()],
            vec![account_ref.into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    assert_eq!(session.output_byte_limit, MAX_SESSION_OUTPUT_BYTES);
    assert_eq!(session.output_bytes_used, 0);
    let bytes = serde_json::to_vec(&json!({
        "protocolVersion": 2, "requestId": Uuid::new_v4(),
        "sessionId": session.session_id, "tool": tool, "toolVersion": 2,
        "accountRef": account_ref,
        "parameters": { "method": "GET", "path": "/status" }
    }))
    .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let parameters = json!({ "method": "GET", "path": "/status" });
    seed_test_direct_action(&mut broker, client_id, account_ref, tool, &parameters);
    let (mut response, mut audit, action) =
        broker.authorize_json_for_dispatch(client_id, &bytes, 1_002);
    let action = action.unwrap();
    action
        .output_bytes_used
        .store(MAX_SESSION_OUTPUT_BYTES - 1, Ordering::Release);
    let executor: AgentToolExecutor =
        Arc::new(|_, _, _, _, _| Ok(json!({ "status": "larger-than-one-byte" })));
    execute_authorized_action(&mut response, &mut audit, Some(action), &executor);
    assert_eq!(response["error"]["code"], "output-quota-exceeded");
    assert!(response.get("result").is_none());
    assert_eq!(audit.unwrap().result_class, AgentAuditResultClass::Failed);
    assert_eq!(
        broker
            .sessions()
            .into_iter()
            .find(|snapshot| snapshot.session_id == session.session_id)
            .unwrap()
            .output_bytes_used,
        MAX_SESSION_OUTPUT_BYTES - 1
    );
}

#[test]
fn ct_agent_account_tools_reject_legacy_confirmation_tickets_without_creating_challenges() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let tool = "vaultmesh_ssh_upload";
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    broker
        .sync_connector_definitions(vec![test_agent_connector_definition(account_ref, &[tool])])
        .unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec![tool.into()],
            vec![account_ref.into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let parameters = json!({ "fileRef": Uuid::new_v4(), "remotePath": "/srv/app.bin" });
    seed_test_direct_action(&mut broker, client_id, account_ref, tool, &parameters);
    let first = serde_json::to_vec(&json!({
        "protocolVersion": 2, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
        "accountRef": account_ref, "tool": tool, "toolVersion": 1, "parameters": parameters
    }))
    .unwrap();
    let response = broker.handle_json(client_id, &first, 1_002);
    assert_ne!(response["error"]["code"], "confirmation-required");
    assert!(broker.confirmations().is_empty());

    let with_legacy_ticket = serde_json::to_vec(&json!({
        "protocolVersion": 2, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
        "accountRef": account_ref, "tool": tool, "toolVersion": 1,
        "parameters": parameters,
        "confirmationTicket": Uuid::new_v4()
    }))
    .unwrap();
    assert_eq!(
        broker.handle_json(client_id, &with_legacy_ticket, 1_003)["error"]["code"],
        "invalid-confirmation"
    );
    assert!(broker.confirmations().is_empty());
}

#[test]
fn ct_agent_protocol_returns_only_safe_metadata_and_denies_unimplemented_adapter() {
    let tools = [
        "vaultmesh_accounts_list",
        "vaultmesh_accounts_list",
        "vaultmesh_ssh_exec",
    ];
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&tools), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    broker
        .sync_connector_definitions(vec![test_agent_connector_definition(
            "00000000-0000-4000-8000-000000000099",
            &["vaultmesh_ssh_exec"],
        )])
        .unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            tools.iter().map(|tool| (*tool).to_owned()).collect(),
            vec!["00000000-0000-4000-8000-000000000099".into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let parameters = json!({ "program": "status" });
    seed_test_direct_action(
        &mut broker,
        client_id,
        "00000000-0000-4000-8000-000000000099",
        "vaultmesh_ssh_exec",
        &parameters,
    );
    let accounts = broker.handle_json(
        client_id,
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({}),
        ),
        1_002,
    );
    assert_eq!(accounts["result"]["accounts"], json!([]));
    let ssh = serde_json::to_vec(&json!({
            "protocolVersion": 2, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
            "accountRef": "00000000-0000-4000-8000-000000000099", "tool": "vaultmesh_ssh_exec", "toolVersion": 2,
            "parameters": { "program": "status" }
        }))
        .unwrap();
    let denied = broker.handle_json(client_id, &ssh, 1_003);
    assert_eq!(denied["error"]["code"], "adapter-unavailable");
    assert!(!denied.to_string().contains("status"));
    let audit = broker.take_audit().expect("safe audit");
    let serialized_audit = serde_json::to_string(&audit).unwrap();
    assert_eq!(audit.account_label, "Direct SSH");
    assert_eq!(audit.result_class, AgentAuditResultClass::Unavailable);
    assert!(!serialized_audit.contains("command"));
    assert!(!serialized_audit.contains("/Applications"));
}

#[test]
fn ct_agent_dispatches_authorized_metadata_through_the_native_executor() {
    let tool = "vaultmesh_items_list_metadata";
    let (mut broker, client_id, session) = paired_broker(&[tool]);
    let executor: AgentToolExecutor = Arc::new(|tool, account_ref, parameters, cancellation, _| {
        assert!(!cancellation.load(Ordering::Acquire));
        assert_eq!(tool, "vaultmesh_items_list_metadata");
        assert!(account_ref.is_none());
        assert_eq!(parameters["kind"], "login");
        Ok(json!({
            "items": [{ "itemRef": "00000000-0000-4000-8000-000000000099", "kind": "login", "label": "Example" }],
            "truncated": false
        }))
    });
    let response = broker.handle_json_with_executor(
        client_id,
        &request(&session, Uuid::new_v4(), tool, json!({ "kind": "login" })),
        1_002,
        &executor,
    );
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["items"][0]["label"], "Example");
}

#[test]
fn ct_agent_connection_metadata_does_not_require_an_account_reference() {
    let tool = "vaultmesh_items_list_metadata";
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_access_check(Arc::new(|_| true));
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let session = broker
        .sessions()
        .into_iter()
        .find(|session| session.client_id == client.client_id)
        .expect("connection-managed session");
    let executor: AgentToolExecutor = Arc::new(|tool, account_ref, parameters, _, _| {
        assert_eq!(tool, "vaultmesh_items_list_metadata");
        assert!(account_ref.is_none());
        assert_eq!(parameters["kind"], "login");
        Ok(json!({ "items": [], "truncated": false }))
    });

    let response = broker.handle_json_with_executor(
        client_id,
        &request(&session, Uuid::new_v4(), tool, json!({ "kind": "login" })),
        1_002,
        &executor,
    );

    assert_eq!(response["ok"], true, "{response}");
}

#[test]
fn ct_agent_ssh_agent_close_does_not_require_an_account_reference() {
    let tool = "vaultmesh_ssh_agent_close";
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_access_check(Arc::new(|_| true));
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let session = broker
        .sessions()
        .into_iter()
        .find(|session| session.client_id == client.client_id)
        .expect("connection-managed session");
    let executor: AgentToolExecutor = Arc::new(|tool, account_ref, parameters, _, _| {
        assert_eq!(tool, "vaultmesh_ssh_agent_close");
        assert!(account_ref.is_none());
        assert_eq!(parameters["sessionRef"], "sess-test-123");
        Ok(json!({ "closed": true, "sessionRef": "sess-test-123" }))
    });

    let response = broker.handle_json_with_executor(
        client_id,
        &request(
            &session,
            Uuid::new_v4(),
            tool,
            json!({ "sessionRef": "sess-test-123" }),
        ),
        1_002,
        &executor,
    );

    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["result"]["closed"], true);
    assert_eq!(response["result"]["sessionRef"], "sess-test-123");
}

#[test]
fn ct_agent_executor_runs_after_releasing_the_broker_mutex() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let tool = "vaultmesh_ssh_exec";
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&[tool]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    broker
        .sync_connector_definitions(vec![test_agent_connector_definition(account_ref, &[tool])])
        .unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec![tool.into()],
            vec![account_ref.into()],
            60_000,
            20,
            1_001,
        )
        .unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let parameters = json!({ "program": "status" });
    seed_test_direct_action(&mut broker, client_id, account_ref, tool, &parameters);
    let broker = Arc::new(Mutex::new(broker));
    let bytes = serde_json::to_vec(&json!({
        "protocolVersion": 2, "requestId": Uuid::new_v4(), "sessionId": session.session_id,
        "accountRef": account_ref, "tool": tool, "toolVersion": 2,
        "parameters": { "program": "status" }
    }))
    .unwrap();
    let (mut response, mut audit, action) = broker
        .lock()
        .unwrap()
        .authorize_json_for_dispatch(client_id, &bytes, 1_002);
    let probe = Arc::clone(&broker);
    let executor: AgentToolExecutor = Arc::new(move |_, _, _, cancellation, _| {
        assert!(!cancellation.load(Ordering::Acquire));
        assert!(
            probe.try_lock().is_ok(),
            "network executor must not hold broker mutex"
        );
        Ok(json!({ "status": "ok" }))
    });
    execute_authorized_action(&mut response, &mut audit, action, &executor);
    assert_eq!(response["result"]["status"], "ok");
}

#[test]
fn ct_agent_revocation_cancels_an_authorized_action_before_execution() {
    let tool = "vaultmesh_items_list_metadata";
    let (mut broker, client_id, session) = paired_broker(&[tool]);
    let (mut response, mut audit, action) = broker.authorize_json_for_dispatch(
        client_id,
        &request(&session, Uuid::new_v4(), tool, json!({})),
        1_002,
    );
    broker.revoke_session(&session.session_id).unwrap();
    let executor: AgentToolExecutor = Arc::new(|_, _, _, cancellation, _| {
        assert!(cancellation.load(Ordering::Acquire));
        Err(AgentBrokerError::new(
            "session-cancelled",
            "The connection session was revoked or expired.",
            false,
        ))
    });
    execute_authorized_action(&mut response, &mut audit, action, &executor);
    assert_eq!(response["error"]["code"], "session-cancelled");
}

#[test]
fn ct_agent_lifecycle_expiry_cancels_an_active_action() {
    let tool = "vaultmesh_items_list_metadata";
    let (mut broker, client_id, session) = paired_broker(&[tool]);
    broker
        .sessions
        .get_mut(&Uuid::parse_str(&session.session_id).unwrap())
        .unwrap()
        .expires_at = 1_027;
    let (mut response, mut audit, action) = broker.authorize_json_for_dispatch(
        client_id,
        &request(&session, Uuid::new_v4(), tool, json!({})),
        1_002,
    );
    let executor: AgentToolExecutor = Arc::new(|_, _, _, cancellation, _| {
        let started = Instant::now();
        while !cancellation.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(1) {
            thread::sleep(Duration::from_millis(2));
        }
        if cancellation.load(Ordering::Acquire) {
            Err(AgentBrokerError::new(
                "session-cancelled",
                "The connection session was revoked or expired.",
                false,
            ))
        } else {
            Ok(json!({ "status": "too-late" }))
        }
    });
    let started = Instant::now();
    execute_authorized_action(&mut response, &mut audit, action, &executor);

    assert_eq!(response["error"]["code"], "session-cancelled");
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn ct_agent_lifecycle_disconnect_and_clear_are_idempotent() {
    let (mut broker, client_id, _) = paired_broker(&["vaultmesh_accounts_list"]);
    broker
        .transport_permission_grants
        .insert(client_id, Vec::new());
    broker.disconnect(client_id);
    broker.disconnect(client_id);
    broker.clear();
    broker.clear();
    assert!(broker.clients().is_empty());
    assert!(broker.sessions().is_empty());
    assert!(broker.transport_permission_grants.is_empty());
}

#[test]
fn ct_agent_lifecycle_resource_cleanup_tracks_session_client_and_final_lock() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let cleanup_events = Arc::clone(&events);
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_resource_cleanup(Arc::new(move |scope| {
        cleanup_events.lock().unwrap().push(scope);
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing(&client.client_id).unwrap();
    let session = broker
        .issue_session(
            &client.client_id,
            vec!["vaultmesh_accounts_list".into()],
            vec![],
            60_000,
            10,
            1_001,
        )
        .unwrap();
    let session_id = Uuid::parse_str(&session.session_id).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    broker.revoke_session(&session.session_id).unwrap();
    broker.disconnect(client_id);
    broker.clear();

    let events = events.lock().unwrap();
    assert!(events.contains(&AgentCleanupScope::Session(session_id)));
    assert!(events.contains(&AgentCleanupScope::Client(client_id)));
    assert!(events.contains(&AgentCleanupScope::All));
}
