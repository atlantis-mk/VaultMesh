use super::*;

#[test]
fn ct_agent_protocol_registry_is_shared_strict_and_secret_free() {
    let registry = capability_registry().unwrap();
    assert_eq!(registry.protocol_version, 2);
    assert_eq!(registry.tools.len(), 30);
    let serialized = serde_json::to_string(&registry).unwrap();
    for forbidden in ["get_password", "export_secret", "dump_vault", "copy_secret"] {
        assert!(!serialized.contains(forbidden));
    }
    assert_eq!(
        registry
            .tools
            .iter()
            .map(|tool| &tool.name)
            .collect::<HashSet<_>>()
            .len(),
        30
    );
    assert!(registry.tools.iter().any(|tool| tool.name == "vaultmesh_ssh_agent_open"));
    assert!(registry.tools.iter().any(|tool| tool.name == "vaultmesh_ssh_agent_close"));
    let accounts = registry
        .tools
        .iter()
        .find(|tool| tool.name == "vaultmesh_accounts_list")
        .unwrap();
    assert!(
        !accounts
            .parameters
            .iter()
            .any(|parameter| parameter.name == "permission")
    );
}

#[test]
fn ct_agent_auth_requires_pairing_and_bounds_session() {
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    assert_eq!(client.pairing_state, PairingState::Pending);
    assert_eq!(
        broker
            .issue_session(
                &client.client_id,
                vec!["vaultmesh_accounts_list".into()],
                vec![],
                1_000,
                1,
                1_001
            )
            .unwrap_err()
            .code,
        "pairing-required"
    );
    broker.approve_pairing(&client.client_id).unwrap();
    assert_eq!(
        broker
            .issue_session(
                &client.client_id,
                vec!["vaultmesh_accounts_list".into()],
                vec![],
                MAX_SESSION_MILLIS + 1,
                1,
                1_001
            )
            .unwrap_err()
            .code,
        "invalid-session"
    );
    let session = broker
        .issue_session(
            &client.client_id,
            vec!["vaultmesh_accounts_list".into()],
            vec![],
            1_000,
            1,
            1_001,
        )
        .unwrap();
    assert_eq!(session.expires_at, 2_001);
    broker.revoke_client(&client.client_id).unwrap();
    assert!(broker.sessions().is_empty());
}

#[test]
fn ct_agent_pending_connection_reports_pairing_before_action_authorization() {
    let mut broker = AgentBrokerCore::new().unwrap();
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let request = serde_json::to_vec(&json!({
        "protocolVersion": 2,
        "requestId": Uuid::new_v4(),
        "tool": "vaultmesh_accounts_list",
        "toolVersion": 2,
        "parameters": {}
    }))
    .unwrap();

    let pairing = broker.handle_json(client_id, &request, 1_001);
    assert_eq!(pairing["error"]["code"], "pairing-required");
    assert_eq!(pairing["error"]["nativeActionRequired"], "approve-pairing");
    assert_eq!(
        pairing["error"]["message"],
        "VaultMesh requires approval of this local MCP client pairing."
    );

    broker.approve_pairing_at(&client.client_id, 1_002).unwrap();
    let retried = broker.handle_json(client_id, &request, 1_003);
    assert_eq!(retried["ok"], true, "{retried}");
}

#[test]
fn ct_agent_pairing_request_survives_probe_disconnect_and_approves_next_connection() {
    let proofs = AgentPairingProofs::memory();
    let mut broker = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    let request = broker.pending_pairing_request(1_001).unwrap();
    broker.disconnect(Uuid::parse_str(&client.client_id).unwrap());

    let retained = broker.pending_pairing_request(1_002).unwrap();
    assert_eq!(retained.client_id, request.client_id);
    broker
        .approve_pairing_request_at(&retained.client_id, 1_003)
        .unwrap();
    assert!(broker.pending_pairing_request(1_004).is_none());

    let mut reconnected = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    let next = reconnected
        .register_client(peer(), hello(&[]), 2_000)
        .unwrap();
    assert_eq!(next.pairing_state, PairingState::Paired);
}

#[test]
fn ct_agent_auth_persists_pairing_across_connections_without_restoring_session() {
    let proofs = AgentPairingProofs::memory();
    let tools = ["vaultmesh_accounts_list"];
    let mut first = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    let first_client = first.register_client(peer(), hello(&tools), 1_000).unwrap();
    assert_eq!(first_client.pairing_state, PairingState::Pending);
    let mut concurrent_peer = peer();
    concurrent_peer.process_id = 42_002;
    let concurrent_connection = first
        .register_client(concurrent_peer, hello(&tools), 1_000)
        .unwrap();
    assert_eq!(concurrent_connection.pairing_state, PairingState::Pending);
    first
        .approve_pairing_at(&first_client.client_id, 1_001)
        .unwrap();
    let first_groups = first.admin_clients();
    assert_eq!(first_groups.len(), 1);
    assert_eq!(first_groups[0].pairing_state, PairingState::Paired);
    assert_eq!(first_groups[0].activities.len(), 2);
    assert_eq!(first_groups[0].active_session_count, 2);
    assert_eq!(first_groups[0].activities[0].active_session_count, 1);
    assert_eq!(first_groups[0].activities[1].active_session_count, 1);
    assert_ne!(
        first_groups[0].activities[0].process_id,
        first_groups[0].activities[1].process_id
    );
    assert_eq!(
        first
            .client_snapshot(Uuid::parse_str(&concurrent_connection.client_id).unwrap())
            .unwrap()
            .pairing_state,
        PairingState::Paired
    );
    first
        .issue_session(
            &first_client.client_id,
            tools.iter().map(|tool| (*tool).to_owned()).collect(),
            vec![],
            60_000,
            20,
            1_002,
        )
        .unwrap();
    first.disconnect(Uuid::parse_str(&first_client.client_id).unwrap());
    let connected_group = first.admin_clients();
    assert_eq!(connected_group.len(), 1);
    assert_eq!(connected_group[0].activities.len(), 1);

    let mut reconnected = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    let offline_group = reconnected.admin_clients();
    assert_eq!(offline_group.len(), 1);
    assert_eq!(offline_group[0].pairing_state, PairingState::Paired);
    assert!(offline_group[0].activities.is_empty());
    let reconnected_client = reconnected
        .register_client(peer(), hello(&tools), 2_000)
        .unwrap();
    assert_eq!(reconnected_client.pairing_state, PairingState::Paired);
    let reconnected_id = Uuid::parse_str(&reconnected_client.client_id).unwrap();
    let restored_sessions = reconnected
        .sessions
        .values()
        .filter(|session| session.client_id == reconnected_id)
        .collect::<Vec<_>>();
    assert_eq!(restored_sessions.len(), 1);
    assert!(restored_sessions[0].connection_managed);

    let drifted = reconnected
        .register_client(peer(), hello(&tools), 2_001)
        .unwrap();
    assert_eq!(drifted.pairing_state, PairingState::Paired);
    let aggregated = reconnected.admin_clients();
    assert_eq!(aggregated.len(), 1);
    assert_eq!(aggregated[0].activities.len(), 2);

    let mut drifted_peer = peer();
    drifted_peer.binary_identity = format!("sha256:{}", "d".repeat(64));
    let drifted_binary = reconnected
        .register_client(drifted_peer, hello(&tools), 2_002)
        .unwrap();
    assert_eq!(drifted_binary.pairing_state, PairingState::Paired);
    let aggregated_after_binary_change = reconnected.admin_clients();
    assert_eq!(aggregated_after_binary_change.len(), 1);
    assert_eq!(aggregated_after_binary_change[0].activities.len(), 3);

    reconnected
        .revoke_client(&reconnected_client.client_id)
        .unwrap();
    assert!(
        reconnected
            .client_snapshot(Uuid::parse_str(&drifted.client_id).unwrap())
            .is_none()
    );
    let mut after_revoke = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    let revoked_identity = after_revoke
        .register_client(peer(), hello(&tools), 3_000)
        .unwrap();
    assert_eq!(revoked_identity.pairing_state, PairingState::Pending);
}

#[test]
fn ct_agent_auth_offline_pairing_record_can_be_revoked() {
    let proofs = AgentPairingProofs::memory();
    let mut connected = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    let client = connected
        .register_client(peer(), hello(&[]), 1_000)
        .unwrap();
    connected
        .approve_pairing_at(&client.client_id, 1_001)
        .unwrap();
    connected.disconnect(Uuid::parse_str(&client.client_id).unwrap());

    let mut offline = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    let groups = offline.admin_clients();
    assert_eq!(groups.len(), 1);
    assert!(groups[0].activities.is_empty());
    offline.revoke_client(&groups[0].client_id).unwrap();
    assert!(offline.admin_clients().is_empty());

    let mut after_revoke = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    let reconnected = after_revoke
        .register_client(peer(), hello(&[]), 2_000)
        .unwrap();
    assert_eq!(reconnected.pairing_state, PairingState::Pending);
}

#[test]
fn ct_agent_auth_custom_client_keys_pair_and_revoke_independently() {
    let proofs = AgentPairingProofs::memory();
    let mut broker = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    let first = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&first.client_id, 1_001).unwrap();

    let mut custom_hello = hello(&[]);
    custom_hello.client_key = "cursor.team-a".into();
    let custom = broker
        .register_client(peer(), custom_hello.clone(), 1_002)
        .unwrap();
    assert_eq!(custom.pairing_state, PairingState::Pending);
    broker.approve_pairing_at(&custom.client_id, 1_003).unwrap();
    broker.revoke_client(&first.client_id).unwrap();

    let custom_reconnect = broker.register_client(peer(), custom_hello, 1_004).unwrap();
    assert_eq!(custom_reconnect.pairing_state, PairingState::Paired);
    let default_reconnect = broker.register_client(peer(), hello(&[]), 1_005).unwrap();
    assert_eq!(default_reconnect.pairing_state, PairingState::Pending);
}

#[test]
fn ct_agent_permission_request_defaults_to_ask_and_scopes_allow_once_after_timeout() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let mut broker = AgentBrokerCore::new().unwrap();
    configure_test_direct_http_account(&mut broker, Uuid::parse_str(account_ref).unwrap());
    let client = broker
        .register_client(
            peer(),
            hello(&[
                "vaultmesh_accounts_list",
                "vaultmesh_accounts_list",
                "vaultmesh_accounts_list",
                "vaultmesh_request_local_ui",
                "vaultmesh_http_request",
            ]),
            1_000,
        )
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().into_iter().next().unwrap();
    assert!(
        !session
            .allowed_tools
            .contains(&"vaultmesh_permission_request".into())
    );
    assert!(
        session
            .allowed_tools
            .contains(&"vaultmesh_http_request".into())
    );
    assert!(!session.allowed_accounts.contains(&account_ref.to_owned()));

    let response = broker_permission_request(
        &mut broker,
        Uuid::parse_str(&client.client_id).unwrap(),
        &session,
        account_ref,
        json!({
            "tool": "vaultmesh_http_request",
            "actionParameters": { "method": "GET", "path": "/status" }
        }),
        1_002,
    );
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["status"], "pending-action");
    let pending = broker.permission_requests();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].risk, "R1");
    assert_eq!(
        pending[0].approved_display,
        "https://api.example.test/v1/status"
    );
    let after_execution_timeout = 1_002 + AUTHORIZATION_TTL_MILLIS;
    assert_eq!(
        broker.permission_wait_outcome(&pending[0].permission_ref, after_execution_timeout),
        PermissionWaitOutcome::Pending
    );

    broker
        .activate_pending_direct_action(&pending[0].permission_ref, after_execution_timeout + 1)
        .unwrap();
    broker
        .resolve_permission(
            &pending[0].permission_ref,
            PermissionDecision::AllowOnce,
            after_execution_timeout + 2,
        )
        .unwrap();
    let granted_session = broker.sessions().into_iter().next().unwrap();
    assert!(
        granted_session
            .allowed_tools
            .contains(&"vaultmesh_http_request".into())
    );
    let attempted = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &account_request(
            &granted_session,
            Uuid::new_v4(),
            account_ref,
            "vaultmesh_http_request",
            json!({ "method": "GET", "path": "/status" }),
        ),
        after_execution_timeout + 3,
    );
    assert_eq!(attempted["error"]["code"], "adapter-unavailable");
    let next_attempt = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &account_request(
            &granted_session,
            Uuid::new_v4(),
            account_ref,
            "vaultmesh_http_request",
            json!({ "method": "GET", "path": "/status" }),
        ),
        after_execution_timeout + 4,
    );
    assert_eq!(next_attempt["error"]["code"], "authorization-required");
}

#[test]
fn ct_agent_permission_connection_deny_blocks_matching_actions_until_disconnect() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let mut broker = AgentBrokerCore::new().unwrap();
    configure_test_direct_http_account(&mut broker, Uuid::parse_str(account_ref).unwrap());
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_http_request"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let session = broker.sessions().into_iter().next().unwrap();
    let response = broker_permission_request(
        &mut broker,
        client_id,
        &session,
        account_ref,
        json!({
            "tool": "vaultmesh_http_request",
            "actionParameters": { "method": "GET", "path": "/status" }
        }),
        1_002,
    );
    assert_eq!(response["result"]["status"], "pending-action");
    let pending = broker.permission_requests().remove(0);
    broker
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Deny,
                scope: PermissionScope::Exact,
                duration: PermissionDuration::Connection,
                path_pattern: None,
            },
            1_003,
        )
        .unwrap();

    let denied = broker.handle_json(
        client_id,
        &account_request(
            &session,
            Uuid::new_v4(),
            account_ref,
            "vaultmesh_http_request",
            json!({ "method": "GET", "path": "/status" }),
        ),
        1_004,
    );
    assert_eq!(denied["error"]["code"], "authorization-denied");
    assert!(broker.permission_requests().is_empty());

    broker.disconnect(client_id);
    assert!(broker.transport_permission_grants.is_empty());
}

#[test]
fn ct_agent_account_discovery_pages_vault_candidates_without_secret_fields() {
    let candidates = vec![
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000091").unwrap(),
            kind: "secret".into(),
            label: "Beta Token".into(),
        },
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000090").unwrap(),
            kind: "secret".into(),
            label: "Alpha Token".into(),
        },
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000092").unwrap(),
            kind: "login".into(),
            label: "Service Token".into(),
        },
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000093").unwrap(),
            kind: "ssh".into(),
            label: "Unraid".into(),
        },
    ];
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: candidates.clone(),
        })
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().remove(0);
    let first = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["secret"], "limit": 1 }),
        ),
        1_002,
    );
    assert_eq!(first["result"]["accounts"][0]["label"], "Alpha Token");
    assert!(first["result"]["accounts"][0]["source"].is_null());
    assert!(first["result"]["accounts"][0]["permissionSummary"].is_null());
    assert!(
        first["result"]["accounts"][0]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("http"))
    );
    let next_cursor = first["result"]["nextCursor"].as_str().unwrap().to_owned();
    assert!(next_cursor.starts_with("v2:"));
    let serialized = first.to_string();
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("token-value"));

    let second = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["secret"], "limit": 1, "cursor": next_cursor }),
        ),
        1_003,
    );
    assert_eq!(second["result"]["accounts"][0]["label"], "Beta Token");
    assert!(second["result"]["nextCursor"].is_null());

    let ssh = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["ssh"], "capabilities": ["ssh-exec"] }),
        ),
        1_004,
    );
    assert_eq!(ssh["result"]["total"], 1);
    assert_eq!(ssh["result"]["accounts"][0]["label"], "Unraid");
    assert!(
        ssh["result"]["accounts"][0]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("ssh-exec"))
    );

    let tool_name_is_not_a_capability = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "capabilities": ["vaultmesh_ssh_exec"] }),
        ),
        1_005,
    );
    assert_eq!(
        tool_name_is_not_a_capability["error"]["code"],
        "invalid-parameters"
    );
}

#[test]
fn ct_api_environment_discovery_is_allowlisted_and_policy_drift_invalidates_cursor() {
    let candidates = Arc::new(Mutex::new(vec![
        AgentApiEnvironmentCandidate {
            environment_ref: Uuid::parse_str("00000000-0000-4000-8000-0000000000a1").unwrap(),
            label: "Example · Production".into(),
            environment: "production".into(),
            capability: "http".into(),
            openapi_url: Some("https://docs.example.test/openapi.json".into()),
            revision: 1,
            policy_digest: "a".repeat(64),
        },
        AgentApiEnvironmentCandidate {
            environment_ref: Uuid::parse_str("00000000-0000-4000-8000-0000000000a2").unwrap(),
            label: "Example · Staging".into(),
            environment: "staging".into(),
            capability: "http".into(),
            openapi_url: None,
            revision: 1,
            policy_digest: "b".repeat(64),
        },
    ]));
    let catalog = Arc::clone(&candidates);
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_api_environment_catalog(Arc::new(move || Ok(catalog.lock().unwrap().clone())));
    let client = broker
        .register_client(
            peer(),
            hello(&["vaultmesh_accounts_list", "vaultmesh_http_request"]),
            1_000,
        )
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().remove(0);
    let first = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({
                "kinds": ["api-environment"], "capabilities": ["http"], "limit": 1
            }),
        ),
        1_002,
    );
    let account = &first["result"]["accounts"][0];
    assert_eq!(account["kind"], "api-environment");
    assert_eq!(account["environmentRef"], account["accountRef"]);
    assert_eq!(
        account["openapiUrl"],
        "https://docs.example.test/openapi.json"
    );
    assert_eq!(account["capabilities"], json!(["http"]));
    assert_eq!(account["actions"], json!([]));
    let serialized = first.to_string();
    for forbidden in [
        "api.example.test/v1",
        "authorization",
        "credentialRef",
        "x-api-key",
        "secret-canary",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    let unavailable = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &account_request(
            &session,
            Uuid::new_v4(),
            account["accountRef"].as_str().unwrap(),
            "vaultmesh_http_request",
            json!({ "method": "GET", "path": "/status" }),
        ),
        1_002,
    );
    assert_eq!(unavailable["error"]["code"], "account-unavailable");
    let cursor = first["result"]["nextCursor"].as_str().unwrap().to_owned();
    candidates.lock().unwrap()[0].revision = 2;
    candidates.lock().unwrap()[0].policy_digest = "c".repeat(64);
    let drifted = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({
                "kinds": ["api-environment"], "capabilities": ["http"], "limit": 1, "cursor": cursor
            }),
        ),
        1_003,
    );
    assert_eq!(drifted["error"]["code"], "invalid-cursor");
}

#[test]
fn ct_agent_account_discovery_advertises_complete_direct_ssh_chain_and_configured_tunnels() {
    let account_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000098").unwrap();
    let mut definition = serde_json::to_value(test_agent_connector_definition(
        "00000000-0000-4000-8000-000000000099",
        &["vaultmesh_ssh_tunnel_open"],
    ))
    .unwrap();
    definition["credentialRefs"][0]["itemId"] = json!(account_ref);
    let definition: AgentConnectorDefinition = serde_json::from_value(definition).unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: vec![definition.clone()],
            candidates: vec![AgentVaultAccountCandidate {
                account_ref,
                kind: "ssh".into(),
                label: "Direct SSH".into(),
            }],
        })
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().remove(0);
    let response = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["ssh"] }),
        ),
        1_002,
    );

    assert_eq!(response["result"]["total"], 1);
    let account = &response["result"]["accounts"][0];
    assert_eq!(account["accountRef"], account_ref.to_string());
    let capabilities = account["capabilities"].as_array().unwrap();
    for capability in [
        "ssh-exec",
        "ssh-transfer",
        "ssh-key-install",
        "ssh-host-setup",
        "ssh-pty",
        "ssh-tunnel",
        "local-file",
    ] {
        assert!(capabilities.contains(&json!(capability)), "{capability}");
    }
    let actions = account["actions"].as_array().unwrap();
    for action in [
        "upload",
        "download",
        "install-public-key",
        "setup-openssh-host",
        "pty",
        "database",
    ] {
        assert!(
            actions.iter().any(|candidate| candidate["name"] == action),
            "{action}"
        );
    }
    assert!(!response.to_string().contains("server-password"));
}

#[test]
fn ct_agent_account_discovery_projects_managed_web_actions_without_definition_details() {
    let definition_ref = "00000000-0000-4000-8000-000000000089";
    let web_ref = "00000000-0000-4000-8000-000000000090";
    let connector_definitions = vec![test_managed_web_definition(definition_ref, web_ref)];
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: connector_definitions.clone(),
            candidates: Vec::new(),
        })
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let response = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &broker.sessions().remove(0),
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({}),
        ),
        1_002,
    );
    let accounts = response["result"]["accounts"].as_array().unwrap();
    let account = |account_ref: &str| {
        accounts
            .iter()
            .find(|account| account["accountRef"] == account_ref)
            .unwrap()
    };
    let action_tools = |account: &Value, name: &str| {
        account["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|action| action["name"].as_str() == Some(name))
            .unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone()
    };

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["accountRef"], web_ref);
    assert!(!response.to_string().contains(definition_ref));
    assert!(action_tools(account(web_ref), "report").contains(&json!("vaultmesh_result_save")));
    for forbidden in [
        "portal.example.test",
        "/usr/bin/example",
        "credentialRefs",
        "targetPolicy",
    ] {
        assert!(
            !response.to_string().contains(forbidden),
            "leaked {forbidden}"
        );
    }
}

#[test]
fn ct_agent_account_discovery_rejects_cursor_after_catalog_drift() {
    let candidates = Arc::new(Mutex::new(vec![
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000081").unwrap(),
            kind: "login".into(),
            label: "Alpha Login".into(),
        },
        AgentVaultAccountCandidate {
            account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000082").unwrap(),
            kind: "login".into(),
            label: "Beta Login".into(),
        },
    ]));
    let catalog_candidates = candidates.clone();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: catalog_candidates.lock().unwrap().clone(),
        })
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_accounts_list"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().remove(0);
    let first = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["login"], "limit": 1 }),
        ),
        1_002,
    );
    let cursor = first["result"]["nextCursor"].as_str().unwrap().to_owned();
    candidates.lock().unwrap().push(AgentVaultAccountCandidate {
        account_ref: Uuid::parse_str("00000000-0000-4000-8000-000000000083").unwrap(),
        kind: "login".into(),
        label: "Gamma Login".into(),
    });

    let drifted = broker.handle_json(
        Uuid::parse_str(&client.client_id).unwrap(),
        &request(
            &session,
            Uuid::new_v4(),
            "vaultmesh_accounts_list",
            json!({ "kinds": ["login"], "limit": 1, "cursor": cursor }),
        ),
        1_003,
    );
    assert_eq!(drifted["error"]["code"], "invalid-cursor");
}

#[test]
fn ct_agent_authz_vault_candidate_never_falls_back_to_an_implicit_connector() {
    let source_item_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000097").unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "login".into(),
                label: "Incomplete login".into(),
            }],
        })
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_http_request"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let request = serde_json::to_vec(&json!({
        "protocolVersion": 2,
        "requestId": Uuid::new_v4(),
        "accountRef": source_item_ref,
        "tool": "vaultmesh_http_request",
        "toolVersion": 2,
        "parameters": { "method": "GET", "path": "/status" }
    }))
    .unwrap();
    let response = broker.handle_json(Uuid::parse_str(&client.client_id).unwrap(), &request, 1_002);

    assert_eq!(response["error"]["code"], "account-policy-denied");
    assert_eq!(response["error"]["retryable"], false);
    assert!(response["error"]["details"].is_null());
    assert!(broker.permission_requests().is_empty());
    assert!(broker.connector_definitions.is_empty());
}

#[test]
fn ct_agent_authz_direct_ssh_action_uses_item_ref_without_session_or_permission_tool() {
    let source_item_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000094").unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "ssh".into(),
                label: "Direct SSH".into(),
            }],
        })
    }));
    broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, parameters| {
        assert_eq!(item_id, source_item_ref);
        assert_eq!(tool, "vaultmesh_ssh_exec");
        assert_eq!(parameters["program"], "hostname");
        Ok(test_direct_ssh_policy(
            item_id,
            "Direct SSH",
            "server.example.test",
        ))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let direct_request = |request_id| {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": request_id,
            "accountRef": source_item_ref,
            "tool": "vaultmesh_ssh_exec",
            "toolVersion": 2,
            "parameters": { "program": "hostname", "arguments": [] }
        }))
        .unwrap()
    };

    let request_id = Uuid::new_v4();
    let original_request = direct_request(request_id);
    let challenged = broker.handle_json(client_id, &original_request, 1_002);
    assert_eq!(challenged["error"]["code"], "authorization-required");
    assert_eq!(
        challenged["error"]["nativeActionRequired"],
        "request-authorization"
    );
    let pending = broker.permission_requests().remove(0);
    assert_eq!(pending.expires_at, 1_002 + PERMISSION_TTL_MILLIS);
    assert_eq!(pending.action_display, "hostname");
    assert_eq!(pending.risk, "R1");
    assert_eq!(
        broker.permission_wait_outcome(&pending.permission_ref, 1_002 + AUTHORIZATION_TTL_MILLIS,),
        PermissionWaitOutcome::Pending
    );
    assert_eq!(
        challenged["error"]["details"]["authorizationRef"],
        pending.permission_ref
    );
    broker
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    assert!(broker.connector_definitions.is_empty());
    assert_eq!(broker.active_direct_ssh_policies.len(), 1);
    broker
        .resolve_permission(
            &pending.permission_ref,
            PermissionDecision::AllowSession,
            1_003,
        )
        .unwrap();

    let executor: AgentToolExecutor = Arc::new(move |tool, account_ref, parameters, _, scope| {
        assert_eq!(tool, "vaultmesh_ssh_exec");
        assert_eq!(account_ref, Some(source_item_ref.to_string().as_str()));
        assert_eq!(parameters["program"], "hostname");
        assert_eq!(
            scope
                .direct_ssh_policy
                .as_ref()
                .map(|policy| policy.account_ref),
            Some(source_item_ref)
        );
        Ok(json!({ "exitStatus": 0, "stdout": "host\n", "stderr": "" }))
    });
    assert_eq!(
        broker.permission_wait_outcome(&pending.permission_ref, 1_004),
        PermissionWaitOutcome::Allowed
    );
    let (mut executed, mut audit, action) =
        broker.continue_json_for_dispatch(client_id, &original_request, 1_004);
    execute_authorized_action(&mut executed, &mut audit, action, &executor);
    assert_eq!(executed["ok"], true, "{executed}");
    assert_eq!(executed["result"]["exitStatus"], 0);
    let changed_arguments = serde_json::to_vec(&json!({
        "protocolVersion": 2,
        "requestId": Uuid::new_v4(),
        "accountRef": source_item_ref,
        "tool": "vaultmesh_ssh_exec",
        "toolVersion": 2,
        "parameters": { "program": "hostname", "arguments": ["--help"] }
    }))
    .unwrap();
    let changed = broker.handle_json(client_id, &changed_arguments, 1_005);
    assert_eq!(changed["error"]["code"], "authorization-required");
    assert_eq!(broker.permission_requests().len(), 1);
}

#[test]
fn ct_agent_authz_compiles_exact_plans_for_every_direct_ssh_action() {
    let source_item_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000094").unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "ssh".into(),
                label: "Direct SSH".into(),
            }],
        })
    }));
    broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, parameters| {
        assert_eq!(item_id, source_item_ref);
        Ok(test_direct_ssh_policy_for_tool(item_id, tool, parameters))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let cases = [
        (
            "vaultmesh_local_file_select",
            json!({ "purpose": "ssh-upload" }),
            "R2",
            2,
        ),
        (
            "vaultmesh_result_save",
            json!({ "resultRef": Uuid::new_v4() }),
            "R2",
            2,
        ),
        (
            "vaultmesh_ssh_upload",
            json!({ "fileRef": Uuid::new_v4(), "remotePath": "/srv/upload.bin" }),
            "R2",
            2,
        ),
        (
            "vaultmesh_ssh_download",
            json!({ "remotePath": "/srv/download.bin" }),
            "R1",
            2,
        ),
        (
            "vaultmesh_ssh_public_key_install",
            json!({ "publicKeyRef": Uuid::new_v4() }),
            "R2",
            2,
        ),
        (
            "vaultmesh_ssh_host_setup",
            json!({ "alias": "home-server" }),
            "R3",
            1,
        ),
        (
            "vaultmesh_ssh_pty_open",
            json!({ "terminal": "xterm-256color" }),
            "R3",
            1,
        ),
        (
            "vaultmesh_ssh_tunnel_open",
            json!({ "endpoint": "database" }),
            "R3",
            1,
        ),
    ];

    let case_count = cases.len();
    for (index, (tool, parameters, risk, scope_count)) in cases.into_iter().enumerate() {
        let bytes = account_request(
            &broker.sessions().remove(0),
            Uuid::new_v4(),
            &source_item_ref.to_string(),
            tool,
            parameters.clone(),
        );
        let challenged = broker.handle_json(client_id, &bytes, 1_002 + index as u64 * 10);
        assert_eq!(
            challenged["error"]["code"], "authorization-required",
            "{tool}"
        );
        let pending = broker.permission_requests().remove(0);
        assert_eq!(pending.tool, tool);
        assert_eq!(pending.risk, risk);
        assert_eq!(pending.available_scopes.len(), scope_count);
        broker
            .activate_pending_direct_action(&pending.permission_ref, 1_003 + index as u64 * 10)
            .unwrap();
        assert!(
            broker
                .active_direct_ssh_policies
                .values()
                .any(|policy| policy.tool == tool)
        );
        broker
            .resolve_permission(
                &pending.permission_ref,
                PermissionDecision::AllowSession,
                1_004 + index as u64 * 10,
            )
            .unwrap();
    }
    assert_eq!(broker.active_direct_ssh_policies.len(), case_count);
}

#[test]
fn ct_agent_authz_pty_child_actions_reuse_the_open_session_without_new_prompt() {
    let source_item_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000094").unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "ssh".into(),
                label: "Direct SSH".into(),
            }],
        })
    }));
    broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, parameters| {
        Ok(test_direct_ssh_policy_for_tool(item_id, tool, parameters))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let session = broker.sessions().remove(0);
    let open = account_request(
        &session,
        Uuid::new_v4(),
        &source_item_ref.to_string(),
        "vaultmesh_ssh_pty_open",
        json!({ "terminal": "xterm-256color" }),
    );
    assert_eq!(
        broker.handle_json(client_id, &open, 1_002)["error"]["code"],
        "authorization-required"
    );
    let pending = broker.permission_requests().remove(0);
    broker
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    broker
        .resolve_permission(
            &pending.permission_ref,
            PermissionDecision::AllowSession,
            1_004,
        )
        .unwrap();

    let read = account_request(
        &session,
        Uuid::new_v4(),
        &source_item_ref.to_string(),
        "vaultmesh_ssh_pty_read",
        json!({ "sessionRef": "pty_bound", "afterSequence": 0 }),
    );
    let (response, _, action) = broker.authorize_json_for_dispatch(client_id, &read, 1_005);
    assert!(response["error"].is_null(), "{response}");
    let action = action.expect("derived PTY action");
    assert_eq!(action.tool, "vaultmesh_ssh_pty_read");
    assert_eq!(action.parameters["sessionRef"], "pty_bound");
    assert!(action.scope.direct_ssh_policy.is_none());
    assert!(broker.permission_requests().is_empty());
}

#[test]
fn ct_agent_authz_web_connector_compiles_direct_action_plans() {
    let web_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000091").unwrap();
    let web = test_managed_web_definition(&web_ref.to_string(), &web_ref.to_string());
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: vec![web.clone()],
            candidates: Vec::new(),
        })
    }));
    broker.set_direct_connector_policy_factory(Arc::new(move |account_ref, tool, parameters| {
        Ok(test_direct_connector_policy(account_ref, tool, parameters))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let cases = [
        (web_ref, "vaultmesh_web_session_open", json!({}), "R2"),
        (
            web_ref,
            "vaultmesh_web_extract",
            json!({ "sessionRef": "web_bound", "recipe": "status" }),
            "R1",
        ),
        (
            web_ref,
            "vaultmesh_web_act",
            json!({ "sessionRef": "web_bound", "recipe": "restart", "input": {} }),
            "R3",
        ),
    ];

    for (index, (account_ref, tool, parameters, risk)) in cases.into_iter().enumerate() {
        let bytes = account_request(
            &broker.sessions().remove(0),
            Uuid::new_v4(),
            &account_ref.to_string(),
            tool,
            parameters,
        );
        let response = broker.handle_json(client_id, &bytes, 1_010 + index as u64 * 10);
        assert_eq!(
            response["error"]["code"], "authorization-required",
            "{tool}"
        );
        let pending = broker.permission_requests().remove(0);
        assert_eq!(pending.tool, tool);
        assert_eq!(pending.risk, risk);
        broker
            .activate_pending_direct_action(&pending.permission_ref, 1_011 + index as u64 * 10)
            .unwrap();
        assert!(
            broker
                .active_direct_connector_policies
                .values()
                .any(|policy| policy.tool == tool && policy.account_ref == account_ref)
        );
        broker
            .resolve_permission(
                &pending.permission_ref,
                PermissionDecision::AllowSession,
                1_012 + index as u64 * 10,
            )
            .unwrap();
    }
}

#[test]
fn ct_agent_authz_protected_actions_compile_direct_resource_plans() {
    let web_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000093").unwrap();
    let web = test_protected_web_definition(&web_ref.to_string(), &web_ref.to_string());
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: vec![web.clone()],
            candidates: vec![],
        })
    }));
    broker.set_direct_connector_policy_factory(Arc::new(move |account_ref, tool, parameters| {
        Ok(test_direct_connector_policy(account_ref, tool, parameters))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();

    let catalog = broker.accounts_page(&json!({})).unwrap();
    let accounts = catalog["accounts"].as_array().unwrap();
    let action_tools = |account_ref: Uuid, name: &str| {
        let account = accounts
            .iter()
            .find(|account| account["accountRef"] == account_ref.to_string())
            .unwrap();
        account["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|action| action["name"].as_str() == Some(name))
            .unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone()
    };
    assert_eq!(
        action_tools(web_ref, "totp"),
        vec![json!("vaultmesh_otp_fill")]
    );
    assert_eq!(
        action_tools(web_ref, "recovery"),
        vec![json!("vaultmesh_recovery_code_consume")]
    );
    assert_eq!(
        action_tools(web_ref, "register"),
        vec![
            json!("vaultmesh_passkey_perform"),
            json!("vaultmesh_passkey_request_begin")
        ]
    );
    let cases = [
        (
            web_ref,
            "vaultmesh_otp_fill",
            json!({ "targetRef": format!("webt_{}", "a".repeat(32)) }),
            "R2",
        ),
        (
            web_ref,
            "vaultmesh_recovery_code_consume",
            json!({ "targetRef": format!("webt_{}", "b".repeat(32)) }),
            "R3",
        ),
        (
            web_ref,
            "vaultmesh_passkey_request_begin",
            json!({ "sessionRef": "web_bound", "recipe": "register" }),
            "R3",
        ),
        (
            web_ref,
            "vaultmesh_passkey_perform",
            json!({ "requestRef": format!("webauthn_{}", "c".repeat(32)) }),
            "R3",
        ),
    ];
    for (index, (account_ref, tool, parameters, risk)) in cases.into_iter().enumerate() {
        let bytes = account_request(
            &broker.sessions().remove(0),
            Uuid::new_v4(),
            &account_ref.to_string(),
            tool,
            parameters,
        );
        let response = broker.handle_json(client_id, &bytes, 1_010 + index as u64 * 10);
        assert_eq!(
            response["error"]["code"], "authorization-required",
            "{tool}"
        );
        let pending = broker.permission_requests().remove(0);
        assert_eq!(pending.tool, tool);
        assert_eq!(pending.risk, risk);
        broker
            .activate_pending_direct_action(&pending.permission_ref, 1_011 + index as u64 * 10)
            .unwrap();
        assert!(
            broker
                .active_direct_connector_policies
                .values()
                .any(|policy| policy.account_ref == account_ref && policy.tool == tool)
        );
        broker
            .resolve_permission(
                &pending.permission_ref,
                PermissionDecision::AllowSession,
                1_012 + index as u64 * 10,
            )
            .unwrap();
    }
}

#[test]
fn ct_agent_authz_direct_http_action_uses_the_vault_item_directly() {
    let source_item_ref = Uuid::new_v4();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "secret".into(),
                label: "Direct API".into(),
            }],
        })
    }));
    broker.set_direct_http_policy_factory(Arc::new(move |item_id, kind, tool, parameters| {
        assert_eq!(item_id, source_item_ref);
        assert_eq!(kind, "secret");
        assert_eq!(tool, "vaultmesh_http_request");
        assert_eq!(parameters["method"], "GET");
        assert_eq!(parameters["path"], "/status");
        Ok(test_direct_http_policy(item_id))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let request = || {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "accountRef": source_item_ref,
            "tool": "vaultmesh_http_request",
            "toolVersion": 2,
            "parameters": { "method": "GET", "path": "/status" }
        }))
        .unwrap()
    };

    let challenged = broker.handle_json(client_id, &request(), 1_002);
    assert_eq!(challenged["error"]["code"], "authorization-required");
    let pending = broker.permission_requests().remove(0);
    assert!(pending.activation_required);
    assert_eq!(pending.operation.as_deref(), Some("/status"));
    assert_eq!(
        pending.approved_display,
        "https://api.example.test/v1/status"
    );
    assert_eq!(pending.action_display, "GET /v1/status");
    assert!(broker.connector_definitions.is_empty());
    broker
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    broker
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Exact,
                duration: PermissionDuration::Connection,
                path_pattern: None,
            },
            1_003,
        )
        .unwrap();

    let executor: AgentToolExecutor = Arc::new(move |tool, account_ref, parameters, _, scope| {
        assert_eq!(tool, "vaultmesh_http_request");
        assert_eq!(account_ref, Some(source_item_ref.to_string().as_str()));
        assert_eq!(parameters["method"], "GET");
        assert_eq!(parameters["path"], "/status");
        assert_eq!(
            scope
                .direct_http_policy
                .as_ref()
                .map(|policy| policy.account_ref),
            Some(source_item_ref)
        );
        Ok(json!({ "status": 200 }))
    });
    let executed = broker.handle_json_with_executor(client_id, &request(), 1_004, &executor);
    assert_eq!(executed["ok"], true, "{executed}");
    assert_eq!(executed["result"]["status"], 200);
}

#[test]
fn ct_agent_authz_direct_http_persistent_exact_restores_for_the_vault_item() {
    let source_item_ref = Uuid::new_v4();
    let directory = std::env::temp_dir().join(format!("vaultmesh-http-authz-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let store = AgentAuthorizationStore::memory(directory.join("rules.v1"), "vault-http");
    let proofs = AgentPairingProofs::memory();
    let configure = |broker: &mut AgentBrokerCore| {
        broker.set_access_check(Arc::new(|_| true));
        broker.set_authorization_store(store.clone());
        broker.set_account_catalog(Arc::new(move || {
            Ok(AgentAccountCatalogSnapshot {
                connector_definitions: Vec::new(),
                candidates: vec![AgentVaultAccountCandidate {
                    account_ref: source_item_ref,
                    kind: "secret".into(),
                    label: "Direct API".into(),
                }],
            })
        }));
        broker.set_direct_http_policy_factory(Arc::new(move |item_id, _, _, _| {
            Ok(test_direct_http_policy(item_id))
        }));
    };
    let request = || {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "accountRef": source_item_ref,
            "tool": "vaultmesh_http_request",
            "toolVersion": 2,
            "parameters": { "method": "GET", "path": "/status" }
        }))
        .unwrap()
    };

    let mut first = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    configure(&mut first);
    let client = first.register_client(peer(), hello(&[]), 1_000).unwrap();
    first.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    assert_eq!(
        first.handle_json(client_id, &request(), 1_002)["error"]["code"],
        "authorization-required"
    );
    let pending = first.permission_requests().remove(0);
    first
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    first
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Exact,
                duration: PermissionDuration::Permanent,
                path_pattern: None,
            },
            1_003,
        )
        .unwrap();
    drop(first);

    let mut restored = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    configure(&mut restored);
    let client = restored.register_client(peer(), hello(&[]), 2_000).unwrap();
    assert_eq!(client.pairing_state, PairingState::Paired);
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let executor: AgentToolExecutor = Arc::new(move |_, account_ref, _, _, scope| {
        assert_eq!(account_ref, Some(source_item_ref.to_string().as_str()));
        assert!(scope.direct_http_policy.is_some());
        Ok(json!({ "status": 200 }))
    });
    let executed = restored.handle_json_with_executor(client_id, &request(), 2_001, &executor);
    assert_eq!(executed["ok"], true, "{executed}");
    assert!(restored.connector_definitions.is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn ct_agent_authz_removed_http_transfer_tools_are_unregistered() {
    let account_ref = "00000000-0000-4000-8000-000000000096";
    let account_id = Uuid::parse_str(account_ref).unwrap();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_access_check(Arc::new(|_| true));
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: account_id,
                kind: "secret".into(),
                label: "Service token".into(),
            }],
        })
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();

    for (index, (tool, operation, extra)) in [
        (
            "vaultmesh_http_upload",
            "upload_artifact",
            json!({ "fileRef": Uuid::new_v4() }),
        ),
        ("vaultmesh_http_download", "download_report", json!({})),
    ]
    .into_iter()
    .enumerate()
    {
        let parameters = json!({ "operation": operation })
            .as_object()
            .unwrap()
            .iter()
            .chain(extra.as_object().unwrap())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<serde_json::Map<_, _>>();
        let request = || {
            serde_json::to_vec(&json!({
                "protocolVersion": 2,
                "requestId": Uuid::new_v4(),
                "accountRef": account_id,
                "tool": tool,
                "toolVersion": 1,
                "parameters": parameters
            }))
            .unwrap()
        };
        let now = 1_010 + index as u64 * 10;
        let challenged = broker.handle_json(client_id, &request(), now);
        assert_eq!(challenged["error"]["code"], "unknown-tool");
        assert!(broker.permission_requests().is_empty());
    }
}

#[test]
fn ct_agent_authz_persistent_http_path_scope_still_requires_fresh_r2_permission() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let account_id = Uuid::parse_str(account_ref).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "vaultmesh-connector-capability-authz-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let store = AgentAuthorizationStore::memory(directory.join("rules.v1"), "vault-connector-all");
    let proofs = AgentPairingProofs::memory();
    let configure = |broker: &mut AgentBrokerCore| {
        broker.set_access_check(Arc::new(|_| true));
        broker.set_authorization_store(store.clone());
        broker.set_account_catalog(Arc::new(move || {
            Ok(AgentAccountCatalogSnapshot {
                connector_definitions: Vec::new(),
                candidates: vec![AgentVaultAccountCandidate {
                    account_ref: account_id,
                    kind: "secret".into(),
                    label: "Direct API".into(),
                }],
            })
        }));
        broker.set_direct_http_policy_factory(Arc::new(move |item_id, kind, _, parameters| {
            assert_eq!(kind, "secret");
            let method = parameters["method"].as_str().unwrap();
            let path = parameters["path"].as_str().unwrap();
            let mut policy = test_direct_http_policy(item_id);
            policy.operation.method = method.to_owned();
            policy.operation.path = format!("/v1{path}");
            policy.operation.request_fields = vec!["service".into()];
            policy.operation.request_mode = vaultmesh_ffi::AgentHttpBodyMode::Json;
            policy.operation.risk = crate::agent_http_path_policy::method_risk(method).unwrap();
            policy.approved_display = format!("https://api.example.test/v1{path}");
            Ok(policy)
        }));
    };
    let request = || {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "accountRef": account_id,
            "tool": "vaultmesh_http_request",
            "toolVersion": 2,
            "parameters": {
                "method": "POST", "path": "/restart",
                "body": { "service": "api" }
            }
        }))
        .unwrap()
    };

    let mut first = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    configure(&mut first);
    let client = first.register_client(peer(), hello(&[]), 1_000).unwrap();
    first.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    assert_eq!(
        first.handle_json(client_id, &request(), 1_002)["error"]["code"],
        "authorization-required"
    );
    let pending = first.permission_requests().remove(0);
    assert_eq!(
        pending.available_scopes,
        vec![PermissionScope::Exact, PermissionScope::Path]
    );
    first
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    first
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Path,
                duration: PermissionDuration::Permanent,
                path_pattern: Some("/restart".to_owned()),
            },
            1_003,
        )
        .unwrap();
    drop(first);

    let mut restored = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    configure(&mut restored);
    let client = restored.register_client(peer(), hello(&[]), 2_000).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let response = restored.handle_json(client_id, &request(), 2_001);
    assert_eq!(response["error"]["code"], "authorization-required");
    let pending = restored.permission_requests().remove(0);
    assert_eq!(pending.risk, "R2");
    assert!(pending.fresh_confirmation_required);
    restored
        .activate_pending_direct_action(&pending.permission_ref, 2_002)
        .unwrap();
    restored
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Exact,
                duration: PermissionDuration::Once,
                path_pattern: None,
            },
            2_002,
        )
        .unwrap();
    let response = restored.handle_json(client_id, &request(), 2_003);
    assert_eq!(response["error"]["code"], "adapter-unavailable");
    assert!(restored.permission_requests().is_empty());
    assert!(restored.confirmations().is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn ct_agent_authz_direct_ssh_safe_scope_spans_catalog_commands_but_not_other_programs() {
    let source_item_ref = Uuid::new_v4();
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "ssh".into(),
                label: "Safe SSH".into(),
            }],
        })
    }));
    broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, parameters| {
        assert_eq!(item_id, source_item_ref);
        assert_eq!(tool, "vaultmesh_ssh_exec");
        let program = parameters["program"].as_str().unwrap();
        assert_eq!(parameters["program"], program);
        Ok(test_direct_ssh_policy(
            item_id,
            "Safe SSH",
            "safe.example.test",
        ))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let request = |program: &str| {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "accountRef": source_item_ref,
            "tool": "vaultmesh_ssh_exec",
            "toolVersion": 2,
            "parameters": { "program": program, "arguments": [] }
        }))
        .unwrap()
    };

    let challenged = broker.handle_json(client_id, &request("whoami"), 1_002);
    assert_eq!(challenged["error"]["code"], "authorization-required");
    let pending = broker.permission_requests().remove(0);
    assert_eq!(
        pending.available_scopes,
        vec![
            PermissionScope::Exact,
            PermissionScope::Safe,
            PermissionScope::All
        ]
    );
    broker
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    broker
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Safe,
                duration: PermissionDuration::Connection,
                path_pattern: None,
            },
            1_003,
        )
        .unwrap();

    let executor: AgentToolExecutor = Arc::new(move |_, account_ref, parameters, _, scope| {
        assert_eq!(account_ref, Some(source_item_ref.to_string().as_str()));
        assert_eq!(parameters["program"], "hostname");
        assert!(scope.direct_ssh_policy.is_some());
        Ok(json!({ "exitStatus": 0, "stdout": "safe\n", "stderr": "" }))
    });
    let safe = broker.handle_json_with_executor(client_id, &request("hostname"), 1_004, &executor);
    assert_eq!(safe["ok"], true, "{safe}");

    let unsafe_request = broker.handle_json(client_id, &request("not-allowed"), 1_005);
    assert_eq!(unsafe_request["error"]["code"], "authorization-required");
}

#[test]
fn ct_agent_authz_persistent_exact_rule_restores_after_reconnect_and_target_drift_asks() {
    let source_item_ref = Uuid::new_v4();
    let directory = std::env::temp_dir().join(format!("vaultmesh-broker-authz-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let store = AgentAuthorizationStore::memory(directory.join("rules.v1"), "vault-a");
    let proofs = AgentPairingProofs::memory();

    let configure = |broker: &mut AgentBrokerCore, host: &'static str| {
        broker.set_access_check(Arc::new(|_| true));
        broker.set_authorization_store(store.clone());
        broker.set_account_catalog(Arc::new(move || {
            Ok(AgentAccountCatalogSnapshot {
                connector_definitions: Vec::new(),
                candidates: vec![AgentVaultAccountCandidate {
                    account_ref: source_item_ref,
                    kind: "ssh".into(),
                    label: "Persistent SSH".into(),
                }],
            })
        }));
        broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, parameters| {
            assert_eq!(item_id, source_item_ref);
            assert_eq!(tool, "vaultmesh_ssh_exec");
            let program = parameters["program"].as_str().unwrap();
            assert_eq!(parameters["program"], program);
            Ok(test_direct_ssh_policy(item_id, "Persistent SSH", host))
        }));
    };
    let request = || {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": Uuid::new_v4(),
            "accountRef": source_item_ref,
            "tool": "vaultmesh_ssh_exec",
            "toolVersion": 2,
            "parameters": { "program": "hostname", "arguments": [] }
        }))
        .unwrap()
    };

    let mut first = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    configure(&mut first, "server.example.test");
    let client = first.register_client(peer(), hello(&[]), 1_000).unwrap();
    first.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let challenged = first.handle_json(client_id, &request(), 1_002);
    assert_eq!(challenged["error"]["code"], "authorization-required");
    let pending = first.permission_requests().remove(0);
    first
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    first
        .resolve_permission_choice(
            &pending.permission_ref,
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Exact,
                duration: PermissionDuration::Permanent,
                path_pattern: None,
            },
            1_003,
        )
        .unwrap();
    drop(first);

    let mut restored = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    configure(&mut restored, "server.example.test");
    let client = restored.register_client(peer(), hello(&[]), 2_000).unwrap();
    assert_eq!(client.pairing_state, PairingState::Paired);
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let executor: AgentToolExecutor = Arc::new(move |_, account_ref, _, _, scope| {
        assert_eq!(account_ref, Some(source_item_ref.to_string().as_str()));
        assert!(scope.direct_ssh_policy.is_some());
        Ok(json!({ "exitStatus": 0, "stdout": "restored\n", "stderr": "" }))
    });
    let executed = restored.handle_json_with_executor(client_id, &request(), 2_001, &executor);
    assert_eq!(executed["ok"], true, "{executed}");
    assert!(restored.permission_requests().is_empty());
    drop(restored);

    let mut deny_rule = store.load("501").unwrap().remove(0);
    deny_rule.effect = PermissionEffect::Deny;
    deny_rule.updated_at = 2_100;
    store.upsert("501", deny_rule).unwrap();
    let mut denied = AgentBrokerCore::new_with_pairing_proofs(proofs.clone()).unwrap();
    configure(&mut denied, "server.example.test");
    let client = denied.register_client(peer(), hello(&[]), 2_200).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let denied_response = denied.handle_json(client_id, &request(), 2_201);
    assert_eq!(denied_response["error"]["code"], "authorization-denied");
    assert!(denied.permission_requests().is_empty());

    let mut drifted = AgentBrokerCore::new_with_pairing_proofs(proofs).unwrap();
    configure(&mut drifted, "changed.example.test");
    let client = drifted.register_client(peer(), hello(&[]), 3_000).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let drift = drifted.handle_json(client_id, &request(), 3_001);
    assert_eq!(drift["error"]["code"], "authorization-required");
    assert_eq!(drifted.permission_requests().len(), 1);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn ct_agent_permission_connector_requires_its_exact_directory_account_ref() {
    let source_item_ref = Uuid::parse_str("00000000-0000-4000-8000-000000000077").unwrap();
    let definition_ref = "00000000-0000-4000-8000-000000000099";
    let definition = test_managed_web_definition(definition_ref, &source_item_ref.to_string());
    let mut broker = AgentBrokerCore::new().unwrap();
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: vec![definition.clone()],
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "secret".into(),
                label: "Service Token".into(),
            }],
        })
    }));
    broker.set_direct_connector_policy_factory(Arc::new(move |account_ref, tool, parameters| {
        Ok(test_direct_connector_policy(account_ref, tool, parameters))
    }));
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_web_session_open"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().remove(0);
    let error = broker
        .request_permission(
            Uuid::parse_str(&client.client_id).unwrap(),
            Uuid::parse_str(&session.session_id).unwrap(),
            definition_ref,
            &json!({
            "tool": "vaultmesh_web_session_open",
            "actionParameters": {}
            }),
            1_002,
        )
        .unwrap_err();
    assert_eq!(error.code, "account-unavailable");
    assert!(broker.permission_requests().is_empty());
}

#[test]
fn ct_agent_permission_permanent_requires_scoped_store_and_session_grants_remain_available() {
    let account_ref = "00000000-0000-4000-8000-000000000099";
    let mut broker = AgentBrokerCore::new().unwrap();
    configure_test_direct_http_account(&mut broker, Uuid::parse_str(account_ref).unwrap());
    let client = broker
        .register_client(peer(), hello(&["vaultmesh_http_request"]), 1_000)
        .unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let session = broker.sessions().into_iter().next().unwrap();
    let response = broker_permission_request(
        &mut broker,
        Uuid::parse_str(&client.client_id).unwrap(),
        &session,
        account_ref,
        json!({
            "tool": "vaultmesh_http_request",
            "actionParameters": { "method": "GET", "path": "/status" }
        }),
        1_002,
    );
    assert_eq!(response["result"]["status"], "pending-action");
    let pending = broker.permission_requests().remove(0);
    assert_eq!(pending.risk, "R1");
    broker
        .activate_pending_direct_action(&pending.permission_ref, 1_003)
        .unwrap();
    assert_eq!(
        broker
            .resolve_permission(
                &pending.permission_ref,
                PermissionDecision::AlwaysAllow,
                1_004,
            )
            .unwrap_err()
            .code,
        "permission-store-unavailable"
    );
    broker
        .resolve_permission(
            &pending.permission_ref,
            PermissionDecision::AllowSession,
            1_005,
        )
        .unwrap();
}

#[test]
fn ct_agent_ssh_agent_open_requires_unlock_but_no_authorization_prompt() {
    let unlocked_clients = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
    let source_item_ref = Uuid::new_v4();
    let mut broker =
        AgentBrokerCore::new_with_pairing_proofs(AgentPairingProofs::memory()).unwrap();
    let access = Arc::clone(&unlocked_clients);
    broker.set_access_check(Arc::new(move |client_id| {
        access
            .lock()
            .is_ok_and(|clients| clients.contains(&client_id))
    }));
    broker.set_account_catalog(Arc::new(move || {
        Ok(AgentAccountCatalogSnapshot {
            connector_definitions: Vec::new(),
            candidates: vec![AgentVaultAccountCandidate {
                account_ref: source_item_ref,
                kind: "ssh".into(),
                label: "Direct SSH".into(),
            }],
        })
    }));
    broker.set_direct_ssh_policy_factory(Arc::new(move |item_id, tool, _parameters| {
        assert_eq!(item_id, source_item_ref);
        assert_eq!(tool, "vaultmesh_ssh_agent_open");
        Ok(test_direct_ssh_policy(
            item_id,
            "Direct SSH",
            "server.example.test",
        ))
    }));
    let client = broker.register_client(peer(), hello(&[]), 1_000).unwrap();
    broker.approve_pairing_at(&client.client_id, 1_001).unwrap();
    let client_id = Uuid::parse_str(&client.client_id).unwrap();
    let agent_open_request = |request_id| {
        serde_json::to_vec(&json!({
            "protocolVersion": 2,
            "requestId": request_id,
            "accountRef": source_item_ref,
            "tool": "vaultmesh_ssh_agent_open",
            "toolVersion": 1,
            "parameters": { "durationMinutes": 15 }
        }))
        .unwrap()
    };

    // 1. When locked: must require unlock
    let request_id = Uuid::new_v4();
    let locked = broker.handle_json(client_id, &agent_open_request(request_id), 1_002);
    assert_eq!(locked["error"]["code"], "mcp-locked");
    assert_eq!(locked["error"]["nativeActionRequired"], "unlock-agent");

    // 2. Unlock vault
    let unlock_ref = locked["error"]["details"]["unlockRef"].as_str().unwrap().to_owned();
    unlocked_clients.lock().unwrap().insert(client_id);
    broker
        .resolve_unlock_request(&unlock_ref, client_id, true, 1_003)
        .unwrap();

    // 3. When unlocked: does NOT return permission-required or authorization-required!
    let next_id = Uuid::new_v4();
    let (response, _audit, action) =
        broker.authorize_json_for_dispatch(client_id, &agent_open_request(next_id), 1_004);
    assert_ne!(response["error"]["code"], "authorization-required");
    assert_ne!(response["error"]["code"], "permission-required");
    assert_eq!(response["ok"], true);
    let authorized = action.expect("action authorized without popup");
    assert_eq!(authorized.tool, "vaultmesh_ssh_agent_open");
    assert_eq!(authorized.account_ref.as_deref(), Some(source_item_ref.to_string().as_str()));
}
