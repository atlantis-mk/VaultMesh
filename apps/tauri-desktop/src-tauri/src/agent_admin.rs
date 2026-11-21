use super::*;
use crate::{
    agent_broker::capability_registry,
    pin_domain_adapter::{PinDomainAction, PinDomainFactory, PinDomainKind, execute_pin_domain_action},
};

pub(super) fn handle_agent_admin(
    app: Option<&AppHandle>,
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    let unlocked = state
        .runtime
        .lock()
        .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
        .status()
        .unlocked;
    if !unlocked {
        return Err("请先在桌面端解锁保险库。".to_owned());
    }
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    let map_error =
        |error: agent_broker::AgentBrokerError| format!("Agent 操作被拒绝：{}", error.code);
    match operation {
        "agent.status" => {
            require_empty_object(&input)?;
            let registry = capability_registry().map_err(map_error)?;
            let shim_path = installed_agent_shim_path();
            let shim_available = shim_path.is_file();
            let (connector_definitions, audit_events) = {
                let mut runtime = state
                    .runtime
                    .lock()
                    .map_err(|_| "保险库运行时暂时不可用。".to_owned())?;
                let connector_definitions = runtime
                    .agent_connector_definition_records()
                    .map_err(|error| error.public_message().to_owned())?;
                let audit_events = runtime
                    .agent_audit_events()
                    .map_err(|error| error.public_message().to_owned())?;
                (connector_definitions, audit_events)
            };
            broker
                .sync_connector_definitions(connector_definitions)
                .map_err(map_error)?;
            let selected_vault_path = state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .current_path();
            let access = state
                .agent_vault_access
                .status(None, &selected_vault_path)?;
            let agent_pin_adapter = PinDomainFactory::create_for(PinDomainKind::Agent);
            let pin = agent_pin_adapter
                .service(state)
                .lock()
                .map_err(|_| agent_pin_adapter.unavailable_error().to_owned())?
                .status();
            Ok(json!({
                "protocolVersion": registry.protocol_version,
                "shimPath": shim_path,
                "shimAvailable": shim_available,
                "confirmations": broker.confirmations(),
                "permissionRequests": broker.permission_requests(),
                "authorizationRules": broker.authorization_rules(),
                "auditEvents": audit_events,
                "clients": broker.admin_clients(),
                "access": access,
                "pin": pin,
                "tools": registry.tools
            }))
        }
        "agent.pin.status" => {
            drop(broker);
            execute_pin_domain_action(
                state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Status,
                input,
            )
        }
        "agent.pin.enable" => {
            drop(broker);
            let result = execute_pin_domain_action(
                state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Enable,
                input,
            )?;
            crate::desktop_runtime::lock_agent_sessions(app, state);
            Ok(result)
        }
        "agent.pin.disable" => {
            drop(broker);
            let result = execute_pin_domain_action(
                state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Disable,
                input,
            )?;
            crate::desktop_runtime::lock_agent_sessions(app, state);
            Ok(result)
        }
        "agent.access.lock-all" => {
            require_empty_object(&input)?;
            drop(broker);
            finish_agent_boundary_lock(state);
            Ok(json!({ "locked": true }))
        }
        "agent.access.lock-client" => {
            let input: AgentClientIdInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let client_id =
                uuid::Uuid::parse_str(&input.client_id).map_err(|_| "请求参数无效。".to_owned())?;
            broker.lock_agent_client(client_id);
            Ok(json!({ "locked": true }))
        }
        "agent.access.settings.update" => {
            let settings: AgentAccessSettings =
                serde_json::from_value(input).map_err(|_| "Agent 自动锁定设置无效。")?;
            let expired_clients = state
                .agent_vault_access
                .update_settings(settings, unix_millis())?;
            for client_id in expired_clients {
                broker.expire_agent_client_authority(client_id);
            }
            Ok(json!(settings))
        }
        "agent.permission.action.resolve" => {
            let input: AgentPermissionActionResolveInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            if input.choice.effect != agent_broker::PermissionEffect::Allow {
                return Err("当前动作安装入口只接受允许授权。".to_owned());
            }
            if broker
                .activate_pending_direct_action(&input.permission_ref, unix_millis())
                .map_err(map_error)?
                .is_some()
            {
                let resolution = broker
                    .resolve_permission_choice(&input.permission_ref, input.choice, unix_millis())
                    .map_err(map_error)?;
                return Ok(json!({
                    "request": resolution.request,
                    "choice": resolution.choice
                }));
            }
            Err("该授权请求没有可激活的直接动作。".to_owned())
        }
        "agent.confirmation.approve" => {
            let input: AgentConfirmationInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            broker
                .approve_confirmation(&input.confirmation_ref, unix_millis())
                .map(|confirmation| json!(confirmation))
                .map_err(map_error)
        }
        "agent.confirmation.reject" => {
            let input: AgentConfirmationInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            broker
                .reject_confirmation(&input.confirmation_ref, unix_millis())
                .map(|()| json!({ "rejected": true }))
                .map_err(map_error)
        }
        "agent.permission.resolve" => {
            let input: AgentPermissionResolveInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let resolution = broker
                .resolve_permission_choice(&input.permission_ref, input.choice, unix_millis())
                .map_err(map_error)?;
            Ok(json!({
                "request": resolution.request,
                "choice": resolution.choice
            }))
        }
        "agent.authorization.rule.delete" => {
            let input: AgentAuthorizationRuleDeleteInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            broker
                .revoke_authorization_rule(&input.rule_id, unix_millis())
                .map_err(map_error)?;
            Ok(json!({ "deleted": true }))
        }
        "agent.audit.clear" => {
            require_empty_object(&input)?;
            state
                .runtime
                .lock()
                .map_err(|_| "保险库运行时暂时不可用。".to_owned())?
                .clear_agent_audit()
                .map(|()| json!({ "cleared": true }))
                .map_err(|error| error.public_message().to_owned())
        }
        "agent.client.revoke" => {
            let input: AgentClientIdInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            broker
                .revoke_client(&input.client_id)
                .map(|()| json!({ "revoked": true }))
                .map_err(map_error)
        }
        _ => Err("该桌面操作不被允许。".to_owned()),
    }
}

pub(super) fn installed_agent_shim_path() -> PathBuf {
    let executable_name = if cfg!(target_os = "windows") {
        "vaultmesh-agent-mcp.exe"
    } else {
        "vaultmesh-agent-mcp"
    };
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(executable_name)))
        .unwrap_or_else(|| PathBuf::from(executable_name))
}

#[cfg(test)]
mod agent_admin_tests {
    use super::*;
    use crate::{
        agent_authorization_window::DisplayedAgentAuthorization,
        agent_broker::{ClientHello, PeerIdentity},
    };
    use uuid::Uuid;

    #[test]
    fn agent_pin_enable_and_disable_lock_only_agent_and_protect_browser_unlock_window() {
        let root = std::env::temp_dir().join(format!("vaultmesh-agent-pin-lock-{}", Uuid::new_v4()));
        let state = crate::pin_domain_adapter::test_runtime_state(&root);
        let password = "correct horse battery staple";
        let vault_path = root.join("vaultmesh.vault");
        state
            .runtime
            .lock()
            .unwrap()
            .create(password.to_owned())
            .expect("create vault");

        let client_id = {
            let mut broker = state.agent_broker.lock().unwrap();
            let peer = PeerIdentity {
                user_id: "501".into(),
                process_id: 4242,
                executable: "/usr/bin/agent-test".into(),
                binary_identity: format!("sha256:{}", "a".repeat(64)),
            };
            let snapshot = broker
                .register_client(
                    peer,
                    ClientHello {
                        client_key: "agent-test-client".into(),
                    },
                    1_000,
                )
                .expect("register");
            broker
                .approve_pairing_at(&snapshot.client_id, 1_001)
                .expect("approve pairing");
            broker.restart_connection_sessions(1_002);
            assert_eq!(broker.sessions().len(), 1);
            Uuid::parse_str(&snapshot.client_id).expect("client uuid")
        };

        state
            .agent_vault_access
            .register_client(client_id, "agent-test-client".into());
        state
            .agent_vault_access
            .unlock_with_password(client_id, vault_path.clone(), password.to_owned())
            .expect("unlock agent access");
        assert!(state.agent_vault_access.is_unlocked(client_id));

        // Put BrowserUnlock in agent-unlock window; enabling Agent PIN must NOT disturb it.
        *state.agent_unlock_window_request.lock().unwrap() =
            Some(DisplayedAgentUnlock::BrowserUnlock {
                unlock_ref: "browser-unlock-ref".into(),
                vault_path: vault_path.clone(),
                master_password_reprompt: false,
            });
        *state.agent_authorization_window_request.lock().unwrap() =
            Some(DisplayedAgentAuthorization::Permission("perm-ref".into()));
        state
            .agent_authorization_window_deadline
            .store(99_999, std::sync::atomic::Ordering::Release);

        // Hold `lan_sync` mutex across `agent.pin.enable` to prove `lock_agent_sessions` never touches/stops it.
        let lan_guard = state.lan_sync.lock().unwrap();
        let enabled = handle_agent_admin(
            None,
            &state,
            "agent.pin.enable",
            json!({ "pin": "333333", "failureLimit": 4 }),
        )
        .expect("agent pin enable");
        drop(lan_guard);
        assert_eq!(enabled["enabled"], true);

        // Agent broker sessions & agent vault access must be locked, and auth window cleared.
        assert!(!state.agent_vault_access.is_unlocked(client_id));
        assert!(state.agent_broker.lock().unwrap().sessions().is_empty());
        assert!(state.agent_authorization_window_request.lock().unwrap().is_none());
        assert_eq!(
            state
                .agent_authorization_window_deadline
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        // Desktop stayed unlocked AND BrowserUnlock window request was preserved!
        assert!(state.runtime.lock().unwrap().status().unlocked);
        assert!(matches!(
            &*state.agent_unlock_window_request.lock().unwrap(),
            Some(DisplayedAgentUnlock::BrowserUnlock { unlock_ref, .. }) if unlock_ref == "browser-unlock-ref"
        ));

        // Now place an Agent unlock request in agent-unlock window and disable Agent PIN.
        state
            .agent_vault_access
            .unlock_with_password(client_id, vault_path, password.to_owned())
            .expect("re-unlock agent access");
        *state.agent_unlock_window_request.lock().unwrap() = Some(DisplayedAgentUnlock::Agent {
            unlock_ref: "agent-unlock-ref".into(),
            client_id,
        });
        *state.agent_authorization_window_request.lock().unwrap() =
            Some(DisplayedAgentAuthorization::Confirmation("confirm-ref".into()));
        state
            .agent_authorization_window_deadline
            .store(88_888, std::sync::atomic::Ordering::Release);

        let disabled =
            handle_agent_admin(None, &state, "agent.pin.disable", json!({})).expect("disable");
        assert_eq!(disabled["enabled"], false);
        assert!(!state.agent_vault_access.is_unlocked(client_id));
        assert!(state.agent_unlock_window_request.lock().unwrap().is_none());
        assert!(state.agent_authorization_window_request.lock().unwrap().is_none());
        assert_eq!(
            state
                .agent_authorization_window_deadline
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(state.runtime.lock().unwrap().status().unlocked);

        let _ = std::fs::remove_dir_all(root);
    }
}
