use super::*;
use crate::{
    agent_broker::capability_registry,
    pin_domain_adapter::{PinDomainAction, PinDomainFactory, PinDomainKind, execute_pin_domain_action},
};

pub(super) fn handle_agent_admin(
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
            execute_pin_domain_action(
                state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Enable,
                input,
            )
        }
        "agent.pin.disable" => {
            drop(broker);
            execute_pin_domain_action(
                state,
                PinDomainFactory::create_for(PinDomainKind::Agent),
                PinDomainAction::Disable,
                input,
            )
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
