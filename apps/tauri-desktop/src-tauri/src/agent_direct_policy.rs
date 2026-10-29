use super::*;
use crate::agent_broker::{
    AgentBrokerError, AgentDirectConnectorPolicy, AgentDirectHttpPolicy, AgentDirectSshPolicy,
};

pub(super) fn generate_direct_connector_policy(
    runtime: &mut DesktopRuntime,
    connector_id: uuid::Uuid,
    tool: &str,
    action_parameters: &Value,
) -> Result<AgentDirectConnectorPolicy, AgentBrokerError> {
    if !runtime.status().unlocked {
        return Err(AgentBrokerError::vault_locked());
    }
    let definition = runtime
        .agent_connector_definition(connector_id)
        .map_err(|_| AgentBrokerError::action_rule_unavailable("connector", tool))?;
    let explicitly_allowed = definition
        .capability_policy
        .allowed_tools
        .iter()
        .any(|allowed| allowed == tool);
    let derived_action = match (definition.connector_kind, tool) {
        (AgentConnectorKind::ManagedWeb, "vaultmesh_result_save") => definition
            .capability_policy
            .allowed_tools
            .iter()
            .any(|allowed| allowed == "vaultmesh_web_download"),
        (AgentConnectorKind::ManagedWeb, "vaultmesh_passkey_perform") => definition
            .capability_policy
            .allowed_tools
            .iter()
            .any(|allowed| allowed == "vaultmesh_passkey_request_begin"),
        _ => false,
    };
    if !definition.enabled || (!explicitly_allowed && !derived_action) {
        return Err(AgentBrokerError::action_rule_unavailable("connector", tool));
    }
    let allows = |required: &str| {
        definition
            .capability_policy
            .allowed_tools
            .iter()
            .any(|allowed| allowed == required)
    };
    if tool == "vaultmesh_result_save"
        && (definition.connector_kind != AgentConnectorKind::ManagedWeb
            || !allows("vaultmesh_web_download"))
    {
        return Err(AgentBrokerError::action_rule_unavailable("connector", tool));
    }
    let operation =
        crate::agent_broker::direct_action_operation(tool, action_parameters).map(str::to_owned);
    let (connector_kind, risk, action_display, approved_display) = match &definition.target_policy {
        AgentTargetPolicy::ManagedWeb {
            origins, recipes, ..
        } => {
            if tool == "vaultmesh_result_save" {
                validate_connector_file_action(tool, action_parameters)?;
            }
            let (risk, action_display) =
                direct_web_action(tool, operation.as_deref(), action_parameters, recipes)?;
            (
                "managed-web",
                risk,
                action_display,
                origins.first().cloned().ok_or_else(|| {
                    AgentBrokerError::action_rule_unavailable("connector-managed-web", tool)
                })?,
            )
        }
        _ => {
            return Err(AgentBrokerError::action_rule_unavailable("connector", tool));
        }
    };
    if risk_rank(&risk)? > risk_rank(&risk_name(definition.capability_policy.risk_ceiling)?)? {
        return Err(AgentBrokerError::action_rule_unavailable("connector", tool));
    }
    let target_digest = crate::agent_broker::canonical_parameters_digest(&json!({
        "connectorDefinition": definition.target_policy,
        "credentialRefs": definition.credential_refs,
        "capabilityPolicy": definition.capability_policy,
        "outputPolicy": definition.output_policy,
    }))?;
    let account_ref = definition
        .credential_refs
        .first()
        .map(|credential| credential.item_id)
        .ok_or_else(|| AgentBrokerError::action_rule_unavailable("connector", tool))?;
    Ok(AgentDirectConnectorPolicy {
        connector_ref: connector_id,
        account_ref,
        account_label: definition.display_label.clone(),
        environment: definition.environment.clone(),
        connector_kind: connector_kind.to_owned(),
        tool: tool.to_owned(),
        operation,
        risk,
        action_display,
        approved_display,
        target_digest,
    })
}

fn direct_web_action(
    tool: &str,
    operation: Option<&str>,
    parameters: &Value,
    recipes: &[vaultmesh_ffi::AgentWebRecipePolicy],
) -> Result<(String, String), AgentBrokerError> {
    use vaultmesh_ffi::AgentWebRecipeKind;

    if tool == "vaultmesh_web_session_close" {
        return Ok(("R1".to_owned(), "关闭隔离网站会话".to_owned()));
    }
    if tool == "vaultmesh_result_save" {
        return Ok(("R2".to_owned(), "保存网站下载结果".to_owned()));
    }
    if tool == "vaultmesh_otp_fill" {
        validate_bound_resource_parameter(parameters, "targetRef", "webt_")?;
        return Ok((
            highest_web_recipe_risk(
                recipes,
                &[AgentWebRecipeKind::Totp, AgentWebRecipeKind::EmailOtp],
                "R2",
            )?,
            "向绑定网站目标提交一次性验证码".to_owned(),
        ));
    }
    if tool == "vaultmesh_recovery_code_consume" {
        validate_bound_resource_parameter(parameters, "targetRef", "webt_")?;
        return Ok((
            highest_web_recipe_risk(recipes, &[AgentWebRecipeKind::RecoveryCode], "R3")?,
            "向绑定网站目标提交并消费恢复码".to_owned(),
        ));
    }
    if tool == "vaultmesh_passkey_perform" {
        validate_bound_resource_parameter(parameters, "requestRef", "webauthn_")?;
        return Ok((
            highest_web_recipe_risk(
                recipes,
                &[
                    AgentWebRecipeKind::PasskeyRegistration,
                    AgentWebRecipeKind::PasskeyAssertion,
                ],
                "R3",
            )?,
            "完成绑定页面发起的 Passkey 请求".to_owned(),
        ));
    }
    if tool == "vaultmesh_web_session_open" {
        let login = recipes
            .iter()
            .find(|recipe| recipe.kind == AgentWebRecipeKind::Login)
            .ok_or_else(|| {
                AgentBrokerError::action_rule_unavailable("connector-managed-web", tool)
            })?;
        return Ok((risk_name(login.risk)?, "打开并登录隔离网站会话".to_owned()));
    }
    let operation = operation.ok_or_else(|| {
        AgentBrokerError::action_input_insufficient(vec!["web.operation".to_owned()])
    })?;
    let expected_kind = match tool {
        "vaultmesh_web_navigate" => AgentWebRecipeKind::Navigate,
        "vaultmesh_web_extract" => AgentWebRecipeKind::Extract,
        "vaultmesh_web_act" => AgentWebRecipeKind::Action,
        "vaultmesh_web_download" => AgentWebRecipeKind::Download,
        "vaultmesh_passkey_request_begin" => {
            let recipe = recipes
                .iter()
                .find(|recipe| {
                    recipe.name == operation
                        && matches!(
                            recipe.kind,
                            AgentWebRecipeKind::PasskeyRegistration
                                | AgentWebRecipeKind::PasskeyAssertion
                        )
                })
                .ok_or_else(|| {
                    AgentBrokerError::action_rule_unavailable("connector-managed-web", tool)
                })?;
            return Ok((
                risk_name(recipe.risk)?,
                format!("捕获 Passkey 请求：{}", recipe.name),
            ));
        }
        _ => {
            return Err(AgentBrokerError::action_rule_unavailable(
                "connector-managed-web",
                tool,
            ));
        }
    };
    let recipe = recipes
        .iter()
        .find(|recipe| recipe.name == operation && recipe.kind == expected_kind)
        .ok_or_else(|| AgentBrokerError::action_rule_unavailable("connector-managed-web", tool))?;
    let verb = match expected_kind {
        AgentWebRecipeKind::Navigate => "导航",
        AgentWebRecipeKind::Extract => "提取",
        AgentWebRecipeKind::Action => "执行网站动作",
        AgentWebRecipeKind::Download => "下载",
        _ => unreachable!(),
    };
    Ok((risk_name(recipe.risk)?, format!("{verb}：{}", recipe.name)))
}

fn validate_bound_resource_parameter(
    parameters: &Value,
    field: &str,
    prefix: &str,
) -> Result<(), AgentBrokerError> {
    let value = parameters
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AgentBrokerError::action_input_insufficient(vec![format!("protected.{field}")])
        })?;
    let suffix = value.strip_prefix(prefix).ok_or_else(|| {
        AgentBrokerError::new(
            "invalid-parameters",
            "The protected resource reference is invalid.",
            false,
        )
    })?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AgentBrokerError::new(
            "invalid-parameters",
            "The protected resource reference is invalid.",
            false,
        ));
    }
    Ok(())
}

fn highest_web_recipe_risk(
    recipes: &[vaultmesh_ffi::AgentWebRecipePolicy],
    kinds: &[vaultmesh_ffi::AgentWebRecipeKind],
    minimum: &str,
) -> Result<String, AgentBrokerError> {
    let mut highest = minimum.to_owned();
    let mut found = false;
    for recipe in recipes.iter().filter(|recipe| kinds.contains(&recipe.kind)) {
        found = true;
        let candidate = risk_name(recipe.risk)?;
        if risk_rank(&candidate)? > risk_rank(&highest)? {
            highest = candidate;
        }
    }
    found.then_some(highest).ok_or_else(|| {
        AgentBrokerError::action_rule_unavailable("connector-managed-web", "protected")
    })
}

fn validate_connector_file_action(tool: &str, parameters: &Value) -> Result<(), AgentBrokerError> {
    match tool {
        "vaultmesh_result_save"
            if parameters
                .get("resultRef")
                .and_then(Value::as_str)
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .is_some() =>
        {
            Ok(())
        }
        _ => Err(AgentBrokerError::new(
            "invalid-parameters",
            "The connector file action is invalid.",
            false,
        )),
    }
}

fn risk_name(risk: AgentRiskTier) -> Result<String, AgentBrokerError> {
    serde_json::to_value(risk)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(AgentBrokerError::internal)
}

fn risk_rank(risk: &str) -> Result<u8, AgentBrokerError> {
    match risk {
        "R0" => Ok(0),
        "R1" => Ok(1),
        "R2" => Ok(2),
        "R3" => Ok(3),
        "R4" => Ok(4),
        _ => Err(AgentBrokerError::internal()),
    }
}

pub(super) fn generate_direct_http_policy(
    runtime: &mut DesktopRuntime,
    item_id: uuid::Uuid,
    item_kind: &str,
    tool: &str,
    action_parameters: &Value,
) -> Result<AgentDirectHttpPolicy, AgentBrokerError> {
    if !runtime.status().unlocked {
        return Err(AgentBrokerError::vault_locked());
    }
    if tool != "vaultmesh_http_request" || item_kind != "secret" {
        return Err(AgentBrokerError::action_rule_unavailable(item_kind, tool));
    }
    let method = action_parameters
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AgentBrokerError::action_input_insufficient(vec!["http.method".to_owned()])
        })?;
    let risk = crate::agent_http_path_policy::method_risk(method)?;
    let requested_path = action_parameters
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| AgentBrokerError::action_input_insufficient(vec!["http.path".to_owned()]))?;
    let response_mode = crate::agent_http_path_policy::response_mode(action_parameters)?;
    let query = action_parameters.get("query");
    let body = action_parameters.get("body");
    if query.is_some_and(|value| !value.is_object())
        || body.is_some_and(|value| !value.is_object())
        || (matches!(method, "GET" | "HEAD") && body.is_some())
        || (!matches!(method, "GET" | "HEAD") && query.is_some())
    {
        return Err(AgentBrokerError::new(
            "invalid-http-request",
            "The HTTP query or JSON body is invalid for this method.",
            false,
        ));
    }
    let input = if matches!(method, "GET" | "HEAD") {
        query
    } else {
        body
    }
    .cloned()
    .unwrap_or_else(|| json!({}));
    if serde_json::to_vec(&input).map_or(true, |bytes| bytes.len() > 256 * 1_024) {
        return Err(AgentBrokerError::new(
            "http-request-too-large",
            "The HTTP request parameters exceed the supported size.",
            false,
        ));
    }
    let detail = runtime
        .execute("secrets.detail", json!({ "id": item_id }))
        .map_err(|_| AgentBrokerError::action_input_insufficient(vec!["secret".to_owned()]))?;
    let mut missing = Vec::new();
    if detail.get("kind").and_then(Value::as_str) != Some("access-token") {
        missing.push("secret.kind=access-token".to_owned());
    }
    if detail
        .get("masterPasswordReprompt")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        missing.push(format!("{item_kind}.masterPasswordReprompt=false"));
    }
    if !runtime.agent_access_token_enabled(item_id).unwrap_or(false) {
        missing.push("secret.agentAccessTokenEnabled=true".to_owned());
    }
    let parsed = detail
        .get("website")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| url::Url::parse(value.trim()).ok());
    let valid_url = parsed.as_ref().filter(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if valid_url.is_none() {
        missing.push(
            "secret.website (exact HTTP(S) URL without userinfo, query, or fragment)".to_owned(),
        );
    }
    if !missing.is_empty() {
        return Err(AgentBrokerError::action_input_insufficient(missing));
    }
    let url = valid_url.expect("validated above");
    let origin = url.origin().ascii_serialization();
    let base_path = crate::agent_http_path_policy::canonicalize_exact_path(url.path())?;
    let path = crate::agent_http_path_policy::join_base_path(&base_path, requested_path)?;
    let request_fields = input
        .as_object()
        .ok_or_else(AgentBrokerError::internal)?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let operation = AgentHttpOperationPolicy {
        name: "direct".to_owned(),
        method: method.to_owned(),
        path,
        request_fields,
        response_fields: if response_mode == "json" {
            vec!["*".to_owned()]
        } else {
            Vec::new()
        },
        request_mode: if input.as_object().is_some_and(|object| object.is_empty()) {
            AgentHttpBodyMode::Empty
        } else {
            AgentHttpBodyMode::Json
        },
        response_mode: if response_mode == "json" {
            AgentHttpBodyMode::Json
        } else {
            AgentHttpBodyMode::Empty
        },
        risk,
    };
    let target_digest = crate::agent_broker::canonical_parameters_digest(&json!({
        "connector": "http",
        "origin": origin,
        "basePath": base_path,
        "authStrategy": "bearer",
        "accountRef": item_id,
        "matcherRevision": crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION,
    }))?;
    Ok(AgentDirectHttpPolicy {
        account_ref: item_id,
        account_label: detail
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("Vault account")
            .to_owned(),
        environment: detail
            .get("environment")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("default")
            .to_owned(),
        item_kind: item_kind.to_owned(),
        credential_kind: AgentCredentialKind::Secret,
        origin: origin.clone(),
        auth_strategy: AgentHttpAuthStrategy::Bearer,
        approved_display: format!("{}{}", origin, operation.path),
        operation,
        target_digest,
        allowed_output_fields: if response_mode == "json" {
            vec!["*".to_owned()]
        } else {
            Vec::new()
        },
        max_output_bytes: 64 * 1_024,
        max_output_items: 1_000,
    })
}

pub(super) fn generate_direct_ssh_policy(
    runtime: &mut DesktopRuntime,
    item_id: uuid::Uuid,
    tool: &str,
    action_parameters: &Value,
) -> Result<AgentDirectSshPolicy, AgentBrokerError> {
    generate_direct_ssh_policy_with_host_key_inspector(
        runtime,
        item_id,
        tool,
        action_parameters,
        |target| {
            ssh_service::inspect_host_key(target)
                .map(|preview| preview.fingerprint)
                .map_err(|_| AgentBrokerError::action_target_unavailable())
        },
    )
}

fn generate_direct_ssh_policy_with_host_key_inspector<F>(
    runtime: &mut DesktopRuntime,
    item_id: uuid::Uuid,
    tool: &str,
    action_parameters: &Value,
    inspect_host_key: F,
) -> Result<AgentDirectSshPolicy, AgentBrokerError>
where
    F: FnOnce(ssh_service::SshTarget) -> Result<String, AgentBrokerError>,
{
    if !runtime.status().unlocked {
        return Err(AgentBrokerError::vault_locked());
    }
    let detail = runtime
        .execute("ssh.detail", json!({ "id": item_id }))
        .map_err(|_| AgentBrokerError::action_input_insufficient(vec!["ssh".to_owned()]))?;
    let mut missing = Vec::new();
    if detail
        .get("masterPasswordReprompt")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        missing.push("ssh.masterPasswordReprompt=false".to_owned());
    }
    if detail.get("recordKind").and_then(Value::as_str) != Some("account") {
        missing.push("ssh.recordKind=account".to_owned());
    }
    let host = detail
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|host| !host.is_empty());
    if host.is_none() {
        missing.push("ssh.host".to_owned());
    }
    let username = detail
        .get("username")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|username| !username.is_empty());
    if username.is_none() {
        missing.push("ssh.username".to_owned());
    }
    let port = detail
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0);
    if port.is_none() {
        missing.push("ssh.port".to_owned());
    }
    if !missing.is_empty() {
        return Err(AgentBrokerError::action_input_insufficient(missing));
    }
    let host = host.expect("validated above").to_ascii_lowercase();
    if host.len() > 253
        || host.contains(['/', '\\', '@'])
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AgentBrokerError::action_input_insufficient(vec![
            "ssh.host (valid exact SSH host)".to_owned(),
        ]));
    }
    let port = port.expect("validated above");
    let username = username.expect("validated above").to_owned();
    let host_key_sha256 = inspect_host_key(ssh_service::SshTarget {
        host: host.clone(),
        port,
        username: username.clone(),
    })?;
    let action_policy = direct_ssh_action_policy(
        runtime,
        item_id,
        tool,
        action_parameters,
        &host,
        port,
        &host_key_sha256,
    )?;
    let DirectSshActionPolicy {
        risk,
        action_display,
        remote_path_prefixes,
        connector_ref,
        tunnel,
    } = action_policy;
    let mut target_binding = json!({
        "connector": "ssh",
        "host": host,
        "port": port,
        "username": username,
        "hostKeySha256": host_key_sha256,
    });
    if let Some(tunnel) = tunnel.as_ref() {
        target_binding["tunnel"] = json!({
            "name": tunnel.name,
            "localHost": tunnel.local_host,
            "localPort": tunnel.local_port,
            "destinationHost": tunnel.destination_host,
            "destinationPort": tunnel.destination_port,
            "maxConnections": tunnel.max_connections,
            "ttlMillis": tunnel.ttl_millis,
        });
    }
    let target_digest = crate::agent_broker::canonical_parameters_digest(&target_binding)?;
    let approved_display = if let Some(tunnel) = tunnel.as_ref() {
        format!(
            "{username}@{host}:{port} · {host_key_sha256} → {}:{}",
            tunnel.destination_host, tunnel.destination_port
        )
    } else {
        format!("{username}@{host}:{port} · {host_key_sha256}")
    };
    Ok(AgentDirectSshPolicy {
        account_ref: item_id,
        account_label: ssh_account_label(&detail, &host),
        environment: "default".to_owned(),
        tool: tool.to_owned(),
        risk,
        action_display,
        host: host.clone(),
        port,
        username: username.clone(),
        host_key_sha256: host_key_sha256.clone(),
        target_digest,
        approved_display,
        max_output_bytes: 4_096,
        remote_path_prefixes,
        connector_ref,
        tunnel,
    })
}

struct DirectSshActionPolicy {
    risk: String,
    action_display: String,
    remote_path_prefixes: Vec<String>,
    connector_ref: Option<uuid::Uuid>,
    tunnel: Option<vaultmesh_ffi::AgentSshTunnelPolicy>,
}

#[allow(clippy::too_many_arguments)]
fn direct_ssh_action_policy(
    runtime: &mut DesktopRuntime,
    account_ref: uuid::Uuid,
    tool: &str,
    parameters: &Value,
    host: &str,
    port: u16,
    host_key_sha256: &str,
) -> Result<DirectSshActionPolicy, AgentBrokerError> {
    let fixed = |risk: &str, action_display: String| {
        Ok(DirectSshActionPolicy {
            risk: risk.to_owned(),
            action_display,
            remote_path_prefixes: Vec::new(),
            connector_ref: None,
            tunnel: None,
        })
    };
    match tool {
        "vaultmesh_ssh_exec" => {
            let risk = crate::agent_ssh_command_policy::command_risk(parameters)?;
            let risk = serde_json::to_value(risk)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(AgentBrokerError::internal)?;
            Ok(DirectSshActionPolicy {
                risk,
                action_display: crate::agent_ssh_command_policy::command_display(parameters)?,
                remote_path_prefixes: Vec::new(),
                connector_ref: None,
                tunnel: None,
            })
        }
        "vaultmesh_local_file_select" => {
            if parameters.get("purpose").and_then(Value::as_str) != Some("ssh-upload") {
                return Err(AgentBrokerError::new(
                    "invalid-parameters",
                    "The local file purpose is invalid for this SSH account.",
                    false,
                ));
            }
            fixed("R2", "选择供 SSH 上传使用的本地文件".to_owned())
        }
        "vaultmesh_result_save" => {
            require_uuid_parameter(parameters, "resultRef")?;
            fixed("R2", "保存 SSH 下载结果".to_owned())
        }
        "vaultmesh_ssh_upload" | "vaultmesh_ssh_download" => {
            let remote_path = parameters
                .get("remotePath")
                .and_then(Value::as_str)
                .filter(|path| valid_direct_remote_path(path))
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The SSH remote path is invalid.",
                        false,
                    )
                })?;
            if tool == "vaultmesh_ssh_upload" {
                require_uuid_parameter(parameters, "fileRef")?;
            }
            let prefix = if tool == "vaultmesh_ssh_upload" {
                remote_parent(remote_path)
            } else {
                remote_path.to_owned()
            };
            Ok(DirectSshActionPolicy {
                risk: if tool == "vaultmesh_ssh_upload" {
                    "R2"
                } else {
                    "R1"
                }
                .to_owned(),
                action_display: format!(
                    "{} {remote_path}",
                    if tool == "vaultmesh_ssh_upload" {
                        "上传到"
                    } else {
                        "下载"
                    }
                ),
                remote_path_prefixes: vec![prefix],
                connector_ref: None,
                tunnel: None,
            })
        }
        "vaultmesh_ssh_public_key_install" => {
            let public_key_ref = require_uuid_parameter(parameters, "publicKeyRef")?;
            let key = runtime
                .execute("ssh.detail", json!({ "id": public_key_ref }))
                .map_err(|_| {
                    AgentBrokerError::action_input_insufficient(vec!["ssh.publicKeyRef".to_owned()])
                })?;
            if key.get("recordKind").and_then(Value::as_str) != Some("key")
                || !key
                    .get("hasPublicKey")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                return Err(AgentBrokerError::action_input_insufficient(vec![
                    "ssh.publicKeyRef (public-key record)".to_owned(),
                ]));
            }
            let label = key
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("SSH key");
            fixed("R2", format!("安装公钥：{label}"))
        }
        "vaultmesh_ssh_agent_open" => {
            let duration_minutes = parameters
                .get("durationMinutes")
                .and_then(Value::as_u64)
                .unwrap_or(15)
                .clamp(1, 60);
            fixed(
                "R1",
                format!("开启本地短时 SSH-Agent 桥接会话（原生工具直接免密连接，有效期 {duration_minutes} 分钟）"),
            )
        }
        "vaultmesh_ssh_host_setup" => {
            let alias = parameters
                .get("alias")
                .and_then(Value::as_str)
                .filter(|alias| crate::ssh_host_setup::validate_ssh_host_alias(alias).is_ok())
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The OpenSSH host alias is invalid.",
                        false,
                    )
                })?;
            fixed(
                "R3",
                format!("配置持久 OpenSSH 主机别名（当前 OS 用户进程可直接使用）：{alias}"),
            )
        }
        "vaultmesh_ssh_pty_open" => {
            let terminal = parameters
                .get("terminal")
                .and_then(Value::as_str)
                .unwrap_or("xterm-256color");
            if !matches!(terminal, "xterm-256color" | "xterm" | "vt100") {
                return Err(AgentBrokerError::new(
                    "invalid-parameters",
                    "The SSH terminal type is invalid.",
                    false,
                ));
            }
            fixed("R3", format!("打开独占 SSH PTY（{terminal}）"))
        }
        "vaultmesh_ssh_tunnel_open" => {
            let endpoint = parameters
                .get("endpoint")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AgentBrokerError::action_input_insufficient(vec![
                        "ssh.tunnel.endpoint".to_owned(),
                    ])
                })?;
            let (connector_ref, tunnel) = configured_direct_ssh_tunnel(
                runtime,
                account_ref,
                endpoint,
                host,
                port,
                host_key_sha256,
            )?;
            Ok(DirectSshActionPolicy {
                risk: "R3".to_owned(),
                action_display: format!(
                    "打开固定隧道 {} → {}:{}（最多 {} 条连接，{} 秒）",
                    tunnel.name,
                    tunnel.destination_host,
                    tunnel.destination_port,
                    tunnel.max_connections,
                    tunnel.ttl_millis / 1_000
                ),
                remote_path_prefixes: Vec::new(),
                connector_ref: Some(connector_ref),
                tunnel: Some(tunnel),
            })
        }
        _ => Err(AgentBrokerError::action_rule_unavailable("ssh", tool)),
    }
}

fn configured_direct_ssh_tunnel(
    runtime: &mut DesktopRuntime,
    account_ref: uuid::Uuid,
    endpoint: &str,
    host: &str,
    port: u16,
    host_key_sha256: &str,
) -> Result<(uuid::Uuid, vaultmesh_ffi::AgentSshTunnelPolicy), AgentBrokerError> {
    let mut matches = runtime
        .agent_connector_definition_records()
        .map_err(|_| AgentBrokerError::action_rule_unavailable("ssh", "vaultmesh_ssh_tunnel_open"))?
        .into_iter()
        .filter(|definition| {
            definition.enabled
                && definition.connector_kind == AgentConnectorKind::Ssh
                && definition
                    .capability_policy
                    .allowed_tools
                    .iter()
                    .any(|tool| tool == "vaultmesh_ssh_tunnel_open")
                && definition
                    .credential_refs
                    .first()
                    .is_some_and(|credential| {
                        credential.kind == AgentCredentialKind::Ssh
                            && credential.item_id == account_ref
                    })
        })
        .filter_map(|definition| {
            let definition_id = definition.id;
            match &definition.target_policy {
                AgentTargetPolicy::Ssh {
                    host: policy_host,
                    port: policy_port,
                    host_key_sha256: policy_host_key,
                    tunnel_policies,
                    ..
                } if policy_host.trim().eq_ignore_ascii_case(host)
                    && *policy_port == port
                    && policy_host_key == host_key_sha256 =>
                {
                    tunnel_policies
                        .iter()
                        .find(|policy| policy.name == endpoint)
                        .cloned()
                        .map(|policy| (definition_id, policy))
                }
                _ => None,
            }
        });
    let tunnel = matches.next().ok_or_else(|| {
        AgentBrokerError::action_rule_unavailable("ssh", "vaultmesh_ssh_tunnel_open")
    })?;
    if matches.next().is_some() {
        return Err(AgentBrokerError::new(
            "action-target-ambiguous",
            "More than one fixed SSH tunnel endpoint matches this account.",
            false,
        ));
    }
    Ok(tunnel)
}

fn require_uuid_parameter(parameters: &Value, field: &str) -> Result<uuid::Uuid, AgentBrokerError> {
    parameters
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| {
            AgentBrokerError::new(
                "invalid-parameters",
                "An SSH action handle is invalid.",
                false,
            )
        })
}

fn valid_direct_remote_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4_096
        && path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && path.is_ascii()
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| component == ".." || component == ".")
        && !path.chars().any(char::is_control)
}

fn remote_parent(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
        .to_owned()
}

fn ssh_account_label(detail: &Value, host: &str) -> String {
    detail
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .unwrap_or(host)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_with_ssh() -> (DesktopRuntime, std::path::PathBuf, uuid::Uuid) {
        let path = std::env::temp_dir().join(format!(
            "vaultmesh-tauri-system-ssh-definition-{}.vault",
            uuid::Uuid::new_v4()
        ));
        let mut runtime = DesktopRuntime::new(path.clone()).expect("runtime");
        runtime
            .create("correct horse battery staple".into())
            .expect("create");
        let item = runtime
            .execute(
                "ssh.add",
                json!({
                    "title": "Unraid", "host": "UNRAID.local", "port": 22,
                    "username": "operator", "password": "secret", "publicKey": null,
                    "privateKey": null, "keyPassphrase": null, "notes": null, "folder": null,
                    "favorite": false, "masterPasswordReprompt": false, "recordKind": "account"
                }),
            )
            .expect("add SSH account");
        let item_id = uuid::Uuid::parse_str(item["id"].as_str().expect("item id")).unwrap();
        (runtime, path, item_id)
    }

    #[test]
    fn ct_agent_permission_direct_ssh_policy_pins_the_vault_item_target() {
        let (mut runtime, path, item_id) = runtime_with_ssh();
        let vault_before = std::fs::read(&path).expect("vault before definition");
        let fingerprint = format!("SHA256:{}", "a".repeat(43));

        let policy = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_exec",
            &json!({ "program": "hostname" }),
            |target| {
                assert_eq!(target.host, "unraid.local");
                assert_eq!(target.port, 22);
                assert_eq!(target.username, "operator");
                Ok(fingerprint.clone())
            },
        )
        .expect("direct SSH policy");

        assert_eq!(policy.account_ref, item_id);
        assert_eq!(policy.account_label, "Unraid");
        assert_eq!(policy.host, "unraid.local");
        assert_eq!(policy.port, 22);
        assert_eq!(policy.username, "operator");
        assert_eq!(policy.host_key_sha256, fingerprint);
        assert_eq!(policy.max_output_bytes, 4_096);
        assert!(policy.target_digest.starts_with("sha256:"));
        assert_eq!(policy.target_digest.len(), 71);
        assert_eq!(
            std::fs::read(&path).expect("vault after definition"),
            vault_before,
            "direct SSH policy generation must not mutate the Vault file"
        );
        runtime.lock();
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn ct_agent_ssh_host_setup_is_r3_and_only_accepts_a_bounded_alias() {
        let (mut runtime, path, item_id) = runtime_with_ssh();
        let fingerprint = format!("SHA256:{}", "a".repeat(43));
        let policy = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_host_setup",
            &json!({ "alias": "home-server" }),
            |_| Ok(fingerprint.clone()),
        )
        .expect("host setup policy");
        assert_eq!(policy.risk, "R3");
        assert_eq!(
            policy.action_display,
            "配置持久 OpenSSH 主机别名（当前 OS 用户进程可直接使用）：home-server"
        );
        assert!(
            generate_direct_ssh_policy_with_host_key_inspector(
                &mut runtime,
                item_id,
                "vaultmesh_ssh_host_setup",
                &json!({ "alias": "../other" }),
                |_| Ok(fingerprint.clone()),
            )
            .is_err()
        );
        runtime.lock();
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn ct_agent_ssh_agent_open_is_r1_with_duration() {
        let (mut runtime, path, item_id) = runtime_with_ssh();
        let fingerprint = format!("SHA256:{}", "a".repeat(43));
        let policy = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_agent_open",
            &json!({ "durationMinutes": 30 }),
            |_| Ok(fingerprint.clone()),
        )
        .expect("ssh agent open policy");
        assert_eq!(policy.risk, "R1");
        assert!(policy.action_display.contains("30 分钟"));
        runtime.lock();
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn ct_agent_ssh_agent_open_resolves_managed_key_for_password_account() {
        let (mut runtime, path, item_id) = runtime_with_ssh();
        let fingerprint = format!("SHA256:{}", "a".repeat(43));
        let policy = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_agent_open",
            &json!({ "durationMinutes": 30 }),
            |_| Ok(fingerprint.clone()),
        )
        .expect("ssh agent open policy");

        let identity = crate::ssh_host_setup::generate_ssh_host_identity("auto-test").unwrap();
        runtime
            .add_managed_ssh_host_key(
                item_id,
                "auto-test".to_owned(),
                fingerprint.clone(),
                identity.public_key,
                identity.private_key,
            )
            .expect("add managed key");

        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let material = crate::agent_ssh_runtime::collect_direct_agent_ssh_agent_material(
            &mut runtime,
            &policy,
            &cancellation,
        )
        .expect("material collected via managed key");

        assert!(!material.private_key.is_empty());
        assert_eq!(material.account_label, "Unraid");

        runtime.lock();
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn ct_agent_permission_ssh_account_label_falls_back_to_host() {
        assert_eq!(
            ssh_account_label(&json!({ "title": "unRaid" }), "unraid.local"),
            "unRaid"
        );
        assert_eq!(
            ssh_account_label(&json!({ "title": "  " }), "unraid.local"),
            "unraid.local"
        );
        assert_eq!(
            ssh_account_label(&json!({}), "unraid.local"),
            "unraid.local"
        );
    }

    #[test]
    fn ct_agent_permission_direct_ssh_policy_returns_retryable_target_error() {
        let (mut runtime, path, item_id) = runtime_with_ssh();

        let error = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_exec",
            &json!({ "program": "hostname" }),
            |_| Err(AgentBrokerError::action_target_unavailable()),
        )
        .expect_err("unreachable SSH target must fail before prompting");

        assert_eq!(error.code, "action-target-unavailable");
        assert!(error.retryable);
        assert!(
            error.details.as_ref().unwrap()["retryHint"]
                .as_str()
                .unwrap()
                .contains("retry the same SSH action")
        );
        runtime.lock();
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn ct_agent_locked_vault_returns_a_typed_retryable_error() {
        let (mut runtime, path, item_id) = runtime_with_ssh();
        runtime.lock();

        let error = generate_direct_ssh_policy_with_host_key_inspector(
            &mut runtime,
            item_id,
            "vaultmesh_ssh_exec",
            &json!({ "program": "hostname" }),
            |_| panic!("locked Vault must fail before inspecting the target"),
        )
        .expect_err("locked Vault must not compile an action policy");

        assert_eq!(error.code, "vault-locked");
        assert!(error.retryable);
        std::fs::remove_file(path).expect("cleanup");
    }
}
