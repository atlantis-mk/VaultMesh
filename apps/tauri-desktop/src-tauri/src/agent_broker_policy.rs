use super::*;

pub(super) fn parse_opaque_id(value: &str, code: &'static str) -> Result<Uuid, AgentBrokerError> {
    Uuid::parse_str(value)
        .map_err(|_| AgentBrokerError::new(code, "The opaque Agent reference is invalid.", false))
}

pub(super) fn permission_snapshot(permission: &PendingPermission) -> PermissionRequestSnapshot {
    PermissionRequestSnapshot {
        permission_ref: permission.permission_ref.to_string(),
        client_id: permission.client_id.to_string(),
        session_id: permission.session_id.to_string(),
        account_ref: permission.account_ref.clone(),
        account_label: permission.account_label.clone(),
        environment: permission.environment.clone(),
        tool: permission.tool.clone(),
        operation: permission.operation.clone(),
        risk: permission.risk.clone(),
        approved_display: permission.approved_display.clone(),
        action_display: permission.action_display.clone(),
        source_item_ref: permission.source_item_ref.map(|value| value.to_string()),
        source_item_kind: permission.source_item_kind.clone(),
        activation_required: permission.activation_required,
        available_scopes: permission_available_scopes(permission),
        available_path_patterns: permission_available_path_patterns(permission),
        available_allow_durations: permission_available_durations(
            permission,
            PermissionEffect::Allow,
        ),
        available_deny_durations: permission_available_durations(
            permission,
            PermissionEffect::Deny,
        ),
        recommended_scope: permission_recommended_choice(permission).scope,
        recommended_duration: permission_recommended_choice(permission).duration,
        fresh_confirmation_required: risk_rank(&permission.risk) >= risk_rank("R2"),
        created_at: permission.created_at,
        expires_at: permission.expires_at,
    }
}

pub(super) fn permission_available_scopes(permission: &PendingPermission) -> Vec<PermissionScope> {
    let mut scopes = vec![PermissionScope::Exact];
    if permission
        .direct_http_policy
        .as_ref()
        .is_some_and(|policy| policy.item_kind == "secret")
    {
        scopes.push(PermissionScope::Path);
    }
    if risk_rank(&permission.risk) >= risk_rank("R3") {
        return scopes;
    }
    if permission.tool == "vaultmesh_ssh_exec" {
        if permission.risk == "R1" {
            scopes.push(PermissionScope::Safe);
        }
        scopes.push(PermissionScope::All);
    } else if is_direct_ssh_action_tool(&permission.tool) || permission.source_item_ref.is_none() {
        scopes.push(PermissionScope::All);
    }
    scopes
}

pub(super) fn permission_available_path_patterns(permission: &PendingPermission) -> Vec<String> {
    let Some(policy) = permission
        .direct_http_policy
        .as_ref()
        .filter(|policy| policy.item_kind == "secret")
    else {
        return Vec::new();
    };
    let exact = permission
        .operation
        .clone()
        .unwrap_or_else(|| policy.operation.path.clone());
    let Some((parent, _)) = exact.rsplit_once('/') else {
        return vec![exact];
    };
    let parent = if parent.is_empty() { "" } else { parent };
    let mut patterns = vec![exact.clone(), format!("{parent}/*"), format!("{parent}/**")];
    patterns.retain(|pattern| crate::agent_http_path_policy::validate_pattern(pattern).is_ok());
    patterns
}

pub(super) fn permission_choice_is_valid(
    permission: &PendingPermission,
    choice: &PermissionChoice,
) -> bool {
    if choice.scope != PermissionScope::Path {
        return choice.path_pattern.is_none();
    }
    let Some(pattern) = choice.path_pattern.as_deref() else {
        return false;
    };
    permission_available_path_patterns(permission)
        .iter()
        .any(|candidate| candidate == pattern)
        && permission
            .operation
            .as_deref()
            .is_some_and(|path| crate::agent_http_path_policy::path_matches(pattern, path))
}

pub(super) fn permission_choice_operation<'a>(
    permission: &'a PendingPermission,
    choice: &'a PermissionChoice,
) -> Option<&'a str> {
    match choice.scope {
        PermissionScope::Exact => permission.operation.as_deref(),
        PermissionScope::Path => choice.path_pattern.as_deref(),
        PermissionScope::Safe | PermissionScope::All => None,
    }
}

pub(super) fn permission_choice_parameters_digest<'a>(
    permission: &'a PendingPermission,
    choice: &PermissionChoice,
) -> Option<&'a str> {
    match choice.scope {
        PermissionScope::Exact => permission.parameters_digest.as_deref(),
        PermissionScope::Path => permission
            .direct_http_policy
            .as_ref()
            .map(|policy| policy.operation.method.as_str()),
        PermissionScope::Safe | PermissionScope::All => None,
    }
}

pub(super) fn permission_choice_catalog_revision(
    choice: &PermissionChoice,
) -> Option<&'static str> {
    match choice.scope {
        PermissionScope::Path => Some(crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION),
        PermissionScope::Safe => Some(crate::agent_ssh_command_policy::SAFE_SSH_CATALOG_REVISION),
        PermissionScope::Exact | PermissionScope::All => None,
    }
}

pub(super) fn permission_available_durations(
    permission: &PendingPermission,
    effect: PermissionEffect,
) -> Vec<PermissionDuration> {
    if effect == PermissionEffect::Allow && permission.risk == "R4" {
        return vec![PermissionDuration::Once];
    }
    vec![
        PermissionDuration::Once,
        PermissionDuration::Connection,
        PermissionDuration::Permanent,
    ]
}

pub(super) fn permission_recommended_choice(permission: &PendingPermission) -> PermissionChoice {
    if permission.risk == "R1" {
        return PermissionChoice {
            effect: PermissionEffect::Allow,
            scope: if permission_available_scopes(permission).contains(&PermissionScope::Safe) {
                PermissionScope::Safe
            } else {
                PermissionScope::Exact
            },
            duration: PermissionDuration::Connection,
            path_pattern: None,
        };
    }
    PermissionChoice {
        effect: PermissionEffect::Allow,
        scope: PermissionScope::Exact,
        duration: PermissionDuration::Once,
        path_pattern: None,
    }
}

pub(super) fn permission_grant_matches(
    grant: &PermissionGrant,
    account_ref: &str,
    tool: &str,
    operation: Option<&str>,
    parameters_digest: &str,
    parameters: &Value,
) -> bool {
    if grant.account_ref != account_ref || grant.tool != tool || grant.remaining_uses == Some(0) {
        return false;
    }
    match grant.scope {
        PermissionScope::Exact => {
            grant.operation.as_deref() == operation
                && grant
                    .parameters_digest
                    .as_deref()
                    .is_none_or(|digest| digest == parameters_digest)
        }
        PermissionScope::Path => {
            tool == "vaultmesh_http_request"
                && grant.catalog_revision.as_deref()
                    == Some(crate::agent_http_path_policy::HTTP_PATH_MATCHER_REVISION)
                && grant.operation.as_deref().is_some_and(|pattern| {
                    parameters.get("method").and_then(Value::as_str)
                        == grant.parameters_digest.as_deref()
                        && parameters
                            .get("path")
                            .and_then(Value::as_str)
                            .is_some_and(|path| {
                                crate::agent_http_path_policy::path_matches(pattern, path)
                            })
                })
        }
        PermissionScope::Safe => {
            tool == "vaultmesh_ssh_exec"
                && grant.catalog_revision.as_deref()
                    == Some(crate::agent_ssh_command_policy::SAFE_SSH_CATALOG_REVISION)
                && crate::agent_ssh_command_policy::command_risk(parameters)
                    .is_ok_and(|risk| risk == AgentRiskTier::R1)
        }
        PermissionScope::All => true,
    }
}

pub(super) fn matching_permission_grant_index(
    grants: &[PermissionGrant],
    account_ref: &str,
    tool: &str,
    operation: Option<&str>,
    parameters_digest: &str,
    parameters: &Value,
) -> Option<usize> {
    grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| {
            permission_grant_matches(
                grant,
                account_ref,
                tool,
                operation,
                parameters_digest,
                parameters,
            )
        })
        .max_by_key(|(_, grant)| {
            let specificity = match grant.scope {
                PermissionScope::Exact => 4_u8,
                PermissionScope::Path => 3,
                PermissionScope::Safe => 2,
                PermissionScope::All => 1,
            };
            let deny_priority = u8::from(grant.effect == PermissionEffect::Deny);
            let ready_priority = u8::from(!grant.fresh_confirmation_required);
            (deny_priority, specificity, ready_priority)
        })
        .map(|(index, _)| index)
}

pub(super) fn candidate_tools(kind: &str) -> &'static [&'static str] {
    match kind {
        "secret" => &["vaultmesh_http_request"],
        "ssh" => &[
            "vaultmesh_local_file_select",
            "vaultmesh_result_save",
            "vaultmesh_ssh_agent_open",
            "vaultmesh_ssh_agent_close",
            "vaultmesh_ssh_exec",
            "vaultmesh_ssh_upload",
            "vaultmesh_ssh_download",
            "vaultmesh_ssh_public_key_install",
            "vaultmesh_ssh_host_setup",
            "vaultmesh_ssh_pty_open",
            "vaultmesh_ssh_tunnel_open",
        ],
        _ => &[],
    }
}

pub(super) fn candidate_accepts_tool(kind: &str, tool: &str) -> bool {
    candidate_tools(kind).contains(&tool)
        || (kind == "ssh"
            && matches!(
                tool,
                "vaultmesh_local_file_select"
                    | "vaultmesh_result_save"
                    | "vaultmesh_ssh_pty_read"
                    | "vaultmesh_ssh_pty_write"
                    | "vaultmesh_ssh_pty_resize"
                    | "vaultmesh_ssh_pty_close"
            ))
}

pub(super) fn is_direct_ssh_action_tool(tool: &str) -> bool {
    matches!(
        tool,
        "vaultmesh_local_file_select"
            | "vaultmesh_result_save"
            | "vaultmesh_ssh_agent_open"
            | "vaultmesh_ssh_exec"
            | "vaultmesh_ssh_upload"
            | "vaultmesh_ssh_download"
            | "vaultmesh_ssh_public_key_install"
            | "vaultmesh_ssh_host_setup"
            | "vaultmesh_ssh_pty_open"
            | "vaultmesh_ssh_tunnel_open"
    )
}

pub(super) fn is_ssh_pty_session_tool(tool: &str) -> bool {
    matches!(
        tool,
        "vaultmesh_ssh_pty_read"
            | "vaultmesh_ssh_pty_write"
            | "vaultmesh_ssh_pty_resize"
            | "vaultmesh_ssh_pty_close"
    )
}

pub(super) fn is_direct_connector_action_tool(connector_kind: &str, tool: &str) -> bool {
    match connector_kind {
        "managed-web" => matches!(
            tool,
            "vaultmesh_web_session_open"
                | "vaultmesh_web_navigate"
                | "vaultmesh_web_extract"
                | "vaultmesh_web_act"
                | "vaultmesh_web_download"
                | "vaultmesh_web_session_close"
                | "vaultmesh_otp_fill"
                | "vaultmesh_recovery_code_consume"
                | "vaultmesh_passkey_request_begin"
                | "vaultmesh_passkey_perform"
                | "vaultmesh_result_save"
        ),
        _ => false,
    }
}

pub(super) fn tools_for_named_operation<'a>(field: &str, operation: &'a Value) -> Vec<&'a str> {
    match field {
        "tunnelPolicies" => vec!["vaultmesh_ssh_tunnel_open"],
        "recipes" => match operation.get("kind").and_then(Value::as_str) {
            Some("navigate") => vec!["vaultmesh_web_navigate"],
            Some("extract") => vec!["vaultmesh_web_extract"],
            Some("action") => vec!["vaultmesh_web_act"],
            Some("download") => vec!["vaultmesh_web_download"],
            Some("totp" | "email-otp") => vec!["vaultmesh_otp_fill"],
            Some("recovery-code") => vec!["vaultmesh_recovery_code_consume"],
            Some("passkey-registration" | "passkey-assertion") => vec![
                "vaultmesh_passkey_request_begin",
                "vaultmesh_passkey_perform",
            ],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

pub(super) fn request_permission_operation<'a>(
    tool: &str,
    parameters: &'a Value,
) -> Option<&'a str> {
    let field = match tool {
        "vaultmesh_ssh_exec" => "program",
        "vaultmesh_ssh_tunnel_open" => "endpoint",
        "vaultmesh_web_navigate" => "route",
        "vaultmesh_web_extract"
        | "vaultmesh_web_act"
        | "vaultmesh_web_download"
        | "vaultmesh_passkey_request_begin" => "recipe",
        "vaultmesh_http_request" => "path",
        _ => return None,
    };
    parameters.get(field).and_then(Value::as_str)
}

pub(super) fn valid_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub(super) fn risk_rank(risk: &str) -> u8 {
    match risk {
        "R0" => 0,
        "R1" => 1,
        "R2" => 2,
        "R3" => 3,
        "R4" => 4,
        _ => u8::MAX,
    }
}

pub(super) struct CanonicalActionInput<'a> {
    pub(super) client_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) account_ref: Option<&'a str>,
    pub(super) tool: &'a str,
    pub(super) tool_version: u32,
    pub(super) canonical_target: &'a Value,
    pub(super) parameters: &'a Value,
    pub(super) risk: &'a str,
}

pub(super) fn canonical_action_digest(
    input: CanonicalActionInput<'_>,
) -> Result<String, AgentBrokerError> {
    let record = json!({
        "accountRef": input.account_ref,
        "canonicalParameters": canonicalize_json(input.parameters)?,
        "canonicalTarget": canonicalize_json(input.canonical_target)?,
        "clientId": input.client_id,
        "risk": input.risk,
        "sessionId": input.session_id,
        "tool": input.tool,
        "toolVersion": input.tool_version,
    });
    let bytes = serde_json::to_vec(&record).map_err(|_| AgentBrokerError::internal())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(super) fn canonicalize_json(value: &Value) -> Result<Value, AgentBrokerError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(value.clone()),
        Value::Number(_) => Err(AgentBrokerError::new(
            "invalid-parameters",
            "Floating-point Agent parameters are not canonical.",
            false,
        )),
        Value::Array(values) => values
            .iter()
            .map(canonicalize_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json(&object[key])?);
            }
            Ok(Value::Object(canonical))
        }
    }
}

pub(crate) fn canonical_parameters_digest(value: &Value) -> Result<String, AgentBrokerError> {
    let bytes =
        serde_json::to_vec(&canonicalize_json(value)?).map_err(|_| AgentBrokerError::internal())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(super) fn validate_parameters(
    tool: &AgentToolDefinition,
    parameters: &Value,
) -> Result<(), AgentBrokerError> {
    let object = parameters.as_object().ok_or_else(|| {
        AgentBrokerError::new(
            "invalid-parameters",
            "The Agent tool parameters are invalid.",
            false,
        )
    })?;
    let known: HashSet<&str> = tool
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect();
    if object.keys().any(|key| !known.contains(key.as_str())) {
        return Err(AgentBrokerError::new(
            "unknown-field",
            "The Agent tool parameters contain an unknown field.",
            false,
        ));
    }
    for parameter in &tool.parameters {
        let value = object.get(&parameter.name);
        if parameter.required && value.is_none() {
            return Err(AgentBrokerError::new(
                "missing-field",
                "The Agent tool parameters are incomplete.",
                false,
            ));
        }
        let Some(value) = value else { continue };
        let valid = match parameter.parameter_type.as_str() {
            "string" => value.as_str().is_some_and(|value| {
                parameter
                    .max_length
                    .is_none_or(|maximum| value.encode_utf16().count() as u64 <= maximum)
            }),
            "integer" => value.as_u64().is_some(),
            "string-array" => value.as_array().is_some_and(|values| {
                parameter
                    .max_items
                    .is_none_or(|maximum| values.len() as u64 <= maximum)
                    && values.iter().all(|value| {
                        value.as_str().is_some_and(|value| {
                            parameter.max_length.is_none_or(|maximum| {
                                value.encode_utf16().count() as u64 <= maximum
                            })
                        })
                    })
            }),
            "object" => value.as_object().is_some_and(|_| {
                parameter.max_bytes.is_none_or(|maximum| {
                    serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() as u64 <= maximum)
                })
            }),
            _ => false,
        };
        if !valid {
            return Err(AgentBrokerError::new(
                "invalid-parameters",
                "The Agent tool parameters are invalid.",
                false,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod authorization_scope_tests {
    use super::*;

    fn pending(risk: &str) -> PendingPermission {
        PendingPermission {
            permission_ref: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            account_ref: Uuid::new_v4().to_string(),
            account_label: "SSH".to_owned(),
            environment: "test".to_owned(),
            tool: "vaultmesh_ssh_exec".to_owned(),
            operation: Some("hostname".to_owned()),
            parameters_digest: Some("sha256:permission-matrix".to_owned()),
            risk: risk.to_owned(),
            approved_display: "root@example.test:22".to_owned(),
            action_display: "hostname".to_owned(),
            target_digest: "sha256:target".to_owned(),
            source_item_ref: Some(Uuid::new_v4()),
            source_item_kind: Some("ssh".to_owned()),
            activation_required: false,
            direct_ssh_policy: None,
            direct_http_policy: None,
            direct_connector_policy: None,
            created_at: 1,
            expires_at: 31_000,
        }
    }

    fn grant(scope: PermissionScope) -> PermissionGrant {
        PermissionGrant {
            account_ref: "account-1".to_owned(),
            tool: "vaultmesh_ssh_exec".to_owned(),
            operation: (scope == PermissionScope::Exact).then(|| "hostname".to_owned()),
            scope,
            parameters_digest: (scope == PermissionScope::Exact).then(|| "exact-digest".to_owned()),
            catalog_revision: (scope == PermissionScope::Safe)
                .then(|| crate::agent_ssh_command_policy::SAFE_SSH_CATALOG_REVISION.to_owned()),
            effect: PermissionEffect::Allow,
            fresh_confirmation_required: false,
            remaining_uses: None,
        }
    }

    #[test]
    fn ct_agent_authz_scope_predicates_keep_exact_safe_and_all_distinct() {
        let hostname = json!({ "program": "hostname", "arguments": [] });
        let whoami = json!({ "program": "whoami", "arguments": [] });
        let remove = json!({ "program": "rm", "arguments": ["-f", "/tmp/x"] });
        assert!(permission_grant_matches(
            &grant(PermissionScope::Exact),
            "account-1",
            "vaultmesh_ssh_exec",
            Some("hostname"),
            "exact-digest",
            &hostname,
        ));
        assert!(!permission_grant_matches(
            &grant(PermissionScope::Exact),
            "account-1",
            "vaultmesh_ssh_exec",
            Some("hostname"),
            "changed-digest",
            &hostname,
        ));
        assert!(permission_grant_matches(
            &grant(PermissionScope::Safe),
            "account-1",
            "vaultmesh_ssh_exec",
            Some("whoami"),
            "ignored",
            &whoami,
        ));
        assert!(!permission_grant_matches(
            &grant(PermissionScope::Safe),
            "account-1",
            "vaultmesh_ssh_exec",
            Some("rm"),
            "ignored",
            &remove,
        ));
        assert!(permission_grant_matches(
            &grant(PermissionScope::All),
            "account-1",
            "vaultmesh_ssh_exec",
            Some("rm"),
            "ignored",
            &remove,
        ));
    }

    #[test]
    fn ct_agent_authz_risk_matrix_bounds_scope_duration_and_recommendation() {
        let r1 = pending("R1");
        assert_eq!(
            permission_available_scopes(&r1),
            vec![
                PermissionScope::Exact,
                PermissionScope::Safe,
                PermissionScope::All
            ]
        );
        assert_eq!(
            permission_recommended_choice(&r1),
            PermissionChoice {
                effect: PermissionEffect::Allow,
                scope: PermissionScope::Safe,
                duration: PermissionDuration::Connection,
                path_pattern: None,
            }
        );

        let r3 = pending("R3");
        assert_eq!(
            permission_available_scopes(&r3),
            vec![PermissionScope::Exact]
        );
        assert!(permission_snapshot(&r3).fresh_confirmation_required);

        let r4 = pending("R4");
        assert_eq!(
            permission_available_durations(&r4, PermissionEffect::Allow),
            vec![PermissionDuration::Once]
        );
        assert_eq!(
            permission_available_durations(&r4, PermissionEffect::Deny),
            vec![
                PermissionDuration::Once,
                PermissionDuration::Connection,
                PermissionDuration::Permanent
            ]
        );
    }
}
