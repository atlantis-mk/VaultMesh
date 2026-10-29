use super::*;

#[derive(Clone, Debug)]
struct AgentAuditContext {
    account_ref: Uuid,
    account_label: String,
    environment: String,
    target_class: String,
    approved_display: String,
    risk: String,
}

impl AgentBrokerCore {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn handle_json(&mut self, client_id: Uuid, bytes: &[u8], now_millis: u64) -> Value {
        self.handle_json_inner(client_id, bytes, now_millis, None, false, false)
            .0
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn handle_json_with_executor(
        &mut self,
        client_id: Uuid,
        bytes: &[u8],
        now_millis: u64,
        executor: &AgentToolExecutor,
    ) -> Value {
        self.handle_json_inner(client_id, bytes, now_millis, Some(executor), false, false)
            .0
    }

    pub fn authorize_json_for_dispatch(
        &mut self,
        client_id: Uuid,
        bytes: &[u8],
        now_millis: u64,
    ) -> (
        Value,
        Option<NewAgentAuditEvent>,
        Option<AuthorizedAgentAction>,
    ) {
        let (response, action) =
            self.handle_json_inner(client_id, bytes, now_millis, None, true, false);
        let audit = self.take_audit();
        (response, audit, action)
    }

    pub(crate) fn continue_json_for_dispatch(
        &mut self,
        client_id: Uuid,
        bytes: &[u8],
        now_millis: u64,
    ) -> (
        Value,
        Option<NewAgentAuditEvent>,
        Option<AuthorizedAgentAction>,
    ) {
        let (response, action) =
            self.handle_json_inner(client_id, bytes, now_millis, None, true, true);
        let audit = self.take_audit();
        (response, audit, action)
    }

    pub(super) fn handle_json_inner(
        &mut self,
        client_id: Uuid,
        bytes: &[u8],
        now_millis: u64,
        executor: Option<&AgentToolExecutor>,
        capture_action: bool,
        native_continuation: bool,
    ) -> (Value, Option<AuthorizedAgentAction>) {
        let request_id = serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("requestId")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .map(|value| value.to_string())
            });
        let audit_request = serde_json::from_slice::<AgentRequest>(bytes).ok();
        let result = self.handle_request(
            client_id,
            bytes,
            now_millis,
            executor,
            capture_action,
            native_continuation,
        );
        if let Some(request) = audit_request.as_ref()
            && let Some(context) = self.audit_context_for_request(client_id, request)
            && !matches!(
                &result,
                Err(AgentBrokerError {
                    code: "confirmation-required",
                    ..
                })
            )
        {
            let tool = self
                .registry
                .tools
                .iter()
                .find(|tool| tool.name == request.tool);
            let client_kind = self
                .clients
                .get(&client_id)
                .map(|client| client.client_key.clone());
            if let (Some(tool), Some(client_kind), Some(risk)) = (
                tool,
                client_kind,
                serde_json::from_value::<AgentRiskTier>(json!(&context.risk)).ok(),
            ) {
                let (decision, result_class, status_class) = match &result {
                    Ok(_) => (
                        AgentAuditDecision::Allowed,
                        AgentAuditResultClass::Succeeded,
                        Some("ok".to_owned()),
                    ),
                    Err(error) if error.code == "adapter-unavailable" => (
                        AgentAuditDecision::Allowed,
                        AgentAuditResultClass::Unavailable,
                        Some(error.code.to_owned()),
                    ),
                    Err(error) => (
                        AgentAuditDecision::Denied,
                        AgentAuditResultClass::Denied,
                        Some(error.code.to_owned()),
                    ),
                };
                let confirmation = match tool.confirmation.as_str() {
                    "fresh" => AgentAuditConfirmation::Fresh,
                    "privileged" => AgentAuditConfirmation::Privileged,
                    "session" => AgentAuditConfirmation::Session,
                    "risk-dependent" if risk_rank(&context.risk) >= 2 => {
                        AgentAuditConfirmation::Fresh
                    }
                    "risk-dependent" => AgentAuditConfirmation::Session,
                    _ => AgentAuditConfirmation::None,
                };
                self.audit_queue.clear();
                self.audit_queue.push(NewAgentAuditEvent {
                    occurred_at: now_millis,
                    client_id,
                    client_kind,
                    session_id: request.session_id,
                    account_ref: context.account_ref,
                    account_label: context.account_label,
                    environment: context.environment,
                    tool: request.tool.clone(),
                    target_class: context.target_class,
                    approved_display: context.approved_display,
                    risk,
                    decision,
                    confirmation,
                    duration_millis: 0,
                    result_class,
                    status_class,
                    item_count: 0,
                    byte_count: 0,
                });
            }
        }
        match result {
            Ok((request_id, result, action)) => (
                json!({
                    "ok": true,
                    "requestId": request_id,
                    "auditRef": Value::Null,
                    "result": result,
                    "truncated": false,
                    "continuationRef": Value::Null
                }),
                action,
            ),
            Err(error) => (
                json!({
                    "ok": false,
                    "requestId": request_id,
                    "error": error
                }),
                None,
            ),
        }
    }

    fn audit_context_for_request(
        &self,
        client_id: Uuid,
        request: &AgentRequest,
    ) -> Option<AgentAuditContext> {
        let account_ref = request.account_ref.as_deref()?;
        let parameters_digest = canonical_parameters_digest(&request.parameters).ok()?;
        let key = (
            client_id,
            account_ref.to_owned(),
            request.tool.clone(),
            parameters_digest.clone(),
        );
        if let Some(policy) = self.active_direct_ssh_policies.get(&key) {
            return Some(AgentAuditContext {
                account_ref: policy.account_ref,
                account_label: policy.account_label.clone(),
                environment: policy.environment.clone(),
                target_class: "ssh".to_owned(),
                approved_display: policy.approved_display.clone(),
                risk: policy.risk.clone(),
            });
        }
        if let Some(policy) = self.active_direct_http_policies.get(&key) {
            let risk = serde_json::to_value(policy.operation.risk)
                .ok()?
                .as_str()?
                .to_owned();
            return Some(AgentAuditContext {
                account_ref: policy.account_ref,
                account_label: policy.account_label.clone(),
                environment: policy.environment.clone(),
                target_class: "http".to_owned(),
                approved_display: policy.approved_display.clone(),
                risk,
            });
        }
        if let Some(policy) = self.active_direct_connector_policies.get(&key) {
            return Some(AgentAuditContext {
                account_ref: policy.account_ref,
                account_label: policy.account_label.clone(),
                environment: policy.environment.clone(),
                target_class: policy.connector_kind.clone(),
                approved_display: policy.approved_display.clone(),
                risk: policy.risk.clone(),
            });
        }
        if let Some(pending) = self.permission_requests.values().find(|pending| {
            pending.client_id == client_id
                && pending.account_ref == account_ref
                && pending.tool == request.tool
                && pending.parameters_digest.as_deref() == Some(parameters_digest.as_str())
        }) {
            let target_class = pending
                .direct_ssh_policy
                .as_ref()
                .map(|_| "ssh".to_owned())
                .or_else(|| {
                    pending
                        .direct_http_policy
                        .as_ref()
                        .map(|_| "http".to_owned())
                })
                .or_else(|| {
                    pending
                        .direct_connector_policy
                        .as_ref()
                        .map(|policy| policy.connector_kind.clone())
                })?;
            return Some(AgentAuditContext {
                account_ref: Uuid::parse_str(account_ref).ok()?,
                account_label: pending.account_label.clone(),
                environment: pending.environment.clone(),
                target_class,
                approved_display: pending.approved_display.clone(),
                risk: pending.risk.clone(),
            });
        }
        if is_ssh_pty_session_tool(&request.tool) {
            return Some(AgentAuditContext {
                account_ref: Uuid::parse_str(account_ref).ok()?,
                account_label: "SSH PTY session".to_owned(),
                environment: "active-session".to_owned(),
                target_class: "ssh-pty-session".to_owned(),
                approved_display: "Bound SSH PTY session".to_owned(),
                risk: self
                    .registry
                    .tools
                    .iter()
                    .find(|tool| tool.name == request.tool)
                    .map(|tool| tool.risk.clone())?,
            });
        }
        None
    }

    pub(super) fn handle_request(
        &mut self,
        client_id: Uuid,
        bytes: &[u8],
        now_millis: u64,
        executor: Option<&AgentToolExecutor>,
        capture_action: bool,
        native_continuation: bool,
    ) -> Result<(Uuid, Value, Option<AuthorizedAgentAction>), AgentBrokerError> {
        self.prune(now_millis);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(AgentBrokerError::new(
                "request-too-large",
                "The Agent request exceeds the size limit.",
                false,
            ));
        }
        let mut request: AgentRequest = serde_json::from_slice(bytes).map_err(|_| {
            AgentBrokerError::new("invalid-request", "The Agent request is invalid.", false)
        })?;
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(AgentBrokerError::new(
                "update-required",
                "The Agent protocol version is not supported.",
                false,
            ));
        }
        if request.session_id.is_nil() {
            let mut connection_session = self
                .sessions
                .values()
                .find(|session| session.client_id == client_id && session.connection_managed)
                .map(|session| session.session_id);
            let pairing_state = self
                .clients
                .get(&client_id)
                .map(|client| client.pairing_state);
            if connection_session.is_none() && pairing_state == Some(PairingState::Paired) {
                self.ensure_connection_session(client_id, now_millis)?;
                connection_session = self
                    .sessions
                    .values()
                    .find(|session| session.client_id == client_id && session.connection_managed)
                    .map(|session| session.session_id);
            }
            request.session_id = if let Some(session_id) = connection_session {
                session_id
            } else if pairing_state == Some(PairingState::Pending) {
                return Err(AgentBrokerError::native(
                    "pairing-required",
                    "approve-pairing",
                ));
            } else {
                return Err(AgentBrokerError::new(
                    "session-required",
                    "The MCP connection session is unavailable; reconnect the client.",
                    true,
                ));
            };
        }
        if native_continuation && !self.seen_requests.contains(&request.request_id) {
            return Err(AgentBrokerError::internal());
        }
        if !native_continuation && self.seen_requests.contains(&request.request_id) {
            return Err(AgentBrokerError::new(
                "request-replayed",
                "The Agent request has already been used.",
                false,
            ));
        }
        if !native_continuation {
            if self.seen_requests.len() >= MAX_SEEN_REQUESTS {
                self.seen_requests.clear();
            }
            self.seen_requests.insert(request.request_id);
        }
        let tool = self
            .registry
            .tools
            .iter()
            .find(|tool| tool.name == request.tool)
            .ok_or_else(|| {
                AgentBrokerError::new("unknown-tool", "The Agent tool is not supported.", false)
            })?
            .clone();
        if request.tool_version != tool.version {
            return Err(AgentBrokerError::new(
                "update-required",
                "The Agent tool version is not supported.",
                false,
            ));
        }
        if !request.parameters.is_object() {
            return Err(AgentBrokerError::new(
                "invalid-parameters",
                "The Agent tool parameters are invalid.",
                false,
            ));
        }
        validate_parameters(&tool, &request.parameters)?;
        let session = self.sessions.get(&request.session_id).ok_or_else(|| {
            AgentBrokerError::new(
                "session-required",
                "The MCP connection session is unavailable; reconnect the client.",
                true,
            )
        })?;
        if session.client_id != client_id
            || session.expires_at <= now_millis
            || session.requests_used >= session.request_limit
        {
            return Err(AgentBrokerError::new(
                "session-denied",
                "The connection session is expired or unavailable.",
                false,
            ));
        }
        if !session.allowed_tools.contains(&request.tool) {
            return Err(AgentBrokerError::new(
                "capability-denied",
                "The connection session does not allow this capability.",
                false,
            ));
        }
        self.require_agent_unlock(client_id, &request.tool, now_millis)?;
        let permission_operation = request_permission_operation(&request.tool, &request.parameters);
        let parameters_digest = canonical_parameters_digest(&request.parameters)?;
        let direct_policy_key = request.account_ref.as_ref().map(|account_ref| {
            (
                client_id,
                account_ref.clone(),
                request.tool.clone(),
                parameters_digest.clone(),
            )
        });
        let derived_ssh_pty_action = is_ssh_pty_session_tool(&request.tool);
        let direct_plan_missing = tool.requires_account
            && !derived_ssh_pty_action
            && direct_policy_key.as_ref().is_none_or(|key| {
                !self.active_direct_ssh_policies.contains_key(key)
                    && !self.active_direct_http_policies.contains_key(key)
                    && !self.active_direct_connector_policies.contains_key(key)
            });
        let connection_session = self
            .sessions
            .get(&request.session_id)
            .is_some_and(|session| session.connection_managed);
        if connection_session
            && tool.requires_account
            && !derived_ssh_pty_action
            && request.tool != "vaultmesh_ssh_agent_open"
        {
            let account_ref = request.account_ref.as_deref().ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An account reference is required.",
                    false,
                )
            })?;
            let permission_grant =
                self.transport_permission_grants
                    .get(&client_id)
                    .and_then(|grants| {
                        matching_permission_grant_index(
                            grants,
                            account_ref,
                            &request.tool,
                            permission_operation,
                            &parameters_digest,
                            &request.parameters,
                        )
                        .map(|index| &grants[index])
                    });
            if permission_grant.is_some_and(|grant| grant.effect == PermissionEffect::Deny) {
                return Err(AgentBrokerError::authorization_denied());
            }
            if direct_plan_missing
                || !permission_grant.is_some_and(|grant| {
                    grant.effect == PermissionEffect::Allow && !grant.fresh_confirmation_required
                })
            {
                let pending = self.request_permission(
                    client_id,
                    request.session_id,
                    account_ref,
                    &json!({
                        "tool": request.tool,
                        "operation": permission_operation,
                        "actionParameters": request.parameters
                    }),
                    now_millis,
                )?;
                match pending.get("status").and_then(Value::as_str) {
                    Some("allowed") => {}
                    Some("denied") => {
                        return Err(AgentBrokerError::new(
                            "authorization-denied",
                            "The action is denied by a persistent authorization rule.",
                            false,
                        ));
                    }
                    _ => {
                        let permission_ref = pending
                            .get("permissionRef")
                            .and_then(Value::as_str)
                            .ok_or_else(AgentBrokerError::internal)?;
                        return Err(AgentBrokerError::authorization(permission_ref));
                    }
                }
            }
        }
        let direct_ssh_policy = if request.tool == "vaultmesh_ssh_agent_open" {
            let account_uuid = request
                .account_ref
                .as_deref()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "account-required",
                        "An account reference is required.",
                        false,
                    )
                })?;
            let factory = self
                .direct_ssh_policy_factory
                .clone()
                .ok_or_else(|| AgentBrokerError::action_rule_unavailable("ssh", &request.tool))?;
            let policy = factory(account_uuid, &request.tool, &request.parameters)?;
            Some(policy)
        } else {
            direct_policy_key
                .as_ref()
                .and_then(|key| self.active_direct_ssh_policies.get(key).cloned())
        };
        let direct_http_policy = (request.tool == "vaultmesh_http_request")
            .then(|| {
                request.account_ref.as_ref().and_then(|account_ref| {
                    self.active_direct_http_policies
                        .get(&(
                            client_id,
                            account_ref.clone(),
                            request.tool.clone(),
                            parameters_digest.clone(),
                        ))
                        .cloned()
                })
            })
            .flatten();
        let direct_connector_policy = direct_policy_key
            .as_ref()
            .and_then(|key| self.active_direct_connector_policies.get(key).cloned());
        let execution_account_ref = request.account_ref.clone();
        if tool.requires_account {
            let account_ref = request.account_ref.as_deref().ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let account_approved = if request.tool == "vaultmesh_ssh_agent_open" {
                let is_valid = self
                    .refresh_account_catalog()
                    .map(|candidates| {
                        candidates.iter().any(|candidate| {
                            candidate.account_ref.to_string() == account_ref
                                && candidate.kind == "ssh"
                        })
                    })
                    .unwrap_or(false);
                if is_valid {
                    if let Some(session) = self.sessions.get_mut(&request.session_id) {
                        session.allowed_accounts.insert(account_ref.to_owned());
                    }
                    true
                } else {
                    false
                }
            } else {
                self.sessions
                    .get(&request.session_id)
                    .is_some_and(|session| session.allowed_accounts.contains(account_ref))
            };
            if !account_approved {
                return Err(AgentBrokerError::new(
                    "account-denied",
                    "The account is not approved for this connection.",
                    false,
                ));
            }
            if direct_ssh_policy.is_none()
                && direct_http_policy.is_none()
                && direct_connector_policy.is_none()
                && !derived_ssh_pty_action
            {
                return Err(AgentBrokerError::new(
                    "action-plan-unavailable",
                    "The account action is missing its immutable direct plan.",
                    false,
                ));
            }
        } else if request.account_ref.is_some() {
            return Err(AgentBrokerError::new(
                "invalid-account",
                "This Agent tool does not accept an account reference.",
                false,
            ));
        }
        let direct_ssh_action = direct_ssh_policy.is_some();
        let effective_risk = if direct_ssh_action {
            direct_ssh_policy
                .as_ref()
                .map(|policy| policy.risk.clone())
                .ok_or_else(AgentBrokerError::internal)?
        } else if let Some(policy) = direct_http_policy.as_ref() {
            serde_json::to_value(policy.operation.risk)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(AgentBrokerError::internal)?
        } else if let Some(policy) = direct_connector_policy.as_ref() {
            policy.risk.clone()
        } else {
            tool.risk.clone()
        };
        if connection_session
            && !SESSION_BASE_TOOLS.contains(&request.tool.as_str())
            && !derived_ssh_pty_action
            && request.tool != "vaultmesh_ssh_agent_open"
        {
            let account_ref = request.account_ref.as_deref().ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let permission_grant =
                self.transport_permission_grants
                    .get(&client_id)
                    .and_then(|grants| {
                        matching_permission_grant_index(
                            grants,
                            account_ref,
                            &request.tool,
                            permission_operation,
                            &parameters_digest,
                            &request.parameters,
                        )
                        .map(|index| &grants[index])
                    });
            if permission_grant.is_some_and(|grant| grant.effect == PermissionEffect::Deny) {
                return Err(AgentBrokerError::authorization_denied());
            }
            if !permission_grant.is_some_and(|grant| {
                grant.effect == PermissionEffect::Allow && !grant.fresh_confirmation_required
            }) {
                return Err(AgentBrokerError::native(
                    "permission-required",
                    "request-permission",
                ));
            }
        }
        let confirmation_required = matches!(
            tool.confirmation.as_str(),
            "fresh" | "privileged" | "first-target"
        ) || (tool.confirmation == "risk-dependent"
            && risk_rank(&effective_risk) >= 2);
        if request.confirmation_ticket.is_some() && !confirmation_required {
            return Err(AgentBrokerError::new(
                "invalid-confirmation",
                "This Agent tool does not accept a confirmation ticket.",
                false,
            ));
        }
        if request
            .confirmation_ticket
            .as_deref()
            .is_some_and(|ticket| {
                ticket.is_empty() || ticket.len() > 128 || ticket.chars().any(char::is_control)
            })
        {
            return Err(AgentBrokerError::new(
                "invalid-confirmation",
                "The Agent confirmation ticket is invalid.",
                false,
            ));
        }
        let canonical_target = if let Some(policy) = direct_ssh_policy.as_ref() {
            json!({
                "accountRef": policy.account_ref,
                "connector": "ssh",
                "host": policy.host,
                "port": policy.port,
                "username": policy.username,
                "hostKeySha256": policy.host_key_sha256,
                "targetDigest": policy.target_digest,
            })
        } else if derived_ssh_pty_action {
            json!({
                "accountRef": request.account_ref,
                "connector": "ssh-pty-session",
                "sessionRef": request.parameters.get("sessionRef")
            })
        } else if let Some(policy) = direct_http_policy.as_ref() {
            json!({
                "accountRef": policy.account_ref,
                "connector": "http",
                "origin": policy.origin,
                "operation": policy.operation.name,
                "targetDigest": policy.target_digest,
            })
        } else if let Some(policy) = direct_connector_policy.as_ref() {
            json!({
                "accountRef": policy.account_ref,
                "connector": policy.connector_kind,
                "operation": policy.operation,
                "targetDigest": policy.target_digest,
            })
        } else {
            Value::Null
        };
        let action_digest = canonical_action_digest(CanonicalActionInput {
            client_id,
            session_id: request.session_id,
            account_ref: request.account_ref.as_deref(),
            tool: &request.tool,
            tool_version: request.tool_version,
            canonical_target: &canonical_target,
            parameters: &request.parameters,
            risk: &effective_risk,
        })?;
        if confirmation_required {
            self.validate_or_request_confirmation(
                client_id,
                request.session_id,
                request.account_ref.clone(),
                direct_ssh_policy
                    .as_ref()
                    .map(|policy| policy.account_label.clone())
                    .or_else(|| {
                        direct_http_policy
                            .as_ref()
                            .map(|policy| policy.account_label.clone())
                    })
                    .or_else(|| {
                        direct_connector_policy
                            .as_ref()
                            .map(|policy| policy.account_label.clone())
                    }),
                &request.tool,
                &effective_risk,
                action_digest,
                request.confirmation_ticket.as_deref(),
                now_millis,
            )?;
        }
        let session = self.sessions.get_mut(&request.session_id).ok_or_else(|| {
            AgentBrokerError::new(
                "session-required",
                "The MCP connection session is unavailable; reconnect the client.",
                true,
            )
        })?;
        session.requests_used = session.requests_used.saturating_add(1);
        if session.connection_managed
            && !SESSION_BASE_TOOLS.contains(&request.tool.as_str())
            && request.tool != "vaultmesh_ssh_agent_open"
            && let Some(grants) = self.transport_permission_grants.get_mut(&client_id)
        {
            if let Some(index) = matching_permission_grant_index(
                grants,
                request.account_ref.as_deref().unwrap_or_default(),
                &request.tool,
                permission_operation,
                &parameters_digest,
                &request.parameters,
            ) && grants[index].effect == PermissionEffect::Allow
                && let Some(remaining) = grants[index].remaining_uses.as_mut()
            {
                *remaining = remaining.saturating_sub(1);
            }
            grants.retain(|grant| grant.remaining_uses != Some(0));
        }
        let session_cancellation = Arc::clone(&session.cancellation);
        let mut authorized_action = None;
        let result = match request.tool.as_str() {
            "vaultmesh_accounts_list" => self.accounts_page(&request.parameters)?,
            "vaultmesh_request_local_ui" => {
                return Err(AgentBrokerError::native(
                    "native-action-required",
                    "open-local-ui",
                ));
            }
            _ => {
                if let Some(executor) = executor {
                    let scope = AgentExecutionScope {
                        client_id,
                        session_id: request.session_id,
                        cancellation: Arc::clone(&session_cancellation),
                        direct_ssh_policy: direct_ssh_policy.clone(),
                        direct_http_policy: direct_http_policy.clone(),
                        direct_connector_policy: direct_connector_policy.clone(),
                    };
                    executor(
                        &request.tool,
                        execution_account_ref.as_deref(),
                        &request.parameters,
                        &session_cancellation,
                        &scope,
                    )?
                } else if capture_action {
                    let scope = AgentExecutionScope {
                        client_id,
                        session_id: request.session_id,
                        cancellation: Arc::clone(&session_cancellation),
                        direct_ssh_policy: direct_ssh_policy.clone(),
                        direct_http_policy: direct_http_policy.clone(),
                        direct_connector_policy: direct_connector_policy.clone(),
                    };
                    authorized_action = Some(AuthorizedAgentAction {
                        tool: request.tool.clone(),
                        account_ref: execution_account_ref.clone(),
                        parameters: request.parameters.clone(),
                        scope,
                        cancellation: Arc::clone(&session_cancellation),
                        output_bytes_used: Arc::clone(&session.output_bytes_used),
                        remaining_session_millis: session.expires_at.saturating_sub(now_millis),
                        authorized_at: Instant::now(),
                    });
                    json!({})
                } else {
                    Err(AgentBrokerError::new(
                        "adapter-unavailable",
                        "This approved Agent adapter is not available in this build.",
                        false,
                    ))?
                }
            }
        };
        Ok((request.request_id, result, authorized_action))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_or_request_confirmation(
        &mut self,
        client_id: Uuid,
        session_id: Uuid,
        account_ref: Option<String>,
        account_label: Option<String>,
        tool: &str,
        risk: &str,
        action_digest: String,
        confirmation_ticket: Option<&str>,
        now_millis: u64,
    ) -> Result<(), AgentBrokerError> {
        if let Some(ticket) = confirmation_ticket {
            let ticket = parse_opaque_id(ticket, "invalid-confirmation")?;
            let confirmation = self.confirmations.remove(&ticket).ok_or_else(|| {
                AgentBrokerError::new(
                    "invalid-confirmation",
                    "The confirmation ticket is expired or unavailable.",
                    false,
                )
            })?;
            if !confirmation.approved
                || confirmation.expires_at <= now_millis
                || confirmation.client_id != client_id
                || confirmation.session_id != session_id
                || confirmation.action_digest != action_digest
            {
                return Err(AgentBrokerError::new(
                    "confirmation-mismatch",
                    "The confirmation does not match this exact action.",
                    false,
                ));
            }
            return Ok(());
        }

        if let Some(existing) = self.confirmations.values().find(|confirmation| {
            confirmation.client_id == client_id
                && confirmation.session_id == session_id
                && confirmation.action_digest == action_digest
                && confirmation.expires_at > now_millis
        }) {
            return Err(AgentBrokerError::confirmation(existing.confirmation_ref));
        }
        let confirmation_ref = Uuid::new_v4();
        self.confirmations.insert(
            confirmation_ref,
            PendingConfirmation {
                confirmation_ref,
                client_id,
                session_id,
                account_ref,
                account_label,
                tool: tool.to_owned(),
                risk: risk.to_owned(),
                action_digest,
                created_at: now_millis,
                expires_at: now_millis.saturating_add(CONFIRMATION_TTL_MILLIS),
                approved: false,
            },
        );
        Err(AgentBrokerError::confirmation(confirmation_ref))
    }

    pub(crate) fn prune(&mut self, now_millis: u64) {
        self.pending_pairings
            .retain(|_, pending| pending.expires_at > now_millis);
        let expired = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session.expires_at <= now_millis).then_some(*session_id)
            })
            .collect::<Vec<_>>();
        for session_id in expired {
            if let Some(session) = self.sessions.remove(&session_id) {
                session.cancellation.store(true, Ordering::Release);
                self.cleanup_resources(AgentCleanupScope::Session(session_id));
            }
        }
        self.confirmations.retain(|_, confirmation| {
            confirmation.expires_at > now_millis
                && self.sessions.contains_key(&confirmation.session_id)
        });
        self.permission_requests.retain(|_, permission| {
            permission.expires_at > now_millis
                && self.sessions.contains_key(&permission.session_id)
                && self.clients.contains_key(&permission.client_id)
        });
        self.permission_outcomes
            .retain(|_, outcome| outcome.expires_at > now_millis);
        self.confirmation_outcomes
            .retain(|_, outcome| outcome.expires_at > now_millis);
        let expired_unlock_outcomes = self
            .unlock_outcomes
            .iter()
            .filter_map(|(unlock_ref, outcome)| {
                (outcome.expires_at <= now_millis).then_some(*unlock_ref)
            })
            .collect::<Vec<_>>();
        for unlock_ref in expired_unlock_outcomes {
            self.unlock_outcomes.remove(&unlock_ref);
            self.pending_unlocks.remove(&unlock_ref);
        }
        let connected_clients = &self.clients;
        self.pending_unlocks.retain(|_, pending| {
            pending
                .client_ids
                .retain(|client_id| connected_clients.contains_key(client_id));
            if !pending.client_ids.contains(&pending.client_id)
                && let Some(next) = pending.client_ids.iter().next()
            {
                pending.client_id = *next;
            }
            pending.expires_at > now_millis && !pending.client_ids.is_empty()
        });
    }

    pub(super) fn cleanup_resources(&self, scope: AgentCleanupScope) {
        if let Some(cleanup) = &self.resource_cleanup {
            cleanup(scope);
        }
    }

    pub(super) fn client_snapshot(&self, client_id: Uuid) -> Option<AgentClientSnapshot> {
        let client = self.clients.get(&client_id)?;
        Some(AgentClientSnapshot {
            client_id: client.client_id.to_string(),
            client_key: client.client_key.clone(),
            pairing_state: client.pairing_state,
            connected_at: client.connected_at,
            active_session_count: self
                .sessions
                .values()
                .filter(|session| session.client_id == client_id)
                .count(),
        })
    }

    pub(super) fn session_snapshot(&self, session_id: Uuid) -> Option<ConnectionSessionSnapshot> {
        let session = self.sessions.get(&session_id)?;
        let mut allowed_tools = session.allowed_tools.iter().cloned().collect::<Vec<_>>();
        let mut allowed_accounts = session.allowed_accounts.iter().cloned().collect::<Vec<_>>();
        allowed_tools.sort();
        allowed_accounts.sort();
        Some(ConnectionSessionSnapshot {
            session_id: session.session_id.to_string(),
            client_id: session.client_id.to_string(),
            allowed_tools,
            allowed_accounts,
            issued_at: session.issued_at,
            expires_at: session.expires_at,
            request_limit: session.request_limit,
            requests_used: session.requests_used,
            output_byte_limit: MAX_SESSION_OUTPUT_BYTES,
            output_bytes_used: session.output_bytes_used.load(Ordering::Acquire),
        })
    }
}
