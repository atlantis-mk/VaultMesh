use super::*;

impl AgentBrokerCore {
    #[cfg(test)]
    pub fn new() -> Result<Self, AgentBrokerError> {
        let mut broker = Self::new_with_pairing_proofs(AgentPairingProofs::memory())?;
        broker.set_access_check(Arc::new(|_| true));
        Ok(broker)
    }

    pub fn new_with_pairing_proofs(
        pairing_proofs: AgentPairingProofs,
    ) -> Result<Self, AgentBrokerError> {
        Ok(Self {
            registry: capability_registry()?,
            pairing_proofs,
            clients: HashMap::new(),
            pending_pairings: HashMap::new(),
            pending_unlocks: HashMap::new(),
            unlock_outcomes: HashMap::new(),
            sessions: HashMap::new(),
            seen_requests: HashSet::new(),
            connector_definitions: HashMap::new(),
            confirmations: HashMap::new(),
            permission_requests: HashMap::new(),
            permission_outcomes: HashMap::new(),
            confirmation_outcomes: HashMap::new(),
            audit_queue: Vec::new(),
            resource_cleanup: None,
            access_check: None,
            access_shares_unlock: None,
            access_lock: None,
            access_register: None,
            access_disconnect: None,
            account_catalog: None,
            api_environment_catalog: None,
            direct_ssh_policy_factory: None,
            direct_http_policy_factory: None,
            direct_connector_policy_factory: None,
            authorization_store: None,
            transport_permission_grants: HashMap::new(),
            active_direct_ssh_policies: HashMap::new(),
            active_direct_http_policies: HashMap::new(),
            active_direct_connector_policies: HashMap::new(),
        })
    }

    pub fn set_resource_cleanup(&mut self, cleanup: AgentResourceCleanup) {
        self.resource_cleanup = Some(cleanup);
    }

    pub fn set_access_check(&mut self, check: AgentAccessCheck) {
        self.access_check = Some(check);
    }

    pub fn set_access_shares_unlock(&mut self, shares_unlock: AgentAccessSharesUnlock) {
        self.access_shares_unlock = Some(shares_unlock);
    }

    pub fn set_access_lock(&mut self, lock: AgentAccessLock) {
        self.access_lock = Some(lock);
    }

    pub fn set_access_register(&mut self, register: AgentAccessRegister) {
        self.access_register = Some(register);
    }

    pub fn set_access_disconnect(&mut self, disconnect: AgentAccessDisconnect) {
        self.access_disconnect = Some(disconnect);
    }

    pub fn set_account_catalog(&mut self, catalog: AgentAccountCatalog) {
        self.account_catalog = Some(catalog);
    }

    pub fn set_api_environment_catalog(&mut self, catalog: AgentApiEnvironmentCatalog) {
        self.api_environment_catalog = Some(catalog);
    }

    fn refresh_api_environment_catalog(
        &self,
    ) -> Result<Vec<AgentApiEnvironmentCandidate>, AgentBrokerError> {
        let Some(catalog) = self.api_environment_catalog.clone() else {
            return Ok(Vec::new());
        };
        let candidates = catalog()?;
        if candidates.len() > 10_000 {
            return Err(AgentBrokerError::new(
                "account-catalog-too-large",
                "The API environment catalog exceeds the supported size.",
                false,
            ));
        }
        let mut seen = HashSet::new();
        for candidate in &candidates {
            if !seen.insert(candidate.environment_ref)
                || candidate.label.is_empty()
                || candidate.label.encode_utf16().count() > 128
                || candidate.label.chars().any(char::is_control)
                || !matches!(
                    candidate.environment.as_str(),
                    "production" | "staging" | "development" | "local" | "other"
                )
                || candidate.capability != "http"
                || candidate.policy_digest.len() != 64
                || !candidate
                    .policy_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || candidate.openapi_url.as_ref().is_some_and(|url| {
                    url.encode_utf16().count() > 2_048
                        || url.chars().any(char::is_control)
                        || url::Url::parse(url).ok().is_none_or(|parsed| {
                            !matches!(parsed.scheme(), "http" | "https")
                                || !parsed.username().is_empty()
                                || parsed.password().is_some()
                                || parsed.host_str().is_none()
                        })
                })
            {
                return Err(AgentBrokerError::new(
                    "invalid-account-catalog",
                    "The API environment catalog is invalid.",
                    false,
                ));
            }
        }
        Ok(candidates)
    }

    pub fn set_direct_ssh_policy_factory(&mut self, factory: AgentDirectSshPolicyFactory) {
        self.direct_ssh_policy_factory = Some(factory);
    }

    pub fn set_direct_http_policy_factory(&mut self, factory: AgentDirectHttpPolicyFactory) {
        self.direct_http_policy_factory = Some(factory);
    }

    pub fn set_direct_connector_policy_factory(
        &mut self,
        factory: AgentDirectConnectorPolicyFactory,
    ) {
        self.direct_connector_policy_factory = Some(factory);
    }

    pub fn set_authorization_store(&mut self, store: AgentAuthorizationStore) {
        self.authorization_store = Some(store);
    }

    pub(super) fn remove_direct_action_policies_for_client(&mut self, client_id: Uuid) {
        self.active_direct_ssh_policies
            .retain(|(policy_client_id, _, _, _), _| *policy_client_id != client_id);
        self.active_direct_http_policies
            .retain(|(policy_client_id, _, _, _), _| *policy_client_id != client_id);
        self.active_direct_connector_policies
            .retain(|(policy_client_id, _, _, _), _| *policy_client_id != client_id);
    }

    pub(super) fn remove_all_direct_action_policies(&mut self) {
        self.active_direct_ssh_policies.clear();
        self.active_direct_http_policies.clear();
        self.active_direct_connector_policies.clear();
    }

    pub(super) fn refresh_account_catalog(
        &mut self,
    ) -> Result<Vec<AgentVaultAccountCandidate>, AgentBrokerError> {
        let catalog = self.account_catalog.clone().ok_or_else(|| {
            AgentBrokerError::new(
                "account-catalog-unavailable",
                "The Vault account catalog is unavailable.",
                true,
            )
        })?;
        let snapshot = catalog()?;
        if snapshot.connector_definitions.len() > 256 || snapshot.candidates.len() > 50_000 {
            return Err(AgentBrokerError::new(
                "account-catalog-too-large",
                "The Vault account catalog exceeds the supported size.",
                false,
            ));
        }
        self.sync_connector_definitions(snapshot.connector_definitions)?;
        let mut seen = HashSet::new();
        for candidate in &snapshot.candidates {
            if !seen.insert(candidate.account_ref)
                || !matches!(candidate.kind.as_str(), "login" | "ssh" | "secret")
                || candidate.label.is_empty()
                || candidate.label.encode_utf16().count() > 128
                || candidate.label.chars().any(char::is_control)
            {
                return Err(AgentBrokerError::new(
                    "invalid-account-catalog",
                    "The Vault account catalog is invalid.",
                    false,
                ));
            }
        }
        Ok(snapshot.candidates)
    }

    pub(super) fn accounts_page(&mut self, parameters: &Value) -> Result<Value, AgentBrokerError> {
        let limit = parameters
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(AgentBrokerError::new(
                "invalid-parameters",
                "The account page limit must be between 1 and 100.",
                false,
            ));
        }
        let cursor = parameters.get("cursor").and_then(Value::as_str);
        let query = parameters
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|query| !query.is_empty())
            .map(str::to_lowercase);
        let string_filter = |field: &str| -> Result<HashSet<String>, AgentBrokerError> {
            parameters
                .get(field)
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(|value| {
                            value.as_str().map(str::to_owned).ok_or_else(|| {
                                AgentBrokerError::new(
                                    "invalid-parameters",
                                    "An account filter is invalid.",
                                    false,
                                )
                            })
                        })
                        .collect()
                })
                .unwrap_or_else(|| Ok(HashSet::new()))
        };
        let kinds = string_filter("kinds")?;
        if kinds.iter().any(|kind| {
            !matches!(
                kind.as_str(),
                "login" | "ssh" | "secret" | "api-environment"
            )
        }) {
            return Err(AgentBrokerError::new(
                "invalid-parameters",
                "The requested account kind is invalid.",
                false,
            ));
        }
        let capabilities = string_filter("capabilities")?;
        let environments = string_filter("environments")?;
        let capability_by_tool = self
            .registry
            .tools
            .iter()
            .map(|tool| (tool.name.clone(), tool.capability.clone()))
            .collect::<HashMap<_, _>>();
        let known_capabilities = capability_by_tool
            .values()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if capabilities
            .iter()
            .any(|capability| !known_capabilities.contains(capability.as_str()))
        {
            return Err(AgentBrokerError::new(
                "invalid-parameters",
                "The requested account capability is not in the public capability catalog.",
                false,
            ));
        }
        let mut candidates = if self.account_catalog.is_some() {
            self.refresh_account_catalog()?
        } else {
            Vec::new()
        };
        let api_environments = self.refresh_api_environment_catalog()?;
        let mut ssh_tunnel_actions: HashMap<Uuid, Vec<Value>> = HashMap::new();
        for definition in self.connector_definitions.values().filter(|definition| {
            definition.enabled
                && definition.connector_kind == "ssh"
                && definition.source_account_ref.is_some()
                && definition
                    .allowed_tools
                    .contains("vaultmesh_ssh_tunnel_open")
        }) {
            let account_ref = definition.source_account_ref.expect("filtered above");
            for (name, tools) in &definition.operation_tools {
                if tools.contains("vaultmesh_ssh_tunnel_open") {
                    ssh_tunnel_actions
                        .entry(account_ref)
                        .or_default()
                        .push(json!({
                            "name": name,
                            "tools": ["vaultmesh_ssh_tunnel_open"],
                            "risk": definition.operation_risks.get(name)
                        }));
                }
            }
        }
        for actions in ssh_tunnel_actions.values_mut() {
            actions.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        }
        let candidate_tool_names = |candidate: &AgentVaultAccountCandidate| {
            candidate_tools(&candidate.kind)
                .iter()
                .copied()
                .filter(|tool| {
                    *tool != "vaultmesh_ssh_tunnel_open"
                        || ssh_tunnel_actions.contains_key(&candidate.account_ref)
                })
                .collect::<Vec<_>>()
        };
        candidates.retain(|candidate| {
            (kinds.is_empty() || kinds.contains(&candidate.kind))
                && query
                    .as_ref()
                    .is_none_or(|query| candidate.label.to_lowercase().contains(query))
                && (environments.is_empty() || environments.contains("default"))
                && (capabilities.is_empty()
                    || capabilities.iter().all(|capability| {
                        candidate_tool_names(candidate).iter().any(|tool| {
                            capability_by_tool.get(*tool).map(String::as_str)
                                == Some(capability.as_str())
                        })
                    }))
        });
        candidates.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.label.cmp(&right.label))
                .then_with(|| left.account_ref.cmp(&right.account_ref))
        });
        let mut entries = candidates
            .iter()
            .map(|candidate| {
                let mut advertised_capabilities = candidate_tool_names(candidate)
                    .iter()
                    .filter_map(|tool| capability_by_tool.get(*tool).cloned())
                    .collect::<Vec<_>>();
                advertised_capabilities.sort_unstable();
                advertised_capabilities.dedup();
                let actions = match candidate.kind.as_str() {
                    "secret" => json!([{
                        "name": "http",
                        "tools": ["vaultmesh_http_request"],
                        "risk": "method-dependent"
                    }]),
                    "ssh" => {
                        let mut actions = crate::agent_ssh_command_policy::SAFE_SSH_PROGRAMS
                            .iter()
                            .map(|program| {
                                json!({
                                    "name": program,
                                    "tools": ["vaultmesh_ssh_exec"],
                                    "risk": "R1"
                                })
                            })
                            .collect::<Vec<_>>();
                        actions.extend([
                            json!({
                                "name": "upload",
                                "tools": ["vaultmesh_local_file_select", "vaultmesh_ssh_upload"],
                                "risk": "R2"
                            }),
                            json!({
                                "name": "download",
                                "tools": ["vaultmesh_ssh_download", "vaultmesh_result_save"],
                                "risk": "R1"
                            }),
                            json!({
                                "name": "install-public-key",
                                "tools": ["vaultmesh_ssh_public_key_install"],
                                "risk": "R2"
                            }),
                            json!({
                                "name": "setup-openssh-host",
                                "tools": ["vaultmesh_ssh_host_setup"],
                                "risk": "R3"
                            }),
                            json!({
                                "name": "ssh-agent",
                                "tools": ["vaultmesh_ssh_agent_open", "vaultmesh_ssh_agent_close"],
                                "risk": "R1"
                            }),
                            json!({
                                "name": "pty",
                                "tools": [
                                    "vaultmesh_ssh_pty_open",
                                    "vaultmesh_ssh_pty_read",
                                    "vaultmesh_ssh_pty_write",
                                    "vaultmesh_ssh_pty_resize",
                                    "vaultmesh_ssh_pty_close"
                                ],
                                "risk": "R3"
                            }),
                        ]);
                        actions.extend(
                            ssh_tunnel_actions
                                .get(&candidate.account_ref)
                                .cloned()
                                .unwrap_or_default(),
                        );
                        Value::Array(actions)
                    }
                    _ => Value::Array(Vec::new()),
                };
                json!({
                    "accountRef": candidate.account_ref,
                    "label": candidate.label,
                    "kind": candidate.kind,
                    "environment": "default",
                    "capabilities": advertised_capabilities,
                    "actions": actions
                })
            })
            .collect::<Vec<_>>();
        entries.extend(api_environments.iter().filter_map(|candidate| {
            if (!kinds.is_empty() && !kinds.contains("api-environment"))
                || query
                    .as_ref()
                    .is_some_and(|query| !candidate.label.to_lowercase().contains(query))
                || (!environments.is_empty() && !environments.contains(&candidate.environment))
                || (!capabilities.is_empty()
                    && !capabilities
                        .iter()
                        .all(|capability| capability == &candidate.capability))
            {
                return None;
            }
            Some(json!({
                "accountRef": candidate.environment_ref,
                "environmentRef": candidate.environment_ref,
                "label": candidate.label,
                "kind": "api-environment",
                "environment": candidate.environment,
                "capabilities": [candidate.capability.clone()],
                "openapiUrl": candidate.openapi_url,
                "actions": []
            }))
        }));
        entries.extend(
            self.connector_definitions
                .values()
                .filter(|definition| {
                    definition.enabled
                        && definition.connector_kind != "ssh"
                        && !definition.operation_tools.is_empty()
                        && (kinds.is_empty() || kinds.contains(&definition.catalog_kind))
                        && query.as_ref().is_none_or(|query| {
                            definition.display_label.to_lowercase().contains(query)
                        })
                        && (environments.is_empty()
                            || environments.contains(&definition.environment))
                        && (capabilities.is_empty()
                            || capabilities.iter().all(|capability| {
                                definition.allowed_tools.iter().any(|tool| {
                                    capability_by_tool.get(tool.as_str()).map(String::as_str)
                                        == Some(capability.as_str())
                                })
                            }))
                })
                .map(|definition| {
                    let mut capabilities = definition
                        .allowed_tools
                        .iter()
                        .filter_map(|tool| capability_by_tool.get(tool.as_str()).cloned())
                        .collect::<Vec<_>>();
                    capabilities.sort();
                    capabilities.dedup();
                    let mut actions = definition
                        .operation_tools
                        .iter()
                        .filter(|(name, _)| !name.starts_with("__"))
                        .map(|(name, tools)| {
                            let mut tools = tools.iter().cloned().collect::<Vec<_>>();
                            tools.sort();
                            json!({
                                "name": name,
                                "tools": tools,
                                "risk": definition.operation_risks.get(name)
                            })
                        })
                        .collect::<Vec<_>>();
                    actions
                        .sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
                    json!({
                        "accountRef": definition.source_account_ref,
                        "label": definition.display_label,
                        "kind": definition.catalog_kind,
                        "environment": definition.environment,
                        "capabilities": capabilities,
                        "actions": actions
                    })
                }),
        );
        let mut account_refs = HashSet::new();
        if entries.iter().any(|entry| {
            entry
                .get("accountRef")
                .and_then(Value::as_str)
                .is_none_or(|account_ref| !account_refs.insert(account_ref.to_owned()))
        }) {
            return Err(AgentBrokerError::new(
                "invalid-account-catalog",
                "The account catalog contains an ambiguous reference.",
                false,
            ));
        }
        entries.sort_by(|left, right| {
            left["kind"]
                .as_str()
                .cmp(&right["kind"].as_str())
                .then_with(|| left["label"].as_str().cmp(&right["label"].as_str()))
                .then_with(|| {
                    left["accountRef"]
                        .as_str()
                        .cmp(&right["accountRef"].as_str())
                })
        });
        let mut catalog_digest = Sha256::new();
        catalog_digest.update(
            serde_json::to_vec(&json!({
                "query": query,
                "kinds": kinds,
                "capabilities": capabilities,
                "environments": environments
            }))
            .map_err(|_| AgentBrokerError::internal())?,
        );
        for entry in &entries {
            catalog_digest
                .update(serde_json::to_vec(entry).map_err(|_| AgentBrokerError::internal())?);
            catalog_digest.update([0]);
        }
        for candidate in &api_environments {
            catalog_digest.update(candidate.environment_ref.as_bytes());
            catalog_digest.update(candidate.revision.to_le_bytes());
            catalog_digest.update(candidate.policy_digest.as_bytes());
            catalog_digest.update([0]);
        }
        let catalog_digest = format!("{:x}", catalog_digest.finalize());
        let catalog_revision = &catalog_digest[..16];
        let offset = cursor
            .map(|cursor| {
                let mut parts = cursor.split(':');
                let version = parts.next();
                let revision = parts.next();
                let offset = parts.next().and_then(|value| value.parse::<usize>().ok());
                if version != Some("v2")
                    || revision != Some(catalog_revision)
                    || offset.is_none()
                    || parts.next().is_some()
                {
                    return Err(AgentBrokerError::new(
                        "invalid-cursor",
                        "The account page cursor is invalid or the account catalog changed.",
                        false,
                    ));
                }
                Ok(offset.unwrap_or_default())
            })
            .transpose()?
            .unwrap_or(0);
        if offset > entries.len() {
            return Err(AgentBrokerError::new(
                "invalid-cursor",
                "The account page cursor is no longer available.",
                false,
            ));
        }
        let end = offset.saturating_add(limit as usize).min(entries.len());
        let accounts = entries[offset..end].to_vec();
        Ok(json!({
            "accounts": accounts,
            "nextCursor": (end < entries.len())
                .then(|| format!("v2:{catalog_revision}:{end}")),
            "total": entries.len()
        }))
    }

    pub fn register_client(
        &mut self,
        peer: PeerIdentity,
        hello: ClientHello,
        now_millis: u64,
    ) -> Result<AgentClientSnapshot, AgentBrokerError> {
        self.prune(now_millis);
        if self.clients.len() >= MAX_CLIENTS
            || !valid_client_key(&hello.client_key)
            || peer.executable.len() > 4_096
            || peer.executable.chars().any(char::is_control)
            || !valid_sha256_identity(&peer.binary_identity)
        {
            return Err(AgentBrokerError::new(
                "invalid-client",
                "The local Agent client identity is invalid.",
                false,
            ));
        }
        let pairing_record = self.pairing_proofs.find(&AgentPairingIdentity {
            client_key: &hello.client_key,
            user_id: &peer.user_id,
        });
        let pairing_state = pairing_record
            .as_ref()
            .map_or(PairingState::Pending, |_| PairingState::Paired);
        let pairing_identity = AgentPairingIdentity {
            client_key: &hello.client_key,
            user_id: &peer.user_id,
        };
        let pairing_key = pairing_identity.pairing_ref();
        if pairing_state == PairingState::Pending
            && !self.pending_pairings.contains_key(&pairing_key)
            && self.pending_pairings.len() >= MAX_CLIENTS
        {
            return Err(AgentBrokerError::new(
                "too-many-pairing-requests",
                "Too many Agent pairing requests are pending.",
                true,
            ));
        }
        let client_id = Uuid::new_v4();
        if pairing_state == PairingState::Pending {
            self.pending_pairings
                .entry(pairing_key.clone())
                .and_modify(|pending| {
                    pending.peer = peer.clone();
                    pending.expires_at = now_millis.saturating_add(PAIRING_REQUEST_TTL_MILLIS);
                })
                .or_insert_with(|| PendingPairingRecord {
                    request_id: client_id,
                    client_key: hello.client_key.clone(),
                    peer: peer.clone(),
                    created_at: now_millis,
                    expires_at: now_millis.saturating_add(PAIRING_REQUEST_TTL_MILLIS),
                });
        } else {
            self.pending_pairings.remove(&pairing_key);
        }
        self.clients.insert(
            client_id,
            AgentClientRecord {
                client_id,
                client_key: hello.client_key,
                peer,
                pairing_ref: pairing_record.map(|record| record.pairing_ref),
                pairing_state,
                connected_at: now_millis,
            },
        );
        if pairing_state == PairingState::Paired {
            self.ensure_connection_session(client_id, now_millis)?;
        }
        if let Some(register) = self.access_register.as_ref() {
            register(client_id, pairing_key);
        }
        self.client_snapshot(client_id)
            .ok_or_else(AgentBrokerError::internal)
    }

    #[cfg(test)]
    pub fn approve_pairing(
        &mut self,
        client_id: &str,
    ) -> Result<AgentClientSnapshot, AgentBrokerError> {
        let connected_at = parse_opaque_id(client_id, "unknown-client")
            .ok()
            .and_then(|id| self.clients.get(&id).map(|client| client.connected_at))
            .unwrap_or(0);
        self.approve_pairing_at(client_id, connected_at)
    }

    #[cfg(test)]
    pub fn approve_pairing_at(
        &mut self,
        client_id: &str,
        now_millis: u64,
    ) -> Result<AgentClientSnapshot, AgentBrokerError> {
        self.prune(now_millis);
        let client_id = parse_opaque_id(client_id, "unknown-client")?;
        let client = self.clients.get(&client_id).ok_or_else(|| {
            AgentBrokerError::new(
                "unknown-client",
                "The Agent client is not connected.",
                false,
            )
        })?;
        let client_key = client.client_key.clone();
        let user_id = client.peer.user_id.clone();
        self.approve_pairing_identity_at(&client_key, &user_id, now_millis)?;
        self.client_snapshot(client_id)
            .ok_or_else(AgentBrokerError::internal)
    }

    pub fn pending_pairing_request(
        &mut self,
        now_millis: u64,
    ) -> Option<AgentPairingRequestSnapshot> {
        self.prune(now_millis);
        self.pending_pairings
            .values()
            .max_by_key(|pending| pending.created_at)
            .map(|pending| AgentPairingRequestSnapshot {
                client_id: pending.request_id.to_string(),
                client_key: pending.client_key.clone(),
                connected_at: pending.created_at,
            })
    }

    pub fn approve_pairing_request_at(
        &mut self,
        request_id: &str,
        now_millis: u64,
    ) -> Result<(), AgentBrokerError> {
        self.prune(now_millis);
        let request_id = parse_opaque_id(request_id, "unknown-pairing-request")?;
        let pending = self
            .pending_pairings
            .values()
            .find(|pending| pending.request_id == request_id)
            .cloned()
            .ok_or_else(|| {
                AgentBrokerError::new(
                    "unknown-pairing-request",
                    "The Agent pairing request is no longer available.",
                    true,
                )
            })?;
        self.approve_pairing_identity_at(&pending.client_key, &pending.peer.user_id, now_millis)?;
        Ok(())
    }

    pub fn reject_pairing_request(&mut self, request_id: &str) -> Result<(), AgentBrokerError> {
        let request_id = parse_opaque_id(request_id, "unknown-pairing-request")?;
        let pairing_key = self
            .pending_pairings
            .iter()
            .find_map(|(pairing_key, pending)| {
                (pending.request_id == request_id).then(|| pairing_key.clone())
            })
            .ok_or_else(|| {
                AgentBrokerError::new(
                    "unknown-pairing-request",
                    "The Agent pairing request is no longer available.",
                    true,
                )
            })?;
        let pending = self
            .pending_pairings
            .remove(&pairing_key)
            .ok_or_else(AgentBrokerError::internal)?;
        let matching_clients = self.matching_client_ids(&pending.client_key, &pending.peer.user_id);
        for client_id in matching_clients {
            self.disconnect(client_id);
        }
        Ok(())
    }

    fn approve_pairing_identity_at(
        &mut self,
        client_key: &str,
        user_id: &str,
        now_millis: u64,
    ) -> Result<(), AgentBrokerError> {
        let pairing_identity = AgentPairingIdentity {
            client_key,
            user_id,
        };
        let matching_clients = self.matching_client_ids(client_key, user_id);
        let pairing_record = match self.pairing_proofs.approve(&pairing_identity) {
            Ok(record) => Some(record),
            Err(_) => {
                return Err(AgentBrokerError::new(
                    "pairing-storage-unavailable",
                    "The Agent pairing approval could not be saved.",
                    true,
                ));
            }
        };
        self.pending_pairings
            .remove(&pairing_identity.pairing_ref());
        for matching_id in &matching_clients {
            if let Some(candidate) = self.clients.get_mut(matching_id) {
                candidate.pairing_state = PairingState::Paired;
                candidate.pairing_ref = pairing_record
                    .as_ref()
                    .map(|record| record.pairing_ref.clone());
            }
        }
        for matching_id in matching_clients {
            self.ensure_connection_session(matching_id, now_millis)?;
        }
        Ok(())
    }

    fn matching_client_ids(&self, client_key: &str, user_id: &str) -> Vec<Uuid> {
        self.clients
            .iter()
            .filter_map(|(candidate_id, candidate)| {
                (candidate.client_key == client_key && candidate.peer.user_id == user_id)
                    .then_some(*candidate_id)
            })
            .collect()
    }

    pub(super) fn ensure_connection_session(
        &mut self,
        client_id: Uuid,
        now_millis: u64,
    ) -> Result<(), AgentBrokerError> {
        if self
            .sessions
            .values()
            .any(|session| session.client_id == client_id && session.connection_managed)
        {
            return Ok(());
        }
        if !self.clients.contains_key(&client_id) {
            return Err(AgentBrokerError::new(
                "unknown-client",
                "The Agent client is not connected.",
                false,
            ));
        }
        let allowed_tools = self
            .registry
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<HashSet<_>>();
        let allowed_accounts = self
            .transport_permission_grants
            .get(&client_id)
            .into_iter()
            .flatten()
            .filter(|grant| grant.effect == PermissionEffect::Allow)
            .map(|grant| grant.account_ref.clone())
            .collect::<HashSet<_>>();
        let session_id = Uuid::new_v4();
        self.sessions.insert(
            session_id,
            ConnectionSession {
                session_id,
                client_id,
                allowed_tools,
                allowed_accounts,
                issued_at: now_millis,
                expires_at: now_millis.saturating_add(MAX_SESSION_MILLIS),
                request_limit: SESSION_REQUEST_LIMIT,
                requests_used: 0,
                cancellation: Arc::new(AtomicBool::new(false)),
                output_bytes_used: Arc::new(AtomicU64::new(0)),
                connection_managed: true,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn issue_session(
        &mut self,
        client_id: &str,
        allowed_tools: Vec<String>,
        allowed_accounts: Vec<String>,
        ttl_millis: u64,
        request_limit: u32,
        now_millis: u64,
    ) -> Result<ConnectionSessionSnapshot, AgentBrokerError> {
        self.prune(now_millis);
        let client_id = parse_opaque_id(client_id, "unknown-client")?;
        let client = self.clients.get(&client_id).ok_or_else(|| {
            AgentBrokerError::new(
                "unknown-client",
                "The Agent client is not connected.",
                false,
            )
        })?;
        if client.pairing_state != PairingState::Paired {
            return Err(AgentBrokerError::native(
                "pairing-required",
                "approve-pairing",
            ));
        }
        let direct_accounts = if self.account_catalog.is_some() {
            self.refresh_account_catalog()?
                .into_iter()
                .map(|candidate| candidate.account_ref.to_string())
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        if ttl_millis == 0
            || ttl_millis > MAX_SESSION_MILLIS
            || !(1..=10_000).contains(&request_limit)
            || allowed_tools.is_empty()
            || allowed_tools.len() > self.registry.tools.len()
            || allowed_accounts.len() > 256
            || allowed_accounts.iter().any(|account| {
                Uuid::parse_str(account).is_err()
                    || (!self
                        .connector_definitions
                        .get(account)
                        .is_some_and(|definition| definition.enabled)
                        && !direct_accounts.contains(account))
            })
        {
            return Err(AgentBrokerError::new(
                "invalid-session",
                "The requested connection session is invalid.",
                false,
            ));
        }
        let known_tools: HashSet<&str> = self
            .registry
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        if allowed_tools
            .iter()
            .any(|tool| !known_tools.contains(tool.as_str()))
        {
            return Err(AgentBrokerError::new(
                "capability-denied",
                "The requested capability is not approved for this client.",
                false,
            ));
        }
        let session_id = Uuid::new_v4();
        self.sessions.insert(
            session_id,
            ConnectionSession {
                session_id,
                client_id,
                allowed_tools: allowed_tools.into_iter().collect(),
                allowed_accounts: allowed_accounts.into_iter().collect(),
                issued_at: now_millis,
                expires_at: now_millis.saturating_add(ttl_millis),
                request_limit,
                requests_used: 0,
                cancellation: Arc::new(AtomicBool::new(false)),
                output_bytes_used: Arc::new(AtomicU64::new(0)),
                connection_managed: false,
            },
        );
        self.session_snapshot(session_id)
            .ok_or_else(AgentBrokerError::internal)
    }

    pub fn sync_connector_definitions(
        &mut self,
        connector_definitions: Vec<AgentConnectorDefinition>,
    ) -> Result<(), AgentBrokerError> {
        let mut next = HashMap::new();
        for definition in connector_definitions {
            let connector_kind = serde_json::to_value(definition.connector_kind)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(AgentBrokerError::internal)?;
            let target = serde_json::to_value(&definition.target_policy)
                .map_err(|_| AgentBrokerError::internal())?;
            let mut operation_risks = HashMap::new();
            let mut operation_tools: HashMap<String, HashSet<String>> = HashMap::new();
            for field in ["tunnelPolicies", "recipes"] {
                for operation in target
                    .get(field)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let (Some(name), Some(risk)) = (
                        operation.get("name").and_then(Value::as_str),
                        operation.get("risk").and_then(Value::as_str),
                    ) {
                        operation_risks.insert(name.to_owned(), risk.to_owned());
                        for tool in tools_for_named_operation(field, operation) {
                            let tools = operation_tools.entry(name.to_owned()).or_default();
                            tools.insert(tool.to_owned());
                            if tool == "vaultmesh_web_download" {
                                tools.insert("vaultmesh_result_save".to_owned());
                            }
                        }
                        if field == "recipes"
                            && operation.get("kind").and_then(Value::as_str) == Some("login")
                        {
                            operation_risks
                                .insert("__managed_web_login__".to_owned(), risk.to_owned());
                            operation_tools
                                .entry("__managed_web_login__".to_owned())
                                .or_default()
                                .insert("vaultmesh_web_session_open".to_owned());
                        }
                    }
                }
            }
            let definition_id = definition.id;
            let source_account_ref = definition
                .credential_refs
                .first()
                .map(|credential| credential.item_id);
            let catalog_kind = definition
                .credential_refs
                .first()
                .and_then(|credential| serde_json::to_value(credential.kind).ok())
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(AgentBrokerError::internal)?;
            let mut allowed_tools = definition
                .capability_policy
                .allowed_tools
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            if allowed_tools.contains("vaultmesh_web_download") {
                allowed_tools.insert("vaultmesh_result_save".to_owned());
            }
            if allowed_tools.contains("vaultmesh_passkey_request_begin") {
                allowed_tools.insert("vaultmesh_passkey_perform".to_owned());
            }
            for tools in operation_tools.values_mut() {
                tools.retain(|tool| allowed_tools.contains(tool));
            }
            operation_tools.retain(|_, tools| !tools.is_empty());
            let source_account_ref = source_account_ref.ok_or_else(AgentBrokerError::internal)?;
            if next
                .insert(
                    source_account_ref.to_string(),
                    AgentAccountPolicy {
                        definition_id,
                        source_account_ref: Some(source_account_ref),
                        display_label: definition.display_label.clone(),
                        environment: definition.environment.clone(),
                        connector_kind,
                        catalog_kind,
                        allowed_tools,
                        enabled: definition.enabled,
                        operation_risks,
                        operation_tools,
                    },
                )
                .is_some()
            {
                return Err(AgentBrokerError::new(
                    "connector-definition-conflict",
                    "More than one internal connector definition targets the same Vault account.",
                    false,
                ));
            }
        }
        self.connector_definitions = next;
        let enabled_accounts = self
            .connector_definitions
            .iter()
            .filter_map(|(account_ref, definition)| {
                definition.enabled.then_some(account_ref.clone())
            })
            .collect::<HashSet<_>>();
        for session in self
            .sessions
            .values_mut()
            .filter(|session| session.connection_managed)
        {
            session.allowed_accounts.retain(|account_ref| {
                self.connector_definitions
                    .get(account_ref)
                    .is_none_or(|definition| definition.enabled)
            });
            session
                .allowed_accounts
                .extend(enabled_accounts.iter().cloned());
            session.allowed_tools = self
                .registry
                .tools
                .iter()
                .map(|tool| tool.name.clone())
                .collect::<HashSet<_>>();
        }
        for grants in self.transport_permission_grants.values_mut() {
            grants.retain(|grant| {
                self.connector_definitions
                    .get(&grant.account_ref)
                    .is_none_or(|definition| {
                        definition.enabled
                            && (definition.allowed_tools.contains(&grant.tool)
                                || candidate_accepts_tool(&definition.catalog_kind, &grant.tool))
                    })
            });
        }
        let invalid_sessions = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                if session.connection_managed {
                    return None;
                }
                let keep = session.allowed_accounts.iter().all(|account| {
                    self.connector_definitions
                        .get(account)
                        .is_none_or(|definition| definition.enabled)
                });
                (!keep).then_some(*session_id)
            })
            .collect::<Vec<_>>();
        for session_id in invalid_sessions {
            if let Some(session) = self.sessions.remove(&session_id) {
                session.cancellation.store(true, Ordering::Release);
                self.cleanup_resources(AgentCleanupScope::Session(session_id));
            }
        }
        Ok(())
    }
}
