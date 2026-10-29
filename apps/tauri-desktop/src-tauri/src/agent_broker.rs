use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

#[cfg(unix)]
use std::{
    fs,
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixListener,
        net::UnixStream,
    },
    path::{Path, PathBuf},
    thread::{self, JoinHandle},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vaultmesh_ffi::{
    AgentAuditConfirmation, AgentAuditDecision, AgentAuditResultClass, AgentConnectorDefinition,
    AgentRiskTier, NewAgentAuditEvent,
};

use crate::agent_authorization_store::{
    AgentAuthorizationMatch, AgentAuthorizationRule, AgentAuthorizationStore,
};
use crate::agent_pairing::{AgentPairingIdentity, AgentPairingProofs, valid_client_key};

#[path = "agent_broker_accounts.rs"]
mod agent_broker_accounts;
#[path = "agent_broker_dispatch.rs"]
mod agent_broker_dispatch;
#[path = "agent_broker_execution.rs"]
mod agent_broker_execution;
#[path = "agent_broker_lifecycle.rs"]
mod agent_broker_lifecycle;
#[path = "agent_broker_permissions.rs"]
mod agent_broker_permissions;
#[path = "agent_broker_policy.rs"]
mod agent_broker_policy;
#[cfg(unix)]
#[path = "agent_broker_transport.rs"]
mod agent_broker_transport;
#[path = "agent_broker_unlock.rs"]
mod agent_broker_unlock;

#[cfg(target_os = "windows")]
pub(crate) use agent_broker_execution::wait_for_native_authorization;
pub(crate) use agent_broker_execution::{
    attach_persisted_audit, complete_native_ui_action, execute_authorized_action,
};
pub(crate) use agent_broker_policy::canonical_parameters_digest;
use agent_broker_policy::*;
#[cfg(unix)]
pub use agent_broker_transport::AgentBrokerUnixListener;
#[cfg(all(test, unix))]
use agent_broker_transport::unix_millis;

const PROTOCOL_VERSION: u32 = 2;
const MAX_REQUEST_BYTES: usize = 384 * 1024;
const MAX_SESSION_MILLIS: u64 = 15 * 60_000;
const MAX_CLIENTS: usize = 32;
const MAX_CONNECTIONS: usize = 32;
const MAX_SEEN_REQUESTS: usize = 4_096;
const MAX_SESSION_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_FRAME_DURATION: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const AUTHORIZATION_TTL_MILLIS: u64 = 30_000;
const CONFIRMATION_TTL_MILLIS: u64 = AUTHORIZATION_TTL_MILLIS;
const PERMISSION_TTL_MILLIS: u64 = MAX_SESSION_MILLIS;
const PAIRING_REQUEST_TTL_MILLIS: u64 = 10 * 60_000;
const SESSION_REQUEST_LIMIT: u32 = 1_000;
const SESSION_BASE_TOOLS: [&str; 5] = [
    "vaultmesh_accounts_list",
    "vaultmesh_items_list_metadata",
    "vaultmesh_item_get_metadata",
    "vaultmesh_request_local_ui",
    "vaultmesh_ssh_agent_close",
];
#[cfg(unix)]
const MAX_IPC_LINE_BYTES: usize = 384 * 1024;

pub(crate) fn direct_action_operation<'a>(tool: &str, parameters: &'a Value) -> Option<&'a str> {
    request_permission_operation(tool, parameters)
}

pub type AgentAuditSink = Arc<dyn Fn(NewAgentAuditEvent) -> Result<String, ()> + Send + Sync>;
pub type AgentResourceCleanup = Arc<dyn Fn(AgentCleanupScope) + Send + Sync>;
pub type AgentAccessCheck = Arc<dyn Fn(Uuid) -> bool + Send + Sync>;
pub type AgentAccessSharesUnlock = Arc<dyn Fn(Uuid, Uuid) -> bool + Send + Sync>;
pub type AgentAccessLock = Arc<dyn Fn(Uuid) -> Vec<Uuid> + Send + Sync>;
pub type AgentAccessRegister = Arc<dyn Fn(Uuid, String) + Send + Sync>;
pub type AgentAccessDisconnect = Arc<dyn Fn(Uuid) + Send + Sync>;
pub type AgentAccountCatalog =
    Arc<dyn Fn() -> Result<AgentAccountCatalogSnapshot, AgentBrokerError> + Send + Sync>;
pub type AgentApiEnvironmentCatalog =
    Arc<dyn Fn() -> Result<Vec<AgentApiEnvironmentCandidate>, AgentBrokerError> + Send + Sync>;
pub type AgentDirectSshPolicyFactory =
    Arc<dyn Fn(Uuid, &str, &Value) -> Result<AgentDirectSshPolicy, AgentBrokerError> + Send + Sync>;
pub type AgentDirectHttpPolicyFactory = Arc<
    dyn Fn(Uuid, &str, &str, &Value) -> Result<AgentDirectHttpPolicy, AgentBrokerError>
        + Send
        + Sync,
>;
pub type AgentDirectConnectorPolicyFactory = Arc<
    dyn Fn(Uuid, &str, &Value) -> Result<AgentDirectConnectorPolicy, AgentBrokerError>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct AgentDirectSshPolicy {
    pub account_ref: Uuid,
    pub account_label: String,
    pub environment: String,
    pub tool: String,
    pub risk: String,
    pub action_display: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub target_digest: String,
    pub approved_display: String,
    pub max_output_bytes: usize,
    pub remote_path_prefixes: Vec<String>,
    pub connector_ref: Option<Uuid>,
    pub tunnel: Option<vaultmesh_ffi::AgentSshTunnelPolicy>,
}

#[derive(Clone, Debug)]
pub struct AgentDirectHttpPolicy {
    pub account_ref: Uuid,
    pub account_label: String,
    pub environment: String,
    pub item_kind: String,
    pub credential_kind: vaultmesh_ffi::AgentCredentialKind,
    pub origin: String,
    pub auth_strategy: vaultmesh_ffi::AgentHttpAuthStrategy,
    pub operation: vaultmesh_ffi::AgentHttpOperationPolicy,
    pub target_digest: String,
    pub approved_display: String,
    pub allowed_output_fields: Vec<String>,
    pub max_output_bytes: usize,
    pub max_output_items: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDirectConnectorPolicy {
    pub connector_ref: Uuid,
    pub account_ref: Uuid,
    pub account_label: String,
    pub environment: String,
    pub connector_kind: String,
    pub tool: String,
    pub operation: Option<String>,
    pub risk: String,
    pub action_display: String,
    pub approved_display: String,
    pub target_digest: String,
}
pub type AgentToolExecutor = Arc<
    dyn Fn(
            &str,
            Option<&str>,
            &Value,
            &AtomicBool,
            &AgentExecutionScope,
        ) -> Result<Value, AgentBrokerError>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct AgentAccountCatalogSnapshot {
    pub connector_definitions: Vec<AgentConnectorDefinition>,
    pub candidates: Vec<AgentVaultAccountCandidate>,
}

#[derive(Clone, Debug)]
pub struct AgentVaultAccountCandidate {
    pub account_ref: Uuid,
    pub kind: String,
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct AgentApiEnvironmentCandidate {
    pub environment_ref: Uuid,
    pub label: String,
    pub environment: String,
    pub capability: String,
    pub openapi_url: Option<String>,
    pub revision: u64,
    pub policy_digest: String,
}

#[derive(Clone, Debug)]
pub struct AgentExecutionScope {
    pub client_id: Uuid,
    pub session_id: Uuid,
    pub cancellation: Arc<AtomicBool>,
    pub direct_ssh_policy: Option<AgentDirectSshPolicy>,
    pub direct_http_policy: Option<AgentDirectHttpPolicy>,
    pub direct_connector_policy: Option<AgentDirectConnectorPolicy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCleanupScope {
    Client(Uuid),
    Session(Uuid),
    All,
}

#[derive(Clone, Debug)]
pub struct AuthorizedAgentAction {
    tool: String,
    account_ref: Option<String>,
    parameters: Value,
    scope: AgentExecutionScope,
    cancellation: Arc<AtomicBool>,
    output_bytes_used: Arc<AtomicU64>,
    remaining_session_millis: u64,
    authorized_at: Instant,
}

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRegistry {
    pub protocol_version: u32,
    pub tools: Vec<AgentToolDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentToolDefinition {
    pub name: String,
    pub version: u32,
    pub capability: String,
    pub risk: String,
    pub requires_account: bool,
    pub confirmation: String,
    #[serde(default)]
    pub deprecated: bool,
    pub parameters: Vec<AgentToolParameter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentToolParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub parameter_type: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

pub fn capability_registry() -> Result<AgentRegistry, AgentBrokerError> {
    let registry: AgentRegistry =
        serde_json::from_str(include_str!("../../src/shared/agent-capabilities.json"))
            .map_err(|_| AgentBrokerError::internal())?;
    validate_registry(&registry)?;
    Ok(registry)
}

fn validate_registry(registry: &AgentRegistry) -> Result<(), AgentBrokerError> {
    if registry.protocol_version != PROTOCOL_VERSION || registry.tools.is_empty() {
        return Err(AgentBrokerError::internal());
    }
    let mut names = HashSet::new();
    for tool in &registry.tools {
        if !(1..=3).contains(&tool.version)
            || !tool.name.starts_with("vaultmesh_")
            || !names.insert(tool.name.as_str())
            || tool.name.contains("get_password")
            || tool.name.contains("export_secret")
            || tool.name.contains("dump_vault")
        {
            return Err(AgentBrokerError::internal());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerIdentity {
    pub user_id: String,
    pub process_id: u32,
    pub executable: String,
    pub binary_identity: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHello {
    #[serde(alias = "kind")]
    pub client_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairingState {
    Pending,
    Paired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AgentNativeUiSurface {
    Pairing,
    Unlock,
    UnlockExpired(String),
    Authorization,
    AuthorizationExpired(String),
    LocalUi,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClientSnapshot {
    pub client_id: String,
    pub client_key: String,
    pub pairing_state: PairingState,
    pub connected_at: u64,
    pub active_session_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClientActivitySnapshot {
    pub client_id: String,
    pub process_id: u32,
    pub connected_at: u64,
    pub active_session_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClientAdminSnapshot {
    pub client_id: String,
    pub client_key: String,
    pub pairing_state: PairingState,
    pub active_session_count: usize,
    pub activities: Vec<AgentClientActivitySnapshot>,
}

#[derive(Clone, Debug)]
struct AgentClientRecord {
    client_id: Uuid,
    client_key: String,
    peer: PeerIdentity,
    pairing_ref: Option<String>,
    pairing_state: PairingState,
    connected_at: u64,
}

#[derive(Clone, Debug)]
struct PendingPairingRecord {
    request_id: Uuid,
    client_key: String,
    peer: PeerIdentity,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct PendingUnlockRecord {
    unlock_ref: Uuid,
    client_id: Uuid,
    client_ids: HashSet<Uuid>,
    client_key: String,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUnlockRequestSnapshot {
    pub unlock_ref: String,
    pub client_id: String,
    pub client_key: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentUnlockWaitOutcome {
    Pending,
    Allowed,
    Denied,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPairingRequestSnapshot {
    pub client_id: String,
    pub client_key: String,
    pub connected_at: u64,
}

#[derive(Clone, Debug)]
struct ConnectionSession {
    session_id: Uuid,
    client_id: Uuid,
    allowed_tools: HashSet<String>,
    allowed_accounts: HashSet<String>,
    issued_at: u64,
    expires_at: u64,
    request_limit: u32,
    requests_used: u32,
    cancellation: Arc<AtomicBool>,
    output_bytes_used: Arc<AtomicU64>,
    connection_managed: bool,
}

#[derive(Clone, Debug)]
struct PermissionGrant {
    account_ref: String,
    tool: String,
    operation: Option<String>,
    scope: PermissionScope,
    parameters_digest: Option<String>,
    catalog_revision: Option<String>,
    effect: PermissionEffect,
    fresh_confirmation_required: bool,
    remaining_uses: Option<u32>,
}

struct PermissionGrantInput<'a> {
    account_ref: &'a str,
    tool: &'a str,
    operation: Option<&'a str>,
    scope: PermissionScope,
    parameters_digest: Option<&'a str>,
    catalog_revision: Option<&'a str>,
    effect: PermissionEffect,
    fresh_confirmation_required: bool,
    remaining_uses: Option<u32>,
}

#[derive(Clone, Debug)]
struct AgentAccountPolicy {
    definition_id: Uuid,
    source_account_ref: Option<Uuid>,
    display_label: String,
    environment: String,
    connector_kind: String,
    catalog_kind: String,
    allowed_tools: HashSet<String>,
    enabled: bool,
    operation_risks: HashMap<String, String>,
    operation_tools: HashMap<String, HashSet<String>>,
}

#[derive(Clone, Debug)]
struct PendingPermission {
    permission_ref: Uuid,
    client_id: Uuid,
    session_id: Uuid,
    account_ref: String,
    account_label: String,
    environment: String,
    tool: String,
    operation: Option<String>,
    parameters_digest: Option<String>,
    risk: String,
    approved_display: String,
    action_display: String,
    target_digest: String,
    source_item_ref: Option<Uuid>,
    source_item_kind: Option<String>,
    activation_required: bool,
    direct_ssh_policy: Option<AgentDirectSshPolicy>,
    direct_http_policy: Option<AgentDirectHttpPolicy>,
    direct_connector_policy: Option<AgentDirectConnectorPolicy>,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermissionWaitOutcome {
    Pending,
    Allowed,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug)]
struct ResolvedPermissionOutcome {
    allowed: bool,
    expires_at: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionDecision {
    AllowOnce,
    #[serde(alias = "allow-task")]
    AllowSession,
    AlwaysAllow,
    DenyOnce,
    AlwaysDeny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionScope {
    Exact,
    Path,
    Safe,
    All,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionDuration {
    Once,
    #[serde(alias = "session")]
    Connection,
    Permanent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionChoice {
    pub effect: PermissionEffect,
    pub scope: PermissionScope,
    pub duration: PermissionDuration,
    #[serde(default)]
    pub path_pattern: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestSnapshot {
    pub permission_ref: String,
    pub client_id: String,
    pub session_id: String,
    pub account_ref: String,
    pub account_label: String,
    pub environment: String,
    pub tool: String,
    pub operation: Option<String>,
    pub risk: String,
    pub approved_display: String,
    pub action_display: String,
    pub source_item_ref: Option<String>,
    pub source_item_kind: Option<String>,
    pub activation_required: bool,
    pub available_scopes: Vec<PermissionScope>,
    pub available_path_patterns: Vec<String>,
    pub available_allow_durations: Vec<PermissionDuration>,
    pub available_deny_durations: Vec<PermissionDuration>,
    pub recommended_scope: PermissionScope,
    pub recommended_duration: PermissionDuration,
    pub fresh_confirmation_required: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationRuleSnapshot {
    pub id: String,
    pub client_key: String,
    pub account_ref: String,
    pub tool: String,
    pub scope: PermissionScope,
    pub effect: PermissionEffect,
    pub http_method: Option<String>,
    pub path_pattern: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug)]
pub struct PermissionResolution {
    pub request: PermissionRequestSnapshot,
    pub choice: PermissionChoice,
}

#[derive(Clone, Debug)]
struct PendingConfirmation {
    confirmation_ref: Uuid,
    client_id: Uuid,
    session_id: Uuid,
    account_ref: Option<String>,
    account_label: Option<String>,
    tool: String,
    risk: String,
    action_digest: String,
    created_at: u64,
    expires_at: u64,
    approved: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationSnapshot {
    pub confirmation_ref: String,
    pub client_id: String,
    pub session_id: String,
    pub account_ref: Option<String>,
    pub account_label: Option<String>,
    pub tool: String,
    pub risk: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub approved: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSessionSnapshot {
    pub session_id: String,
    pub client_id: String,
    pub allowed_tools: Vec<String>,
    pub allowed_accounts: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub request_limit: u32,
    pub requests_used: u32,
    pub output_byte_limit: u64,
    pub output_bytes_used: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionSnapshot {
    pub client: AgentClientSnapshot,
    pub session: Option<ConnectionSessionSnapshot>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentRequest {
    protocol_version: u32,
    request_id: Uuid,
    #[serde(default)]
    session_id: Uuid,
    #[serde(default)]
    account_ref: Option<String>,
    tool: String,
    tool_version: u32,
    #[serde(default)]
    parameters: Value,
    #[serde(default)]
    confirmation_ticket: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBrokerError {
    pub code: &'static str,
    pub message: &'static str,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_action_required: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl AgentBrokerError {
    pub(crate) fn new(code: &'static str, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
            native_action_required: None,
            confirmation_ref: None,
            details: None,
        }
    }

    fn native(code: &'static str, action: &'static str) -> Self {
        let message = match action {
            "approve-pairing" => "VaultMesh requires approval of this local MCP client pairing.",
            "unlock-agent" => "VaultMesh requires independent MCP access unlock in the local app.",
            "request-authorization" => {
                "VaultMesh requires authorization for this action in the local app."
            }
            "approve-confirmation" => {
                "VaultMesh requires confirmation for this action in the local app."
            }
            _ => "VaultMesh requires a local user action.",
        };
        Self {
            code,
            message,
            retryable: true,
            native_action_required: Some(action),
            confirmation_ref: None,
            details: None,
        }
    }

    fn confirmation(confirmation_ref: Uuid) -> Self {
        Self {
            code: "confirmation-required",
            message: "VaultMesh requires confirmation in the local app.",
            retryable: true,
            native_action_required: Some("approve-confirmation"),
            confirmation_ref: Some(confirmation_ref.to_string()),
            details: None,
        }
    }

    fn authorization(permission_ref: &str) -> Self {
        let mut error = Self::native("authorization-required", "request-authorization");
        error.details = Some(json!({ "authorizationRef": permission_ref }));
        error
    }

    fn agent_unlock(unlock_ref: Uuid) -> Self {
        let mut error = Self::native("mcp-locked", "unlock-agent");
        error.details = Some(json!({ "unlockRef": unlock_ref }));
        error
    }

    pub(crate) fn agent_unlock_timeout() -> Self {
        Self::new(
            "mcp-unlock-timeout",
            "The independent MCP unlock was not completed within 30 seconds.",
            true,
        )
    }

    pub(crate) fn authorization_denied() -> Self {
        Self::new(
            "authorization-denied",
            "The action was denied in the local authorization window.",
            false,
        )
    }

    pub(crate) fn authorization_timeout() -> Self {
        Self::new(
            "authorization-timeout",
            "The local authorization window expired after 30 seconds.",
            true,
        )
    }

    pub(crate) fn vault_locked() -> Self {
        Self::new(
            "vault-locked",
            "VaultMesh is locked; unlock it locally, then retry the same tool call.",
            true,
        )
    }

    pub(crate) fn internal() -> Self {
        Self::new(
            "broker-unavailable",
            "VaultMesh Agent broker is unavailable.",
            true,
        )
    }

    pub(crate) fn action_input_insufficient(missing_fields: Vec<String>) -> Self {
        let mut error = Self::new(
            "action-input-insufficient",
            "The account does not contain enough metadata for a direct action plan.",
            true,
        );
        error.details = Some(json!({
            "missingFields": missing_fields,
            "retryHint": "Update the Vault item, then retry the same action with the same accountRef.",
            "allowedSources": ["vault-item", "built-in-rule"]
        }));
        error
    }

    pub(crate) fn action_rule_unavailable(kind: &str, tool: &str) -> Self {
        let mut error = Self::new(
            "action-rule-unavailable",
            "VaultMesh has no direct action rule for this account and capability.",
            true,
        );
        error.details = Some(json!({
            "missingFields": [format!("builtInRule:{kind}:{tool}")],
            "retryHint": "Choose a capability published by vaultmesh_accounts_list, then call that action directly.",
            "allowedSources": ["vault-item", "built-in-rule"]
        }));
        error
    }

    pub(crate) fn action_target_unavailable() -> Self {
        let mut error = Self::new(
            "action-target-unavailable",
            "VaultMesh could not verify the target identity for this direct action.",
            true,
        );
        error.details = Some(json!({
            "retryHint": "Ensure the SSH endpoint saved in the Vault item is reachable, then retry the same SSH action.",
            "allowedSources": ["vault-item", "built-in-rule"]
        }));
        error
    }
}

pub struct AgentBrokerCore {
    registry: AgentRegistry,
    pairing_proofs: AgentPairingProofs,
    clients: HashMap<Uuid, AgentClientRecord>,
    pending_pairings: HashMap<String, PendingPairingRecord>,
    pending_unlocks: HashMap<Uuid, PendingUnlockRecord>,
    unlock_outcomes: HashMap<Uuid, ResolvedPermissionOutcome>,
    sessions: HashMap<Uuid, ConnectionSession>,
    seen_requests: HashSet<Uuid>,
    connector_definitions: HashMap<String, AgentAccountPolicy>,
    confirmations: HashMap<Uuid, PendingConfirmation>,
    permission_requests: HashMap<Uuid, PendingPermission>,
    permission_outcomes: HashMap<Uuid, ResolvedPermissionOutcome>,
    confirmation_outcomes: HashMap<Uuid, ResolvedPermissionOutcome>,
    audit_queue: Vec<NewAgentAuditEvent>,
    resource_cleanup: Option<AgentResourceCleanup>,
    access_check: Option<AgentAccessCheck>,
    access_shares_unlock: Option<AgentAccessSharesUnlock>,
    access_lock: Option<AgentAccessLock>,
    access_register: Option<AgentAccessRegister>,
    access_disconnect: Option<AgentAccessDisconnect>,
    account_catalog: Option<AgentAccountCatalog>,
    api_environment_catalog: Option<AgentApiEnvironmentCatalog>,
    direct_ssh_policy_factory: Option<AgentDirectSshPolicyFactory>,
    direct_http_policy_factory: Option<AgentDirectHttpPolicyFactory>,
    direct_connector_policy_factory: Option<AgentDirectConnectorPolicyFactory>,
    authorization_store: Option<AgentAuthorizationStore>,
    transport_permission_grants: HashMap<Uuid, Vec<PermissionGrant>>,
    active_direct_ssh_policies: HashMap<(Uuid, String, String, String), AgentDirectSshPolicy>,
    active_direct_http_policies: HashMap<(Uuid, String, String, String), AgentDirectHttpPolicy>,
    active_direct_connector_policies:
        HashMap<(Uuid, String, String, String), AgentDirectConnectorPolicy>,
}

impl Drop for AgentBrokerCore {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
#[path = "agent_broker_tests/mod.rs"]
mod tests;
