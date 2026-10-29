use super::*;

pub(super) struct AgentToolContext<'a> {
    pub(super) runtime: &'a Arc<Mutex<DesktopRuntime>>,
    pub(super) resources: &'a Arc<Mutex<AgentResourceStore>>,
    pub(super) managed_web: &'a Arc<Mutex<AgentManagedWebStore>>,
    pub(super) email_otp: &'a Arc<Mutex<EmailOtpService>>,
    pub(super) ssh_sessions: &'a Arc<Mutex<AgentSshSessionStore>>,
    pub(super) ssh_agent_registry: &'a Arc<Mutex<crate::agent_ssh_agent::SshAgentRegistry>>,
    pub(super) ssh_directory: &'a std::path::Path,
    pub(super) app: &'a AppHandle,
    pub(super) dialog_focus: &'a Arc<NativeDialogFocusState>,
}

include!("agent_tool_executor_local.inc.rs");
include!("agent_tool_executor_remote.inc.rs");

fn required_direct_ssh_policy<'a>(
    scope: &'a AgentExecutionScope,
    account_ref: &str,
    tool: &str,
) -> Result<&'a crate::agent_broker::AgentDirectSshPolicy, AgentBrokerError> {
    scope
        .direct_ssh_policy
        .as_ref()
        .filter(|policy| policy.account_ref.to_string() == account_ref && policy.tool == tool)
        .ok_or_else(|| {
            AgentBrokerError::new(
                "account-policy-denied",
                "The SSH action is missing its immutable direct plan.",
                false,
            )
        })
}

fn required_direct_http_policy<'a>(
    scope: &'a AgentExecutionScope,
    account_ref: &str,
    tool: &str,
) -> Result<&'a crate::agent_broker::AgentDirectHttpPolicy, AgentBrokerError> {
    scope
        .direct_http_policy
        .as_ref()
        .filter(|policy| policy.account_ref.to_string() == account_ref)
        .filter(|policy| policy.item_kind == "secret" && tool == "vaultmesh_http_request")
        .ok_or_else(|| {
            AgentBrokerError::new(
                "account-policy-denied",
                "The HTTP action is missing its immutable direct plan.",
                false,
            )
        })
}

fn required_direct_connector_ref(
    scope: &AgentExecutionScope,
    account_ref: &str,
    tool: &str,
) -> Result<uuid::Uuid, AgentBrokerError> {
    required_direct_connector_policy(scope, account_ref, tool, "managed-web")
        .map(|policy| policy.connector_ref)
}

fn validate_direct_connector_action(
    runtime: &Arc<Mutex<DesktopRuntime>>,
    scope: &AgentExecutionScope,
    account_ref: &str,
    tool: &str,
    connector_kind: &str,
    parameters: &Value,
) -> Result<(), AgentBrokerError> {
    let Some(policy) = scope.direct_connector_policy.as_ref() else {
        return Err(AgentBrokerError::new(
            "account-policy-denied",
            "The connector action is missing its immutable direct plan.",
            false,
        ));
    };
    if policy.account_ref.to_string() != account_ref
        || policy.tool != tool
        || policy.connector_kind != connector_kind
    {
        return Err(AgentBrokerError::new(
            "account-policy-denied",
            "The direct connector action does not match this account or tool.",
            false,
        ));
    }
    let mut runtime = runtime.lock().map_err(|_| AgentBrokerError::internal())?;
    validate_direct_agent_connector_policy(&mut runtime, policy, parameters).map_err(|_| {
        AgentBrokerError::new(
            "account-unavailable",
            "The approved connector changed before execution.",
            false,
        )
    })?;
    Ok(())
}

fn required_direct_connector_policy<'a>(
    scope: &'a AgentExecutionScope,
    account_ref: &str,
    tool: &str,
    connector_kind: &str,
) -> Result<&'a crate::agent_broker::AgentDirectConnectorPolicy, AgentBrokerError> {
    scope
        .direct_connector_policy
        .as_ref()
        .filter(|policy| {
            policy.account_ref.to_string() == account_ref
                && policy.tool == tool
                && policy.connector_kind == connector_kind
        })
        .ok_or_else(|| {
            AgentBrokerError::new(
                "account-policy-denied",
                "The protected action is missing its immutable connector plan.",
                false,
            )
        })
}

fn agent_string_parameter<'a>(
    parameters: &'a Value,
    name: &str,
) -> Result<&'a str, AgentBrokerError> {
    parameters
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| agent_ssh_session_error("invalid-parameters"))
}

fn required_agent_account(account_ref: Option<&str>) -> Result<&str, AgentBrokerError> {
    account_ref.ok_or_else(|| {
        AgentBrokerError::new(
            "account-required",
            "An approved account reference is required.",
            false,
        )
    })
}

fn agent_managed_web_error(code: &'static str) -> AgentBrokerError {
    AgentBrokerError::new(
        code,
        match code {
            "session-cancelled" => "The connection session was revoked or expired.",
            "invalid-parameters" => "The managed-web parameters are invalid.",
            "web-session-unavailable" => {
                "The managed-web session is unavailable for this connection and account."
            }
            "web-policy-denied" | "web-origin-denied" | "web-navigation-mismatch" => {
                "The managed-web definition does not allow this operation."
            }
            "web-secret-detected" => "The managed-web result contained protected material.",
            "web-session-quota-exceeded" | "web-session-busy" | "web-output-too-large" => {
                "The managed-web resource quota has been exceeded."
            }
            _ => "The approved managed-web operation failed safely.",
        },
        false,
    )
}

fn agent_ssh_session_error(code: &'static str) -> AgentBrokerError {
    AgentBrokerError::new(
        code,
        match code {
            "session-cancelled" => "The connection session was revoked or expired.",
            "invalid-parameters" => "The SSH PTY parameters are invalid.",
            "ssh-pty-session-unavailable" => {
                "The SSH PTY session is unavailable for this connection and account."
            }
            "ssh-pty-sequence-mismatch" => "The SSH PTY sequence does not match.",
            "ssh-pty-quota-exceeded" | "ssh-pty-output-quota-exceeded" => {
                "The SSH PTY quota has been exceeded."
            }
            _ => "The approved SSH PTY operation failed safely.",
        },
        false,
    )
}
