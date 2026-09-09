//! Shared Rust runtime for the Tauri desktop process.

mod browser_ops;
mod privileged;
mod runtime;
mod status;
mod storage;
pub mod sync_relay;
mod vault;

pub use privileged::{
    VAULTMESH_PROTECTED_FIELD_CARD_NUMBER, VAULTMESH_PROTECTED_FIELD_CARD_PIN,
    VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE, VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD,
    VAULTMESH_PROTECTED_FIELD_LOGIN_TOTP, VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
    VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE, VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
    VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY, VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
};
pub use runtime::{
    DesktopRuntime, DesktopRuntimeError, DesktopRuntimeStatus, ManagedSshHostKeyMaterial,
};
pub use status::{
    VAULTMESH_STATUS_AUTH_FAILED, VAULTMESH_STATUS_CONFLICT, VAULTMESH_STATUS_CORE_ERROR,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_IO_ERROR, VAULTMESH_STATUS_LOCKED,
    VAULTMESH_STATUS_NOT_FOUND, VAULTMESH_STATUS_OK, VAULTMESH_STATUS_REAUTH_REQUIRED,
    VAULTMESH_STATUS_VALUE_UNAVAILABLE, VAULTMESH_STATUS_VAULT_EXISTS, VaultmeshStatus,
};
pub(crate) use vault::VaultmeshVault;
pub use vaultmesh_core::{
    AgentAuditConfirmation, AgentAuditDecision, AgentAuditEvent, AgentAuditResultClass,
    AgentCapabilityPolicy, AgentConnectorDefinition, AgentConnectorDefinitionSummary,
    AgentConnectorKind, AgentCredentialKind, AgentCredentialRef, AgentHttpAuthStrategy,
    AgentHttpBodyMode, AgentHttpOperationPolicy, AgentOutputPolicy, AgentRiskTier,
    AgentSshTunnelPolicy, AgentTargetPolicy, AgentWebFieldPolicy, AgentWebFieldSource,
    AgentWebInputPolicy, AgentWebRecipeKind, AgentWebRecipePolicy, ApiKeyLocation,
    ApiRequestAuthenticationMaterial, ApiRequestBodyInput, ApiRequestExecutionPlan,
    ApiRequestInput, ApiRequestPair, ApiRequestPlanSummary, ApiRequestValueMaterial,
    NewAgentAuditEvent, NewAgentConnectorDefinition, SYNC_MAX_BYTES, SYNC_MAX_RECORDS, SyncEntry,
    SyncManifest, SyncRecord, SyncState, SyncVersion, validate_agent_audit,
};

pub const VAULTMESH_ITEM_KIND_LOGIN: u32 = 1;
pub const VAULTMESH_ITEM_KIND_PAYMENT_CARD: u32 = 2;
pub const VAULTMESH_ITEM_KIND_IDENTITY: u32 = 3;
pub const VAULTMESH_ITEM_KIND_SSH_CREDENTIAL: u32 = 4;
pub const VAULTMESH_ITEM_KIND_SECRET: u32 = 5;

pub use vaultmesh_core::{SyncChannel, SyncPacket, SyncRoute};
