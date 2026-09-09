//! Portable cryptographic core for VaultMesh.
//!
//! Filesystem, UI, clipboard, platform key stores, sync, and networking remain
//! outside this crate. The public API is organized into focused modules and
//! re-exported here for platform clients.

mod agent_connector;
mod error;
mod format;
mod model;
mod session;
mod sync;
mod totp;
pub use sync::{
    SYNC_MAX_BYTES, SYNC_MAX_RECORDS, SyncAuthorization, SyncEntry, SyncManifest, SyncRecord,
    SyncState, SyncVersion,
};

pub use agent_connector::{
    AgentAuditConfirmation, AgentAuditDecision, AgentAuditEvent, AgentAuditResultClass,
    AgentCapabilityPolicy, AgentConnectorDefinition, AgentConnectorDefinitionHealth,
    AgentConnectorDefinitionSummary, AgentConnectorKind, AgentCredentialKind, AgentCredentialRef,
    AgentHttpAuthStrategy, AgentHttpBodyMode, AgentHttpOperationPolicy, AgentOutputPolicy,
    AgentRiskTier, AgentSshTunnelPolicy, AgentTargetPolicy, AgentWebFieldPolicy,
    AgentWebFieldSource, AgentWebInputPolicy, AgentWebRecipeKind, AgentWebRecipePolicy,
    NewAgentAuditEvent, NewAgentConnectorDefinition, validate_agent_audit,
    validate_agent_connector_definition,
};
pub use error::VaultError;
pub use format::{Argon2idParameters, VaultEnvelope, VaultHeader};
pub use model::{
    AgentApiEnvironmentSummary, ApiCredentialField, ApiCredentialItemKind, ApiCredentialRef,
    ApiEnvironmentAuth, ApiEnvironmentDetail, ApiEnvironmentKind, ApiEnvironmentRecord,
    ApiEnvironmentRevision, ApiEnvironmentRevisionSummary, ApiEnvironmentSummary,
    ApiEnvironmentTrashSummary, ApiEnvironmentUpdate, ApiFixedHeader, ApiHeaderSource,
    ApiKeyLocation, ApiRequestAuthenticationMaterial, ApiRequestBodyInput, ApiRequestExecutionPlan,
    ApiRequestInput, ApiRequestPair, ApiRequestPlanSummary, ApiRequestValueMaterial,
    EmailAccountRecord, EmailAccountRecordSummary, EmailAccountRecordUpdate, FillEvent,
    FillItemKind, IdentityDetail, IdentityItem, IdentityItemUpdate, IdentityRevision,
    IdentityRevisionSummary, IdentitySummary, IdentityTrashSummary, IdentityValue,
    LoginCustomField, LoginItem, LoginItemDetail, LoginItemRevision, LoginItemRevisionSummary,
    LoginItemSummary, LoginItemUpdate, ManagedSshHostBinding, NewApiEnvironment,
    NewEmailAccountRecord, NewIdentityItem, NewLoginItem, NewPaymentCardItem, NewSecretItem,
    NewServiceRecord, NewSshCredentialItem, PasswordHealthReport, PaymentCardDetail,
    PaymentCardItem, PaymentCardItemUpdate, PaymentCardRevision, PaymentCardRevisionSummary,
    PaymentCardSummary, PaymentCardTrashSummary, PostalAddress, SecretItem, SecretItemDetail,
    SecretItemKind, SecretItemSummary, SecretItemUpdate, ServiceAggregationApplyResult,
    ServiceAggregationBatch, ServiceAggregationCluster, ServiceAggregationPlan,
    ServiceAggregationReviewItem, ServiceAggregationReviewReason, ServiceBatchRelationship,
    ServiceDetail, ServiceIgnoredSuggestion, ServiceItemCounts, ServiceItemKind, ServiceRecord,
    ServiceRecordUpdate, ServiceRelationship, ServiceRelationshipSource, ServiceRevision,
    ServiceRevisionSummary, ServiceSummary, ServiceTrashSummary, SshCredentialDetail,
    SshCredentialItem, SshCredentialItemUpdate, SshCredentialRecordKind, SshCredentialRevision,
    SshCredentialRevisionSummary, SshCredentialSummary, SshCredentialTrashSummary,
    TrashItemSummary, TrashedApiEnvironment, TrashedIdentity, TrashedLoginItem, TrashedPaymentCard,
    TrashedServiceRecord, TrashedSshCredential, UnlockEvent, UnlockEventSource, VaultPayload,
};
pub use session::VaultSession;
pub use totp::{TotpCode, normalize_totp_secret};

/// Compatibility helper for imports and test fixtures. Applications should
/// retain a `VaultSession` instead of retaining the master password.
pub fn create(master_password: &str, payload: &VaultPayload) -> Result<Vec<u8>, VaultError> {
    let mut session = VaultSession::create_with_payload(master_password, payload.clone())?;
    let encrypted = session.save();
    session.lock();
    encrypted
}

/// Compatibility helper for imports and tests. Application code should use an
/// explicit `VaultSession` and call `lock` when leaving the unlocked state.
pub fn open(master_password: &str, encrypted_vault: &[u8]) -> Result<VaultPayload, VaultError> {
    let mut session = VaultSession::unlock(master_password, encrypted_vault)?;
    let payload = session.payload()?.clone();
    session.lock();
    Ok(payload)
}
