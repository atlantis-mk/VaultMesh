use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AgentApiEnvironmentSummary, AgentAuditEvent, AgentConnectorDefinition,
    AgentConnectorDefinitionSummary, ApiCredentialItemKind, ApiCredentialRef, ApiEnvironmentAuth,
    ApiEnvironmentDetail, ApiEnvironmentRecord, ApiEnvironmentRevision,
    ApiEnvironmentRevisionSummary, ApiEnvironmentSummary, ApiEnvironmentTrashSummary,
    ApiEnvironmentUpdate, ApiHeaderSource, ApiRequestAuthenticationMaterial, ApiRequestBodyInput,
    ApiRequestExecutionPlan, ApiRequestInput, ApiRequestPlanSummary, ApiRequestValueMaterial,
    EmailAccountRecord, EmailAccountRecordSummary, EmailAccountRecordUpdate, FillEvent,
    FillItemKind, IdentityDetail, IdentityRevision, IdentityRevisionSummary, IdentitySummary,
    IdentityTrashSummary, LoginItemDetail, LoginItemRevision, LoginItemRevisionSummary,
    LoginItemSummary, LoginItemUpdate, ManagedSshHostBinding, NewAgentAuditEvent,
    NewAgentConnectorDefinition, NewApiEnvironment, NewEmailAccountRecord, NewIdentityItem,
    NewLoginItem, NewPaymentCardItem, NewSecretItem, NewServiceRecord, NewSshCredentialItem,
    PasswordHealthReport, PaymentCardDetail, PaymentCardItem, PaymentCardItemUpdate,
    PaymentCardRevision, PaymentCardRevisionSummary, PaymentCardSummary, PaymentCardTrashSummary,
    SecretItemDetail, SecretItemSummary, SecretItemUpdate, ServiceAggregationApplyResult,
    ServiceAggregationPlan, ServiceAggregationReviewItem, ServiceAggregationReviewReason,
    ServiceDetail, ServiceIgnoredSuggestion, ServiceItemCounts, ServiceItemKind, ServiceRecord,
    ServiceRecordUpdate, ServiceRelationship, ServiceRelationshipSource, ServiceRevision,
    ServiceRevisionSummary, ServiceSummary, ServiceTrashSummary, SshCredentialDetail,
    SshCredentialItem, SshCredentialItemUpdate, SshCredentialRevision,
    SshCredentialRevisionSummary, SshCredentialSummary, SshCredentialTrashSummary, TotpCode,
    TrashItemSummary, TrashedApiEnvironment, TrashedIdentity, TrashedLoginItem, TrashedPaymentCard,
    TrashedServiceRecord, TrashedSshCredential, UnlockEvent, UnlockEventSource, VaultError,
    VaultHeader, VaultPayload,
    agent_connector::{MAX_AGENT_AUDIT_EVENTS, validate_agent_audit},
    format::{
        KEY_LEN, VaultKey, create_header, decrypt_payload, encrypt_payload, parse_envelope,
        rewrap_header, unlock_key,
    },
};

#[path = "session_agent.rs"]
mod session_agent;
#[path = "session_api_environment.rs"]
pub(crate) mod session_api_environment;
#[path = "session_api_request.rs"]
mod session_api_request;
#[path = "session_base.rs"]
mod session_base;
#[path = "session_card.rs"]
mod session_card;
#[path = "session_events.rs"]
mod session_events;
#[path = "session_login.rs"]
mod session_login;
#[path = "session_secret_identity.rs"]
mod session_secret_identity;
#[path = "session_service.rs"]
mod session_service;
#[path = "session_ssh.rs"]
mod session_ssh;

const MAX_REVISIONS_PER_ITEM: usize = 20;
const OLD_PASSWORD_SECONDS: u64 = 180 * 24 * 60 * 60;
const MAX_UNLOCK_EVENTS: usize = 100;
const MAX_FILL_EVENTS: usize = 500;

/// An in-memory unlocked vault. Calling `lock` clears both the vault key and
/// decrypted payload, and all data operations subsequently return `Locked`.
pub struct VaultSession {
    header: VaultHeader,
    vault_key: Option<Zeroizing<VaultKey>>,
    payload: Option<VaultPayload>,
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

fn zeroize_option(value: &mut Option<String>) {
    if let Some(value) = value {
        value.zeroize();
    }
}

fn identity_matches_query(item: &crate::IdentityItem, query: &str) -> bool {
    let scalar_fields = [
        Some(item.title.as_str()),
        item.first_name.as_deref(),
        item.middle_name.as_deref(),
        item.last_name.as_deref(),
        item.organization.as_deref(),
        item.department.as_deref(),
        item.job_title.as_deref(),
        item.website.as_deref(),
        item.notes.as_deref(),
        item.folder.as_deref(),
    ];
    scalar_fields
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(query))
        || item.emails.iter().chain(&item.phones).any(|value| {
            value.label.to_lowercase().contains(query) || value.value.to_lowercase().contains(query)
        })
        || item.addresses.iter().any(|address| {
            [
                address.label.as_str(),
                address.address_line1.as_str(),
                address.address_line2.as_deref().unwrap_or_default(),
                address.city.as_deref().unwrap_or_default(),
                address.region.as_deref().unwrap_or_default(),
                address.postal_code.as_deref().unwrap_or_default(),
                address.country_code.as_deref().unwrap_or_default(),
                address.country.as_deref().unwrap_or_default(),
            ]
            .into_iter()
            .any(|value| value.to_lowercase().contains(query))
        })
}

fn replace_optional_secret(target: &mut Option<String>, replacement: Option<String>, clear: bool) {
    if clear {
        zeroize_option(target);
        *target = None;
    } else if let Some(mut replacement) = replacement {
        zeroize_option(target);
        *target = Some(std::mem::take(&mut replacement));
    }
}

fn same_optional_key(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left.trim() == right.trim())
}

fn same_optional_public_key(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            let normalized = |value: &str| {
                value
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            normalized(left) == normalized(right)
        }
        _ => false,
    }
}

fn unix_time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalized_http_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit('@')
        .next()?
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host.strip_prefix("www.").unwrap_or(&host).to_owned())
    }
}

fn is_weak(password: &str) -> bool {
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    password.chars().count() < 12 || classes < 3
}
