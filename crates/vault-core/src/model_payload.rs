use super::*;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultPayload {
    #[serde(default)]
    pub sync: crate::SyncState,
    pub items: Vec<LoginItem>,
    #[serde(default)]
    pub trash: Vec<TrashedLoginItem>,
    #[serde(default)]
    pub history: Vec<LoginItemRevision>,
    #[serde(default)]
    pub cards: Vec<PaymentCardItem>,
    #[serde(default)]
    pub card_trash: Vec<TrashedPaymentCard>,
    #[serde(default)]
    pub card_history: Vec<PaymentCardRevision>,
    #[serde(default)]
    pub ssh_items: Vec<SshCredentialItem>,
    #[serde(default)]
    pub ssh_trash: Vec<TrashedSshCredential>,
    #[serde(default)]
    pub ssh_history: Vec<SshCredentialRevision>,
    #[serde(default)]
    pub identities: Vec<IdentityItem>,
    #[serde(default)]
    pub identity_trash: Vec<TrashedIdentity>,
    #[serde(default)]
    pub identity_history: Vec<IdentityRevision>,
    #[serde(default)]
    pub secrets: Vec<SecretItem>,
    /// Encrypted navigation-only Service records. These references never own
    /// credentials, targets, or permission decisions.
    #[serde(default)]
    pub services: Vec<ServiceRecord>,
    #[serde(default)]
    pub service_trash: Vec<TrashedServiceRecord>,
    #[serde(default)]
    pub service_history: Vec<ServiceRevision>,
    #[serde(default)]
    pub service_ignored_suggestions: Vec<ServiceIgnoredSuggestion>,
    #[serde(default)]
    pub service_aggregation_batches: Vec<ServiceAggregationBatch>,
    /// Missing means continuous exact-host linking remains enabled.
    #[serde(default)]
    pub service_automatic_linking_disabled: bool,
    /// Encrypted API target/config records. Credential values remain owned by
    /// Login/Secret items and are referenced only by typed opaque IDs.
    #[serde(default)]
    pub api_environments: Vec<ApiEnvironmentRecord>,
    #[serde(default)]
    pub api_environment_trash: Vec<TrashedApiEnvironment>,
    #[serde(default)]
    pub api_environment_history: Vec<ApiEnvironmentRevision>,
    /// Privileged email provider credentials. These records are part of the
    /// encrypted payload and are never exposed through ordinary item APIs.
    #[serde(default)]
    pub email_accounts: Vec<EmailAccountRecord>,
    /// Rust-owned managed-web recipes and fixed SSH tunnel endpoints. These
    /// definitions never own accounts, credentials, or permission decisions.
    /// Every write stores the collection in the single current envelope.
    #[serde(default)]
    pub agent_connector_definitions: Vec<crate::AgentConnectorDefinition>,
    /// Bounded, encrypted Agent activity metadata. It never contains request
    /// or response bodies, credentials, command output, or local paths.
    #[serde(default)]
    pub agent_audit_events: Vec<crate::AgentAuditEvent>,
    /// Successful unlocks are deliberately coarse audit metadata. They remain
    /// inside the encrypted payload and never contain credentials or device
    /// identifiers.
    #[serde(default)]
    pub unlock_events: Vec<UnlockEvent>,
    /// Successful browser fills are recorded as encrypted audit metadata.
    /// Values written into page fields are deliberately never stored here.
    #[serde(default)]
    pub fill_events: Vec<FillEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FillItemKind {
    Login,
    Card,
    Identity,
    Secret,
    Ssh,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FillEvent {
    pub event_id: Uuid,
    pub occurred_at: u64,
    pub item_kind: FillItemKind,
    pub item_id: Uuid,
    pub item_title: String,
    pub origin: String,
    pub field_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockEventSource {
    Desktop,
    DesktopPin,
    ExtensionMasterPassword,
    ExtensionBiometric,
    ExtensionPin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnlockEvent {
    pub event_id: Uuid,
    pub occurred_at: u64,
    pub source: UnlockEventSource,
}

impl Zeroize for VaultPayload {
    fn zeroize(&mut self) {
        self.sync.zeroize();
        self.items.zeroize();
        self.trash.zeroize();
        self.history.zeroize();
        self.cards.zeroize();
        self.card_trash.zeroize();
        self.card_history.zeroize();
        self.ssh_items.zeroize();
        self.ssh_trash.zeroize();
        self.ssh_history.zeroize();
        self.identities.zeroize();
        self.identity_trash.zeroize();
        self.identity_history.zeroize();
        self.secrets.zeroize();
        self.services.zeroize();
        self.service_trash.zeroize();
        self.service_history.zeroize();
        for ignored in &mut self.service_ignored_suggestions {
            ignored.service_key.zeroize();
        }
        self.service_ignored_suggestions.clear();
        for batch in &mut self.service_aggregation_batches {
            batch.plan_id.zeroize();
            batch.created_service_ids.clear();
            batch.added_relationships.clear();
        }
        self.service_aggregation_batches.clear();
        self.api_environments.zeroize();
        self.api_environment_trash.zeroize();
        self.api_environment_history.zeroize();
        self.email_accounts.zeroize();
        self.agent_connector_definitions.zeroize();
        self.agent_audit_events.zeroize();
        self.unlock_events.clear();
        for event in &mut self.fill_events {
            event.item_title.zeroize();
            event.origin.zeroize();
        }
        self.fill_events.clear();
    }
}

/// An encrypted, desktop-runtime-owned email provider record.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmailAccountRecord {
    pub id: Uuid,
    pub label: String,
    pub address: String,
    pub provider: String,
    pub auth_kind: String,
    pub credential: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub use_tls: bool,
    pub enabled: bool,
}

impl fmt::Debug for EmailAccountRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailAccountRecord")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("address", &self.address)
            .field("provider", &self.provider)
            .field("auth_kind", &self.auth_kind)
            .field("credential", &"[REDACTED]")
            .field("imap_host", &self.imap_host)
            .field("imap_port", &self.imap_port)
            .field("use_tls", &self.use_tls)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl Zeroize for EmailAccountRecord {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.address.zeroize();
        self.provider.zeroize();
        self.auth_kind.zeroize();
        self.credential.zeroize();
        self.imap_host.zeroize();
    }
}

impl Drop for EmailAccountRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewEmailAccountRecord {
    pub label: String,
    pub address: String,
    pub provider: String,
    pub auth_kind: String,
    pub credential: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub use_tls: bool,
    pub enabled: bool,
}

impl Zeroize for NewEmailAccountRecord {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.address.zeroize();
        self.provider.zeroize();
        self.auth_kind.zeroize();
        self.credential.zeroize();
        self.imap_host.zeroize();
    }
}

impl Drop for NewEmailAccountRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmailAccountRecordUpdate {
    pub id: Uuid,
    pub label: String,
    pub address: String,
    pub provider: String,
    pub auth_kind: String,
    pub credential: Option<String>,
    pub imap_host: String,
    pub imap_port: u16,
    pub use_tls: bool,
    pub enabled: bool,
}

impl Zeroize for EmailAccountRecordUpdate {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.address.zeroize();
        self.provider.zeroize();
        self.auth_kind.zeroize();
        zeroize_option(&mut self.credential);
        self.imap_host.zeroize();
    }
}

impl Drop for EmailAccountRecordUpdate {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAccountRecordSummary {
    pub id: Uuid,
    pub label: String,
    pub address: String,
    pub provider: String,
    pub auth_kind: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub use_tls: bool,
    pub enabled: bool,
    pub has_credential: bool,
}

impl From<&EmailAccountRecord> for EmailAccountRecordSummary {
    fn from(value: &EmailAccountRecord) -> Self {
        Self {
            id: value.id,
            label: value.label.clone(),
            address: value.address.clone(),
            provider: value.provider.clone(),
            auth_kind: value.auth_kind.clone(),
            imap_host: value.imap_host.clone(),
            imap_port: value.imap_port,
            use_tls: value.use_tls,
            enabled: value.enabled,
            has_credential: !value.credential.is_empty(),
        }
    }
}

pub(crate) fn validate_email_account(
    label: &str,
    address: &str,
    provider: &str,
    auth_kind: &str,
    credential: &str,
    imap_host: &str,
    imap_port: u16,
) -> Result<(), VaultError> {
    const PROVIDERS: &[&str] = &[
        "gmail",
        "outlook",
        "qq",
        "163",
        "126",
        "yeah",
        "icloud",
        "yahoo",
        "zoho",
        "fastmail",
        "custom-imap",
    ];
    let valid_address = address.len() <= 320
        && address.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.chars().any(char::is_whitespace)
        });
    if label.trim().is_empty()
        || label.encode_utf16().count() > 128
        || !valid_address
        || !PROVIDERS.contains(&provider)
        || !matches!(auth_kind, "oauth" | "app-password")
        || credential.is_empty()
        || credential.encode_utf16().count() > 10_000
        || imap_host.trim().is_empty()
        || imap_host.len() > 253
        || imap_port == 0
    {
        return Err(VaultError::InvalidEmailAccount);
    }
    Ok(())
}

impl Drop for VaultPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}
