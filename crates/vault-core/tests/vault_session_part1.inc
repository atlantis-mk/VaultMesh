use sha2::{Digest, Sha256};
use uuid::Uuid;
use vaultmesh_core::{
    AgentAuditConfirmation, AgentAuditDecision, AgentAuditResultClass, AgentCapabilityPolicy,
    ApiCredentialField, ApiCredentialItemKind, ApiCredentialRef, ApiEnvironmentAuth,
    ApiEnvironmentKind, ApiEnvironmentUpdate, ApiFixedHeader, ApiHeaderSource, ApiKeyLocation,
    ApiRequestAuthenticationMaterial, ApiRequestBodyInput, ApiRequestInput, ApiRequestPair,
    AgentConnectorKind, AgentCredentialKind, AgentCredentialRef, AgentOutputPolicy, AgentRiskTier,
    AgentSshTunnelPolicy, AgentTargetPolicy, EmailAccountRecordUpdate, FillItemKind,
    IdentityValue, LoginCustomField, LoginItem, LoginItemUpdate, NewAgentAuditEvent,
    NewAgentConnectorDefinition, NewApiEnvironment, NewEmailAccountRecord, NewIdentityItem, NewLoginItem,
    NewPaymentCardItem, NewSecretItem, NewSshCredentialItem, PaymentCardItemUpdate, PostalAddress,
    SecretItemKind, SecretItemUpdate, SshCredentialItemUpdate, SshCredentialRecordKind,
    NewServiceRecord, ServiceIgnoredSuggestion, ServiceItemKind, ServiceRecordUpdate,
    ServiceRelationship, ServiceRelationshipSource, UnlockEventSource, VaultEnvelope, VaultError,
    VaultPayload, VaultSession, create, open,
};

fn example_payload() -> VaultPayload {
    VaultPayload {
        sync: Default::default(),
        items: vec![LoginItem::new(
            "Example".into(),
            "ada@example.test".into(),
            "never-use-this-password".into(),
        )],
        trash: Vec::new(),
        history: Vec::new(),
        cards: Vec::new(),
        card_trash: Vec::new(),
        card_history: Vec::new(),
        ssh_items: Vec::new(),
        ssh_trash: Vec::new(),
        ssh_history: Vec::new(),
        identities: Vec::new(),
        identity_trash: Vec::new(),
        identity_history: Vec::new(),
        secrets: Vec::new(),
        services: Vec::new(),
        service_trash: Vec::new(),
        service_history: Vec::new(),
        service_ignored_suggestions: Vec::new(),
        service_aggregation_batches: Vec::new(),
        service_automatic_linking_disabled: false,
        api_environments: Vec::new(),
        api_environment_trash: Vec::new(),
        api_environment_history: Vec::new(),
        email_accounts: Vec::new(),
        agent_connector_definitions: Vec::new(),
        agent_audit_events: Vec::new(),
        unlock_events: Vec::new(),
        fill_events: Vec::new(),
    }
}

#[test]
fn email_provider_credentials_stay_in_encrypted_internal_records() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let account = session
        .add_email_account(NewEmailAccountRecord {
            label: "Work".into(),
            address: "ada@example.test".into(),
            provider: "custom-imap".into(),
            auth_kind: "app-password".into(),
            credential: "provider-secret".into(),
            imap_host: "imap.example.test".into(),
            imap_port: 993,
            use_tls: true,
            enabled: true,
        })
        .unwrap();

    assert!(account.has_credential);
    let serialized_summary = serde_json::to_string(&account).unwrap();
    assert!(!serialized_summary.contains("provider-secret"));
    assert_eq!(
        session.email_account(account.id).unwrap().credential,
        "provider-secret"
    );

    session
        .update_email_account(EmailAccountRecordUpdate {
            id: account.id,
            label: "Work mail".into(),
            address: "ada@example.test".into(),
            provider: "custom-imap".into(),
            auth_kind: "app-password".into(),
            credential: None,
            imap_host: "imap.example.test".into(),
            imap_port: 993,
            use_tls: true,
            enabled: false,
        })
        .unwrap();
    assert_eq!(
        session.email_account(account.id).unwrap().credential,
        "provider-secret"
    );
    session.delete_email_account(account.id).unwrap();
    assert!(session.email_accounts().unwrap().is_empty());
}

fn new_item(title: &str, password: &str) -> NewLoginItem {
    NewLoginItem {
        title: title.into(),
        username: "ada@example.test".into(),
        password: password.into(),
        url: Some("https://example.test".into()),
        notes: None,
        folder: None,
        favorite: false,
        totp_secret: None,
        recovery_codes: Vec::new(),
        additional_urls: Vec::new(),
        autofill_on_page_load: true,
        master_password_reprompt: false,
        custom_fields: Vec::new(),
    }
}

fn ssh_tunnel_connector_definition(item_id: Uuid) -> NewAgentConnectorDefinition {
    NewAgentConnectorDefinition {
        display_label: "Production database tunnel".into(),
        environment: "production".into(),
        connector_kind: AgentConnectorKind::Ssh,
        credential_refs: vec![AgentCredentialRef {
            kind: AgentCredentialKind::Ssh,
            item_id,
        }],
        target_policy: AgentTargetPolicy::Ssh {
            host: "deploy.example.test".into(),
            port: 22,
            host_key_sha256: format!("SHA256:{}", "a".repeat(43)),
            tunnel_policies: vec![AgentSshTunnelPolicy {
                name: "database".into(),
                local_host: "127.0.0.1".into(),
                local_port: 15_432,
                destination_host: "database.internal".into(),
                destination_port: 5_432,
                max_connections: 2,
                ttl_millis: 60_000,
                risk: AgentRiskTier::R3,
            }],
        },
        capability_policy: AgentCapabilityPolicy {
            allowed_tools: vec!["vaultmesh_ssh_tunnel_open".into()],
            risk_ceiling: AgentRiskTier::R3,
            destructive_enabled: false,
        },
        output_policy: AgentOutputPolicy {
            allowed_fields: vec!["status".into()],
            max_bytes: 16 * 1024,
            max_items: 100,
            disclose_target: false,
        },
        enabled: true,
    }
}

#[test]
fn agent_connector_definitions_persist_in_the_single_format_four_contract() {
    let password = "a long unique master password";
    let mut session = VaultSession::create(password).unwrap();
    let ssh_account = session
        .add_ssh_credential(new_ssh("Agent SSH account"))
        .unwrap();
    assert_eq!(session.format_version().unwrap(), 4);
    assert!(session.agent_connector_definitions().unwrap().is_empty());

    let definition = session
        .add_agent_connector_definition(ssh_tunnel_connector_definition(ssh_account.id), 11)
        .unwrap();
    assert_eq!(session.format_version().unwrap(), 4);
    assert_eq!(session.agent_connector_definitions().unwrap(), vec![definition.clone()]);

    let encrypted_v3 = session.save().unwrap();
    assert!(!String::from_utf8_lossy(&encrypted_v3).contains("Production database tunnel"));
    let envelope: VaultEnvelope = serde_json::from_slice(&encrypted_v3).unwrap();
    assert_eq!(envelope.header.format_version, 4);
    let mut reopened = VaultSession::unlock(password, &encrypted_v3).unwrap();
    assert_eq!(reopened.agent_connector_definitions().unwrap(), vec![definition.clone()]);
    reopened
        .change_master_password(password, "replacement master password")
        .unwrap();
    assert_eq!(reopened.format_version().unwrap(), 4);
    let rewrapped_v3 = reopened.save().unwrap();
    assert!(VaultSession::unlock(password, &rewrapped_v3).is_err());
    let mut reopened = VaultSession::unlock("replacement master password", &rewrapped_v3).unwrap();
    reopened.delete_agent_connector_definition(definition.id).unwrap();
    assert_eq!(reopened.format_version().unwrap(), 4);
    let without_definition = reopened.save().unwrap();
    assert_eq!(
        serde_json::from_slice::<VaultEnvelope>(&without_definition)
            .unwrap()
            .header
            .format_version,
        4
    );
}

fn agent_audit_event(account_ref: Uuid, index: u64) -> NewAgentAuditEvent {
    NewAgentAuditEvent {
        occurred_at: index + 1,
        client_id: Uuid::from_u128(1),
        client_kind: "codex".into(),
        session_id: Uuid::from_u128(2),
        account_ref,
        account_label: "Production API".into(),
        environment: "production".into(),
        tool: "vaultmesh_http_request".into(),
        target_class: "https-origin".into(),
        approved_display: "api.example.test".into(),
        risk: AgentRiskTier::R1,
        decision: AgentAuditDecision::Allowed,
        confirmation: AgentAuditConfirmation::Session,
        duration_millis: 25,
        result_class: AgentAuditResultClass::Succeeded,
        status_class: Some("2xx".into()),
        item_count: 1,
        byte_count: 128,
    }
}

#[test]
fn agent_audit_is_encrypted_bounded_and_cleared_only_by_explicit_clear() {
    let password = "a long unique master password";
    let mut session = VaultSession::create(password).unwrap();
    let ssh_account = session
        .add_ssh_credential(new_ssh("Agent SSH account"))
        .unwrap();
    let definition = session
        .add_agent_connector_definition(ssh_tunnel_connector_definition(ssh_account.id), 10)
        .unwrap();
    for index in 0..505 {
        session
            .record_agent_audit(agent_audit_event(definition.id, index))
            .unwrap();
    }
    let events = session.agent_audit_events().unwrap();
    assert_eq!(events.len(), 500);
    assert_eq!(events[0].event.occurred_at, 6);
    let encrypted = session.save().unwrap();
    let visible = String::from_utf8_lossy(&encrypted);
    assert!(!visible.contains("Production API"));
    assert!(!visible.contains("api.example.test"));

    session.clear_agent_audit().unwrap();
    assert!(session.agent_audit_events().unwrap().is_empty());
    assert_eq!(session.format_version().unwrap(), 4);
}

fn new_card(title: &str) -> NewPaymentCardItem {
    NewPaymentCardItem {
        title: title.into(),
        cardholder_name: "Ada Lovelace".into(),
        card_number: "4111 1111 1111 1111".into(),
        expiration_month: 12,
        expiration_year: 2030,
        security_code: Some("123".into()),
        pin: Some("1234".into()),
        issuer: Some("Example Bank".into()),
        network: Some("Visa".into()),
        billing_address: Some("Private address".into()),
        notes: Some("Private note".into()),
        folder: Some("Wallet".into()),
        favorite: true,
        master_password_reprompt: false,
    }
}

fn new_ssh(title: &str) -> NewSshCredentialItem {
    NewSshCredentialItem {
        title: title.into(),
        host: Some("server.example.test".into()),
        port: 22,
        username: "deploy".into(),
        password: Some("ssh-password".into()),
        public_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGU= ada@test".into()),
        private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material\n-----END OPENSSH PRIVATE KEY-----".into()),
        key_passphrase: Some("key-passphrase".into()),
        notes: Some("SSH note".into()),
        folder: Some("Servers".into()),
        favorite: true,
        master_password_reprompt: false,
    }
}

fn new_identity(title: &str) -> NewIdentityItem {
    NewIdentityItem {
        title: title.into(),
        first_name: Some("Ada".into()),
        middle_name: None,
        last_name: Some("Lovelace".into()),
        birth_date: Some("1815-12-10".into()),
        emails: vec![IdentityValue {
            id: Uuid::nil(),
            label: "Work".into(),
            value: "ada@example.test".into(),
            preferred: true,
        }],
        phones: vec![IdentityValue {
            id: Uuid::nil(),
            label: "Mobile".into(),
            value: "+44 20 0000 0000".into(),
            preferred: true,
        }],
        addresses: vec![PostalAddress {
            id: Uuid::nil(),
            label: "Home".into(),
            address_line1: "12 Example Street".into(),
            address_line2: None,
            city: Some("London".into()),
            region: None,
            postal_code: Some("N1 9GU".into()),
            country_code: Some("GB".into()),
            country: Some("United Kingdom".into()),
            preferred: true,
        }],
        organization: Some("Analytical Engines".into()),
        department: Some("Mathematics".into()),
        job_title: Some("Programmer".into()),
        website: Some("https://example.test/ada".into()),
        notes: Some("Private identity note".into()),
        folder: Some("Personal".into()),
        favorite: true,
    }
}

#[test]
fn a_vault_round_trips() {
    let expected = example_payload();
    let encrypted = create("a long unique master password", &expected).unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("never-use-this-password"));
    assert_eq!(
        open("a long unique master password", &encrypted).unwrap(),
        expected
    );
}

#[test]
fn a_session_supports_crud_save_and_unlock() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let first = session.add_item(new_item("First", "secret-one")).unwrap();
    let second = session.add_item(new_item("Second", "secret-two")).unwrap();
    let without_password = session.add_item(new_item("No password", "")).unwrap();
    assert!(!without_password.has_password);

    let updated = session
        .update_item(LoginItemUpdate {
            id: first.id,
            title: "First updated".into(),
            username: "new@example.test".into(),
            password: None,
            url: None,
            notes: Some("private note".into()),
            folder: Some("Personal".into()),
            favorite: true,
            totp_secret: Some("jbsw-y3dp ehpk3pxp".into()),
            clear_totp_secret: false,
            recovery_codes: None,
            clear_recovery_codes: false,
            additional_urls: vec!["https://accounts.example.test".into()],
            autofill_on_page_load: false,
            master_password_reprompt: true,
            custom_fields: vec![LoginCustomField {
                label: "Recovery code".into(),
                value: "123456".into(),
            }],
        })
        .unwrap();
    assert_eq!(updated.title, "First updated");
    assert!(updated.has_password);
    assert_eq!(session.password_for_copy(first.id).unwrap(), "secret-one");
    let detail = session.item_detail(first.id).unwrap();
    assert!(detail.has_totp_secret);
    assert_eq!(session.totp_code(first.id, 59).unwrap().code, "996554");
    assert_eq!(detail.folder.as_deref(), Some("Personal"));
    assert_eq!(
        detail.additional_urls,
        vec!["https://accounts.example.test"]
    );
    assert_eq!(detail.custom_fields[0].label, "Recovery code");

    session.delete_item(second.id).unwrap();
    session.delete_item(without_password.id).unwrap();
    assert_eq!(session.list_items().unwrap().len(), 1);

    let encrypted = session.save().unwrap();
    session.lock();
    let reopened = VaultSession::unlock("correct horse battery staple", &encrypted).unwrap();
    let items = reopened.list_items().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "First updated");
    assert!(items[0].has_password);
    assert_eq!(reopened.password_for_copy(first.id).unwrap(), "secret-one");
    assert_eq!(
        open("correct horse battery staple", &encrypted)
            .unwrap()
            .items[0]
            .totp_secret
            .as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );

    let mut reopened = reopened;
    reopened
        .update_item(LoginItemUpdate {
            id: first.id,
            title: "First updated".into(),
            username: "new@example.test".into(),
            password: None,
            url: None,
            notes: Some("private note".into()),
            folder: Some("Personal".into()),
            favorite: true,
            totp_secret: None,
            clear_totp_secret: true,
            recovery_codes: None,
            clear_recovery_codes: false,
            additional_urls: vec!["https://accounts.example.test".into()],
            autofill_on_page_load: false,
            master_password_reprompt: true,
            custom_fields: Vec::new(),
        })
        .unwrap();
    assert!(!reopened.item_detail(first.id).unwrap().has_totp_secret);
    assert_eq!(
        reopened.totp_code(first.id, 59),
        Err(VaultError::TotpUnavailable)
    );
}

#[test]
fn a_session_can_quick_unlock_with_its_random_vault_key() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let item = session.add_item(new_item("Example", "secret")).unwrap();
    let encrypted = session.save().unwrap();
    let quick_unlock_key = session.quick_unlock_key().unwrap();
    session.lock();

    let reopened =
        VaultSession::unlock_with_vault_key(quick_unlock_key.as_ref(), &encrypted).unwrap();
    assert_eq!(reopened.password_for_copy(item.id).unwrap(), "secret");
    assert!(matches!(
        VaultSession::unlock_with_vault_key(&[0_u8; 31], &encrypted),
        Err(VaultError::UnlockFailed)
    ));
    assert!(matches!(
        VaultSession::unlock_with_vault_key(&[0_u8; 32], &encrypted),
        Err(VaultError::UnlockFailed)
    ));
}

#[test]
fn unlock_events_are_bounded_and_survive_encrypted_round_trips() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    for _ in 0..101 {
        session
            .record_unlock_event(UnlockEventSource::ExtensionMasterPassword)
            .unwrap();
    }
    assert_eq!(session.unlock_events().unwrap().len(), 100);
    let encrypted = session.save().unwrap();
    let reopened = VaultSession::unlock("correct horse battery staple", &encrypted).unwrap();
    assert_eq!(reopened.unlock_events().unwrap().len(), 100);
}

#[test]
fn fill_events_are_bounded_and_survive_encrypted_round_trips_without_field_values() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let item_id = Uuid::new_v4();
    for index in 0..501 {
        session
            .record_fill_event(
                FillItemKind::Login,
                item_id,
                "Example login".into(),
                "https://example.test".into(),
                index + 1,
            )
            .unwrap();
    }
    let events = session.fill_events().unwrap();
    assert_eq!(events.len(), 500);
    assert_eq!(events[0].item_id, item_id);
    assert_eq!(events[0].field_count, 501);
    assert_eq!(events[0].origin, "https://example.test");
    let encrypted = session.save().unwrap();
    let reopened = VaultSession::unlock("correct horse battery staple", &encrypted).unwrap();
    assert_eq!(reopened.fill_events().unwrap(), events);
}

#[test]
fn locking_is_idempotent_and_blocks_every_data_operation() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let item = session.add_item(new_item("Example", "secret")).unwrap();
    session.lock();
    session.lock();

    assert!(session.is_locked());
    assert_eq!(session.list_items().unwrap_err(), VaultError::Locked);
    assert_eq!(session.save().unwrap_err(), VaultError::Locked);
    assert_eq!(
        session.password_for_copy(item.id).unwrap_err(),
        VaultError::Locked
    );
}

#[test]
fn debug_output_redacts_passwords_and_notes() {
    let mut item = LoginItem::new(
        "Example".into(),
        "ada@example.test".into(),
        "super-secret".into(),
    );
    item.notes = Some("private note".into());
    let output = format!("{item:?}");
    assert!(!output.contains("super-secret"));
    assert!(!output.contains("private note"));
}

#[test]
fn a_wrong_password_cannot_unlock_the_vault() {
    let encrypted = create("correct horse battery staple", &example_payload()).unwrap();
    assert!(matches!(
        VaultSession::unlock("incorrect", &encrypted),
        Err(VaultError::UnlockFailed)
    ));
}

#[test]
fn modified_ciphertext_cannot_unlock_the_vault() {
    let encrypted = create("correct horse battery staple", &example_payload()).unwrap();
    let mut envelope: VaultEnvelope = serde_json::from_slice(&encrypted).unwrap();
    envelope.payload_ciphertext[0] ^= 1;
    let modified = serde_json::to_vec(&envelope).unwrap();
    assert!(matches!(
        VaultSession::unlock("correct horse battery staple", &modified),
        Err(VaultError::UnlockFailed)
    ));
}

#[test]
fn untrusted_kdf_parameters_are_rejected_before_derivation() {
    let encrypted = create("correct horse battery staple", &example_payload()).unwrap();
    let mut envelope: VaultEnvelope = serde_json::from_slice(&encrypted).unwrap();
    envelope.header.kdf.memory_kib = u32::MAX;
    let modified = serde_json::to_vec(&envelope).unwrap();
    assert!(matches!(
        VaultSession::unlock("correct horse battery staple", &modified),
        Err(VaultError::UnsupportedFormat)
    ));
}

#[test]
fn non_current_formats_are_rejected_before_any_untrusted_kdf_parameters() {
    let encrypted = create("correct horse battery staple", &example_payload()).unwrap();
    for version in [1, 2, u16::MAX] {
        let mut envelope: VaultEnvelope = serde_json::from_slice(&encrypted).unwrap();
        envelope.header.format_version = version;
        envelope.header.kdf.memory_kib = u32::MAX;
        let modified = serde_json::to_vec(&envelope).unwrap();
        assert!(matches!(
            VaultSession::unlock("correct horse battery staple", &modified),
            Err(VaultError::UnsupportedFormat)
        ));
    }
}

#[test]
fn format_four_authenticates_both_header_and_payload() {
    let password = "a long unique master password";
    let mut session = VaultSession::create(password).unwrap();
    let ssh_account = session.add_ssh_credential(new_ssh("Agent SSH account")).unwrap();
    session
        .add_agent_connector_definition(ssh_tunnel_connector_definition(ssh_account.id), 10)
        .unwrap();
    let encrypted = session.save().unwrap();

    let mut header_tampered: VaultEnvelope = serde_json::from_slice(&encrypted).unwrap();
    header_tampered.header.salt[0] ^= 1;
    assert!(matches!(
        VaultSession::unlock(password, &serde_json::to_vec(&header_tampered).unwrap()),
        Err(VaultError::UnlockFailed)
    ));

    let mut payload_tampered: VaultEnvelope = serde_json::from_slice(&encrypted).unwrap();
    payload_tampered.payload_ciphertext[0] ^= 1;
    assert!(matches!(
        VaultSession::unlock(password, &serde_json::to_vec(&payload_tampered).unwrap()),
        Err(VaultError::UnlockFailed)
    ));
}

#[test]
fn password_rotation_rewraps_key_and_preserves_payload() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let item = session.add_item(new_item("Example", "secret")).unwrap();
    session
        .change_master_password(
            "correct horse battery staple",
            "a new long unique master password",
        )
        .unwrap();
    let encrypted = session.save().unwrap();
    assert!(matches!(
        VaultSession::unlock("correct horse battery staple", &encrypted),
        Err(VaultError::UnlockFailed)
    ));
    let reopened = VaultSession::unlock("a new long unique master password", &encrypted).unwrap();
    assert_eq!(reopened.password_for_copy(item.id).unwrap(), "secret");
}

#[test]
fn trash_and_history_restore_complete_items() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let item = session.add_item(new_item("Original", "secret")).unwrap();
    session
        .update_item(LoginItemUpdate {
            id: item.id,
            title: "Updated".into(),
            username: "ada@example.test".into(),
            password: None,
            url: None,
            notes: None,
            folder: None,
            favorite: false,
            totp_secret: None,
            clear_totp_secret: false,
            recovery_codes: None,
            clear_recovery_codes: false,
            additional_urls: Vec::new(),
            autofill_on_page_load: true,
            master_password_reprompt: false,
            custom_fields: Vec::new(),
        })
        .unwrap();
    let revision = session.item_history(item.id).unwrap()[0].clone();
    session
        .restore_revision(item.id, revision.revision_id)
        .unwrap();
    assert_eq!(session.item_detail(item.id).unwrap().title, "Original");

    session.delete_item(item.id).unwrap();
    assert!(session.list_items().unwrap().is_empty());
    let trash = session.list_trash().unwrap();
    session.restore_trash(trash[0].trash_id).unwrap();
    assert_eq!(session.password_for_copy(item.id).unwrap(), "secret");
}

#[test]
fn reprompt_autofill_and_health_policies_are_enforced_in_core() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let mut protected = new_item("Protected", "short");
    protected.master_password_reprompt = true;
    protected.additional_urls = vec!["https://login.example.test/account".into()];
    let protected = session.add_item(protected).unwrap();
    let duplicate = session.add_item(new_item("Duplicate", "short")).unwrap();

    assert_eq!(
        session.password_for_access(protected.id, None),
        Err(VaultError::MasterPasswordRequired)
    );
    assert!(matches!(
        session.password_for_access(protected.id, Some("wrong")),
        Err(VaultError::UnlockFailed)
    ));
    assert_eq!(
        session
            .password_for_access(protected.id, Some("correct horse battery staple"))
            .unwrap(),
        "short"
    );
    let candidates = session
        .autofill_candidates("https://example.test/page")
        .unwrap();
    assert!(candidates.iter().any(|item| item.id == protected.id));
    assert!(candidates.iter().any(|item| item.id == duplicate.id));
    let browser_metadata = session.list_item_details().unwrap();
    let protected_metadata = browser_metadata
        .iter()
        .find(|item| item.id == protected.id)
        .unwrap();
    assert_eq!(
        protected_metadata.additional_urls,
        ["https://login.example.test/account"]
    );
    assert!(protected_metadata.master_password_reprompt);
    let report = session.password_health(u64::MAX / 2).unwrap();
    assert_eq!(report.weak_item_ids.len(), 2);
    assert_eq!(report.reused_item_ids.len(), 2);
    assert!(report.old_item_ids.len() <= 2);
    assert_eq!(report.score, 0);
}

#[test]
fn legacy_payload_fields_default_without_marking_password_old() {
    let json = r#"{"items":[{"id":"953370ec-4dc7-4c77-a6e0-f2a4f6e37f03","title":"Legacy","username":"ada","password":"long-legacy-password","url":null,"notes":null}]}"#;
    let payload: VaultPayload = serde_json::from_str(json).unwrap();
    assert!(payload.trash.is_empty());
    assert!(payload.history.is_empty());
    assert!(payload.cards.is_empty());
    assert!(payload.card_trash.is_empty());
    assert!(payload.card_history.is_empty());
    assert!(payload.ssh_items.is_empty());
    assert!(payload.ssh_trash.is_empty());
    assert!(payload.ssh_history.is_empty());
    assert!(payload.identities.is_empty());
    assert!(payload.identity_trash.is_empty());
    assert!(payload.identity_history.is_empty());
    assert_eq!(payload.items[0].password_changed_at, 0);
    assert!(payload.items[0].recovery_codes.is_empty());
}

#[test]
fn recovery_codes_are_redacted_and_require_master_password_for_every_access() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let mut invalid = new_item("Invalid recovery", "secret");
    invalid.recovery_codes = vec!["   ".into()];
    assert_eq!(
        session.add_item(invalid),
        Err(VaultError::InvalidRecoveryCodes)
    );
    assert!(session.list_items().unwrap().is_empty());
    let mut input = new_item("Recovery protected", "secret");
    input.recovery_codes = vec!["alpha-code".into(), " beta code ".into()];
    let item = session.add_item(input).unwrap();

    assert!(item.has_recovery_codes);
    assert!(session.item_detail(item.id).unwrap().has_recovery_codes);
    assert_eq!(
        session.recovery_codes_for_access(item.id, None),
        Err(VaultError::MasterPasswordRequired)
    );
    assert_eq!(
        session.recovery_codes_for_access(item.id, Some("wrong password")),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(
        session
            .recovery_codes_for_access(item.id, Some("correct horse battery staple"))
            .unwrap(),
        ["alpha-code", " beta code "]
    );
    let debug = format!("{:?}", session.payload_snapshot().unwrap().items[0]);
    assert!(!debug.contains("alpha-code"));
    assert!(!debug.contains("beta code"));

    let recovery_update =
        |title: &str, recovery_codes: Option<Vec<String>>, clear_recovery_codes: bool| {
            LoginItemUpdate {
                id: item.id,
                title: title.into(),
                username: "ada@example.test".into(),
                password: None,
                url: Some("https://example.test".into()),
                notes: None,
                folder: None,
                favorite: false,
                totp_secret: None,
                clear_totp_secret: false,
                recovery_codes,
                clear_recovery_codes,
                additional_urls: Vec::new(),
                autofill_on_page_load: true,
                master_password_reprompt: false,
                custom_fields: Vec::new(),
            }
        };
    assert_eq!(
        session.update_item(recovery_update(
            "Invalid replacement",
            Some(vec!["\t".into()]),
            false,
        )),
        Err(VaultError::InvalidRecoveryCodes)
    );
    assert_eq!(
        session
            .recovery_codes_for_access(item.id, Some("correct horse battery staple"))
            .unwrap(),
        ["alpha-code", " beta code "]
    );
    session
        .update_item(recovery_update(
            "Recovery replaced",
            Some(vec!["replacement-code".into()]),
            false,
        ))
        .unwrap();
    session
        .update_item(recovery_update("Recovery preserved", None, false))
        .unwrap();
    assert_eq!(
        session
            .recovery_codes_for_access(item.id, Some("correct horse battery staple"))
            .unwrap(),
        ["replacement-code"]
    );
    let original_revision = session
        .item_history(item.id)
        .unwrap()
        .into_iter()
        .find(|revision| revision.title == "Recovery protected")
        .expect("original recovery-code revision");
    session
        .restore_revision(item.id, original_revision.revision_id)
        .unwrap();
    assert_eq!(
        session
            .recovery_codes_for_access(item.id, Some("correct horse battery staple"))
            .unwrap(),
        ["alpha-code", " beta code "]
    );
    session
        .update_item(recovery_update("Recovery protected", None, true))
        .unwrap();
    assert_eq!(
        session.recovery_codes_for_access(item.id, Some("correct horse battery staple")),
        Err(VaultError::RecoveryCodesUnavailable)
    );
}

#[test]
fn agent_recovery_code_is_compare_and_consumed_only_after_success_evidence() {
    let mut session = VaultSession::create("correct horse battery staple").unwrap();
    let mut input = new_item("Agent recovery", "secret");
    input.recovery_codes = vec!["first-code".into(), "second-code".into()];
    let item = session.add_item(input).unwrap();

    assert_eq!(
        session
            .agent_recovery_code_for_consumption(item.id)
            .unwrap(),
        "first-code"
    );
    let wrong: [u8; 32] = Sha256::digest(b"not-the-submitted-code").into();
    assert_eq!(
        session.consume_agent_recovery_code(item.id, &wrong),
        Err(VaultError::RecoveryCodesUnavailable)
    );
    assert_eq!(
        session
            .agent_recovery_code_for_consumption(item.id)
            .unwrap(),
        "first-code"
    );

    let expected: [u8; 32] = Sha256::digest(b"first-code").into();
    assert_eq!(
        session.consume_agent_recovery_code(item.id, &expected),
        Ok(1)
    );
    assert_eq!(
        session
            .agent_recovery_code_for_consumption(item.id)
            .unwrap(),
        "second-code"
    );
    assert_eq!(
        session.consume_agent_recovery_code(item.id, &expected),
        Err(VaultError::RecoveryCodesUnavailable)
    );

    let reopened = VaultSession::unlock(
        "correct horse battery staple",
        session.save().unwrap().as_slice(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .recovery_codes_for_access(item.id, Some("correct horse battery staple"))
            .unwrap(),
        ["second-code"]
    );
}
