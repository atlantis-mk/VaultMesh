pub(crate) fn transaction(
    vault: &mut VaultmeshVault,
    operation: impl FnOnce(&mut VaultSession) -> Result<Value, VaultmeshStatus>,
) -> Result<Value, VaultmeshStatus> {
    transaction_guarded(vault, operation, || true)
}

pub(crate) fn transaction_guarded(
    vault: &mut VaultmeshVault,
    operation: impl FnOnce(&mut VaultSession) -> Result<Value, VaultmeshStatus>,
    can_commit: impl Fn() -> bool,
) -> Result<Value, VaultmeshStatus> {
    let mutation_lock = mutation_lock(&vault.path);
    let _guard = mutation_lock
        .lock()
        .map_err(|_| VAULTMESH_STATUS_IO_ERROR)?;
    let before = Zeroizing::new(read_vault(&vault.path).map_err(|()| VAULTMESH_STATUS_IO_ERROR)?);
    if vault_fingerprint(before.as_slice()) != vault.persisted_fingerprint {
        return Err(VAULTMESH_STATUS_CONFLICT);
    }
    let key = vault.session.quick_unlock_key().map_err(map_core_error)?;
    let result = operation(&mut vault.session).and_then(|value| {
        vault.session.sync_checkpoint(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64).map_err(map_core_error)?;
        Ok(value)
    });
    if result.is_ok() {
        let encrypted = vault
            .session
            .save()
            .map(Zeroizing::new)
            .map_err(map_core_error);
        if let Ok(encrypted) = encrypted
            && can_commit()
            && write_vault(&vault.path, encrypted.as_slice()).is_ok()
        {
            vault.persisted_fingerprint = vault_fingerprint(encrypted.as_slice());
            crate::sync_relay::publish_committed(vault);
            return result;
        }
    }

    vault.session = VaultSession::unlock_with_vault_key(key.as_slice(), before.as_slice())
        .map_err(map_core_error)?;
    match result {
        Ok(_) => Err(VAULTMESH_STATUS_IO_ERROR),
        Err(status) => Err(status),
    }
}

fn dispatch(
    session: &mut VaultSession,
    operation: &str,
    mut input: Value,
) -> Result<Value, VaultmeshStatus> {
    let result = match operation {
        "_native.record-unlock" => {
            let source = match string(&input, "source")? {
                "extension-master-password" => UnlockEventSource::ExtensionMasterPassword,
                "extension-biometric" => UnlockEventSource::ExtensionBiometric,
                "extension-pin" => UnlockEventSource::ExtensionPin,
                _ => return Err(VAULTMESH_STATUS_INVALID_ARGUMENT),
            };
            value(session.record_unlock_event(source))
        }
        "_native.import.batch" => import_batch(session, &input),
        "_native.ssh.import" => {
            let entries = input
                .as_object()
                .and_then(|value| value.get("items"))
                .and_then(Value::as_array)
                .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?;
            let items = entries
                .iter()
                .map(parse::<NewSshCredentialItem>)
                .collect::<Result<Vec<_>, _>>()?;
            let (imported, skipped_count) = session
                .import_ssh_credentials(items)
                .map_err(map_core_error)?;
            Ok(json!({
                "imported_count": imported.len(),
                "skipped_count": skipped_count,
                "items": imported,
            }))
        }
        "_native.ssh.has-key" => Ok(json!({
            "duplicate": session
                .has_ssh_key_material(
                    optional_string(&input, "public_key"),
                    optional_string(&input, "private_key"),
                )
                .map_err(map_core_error)?,
        })),
        "_native.email.accounts" => value(session.email_accounts()),
        "_native.email.account" => value(session.email_account(uuid(&input, "id")?)),
        "_native.email.add" => {
            value(session.add_email_account(parse::<NewEmailAccountRecord>(&input)?))
        }
        "_native.email.update" => {
            value(session.update_email_account(parse::<EmailAccountRecordUpdate>(&input)?))
        }
        "_native.email.delete" => empty(session.delete_email_account(uuid(&input, "id")?)),
        "vault.unlock-history" => value(session.unlock_events()),
        "vault.change-password" => {
            let current = string(&input, "current_password")?;
            let next = string(&input, "new_password")?;
            session
                .change_master_password(current, next)
                .map(|()| json!({}))
                .map_err(map_core_error)
        }
        "browser.autofill.candidates" => value(session.autofill_candidates(string(&input, "url")?)),
        "browser.card.capture-status" => card_capture_status(session, &input),
        "browser.login.password-changed" => login_password_changed(session, &input),
        "browser.fill.record" => {
            let item_kind = parse(&take(&mut input, "item_kind")?)?;
            let item_id = uuid(&input, "item_id")?;
            let item_title = owned_string(&input, "item_title")?;
            let origin = owned_string(&input, "origin")?;
            let field_count = number(&input, "field_count")? as u32;
            value(session.record_fill_event(item_kind, item_id, item_title, origin, field_count))
        }
        "browser.fill.history" => value(session.fill_events()),
        "items.detail" => {
            let detail = session
                .item_detail(uuid(&input, "id")?)
                .map_err(map_core_error)?;
            serializable(detail)
        }
        "items.add" => value(session.add_item(parse(&input)?)),
        "items.update" => value(session.update_item(parse::<LoginItemUpdate>(&input)?)),
        "items.delete" => empty(session.delete_item(uuid(&input, "id")?)),
        "items.trash.list" => value(session.list_trash()),
        "items.trash.restore" => value(session.restore_trash(uuid(&input, "trash_id")?)),
        "items.trash.purge" => empty(session.purge_trash(uuid(&input, "trash_id")?)),
        "items.trash.empty" => empty(session.empty_trash()),
        "items.history.list" => value(session.item_history(uuid(&input, "id")?)),
        "items.history.restore" => {
            value(session.restore_revision(uuid(&input, "item_id")?, uuid(&input, "revision_id")?))
        }
        "items.history.clear" => empty(session.clear_history(uuid(&input, "id")?)),
        "cards.detail" => value(session.card_detail(uuid(&input, "id")?)),
        "cards.add" => value(session.add_card(parse::<NewPaymentCardItem>(&input)?)),
        "cards.update" => value(session.update_card(parse::<PaymentCardItemUpdate>(&input)?)),
        "cards.delete" => empty(session.delete_card(uuid(&input, "id")?)),
        "cards.trash.list" => value(session.list_card_trash()),
        "cards.trash.restore" => value(session.restore_card_trash(uuid(&input, "trash_id")?)),
        "cards.trash.purge" => empty(session.purge_card_trash(uuid(&input, "trash_id")?)),
        "cards.trash.empty" => empty(session.empty_card_trash()),
        "cards.history.list" => value(session.card_history(uuid(&input, "id")?)),
        "cards.history.restore" => value(
            session.restore_card_revision(uuid(&input, "item_id")?, uuid(&input, "revision_id")?),
        ),
        "cards.history.clear" => empty(session.clear_card_history(uuid(&input, "id")?)),
        "identities.detail" => value(session.identity_detail(uuid(&input, "id")?)),
        "identities.add" => value(session.add_identity(parse::<NewIdentityItem>(&input)?)),
        "identities.update" => {
            let id = uuid(&input, "id")?;
            input
                .as_object_mut()
                .expect("validated object")
                .remove("id");
            let identity = parse::<NewIdentityItem>(&input)?;
            value(session.update_identity(identity, id))
        }
        "identities.delete" => empty(session.delete_identity(uuid(&input, "id")?)),
        "identities.trash.list" => value(session.list_identity_trash()),
        "identities.trash.restore" => {
            value(session.restore_identity_trash(uuid(&input, "trash_id")?))
        }
        "identities.trash.purge" => empty(session.purge_identity_trash(uuid(&input, "trash_id")?)),
        "identities.trash.empty" => empty(session.empty_identity_trash()),
        "identities.history.list" => value(session.identity_history(uuid(&input, "id")?)),
        "identities.history.restore" => value(
            session
                .restore_identity_revision(uuid(&input, "item_id")?, uuid(&input, "revision_id")?),
        ),
        "identities.history.clear" => empty(session.clear_identity_history(uuid(&input, "id")?)),
        "ssh.detail" => value(session.ssh_credential_detail(uuid(&input, "id")?)),
        "ssh.add" => value(session.add_ssh_credential(parse::<NewSshCredentialItem>(&input)?)),
        "ssh.update" => {
            value(session.update_ssh_credential(parse::<SshCredentialItemUpdate>(&input)?))
        }
        "ssh.delete" => empty(session.delete_ssh_credential(uuid(&input, "id")?)),
        "ssh.trash.list" => value(session.list_ssh_trash()),
        "ssh.trash.restore" => value(session.restore_ssh_trash(uuid(&input, "trash_id")?)),
        "ssh.trash.purge" => empty(session.purge_ssh_trash(uuid(&input, "trash_id")?)),
        "ssh.trash.empty" => empty(session.empty_ssh_trash()),
        "ssh.history.list" => value(session.ssh_history(uuid(&input, "id")?)),
        "ssh.history.restore" => value(
            session.restore_ssh_revision(uuid(&input, "item_id")?, uuid(&input, "revision_id")?),
        ),
        "ssh.history.clear" => empty(session.clear_ssh_history(uuid(&input, "id")?)),
        "secrets.detail" => value(session.secret_detail(uuid(&input, "id")?)),
        "secrets.add" => value(session.add_secret(parse::<NewSecretItem>(&input)?)),
        "secrets.update" => value(session.update_secret(parse::<SecretItemUpdate>(&input)?)),
        "secrets.delete" => empty(session.delete_secret(uuid(&input, "id")?)),
        "services.list" => value(session.list_services(optional_string(&input, "query"))),
        "services.detail" => value(session.service_detail(uuid(&input, "id")?)),
        "services.add" => value(session.add_service(parse::<NewServiceRecord>(&input)?)),
        "services.update" => value(session.update_service(parse::<ServiceRecordUpdate>(&input)?)),
        "services.delete" => empty(session.delete_service(uuid(&input, "id")?)),
        "services.link" => value(session.link_service_item(uuid(&input, "service_id")?, parse::<ServiceRelationship>(&take(&mut input, "relationship")?)?)),
        "services.unlink" => value(session.unlink_service_item(uuid(&input, "service_id")?, &parse::<ServiceRelationship>(&take(&mut input, "relationship")?)?)),
        "services.move" => value(session.move_service_item(uuid(&input, "from_id")?, uuid(&input, "to_id")?, parse::<ServiceRelationship>(&take(&mut input, "relationship")?)?)),
        "services.merge" => value(session.merge_services(uuid(&input, "source_id")?, uuid(&input, "destination_id")?)),
        "services.split" => value(session.split_service(uuid(&input, "source_id")?, parse::<NewServiceRecord>(&take(&mut input, "service")?)?, parse::<Vec<ServiceRelationship>>(&take(&mut input, "relationships")?)?)),
        "services.ignore-suggestion" => empty(session.ignore_service_suggestion(parse::<ServiceIgnoredSuggestion>(&input)?)),
        "services.trash.list" => value(session.list_service_trash()),
        "services.trash.restore" => value(session.restore_service_trash(uuid(&input, "trash_id")?)),
        "services.trash.purge" => empty(session.purge_service_trash(uuid(&input, "trash_id")?)),
        "services.trash.empty" => empty(session.empty_service_trash()),
        "services.history.list" => value(session.service_history(uuid(&input, "id")?)),
        "services.history.restore" => value(session.restore_service_revision(uuid(&input, "service_id")?, uuid(&input, "revision_id")?)),
        "services.history.clear" => empty(session.clear_service_history(uuid(&input, "id")?)),
        "services.aggregation.preview" => value(session.service_aggregation_plan()),
        "services.aggregation.apply" => value(session.apply_service_aggregation_plan(string(&input, "plan_id")?)),
        "services.aggregation.rollback" => empty(session.rollback_service_aggregation_batch(uuid(&input, "batch_id")?)),
        "services.automatic-linking.get" => value(session.service_automatic_linking_enabled()),
        "services.automatic-linking.update" => value(session.set_service_automatic_linking_enabled(input.get("enabled").and_then(Value::as_bool).ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?)),
        "api-environments.list" => value(session.list_api_environments(uuid(&input, "service_id")?)),
        "api-environments.detail" => value(session.api_environment_detail(uuid(&input, "id")?)),
        "api-environments.add" => value(session.add_api_environment(parse::<NewApiEnvironment>(&input)?)),
        "api-environments.update" => value(session.update_api_environment(parse::<ApiEnvironmentUpdate>(&input)?)),
        "api-environments.delete" => empty(session.delete_api_environment(uuid(&input, "id")?)),
        "api-environments.trash.list" => value(session.list_api_environment_trash(uuid(&input, "service_id")?)),
        "api-environments.trash.restore" => value(session.restore_api_environment_trash(uuid(&input, "trash_id")?)),
        "api-environments.trash.purge" => empty(session.purge_api_environment_trash(uuid(&input, "trash_id")?)),
        "api-environments.history.list" => value(session.api_environment_history(uuid(&input, "id")?)),
        "api-environments.history.restore" => value(session.restore_api_environment_revision(uuid(&input, "id")?, uuid(&input, "revision_id")?)),
        "api-environments.history.clear" => empty(session.clear_api_environment_history(uuid(&input, "id")?)),
        "password.health" => value(session.password_health(unix_time_now())),
        _ => Err(VAULTMESH_STATUS_INVALID_ARGUMENT),
    }?;
    if matches!(operation, "_native.import.batch" | "_native.ssh.import" | "items.add" | "items.update" | "identities.add" | "identities.update" | "ssh.add" | "ssh.update" | "secrets.add" | "secrets.update") {
        session.reconcile_service_automatic_links().map_err(map_core_error)?;
    }
    Ok(result)
}

fn import_batch(session: &mut VaultSession, input: &Value) -> Result<Value, VaultmeshStatus> {
    let object = input.as_object().ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?;
    let logins = object
        .get("logins")
        .and_then(Value::as_array)
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?
        .iter()
        .map(parse::<NewLoginItem>)
        .collect::<Result<Vec<_>, _>>()?;
    let cards = object
        .get("payment_cards")
        .and_then(Value::as_array)
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?
        .iter()
        .map(parse::<NewPaymentCardItem>)
        .collect::<Result<Vec<_>, _>>()?;
    let ssh = object
        .get("ssh_credentials")
        .and_then(Value::as_array)
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?
        .iter()
        .map(parse::<NewSshCredentialItem>)
        .collect::<Result<Vec<_>, _>>()?;
    let counts = (logins.len(), cards.len(), ssh.len());
    for item in logins {
        session.add_item(item).map_err(map_core_error)?;
    }
    for item in cards {
        session.add_card(item).map_err(map_core_error)?;
    }
    let (imported_ssh, skipped_ssh) = session
        .import_ssh_credentials(ssh)
        .map_err(map_core_error)?;
    Ok(json!({
        "imported_count": counts.0 + counts.1 + imported_ssh.len(),
        "login_count": counts.0,
        "payment_card_count": counts.1,
        "ssh_credential_count": imported_ssh.len(),
        "skipped_count": skipped_ssh,
    }))
}

fn card_capture_status(session: &VaultSession, input: &Value) -> Result<Value, VaultmeshStatus> {
    let number = string(input, "card_number")?;
    let summaries = session.list_cards().map_err(map_core_error)?;
    let matched = if let Some(id) = optional_uuid(input, "card_id")? {
        summaries
            .iter()
            .any(|item| item.id == id)
            .then_some(id)
            .filter(|id| session.card_number_matches(*id, number).unwrap_or(false))
    } else {
        let matches: Vec<_> = summaries
            .iter()
            .filter(|item| {
                session
                    .card_number_matches(item.id, number)
                    .unwrap_or(false)
            })
            .collect();
        if matches.len() == 1 {
            Some(matches[0].id)
        } else {
            None
        }
    };
    let Some(id) = matched else {
        return Ok(json!({ "status": "new" }));
    };
    let detail = session.card_detail(id).map_err(map_core_error)?;
    let unchanged = normalized(detail.cardholder_name.as_str())
        == normalized(optional_string(input, "cardholder_name").unwrap_or_default())
        && detail.expiration_month as u64 == number_value(input, "expiration_month")?
        && detail.expiration_year as u64 == number_value(input, "expiration_year")?
        && optional_string(input, "billing_address").is_none_or(|value| {
            normalized(detail.billing_address.as_deref().unwrap_or_default()) == normalized(value)
        })
        && session
            .card_security_code_matches(id, optional_string(input, "security_code"))
            .map_err(map_core_error)?;
    Ok(json!({ "status": if unchanged { "unchanged" } else { "update" }, "card_id": id }))
}

fn login_password_changed(session: &VaultSession, input: &Value) -> Result<Value, VaultmeshStatus> {
    let current = session
        .password_for_copy(uuid(input, "id")?)
        .map_err(map_core_error)?;
    Ok(
        json!({ "changed": !constant_time_equal(current.as_bytes(), string(input, "password")?.as_bytes()) }),
    )
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn normalized(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn value<T: Serialize>(result: Result<T, VaultError>) -> Result<Value, VaultmeshStatus> {
    result.map_err(map_core_error).and_then(serializable)
}

fn empty(result: Result<(), VaultError>) -> Result<Value, VaultmeshStatus> {
    result.map(|()| json!({})).map_err(map_core_error)
}

fn serializable(value: impl Serialize) -> Result<Value, VaultmeshStatus> {
    serde_json::to_value(value).map_err(|_| VAULTMESH_STATUS_CORE_ERROR)
}

fn parse<T: DeserializeOwned>(value: &Value) -> Result<T, VaultmeshStatus> {
    serde_json::from_value(value.clone()).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT)
}

fn take(value: &mut Value, key: &str) -> Result<Value, VaultmeshStatus> {
    value
        .as_object_mut()
        .and_then(|object| object.remove(key))
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)
}

fn uuid(value: &Value, key: &str) -> Result<Uuid, VaultmeshStatus> {
    Uuid::parse_str(string(value, key)?).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT)
}

fn optional_uuid(value: &Value, key: &str) -> Result<Option<Uuid>, VaultmeshStatus> {
    optional_string(value, key)
        .map(|value| Uuid::parse_str(value).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT))
        .transpose()
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, VaultmeshStatus> {
    optional_string(value, key).ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)
}

fn owned_string(value: &Value, key: &str) -> Result<String, VaultmeshStatus> {
    string(value, key).map(str::to_owned)
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn number(value: &Value, key: &str) -> Result<u64, VaultmeshStatus> {
    number_value(value, key)
}

fn number_value(value: &Value, key: &str) -> Result<u64, VaultmeshStatus> {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_u64)
        .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)
}

fn unix_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn camel_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(convert_keys(object, camel_key)),
        Value::Array(values) => Value::Array(values.into_iter().map(camel_value).collect()),
        value => value,
    }
}

fn convert_keys(object: Map<String, Value>, convert: fn(&str) -> String) -> Map<String, Value> {
    object
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                Value::Object(value) => Value::Object(convert_keys(value, convert)),
                Value::Array(values) => Value::Array(
                    values
                        .into_iter()
                        .map(|value| match value {
                            Value::Object(value) => Value::Object(convert_keys(value, convert)),
                            value => value,
                        })
                        .collect(),
                ),
                value => value,
            };
            (convert(&key), value)
        })
        .collect()
}

fn snake_key(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            output.push('_');
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn camel_key(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase = false;
    for character in value.chars() {
        if character == '_' {
            uppercase = true;
        } else if uppercase {
            output.push(character.to_ascii_uppercase());
            uppercase = false;
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
#[path = "browser_ops_tests.rs"]
mod tests;
