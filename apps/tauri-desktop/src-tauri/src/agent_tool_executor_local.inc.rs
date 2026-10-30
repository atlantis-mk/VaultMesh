pub(super) fn execute_agent_tool(
    context: &AgentToolContext<'_>,
    tool: &str,
    account_ref: Option<&str>,
    parameters: &Value,
    cancellation: &AtomicBool,
    scope: &AgentExecutionScope,
) -> Result<Value, AgentBrokerError> {
    let runtime = context.runtime;
    let resources = context.resources;
    let ssh_sessions = context.ssh_sessions;
    let ssh_directory = context.ssh_directory;
    let app = context.app;
    let dialog_focus = context.dialog_focus;
    let vault_unavailable = || {
        AgentBrokerError::new(
            "vault-unavailable",
            "The local Vault runtime is unavailable.",
            true,
        )
    };
    if cancellation.load(Ordering::Acquire) {
        return Err(AgentBrokerError::new(
            "session-cancelled",
            "The connection session was revoked or expired.",
            false,
        ));
    }
    match tool {
        "vaultmesh_local_file_select" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let purpose = parameters
                .get("purpose")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The local file purpose is invalid.",
                        false,
                    )
                })?;
            match purpose {
                "ssh-upload" => {
                    required_direct_ssh_policy(scope, account_ref, tool)?;
                }
                "http-upload" => validate_direct_connector_action(
                    runtime,
                    scope,
                    account_ref,
                    tool,
                    "http",
                    parameters,
                )?,
                _ => {
                    return Err(AgentBrokerError::new(
                        "invalid-parameters",
                        "The local file purpose is invalid.",
                        false,
                    ));
                }
            }
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            let _dialog_guard = dialog_focus.begin();
            let selected = app
                .dialog()
                .file()
                .set_title("选择供 VaultMesh Agent 使用的本地文件")
                .blocking_pick_file()
                .and_then(|path| path.into_path().ok());
            let Some(path) = selected else {
                return Ok(json!({ "cancelled": true }));
            };
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            let (basename, mime, bytes) = load_selected_file(&path).map_err(|code| {
                AgentBrokerError::new(
                    code,
                    "The selected local file could not be accepted safely.",
                    false,
                )
            })?;
            let result = resources
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .add_input_file(AgentInputFileSelection {
                    scope,
                    account_ref,
                    purpose,
                    basename: &basename,
                    mime: &mime,
                    bytes,
                    now_millis: unix_millis(),
                })
                .map_err(|code| {
                    AgentBrokerError::new(
                        code,
                        "The selected local file could not be accepted safely.",
                        false,
                    )
                })?;
            Ok(json!({ "cancelled": false, "file": result }))
        }
        "vaultmesh_result_save" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let result_ref = parameters
                .get("resultRef")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The result handle is invalid.",
                        false,
                    )
                })?;
            if scope.direct_ssh_policy.is_some() {
                required_direct_ssh_policy(scope, account_ref, tool)?;
            } else if let Some(policy) = scope.direct_connector_policy.as_ref() {
                validate_direct_connector_action(
                    runtime,
                    scope,
                    account_ref,
                    tool,
                    &policy.connector_kind,
                    parameters,
                )?;
            } else {
                return Err(AgentBrokerError::new(
                    "account-policy-denied",
                    "The result-save action is missing its immutable direct plan.",
                    false,
                ));
            }
            let result = resources
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .result_for_save(result_ref, scope, account_ref, unix_millis())
                .map_err(|code| {
                    AgentBrokerError::new(
                        code,
                        "The broker-owned result handle is unavailable.",
                        false,
                    )
                })?;
            let _dialog_guard = dialog_focus.begin();
            let destination = app
                .dialog()
                .file()
                .set_title("保存 VaultMesh Agent 结果")
                .set_file_name(&result.suggested_basename)
                .blocking_save_file()
                .and_then(|path| path.into_path().ok());
            let Some(destination) = destination else {
                return Ok(json!({ "cancelled": true }));
            };
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            save_result_bytes(&destination, result.bytes.as_slice()).map_err(|code| {
                AgentBrokerError::new(
                    code,
                    "The broker-owned result could not be saved safely.",
                    false,
                )
            })?;
            resources
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .complete_result_save(result.result_id);
            Ok(json!({ "cancelled": false, "saved": true }))
        }
        "vaultmesh_items_list_metadata" => {
            let kind = parameters.get("kind").and_then(Value::as_str);
            if kind.is_some_and(|kind| {
                !matches!(kind, "login" | "card" | "identity" | "ssh" | "secret")
            }) {
                return Err(AgentBrokerError::new(
                    "invalid-parameters",
                    "The requested item kind is invalid.",
                    false,
                ));
            }
            runtime
                .lock()
                .map_err(|_| vault_unavailable())?
                .agent_items_metadata(kind)
                .map_err(|_| vault_unavailable())
        }
        "vaultmesh_item_get_metadata" => {
            let item_ref = parameters
                .get("itemRef")
                .and_then(Value::as_str)
                .and_then(|item_ref| uuid::Uuid::parse_str(item_ref).ok())
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The item reference is invalid.",
                        false,
                    )
                })?;
            runtime
                .lock()
                .map_err(|_| vault_unavailable())?
                .agent_item_metadata(item_ref)
                .map_err(|_| {
                    AgentBrokerError::new(
                        "item-unavailable",
                        "The approved item metadata is unavailable.",
                        false,
                    )
                })
        }
        "vaultmesh_ssh_agent_open" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
            let mut registry = context.ssh_agent_registry.lock().map_err(|_| {
                AgentBrokerError::new("internal-error", "SSH agent registry unavailable.", true)
            })?;
            let material = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                agent_ssh_runtime::collect_direct_agent_ssh_agent_material(
                    &mut runtime,
                    policy,
                    cancellation,
                    Some(&mut registry),
                )
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH target or credential is unavailable.",
                        false,
                    )
                })?
            };
            let duration_minutes = parameters
                .get("durationMinutes")
                .and_then(Value::as_u64)
                .unwrap_or(15);
            let base_dir = app.path().app_data_dir().map_err(|_| {
                AgentBrokerError::new("storage-error", "Failed to resolve app data directory.", false)
            })?;
            let session_info = registry
                .start_session(
                    &base_dir,
                    account_ref,
                    &material.account_label,
                    material.private_key,
                    material.passphrase,
                    duration_minutes,
                )
                .map_err(|err| {
                    let mut e = AgentBrokerError::new("session-error", "Failed to start SSH agent session.", false);
                    e.details = Some(json!({ "reason": err }));
                    e
                })?;
            let mut result = serde_json::to_value(session_info).map_err(|_| {
                AgentBrokerError::new("internal-error", "Failed to serialize session info.", false)
            })?;
            result["targetHost"] = json!(policy.host);
            result["targetPort"] = json!(policy.port);
            result["targetUser"] = json!(policy.username);
            result["sshCommand"] = json!(format!(
                "ssh -p {} {}@{}",
                policy.port, policy.username, policy.host
            ));
            result["rsyncCommand"] = json!(format!(
                "rsync -avz -e \"ssh -p {}\" <src> {}@{}:<dest>",
                policy.port, policy.username, policy.host
            ));
            result["scpCommand"] = json!(format!(
                "scp -P {} <src> {}@{}:<dest>",
                policy.port, policy.username, policy.host
            ));
            Ok(result)
        }
        "vaultmesh_ssh_agent_close" => {
            let session_ref = parameters
                .get("sessionRef")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The session reference is required.",
                        false,
                    )
                })?;
            let mut registry = context.ssh_agent_registry.lock().map_err(|_| {
                AgentBrokerError::new("internal-error", "SSH agent registry unavailable.", true)
            })?;
            let closed = registry.close_session(session_ref);
            Ok(json!({
                "closed": closed,
                "sessionRef": session_ref,
            }))
        }
        "vaultmesh_ssh_exec" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_exec_request(&mut runtime, policy, parameters)
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH target or credential is unavailable.",
                        false,
                    )
                })?
            };
            ssh_service::execute_agent_command(request, cancellation).map_err(|_| {
                if cancellation.load(Ordering::Acquire) {
                    AgentBrokerError::new(
                        "session-cancelled",
                        "The connection session was revoked or expired.",
                        false,
                    )
                } else {
                    AgentBrokerError::new(
                        "ssh-operation-failed",
                        "The approved SSH operation failed.",
                        false,
                    )
                }
            })
        }
        "vaultmesh_ssh_upload" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let file_ref = parameters
                .get("fileRef")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AgentBrokerError::new(
                        "invalid-parameters",
                        "The broker-owned file handle is invalid.",
                        false,
                    )
                })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_transfer_request(&mut runtime, policy, parameters)
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH account or credential is unavailable.",
                        false,
                    )
                })?
            };
            let file = resources
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .consume_input_file(file_ref, scope, account_ref, "ssh-upload", unix_millis())
                .map_err(|code| {
                    AgentBrokerError::new(
                        code,
                        "The broker-owned file handle is unavailable.",
                        false,
                    )
                })?;
            let result = ssh_service::execute_agent_upload(request, &file.bytes, cancellation)
                .map_err(|_| {
                    if cancellation.load(Ordering::Acquire) {
                        AgentBrokerError::new(
                            "session-cancelled",
                            "The connection session was revoked or expired.",
                            false,
                        )
                    } else {
                        AgentBrokerError::new(
                            "ssh-operation-failed",
                            "The approved SSH upload failed safely.",
                            false,
                        )
                    }
                })?;
            if result.get("sha256").and_then(Value::as_str) != Some(file.digest.as_str()) {
                return Err(AgentBrokerError::internal());
            }
            Ok(result)
        }
        "vaultmesh_ssh_download" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_transfer_request(&mut runtime, policy, parameters)
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH account or credential is unavailable.",
                        false,
                    )
                })?
            };
            let download =
                ssh_service::execute_agent_download(request, cancellation).map_err(|_| {
                    if cancellation.load(Ordering::Acquire) {
                        AgentBrokerError::new(
                            "session-cancelled",
                            "The connection session was revoked or expired.",
                            false,
                        )
                    } else {
                        AgentBrokerError::new(
                            "ssh-operation-failed",
                            "The approved SSH download failed safely.",
                            false,
                        )
                    }
                })?;
            resources
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .add_result(
                    scope,
                    account_ref,
                    "ssh-download",
                    &download.basename,
                    "application/octet-stream",
                    download.bytes,
                    unix_millis(),
                )
                .map_err(|code| {
                    AgentBrokerError::new(
                        code,
                        "The SSH download result could not be retained safely.",
                        false,
                    )
                })
        }
        "vaultmesh_ssh_host_setup" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_host_setup_request(
                    &mut runtime,
                    ssh_directory,
                    policy,
                    parameters,
                )
                .map_err(|_| {
                    AgentBrokerError::new(
                        "ssh-host-setup-conflict",
                        "The approved OpenSSH host setup conflicts with local state or the account changed.",
                        false,
                    )
                })?
            };
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            let config_was_ready = request.commit.config_ready;
            if request.existing_binding
                && ssh_service::verify_key_login(
                    &request.target,
                    &request.expected_host_key_fingerprint,
                    &request.verification_key,
                )
            {
                request.commit.commit_config().map_err(|_| {
                    AgentBrokerError::new(
                        "ssh-host-config-incomplete",
                        "The generated identity is accepted by the server, but the local OpenSSH config was not committed. Retry the same exact setup to resume safely.",
                        true,
                    )
                })?;
                return Ok(json!({
                    "alias": request.commit.alias,
                    "command": format!("ssh {}", request.commit.alias),
                    "credentialRef": request.key_item_id,
                    "publicKeyFingerprint": request.commit.public_fingerprint,
                    "status": if config_was_ready {
                        "alreadyConfigured"
                    } else {
                        "configured"
                    },
                    "keyLoginVerified": true
                }));
            }
            let authentication = request.bootstrap_authentication.ok_or_else(|| {
                AgentBrokerError::new(
                    "ssh-host-setup-incomplete",
                    "The managed identity is not yet accepted by the server and the bootstrap credential is unavailable.",
                    true,
                )
            })?;
            let install = PublicKeyInstallRequest {
                target: request.target,
                expected_host_key_fingerprint: request.expected_host_key_fingerprint,
                public_key: request.public_key,
                authentication,
                verification_key: Some(request.verification_key),
            };
            let result = ssh_service::install_public_key_cancellable(install, cancellation)
                .map_err(|_| {
                    if cancellation.load(Ordering::Acquire) {
                        AgentBrokerError::new(
                            "session-cancelled",
                            "The connection session was revoked or expired. The managed local identity was retained for a safe explicit retry.",
                            false,
                        )
                    } else {
                        AgentBrokerError::new(
                            "ssh-host-setup-incomplete",
                            "The managed local identity was retained, but the approved server key installation did not complete. Retry the same exact setup to resume safely.",
                            true,
                        )
                    }
                })?;
            if !result.key_login_verified {
                return Err(AgentBrokerError::new(
                    "ssh-host-key-login-failed",
                    "The server did not accept the generated SSH identity. The managed local identity was retained for a safe explicit retry.",
                    true,
                ));
            }
            request.commit.commit_config().map_err(|_| {
                AgentBrokerError::new(
                    "ssh-host-config-incomplete",
                    "The server accepted the generated identity, but the local OpenSSH config was not committed. Retry the same exact setup to resume safely.",
                    true,
                )
            })?;
            Ok(json!({
                "alias": request.commit.alias,
                "command": format!("ssh {}", request.commit.alias),
                "credentialRef": request.key_item_id,
                "publicKeyFingerprint": request.commit.public_fingerprint,
                "status": if config_was_ready && result.status == "alreadyPresent" {
                    "alreadyConfigured"
                } else {
                    "configured"
                },
                "keyLoginVerified": true
            }))
        }
        "vaultmesh_ssh_public_key_install" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_public_key_install_request(
                    &mut runtime,
                    policy,
                    parameters,
                )
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH account, credential, or public key is unavailable.",
                        false,
                    )
                })?
            };
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            let result = ssh_service::install_public_key_cancellable(request, cancellation)
                .map_err(|_| {
                    if cancellation.load(Ordering::Acquire) {
                        AgentBrokerError::new(
                            "session-cancelled",
                            "The connection session was revoked or expired.",
                            false,
                        )
                    } else {
                        AgentBrokerError::new(
                            "ssh-operation-failed",
                            "The approved SSH public-key installation failed safely.",
                            false,
                        )
                    }
                })?;
            if cancellation.load(Ordering::Acquire) {
                return Err(AgentBrokerError::new(
                    "session-cancelled",
                    "The connection session was revoked or expired.",
                    false,
                ));
            }
            Ok(json!({
                "status": result.status,
                "fingerprint": result.fingerprint,
                "keyLoginVerified": result.key_login_verified,
                "keyLoginVerification": result.key_login_verification
            }))
        }
        "vaultmesh_ssh_pty_open" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let terminal = parameters
                .get("terminal")
                .and_then(Value::as_str)
                .unwrap_or("xterm-256color");
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_pty_request(&mut runtime, policy)
                .map_err(|_| {
                    AgentBrokerError::new(
                        "account-unavailable",
                        "The approved SSH PTY account or credential is unavailable.",
                        false,
                    )
                })?
            };
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .open(request, terminal, scope, account_ref, cancellation)
                .map_err(agent_ssh_session_error)
        }
        "vaultmesh_ssh_pty_read" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let session_ref = agent_string_parameter(parameters, "sessionRef")?;
            let after_sequence = parameters
                .get("afterSequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| agent_ssh_session_error("invalid-parameters"))?;
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .read(
                    session_ref,
                    after_sequence,
                    scope,
                    account_ref,
                    cancellation,
                )
                .map_err(agent_ssh_session_error)
        }
        "vaultmesh_ssh_pty_write" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let session_ref = agent_string_parameter(parameters, "sessionRef")?;
            let input = agent_string_parameter(parameters, "input")?;
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .write(session_ref, input, scope, account_ref, cancellation)
                .map_err(agent_ssh_session_error)
        }
        "vaultmesh_ssh_pty_resize" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let session_ref = agent_string_parameter(parameters, "sessionRef")?;
            let columns = parameters
                .get("columns")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| agent_ssh_session_error("invalid-parameters"))?;
            let rows = parameters
                .get("rows")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| agent_ssh_session_error("invalid-parameters"))?;
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .resize(session_ref, columns, rows, scope, account_ref)
                .map_err(agent_ssh_session_error)
        }
        "vaultmesh_ssh_pty_close" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let session_ref = agent_string_parameter(parameters, "sessionRef")?;
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .close(session_ref, scope, account_ref)
                .map_err(agent_ssh_session_error)
        }
        "vaultmesh_ssh_tunnel_open" => {
            let account_ref = account_ref.ok_or_else(|| {
                AgentBrokerError::new(
                    "account-required",
                    "An approved account reference is required.",
                    false,
                )
            })?;
            let request = {
                let mut runtime = runtime.lock().map_err(|_| vault_unavailable())?;
                let policy = required_direct_ssh_policy(scope, account_ref, tool)?;
                collect_direct_agent_ssh_tunnel_request(&mut runtime, policy, parameters)
                .map_err(|_| {
                        AgentBrokerError::new(
                            "account-policy-denied",
                            "The approved SSH tunnel endpoint is unavailable.",
                            false,
                        )
                    })?
            };
            ssh_sessions
                .lock()
                .map_err(|_| AgentBrokerError::internal())?
                .open_tunnel(request, scope, account_ref, unix_millis(), cancellation)
                .map_err(agent_ssh_session_error)
        }
        _ => execute_agent_tool_remote(
            context, tool, account_ref, parameters, cancellation, scope,
        ),
    }
}
