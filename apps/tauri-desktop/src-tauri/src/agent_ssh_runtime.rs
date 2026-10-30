use super::*;

pub(super) struct AgentSshAgentOpenMaterial {
    pub(super) account_label: String,
    pub(super) private_key: Zeroizing<String>,
    pub(super) passphrase: Option<Zeroizing<String>>,
}

pub(super) fn collect_direct_agent_ssh_agent_material(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    cancellation: &std::sync::atomic::AtomicBool,
    registry: Option<&mut crate::agent_ssh_agent::SshAgentRegistry>,
) -> Result<AgentSshAgentOpenMaterial, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_agent_open" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let account = direct_ssh_account(runtime, policy)?;
    let label = policy.account_label.clone();

    // 1. If the account directly holds an SSH private key in VaultMesh, use it.
    if account.has_private_key {
        let key_material = runtime_private_key(runtime, &account, None)?;
        return Ok(AgentSshAgentOpenMaterial {
            account_label: label,
            private_key: key_material.private_key,
            passphrase: key_material.passphrase,
        });
    }

    // 2. If the account already has an encrypted managed key in VaultMesh, reuse it.
    if let Some(managed_key) = runtime.find_managed_ssh_key_for_account(policy.account_ref, &policy.host_key_sha256)? {
        return Ok(AgentSshAgentOpenMaterial {
            account_label: label,
            private_key: managed_key.private_key,
            passphrase: None,
        });
    }

    // 3. If the account has a stored password, auto-bootstrap an ephemeral ED25519 key on the server.
    if account.has_password {
        if cancellation.load(std::sync::atomic::Ordering::Acquire) {
            return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
        }
        let account_ref_str = policy.account_ref.to_string();

        // 3a. Check if we already have an active ephemeral key in memory cache
        if let Some(reg) = registry.as_ref() {
            if let Some(cached_priv_key) = reg.get_ephemeral_key(&account_ref_str, &policy.host_key_sha256) {
                return Ok(AgentSshAgentOpenMaterial {
                    account_label: label,
                    private_key: cached_priv_key,
                    passphrase: None,
                });
            }
        }

        let password = runtime.protected_value(
            VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
            VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
            &account.id,
            None,
        )?;

        // Build alias: auto-<device_id[..8]>-<account_id[..8]>
        let device_id = registry.as_ref().map(|r| r.device_id()).unwrap_or("local");
        let dev_prefix = if device_id.len() >= 8 { &device_id[..8] } else { device_id };
        let acc_prefix = &account_ref_str[..8.min(account_ref_str.len())];
        let alias = format!("auto-{dev_prefix}-{acc_prefix}");

        let identity = crate::ssh_host_setup::generate_ssh_host_identity(&alias)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;

        let install_request = PublicKeyInstallRequest {
            target: direct_ssh_target(policy),
            expected_host_key_fingerprint: policy.host_key_sha256.clone(),
            public_key: identity.public_key.clone(),
            authentication: AuthenticationMaterial::StoredPassword(password),
            verification_key: Some(PrivateKeyMaterial {
                public_key: Some(identity.public_key.clone()),
                private_key: identity.private_key.clone(),
                passphrase: None,
            }),
        };
        ssh_service::install_public_key_cancellable(install_request, cancellation)
            .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;

        let private_key = identity.private_key.clone();
        if let Some(reg) = registry {
            reg.store_ephemeral_key(
                &account_ref_str,
                &policy.host_key_sha256,
                identity.public_key,
                identity.private_key,
            );
        }

        return Ok(AgentSshAgentOpenMaterial {
            account_label: label,
            private_key,
            passphrase: None,
        });
    }

    Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into())
}

pub(super) struct AgentSshHostSetupRequest {
    pub(super) commit: crate::ssh_host_setup::SshHostSetupCommit,
    pub(super) key_item_id: uuid::Uuid,
    pub(super) existing_binding: bool,
    pub(super) target: SshTarget,
    pub(super) expected_host_key_fingerprint: String,
    pub(super) public_key: Zeroizing<String>,
    pub(super) verification_key: PrivateKeyMaterial,
    pub(super) bootstrap_authentication: Option<AuthenticationMaterial>,
}

pub(super) fn collect_direct_agent_ssh_exec_request(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    parameters: &Value,
) -> Result<AgentSshExecRequest, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_exec" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let program = parameters
        .get("program")
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let arguments = parameters
        .get("arguments")
        .and_then(Value::as_array)
        .map(|arguments| {
            arguments
                .iter()
                .map(|argument| {
                    argument
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let command = crate::agent_ssh_command_policy::validate_and_serialize(program, &arguments)
        .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let account = direct_ssh_account(runtime, policy)?;
    let authentication = direct_ssh_authentication(runtime, &account)?;
    Ok(AgentSshExecRequest {
        target: SshTarget {
            host: policy.host.clone(),
            port: policy.port,
            username: policy.username.clone(),
        },
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        command,
        authentication,
        allowed_fields: vec![
            "exit_status".to_owned(),
            "stdout".to_owned(),
            "stderr".to_owned(),
        ],
        max_output_bytes: policy.max_output_bytes,
    })
}

pub(super) fn collect_direct_agent_ssh_transfer_request(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    parameters: &Value,
) -> Result<AgentSshTransferRequest, DesktopRuntimeError> {
    if !matches!(
        policy.tool.as_str(),
        "vaultmesh_ssh_upload" | "vaultmesh_ssh_download"
    ) {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let remote_path = parameters
        .get("remotePath")
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let account = direct_ssh_account(runtime, policy)?;
    let authentication = direct_ssh_authentication(runtime, &account)?;
    Ok(AgentSshTransferRequest {
        target: direct_ssh_target(policy),
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        remote_path: remote_path.to_owned(),
        remote_path_prefixes: policy.remote_path_prefixes.clone(),
        authentication,
    })
}

pub(super) fn collect_direct_agent_ssh_pty_request(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
) -> Result<AgentSshPtyRequest, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_pty_open" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let account = direct_ssh_account(runtime, policy)?;
    let authentication = direct_ssh_authentication(runtime, &account)?;
    Ok(AgentSshPtyRequest {
        target: direct_ssh_target(policy),
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        authentication,
        max_output_bytes: policy.max_output_bytes,
    })
}

pub(super) fn collect_direct_agent_ssh_tunnel_request(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    parameters: &Value,
) -> Result<AgentSshTunnelRequest, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_tunnel_open" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let tunnel = policy
        .tunnel
        .as_ref()
        .filter(|tunnel| {
            parameters.get("endpoint").and_then(Value::as_str) == Some(tunnel.name.as_str())
        })
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let connector_ref = policy
        .connector_ref
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let connector = runtime.agent_connector_definition(connector_ref)?;
    let connector_matches = connector.enabled
        && connector.connector_kind == AgentConnectorKind::Ssh
        && connector.credential_refs.first().is_some_and(|credential| {
            credential.kind == AgentCredentialKind::Ssh && credential.item_id == policy.account_ref
        })
        && match &connector.target_policy {
            AgentTargetPolicy::Ssh {
                host,
                port,
                host_key_sha256,
                tunnel_policies,
                ..
            } => {
                host.trim().eq_ignore_ascii_case(&policy.host)
                    && *port == policy.port
                    && host_key_sha256 == &policy.host_key_sha256
                    && tunnel_policies.iter().any(|current| current == tunnel)
            }
            _ => false,
        };
    if !connector_matches {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let account = direct_ssh_account(runtime, policy)?;
    let authentication = direct_ssh_authentication(runtime, &account)?;
    Ok(AgentSshTunnelRequest {
        target: direct_ssh_target(policy),
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        authentication,
        local_host: tunnel.local_host.clone(),
        local_port: tunnel.local_port,
        destination_host: tunnel.destination_host.clone(),
        destination_port: tunnel.destination_port,
        max_connections: tunnel.max_connections,
        ttl_millis: tunnel.ttl_millis,
    })
}

pub(super) fn collect_direct_agent_ssh_public_key_install_request(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    parameters: &Value,
) -> Result<PublicKeyInstallRequest, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_public_key_install" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let public_key_ref = parameters
        .get("publicKeyRef")
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let key = runtime_ssh_detail(runtime, &public_key_ref.to_string())?;
    if key.record_kind != "key" || !key.has_public_key || key.master_password_reprompt {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let account = direct_ssh_account(runtime, policy)?;
    let public_key = runtime.protected_value(
        VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
        VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
        &key.id,
        None,
    )?;
    let verification_key = key
        .has_private_key
        .then(|| runtime_private_key(runtime, &key, None))
        .transpose()?;
    let authentication = direct_ssh_authentication(runtime, &account)?;
    Ok(PublicKeyInstallRequest {
        target: direct_ssh_target(policy),
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        public_key,
        authentication,
        verification_key,
    })
}

pub(super) fn collect_direct_agent_ssh_host_setup_request(
    runtime: &mut DesktopRuntime,
    ssh_directory: &std::path::Path,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
    parameters: &Value,
) -> Result<AgentSshHostSetupRequest, DesktopRuntimeError> {
    if policy.tool != "vaultmesh_ssh_host_setup" {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let alias = parameters
        .get("alias")
        .and_then(Value::as_str)
        .filter(|alias| crate::ssh_host_setup::validate_ssh_host_alias(alias).is_ok())
        .ok_or_else(|| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let account = direct_ssh_account(runtime, policy)?;
    let target = direct_ssh_target(policy);
    let (managed_key, existing_binding) =
        match runtime.managed_ssh_host_key(policy.account_ref, alias, &policy.host_key_sha256)? {
            Some(key) => (key, true),
            None => {
                let legacy = crate::ssh_host_setup::read_legacy_ssh_host_identity(
                    ssh_directory,
                    &policy.account_ref.to_string(),
                    alias,
                    &target,
                    &policy.host_key_sha256,
                )
                .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
                let (generated, imported_legacy) = match legacy {
                    Some(identity) => (identity, true),
                    None => {
                        crate::ssh_host_setup::preflight_new_ssh_host_identity(
                            ssh_directory,
                            alias,
                            &target,
                        )
                        .map_err(|_| {
                            DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT)
                        })?;
                        (
                            crate::ssh_host_setup::generate_ssh_host_identity(alias).map_err(
                                |_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT),
                            )?,
                            false,
                        )
                    }
                };
                (
                    runtime.add_managed_ssh_host_key(
                        policy.account_ref,
                        alias.to_owned(),
                        policy.host_key_sha256.clone(),
                        generated.public_key,
                        generated.private_key,
                    )?,
                    imported_legacy,
                )
            }
        };
    let prepared = crate::ssh_host_setup::prepare_ssh_host_identity(
        ssh_directory,
        alias,
        &target,
        &managed_key.public_key,
        &managed_key.private_key,
    )
    .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let (commit, public_key, verification_key) = prepared.into_parts();
    let bootstrap_authentication = match direct_ssh_authentication(runtime, &account) {
        Ok(authentication) => Some(authentication),
        Err(_) if existing_binding => None,
        Err(error) => return Err(error),
    };
    Ok(AgentSshHostSetupRequest {
        commit,
        key_item_id: managed_key.key_item_id,
        existing_binding,
        target,
        expected_host_key_fingerprint: policy.host_key_sha256.clone(),
        public_key,
        verification_key,
        bootstrap_authentication,
    })
}

fn direct_ssh_account(
    runtime: &mut DesktopRuntime,
    policy: &crate::agent_broker::AgentDirectSshPolicy,
) -> Result<SshRuntimeDetail, DesktopRuntimeError> {
    let account = runtime_ssh_detail(runtime, &policy.account_ref.to_string())?;
    let current_target = ssh_target(&account)
        .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    if account.master_password_reprompt
        || current_target.host.trim().to_ascii_lowercase() != policy.host
        || current_target.port != policy.port
        || current_target.username.trim() != policy.username
    {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    Ok(account)
}

fn direct_ssh_authentication(
    runtime: &mut DesktopRuntime,
    account: &SshRuntimeDetail,
) -> Result<AuthenticationMaterial, DesktopRuntimeError> {
    if account.has_private_key {
        Ok(AuthenticationMaterial::AuthenticationKey(
            runtime_private_key(runtime, account, None)?,
        ))
    } else if account.has_password {
        Ok(AuthenticationMaterial::StoredPassword(
            runtime.protected_value(
                VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
                &account.id,
                None,
            )?,
        ))
    } else {
        Ok(AuthenticationMaterial::SshAgent)
    }
}

fn direct_ssh_target(policy: &crate::agent_broker::AgentDirectSshPolicy) -> SshTarget {
    SshTarget {
        host: policy.host.clone(),
        port: policy.port,
        username: policy.username.clone(),
    }
}

pub(super) fn collect_ssh_external_launch_material(
    runtime: &mut DesktopRuntime,
    account_id: &str,
    client_id: ssh_external::ExternalClientId,
    copy_password: bool,
    permits_transient_secret: bool,
    registry: Option<&mut crate::agent_ssh_agent::SshAgentRegistry>,
) -> Result<SshExternalLaunchMaterial, DesktopRuntimeError> {
    let detail = runtime_ssh_detail(runtime, account_id)?;
    let target = ssh_target(&detail).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT)?;
    let target = ssh_external::LaunchTarget::new(&target.host, target.port, &target.username)
        .map_err(|_| DesktopRuntimeError::from(VAULTMESH_STATUS_INVALID_ARGUMENT))?;
    let can_access_secret = (client_id == ssh_external::ExternalClientId::SystemTerminal
        || client_id == ssh_external::ExternalClientId::Vscode)
        && !detail.master_password_reprompt
        && permits_transient_secret;

    let mut private_key: Option<Zeroizing<String>> = None;
    let mut passphrase: Option<Zeroizing<String>> = None;

    if can_access_secret && detail.has_private_key {
        let key_material = runtime_private_key(runtime, &detail, None)?;
        private_key = Some(key_material.private_key);
        passphrase = key_material.passphrase;
    } else if can_access_secret && detail.has_password {
        if let Ok(account_ref) = uuid::Uuid::parse_str(account_id) {
            let target_endpoint = SshTarget {
                host: target.host().to_owned(),
                port: target.port(),
                username: target.username().to_owned(),
            };
            if let Ok(host_key_preview) = ssh_service::inspect_host_key(target_endpoint.clone()) {
                if let Some(reg) = registry.as_ref() {
                    if let Some(cached_priv_key) = reg.get_ephemeral_key(account_id, &host_key_preview.fingerprint) {
                        private_key = Some(cached_priv_key);
                    }
                }
                if private_key.is_none() {
                    if let Ok(Some(managed_key)) = runtime.find_managed_ssh_key_for_account(
                        account_ref,
                        &host_key_preview.fingerprint,
                    ) {
                        private_key = Some(managed_key.private_key);
                    } else if let Ok(password) = runtime.protected_value(
                        VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                        VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
                        &detail.id,
                        None,
                    ) {
                        let device_id = registry.as_ref().map(|r| r.device_id()).unwrap_or("local");
                        let dev_prefix = if device_id.len() >= 8 { &device_id[..8] } else { device_id };
                        let acc_prefix = &account_id[..8.min(account_id.len())];
                        let alias = format!("auto-{dev_prefix}-{acc_prefix}");
                        if let Ok(identity) = crate::ssh_host_setup::generate_ssh_host_identity(&alias) {
                            let cancellation = std::sync::atomic::AtomicBool::new(false);
                            let install_request = PublicKeyInstallRequest {
                                target: target_endpoint,
                                expected_host_key_fingerprint: host_key_preview.fingerprint.clone(),
                                public_key: identity.public_key.clone(),
                                authentication: AuthenticationMaterial::StoredPassword(password),
                                verification_key: Some(PrivateKeyMaterial {
                                    public_key: Some(identity.public_key.clone()),
                                    private_key: identity.private_key.clone(),
                                    passphrase: None,
                                }),
                            };
                            if ssh_service::install_public_key_cancellable(install_request, &cancellation).is_ok() {
                                private_key = Some(identity.private_key.clone());
                                if let Some(reg) = registry {
                                    reg.store_ephemeral_key(
                                        account_id,
                                        &host_key_preview.fingerprint,
                                        identity.public_key,
                                        identity.private_key,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let has_key = private_key.is_some();
    let should_copy_password = client_id != ssh_external::ExternalClientId::CopyCommand
        && !has_key
        && copy_password
        && detail.has_password;
    let password_copy_skipped =
        should_copy_password && (detail.master_password_reprompt || !permits_transient_secret);
    let password = (should_copy_password && !password_copy_skipped)
        .then(|| {
            runtime.protected_value(
                VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
                &detail.id,
                None,
            )
        })
        .transpose()?;
    let authentication = if has_key {
        "key"
    } else if detail.has_password {
        "password"
    } else {
        "sshAgent"
    };
    Ok(SshExternalLaunchMaterial {
        target,
        account_label: detail.username.clone(),
        private_key,
        passphrase,
        password,
        password_copy_skipped,
        authentication,
    })
}
