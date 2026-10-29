use super::*;

pub(super) async fn handle_ssh_scan(
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    let operation = operation.to_owned();
    let directory = state.ssh_directory.clone();
    let runtime = Arc::clone(&state.runtime);
    let service = Arc::clone(&state.ssh_scan);
    tauri::async_runtime::spawn_blocking(move || {
        let mut runtime = runtime
            .lock()
            .map_err(|_| "保险库运行时暂时不可用。".to_owned())?;
        runtime
            .refresh_from_disk()
            .map_err(|error| error.public_message().to_owned())?;
        if !runtime.status().unlocked {
            return Err("请先解锁保险库。".to_owned());
        }
        let mut service = service
            .lock()
            .map_err(|_| "SSH 扫描状态暂时不可用。".to_owned())?;
        match operation.as_str() {
            "ssh.scan" => service.scan(&directory, &mut runtime, unix_millis()),
            "ssh.scan.commit" => {
                let session_id = required_string(&input, "sessionId")?;
                let entry_ids = input
                    .get("entryIds")
                    .and_then(Value::as_array)
                    .filter(|values| !values.is_empty() && values.len() <= 200)
                    .ok_or_else(|| "请求参数无效。".to_owned())?;
                let public_key_overrides = match input.get("publicKeyOverrides") {
                    None => None,
                    Some(Value::Object(values)) => Some(values),
                    Some(_) => return Err("请求参数无效。".to_owned()),
                };
                service.commit(
                    &session_id,
                    entry_ids,
                    public_key_overrides,
                    &mut runtime,
                    unix_millis(),
                )
            }
            "ssh.scan.cancel" => {
                service.cancel(&required_string(&input, "sessionId")?, unix_millis())?;
                Ok(json!({}))
            }
            _ => Err("该 SSH 扫描操作不被允许。".to_owned()),
        }
    })
    .await
    .map_err(|_| "SSH 扫描操作未能完成。".to_owned())?
}

pub(super) async fn handle_ssh_privileged(
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    match operation {
        "ssh.inspect-host-key" => {
            let input: SshHostKeyInspectInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let target = with_runtime(state, move |runtime| {
                let detail = runtime_ssh_detail(runtime, &input.account_id)?;
                ssh_target(&detail).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT.into())
            })
            .await?;
            tauri::async_runtime::spawn_blocking(move || ssh_service::inspect_host_key(target))
                .await
                .map_err(|_| "SSH 主机检查未能完成。".to_owned())?
                .and_then(|result| {
                    serde_json::to_value(result).map_err(|_| "无法返回 SSH 主机信息。".to_owned())
                })
        }
        "ssh.install-public-key" => {
            let mut input: SshPublicKeyInstallInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            validate_host_key_fingerprint(&input.host_key_fingerprint)?;
            let master_password = match input.master_password.take() {
                Some(password) if (8..=1_024).contains(&password.len()) => {
                    Some(Zeroizing::new(password))
                }
                Some(_) => return Err("请求参数无效。".to_owned()),
                None => None,
            };
            let request = with_runtime(state, move |runtime| {
                collect_ssh_install_request(runtime, input, master_password)
            })
            .await?;
            tauri::async_runtime::spawn_blocking(move || ssh_service::install_public_key(request))
                .await
                .map_err(|_| "SSH 公钥安装未能完成。".to_owned())?
                .and_then(|result| {
                    serde_json::to_value(result).map_err(|_| "无法返回 SSH 安装结果。".to_owned())
                })
        }
        _ => Err("该 SSH 特权操作不被允许。".to_owned()),
    }
}

pub(super) async fn handle_ssh_external(
    app: &AppHandle,
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    match operation {
        "ssh.external-clients" => {
            require_empty_object(&input)?;
            serde_json::to_value(ssh_external::clients())
                .map_err(|_| "无法返回 SSH 外部客户端。".to_owned())
        }
        "ssh.launch" => {
            let input: ssh_external::LaunchInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let client_id = input.client_id;
            let account_id = input.account_id;
            let account_id_for_material = account_id.clone();
            let copy_password = input.copy_password;
            let permits_transient_secret = state
                .settings
                .lock()
                .map(|settings| !settings.lock_on_blur)
                .unwrap_or(false);
            let material = with_runtime(state, move |runtime| {
                collect_ssh_external_launch_material(
                    runtime,
                    &account_id_for_material,
                    client_id,
                    copy_password,
                    permits_transient_secret,
                )
            })
            .await?;
            let command = material.target.display_command();
            if client_id == ssh_external::ExternalClientId::CopyCommand {
                copy_with_expiry(app, state, command.clone())?;
                return Ok(json!({
                    "launched": false,
                    "command": command,
                    "passwordCopied": false,
                    "passwordCopySkipped": false,
                    "authentication": material.authentication,
                }));
            }

            let duration_minutes = state
                .settings
                .lock()
                .map(|settings| settings.ssh_session_duration_minutes)
                .unwrap_or(15);
            let launch_directory = state.ssh_launch_directory.clone();
            let ssh_directory = state.ssh_directory.clone();
            let base_dir = app.path().app_data_dir().map_err(|_| "无法解析应用数据目录。")?;
            let target = material.target.clone();

            let session_info = if let Some(private_key) = material.private_key {
                let mut registry = state
                    .agent_ssh_agent_registry
                    .lock()
                    .map_err(|_| "SSH agent 注册表不可用。")?;
                let session_info = registry
                    .start_session(
                        &base_dir,
                        &account_id,
                        &material.account_label,
                        private_key,
                        material.passphrase,
                        duration_minutes,
                    )
                    .map_err(|err| format!("启动短时 SSH Agent 会话失败：{err}"))?;

                if client_id == ssh_external::ExternalClientId::Vscode {
                    let fragment = crate::ssh_host_setup::register_ephemeral_session_fragment(
                        &ssh_directory,
                        &session_info.session_ref,
                        &target,
                        &session_info.socket_path,
                    )?;
                    registry.attach_config_fragment(&session_info.session_ref, fragment);
                }
                Some(session_info)
            } else {
                None
            };

            let socket_path = session_info.as_ref().map(|info| info.socket_path.clone());
            tauri::async_runtime::spawn_blocking(move || {
                ssh_external::launch(client_id, &target, &launch_directory, socket_path.as_deref())
            })
            .await
            .map_err(|_| "SSH 外部客户端启动未能完成。".to_owned())??;
            let password_copied = if let Some(password) = material.password {
                copy_with_expiry(app, state, password.to_string())?;
                true
            } else {
                false
            };
            Ok(json!({
                "launched": true,
                "command": command,
                "passwordCopied": password_copied,
                "passwordCopySkipped": material.password_copy_skipped,
                "authentication": material.authentication,
                "durationMinutes": duration_minutes,
                "sessionRef": session_info.as_ref().map(|s| s.session_ref.as_str()),
                "expiresAt": session_info.as_ref().map(|s| s.expires_at.as_str()),
            }))
        }
        _ => Err("该 SSH 外部客户端操作不被允许。".to_owned()),
    }
}

pub(super) async fn handle_ssh_tools(
    app: &AppHandle,
    state: &RuntimeState,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    let unlocked = with_runtime(state, |runtime| Ok(runtime.status().unlocked)).await?;
    if !unlocked {
        return Err("请先在桌面端解锁保险库。".to_owned());
    }
    match operation {
        "ssh.import-clipboard" => {
            require_empty_object(&input)?;
            let command = app
                .clipboard()
                .read_text()
                .map_err(|_| "无法读取系统剪贴板。".to_owned())?;
            let imported = ssh_tools::parse_ssh_command(&command)?;
            serde_json::to_value(imported).map_err(|_| "无法返回 SSH 命令导入结果。".to_owned())
        }
        "ssh.generate-key-pair" => {
            let input: ssh_tools::KeyGenerationInput =
                serde_json::from_value(input).map_err(|_| "请求参数无效。")?;
            let ssh_directory = state.ssh_directory.clone();
            tauri::async_runtime::spawn_blocking(move || {
                ssh_tools::generate_key_pair(&ssh_directory, input)
            })
            .await
            .map_err(|_| "SSH 密钥生成未能完成。".to_owned())?
            .and_then(|result| {
                serde_json::to_value(result).map_err(|_| "无法返回 SSH 密钥生成结果。".to_owned())
            })
        }
        _ => Err("该 SSH 工具操作不被允许。".to_owned()),
    }
}

pub(super) fn collect_ssh_install_request(
    runtime: &mut DesktopRuntime,
    input: SshPublicKeyInstallInput,
    master_password: Option<Zeroizing<String>>,
) -> Result<PublicKeyInstallRequest, DesktopRuntimeError> {
    let account = runtime_ssh_detail(runtime, &input.account_id)?;
    let key = runtime_ssh_detail(runtime, &input.key_id)?;
    let target = ssh_target(&account).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT)?;
    if key.record_kind != "key" || !key.has_public_key {
        return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
    }
    let master_password = master_password.as_ref().map(|password| password.as_str());
    let public_key = runtime.protected_value(
        VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
        VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
        &key.id,
        None,
    )?;
    let authentication = match input.authentication {
        SshInstallAuthentication::StoredPassword => {
            if !account.has_password {
                return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
            }
            AuthenticationMaterial::StoredPassword(runtime.protected_value(
                VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
                &account.id,
                master_password,
            )?)
        }
        SshInstallAuthentication::SshAgent => AuthenticationMaterial::SshAgent,
        SshInstallAuthentication::AuthenticationKey => {
            let authentication_key_id = input
                .authentication_key_id
                .as_deref()
                .ok_or(VAULTMESH_STATUS_INVALID_ARGUMENT)?;
            if authentication_key_id == key.id {
                return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
            }
            let authentication_key = runtime_ssh_detail(runtime, authentication_key_id)?;
            if authentication_key.record_kind != "key" || !authentication_key.has_private_key {
                return Err(VAULTMESH_STATUS_INVALID_ARGUMENT.into());
            }
            AuthenticationMaterial::AuthenticationKey(runtime_private_key(
                runtime,
                &authentication_key,
                master_password,
            )?)
        }
    };
    let verification_key =
        if key.has_private_key && (!key.master_password_reprompt || master_password.is_some()) {
            Some(runtime_private_key(runtime, &key, master_password)?)
        } else {
            None
        };
    Ok(PublicKeyInstallRequest {
        target,
        expected_host_key_fingerprint: input.host_key_fingerprint,
        public_key,
        authentication,
        verification_key,
    })
}

pub(super) fn runtime_private_key(
    runtime: &DesktopRuntime,
    detail: &SshRuntimeDetail,
    master_password: Option<&str>,
) -> Result<PrivateKeyMaterial, DesktopRuntimeError> {
    let public_key = detail
        .has_public_key
        .then(|| {
            runtime.protected_value(
                VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
                &detail.id,
                None,
            )
        })
        .transpose()?;
    let private_key = runtime.protected_value(
        VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
        VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY,
        &detail.id,
        master_password,
    )?;
    let passphrase = detail
        .has_key_passphrase
        .then(|| {
            runtime.protected_value(
                VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
                VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE,
                &detail.id,
                master_password,
            )
        })
        .transpose()?;
    Ok(PrivateKeyMaterial {
        public_key,
        private_key,
        passphrase,
    })
}

pub(super) fn runtime_ssh_detail(
    runtime: &mut DesktopRuntime,
    id: &str,
) -> Result<SshRuntimeDetail, DesktopRuntimeError> {
    let value = runtime.execute("ssh.detail", json!({ "id": id }))?;
    serde_json::from_value(value).map_err(|_| VAULTMESH_STATUS_INVALID_ARGUMENT.into())
}

pub(super) fn ssh_target(detail: &SshRuntimeDetail) -> Result<SshTarget, ()> {
    let host = detail
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty());
    let username = detail.username.trim();
    if detail.record_kind != "account" || host.is_none() || username.is_empty() {
        return Err(());
    }
    Ok(SshTarget {
        host: host.expect("checked host").to_owned(),
        port: detail.port,
        username: username.to_owned(),
    })
}

pub(super) fn validate_host_key_fingerprint(value: &str) -> Result<(), String> {
    let encoded = value
        .strip_prefix("SHA256:")
        .filter(|encoded| (40..=48).contains(&encoded.len()))
        .ok_or_else(|| "请求参数无效。".to_owned())?;
    if !encoded
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return Err("请求参数无效。".to_owned());
    }
    Ok(())
}
