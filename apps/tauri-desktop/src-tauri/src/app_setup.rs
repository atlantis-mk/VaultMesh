use super::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init());
    let builder = if app_update::updater_enabled_for_build() {
        builder.plugin(tauri_plugin_updater::Builder::new().build())
    } else {
        builder
    };
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let builder = builder
        .menu(app_update::desktop_application_menu)
        .on_menu_event(|app, event| {
            app_update::handle_desktop_menu_event(app, event.id().as_ref());
        });
    let app = builder
        .on_window_event(|window, event| {
            if window.label() == "agent-pairing"
                && let WindowEvent::CloseRequested { .. } = event
                && let Some(state) = window.app_handle().try_state::<RuntimeState>()
            {
                agent_pairing_window::reject_displayed_pairing_on_window_close(&state);
            }
            if window.label() == agent_authorization_window::AGENT_AUTHORIZATION_WINDOW_LABEL
                && let WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
                if let Some(state) = window.app_handle().try_state::<RuntimeState>() {
                    agent_authorization_window::reject_displayed_authorization_on_window_close(
                        &state,
                    );
                }
                let _ = window.hide();
            }
            if window.label() == agent_unlock_window::AGENT_UNLOCK_WINDOW_LABEL
                && let WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
                if let Some(state) = window.app_handle().try_state::<RuntimeState>() {
                    agent_unlock_window::reject_displayed_unlock(&state);
                }
                let _ = window.hide();
            }
            if let WindowEvent::Focused(focused) = event {
                let app = window.app_handle();
                if let Some(state) = app.try_state::<RuntimeState>() {
                    let lock_on_blur = state
                        .settings
                        .lock()
                        .map(|settings| settings.lock_on_blur)
                        .unwrap_or(true);
                    let native_dialog_active = state.native_dialog_focus.is_active();
                    let agent_authorization_active = app
                        .get_webview_window(
                            agent_authorization_window::AGENT_AUTHORIZATION_WINDOW_LABEL,
                        )
                        .is_some_and(|authorization| authorization.is_visible().unwrap_or(false));
                    let agent_unlock_active = app
                        .get_webview_window(agent_unlock_window::AGENT_UNLOCK_WINDOW_LABEL)
                        .is_some_and(|unlock| unlock.is_visible().unwrap_or(false));
                    if window.label() == "main"
                        && !focused
                        && lock_on_blur
                        && !native_dialog_active
                        && !agent_authorization_active
                        && !agent_unlock_active
                    {
                        let app = app.clone();
                        let state = state.inner().clone();
                        let window_label = window.label().to_owned();
                        let focused = *focused;
                        tauri::async_runtime::spawn_blocking(move || {
                            if lock_runtime_on_window_blur(
                                &state.runtime,
                                &window_label,
                                focused,
                                lock_on_blur,
                                native_dialog_active,
                            ) {
                                finish_policy_lock(&app, &state);
                            }
                        });
                    }
                }
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            if window.label() == "main"
                && let WindowEvent::CloseRequested { .. } = event
            {
                if let Some(state) = window.app_handle().try_state::<RuntimeState>() {
                    if let Ok(mut requests) = state.api_requests.lock() {
                        requests.clear();
                    }
                    stop_lan_pairing(&state);
                }
                #[cfg(target_os = "macos")]
                let _ = window.app_handle().set_dock_visibility(false);
            }
        })
        .setup(|app| {
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            app.handle().plugin(tauri_plugin_autostart::init(
                MacosLauncher::LaunchAgent,
                Some(vec![desktop_startup::AUTOSTART_ARGUMENT]),
            ))?;
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            setup_desktop_tray(app)?;
            let app_data = app.path().app_data_dir()?;
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            if !cfg!(debug_assertions) {
                let manager = app.autolaunch();
                let _ = desktop_startup::initialize_default(
                    &desktop_startup::marker_path(&app_data),
                    || {
                        manager
                            .is_enabled()
                            .map_err(|_| "无法读取系统登录项。".to_owned())
                    },
                    || {
                        manager
                            .enable()
                            .map_err(|_| "无法启用登录时启动。".to_owned())
                    },
                );
            }
            let legacy_data = app.path().data_dir()?.join("VaultMesh");
            migrate_legacy_electron_data(
                &app_data,
                &legacy_data,
                should_migrate_legacy(&app.config().identifier),
            )
            .map_err(|_| {
                std::io::Error::other("无法安全迁移现有 Electron 保险库；旧数据未被删除。")
            })?;
            let settings_path = app_data.join("security-settings.json");
            let agent_access_settings_path = app_data.join("agent-access-settings.json");
            let email_settings_path = app_data.join("email-otp-settings.json");
            let pin_path = app_data.join("desktop-pin-unlock.json");
            let biometric_path = app_data.join("desktop-biometric-unlock.json");
            let lan_peer_trust_path = app_data.join("lan-peer-trust.json");
            let vault_path_record = app_data.join("vault-path");
            let vault_path = load_vault_path(&vault_path_record, app_data.join("vaultmesh.vault"));
            let runtime = Arc::new(Mutex::new(
                DesktopRuntime::new(vault_path.clone())
                    .map_err(|error| std::io::Error::other(error.public_message()))?,
            ));
            let agent_vault_access =
                AgentVaultAccess::new(vault_path.clone(), agent_access_settings_path)
                    .map_err(|error| std::io::Error::other(error.public_message()))?;
            let agent_runtime = agent_vault_access.runtime();
            let agent_pin = Arc::new(Mutex::new(PinQuickUnlockService::new_agent(
                app_data.join("agent-pin-unlock.json"),
            )));
            let settings = Arc::new(Mutex::new(load_settings(&settings_path)));
            let clipboard_value = Arc::new(Mutex::new(None));
            let native_dialog_focus = Arc::new(NativeDialogFocusState::default());
            let ssh_directory = app.path().home_dir()?.join(".ssh");
            let ssh_launch_directory = ssh_external::launch_root(&app_data);
            ssh_external::clear_launches(&ssh_launch_directory);
            let email_otp = Arc::new(Mutex::new(EmailOtpService::new(email_settings_path)));
            let agent_resources = Arc::new(Mutex::new(AgentResourceStore::default()));
            let agent_managed_web = Arc::new(Mutex::new(AgentManagedWebStore::default()));
            let agent_ssh_sessions = Arc::new(Mutex::new(AgentSshSessionStore::default()));
            let mut agent_broker_core = AgentBrokerCore::new_with_pairing_proofs(
                AgentPairingProofs::platform(app_data.join("agent-pairings.json")),
            )
            .map_err(|_| std::io::Error::other("Agent broker registry is invalid"))?;
            agent_broker_core.set_authorization_store(AgentAuthorizationStore::platform(
                app_data.join("agent-authorizations.v1"),
                &vault_path,
            ));
            let access_check = agent_vault_access.clone();
            agent_broker_core.set_access_check(Arc::new(move |client_id| {
                access_check.is_unlocked(client_id)
            }));
            let access_shares_unlock = agent_vault_access.clone();
            agent_broker_core.set_access_shares_unlock(Arc::new(move |left, right| {
                access_shares_unlock.shares_unlock(left, right)
            }));
            let access_register = agent_vault_access.clone();
            agent_broker_core.set_access_register(Arc::new(move |client_id, pairing_identity| {
                access_register.register_client(client_id, pairing_identity);
            }));
            let access_disconnect = agent_vault_access.clone();
            agent_broker_core.set_access_disconnect(Arc::new(move |client_id| {
                access_disconnect.disconnect_client(client_id);
            }));
            let access_lock = agent_vault_access.clone();
            agent_broker_core.set_access_lock(Arc::new(move |client_id| {
                access_lock.lock_client(client_id)
            }));
            let cleanup_resources = Arc::clone(&agent_resources);
            let cleanup_managed_web = Arc::clone(&agent_managed_web);
            let cleanup_ssh_sessions = Arc::clone(&agent_ssh_sessions);
            agent_broker_core.set_resource_cleanup(Arc::new(move |scope| {
                if let Ok(mut resources) = cleanup_resources.lock() {
                    match scope {
                        AgentCleanupScope::Client(client_id) => {
                            resources.revoke_client(client_id);
                        }
                        AgentCleanupScope::Session(session_id) => {
                            resources.revoke_session(session_id);
                        }
                        AgentCleanupScope::All => resources.clear(),
                    }
                }
                if let Ok(mut sessions) = cleanup_ssh_sessions.lock() {
                    match scope {
                        AgentCleanupScope::Client(client_id) => {
                            sessions.revoke_client(client_id);
                        }
                        AgentCleanupScope::Session(session_id) => {
                            sessions.revoke_session(session_id);
                        }
                        AgentCleanupScope::All => sessions.clear(),
                    }
                }
                if let Ok(mut sessions) = cleanup_managed_web.lock() {
                    match scope {
                        AgentCleanupScope::Client(client_id) => {
                            sessions.revoke_client(client_id);
                        }
                        AgentCleanupScope::Session(session_id) => {
                            sessions.revoke_session(session_id);
                        }
                        AgentCleanupScope::All => sessions.clear(),
                    }
                }
            }));
            let account_catalog_runtime = Arc::clone(&agent_runtime);
            let account_catalog: AgentAccountCatalog = Arc::new(move || {
                let mut runtime = account_catalog_runtime
                    .lock()
                    .map_err(|_| AgentBrokerError::internal())?;
                if !runtime.status().unlocked {
                    return Err(AgentBrokerError::vault_locked());
                }
                let connector_definitions =
                    runtime.agent_connector_definition_records().map_err(|_| {
                        AgentBrokerError::new(
                            "vault-unavailable",
                            "Unlock VaultMesh to discover account metadata.",
                            true,
                        )
                    })?;
                let candidates = runtime.agent_account_candidates().map_err(|_| {
                    AgentBrokerError::new(
                        "vault-unavailable",
                        "Unlock VaultMesh to discover account metadata.",
                        true,
                    )
                })?;
                let candidates = candidates
                    .into_iter()
                    .map(|candidate| {
                        let account_ref = candidate
                            .get("accountRef")
                            .and_then(Value::as_str)
                            .and_then(|value| uuid::Uuid::parse_str(value).ok())
                            .ok_or_else(AgentBrokerError::internal)?;
                        let kind = candidate
                            .get("kind")
                            .and_then(Value::as_str)
                            .ok_or_else(AgentBrokerError::internal)?
                            .to_owned();
                        let label = candidate
                            .get("label")
                            .and_then(Value::as_str)
                            .ok_or_else(AgentBrokerError::internal)?
                            .to_owned();
                        Ok(AgentVaultAccountCandidate {
                            account_ref,
                            kind,
                            label,
                        })
                    })
                    .collect::<Result<Vec<_>, AgentBrokerError>>()?;
                Ok(AgentAccountCatalogSnapshot {
                    connector_definitions,
                    candidates,
                })
            });
            agent_broker_core.set_account_catalog(account_catalog);
            let api_environment_runtime = Arc::clone(&agent_runtime);
            let api_environment_catalog: AgentApiEnvironmentCatalog = Arc::new(move || {
                let mut runtime = api_environment_runtime
                    .lock()
                    .map_err(|_| AgentBrokerError::internal())?;
                if !runtime.status().unlocked {
                    return Err(AgentBrokerError::vault_locked());
                }
                runtime
                    .agent_api_environment_candidates()
                    .map_err(|_| {
                        AgentBrokerError::new(
                            "vault-unavailable",
                            "Unlock VaultMesh to discover API environments.",
                            true,
                        )
                    })?
                    .into_iter()
                    .map(|candidate| {
                        Ok(AgentApiEnvironmentCandidate {
                            environment_ref: candidate
                                .get("environmentRef")
                                .and_then(Value::as_str)
                                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                                .ok_or_else(AgentBrokerError::internal)?,
                            label: candidate
                                .get("label")
                                .and_then(Value::as_str)
                                .ok_or_else(AgentBrokerError::internal)?
                                .to_owned(),
                            environment: candidate
                                .get("environment")
                                .and_then(Value::as_str)
                                .ok_or_else(AgentBrokerError::internal)?
                                .to_owned(),
                            capability: candidate
                                .get("capability")
                                .and_then(Value::as_str)
                                .ok_or_else(AgentBrokerError::internal)?
                                .to_owned(),
                            openapi_url: candidate
                                .get("openapiUrl")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            revision: candidate
                                .get("revision")
                                .and_then(Value::as_u64)
                                .ok_or_else(AgentBrokerError::internal)?,
                            policy_digest: candidate
                                .get("policyDigest")
                                .and_then(Value::as_str)
                                .ok_or_else(AgentBrokerError::internal)?
                                .to_owned(),
                        })
                    })
                    .collect()
            });
            agent_broker_core.set_api_environment_catalog(api_environment_catalog);
            let direct_http_runtime = Arc::clone(&agent_runtime);
            agent_broker_core.set_direct_http_policy_factory(Arc::new(
                move |item_id, item_kind, tool, action_parameters| {
                    let mut runtime = direct_http_runtime
                        .lock()
                        .map_err(|_| AgentBrokerError::internal())?;
                    agent_direct_policy::generate_direct_http_policy(
                        &mut runtime,
                        item_id,
                        item_kind,
                        tool,
                        action_parameters,
                    )
                },
            ));
            let direct_ssh_runtime = Arc::clone(&agent_runtime);
            agent_broker_core.set_direct_ssh_policy_factory(Arc::new(
                move |item_id, tool, action_parameters| {
                    let mut runtime = direct_ssh_runtime
                        .lock()
                        .map_err(|_| AgentBrokerError::internal())?;
                    agent_direct_policy::generate_direct_ssh_policy(
                        &mut runtime,
                        item_id,
                        tool,
                        action_parameters,
                    )
                },
            ));
            let direct_connector_runtime = Arc::clone(&agent_runtime);
            agent_broker_core.set_direct_connector_policy_factory(Arc::new(
                move |connector_id, tool, action_parameters| {
                    let mut runtime = direct_connector_runtime
                        .lock()
                        .map_err(|_| AgentBrokerError::internal())?;
                    agent_direct_policy::generate_direct_connector_policy(
                        &mut runtime,
                        connector_id,
                        tool,
                        action_parameters,
                    )
                },
            ));
            let agent_broker = Arc::new(Mutex::new(agent_broker_core));
            let audit_runtime = Arc::clone(&agent_runtime);
            let agent_audit_sink: AgentAuditSink = Arc::new(move |event| {
                audit_runtime
                    .lock()
                    .map_err(|_| ())?
                    .record_agent_audit(event)
                    .map(|event| event.event_id.to_string())
                    .map_err(|_| ())
            });
            let executor_runtime = Arc::clone(&agent_runtime);
            let executor_access = agent_vault_access.clone();
            let executor_resources = Arc::clone(&agent_resources);
            let executor_managed_web = Arc::clone(&agent_managed_web);
            let executor_ssh_sessions = Arc::clone(&agent_ssh_sessions);
            let executor_ssh_directory = ssh_directory.clone();
            let executor_email_otp = Arc::clone(&email_otp);
            let executor_app = app.handle().clone();
            let executor_dialog_focus = Arc::clone(&native_dialog_focus);
            let agent_executor: AgentToolExecutor =
                Arc::new(move |tool, account_ref, parameters, cancellation, scope| {
                    let _activity =
                        executor_access
                            .begin_activity(scope.client_id)
                            .ok_or_else(|| {
                                AgentBrokerError::new(
                                    "mcp-locked",
                                    "The independent MCP Vault access is locked.",
                                    true,
                                )
                            })?;
                    let context = AgentToolContext {
                        runtime: &executor_runtime,
                        resources: &executor_resources,
                        managed_web: &executor_managed_web,
                        email_otp: &executor_email_otp,
                        ssh_sessions: &executor_ssh_sessions,
                        ssh_directory: &executor_ssh_directory,
                        app: &executor_app,
                        dialog_focus: &executor_dialog_focus,
                    };
                    execute_agent_tool(&context, tool, account_ref, parameters, cancellation, scope)
                });
            #[cfg(unix)]
            let agent_listener = {
                let app_handle = app.handle().clone();
                let on_native_ui: Arc<dyn Fn(AgentNativeUiSurface) + Send + Sync> =
                    Arc::new(move |surface| match surface {
                        AgentNativeUiSurface::Pairing => {
                            agent_pairing_window::show_agent_pairing_window(&app_handle);
                        }
                        AgentNativeUiSurface::Unlock => {
                            agent_unlock_window::show_agent_unlock_window(&app_handle);
                        }
                        AgentNativeUiSurface::UnlockExpired(reference) => {
                            agent_unlock_window::expire_agent_unlock_window(
                                &app_handle,
                                &reference,
                            );
                        }
                        AgentNativeUiSurface::Authorization => {
                            agent_authorization_window::show_agent_authorization_window(
                                &app_handle,
                            );
                        }
                        AgentNativeUiSurface::AuthorizationExpired(reference) => {
                            agent_authorization_window::expire_agent_authorization_window(
                                &app_handle,
                                &reference,
                            );
                        }
                        AgentNativeUiSurface::LocalUi => show_main_window(&app_handle),
                    });
                Some(Arc::new(AgentBrokerUnixListener::start(
                    app_data.join("agent").join("broker-v1.sock"),
                    Arc::clone(&agent_broker),
                    Arc::clone(&agent_audit_sink),
                    Arc::clone(&agent_executor),
                    on_native_ui,
                )?))
            };
            #[cfg(target_os = "windows")]
            let agent_pipe_listener = {
                let app_handle = app.handle().clone();
                let on_native_ui: Arc<dyn Fn(AgentNativeUiSurface) + Send + Sync> =
                    Arc::new(move |surface| match surface {
                        AgentNativeUiSurface::Pairing => {
                            agent_pairing_window::show_agent_pairing_window(&app_handle);
                        }
                        AgentNativeUiSurface::Unlock => {
                            agent_unlock_window::show_agent_unlock_window(&app_handle);
                        }
                        AgentNativeUiSurface::UnlockExpired(reference) => {
                            agent_unlock_window::expire_agent_unlock_window(
                                &app_handle,
                                &reference,
                            );
                        }
                        AgentNativeUiSurface::Authorization => {
                            agent_authorization_window::show_agent_authorization_window(
                                &app_handle,
                            );
                        }
                        AgentNativeUiSurface::AuthorizationExpired(reference) => {
                            agent_authorization_window::expire_agent_authorization_window(
                                &app_handle,
                                &reference,
                            );
                        }
                        AgentNativeUiSurface::LocalUi => show_main_window(&app_handle),
                    });
                Some(Arc::new(AgentBrokerWindowsListener::start(
                    Arc::clone(&agent_broker),
                    Arc::clone(&agent_audit_sink),
                    Arc::clone(&agent_executor),
                    on_native_ui,
                )?))
            };
            #[cfg(unix)]
            let browser_listener =
                BrowserPairingService::new(app_data.join("browser-pairing.json"))
                    .load_or_create()
                    .ok()
                    .and_then(|secret| {
                        let platform = Arc::new(TauriBrowserPlatform::new(
                            app.handle().clone(),
                            app_data.clone(),
                            Arc::clone(&settings),
                            settings_path.clone(),
                            Arc::clone(&clipboard_value),
                            Arc::clone(&native_dialog_focus),
                            Arc::clone(&email_otp),
                        ));
                        BrowserBrokerCore::new_with_platform(vault_path, secret, platform).ok()
                    })
                    .and_then(|broker| {
                        BrowserBrokerUnixListener::start(
                            std::env::temp_dir().join("vaultmesh-tauri-browser.sock"),
                            Arc::new(Mutex::new(broker)),
                        )
                        .ok()
                    })
                    .map(Arc::new);
            #[cfg(target_os = "windows")]
            let browser_integration = {
                let browser_app_handle = app.handle().clone();
                let browser_app_data = app_data.clone();
                let browser_vault_path = vault_path.clone();
                let browser_settings = Arc::clone(&settings);
                let browser_settings_path = settings_path.clone();
                let browser_clipboard_value = Arc::clone(&clipboard_value);
                let browser_native_dialog_focus = Arc::clone(&native_dialog_focus);
                let browser_email_otp = Arc::clone(&email_otp);
                let broker_factory = Arc::new(move || {
                    let secret =
                        BrowserPairingService::new(browser_app_data.join("browser-pairing.json"))
                            .load_or_create()
                            .map_err(|_| BrowserIntegrationError::PairingUnavailable)?;
                    let platform = Arc::new(TauriBrowserPlatform::new(
                        browser_app_handle.clone(),
                        browser_app_data.clone(),
                        Arc::clone(&browser_settings),
                        browser_settings_path.clone(),
                        Arc::clone(&browser_clipboard_value),
                        Arc::clone(&browser_native_dialog_focus),
                        Arc::clone(&browser_email_otp),
                    ));
                    BrowserBrokerCore::new_with_platform(
                        browser_vault_path.clone(),
                        secret,
                        platform,
                    )
                    .map_err(|_| BrowserIntegrationError::BrokerUnavailable)
                });
                let mut integration =
                    WindowsBrowserIntegration::new(app_data.clone(), broker_factory);
                integration.start();
                Arc::new(Mutex::new(integration))
            };
            let lan_sync = Arc::new(Mutex::new(LanSyncService::new(
                runtime.clone(),
                lan_peer_trust_path.clone(),
            )));
            let state = RuntimeState {
                runtime,
                lan_sync,
                agent_vault_access,
                agent_pin,
                agent_broker,
                agent_pairing_window_request: Arc::new(Mutex::new(None)),
                agent_unlock_window_request: Arc::new(Mutex::new(None)),
                agent_authorization_window_request: Arc::new(Mutex::new(None)),
                agent_authorization_window_deadline: Arc::new(AtomicU64::new(0)),
                agent_resources,
                agent_managed_web,
                agent_ssh_sessions,
                #[cfg(unix)]
                _agent_listener: agent_listener,
                #[cfg(target_os = "windows")]
                _agent_pipe_listener: agent_pipe_listener,
                #[cfg(unix)]
                _browser_listener: browser_listener,
                #[cfg(target_os = "windows")]
                browser_integration,
                app_data,
                settings,
                settings_path,
                last_activity: Arc::new(AtomicU64::new(unix_millis())),
                native_dialog_focus,
                clipboard_value,
                imports: Arc::new(Mutex::new(ImportService::default())),
                api_requests: Arc::new(Mutex::new(DesktopApiRequestStore::default())),
                ssh_directory,
                ssh_launch_directory,
                ssh_scan: Arc::new(Mutex::new(SshScanService::default())),
                email_otp,
                biometric: Arc::new(Mutex::new(BiometricQuickUnlockService::new(
                    biometric_path,
                    "com.vaultmesh.desktop.desktop-biometric",
                    "desktop-biometric",
                ))),
                pin: Arc::new(Mutex::new(PinQuickUnlockService::new(pin_path))),
                lan_pairing: Arc::new(Mutex::new(LanPairingService::new(lan_peer_trust_path))),
                vault_path_record,
            };
            app.manage(state.clone());
            agent_unlock_window::prepare_agent_unlock_window(app.handle());
            agent_authorization_window::prepare_agent_authorization_window(app.handle());
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            let lan_session_state = state.clone();
            let lan_app_handle = app.handle().clone();
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            let update_state = state.clone();
            let app_handle = app.handle().clone();
            std::thread::spawn(move || monitor_idle_lock(app_handle, state));
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            std::thread::spawn(move || monitor_lan_session_lock(lan_app_handle, lan_session_state));
            let email_state = app.state::<RuntimeState>().inner().clone();
            let email_app = app.handle().clone();
            std::thread::spawn(move || monitor_email_otp(email_app, email_state));
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            if desktop_startup::launched_by_autostart(std::env::args_os()) {
                #[cfg(target_os = "macos")]
                let _ = app.handle().set_dock_visibility(false);
            } else {
                show_main_window(app.handle());
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            app_update::start_update_monitor(app.handle().clone(), update_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            desktop_invoke,
            desktop_activity,
            agent_pairing_status,
            agent_pairing_resolve,
            agent_unlock_status,
            agent_unlock_set_scope,
            agent_unlock_password,
            agent_unlock_pin,
            agent_unlock_cancel,
            agent_authorization_status,
            agent_authorization_resolve_permission,
            agent_authorization_resolve_confirmation
        ])
        .build(tauri::generate_context!())
        .expect("failed to build VaultMesh Tauri desktop");
    app.run(|handle, event| {
        #[cfg(target_os = "macos")]
        if matches!(event, RunEvent::Reopen { .. }) {
            show_main_window(handle);
        }
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            cleanup_app_state(handle);
        }
        if matches!(event, RunEvent::Resumed)
            && let Some(state) = handle.try_state::<RuntimeState>()
        {
            // The OS suspends application threads during sleep. Tear down any
            // sockets and ephemeral material before accepting post-resume work.
            stop_lan_pairing(&state);
            lock_system_authorizations(handle, &state);
        }
    });
}

fn stop_lan_pairing(state: &RuntimeState) {
    if let Ok(mut sync) = state.lan_sync.lock() {
        sync.stop();
    }
    if let Ok(mut lan_pairing) = state.lan_pairing.lock() {
        lan_pairing.stop();
    }
}

fn lock_system_authorizations(app: &AppHandle, state: &RuntimeState) {
    if let Ok(mut runtime) = state.runtime.lock() {
        runtime.lock();
    }
    finish_policy_lock(app, state);
    finish_agent_boundary_lock(state);
    #[cfg(unix)]
    if let Some(listener) = &state._browser_listener {
        listener.lock_vault();
    }
    #[cfg(target_os = "windows")]
    if let Ok(integration) = state.browser_integration.lock() {
        integration.lock_vault();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn monitor_lan_session_lock(app: AppHandle, state: RuntimeState) {
    let mut was_system_locked = false;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let system_locked = system_session_locked();
        vaultmesh_ffi::sync_relay::set_system_locked(system_locked);
        if system_locked {
            if let Ok(sync) = state.lan_sync.lock() {
                sync.lock_sensitive();
            }
            if !was_system_locked {
                lock_system_authorizations(&app, &state);
            }
        }
        was_system_locked = system_locked;
        let unlocked = state.runtime.lock().ok().is_some_and(|r| r.is_unlocked());
        if system_locked || !unlocked {
            if let Ok(mut pairing) = state.lan_pairing.lock() {
                pairing.stop();
            }
            // Ciphertext transport is independent of desktop unlock. No core
            // key or renderer capability is retained by this service.
        }
        let authorizations = if let Ok(mut pairing) = state.lan_pairing.lock() {
            if pairing.is_active() {
                pairing.status(std::time::Instant::now(), unix_millis());
            }
            pairing.take_sync_authorizations()
        } else {
            vec![]
        };
        for (vault, peer, fingerprint) in authorizations {
            if let Ok(mut runtime) = state.runtime.lock() {
                if runtime.sync_state().is_ok_and(|s| s.vault_id == vault) {
                    let _ = runtime.sync_authorize(&peer, &fingerprint, true);
                }
            }
        }
        let changed = if let Ok(mut sync) = state.lan_sync.lock() {
            sync.tick();
            sync.take_changes() > 0
        } else {
            false
        };
        if changed {
            if let Ok(mut requests) = state.api_requests.lock() {
                requests.clear();
            }
            if let Ok(mut broker) = state.agent_broker.lock() {
                broker.restart_connection_sessions(unix_millis());
            }
            let _ = app.emit("vault-data-changed", ());
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn confirmed_session_lock(observation: Option<bool>) -> bool {
    matches!(observation, Some(true))
}

#[cfg(target_os = "macos")]
fn system_session_locked() -> bool {
    use core_foundation::{
        base::{CFType, TCFType},
        boolean::CFBoolean,
        dictionary::{CFDictionary, CFDictionaryRef},
        string::CFString,
    };

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return confirmed_session_lock(None);
    }
    let session: CFDictionary<CFString, CFType> = unsafe { TCFType::wrap_under_create_rule(raw) };
    let key = CFString::new("CGSSessionScreenIsLocked");
    confirmed_session_lock(
        session
            .find(&key)
            .and_then(|value| value.downcast::<CFBoolean>())
            .map(bool::from),
    )
}

#[cfg(target_os = "windows")]
fn system_session_locked() -> bool {
    use std::{ffi::c_void, ptr::null_mut};
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK,
        WTS_SESSIONSTATE_UNLOCK, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW,
        WTSSessionInfoEx,
    };

    let mut buffer = null_mut();
    let mut bytes = 0_u32;
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )
    } == 0
        || buffer.is_null()
    {
        return confirmed_session_lock(None);
    }
    let observation = if bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
        let info = unsafe { &*buffer.cast::<WTSINFOEXW>() };
        if info.Level == 1 {
            match unsafe { info.Data.WTSInfoExLevel1.SessionFlags } {
                value if value == WTS_SESSIONSTATE_LOCK as i32 => Some(true),
                value if value == WTS_SESSIONSTATE_UNLOCK as i32 => Some(false),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };
    unsafe { WTSFreeMemory(buffer.cast::<c_void>()) };
    confirmed_session_lock(observation)
}

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod session_lock_tests {
    use super::confirmed_session_lock;

    #[test]
    fn ct_lan_pairing_only_a_confirmed_session_lock_stops_discovery() {
        assert!(confirmed_session_lock(Some(true)));
        assert!(!confirmed_session_lock(Some(false)));
        assert!(!confirmed_session_lock(None));
    }
}

pub(super) fn cleanup_app_state(handle: &AppHandle) {
    let Some(state) = handle.try_state::<RuntimeState>() else {
        return;
    };
    if let Ok(mut runtime) = state.runtime.lock() {
        runtime.lock();
    }
    finish_policy_lock(handle, &state);
    #[cfg(unix)]
    if let Some(listener) = &state._browser_listener {
        listener.stop();
    }
    #[cfg(target_os = "windows")]
    if let Ok(mut integration) = state.browser_integration.lock() {
        integration.stop();
    }
    #[cfg(unix)]
    if let Some(listener) = &state._agent_listener {
        listener.stop();
    }
    #[cfg(target_os = "windows")]
    if let Some(listener) = &state._agent_pipe_listener {
        listener.stop();
    }
    if let Ok(mut broker) = state.agent_broker.lock() {
        broker.clear();
    }
    state.agent_vault_access.lock_all();
    if let Ok(mut resources) = state.agent_resources.lock() {
        resources.clear();
    }
    if let Ok(mut sessions) = state.agent_ssh_sessions.lock() {
        sessions.clear();
    }
    if let Ok(mut sessions) = state.agent_managed_web.lock() {
        sessions.clear();
    }
    if let Ok(mut requests) = state.api_requests.lock() {
        requests.clear();
    }
    stop_lan_pairing(&state);
    ssh_external::clear_launches(&state.ssh_launch_directory);
}

fn monitor_idle_lock(app: AppHandle, state: RuntimeState) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        prune_imports(&state);
        if let Ok(mut resources) = state.agent_resources.lock() {
            resources.prune(unix_millis());
        }
        if let Ok(mut sessions) = state.agent_ssh_sessions.lock() {
            sessions.prune(unix_millis());
        }
        if let Ok(mut sessions) = state.agent_managed_web.lock() {
            sessions.prune(unix_millis());
        }
        let _ = prune_expired_agent_access(&state, unix_millis());
        let timeout = state
            .settings
            .lock()
            .map(|settings| settings.idle_timeout_ms)
            .unwrap_or(5 * 60_000);
        if unix_millis().saturating_sub(state.last_activity.load(Ordering::Relaxed)) < timeout {
            continue;
        }
        let locked = state.runtime.lock().ok().is_some_and(|mut runtime| {
            if runtime.status().unlocked {
                runtime.lock();
                true
            } else {
                false
            }
        });
        if locked {
            finish_policy_lock(&app, &state);
        }
        state.last_activity.store(unix_millis(), Ordering::Relaxed);
    }
}

fn monitor_email_otp(app: AppHandle, state: RuntimeState) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = unix_millis() / 1000;
        let due = state
            .email_otp
            .lock()
            .map(|service| service.poll_due(now))
            .unwrap_or(false);
        if !due {
            continue;
        }
        if let Ok(candidates) = perform_email_scan(&state.runtime, &state.email_otp, now) {
            let _ = app.emit("email-otp-candidates", candidates);
        }
    }
}
