use super::*;

#[test]
fn command_allowlist_rejects_unknown_and_keeps_sensitive_routes_separate() {
    assert!(is_core_operation("items.list"));
    assert!(is_core_operation("services.aggregation.preview"));
    assert!(is_core_operation("services.merge"));
    assert!(!is_core_operation("items.copy-password"));
    assert_eq!(
        protected_spec("items.copy-password"),
        Some((
            VAULTMESH_ITEM_KIND_LOGIN,
            VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD
        ))
    );
    assert!(!is_core_operation("shell.execute"));
    assert!(protected_spec("shell.execute").is_none());
    assert!(!is_core_operation("ssh.launch"));
    assert!(protected_spec("ssh.launch").is_none());
    assert!(!is_core_operation("api-requests.prepare"));
    assert!(!is_core_operation("api-requests.execute"));
    assert!(!is_core_operation("api-requests.cancel"));
    assert_eq!(
        ImportOperation::parse("imports.select"),
        Some(ImportOperation::Select)
    );
    assert_eq!(
        ImportOperation::parse("imports.commit"),
        Some(ImportOperation::Commit)
    );
    assert_eq!(
        ImportOperation::parse("imports.cancel"),
        Some(ImportOperation::Cancel)
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn desktop_tray_menu_ids_are_exhaustive_and_reject_unknown_actions() {
    assert_eq!(TrayAction::parse(TRAY_SHOW_ID), Some(TrayAction::Show));
    assert_eq!(TrayAction::parse(TRAY_QUIT_ID), Some(TrayAction::Quit));
    assert_eq!(TrayAction::parse("vaultmesh-tray-lock"), None);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_desktop_tray_uses_retina_template_artwork() {
    let icon = Image::from_bytes(crate::desktop_runtime::DESKTOP_TRAY_ICON_BYTES)
        .expect("decode macOS tray icon");
    assert_eq!((icon.width(), icon.height()), (36, 36));
}

#[test]
fn windows_tray_theme_selects_contrasting_icons_and_safe_fallback() {
    use crate::windows_tray_theme::{
        WINDOWS_DARK_TRAY_ICON_BYTES, WINDOWS_LIGHT_TRAY_ICON_BYTES, WindowsSystemTheme,
        icon_bytes_for_theme, theme_from_system_uses_light_theme,
    };

    assert_eq!(
        theme_from_system_uses_light_theme(Some(1)),
        WindowsSystemTheme::Light
    );
    assert_eq!(
        theme_from_system_uses_light_theme(Some(0)),
        WindowsSystemTheme::Dark
    );
    assert_eq!(
        theme_from_system_uses_light_theme(Some(2)),
        WindowsSystemTheme::Dark
    );
    assert_eq!(
        theme_from_system_uses_light_theme(None),
        WindowsSystemTheme::Dark
    );

    let light_theme_icon =
        Image::from_bytes(icon_bytes_for_theme(WindowsSystemTheme::Light)).expect("light icon");
    let dark_theme_icon =
        Image::from_bytes(icon_bytes_for_theme(WindowsSystemTheme::Dark)).expect("dark icon");
    assert_eq!(
        (light_theme_icon.width(), light_theme_icon.height()),
        (32, 32)
    );
    assert_eq!(
        (dark_theme_icon.width(), dark_theme_icon.height()),
        (32, 32)
    );
    assert_eq!(
        first_opaque_rgb(&light_theme_icon),
        Some([0, 0, 0]),
        "light Windows theme must use a black tray glyph"
    );
    assert_eq!(
        first_opaque_rgb(&dark_theme_icon),
        Some([255, 255, 255]),
        "dark Windows theme and failures must use a white tray glyph"
    );
    assert_ne!(WINDOWS_LIGHT_TRAY_ICON_BYTES, WINDOWS_DARK_TRAY_ICON_BYTES);
}

fn first_opaque_rgb(image: &Image<'_>) -> Option<[u8; 3]> {
    image
        .rgba()
        .chunks_exact(4)
        .find(|pixel| pixel[3] == 255)
        .map(|pixel| [pixel[0], pixel[1], pixel[2]])
}

#[test]
fn window_blur_policy_locks_unlocked_runtime_and_respects_setting() {
    let path = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-window-blur-{}.vault",
        uuid::Uuid::new_v4()
    ));
    let runtime = Mutex::new(DesktopRuntime::new(path.clone()).expect("runtime"));
    runtime
        .lock()
        .expect("runtime lock")
        .create("correct horse battery staple".into())
        .expect("create");

    assert!(!lock_runtime_on_window_blur(
        &runtime, "main", true, true, false
    ));
    assert!(runtime.lock().expect("runtime lock").status().unlocked);
    assert!(!lock_runtime_on_window_blur(
        &runtime,
        "secondary",
        false,
        true,
        false
    ));
    assert!(runtime.lock().expect("runtime lock").status().unlocked);
    assert!(!lock_runtime_on_window_blur(
        &runtime, "main", false, false, false
    ));
    assert!(runtime.lock().expect("runtime lock").status().unlocked);
    assert!(!lock_runtime_on_window_blur(
        &runtime, "main", false, true, true
    ));
    assert!(runtime.lock().expect("runtime lock").status().unlocked);

    assert!(lock_runtime_on_window_blur(
        &runtime, "main", false, true, false
    ));
    assert!(!runtime.lock().expect("runtime lock").status().unlocked);
    assert!(!lock_runtime_on_window_blur(
        &runtime, "main", false, true, false
    ));
    std::fs::remove_file(path).expect("cleanup");
}

#[test]
fn window_capture_protection_is_enabled_and_renderer_cannot_disable_it() {
    let config: Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid Tauri config");
    let windows = config["app"]["windows"]
        .as_array()
        .filter(|windows| !windows.is_empty())
        .expect("at least one product window");
    assert!(
        windows
            .iter()
            .all(|window| window["contentProtected"] == Value::Bool(true)),
        "every declared product window must enable content protection from creation"
    );

    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json"))
        .expect("valid main capability");
    let permissions = capability["permissions"]
        .as_array()
        .expect("capability permissions");
    assert!(
        permissions.iter().all(|permission| {
            permission.as_str().is_none_or(|permission| {
                !permission.contains("set-content-protected")
                    && permission != "core:window:default"
                    && permission != "core:default"
            })
        }),
        "the renderer must not receive a capability that can disable content protection"
    );
}

#[test]
fn desktop_autostart_starts_hidden_and_remains_rust_owned() {
    let config: Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid Tauri config");
    let windows = config["app"]["windows"]
        .as_array()
        .filter(|windows| !windows.is_empty())
        .expect("at least one product window");
    assert!(
        windows
            .iter()
            .all(|window| window["visible"] == Value::Bool(false)),
        "product windows must stay hidden until runtime distinguishes manual launch"
    );

    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json"))
        .expect("valid main capability");
    let permissions = capability["permissions"]
        .as_array()
        .expect("capability permissions");
    assert!(
        permissions.iter().all(|permission| permission
            .as_str()
            .is_none_or(|permission| !permission.starts_with("autostart:"))),
        "the renderer must not receive direct autostart plugin permissions"
    );
}

#[test]
fn native_dialog_focus_guard_tracks_nested_lifecycle() {
    let state = Arc::new(NativeDialogFocusState::default());
    assert!(!state.is_active());
    let first = state.begin();
    assert!(state.is_active());
    {
        let _second = state.begin();
        assert!(state.is_active());
    }
    assert!(state.is_active());
    drop(first);
    assert!(!state.is_active());
}

#[test]
fn browser_recovery_code_dialog_foregrounds_and_parents_the_native_dialogs() {
    let platform = include_str!("browser_platform.rs");
    let start = platform
        .find("fn import_recovery_code_file")
        .expect("recovery-code dialog owner");
    let end = platform[start..]
        .find("fn generate_password")
        .map(|offset| start + offset)
        .expect("next platform operation");
    let operation = &platform[start..end];
    let focus = operation
        .find("focus_main_window_for_dialog")
        .expect("main-window foreground call");
    let pick = operation
        .find("blocking_pick_file")
        .expect("file selection dialog");
    assert!(
        focus < pick,
        "the app must be foregrounded before file selection"
    );
    assert!(operation.contains(".set_parent(&window)"));
    assert!(operation.contains(".parent(&window)"));

    let owner = include_str!("desktop_runtime.rs");
    let start = owner
        .find("pub(crate) fn focus_main_window_for_dialog")
        .expect("foreground helper");
    let end = owner[start..]
        .find("fn show_main_window")
        .map(|offset| start + offset)
        .expect("foreground helper boundary");
    let helper = &owner[start..end];
    let unminimize = helper.find(".unminimize()").expect("unminimize");
    let show = helper.find(".show()").expect("show");
    let focus = helper.find(".set_focus()").expect("focus");
    assert!(unminimize < show && show < focus);
}

#[test]
fn closing_main_window_destroys_its_webview_and_tray_rebuilds_it() {
    let setup = include_str!("app_setup.rs");
    let close_start = setup
        .find("if window.label() == \"main\"")
        .expect("main-window close handler");
    let close_end = setup[close_start..]
        .find("        })\n        .setup")
        .map(|offset| close_start + offset)
        .expect("main-window close handler boundary");
    let close_handler = &setup[close_start..close_end];
    assert!(close_handler.contains("WindowEvent::CloseRequested { .. }"));
    assert!(!close_handler.contains("prevent_close"));
    assert!(!close_handler.contains("window.hide()"));

    let runtime = include_str!("desktop_runtime.rs");
    let rebuild = runtime
        .find("fn get_or_build_main_window")
        .expect("main-window rebuild helper");
    let show = runtime
        .find("fn show_main_window")
        .expect("tray show handler");
    assert!(runtime[rebuild..show].contains("WebviewWindowBuilder::from_config"));
    assert!(runtime[show..].contains("get_or_build_main_window(app)"));
}

#[test]
fn oversized_and_non_object_payloads_fail_closed() {
    let non_object = DesktopRequest {
        operation: "items.list".into(),
        input: Value::Null,
    };
    assert!(validate_request(&non_object).is_err());

    let oversized = DesktopRequest {
        operation: "items.add".into(),
        input: json!({ "password": "x".repeat(MAX_COMMAND_BYTES + 1) }),
    };
    assert!(validate_request(&oversized).is_err());
    assert!(validate_import_file(false, 10).is_err());
    assert!(validate_import_file(true, MAX_IMPORT_FILE_BYTES + 1).is_err());
    assert!(validate_import_file(true, MAX_IMPORT_FILE_BYTES).is_ok());
    assert!(
        bounded_required_string(
            &json!({ "masterPassword": "short" }),
            "masterPassword",
            8,
            1_024
        )
        .is_err()
    );
    assert!(
        bounded_required_string(
            &json!({ "masterPassword": "x".repeat(1_025) }),
            "masterPassword",
            8,
            1_024,
        )
        .is_err()
    );

    assert!(
        serde_json::from_value::<PinSetupInput>(
            json!({ "pin": "123456", "failureLimit": 5, "unexpected": true })
        )
        .is_err()
    );
    assert!(require_empty_object(&json!({ "unexpected": true })).is_err());
}

#[test]
fn email_copy_accepts_bounded_alphanumeric_otp_and_rejects_invalid_tokens() {
    assert_eq!(
        email_otp_code(&json!({ "code": "A9b2C3" })).expect("mixed OTP"),
        "A9b2C3"
    );
    assert_eq!(
        email_otp_code(&json!({ "code": "246810" })).expect("numeric OTP"),
        "246810"
    );
    for code in ["ABCDEF", "A9-B2", "A9b2C3xyz", "验证码1234"] {
        assert!(email_otp_code(&json!({ "code": code })).is_err(), "{code}");
    }
}

#[test]
fn email_provider_network_phase_releases_runtime_and_service_mutexes() {
    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-email-concurrency-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).expect("test root");
    let settings_path = root.join("email-otp-settings.json");
    std::fs::write(
        &settings_path,
        serde_json::to_vec(&json!({
            "enabled": true,
            "pollIntervalSeconds": 10,
            "messageLookbackMinutes": 5,
            "codeLifetimeSeconds": 90,
            "requireDomainMatch": false,
            "onlyUnreadMessages": true
        }))
        .expect("settings"),
    )
    .expect("write settings");
    let runtime = Arc::new(Mutex::new(
        DesktopRuntime::new(root.join("vaultmesh.vault")).expect("runtime"),
    ));
    runtime
        .lock()
        .expect("runtime lock")
        .create("correct horse battery staple".into())
        .expect("create");
    let service = Arc::new(Mutex::new(EmailOtpService::new(settings_path)));
    let runtime_probe = Arc::clone(&runtime);
    let service_probe = Arc::clone(&service);

    let result = perform_email_scan_with(&runtime, &service, 1_700_000_000, move |plan| {
        assert!(
            runtime_probe.try_lock().is_ok(),
            "provider network must not hold the shared Vault runtime"
        );
        assert!(
            service_probe.try_lock().is_ok(),
            "provider network must not hold the Email service"
        );
        EmailOtpService::execute_scan(plan)
    })
    .expect("scan");
    assert!(result.as_array().is_some_and(Vec::is_empty));

    runtime.lock().expect("runtime lock").lock();
    drop(service);
    drop(runtime);
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn import_commit_uses_one_core_transaction_and_rejects_replay() {
    let path = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-import-{}.vault",
        uuid::Uuid::new_v4()
    ));
    let mut runtime = DesktopRuntime::new(path.clone()).expect("runtime");
    runtime
        .create("correct horse battery staple".into())
        .expect("create");
    let mut imports = ImportService::default();
    let preview = imports
        .prepare(
            "csv",
            "passwords.csv".into(),
            Zeroizing::new(
                "title,username,password\nExample,ada,secret\nSecond,grace,another-secret".into(),
            ),
            100,
        )
        .expect("preview");
    let session_id = preview["sessionId"].as_str().expect("session id");
    let payload = imports.take_payload(session_id, 101).expect("payload");
    let result = runtime
        .execute("_native.import.batch", payload)
        .expect("atomic import");
    assert_eq!(result["importedCount"], 2);
    assert_eq!(runtime.status().item_count, 2);
    assert!(imports.take_payload(session_id, 102).is_err());
    assert_eq!(runtime.status().item_count, 2);
    runtime.lock();
    std::fs::remove_file(path).expect("cleanup");
}

#[test]
fn ssh_install_materials_stay_in_rust_and_enforce_account_key_roles() {
    let path = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-ssh-install-{}.vault",
        uuid::Uuid::new_v4()
    ));
    let mut runtime = DesktopRuntime::new(path.clone()).expect("runtime");
    runtime
        .create("correct horse battery staple".into())
        .expect("create");
    let account = runtime
        .execute(
            "ssh.add",
            json!({
                "title": "Production server", "host": "server.example.test", "port": 2222,
                "username": "deploy", "password": "server-password", "publicKey": null,
                "privateKey": null, "keyPassphrase": null, "notes": null, "folder": null,
                "favorite": false, "masterPasswordReprompt": false, "recordKind": "account"
            }),
        )
        .expect("account");
    let upload_key = runtime
            .execute(
                "ssh.add",
                json!({
                    "title": "Upload key", "host": null, "port": 22, "username": "",
                    "password": null,
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGU= upload@test",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nupload-private\n-----END OPENSSH PRIVATE KEY-----",
                    "keyPassphrase": null, "notes": null, "folder": null, "favorite": false,
                    "masterPasswordReprompt": false, "recordKind": "key"
                }),
            )
            .expect("upload key");
    let authentication_key = runtime
            .execute(
                "ssh.add",
                json!({
                    "title": "Authentication key", "host": null, "port": 22, "username": "",
                    "password": null,
                    "publicKey": "ssh-ed25519 YXV0aGVudGljYXRpb24ta2V5 auth@test",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nauth-private\n-----END OPENSSH PRIVATE KEY-----",
                    "keyPassphrase": null, "notes": null, "folder": null, "favorite": false,
                    "masterPasswordReprompt": false, "recordKind": "key"
                }),
            )
            .expect("authentication key");
    let fingerprint = "SHA256:qRX6CeJd4lv20bYyMxX7gc8Cn0Z5scoRYZ92U0cyRpw";

    let request = collect_ssh_install_request(
        &mut runtime,
        SshPublicKeyInstallInput {
            account_id: account["id"].as_str().expect("account id").into(),
            key_id: upload_key["id"].as_str().expect("key id").into(),
            authentication: SshInstallAuthentication::StoredPassword,
            authentication_key_id: None,
            host_key_fingerprint: fingerprint.into(),
            master_password: None,
        },
        None,
    )
    .expect("stored password request");
    assert_eq!(request.target.endpoint(), "deploy@server.example.test:2222");
    assert_eq!(request.expected_host_key_fingerprint, fingerprint);
    assert!(request.public_key.starts_with("ssh-ed25519 "));
    assert!(request.verification_key.is_some());
    assert!(matches!(
        request.authentication,
        AuthenticationMaterial::StoredPassword(ref password)
            if password.as_str() == "server-password"
    ));

    let request = collect_ssh_install_request(
        &mut runtime,
        SshPublicKeyInstallInput {
            account_id: account["id"].as_str().expect("account id").into(),
            key_id: upload_key["id"].as_str().expect("key id").into(),
            authentication: SshInstallAuthentication::AuthenticationKey,
            authentication_key_id: Some(
                authentication_key["id"]
                    .as_str()
                    .expect("authentication key id")
                    .into(),
            ),
            host_key_fingerprint: fingerprint.into(),
            master_password: None,
        },
        None,
    )
    .expect("private key request");
    assert!(matches!(
        request.authentication,
        AuthenticationMaterial::AuthenticationKey(ref key)
            if key.private_key.contains("auth-private")
    ));

    runtime.lock();
    std::fs::remove_file(path).expect("cleanup");
}

#[test]
fn ssh_external_launch_keeps_private_material_in_rust_and_honors_reprompt() {
    let path = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-ssh-launch-{}.vault",
        uuid::Uuid::new_v4()
    ));
    let mut runtime = DesktopRuntime::new(path.clone()).expect("runtime");
    runtime
        .create("correct horse battery staple".into())
        .expect("create");
    let key_import = runtime
            .execute(
                "_native.ssh.import",
                json!({ "items": [{
                    "title": "Key server", "host": "server.example.test", "port": 2222,
                    "username": "deploy", "password": null, "publicKey": null,
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nlaunch-private\n-----END OPENSSH PRIVATE KEY-----",
                    "keyPassphrase": null, "notes": null, "folder": null, "favorite": false,
                    "masterPasswordReprompt": false
                }] }),
            )
            .expect("legacy combined SSH import");
    let key_account = &key_import["items"][0];
    let key_material = collect_ssh_external_launch_material(
        &mut runtime,
        key_account["id"].as_str().expect("key account id"),
        ssh_external::ExternalClientId::SystemTerminal,
        true,
        true,
    )
    .expect("key launch material");
    assert_eq!(
        key_material.target.display_command(),
        "ssh -p 2222 -- 'deploy@server.example.test'"
    );
    assert_eq!(key_material.authentication, "key");
    assert!(
        key_material
            .private_key
            .as_ref()
            .is_some_and(|key| key.contains("launch-private"))
    );
    assert!(key_material.password.is_none());

    let vscode_material = collect_ssh_external_launch_material(
        &mut runtime,
        key_account["id"].as_str().expect("key account id"),
        ssh_external::ExternalClientId::Vscode,
        true,
        true,
    )
    .expect("vscode launch material");
    assert_eq!(vscode_material.authentication, "key");
    assert!(
        vscode_material
            .private_key
            .as_ref()
            .is_some_and(|key| key.contains("launch-private"))
    );
    assert!(vscode_material.password.is_none());

    let locked_on_blur_material = collect_ssh_external_launch_material(
        &mut runtime,
        key_account["id"].as_str().expect("key account id"),
        ssh_external::ExternalClientId::SystemTerminal,
        true,
        false,
    )
    .expect("lock-on-blur launch material");
    assert_eq!(locked_on_blur_material.authentication, "sshAgent");
    assert!(locked_on_blur_material.private_key.is_none());
    assert!(locked_on_blur_material.password.is_none());

    let reprompt_account = runtime
        .execute(
            "ssh.add",
            json!({
                "title": "Reprompt server", "host": "secure.example.test", "port": 22,
                "username": "operator", "password": "server-password", "publicKey": null,
                "privateKey": null, "keyPassphrase": null, "notes": null, "folder": null,
                "favorite": false, "masterPasswordReprompt": true, "recordKind": "account"
            }),
        )
        .expect("reprompt account");
    let reprompt_material = collect_ssh_external_launch_material(
        &mut runtime,
        reprompt_account["id"]
            .as_str()
            .expect("reprompt account id"),
        ssh_external::ExternalClientId::SystemTerminal,
        true,
        true,
    )
    .expect("reprompt launch material");
    assert_eq!(reprompt_material.authentication, "password");
    assert!(reprompt_material.private_key.is_none());
    assert!(reprompt_material.password.is_none());
    assert!(reprompt_material.password_copy_skipped);

    runtime.lock();
    std::fs::remove_file(path).expect("cleanup");
}
