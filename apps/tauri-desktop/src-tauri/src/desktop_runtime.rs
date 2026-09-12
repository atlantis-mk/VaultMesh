use super::*;

pub(super) async fn with_runtime<T, F>(state: &RuntimeState, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut DesktopRuntime) -> Result<T, DesktopRuntimeError> + Send + 'static,
{
    let runtime = Arc::clone(&state.runtime);
    tauri::async_runtime::spawn_blocking(move || {
        let mut runtime = runtime
            .lock()
            .map_err(|_| "保险库运行时暂时不可用。".to_owned())?;
        runtime
            .refresh_from_disk()
            .and_then(|()| operation(&mut runtime))
            .map_err(|error| error.public_message().to_owned())
    })
    .await
    .map_err(|_| "保险库操作未能完成。".to_owned())?
}

pub(super) async fn with_pin<T, F>(state: &RuntimeState, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&PinQuickUnlockService) -> Result<T, String> + Send + 'static,
{
    let pin = Arc::clone(&state.pin);
    tauri::async_runtime::spawn_blocking(move || {
        let pin = pin
            .lock()
            .map_err(|_| "PIN 快速解锁暂时不可用。".to_owned())?;
        operation(&pin)
    })
    .await
    .map_err(|_| "PIN 快速解锁操作未能完成。".to_owned())?
}

pub(super) async fn with_biometric<T, F>(state: &RuntimeState, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&BiometricQuickUnlockService) -> Result<T, String> + Send + 'static,
{
    let biometric = Arc::clone(&state.biometric);
    tauri::async_runtime::spawn_blocking(move || {
        let biometric = biometric
            .lock()
            .map_err(|_| "Touch ID 快速解锁暂时不可用。".to_owned())?;
        operation(&biometric)
    })
    .await
    .map_err(|_| "Touch ID 快速解锁操作未能完成。".to_owned())?
}

pub(super) async fn with_agent_biometric<T, F>(
    state: &RuntimeState,
    operation: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&BiometricQuickUnlockService) -> Result<T, String> + Send + 'static,
{
    let biometric = Arc::clone(&state.agent_biometric);
    tauri::async_runtime::spawn_blocking(move || {
        let biometric = biometric
            .lock()
            .map_err(|_| "Agent Touch ID 快速解锁暂时不可用。".to_owned())?;
        operation(&biometric)
    })
    .await
    .map_err(|_| "Agent Touch ID 快速解锁操作未能完成。".to_owned())?
}

pub(super) async fn disable_biometrics(state: &RuntimeState) -> Result<BiometricStatus, String> {
    let agent_result = with_agent_biometric(state, |biometric| biometric.disable()).await;
    let desktop_result = with_biometric(state, |biometric| biometric.disable()).await;
    agent_result?;
    desktop_result
}

pub(super) fn validate_request(request: &DesktopRequest) -> Result<(), String> {
    if request.operation.is_empty() || request.operation.len() > 128 || !request.input.is_object() {
        return Err("请求参数无效。".into());
    }
    let size = serde_json::to_vec(&request.input)
        .map_err(|_| "请求参数无效。")?
        .len();
    if size > MAX_COMMAND_BYTES {
        return Err("请求超过大小限制。".into());
    }
    Ok(())
}

pub(super) fn is_core_operation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.unlock-history"
            | "vault.change-password"
            | "browser.autofill.candidates"
            | "items.list"
            | "items.detail"
            | "items.add"
            | "items.update"
            | "items.delete"
            | "items.trash.list"
            | "items.trash.restore"
            | "items.trash.purge"
            | "items.trash.empty"
            | "items.history.list"
            | "items.history.restore"
            | "items.history.clear"
            | "password.health"
            | "cards.list"
            | "cards.detail"
            | "cards.add"
            | "cards.update"
            | "cards.delete"
            | "cards.trash.list"
            | "cards.trash.restore"
            | "cards.trash.purge"
            | "cards.trash.empty"
            | "cards.history.list"
            | "cards.history.restore"
            | "cards.history.clear"
            | "identities.list"
            | "identities.detail"
            | "identities.add"
            | "identities.update"
            | "identities.delete"
            | "identities.trash.list"
            | "identities.trash.restore"
            | "identities.trash.purge"
            | "identities.trash.empty"
            | "identities.history.list"
            | "identities.history.restore"
            | "identities.history.clear"
            | "ssh.list"
            | "ssh.detail"
            | "ssh.add"
            | "ssh.update"
            | "ssh.delete"
            | "ssh.trash.list"
            | "ssh.trash.restore"
            | "ssh.trash.purge"
            | "ssh.trash.empty"
            | "ssh.history.list"
            | "ssh.history.restore"
            | "ssh.history.clear"
            | "secrets.list"
            | "secrets.detail"
            | "secrets.add"
            | "secrets.update"
            | "secrets.delete"
            | "services.list"
            | "services.detail"
            | "services.add"
            | "services.update"
            | "services.delete"
            | "services.link"
            | "services.unlink"
            | "services.move"
            | "services.merge"
            | "services.split"
            | "services.ignore-suggestion"
            | "services.trash.list"
            | "services.trash.restore"
            | "services.trash.purge"
            | "services.trash.empty"
            | "services.history.list"
            | "services.history.restore"
            | "services.history.clear"
            | "services.aggregation.preview"
            | "services.aggregation.apply"
            | "services.aggregation.rollback"
            | "services.automatic-linking.get"
            | "services.automatic-linking.update"
            | "api-environments.list"
            | "api-environments.detail"
            | "api-environments.add"
            | "api-environments.update"
            | "api-environments.delete"
            | "api-environments.trash.list"
            | "api-environments.trash.restore"
            | "api-environments.trash.purge"
            | "api-environments.history.list"
            | "api-environments.history.restore"
            | "api-environments.history.clear"
    )
}

pub(super) fn protected_spec(operation: &str) -> Option<(u32, u32)> {
    Some(match operation {
        "items.copy-password" | "items.reveal-password" => (
            VAULTMESH_ITEM_KIND_LOGIN,
            VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD,
        ),
        "cards.copy-number" => (
            VAULTMESH_ITEM_KIND_PAYMENT_CARD,
            VAULTMESH_PROTECTED_FIELD_CARD_NUMBER,
        ),
        "cards.copy-security-code" => (
            VAULTMESH_ITEM_KIND_PAYMENT_CARD,
            VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE,
        ),
        "cards.copy-pin" => (
            VAULTMESH_ITEM_KIND_PAYMENT_CARD,
            VAULTMESH_PROTECTED_FIELD_CARD_PIN,
        ),
        "ssh.copy-password" => (
            VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
            VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
        ),
        "ssh.copy-public-key" => (
            VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
            VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
        ),
        "ssh.copy-private-key" => (
            VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
            VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY,
        ),
        "ssh.copy-key-passphrase" => (
            VAULTMESH_ITEM_KIND_SSH_CREDENTIAL,
            VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE,
        ),
        "secrets.copy-value" => (
            VAULTMESH_ITEM_KIND_SECRET,
            VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
        ),
        _ => return None,
    })
}

pub(super) fn copy_with_expiry(
    app: &AppHandle,
    state: &RuntimeState,
    value: String,
) -> Result<Value, String> {
    let value = Zeroizing::new(value);
    app.clipboard()
        .write_text(value.as_str())
        .map_err(|_| "无法写入剪贴板。".to_owned())?;
    let timeout = state
        .settings
        .lock()
        .map(|settings| settings.clipboard_clear_timeout_ms)
        .unwrap_or(30_000);
    let clears_at = unix_millis().saturating_add(timeout);
    let app = app.clone();
    let clipboard_value = Arc::clone(&state.clipboard_value);
    *clipboard_value
        .lock()
        .map_err(|_| "剪贴板状态暂时不可用。".to_owned())? =
        Some(Zeroizing::new(value.to_string()));
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(timeout));
        if app.clipboard().read_text().ok().as_deref() == Some(value.as_str()) {
            let _ = app.clipboard().write_text(String::new());
        }
        if let Ok(mut current) = clipboard_value.lock()
            && current.as_ref().map(|entry| entry.as_str()) == Some(value.as_str())
        {
            current.take();
        }
    });
    Ok(json!({ "clearsAt": clears_at }))
}

pub(super) fn clear_clipboard_if_unchanged(app: &AppHandle, state: &RuntimeState) {
    let value = state
        .clipboard_value
        .lock()
        .ok()
        .and_then(|mut current| current.take());
    if let Some(value) = value
        && app.clipboard().read_text().ok().as_deref() == Some(value.as_str())
    {
        let _ = app.clipboard().write_text(String::new());
    }
}

pub(super) async fn backup_vault(app: &AppHandle, state: &RuntimeState) -> Result<Value, String> {
    let app_for_dialog = app.clone();
    let dialog_guard = state.native_dialog_focus.begin();
    let destination = tauri::async_runtime::spawn_blocking(move || {
        let _dialog_guard = dialog_guard;
        app_for_dialog
            .dialog()
            .file()
            .add_filter("VaultMesh encrypted vault", &["vault"])
            .set_file_name("VaultMesh-backup.vault")
            .blocking_save_file()
            .and_then(|path| path.into_path().ok())
    })
    .await
    .map_err(|_| "备份对话框未能完成。".to_owned())?;
    let Some(destination) = destination else {
        return Ok(json!({ "cancelled": true }));
    };
    with_runtime(state, move |runtime| {
        runtime
            .backup_to(&destination)
            .map(|()| json!({ "cancelled": false }))
    })
    .await
}

pub(super) async fn unlock_vault(
    app: &AppHandle,
    state: &RuntimeState,
    password: String,
) -> Result<Value, String> {
    let has_vault = with_runtime(state, |runtime| Ok(runtime.status().has_vault)).await?;
    if has_vault {
        let result = with_runtime(state, move |runtime| {
            runtime
                .unlock(password)
                .map(|status| json!({ "cancelled": false, "status": status }))
        })
        .await?;
        if finalize_legacy_electron_migration(&state.app_data).is_err() {
            let _ = with_runtime(state, |runtime| Ok(runtime.lock())).await;
            return Err(
                "保险库已验证，但迁移状态无法安全提交；旧 Electron 数据未被删除。".to_owned(),
            );
        }
        let vault_path = with_runtime(state, |runtime| Ok(runtime.current_path())).await?;
        reconcile_quick_unlock_after_master_unlock(state, vault_path).await?;
        return Ok(result);
    }

    let app_for_dialog = app.clone();
    let dialog_guard = state.native_dialog_focus.begin();
    let source = tauri::async_runtime::spawn_blocking(move || {
        let _dialog_guard = dialog_guard;
        app_for_dialog
            .dialog()
            .file()
            .add_filter("VaultMesh encrypted vault", &["vault"])
            .blocking_pick_file()
            .and_then(|path| path.into_path().ok())
    })
    .await
    .map_err(|_| "打开保险库对话框未能完成。".to_owned())?;
    let Some(source) = source else {
        let status = with_runtime(state, |runtime| Ok(runtime.status())).await?;
        return Ok(json!({ "cancelled": true, "status": status }));
    };
    finish_agent_boundary_lock(state);
    if let Ok(mut requests) = state.api_requests.lock() {
        requests.clear();
    }
    let selected = source.clone();
    let result = with_runtime(state, move |runtime| {
        runtime
            .unlock_from(selected, password)
            .map(|status| json!({ "cancelled": false, "status": status }))
    })
    .await?;
    persist_vault_path(&state.vault_path_record, &source)?;
    reconcile_quick_unlock_after_master_unlock(state, source).await?;
    Ok(result)
}

pub(super) async fn reconcile_quick_unlock_after_master_unlock(
    state: &RuntimeState,
    vault_path: PathBuf,
) -> Result<(), String> {
    with_pin(state, move |pin| {
        pin.disable_if_for_different_vault(&vault_path)?;
        pin.reset_failures(&vault_path)
    })
    .await?;
    let vault_path = with_runtime(state, |runtime| Ok(runtime.current_path())).await?;
    with_biometric(state, move |biometric| {
        biometric.disable_if_for_different_vault(&vault_path)
    })
    .await?;
    let (vault_path, vault_key) = with_runtime(state, |runtime| runtime.quick_unlock_material())
        .await
        .map_err(|_| "请先使用主密码解锁保险库。".to_owned())?;
    if with_biometric(state, |biometric| Ok(biometric.is_enabled())).await? {
        with_agent_biometric(state, move |biometric| {
            biometric
                .provision(vault_path, vault_key.as_slice())
                .map(|_| ())
        })
        .await
    } else {
        with_agent_biometric(state, |biometric| biometric.disable().map(|_| ())).await
    }
}

pub(super) async fn restore_vault(
    app: &AppHandle,
    state: &RuntimeState,
    password: String,
) -> Result<Value, String> {
    let app_for_dialog = app.clone();
    let dialog_guard = state.native_dialog_focus.begin();
    let source = tauri::async_runtime::spawn_blocking(move || {
        let _dialog_guard = dialog_guard;
        app_for_dialog
            .dialog()
            .file()
            .add_filter("VaultMesh encrypted vault", &["vault"])
            .blocking_pick_file()
            .and_then(|path| path.into_path().ok())
    })
    .await
    .map_err(|_| "恢复对话框未能完成。".to_owned())?;
    let Some(source) = source else {
        let status = with_runtime(state, |runtime| Ok(runtime.status())).await?;
        return Ok(json!({ "cancelled": true, "status": status }));
    };
    finish_agent_boundary_lock(state);
    if let Ok(mut requests) = state.api_requests.lock() {
        requests.clear();
    }
    let result = with_runtime(state, move |runtime| {
        runtime
            .restore_from(&source, password)
            .map(|status| json!({ "cancelled": false, "status": status }))
    })
    .await?;
    with_pin(state, |pin| pin.disable()).await?;
    disable_biometrics(state).await?;
    Ok(result)
}

pub(super) fn update_settings(state: &RuntimeState, input: Value) -> Result<Value, String> {
    let settings: SecuritySettings = serde_json::from_value(input).map_err(|_| "安全设置无效。")?;
    if !settings.validate() {
        return Err("安全设置超出允许范围。".into());
    }
    let encoded = serde_json::to_vec(&settings).map_err(|_| "无法保存安全设置。")?;
    write_private_file(&state.settings_path, &encoded, "无法保存安全设置。")?;
    let mut current = state.settings.lock().map_err(|_| "安全设置暂时不可用。")?;
    *current = settings.clone();
    Ok(json!(settings))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn desktop_startup_settings(app: &AppHandle) -> Result<Value, String> {
    app.autolaunch()
        .is_enabled()
        .map(|enabled| json!(desktop_startup::StartupSettings { enabled }))
        .map_err(|_| "无法读取系统登录项。".to_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(super) fn desktop_startup_settings(_app: &AppHandle) -> Result<Value, String> {
    Err("当前平台不支持登录时启动。".to_owned())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn update_desktop_startup(
    app: &AppHandle,
    state: &RuntimeState,
    input: Value,
) -> Result<Value, String> {
    let requested: desktop_startup::StartupSettings =
        serde_json::from_value(input).map_err(|_| "登录时启动设置无效。")?;
    let manager = app.autolaunch();
    desktop_startup::update(
        &desktop_startup::marker_path(&state.app_data),
        requested.enabled,
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
        || {
            manager
                .disable()
                .map_err(|_| "无法关闭登录时启动。".to_owned())
        },
    )
    .map(|settings| json!(settings))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(super) fn update_desktop_startup(
    _app: &AppHandle,
    _state: &RuntimeState,
    _input: Value,
) -> Result<Value, String> {
    Err("当前平台不支持登录时启动。".to_owned())
}

pub(super) fn required_string(input: &Value, key: &str) -> Result<String, String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "请求参数无效。".to_owned())
}

pub(super) fn bounded_required_string(
    input: &Value,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, String> {
    required_string(input, key).and_then(|value| {
        let length = value.encode_utf16().count();
        if (minimum..=maximum).contains(&length) {
            Ok(value)
        } else {
            Err("请求参数无效。".to_owned())
        }
    })
}

pub(super) fn optional_string(input: &Value, key: &str) -> Result<Option<String>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err("请求参数无效。".into()),
    }
}

pub(super) fn email_otp_code(input: &Value) -> Result<String, String> {
    bounded_required_string(input, "code", 4, 8).and_then(|code| {
        if code.bytes().all(|byte| byte.is_ascii_alphanumeric())
            && code.bytes().any(|byte| byte.is_ascii_digit())
        {
            Ok(code)
        } else {
            Err("请求参数无效。".to_owned())
        }
    })
}

pub(super) fn require_empty_object(input: &Value) -> Result<(), String> {
    if input.as_object().is_some_and(serde_json::Map::is_empty) {
        Ok(())
    } else {
        Err("请求参数无效。".to_owned())
    }
}

pub(super) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

pub(super) fn load_settings(path: &std::path::Path) -> SecuritySettings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SecuritySettings>(&bytes).ok())
        .filter(SecuritySettings::validate)
        .unwrap_or_default()
}

pub(super) fn persist_vault_path(
    record_path: &std::path::Path,
    vault_path: &std::path::Path,
) -> Result<(), String> {
    write_private_file(
        record_path,
        vault_path.to_string_lossy().as_bytes(),
        "无法保存保险库位置。",
    )
}

pub(super) fn write_private_file(
    path: &std::path::Path,
    bytes: &[u8],
    message: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| message.to_owned())?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes).map_err(|_| message.to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| message.to_owned())?;
    }
    std::fs::rename(temporary, path).map_err(|_| message.to_owned())
}

pub(super) fn load_vault_path(record_path: &std::path::Path, default_path: PathBuf) -> PathBuf {
    std::fs::read(record_path)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .unwrap_or(default_path)
}

pub(super) fn lock_runtime_on_window_blur(
    runtime: &Mutex<DesktopRuntime>,
    window_label: &str,
    focused: bool,
    lock_on_blur: bool,
    native_dialog_active: bool,
) -> bool {
    if window_label != "main" || focused || !lock_on_blur || native_dialog_active {
        return false;
    }
    runtime.lock().ok().is_some_and(|mut runtime| {
        if !runtime.status().unlocked {
            return false;
        }
        runtime.lock();
        true
    })
}

pub(super) fn finish_policy_lock(app: &AppHandle, state: &RuntimeState) {
    if let Ok(sync) = state.lan_sync.lock() {
        sync.lock_sensitive();
    }
    if let Ok(mut pairing) = state.lan_pairing.lock() {
        pairing.stop();
    }
    clear_clipboard_if_unchanged(app, state);
    clear_imports(state);
    clear_privileged_sessions(state);
    if let Ok(mut requests) = state.api_requests.lock() {
        requests.clear();
    }
    if let Some(window) =
        app.get_webview_window(agent_authorization_window::AGENT_AUTHORIZATION_WINDOW_LABEL)
    {
        let _ = window.hide();
    }
    let _ = app.emit("vault-locked", ());
}

/// Vault replacement/switch and platform lock events cross the Agent storage
/// boundary even though ordinary desktop lock/unlock remains independent.
pub(super) fn finish_agent_boundary_lock(state: &RuntimeState) {
    if let Ok(mut sync) = state.lan_sync.lock() {
        sync.stop();
    }
    if let Ok(mut broker) = state.agent_broker.lock() {
        broker.suspend_for_vault_lock();
    }
    state.agent_vault_access.lock_all();
}

pub(super) fn prune_expired_agent_access(
    state: &RuntimeState,
    now_millis: u64,
) -> Result<usize, String> {
    let expired_clients = state.agent_vault_access.prune_expired(now_millis);
    if expired_clients.is_empty() {
        return Ok(0);
    }
    let mut broker = state
        .agent_broker
        .lock()
        .map_err(|_| "Agent 能力代理暂时不可用。".to_owned())?;
    for client_id in &expired_clients {
        broker.expire_agent_client_authority(*client_id);
    }
    Ok(expired_clients.len())
}

fn get_or_build_main_window(app: &AppHandle) -> Result<tauri::WebviewWindow, String> {
    if let Some(window) = app.get_webview_window("main") {
        return Ok(window);
    }
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|config| config.label == "main")
        .ok_or_else(|| "找不到 VaultMesh 主窗口配置。".to_owned())?;
    tauri::WebviewWindowBuilder::from_config(app, config)
        .map_err(|_| "无法重建 VaultMesh 主窗口。".to_owned())?
        .build()
        .map_err(|_| "无法重建 VaultMesh 主窗口。".to_owned())
}

pub(crate) fn focus_main_window_for_dialog(
    app: &AppHandle,
) -> Result<tauri::WebviewWindow, String> {
    let window = get_or_build_main_window(app)?;
    #[cfg(target_os = "macos")]
    app.set_dock_visibility(true)
        .map_err(|_| "无法将 VaultMesh 显示到前台。".to_owned())?;
    window
        .unminimize()
        .map_err(|_| "无法恢复 VaultMesh 主窗口。".to_owned())?;
    window
        .show()
        .map_err(|_| "无法显示 VaultMesh 主窗口。".to_owned())?;
    window
        .set_focus()
        .map_err(|_| "无法将 VaultMesh 主窗口置于前台。".to_owned())?;
    Ok(window)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn show_main_window(app: &AppHandle) {
    let Ok(window) = get_or_build_main_window(app) else {
        return;
    };
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

#[cfg(target_os = "macos")]
pub(crate) const DESKTOP_TRAY_ICON_BYTES: &[u8] =
    include_bytes!("../../resources/tray-iconTemplate@2x.png");

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn setup_desktop_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, TRAY_SHOW_ID, "显示 VaultMesh", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, TRAY_QUIT_ID, "退出 VaultMesh", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &separator, &quit])?;
    #[cfg(target_os = "macos")]
    let icon = Image::from_bytes(DESKTOP_TRAY_ICON_BYTES)?;
    #[cfg(target_os = "windows")]
    let icon = crate::windows_tray_theme::current_tray_icon()?;

    TrayIconBuilder::with_id(DESKTOP_TRAY_ID)
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("VaultMesh")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match TrayAction::parse(event.id().as_ref()) {
            Some(TrayAction::Show) => show_main_window(app),
            Some(TrayAction::Quit) => app.exit(0),
            None => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    #[cfg(target_os = "windows")]
    crate::windows_tray_theme::start_tray_theme_watcher(app.handle().clone());
    Ok(())
}
