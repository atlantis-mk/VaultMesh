use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};
use tauri::{AppHandle, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use uuid::Uuid;
use vaultmesh_ffi::{
    DesktopRuntime, DesktopRuntimeError, VAULTMESH_ITEM_KIND_LOGIN,
    VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_ITEM_KIND_SECRET,
    VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_CARD_NUMBER,
    VAULTMESH_PROTECTED_FIELD_CARD_PIN, VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE,
    VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD, VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
    VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE, VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
    VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY, VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_LOCKED, VAULTMESH_STATUS_REAUTH_REQUIRED,
};
use zeroize::Zeroizing;

use crate::{
    NativeDialogFocusState, SecuritySettings,
    biometric_service::BiometricQuickUnlockService,
    browser_broker::{BrowserBrokerPlatform, BrowserPlatformError},
    browser_fill::email_otp_assignment,
    browser_pairing::BrowserPairingService,
    email_otp::{EmailOtpService, EmailScanPlan},
    focus_main_window_for_dialog,
    import_service::{ImportService, MAX_IMPORT_FILE_BYTES, validate_source},
    passkey_service::PasskeyService,
    pin_service::PinQuickUnlockService,
    recovery_code_file::{PreparedRecoveryCodeFile, RecoveryFileCleanupSessions},
    ssh_scan::SshScanService,
    write_private_file,
};

pub struct TauriBrowserPlatform {
    app: AppHandle,
    settings: Arc<Mutex<SecuritySettings>>,
    settings_path: PathBuf,
    clipboard_value: Arc<Mutex<Option<Zeroizing<String>>>>,
    native_dialog_focus: Arc<NativeDialogFocusState>,
    imports: Mutex<ImportService>,
    recovery_files: Mutex<RecoveryFileCleanupSessions>,
    pin: Mutex<PinQuickUnlockService>,
    biometric: Mutex<BiometricQuickUnlockService>,
    pairing: BrowserPairingService,
    ssh_directory: PathBuf,
    ssh_scan: Mutex<SshScanService>,
    email_otp: Arc<Mutex<EmailOtpService>>,
    email_fill_seen: Mutex<HashMap<Uuid, i64>>,
}

impl TauriBrowserPlatform {
    /// New OS credential slots and records; never inherits another extension's quick unlock.
    pub fn into_bitwarden_development(mut self, app_data: &std::path::Path) -> Self {
        let directory = app_data.join(crate::browser_development_identity::DIRECTORY);
        self.pin = Mutex::new(PinQuickUnlockService::new_bitwarden_development(
            directory.join("pin-unlock.json"),
        ));
        self.biometric = Mutex::new(BiometricQuickUnlockService::new(
            directory.join("biometric-unlock.json"),
            "com.vaultmesh.desktop.bitwarden-dev-biometric",
            "bitwarden-dev-biometric",
        ));
        self.pairing =
            BrowserPairingService::new_bitwarden_development(directory.join("pairing.json"));
        self
    }

    pub fn new(
        app: AppHandle,
        app_data: PathBuf,
        settings: Arc<Mutex<SecuritySettings>>,
        settings_path: PathBuf,
        clipboard_value: Arc<Mutex<Option<Zeroizing<String>>>>,
        native_dialog_focus: Arc<NativeDialogFocusState>,
        email_otp: Arc<Mutex<EmailOtpService>>,
    ) -> Self {
        let ssh_directory = app
            .path()
            .home_dir()
            .unwrap_or_else(|_| app_data.clone())
            .join(".ssh");
        Self {
            app,
            settings,
            settings_path,
            clipboard_value,
            native_dialog_focus,
            imports: Mutex::new(ImportService::default()),
            recovery_files: Mutex::new(RecoveryFileCleanupSessions::default()),
            pin: Mutex::new(PinQuickUnlockService::new_browser(
                app_data.join("browser-pin-unlock.json"),
            )),
            biometric: Mutex::new(BiometricQuickUnlockService::new(
                app_data.join("browser-biometric-unlock.json"),
                "com.vaultmesh.desktop.browser-biometric",
                "browser-biometric",
            )),
            pairing: BrowserPairingService::new(app_data.join("browser-pairing.json")),
            ssh_directory,
            ssh_scan: Mutex::new(SshScanService::default()),
            email_otp,
            email_fill_seen: Mutex::new(HashMap::new()),
        }
    }

    fn copy(
        &self,
        value: Zeroizing<String>,
        now_millis: i64,
    ) -> Result<Value, BrowserPlatformError> {
        self.app
            .clipboard()
            .write_text(value.as_str())
            .map_err(|_| failure("无法写入剪贴板。"))?;
        let timeout = self
            .settings
            .lock()
            .map(|settings| settings.clipboard_clear_timeout_ms)
            .unwrap_or(30_000);
        let clears_at = now_millis.max(0) as u64 + timeout;
        let app = self.app.clone();
        let clipboard_value = Arc::clone(&self.clipboard_value);
        *clipboard_value
            .lock()
            .map_err(|_| failure("剪贴板状态暂时不可用。"))? =
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

    fn protected_copy(
        &self,
        runtime: &DesktopRuntime,
        operation: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Result<Value, BrowserPlatformError> {
        let id = required_string(input, "id")?;
        let password = optional_string(input, "masterPassword")?;
        if operation == "items.copy-totp" {
            let result = runtime
                .totp_value(&id, password.as_deref())
                .map_err(runtime_error)?;
            let code = result
                .get("code")
                .and_then(Value::as_str)
                .ok_or_else(|| failure("验证码不可用。"))?;
            return self.copy(Zeroizing::new(code.to_owned()), now_millis);
        }
        if operation == "items.copy-username" {
            return Err(failure("用户名复制必须通过安全 runtime 路由。"));
        }
        let (kind, field) = match operation {
            "items.copy-password" => (
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
            _ => return Err(invalid()),
        };
        let value = runtime
            .protected_value(kind, field, &id, password.as_deref())
            .map_err(runtime_error)?;
        self.copy(value, now_millis)
    }

    fn update_settings(&self, input: &Map<String, Value>) -> Result<Value, BrowserPlatformError> {
        let mut settings_input = input.clone();
        settings_input.remove("userGestureId");
        settings_input.remove("confirmationToken");
        let settings: SecuritySettings =
            serde_json::from_value(Value::Object(settings_input)).map_err(|_| invalid())?;
        if !settings.validate() {
            return Err(invalid());
        }
        let encoded = serde_json::to_vec(&settings).map_err(|_| failure("无法保存安全设置。"))?;
        write_private_file(&self.settings_path, &encoded, "无法保存安全设置。")
            .map_err(|message| failure(&message))?;
        *self
            .settings
            .lock()
            .map_err(|_| failure("安全设置暂时不可用。"))? = settings.clone();
        Ok(json!(settings))
    }

    fn import_select(
        &self,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Result<Value, BrowserPlatformError> {
        let source = required_string(input, "source")?;
        validate_source(&source).map_err(|message| failure(&message))?;
        let selected = {
            let _dialog_guard = self.native_dialog_focus.begin();
            let builder = self.app.dialog().file().set_title("选择密码导出文件");
            let builder = if source == "bitwarden" {
                builder.add_filter("Bitwarden 导出文件", &["csv", "json"])
            } else {
                builder.add_filter("CSV 文件", &["csv"])
            };
            builder
                .blocking_pick_file()
                .and_then(|path| path.into_path().ok())
        };
        let Some(path) = selected else {
            return Err(cancelled());
        };
        let metadata = std::fs::metadata(&path).map_err(|_| failure("无法读取导入文件。"))?;
        if !metadata.is_file() || metadata.len() > MAX_IMPORT_FILE_BYTES {
            return Err(failure("导出文件必须是小于 10 MB 的普通文件。"));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(invalid)?
            .to_owned();
        let contents = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|_| failure("导入文件必须使用 UTF-8 编码。"))?,
        );
        self.imports
            .lock()
            .map_err(|_| failure("导入状态暂时不可用。"))?
            .prepare(&source, file_name, contents, now_millis.max(0) as u64)
            .map_err(|message| failure(&message))
    }

    fn import_recovery_code_file(
        &self,
        input: &Map<String, Value>,
    ) -> Result<Value, BrowserPlatformError> {
        let phase = input
            .get("phase")
            .map(|value| value.as_str().ok_or_else(invalid))
            .transpose()?;
        if input.keys().any(|key| {
            !["phase", "cleanupId", "userGestureId", "confirmationToken"].contains(&key.as_str())
        }) || !matches!(phase, None | Some("prepare") | Some("finish"))
            || (phase != Some("finish") && input.contains_key("cleanupId"))
        {
            return Err(invalid());
        }
        let deadline = Utc::now().timestamp_millis().saturating_add(45_000);
        if phase == Some("finish") {
            let id =
                Uuid::parse_str(&required_string(input, "cleanupId")?).map_err(|_| invalid())?;
            // Consume before opening the dialog. Cancellation and duplicate calls cannot replay deletion.
            let cleanup = self
                .recovery_files
                .lock()
                .map_err(|_| failure("导入状态暂时不可用。"))?
                .take(id, Utc::now().timestamp_millis())
                .map_err(|message| failure(&message))?;
            let window =
                focus_main_window_for_dialog(&self.app).map_err(|message| failure(&message))?;
            let _dialog_guard = self.native_dialog_focus.begin();
            let confirmed = self.app.dialog().message(format!(
                "登录信息已保存。是否删除已导入的原文件“{}”？\n\n删除不是安全擦除，不会清理其他副本或备份。", cleanup.file_name))
                .title("删除已导入的恢复码文件？").parent(&window)
                .buttons(MessageDialogButtons::OkCancelCustom("删除文件".into(), "保留文件".into())).blocking_show();
            let now = Utc::now().timestamp_millis();
            return Ok(
                json!({ "sourceFileStatus": cleanup.finish(confirmed && now < deadline, now) }),
            );
        }
        let window =
            focus_main_window_for_dialog(&self.app).map_err(|message| failure(&message))?;
        let _dialog_guard = self.native_dialog_focus.begin();
        let selected = self
            .app
            .dialog()
            .file()
            .set_title("选择恢复码文件")
            .set_parent(&window)
            .blocking_pick_file()
            .and_then(|path| path.into_path().ok());
        let Some(path) = selected else {
            return Err(cancelled());
        };
        let prepared = PreparedRecoveryCodeFile::load(path).map_err(|message| failure(&message))?;
        if phase == Some("prepare") {
            let now = Utc::now().timestamp_millis();
            if now >= deadline {
                return Err(cancelled());
            }
            let (result, id, expires_at) = self
                .recovery_files
                .lock()
                .map_err(|_| failure("导入状态暂时不可用。"))?
                .stage(prepared, now)
                .map_err(|message| failure(&message))?;
            return Ok(json!({ "codes": result.codes, "fileName": result.file_name,
                "sourceFileStatus": result.source_file_status, "cleanup": { "id": id, "expiresAt": expires_at } }));
        }
        let delete_confirmed = self
            .app
            .dialog()
            .message(format!(
                "已从“{}”解析 {} 个恢复码。\n\n是否删除原文件？删除不是安全擦除，不会清理其他副本或备份。",
                prepared.file_name(),
                prepared.code_count()
            ))
            .title("删除恢复码文件？")
            .parent(&window)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "删除文件".into(),
                "保留文件".into(),
            ))
            .blocking_show();
        serde_json::to_value(prepared.finish(delete_confirmed))
            .map_err(|_| failure("无法返回恢复码文件结果。"))
    }

    fn generate_password(&self, input: &Map<String, Value>) -> Result<Value, BrowserPlatformError> {
        let length = input
            .get("length")
            .and_then(Value::as_u64)
            .filter(|length| (8..=128).contains(length))
            .ok_or_else(invalid)? as usize;
        let groups = [
            ("uppercase", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
            ("lowercase", b"abcdefghijklmnopqrstuvwxyz".as_slice()),
            ("numbers", b"0123456789".as_slice()),
            ("symbols", b"!@#$%^&*()-_=+[]{};:,.?".as_slice()),
        ]
        .into_iter()
        .filter_map(|(key, group)| {
            input
                .get(key)
                .and_then(Value::as_bool)
                .filter(|enabled| *enabled)
                .map(|_| group)
        })
        .collect::<Vec<_>>();
        if groups.is_empty() {
            return Err(invalid());
        }
        let all = groups
            .iter()
            .flat_map(|group| group.iter().copied())
            .collect::<Vec<_>>();
        let mut password = groups
            .iter()
            .map(|group| group[random_index(group.len())])
            .collect::<Vec<_>>();
        while password.len() < length {
            password.push(all[random_index(all.len())]);
        }
        for index in (1..password.len()).rev() {
            let target = random_index(index + 1);
            password.swap(index, target);
        }
        let password = String::from_utf8(password).map_err(|_| failure("无法生成密码。"))?;
        Ok(json!({ "password": password }))
    }
}

impl BrowserBrokerPlatform for TauriBrowserPlatform {
    fn dispatch(
        &self,
        runtime: &mut DesktopRuntime,
        operation: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Option<Result<Value, BrowserPlatformError>> {
        if !is_platform_operation(operation) {
            return None;
        }
        let result = (|| -> Result<Value, BrowserPlatformError> {
            match operation {
                "vault.backup" => {
                    let selected = {
                        let _dialog_guard = self.native_dialog_focus.begin();
                        self.app
                            .dialog()
                            .file()
                            .set_file_name("VaultMesh-backup.vaultmesh")
                            .add_filter("VaultMesh 加密备份", &["vaultmesh"])
                            .blocking_save_file()
                            .and_then(|path| path.into_path().ok())
                    };
                    let Some(path) = selected else {
                        return Err(cancelled());
                    };
                    runtime.backup_to(&path).map_err(runtime_error)?;
                    Ok(json!({ "cancelled": false }))
                }
                "vault.restore" => {
                    let password = required_string(input, "masterPassword")?;
                    let selected = {
                        let _dialog_guard = self.native_dialog_focus.begin();
                        self.app
                            .dialog()
                            .file()
                            .add_filter("VaultMesh 加密备份", &["vaultmesh"])
                            .blocking_pick_file()
                            .and_then(|path| path.into_path().ok())
                    };
                    let Some(path) = selected else {
                        return Err(cancelled());
                    };
                    let status = runtime
                        .restore_from_for_browser(&path, password)
                        .map_err(runtime_error)?;
                    self.pin
                        .lock()
                        .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?
                        .disable()
                        .map_err(|message| failure(&message))?;
                    self.biometric
                        .lock()
                        .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
                        .disable()
                        .map_err(|message| failure(&message))?;
                    Ok(json!({ "cancelled": false, "status": status }))
                }
                "biometric.status" => self
                    .biometric
                    .lock()
                    .map(|service| json!(service.status()))
                    .map_err(|_| failure("Touch ID 快速解锁暂时不可用。")),
                "biometric.enable" => {
                    let (path, key) = runtime.quick_unlock_material().map_err(runtime_error)?;
                    self.biometric
                        .lock()
                        .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
                        .enable(path, key.as_slice())
                        .map(|status| json!(status))
                        .map_err(|message| failure(&message))
                }
                "biometric.disable" => self
                    .biometric
                    .lock()
                    .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
                    .disable()
                    .map(|status| json!(status))
                    .map_err(|message| failure(&message)),
                "biometric.unlock" => {
                    let (path, key) = self
                        .biometric
                        .lock()
                        .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
                        .unlock()
                        .map_err(|message| failure(&message))?;
                    let status = runtime
                        .unlock_for_browser_with_biometric_key(path, key.as_slice())
                        .map_err(runtime_error)?;
                    Ok(json!({ "cancelled": false, "status": status }))
                }
                "pin.status" => self
                    .pin
                    .lock()
                    .map(|pin| json!(pin.status()))
                    .map_err(|_| failure("PIN 快速解锁暂时不可用。")),
                "pin.enable" => {
                    let pin_value = required_string(input, "pin")?;
                    let failure_limit = input
                        .get("failureLimit")
                        .and_then(Value::as_u64)
                        .and_then(|value| u8::try_from(value).ok())
                        .ok_or_else(invalid)?;
                    let (path, key) = runtime.quick_unlock_material().map_err(runtime_error)?;
                    self.pin
                        .lock()
                        .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?
                        .enable(path, key.as_slice(), &pin_value, failure_limit)
                        .map(|status| json!(status))
                        .map_err(|message| failure(&message))
                }
                "pin.disable" => {
                    let pin = self
                        .pin
                        .lock()
                        .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?;
                    pin.disable().map_err(|message| failure(&message))?;
                    Ok(json!(pin.status()))
                }
                "pin.unlock" => {
                    let pin_value = required_string(input, "pin")?;
                    let credential = self
                        .pin
                        .lock()
                        .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?
                        .unlock(&pin_value)
                        .map_err(|message| failure(&message))?;
                    let status = runtime
                        .unlock_for_browser_with_quick_key(
                            credential.vault_path,
                            credential.vault_key.as_slice(),
                        )
                        .map_err(runtime_error)?;
                    Ok(json!({ "cancelled": false, "status": status }))
                }
                "security.settings.get" => self
                    .settings
                    .lock()
                    .map(|settings| json!(settings.clone()))
                    .map_err(|_| failure("安全设置暂时不可用。")),
                "security.settings.update" => self.update_settings(input),
                "browser.pairing.revoke" => self
                    .pairing
                    .revoke()
                    .map(|()| json!({ "paired": false }))
                    .map_err(|message| failure(&message)),
                "email.otp.watch" => {
                    let origin = required_string(input, "topOrigin")?;
                    let now = now_millis.max(0) as u64 / 1_000;
                    let (status, plan) = {
                        let mut service = self
                            .email_otp
                            .lock()
                            .map_err(|_| failure("邮箱验证码服务暂时不可用。"))?;
                        service
                            .finish_pending_scan(runtime)
                            .map_err(|message| failure(&message))?;
                        if input.get("active").and_then(Value::as_bool) == Some(false) {
                            service
                                .stop_browser_boost(Some(&origin))
                                .map_err(|message| failure(&message))?;
                            return Ok(json!({ "watching": false, "boostExpiresAt": 0 }));
                        }
                        let status = service
                            .start_browser_boost(&origin, now)
                            .map_err(|message| failure(&message))?;
                        let plan = service
                            .poll_due(now)
                            .then(|| service.begin_scan(runtime, now))
                            .transpose()
                            .map_err(|message| failure(&message))?;
                        (status, plan)
                    };
                    if let Some(plan) = plan {
                        queue_email_scan(Arc::clone(&self.email_otp), plan);
                    }
                    Ok(status)
                }
                "email.otp.poll" => {
                    let now = now_millis.max(0) as u64 / 1_000;
                    let (due, boosted, plan) = {
                        let mut service = self
                            .email_otp
                            .lock()
                            .map_err(|_| failure("邮箱验证码服务暂时不可用。"))?;
                        service
                            .finish_pending_scan(runtime)
                            .map_err(|message| failure(&message))?;
                        let due = service.poll_due(now);
                        let plan = due
                            .then(|| service.begin_scan(runtime, now))
                            .transpose()
                            .map_err(|message| failure(&message))?;
                        (due, service.browser_boost_active(now), plan)
                    };
                    if let Some(plan) = plan {
                        queue_email_scan(Arc::clone(&self.email_otp), plan);
                    }
                    Ok(json!({ "polled": due, "boosted": boosted }))
                }
                "email.otp.candidates" => {
                    let origin = required_string(input, "topOrigin")?;
                    let mut service = self
                        .email_otp
                        .lock()
                        .map_err(|_| failure("邮箱验证码服务暂时不可用。"))?;
                    service
                        .finish_pending_scan(runtime)
                        .map_err(|message| failure(&message))?;
                    service
                        .browser_candidates(&origin, now_millis.max(0) as u64 / 1_000)
                        .map_err(|message| failure(&message))
                }
                "email.otp.fill" => {
                    let candidate_id = required_string(input, "candidateId")?
                        .parse::<Uuid>()
                        .map_err(|_| invalid())?;
                    let origin = input
                        .get("discovery")
                        .and_then(Value::as_object)
                        .and_then(|value| value.get("topOrigin"))
                        .and_then(Value::as_str)
                        .ok_or_else(invalid)?;
                    let code = self
                        .email_otp
                        .lock()
                        .map_err(|_| failure("邮箱验证码服务暂时不可用。"))?
                        .browser_candidate_code(
                            candidate_id,
                            origin,
                            now_millis.max(0) as u64 / 1_000,
                        )
                        .map_err(|message| failure(&message))?;
                    let mut seen = self
                        .email_fill_seen
                        .lock()
                        .map_err(|_| failure("邮箱验证码填充状态暂时不可用。"))?;
                    email_otp_assignment(&mut seen, input, code.as_str(), now_millis)
                }
                "items.copy-username" => runtime
                    .execute("items.copy-username", Value::Object(input.clone()))
                    .map_err(runtime_error)
                    .and_then(|value| {
                        value
                            .as_str()
                            .map(|value| Zeroizing::new(value.to_owned()))
                            .ok_or_else(invalid)
                    })
                    .and_then(|value| self.copy(value, now_millis)),
                "items.copy-password"
                | "items.copy-totp"
                | "cards.copy-number"
                | "cards.copy-security-code"
                | "cards.copy-pin"
                | "ssh.copy-password"
                | "ssh.copy-public-key"
                | "ssh.copy-private-key"
                | "ssh.copy-key-passphrase"
                | "secrets.copy-value" => {
                    self.protected_copy(runtime, operation, input, now_millis)
                }
                "items.recovery-codes" => {
                    let id = required_string(input, "id")?;
                    let master_password =
                        Zeroizing::new(bounded_required_string(input, "masterPassword", 8, 1_024)?);
                    runtime
                        .recovery_codes(&id, Some(master_password.as_str()))
                        .map(|codes| json!({ "codes": codes }))
                        .map_err(runtime_error)
                }
                "items.copy-recovery-code" => {
                    let id = required_string(input, "id")?;
                    let master_password =
                        Zeroizing::new(bounded_required_string(input, "masterPassword", 8, 1_024)?);
                    let index = input
                        .get("index")
                        .and_then(Value::as_u64)
                        .filter(|index| *index < 100)
                        .ok_or_else(invalid)? as usize;
                    let mut codes = Zeroizing::new(
                        runtime
                            .recovery_codes(&id, Some(master_password.as_str()))
                            .map_err(runtime_error)?,
                    );
                    if index >= codes.len() {
                        return Err(invalid());
                    }
                    let code = Zeroizing::new(codes.swap_remove(index));
                    self.copy(code, now_millis)
                }
                "items.recovery-codes.import-file" => self.import_recovery_code_file(input),
                "imports.select" => self.import_select(input, now_millis),
                "imports.commit" => {
                    let session_id = required_string(input, "sessionId")?;
                    let payload = self
                        .imports
                        .lock()
                        .map_err(|_| failure("导入状态暂时不可用。"))?
                        .take_payload(&session_id, now_millis.max(0) as u64)
                        .map_err(|message| failure(&message))?;
                    runtime
                        .execute("_native.import.batch", payload)
                        .map_err(runtime_error)
                }
                "imports.cancel" => {
                    let session_id = required_string(input, "sessionId")?;
                    self.imports
                        .lock()
                        .map_err(|_| failure("导入状态暂时不可用。"))?
                        .cancel(&session_id, now_millis.max(0) as u64)
                        .map_err(|message| failure(&message))?;
                    Ok(json!({}))
                }
                "password.generate" => self.generate_password(input),
                "ssh.scan" => self
                    .ssh_scan
                    .lock()
                    .map_err(|_| failure("SSH 扫描状态暂时不可用。"))?
                    .scan(&self.ssh_directory, runtime, now_millis.max(0) as u64)
                    .map_err(|message| failure(&message)),
                "ssh.scan.commit" => {
                    let session_id = required_string(input, "sessionId")?;
                    let entry_ids = input
                        .get("entryIds")
                        .and_then(Value::as_array)
                        .ok_or_else(invalid)?;
                    let public_key_overrides = match input.get("publicKeyOverrides") {
                        None => None,
                        Some(Value::Object(values)) => Some(values),
                        Some(_) => return Err(invalid()),
                    };
                    self.ssh_scan
                        .lock()
                        .map_err(|_| failure("SSH 扫描状态暂时不可用。"))?
                        .commit(
                            &session_id,
                            entry_ids,
                            public_key_overrides,
                            runtime,
                            now_millis.max(0) as u64,
                        )
                        .map_err(|message| failure(&message))
                }
                "ssh.scan.cancel" => {
                    let session_id = required_string(input, "sessionId")?;
                    self.ssh_scan
                        .lock()
                        .map_err(|_| failure("SSH 扫描状态暂时不可用。"))?
                        .cancel(&session_id, now_millis.max(0) as u64)
                        .map_err(|message| failure(&message))?;
                    Ok(json!({}))
                }
                "passkeys.create" | "passkeys.get" => {
                    let request_json = required_string(input, "requestDetailsJson")?;
                    let kind = if operation == "passkeys.create" {
                        "create"
                    } else {
                        "get"
                    };
                    let (rp_id, origin, account) = PasskeyService::describe(kind, &request_json)
                        .map_err(|message| failure(&message))?;
                    let detail = account
                    .map(|account| format!("账号：{account}\n来源：{origin}\n私钥始终保留在 VaultMesh 加密保险库中。"))
                    .unwrap_or_else(|| format!("来源：{origin}\n私钥始终保留在 VaultMesh 加密保险库中。"));
                    let approved = {
                        let _dialog_guard = self.native_dialog_focus.begin();
                        self.app
                            .dialog()
                            .message(detail)
                            .title(if kind == "create" {
                                "创建 Passkey"
                            } else {
                                "使用 Passkey"
                            })
                            .buttons(MessageDialogButtons::OkCancelCustom(
                                if kind == "create" {
                                    "创建 Passkey".into()
                                } else {
                                    "允许登录".into()
                                },
                                "取消".into(),
                            ))
                            .blocking_show()
                    };
                    if !approved {
                        return Err(cancelled());
                    }
                    let now = DateTime::<Utc>::from_timestamp_millis(now_millis)
                        .unwrap_or(DateTime::UNIX_EPOCH)
                        .to_rfc3339_opts(SecondsFormat::Millis, true);
                    let response = if kind == "create" {
                        let default_login_id = input
                            .get("loginId")
                            .and_then(Value::as_str)
                            .and_then(|value| Uuid::parse_str(value).ok());
                        PasskeyService::create(runtime, &request_json, default_login_id, &now)
                    } else {
                        PasskeyService::get(runtime, &request_json, &now)
                    }
                    .map_err(|message| failure(&format!("{message} ({rp_id})")))?;
                    Ok(json!({ "responseJson": response }))
                }
                _ => unreachable!("platform operation checked above"),
            }
        })();
        Some(result)
    }

    fn after_master_unlock(&self, runtime: &DesktopRuntime) -> Result<(), BrowserPlatformError> {
        let path = runtime.current_path();
        let pin = self
            .pin
            .lock()
            .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?;
        pin.disable_if_for_different_vault(&path)
            .and_then(|()| pin.reset_failures(&path))
            .map_err(|message| failure(&message))?;
        self.biometric
            .lock()
            .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
            .disable_if_for_different_vault(&path)
            .map_err(|message| failure(&message))
    }

    fn after_runtime_mutation(&self, operation: &str) -> Result<(), BrowserPlatformError> {
        if operation == "vault.change-password" {
            self.pin
                .lock()
                .map_err(|_| failure("PIN 快速解锁暂时不可用。"))?
                .disable()
                .map_err(|message| failure(&message))?;
            self.biometric
                .lock()
                .map_err(|_| failure("Touch ID 快速解锁暂时不可用。"))?
                .disable()
                .map_err(|message| failure(&message))?;
        }
        Ok(())
    }

    fn confirm_browser_fill(
        &self,
        item_title: &str,
        item_kind: &str,
        origin: &str,
    ) -> Result<bool, BrowserPlatformError> {
        let kind = match item_kind {
            "login" => "登录项目",
            "card" => "支付卡",
            "identity" => "身份资料",
            "secret" => "敏感信息",
            "ssh" => "SSH 凭据",
            _ => return Err(invalid()),
        };
        let _dialog_guard = self.native_dialog_focus.begin();
        Ok(self
            .app
            .dialog()
            .message(format!(
                "允许将{kind}“{item_title}”填充到：\n{origin}\n\nVaultMesh 不会提交表单。"
            ))
            .title("批准浏览器填充")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "允许填充".into(),
                "取消".into(),
            ))
            .blocking_show())
    }

    fn clear(&self) {
        if let Ok(mut files) = self.recovery_files.lock() {
            files.clear();
        }
        if let Ok(mut imports) = self.imports.lock() {
            imports.clear();
        }
        if let Ok(mut scan) = self.ssh_scan.lock() {
            scan.clear();
        }
        if let Ok(mut email) = self.email_otp.lock() {
            let _ = email.stop_browser_boost(None);
        }
        if let Ok(mut seen) = self.email_fill_seen.lock() {
            seen.clear();
        }
    }
}

fn queue_email_scan(service: Arc<Mutex<EmailOtpService>>, plan: EmailScanPlan) {
    std::thread::spawn(move || {
        let execution = EmailOtpService::execute_scan(plan);
        if let Ok(mut service) = service.lock() {
            service.queue_scan_execution(execution);
        }
    });
}

pub(crate) fn is_platform_operation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.backup"
            | "vault.restore"
            | "biometric.status"
            | "biometric.enable"
            | "biometric.disable"
            | "biometric.unlock"
            | "pin.status"
            | "pin.enable"
            | "pin.disable"
            | "pin.unlock"
            | "security.settings.get"
            | "security.settings.update"
            | "browser.pairing.revoke"
            | "email.otp.watch"
            | "email.otp.poll"
            | "email.otp.candidates"
            | "email.otp.fill"
            | "items.copy-username"
            | "items.copy-password"
            | "items.copy-totp"
            | "items.recovery-codes"
            | "items.copy-recovery-code"
            | "items.recovery-codes.import-file"
            | "cards.copy-number"
            | "cards.copy-security-code"
            | "cards.copy-pin"
            | "ssh.copy-password"
            | "ssh.copy-public-key"
            | "ssh.copy-private-key"
            | "ssh.copy-key-passphrase"
            | "secrets.copy-value"
            | "imports.select"
            | "imports.commit"
            | "imports.cancel"
            | "password.generate"
            | "ssh.scan"
            | "ssh.scan.commit"
            | "ssh.scan.cancel"
            | "passkeys.create"
            | "passkeys.get"
    )
}

fn random_index(upper: usize) -> usize {
    let upper = upper as u32;
    let zone = u32::MAX - u32::MAX % upper;
    loop {
        let value = OsRng.next_u32();
        if value < zone {
            return (value % upper) as usize;
        }
    }
}

fn required_string(input: &Map<String, Value>, key: &str) -> Result<String, BrowserPlatformError> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(invalid)
}

fn bounded_required_string(
    input: &Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, BrowserPlatformError> {
    required_string(input, key).and_then(|value| {
        let length = value.encode_utf16().count();
        if (minimum..=maximum).contains(&length) {
            Ok(value)
        } else {
            Err(invalid())
        }
    })
}

fn optional_string(
    input: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, BrowserPlatformError> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(invalid()),
    }
}

fn runtime_error(error: DesktopRuntimeError) -> BrowserPlatformError {
    let code = match error.status() {
        VAULTMESH_STATUS_LOCKED => "unlock-required",
        VAULTMESH_STATUS_REAUTH_REQUIRED => "re-prompt-required",
        VAULTMESH_STATUS_INVALID_ARGUMENT => "invalid-request",
        _ => "operation-failed",
    };
    BrowserPlatformError {
        code,
        message: error.public_message().to_owned(),
    }
}

fn invalid() -> BrowserPlatformError {
    BrowserPlatformError {
        code: "invalid-request",
        message: "插件请求格式无效。".to_owned(),
    }
}

fn cancelled() -> BrowserPlatformError {
    BrowserPlatformError {
        code: "cancelled",
        message: "操作已取消。".to_owned(),
    }
}

fn failure(message: &str) -> BrowserPlatformError {
    BrowserPlatformError {
        code: "operation-failed",
        message: message.to_owned(),
    }
}
