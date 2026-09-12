use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::FileTypeExt, net::UnixListener},
    sync::atomic::{AtomicBool, Ordering},
    thread::{self, JoinHandle},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use uuid::Uuid;
use vaultmesh_ffi::{
    DesktopRuntime, DesktopRuntimeError, VAULTMESH_STATUS_AUTH_FAILED,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_LOCKED,
};
use zeroize::{Zeroize, Zeroizing};

use crate::browser_fill::BrowserFillService;

const RPC_VERSION: u32 = 2;
const MAX_LINE_BYTES: usize = 384 * 1024;
const MAX_RPC_BYTES: usize = 240 * 1024;
const MAX_BROKER_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_LIFETIME_MILLIS: i64 = 70_000;
const MAX_CLOCK_SKEW_MILLIS: i64 = 30_000;

pub const TAURI_BROWSER_SLICE_OPERATIONS: &[&str] = &[
    "vault.status",
    "vault.workspace",
    "vault.create",
    "vault.unlock",
    "vault.unlock-history",
    "vault.lock",
    "vault.backup",
    "vault.restore",
    "vault.change-password",
    "biometric.status",
    "biometric.enable",
    "biometric.disable",
    "biometric.unlock",
    "pin.status",
    "pin.enable",
    "pin.disable",
    "pin.unlock",
    "security.settings.get",
    "security.settings.update",
    "events.poll",
    "browser.pairing.status",
    "browser.pairing.revoke",
    "browser.autofill.candidates",
    "browser.autofill.profile",
    "browser.autofill.execute",
    "browser.card.capture-status",
    "browser.login.password-changed",
    "browser.fill.record",
    "browser.fill.history",
    "browser.fill.request",
    "email.otp.watch",
    "email.otp.poll",
    "email.otp.candidates",
    "email.otp.fill",
    "passkeys.create",
    "passkeys.get",
    "confirmation.request",
    "items.list",
    "items.detail",
    "items.add",
    "items.update",
    "items.delete",
    "items.copy-username",
    "items.copy-password",
    "items.copy-totp",
    "items.recovery-codes",
    "items.copy-recovery-code",
    "items.recovery-codes.import-file",
    "items.trash.list",
    "items.trash.restore",
    "items.trash.purge",
    "items.trash.empty",
    "items.history.list",
    "items.history.restore",
    "items.history.clear",
    "cards.list",
    "cards.detail",
    "cards.add",
    "cards.update",
    "cards.delete",
    "cards.copy-number",
    "cards.copy-security-code",
    "cards.copy-pin",
    "cards.trash.list",
    "cards.trash.restore",
    "cards.trash.purge",
    "cards.trash.empty",
    "cards.history.list",
    "cards.history.restore",
    "cards.history.clear",
    "identities.list",
    "identities.detail",
    "identities.add",
    "identities.update",
    "identities.delete",
    "identities.trash.list",
    "identities.trash.restore",
    "identities.trash.purge",
    "identities.trash.empty",
    "identities.history.list",
    "identities.history.restore",
    "identities.history.clear",
    "ssh.list",
    "ssh.detail",
    "ssh.add",
    "ssh.update",
    "ssh.delete",
    "ssh.copy-password",
    "ssh.copy-public-key",
    "ssh.copy-private-key",
    "ssh.copy-key-passphrase",
    "ssh.trash.list",
    "ssh.trash.restore",
    "ssh.trash.purge",
    "ssh.trash.empty",
    "ssh.history.list",
    "ssh.history.restore",
    "ssh.history.clear",
    "ssh.scan",
    "ssh.scan.commit",
    "ssh.scan.cancel",
    "secrets.list",
    "secrets.detail",
    "secrets.add",
    "secrets.update",
    "secrets.delete",
    "secrets.copy-value",
    "imports.select",
    "imports.commit",
    "imports.cancel",
    "password.generate",
    "browser.generated.copy",
    "password.health",
];

const CONFIRMATION_LIFETIME_MILLIS: i64 = 30_000;

fn requires_unlock(operation: &str) -> bool {
    !matches!(
        operation,
        "vault.status"
            | "vault.create"
            | "vault.unlock"
            | "vault.unlock-history"
            | "biometric.status"
            | "biometric.unlock"
            | "pin.status"
            | "pin.unlock"
            | "events.poll"
            | "browser.pairing.status"
            | "browser.pairing.revoke"
            | "confirmation.request"
    )
}

fn requires_gesture(operation: &str) -> bool {
    !matches!(
        operation,
        "vault.status"
            | "vault.workspace"
            | "vault.unlock-history"
            | "biometric.status"
            | "pin.status"
            | "security.settings.get"
            | "events.poll"
            | "browser.pairing.status"
            | "browser.autofill.candidates"
            | "browser.autofill.profile"
            | "browser.autofill.execute"
            | "browser.card.capture-status"
            | "browser.login.password-changed"
            | "browser.fill.record"
            | "browser.fill.history"
            | "email.otp.poll"
            | "email.otp.candidates"
            | "passkeys.create"
            | "passkeys.get"
            | "items.list"
            | "items.trash.list"
            | "items.history.list"
            | "cards.list"
            | "cards.detail"
            | "cards.trash.list"
            | "cards.history.list"
            | "identities.list"
            | "identities.detail"
            | "identities.trash.list"
            | "identities.history.list"
            | "ssh.list"
            | "ssh.detail"
            | "ssh.trash.list"
            | "ssh.history.list"
            | "secrets.list"
            | "secrets.detail"
            | "password.health"
    )
}

fn requires_confirmation(operation: &str) -> bool {
    matches!(
        operation,
        "vault.create"
            | "vault.backup"
            | "vault.restore"
            | "vault.change-password"
            | "browser.pairing.revoke"
            | "items.delete"
            | "items.recovery-codes.import-file"
            | "items.trash.purge"
            | "items.trash.empty"
            | "items.history.restore"
            | "items.history.clear"
            | "cards.delete"
            | "cards.trash.purge"
            | "cards.trash.empty"
            | "cards.history.restore"
            | "cards.history.clear"
            | "identities.delete"
            | "identities.trash.purge"
            | "identities.trash.empty"
            | "identities.history.restore"
            | "identities.history.clear"
            | "ssh.delete"
            | "ssh.trash.purge"
            | "ssh.trash.empty"
            | "ssh.history.restore"
            | "ssh.history.clear"
            | "ssh.scan.commit"
            | "secrets.delete"
            | "imports.commit"
    )
}

type HmacSha256 = Hmac<Sha256>;

pub struct BrowserPlatformError {
    pub code: &'static str,
    pub message: String,
}

pub trait BrowserBrokerPlatform: Send + Sync {
    fn dispatch(
        &self,
        runtime: &mut DesktopRuntime,
        operation: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Option<Result<Value, BrowserPlatformError>>;

    fn after_master_unlock(&self, _runtime: &DesktopRuntime) -> Result<(), BrowserPlatformError> {
        Ok(())
    }

    fn after_runtime_mutation(&self, _operation: &str) -> Result<(), BrowserPlatformError> {
        Ok(())
    }

    fn confirm_browser_fill(
        &self,
        _item_title: &str,
        _item_kind: &str,
        _origin: &str,
    ) -> Result<bool, BrowserPlatformError> {
        Ok(false)
    }

    fn clear(&self) {}
}

struct UnavailableBrowserPlatform;

impl BrowserBrokerPlatform for UnavailableBrowserPlatform {
    fn dispatch(
        &self,
        _runtime: &mut DesktopRuntime,
        _operation: &str,
        _input: &Map<String, Value>,
        _now_millis: i64,
    ) -> Option<Result<Value, BrowserPlatformError>> {
        None
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    request_id: String,
    auth: String,
    payload: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatedBody<'a> {
    request_id: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcRequest {
    kind: String,
    version: u32,
    request_id: String,
    issued_at: String,
    expires_at: String,
    operation: String,
    #[serde(default)]
    input: Map<String, Value>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserEvent {
    sequence: u64,
    r#type: &'static str,
    occurred_at: String,
}

struct Confirmation {
    operation: String,
    user_gesture_id: Uuid,
    expires_at: i64,
}

/// Rust-owned Browser RPC v2 lifecycle slice with browser-only authorization.
pub struct BrowserBrokerCore {
    runtime: DesktopRuntime,
    pairing_secret: Zeroizing<[u8; 32]>,
    seen_request_ids: HashMap<Uuid, i64>,
    events: Vec<BrowserEvent>,
    event_sequence: u64,
    sync_merge_generation: u64,
    confirmations: HashMap<Uuid, Confirmation>,
    fill: BrowserFillService,
    unlock_history: Value,
    platform: Arc<dyn BrowserBrokerPlatform>,
    revoked: bool,
}

impl BrowserBrokerCore {
    pub(crate) fn lock_for_system(&mut self) {
        self.runtime.lock();
        self.platform.clear();
        self.confirmations.clear();
        self.fill.clear();
        self.record_event("vault-locked", Utc::now().timestamp_millis());
    }
    pub fn new(
        vault_path: PathBuf,
        pairing_secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, DesktopRuntimeError> {
        Self::new_with_platform(
            vault_path,
            pairing_secret,
            Arc::new(UnavailableBrowserPlatform),
        )
    }

    pub fn new_with_platform(
        vault_path: PathBuf,
        pairing_secret: Zeroizing<[u8; 32]>,
        platform: Arc<dyn BrowserBrokerPlatform>,
    ) -> Result<Self, DesktopRuntimeError> {
        Ok(Self {
            runtime: DesktopRuntime::new(vault_path)?,
            pairing_secret,
            seen_request_ids: HashMap::new(),
            events: Vec::new(),
            event_sequence: 0,
            sync_merge_generation: 0,
            confirmations: HashMap::new(),
            fill: BrowserFillService::default(),
            unlock_history: json!([]),
            platform,
            revoked: false,
        })
    }

    pub fn handle_line(&mut self, line: &[u8]) -> Value {
        self.handle_line_at(line, Utc::now().timestamp_millis())
    }

    fn handle_line_at(&mut self, line: &[u8], now_millis: i64) -> Value {
        if self.revoked {
            return host_status("unpaired", None);
        }
        if line.is_empty() || line.len() > MAX_LINE_BYTES {
            return host_status("invalid-message", None);
        }
        let envelope: Envelope = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) => return host_status("invalid-message", None),
        };
        if !self.authenticate(&envelope) {
            return host_status("unpaired", None);
        }
        let payload = match decode_base64url(&envelope.payload) {
            Some(value) if value.len() <= MAX_RPC_BYTES => value,
            _ => return host_status("invalid-message", Some(&envelope.request_id)),
        };
        self.handle_rpc(&envelope.request_id, &payload, now_millis)
    }

    fn authenticate(&self, envelope: &Envelope) -> bool {
        let Ok(body) = serde_json::to_vec(&AuthenticatedBody {
            request_id: &envelope.request_id,
            payload: &envelope.payload,
        }) else {
            return false;
        };
        let Some(supplied) = decode_base64url(&envelope.auth) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(self.pairing_secret.as_ref()) else {
            return false;
        };
        mac.update(&body);
        mac.verify_slice(&supplied).is_ok()
    }

    fn handle_rpc(&mut self, envelope_request_id: &str, payload: &[u8], now_millis: i64) -> Value {
        let raw: Value = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => {
                return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
            }
        };
        if raw
            .get("version")
            .and_then(Value::as_u64)
            .is_some_and(|version| version != RPC_VERSION as u64)
        {
            return rpc_failure(
                envelope_request_id,
                "update-required",
                "VaultMesh 插件或桌面端版本不兼容，请更新后重试。",
            );
        }
        let request: RpcRequest = match serde_json::from_value(raw) {
            Ok(value) => value,
            Err(_) => {
                return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
            }
        };
        let Some(request_id) = Uuid::parse_str(&request.request_id).ok() else {
            return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
        };
        if request.kind != "vaultmesh.rpc"
            || request.version != RPC_VERSION
            || request.request_id != envelope_request_id
            || request.operation.is_empty()
            || request.operation.len() > 128
        {
            return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
        }

        let Some(issued_at) = parse_rpc_time(&request.issued_at) else {
            return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
        };
        let Some(expires_at) = parse_rpc_time(&request.expires_at) else {
            return rpc_failure(envelope_request_id, "invalid-request", "插件请求格式无效。");
        };
        if expires_at <= now_millis
            || issued_at > now_millis.saturating_add(MAX_CLOCK_SKEW_MILLIS)
            || expires_at.saturating_sub(issued_at) > MAX_LIFETIME_MILLIS
        {
            return rpc_failure(
                envelope_request_id,
                "request-expired",
                "插件请求已过期，请重试。",
            );
        }
        self.seen_request_ids
            .retain(|_, expiry| *expiry > now_millis);
        if self.seen_request_ids.contains_key(&request_id) {
            return rpc_failure(
                envelope_request_id,
                "request-replayed",
                "插件请求不能重复使用。",
            );
        }
        self.seen_request_ids.insert(request_id, expires_at);

        if !TAURI_BROWSER_SLICE_OPERATIONS.contains(&request.operation.as_str()) {
            return rpc_failure(
                envelope_request_id,
                "unsupported-operation",
                "该插件操作不被允许。",
            );
        }
        if self.runtime.is_unlocked()
            && let Err(error) = self.runtime.refresh_from_disk()
        {
            return runtime_failure(envelope_request_id, error);
        }
        if self.runtime.sync_relay().merged_generation() != self.sync_merge_generation {
            self.sync_merge_generation = self.runtime.sync_relay().merged_generation();
            self.fill.clear();
            self.confirmations.clear();
            self.record_event("vault-changed", now_millis);
        }
        if requires_unlock(&request.operation) && !self.runtime.is_unlocked() {
            return rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            );
        }
        if (requires_gesture(&request.operation)
            || (request.operation == "browser.autofill.execute" && (request.input.contains_key("nativeItemPlan") || request.input.contains_key("nativeLoginPlan") && request.input.get("mode").and_then(Value::as_str) != Some("automatic"))))
            && !valid_gesture(&request.input) {
            return rpc_failure(
                envelope_request_id,
                "invalid-request",
                "该操作需要新的用户手势。",
            );
        }
        self.confirmations
            .retain(|_, confirmation| confirmation.expires_at > now_millis);
        if requires_confirmation(&request.operation)
            && !self.consume_confirmation(&request.operation, &request.input, now_millis)
        {
            return rpc_failure(
                envelope_request_id,
                "confirmation-required",
                "请先确认该操作。",
            );
        }

        match request.operation.as_str() {
            "vault.status" => rpc_success(envelope_request_id, json!(self.runtime.status())),
            "vault.workspace" => {
                let result = self.workspace_snapshot();
                match result {
                    Ok(snapshot) => rpc_success(envelope_request_id, snapshot),
                    Err(error) => runtime_failure(envelope_request_id, error),
                }
            }
            "vault.create" => {
                let Some(password) = request
                    .input
                    .get("masterPassword")
                    .and_then(Value::as_str)
                    .filter(|value| (8..=1_024).contains(&value.len()))
                else {
                    return rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        "插件请求格式无效。",
                    );
                };
                match self.runtime.create_for_browser(password.to_owned()) {
                    Ok(status) => {
                        if let Err(error) = self.platform.after_master_unlock(&self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        self.refresh_unlock_history();
                        rpc_success(
                            envelope_request_id,
                            json!({ "cancelled": false, "status": status }),
                        )
                    }
                    Err(error) => runtime_failure(envelope_request_id, error),
                }
            }
            "vault.unlock" => {
                let Some(password) = request
                    .input
                    .get("masterPassword")
                    .and_then(Value::as_str)
                    .filter(|value| (8..=1_024).contains(&value.len()))
                else {
                    return rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        "插件请求格式无效。",
                    );
                };
                match self.runtime.unlock_for_browser(password.to_owned()) {
                    Ok(status) => {
                        if let Err(error) = self.platform.after_master_unlock(&self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        self.refresh_unlock_history();
                        rpc_success(
                            envelope_request_id,
                            json!({ "cancelled": false, "status": status }),
                        )
                    }
                    Err(error) => runtime_failure(envelope_request_id, error),
                }
            }
            "vault.unlock-history" => rpc_success(envelope_request_id, self.unlock_history.clone()),
            "vault.lock" => {
                let status = self.runtime.lock();
                self.platform.clear();
                self.fill.clear();
                self.record_event("vault-locked", now_millis);
                rpc_success(envelope_request_id, json!(status))
            }
            "events.poll" => {
                let after = request
                    .input
                    .get("after")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                rpc_success(
                    envelope_request_id,
                    json!({
                        "sequence": self.event_sequence,
                        "events": self.events.iter().filter(|event| event.sequence > after).cloned().collect::<Vec<_>>()
                    }),
                )
            }
            "browser.pairing.status" => rpc_success(envelope_request_id, json!({ "paired": true })),
            "confirmation.request" => {
                self.create_confirmation(envelope_request_id, &request.input, now_millis)
            }
            "browser.autofill.candidates" => {
                match self.fill.candidates(&mut self.runtime, &request.input) {
                    Ok(result) => rpc_success(envelope_request_id, result),
                    Err(error) => rpc_failure(envelope_request_id, error.code, &error.message),
                }
            }
            "browser.autofill.profile" => {
                match self.fill.profile(&mut self.runtime, &request.input) {
                    Ok(result) => rpc_success(envelope_request_id, result),
                    Err(error) => rpc_failure(envelope_request_id, error.code, &error.message),
                }
            }
            "browser.autofill.execute" => {
                match self
                    .fill
                    .execute(&mut self.runtime, &request.input, now_millis)
                {
                    Ok(result) => rpc_success(envelope_request_id, result),
                    Err(error) => rpc_failure(envelope_request_id, error.code, &error.message),
                }
            }
            "browser.fill.request" => {
                let prompt = match self.fill.prompt(&request.input, now_millis) {
                    Ok(prompt) => prompt,
                    Err(error) => {
                        return rpc_failure(envelope_request_id, error.code, &error.message);
                    }
                };
                match self.platform.confirm_browser_fill(
                    &prompt.item_title,
                    &prompt.item_kind,
                    &prompt.origin,
                ) {
                    Ok(true) => {
                        match self
                            .fill
                            .execute(&mut self.runtime, &request.input, now_millis)
                        {
                            Ok(result) => rpc_success(envelope_request_id, result),
                            Err(error) => {
                                rpc_failure(envelope_request_id, error.code, &error.message)
                            }
                        }
                    }
                    Ok(false) => rpc_failure(
                        envelope_request_id,
                        "cancelled",
                        "用户取消了桌面端填充审批。",
                    ),
                    Err(error) => rpc_failure(envelope_request_id, error.code, &error.message),
                }
            }
            operation if is_runtime_operation(operation) => {
                match self
                    .runtime
                    .execute(operation, Value::Object(request.input))
                {
                    Ok(result) => {
                        if is_runtime_mutation(operation) {
                            if let Err(error) = self.platform.after_runtime_mutation(operation) {
                                return rpc_failure(
                                    envelope_request_id,
                                    error.code,
                                    &error.message,
                                );
                            }
                            self.record_event("vault-changed", now_millis);
                            if operation == "vault.change-password" {
                                self.refresh_unlock_history();
                            }
                        }
                        rpc_success(envelope_request_id, result)
                    }
                    Err(error) => runtime_failure(envelope_request_id, error),
                }
            }
            operation => match self.platform.dispatch(
                &mut self.runtime,
                operation,
                &request.input,
                now_millis,
            ) {
                Some(Ok(result)) => {
                    if matches!(
                        operation,
                        "vault.restore" | "pin.unlock" | "biometric.unlock"
                    ) {
                        if let Err(error) = self.platform.after_master_unlock(&self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        self.refresh_unlock_history();
                    }
                    if matches!(
                        operation,
                        "vault.restore"
                            | "imports.commit"
                            | "ssh.scan.commit"
                            | "passkeys.create"
                            | "passkeys.get"
                    ) {
                        self.record_event("vault-changed", now_millis);
                    }
                    if operation == "browser.pairing.revoke" {
                        self.record_event("pairing-revoked", now_millis);
                        self.revoked = true;
                        self.runtime.lock();
                        self.confirmations.clear();
                        self.fill.clear();
                        self.pairing_secret.zeroize();
                    }
                    rpc_success(envelope_request_id, result)
                }
                Some(Err(error)) => rpc_failure(envelope_request_id, error.code, &error.message),
                None => rpc_failure(
                    envelope_request_id,
                    "desktop-unavailable",
                    "该 Tauri 平台服务尚不可用。",
                ),
            },
        }
    }

    fn create_confirmation(
        &mut self,
        request_id: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Value {
        let Some(operation) = input.get("operation").and_then(Value::as_str) else {
            return rpc_failure(request_id, "invalid-request", "插件请求格式无效。");
        };
        if !TAURI_BROWSER_SLICE_OPERATIONS.contains(&operation) || !requires_confirmation(operation)
        {
            return rpc_failure(
                request_id,
                "unsupported-operation",
                "该操作不支持浏览器确认。",
            );
        }
        if requires_unlock(operation) && !self.runtime.is_unlocked() {
            return rpc_failure(
                request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            );
        }
        let Some(user_gesture_id) = input
            .get("userGestureId")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return rpc_failure(request_id, "invalid-request", "插件请求格式无效。");
        };
        let token = Uuid::new_v4();
        let expires_at = now_millis.saturating_add(CONFIRMATION_LIFETIME_MILLIS);
        self.confirmations.insert(
            token,
            Confirmation {
                operation: operation.to_owned(),
                user_gesture_id,
                expires_at,
            },
        );
        rpc_success(
            request_id,
            json!({
                "confirmationToken": token,
                "expiresAt": DateTime::<Utc>::from_timestamp_millis(expires_at)
                    .unwrap_or(DateTime::UNIX_EPOCH)
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
        )
    }

    fn consume_confirmation(
        &mut self,
        operation: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> bool {
        let Some(token) = input
            .get("confirmationToken")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return false;
        };
        let Some(user_gesture_id) = input
            .get("userGestureId")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return false;
        };
        let valid = self.confirmations.get(&token).is_some_and(|confirmation| {
            confirmation.operation == operation
                && confirmation.user_gesture_id == user_gesture_id
                && confirmation.expires_at > now_millis
        });
        if valid {
            self.confirmations.remove(&token);
        }
        valid
    }

    fn refresh_unlock_history(&mut self) {
        if let Ok(history) = self.runtime.execute("vault.unlock-history", json!({})) {
            self.unlock_history = history;
        }
    }

    fn workspace_snapshot(&mut self) -> Result<Value, DesktopRuntimeError> {
        self.runtime.workspace_snapshot()
    }

    fn record_event(&mut self, event_type: &'static str, now_millis: i64) {
        self.event_sequence = self.event_sequence.saturating_add(1);
        self.events.push(BrowserEvent {
            sequence: self.event_sequence,
            r#type: event_type,
            occurred_at: DateTime::<Utc>::from_timestamp_millis(now_millis)
                .unwrap_or(DateTime::UNIX_EPOCH)
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        if self.events.len() > 32 {
            self.events.drain(..self.events.len() - 32);
        }
    }
}

impl Drop for BrowserBrokerCore {
    fn drop(&mut self) {
        self.runtime.lock();
        self.platform.clear();
        self.seen_request_ids.clear();
        self.events.clear();
        self.confirmations.clear();
        self.fill.clear();
        self.unlock_history = json!([]);
    }
}
