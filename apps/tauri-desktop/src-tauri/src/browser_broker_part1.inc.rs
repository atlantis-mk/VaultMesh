use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs,
    os::unix::{fs::FileTypeExt, net::UnixListener},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use uuid::Uuid;
use vaultmesh_core::{PasskeyError, describe_passkey_request};
use vaultmesh_ffi::{
    DesktopRuntime, DesktopRuntimeError, VAULTMESH_STATUS_AUTH_FAILED,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_LOCKED, VAULTMESH_STATUS_NOT_FOUND,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{browser_fill::BrowserFillService, passkey_service::PasskeyService};

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
    "biometric.authentication.start",
    "biometric.authentication.poll",
    "biometric.authentication.cancel",
    "pin.status",
    "pin.enable",
    "pin.disable",
    "pin.unlock",
    "security.settings.get",
    "security.settings.update",
    "events.poll",
    "browser.pairing.status",
    "browser.pairing.revoke",
    "browser.unlock.request",
    "browser.autofill.candidates",
    "browser.autofill.profile",
    "browser.autofill.execute",
    "browser.card.capture-status",
    "browser.login.password-changed",
    "browser.fill.record",
    "browser.fill.history",
    "browser.fill.request",
    "device.assist.capabilities",
    "device.assist.start",
    "device.assist.poll",
    "device.assist.select",
    "device.assist.finish",
    "device.assist.cancel",
    "email.otp.watch",
    "email.otp.poll",
    "email.otp.candidates",
    "email.otp.fill",
    "passkeys.create",
    "passkeys.probe",
    "passkeys.get",
    "passkeys.cancel",
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
            | "vault.lock"
            | "vault.unlock-history"
            | "biometric.status"
            | "biometric.unlock"
            | "biometric.authentication.start"
            | "biometric.authentication.poll"
            | "biometric.authentication.cancel"
            | "pin.status"
            | "pin.unlock"
            | "events.poll"
            | "browser.pairing.status"
            | "browser.pairing.revoke"
            | "browser.unlock.request"
            | "browser.autofill.candidates"
            | "passkeys.create"
            | "passkeys.probe"
            | "passkeys.get"
            | "passkeys.cancel"
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
            | "biometric.authentication.poll"
            | "biometric.authentication.cancel"
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
            | "device.assist.capabilities" | "device.assist.poll" | "device.assist.cancel"
            | "email.otp.poll"
            | "email.otp.candidates"
            | "passkeys.create"
            | "passkeys.probe"
            | "passkeys.get"
            | "passkeys.cancel"
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

#[derive(Debug)]
pub struct BrowserPlatformError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserUnlockSource {
    Popup,
    Autofill,
    Passkey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserUnlockFactor {
    MasterPassword,
    Pin,
    Biometric,
}

#[derive(Clone)]
pub struct BrowserUnlockResolution {
    pub factor: BrowserUnlockFactor,
    pub vault_path: PathBuf,
    pub vault_key: Zeroizing<Vec<u8>>,
    pub master_password: Option<Zeroizing<String>>,
}

pub struct BrowserSessionUnlockRequest {
    pub passkey_request: Option<(Uuid, i64)>,
    pub vault_path: PathBuf,
    pub source: BrowserUnlockSource,
    pub origin: Option<String>,
    pub item_title: Option<String>,
    pub item_kind: Option<String>,
    pub master_password_reprompt: bool,
}

pub struct BrowserSessionUnlockWaiter {
    wait_fn: Box<dyn FnOnce() -> Result<BrowserUnlockResolution, BrowserPlatformError> + Send>,
}

impl BrowserSessionUnlockWaiter {
    pub fn new<F>(wait_fn: F) -> Self
    where
        F: FnOnce() -> Result<BrowserUnlockResolution, BrowserPlatformError> + Send + 'static,
    {
        Self {
            wait_fn: Box::new(wait_fn),
        }
    }

    pub fn wait(self) -> Result<BrowserUnlockResolution, BrowserPlatformError> {
        (self.wait_fn)()
    }
}

pub struct BrowserRepromptRequest {
    pub vault_path: PathBuf,
    pub origin: String,
    pub item_title: String,
    pub item_kind: String,
}

#[derive(Clone)]
pub struct BrowserRepromptResolution {
    pub vault_path: PathBuf,
    pub vault_key: Option<Zeroizing<Vec<u8>>>,
    pub master_password: Zeroizing<String>,
}

pub struct BrowserRepromptWaiter {
    wait_fn: Box<dyn FnOnce() -> Result<BrowserRepromptResolution, BrowserPlatformError> + Send>,
}

impl BrowserRepromptWaiter {
    pub fn new<F>(wait_fn: F) -> Self
    where
        F: FnOnce() -> Result<BrowserRepromptResolution, BrowserPlatformError> + Send + 'static,
    {
        Self {
            wait_fn: Box::new(wait_fn),
        }
    }

    pub fn wait(self) -> Result<BrowserRepromptResolution, BrowserPlatformError> {
        (self.wait_fn)()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyOpKind {
    Create,
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyConfirmationRequest {
    pub kind: PasskeyOpKind,
    pub rp_id: String,
    pub origin: String,
    pub top_origin: Option<String>,
    pub account: Option<String>,
}

pub struct DeferredBrokerExecution {
    pub(crate) envelope_request_id: String,
    validity: DeferredBrowserRequest,
    work: DeferredBrokerWork,
}

#[derive(Clone, Copy)]
struct DeferredBrowserRequest {
    id: Uuid,
    generation: u64,
    expires_at_millis: i64,
    passkey: bool,
}

enum DeferredBrokerWork {
    BrowserSessionUnlock {
        waiter: BrowserSessionUnlockWaiter,
    },
    AutofillSessionUnlock {
        input: Map<String, Value>,
        waiter: BrowserSessionUnlockWaiter,
    },
    AutofillReprompt {
        input: Map<String, Value>,
        waiter: BrowserRepromptWaiter,
    },
    Passkey(DeferredPasskeyWork),
}

struct DeferredPasskeyWork {
    kind: PasskeyOpKind,
    request_json: String,
    rp_id: String,
    origin: String,
    top_origin: Option<String>,
    account: Option<String>,
    login_id: Option<Uuid>,
    requested_item_id: Option<Uuid>,
    requested_credential_id: Option<String>,
    selected_item_id: Option<Uuid>,
    selected_credential_id: Option<String>,
    expires_at_millis: i64,
    unlock_waiter: Option<BrowserSessionUnlockWaiter>,
    platform: Arc<dyn BrowserBrokerPlatform>,
}

struct PreparedPasskeyExecution {
    kind: PasskeyOpKind,
    request_json: String,
    rp_id: String,
    login_id: Option<Uuid>,
    selected_item_id: Option<Uuid>,
    selected_credential_id: Option<String>,
    expires_at_millis: i64,
}

pub enum BrokerLineOutcome {
    Immediate(Value),
    Deferred(DeferredBrokerExecution),
}

impl DeferredBrokerExecution {
    pub fn wait_and_finish(self, broker: &Arc<Mutex<BrowserBrokerCore>>) -> Value {
        let request_id = self.envelope_request_id.as_str();
        let validity = self.validity;

        match self.work {
            DeferredBrokerWork::BrowserSessionUnlock { waiter } => {
                let resolution = waiter.wait();
                Self::with_valid_broker(broker, request_id, validity, |guard, now| {
                    guard.finish_browser_session_unlock(request_id, resolution, now)
                })
            }
            DeferredBrokerWork::AutofillSessionUnlock { input, waiter } => {
                let resolution = waiter.wait();
                Self::with_valid_broker(broker, request_id, validity, |guard, now| {
                    guard.finish_autofill_session_unlock(request_id, &input, resolution, now)
                })
            }
            DeferredBrokerWork::AutofillReprompt { input, waiter } => {
                let resolution = waiter.wait();
                Self::with_valid_broker(broker, request_id, validity, |guard, now| {
                    guard.finish_autofill_reprompt(request_id, &input, resolution, now)
                })
            }
            DeferredBrokerWork::Passkey(mut work) => {
                if let Some(waiter) = work.unlock_waiter.take() {
                    let resolution = waiter.wait();
                    let result = Self::with_valid_broker(broker, request_id, validity, |guard, now| {
                        guard.commit_browser_passkey_unlock(request_id, &mut work, resolution, now)
                            .err().unwrap_or(Value::Null)
                    });
                    if !result.is_null() {
                        return result;
                    }
                }
                let valid = Self::with_valid_broker(broker, request_id, validity, |_, _| Value::Null);
                if !valid.is_null() {
                    return valid;
                }
                let prepared = match confirm_passkey_outside_lock(
                    request_id,
                    work,
                    || Utc::now().timestamp_millis(),
                ) {
                    Ok(prepared) => prepared,
                    Err(response) => return response,
                };
                Self::with_valid_broker(broker, request_id, validity, |guard, now| {
                    guard.finish_passkey(request_id, prepared, now)
                })
            }
        }
    }

    fn with_valid_broker(
        broker: &Arc<Mutex<BrowserBrokerCore>>,
        request_id: &str,
        validity: DeferredBrowserRequest,
        finish: impl FnOnce(&mut BrowserBrokerCore, i64) -> Value,
    ) -> Value {
        let Ok(mut guard) = broker.lock() else {
            return host_status("desktop-unavailable", Some(request_id));
        };
        let now = Utc::now().timestamp_millis();
        guard.validate_deferred(request_id, validity, now)
            .unwrap_or_else(|| finish(&mut guard, now))
    }

    fn finish_sync_at(self, broker: &mut BrowserBrokerCore, now_millis: i64) -> Value {
        let envelope_request_id = self.envelope_request_id;
        if let Some(failure) = broker.validate_deferred(&envelope_request_id, self.validity, now_millis) {
            return failure;
        }
        match self.work {
            DeferredBrokerWork::BrowserSessionUnlock { waiter } => {
                let resolution = waiter.wait();
                broker.finish_browser_session_unlock(&envelope_request_id, resolution, now_millis)
            }
            DeferredBrokerWork::AutofillSessionUnlock { input, waiter } => {
                let resolution = waiter.wait();
                broker.finish_autofill_session_unlock(
                    &envelope_request_id,
                    &input,
                    resolution,
                    now_millis,
                )
            }
            DeferredBrokerWork::AutofillReprompt { input, waiter } => {
                let password = waiter.wait();
                broker.finish_autofill_reprompt(
                    &envelope_request_id,
                    &input,
                    password,
                    now_millis,
                )
            }
            DeferredBrokerWork::Passkey(mut work) => {
                if let Some(waiter) = work.unlock_waiter.take() {
                    let resolution = waiter.wait();
                    if let Err(response) = broker.commit_browser_passkey_unlock(
                        &envelope_request_id,
                        &mut work,
                        resolution,
                        now_millis,
                    ) {
                        return response;
                    }
                }
                let prepared = match confirm_passkey_outside_lock(
                    &envelope_request_id,
                    work,
                    || now_millis,
                ) {
                    Ok(prepared) => prepared,
                    Err(response) => return response,
                };
                broker.finish_passkey(&envelope_request_id, prepared, now_millis)
            }
        }
    }
}

pub trait BrowserBrokerPlatform: Send + Sync {
    fn dispatch(
        &self,
        runtime: &mut DesktopRuntime,
        operation: &str,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Option<Result<Value, BrowserPlatformError>>;

    fn after_master_unlock(&self, _runtime: &mut DesktopRuntime) -> Result<(), BrowserPlatformError> {
        Ok(())
    }

    fn after_quick_unlock(&self, _runtime: &mut DesktopRuntime) -> Result<(), BrowserPlatformError> {
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

    fn confirm_passkey(
        &self,
        _request: &PasskeyConfirmationRequest,
    ) -> Result<bool, BrowserPlatformError> {
        Ok(false)
    }

    fn begin_browser_session_unlock(
        &self,
        _request: BrowserSessionUnlockRequest,
    ) -> Option<BrowserSessionUnlockWaiter> {
        None
    }

    fn begin_master_password_reprompt(
        &self,
        _request: BrowserRepromptRequest,
    ) -> Option<BrowserRepromptWaiter> {
        None
    }

    fn cancel_passkey_unlock(&self, _request_id: Uuid) {}

    fn cancel_authentication(&self) {}
    fn preauth_preview_store(
        &self,
    ) -> Option<crate::browser_preauth_preview::BrowserPreAuthPreviewStore> {
        None
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
    cancelled_passkey_requests: HashMap<Uuid, i64>,
    access_generation: u64,
    events: Vec<BrowserEvent>,
    event_sequence: u64,
    sync_merge_generation: u64,
    confirmations: HashMap<Uuid, Confirmation>,
    fill: BrowserFillService,
    preauth_preview: crate::browser_preauth_preview::BrowserPreAuthPreviewStore,
    unlock_history: Value,
    platform: Arc<dyn BrowserBrokerPlatform>,
    revoked: bool,
}

impl BrowserBrokerCore {
    #[cfg(test)]
    pub(crate) fn runtime_for_test(&mut self) -> &mut DesktopRuntime {
        &mut self.runtime
    }

    pub(crate) fn lock_for_system(&mut self) {
        self.lock_browser_session(Utc::now().timestamp_millis());
    }

    fn lock_browser_session(&mut self, now_millis: i64) -> Value {
        let status = self.runtime.lock();
        self.invalidate_deferred();
        self.record_event("vault-locked", now_millis);
        json!(status)
    }

    fn invalidate_deferred(&mut self) {
        self.access_generation = self.access_generation.wrapping_add(1);
        self.platform.clear();
        self.confirmations.clear();
        self.fill.clear();
    }

    fn validate_deferred(
        &self,
        envelope_request_id: &str,
        request: DeferredBrowserRequest,
        now_millis: i64,
    ) -> Option<Value> {
        if self.revoked {
            return Some(host_status("unpaired", None));
        }
        if request.expires_at_millis <= now_millis {
            return Some(rpc_failure(
                envelope_request_id, "request-expired", "插件请求已过期，请重试。",
            ));
        }
        if request.generation != self.access_generation {
            return Some(rpc_failure(
                envelope_request_id,
                "cancelled",
                "会话已锁定，操作已取消。",
            ));
        }
        if request.passkey && self.cancelled_passkey_requests.contains_key(&request.id) {
            return Some(rpc_failure(envelope_request_id, "cancelled", "操作已取消。"));
        }
        None
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
        let preauth_preview = platform
            .preauth_preview_store()
            .unwrap_or_else(crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory);
        Ok(Self {
            runtime: DesktopRuntime::new(vault_path)?,
            pairing_secret,
            seen_request_ids: HashMap::new(),
            cancelled_passkey_requests: HashMap::new(),
            access_generation: 0,
            events: Vec::new(),
            event_sequence: 0,
            sync_merge_generation: 0,
            confirmations: HashMap::new(),
            fill: BrowserFillService::default(),
            preauth_preview,
            unlock_history: json!([]),
            platform,
            revoked: false,
        })
    }

    pub fn handle_line(&mut self, line: &[u8]) -> Value {
        self.handle_line_at(line, Utc::now().timestamp_millis())
    }

    pub fn handle_line_shared(broker: &Arc<Mutex<Self>>, line: &[u8]) -> Value {
        let outcome = match broker.lock() {
            Ok(mut guard) => guard.handle_line_or_defer_at(line, Utc::now().timestamp_millis()),
            Err(_) => return host_status("desktop-unavailable", None),
        };
        match outcome {
            BrokerLineOutcome::Immediate(value) => value,
            BrokerLineOutcome::Deferred(deferred) => deferred.wait_and_finish(broker),
        }
    }

    pub(crate) fn handle_line_or_defer(&mut self, line: &[u8]) -> BrokerLineOutcome {
        self.handle_line_or_defer_at(line, Utc::now().timestamp_millis())
    }

    pub(crate) fn handle_http_payload_or_defer(&mut self, payload: &[u8]) -> BrokerLineOutcome {
        self.handle_http_payload_or_defer_at(payload, Utc::now().timestamp_millis())
    }

    fn handle_http_payload_or_defer_at(
        &mut self,
        payload: &[u8],
        now_millis: i64,
    ) -> BrokerLineOutcome {
        if self.revoked {
            return BrokerLineOutcome::Immediate(host_status("unpaired", None));
        }
        if payload.is_empty() || payload.len() > MAX_LINE_BYTES {
            return BrokerLineOutcome::Immediate(host_status("invalid-message", None));
        }
        if let Ok(envelope) = serde_json::from_slice::<Envelope>(payload) {
            if self.authenticate(&envelope) {
                if let Some(inner) = decode_base64url(&envelope.payload) {
                    if inner.len() <= MAX_RPC_BYTES {
                        return self.handle_rpc_or_defer(&envelope.request_id, &inner, now_millis);
                    }
                }
            }
        }
        let raw: Value = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => return BrokerLineOutcome::Immediate(host_status("invalid-message", None)),
        };
        let request_id = raw
            .get("requestId")
            .and_then(Value::as_str)
            .unwrap_or("");
        self.handle_rpc_or_defer(request_id, payload, now_millis)
    }

    fn handle_line_at(&mut self, line: &[u8], now_millis: i64) -> Value {
        match self.handle_line_or_defer_at(line, now_millis) {
            BrokerLineOutcome::Immediate(value) => value,
            BrokerLineOutcome::Deferred(deferred) => deferred.finish_sync_at(self, now_millis),
        }
    }

    fn handle_line_or_defer_at(&mut self, line: &[u8], now_millis: i64) -> BrokerLineOutcome {
        if self.revoked {
            return BrokerLineOutcome::Immediate(host_status("unpaired", None));
        }
        if line.is_empty() || line.len() > MAX_LINE_BYTES {
            return BrokerLineOutcome::Immediate(host_status("invalid-message", None));
        }
        let envelope: Envelope = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) => return BrokerLineOutcome::Immediate(host_status("invalid-message", None)),
        };
        if !self.authenticate(&envelope) {
            return BrokerLineOutcome::Immediate(host_status("unpaired", None));
        }
        let payload = match decode_base64url(&envelope.payload) {
            Some(value) if value.len() <= MAX_RPC_BYTES => value,
            _ => {
                return BrokerLineOutcome::Immediate(host_status(
                    "invalid-message",
                    Some(&envelope.request_id),
                ));
            }
        };
        self.handle_rpc_or_defer(&envelope.request_id, &payload, now_millis)
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

    fn handle_rpc_or_defer(
        &mut self,
        envelope_request_id: &str,
        payload: &[u8],
        now_millis: i64,
    ) -> BrokerLineOutcome {
        let raw: Value = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => {
                return BrokerLineOutcome::Immediate(rpc_failure(
                    envelope_request_id,
                    "invalid-request",
                    "插件请求格式无效。",
                ));
            }
        };
        if raw
            .get("version")
            .and_then(Value::as_u64)
            .is_some_and(|version| version != RPC_VERSION as u64)
        {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "update-required",
                "VaultMesh 插件或桌面端版本不兼容，请更新后重试。",
            ));
        }
        let request: RpcRequest = match serde_json::from_value(raw) {
            Ok(value) => value,
            Err(_) => {
                return BrokerLineOutcome::Immediate(rpc_failure(
                    envelope_request_id,
                    "invalid-request",
                    "插件请求格式无效。",
                ));
            }
        };
        let Some(request_id) = Uuid::parse_str(&request.request_id).ok() else {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "插件请求格式无效。",
            ));
        };
        if request.kind != "vaultmesh.rpc"
            || request.version != RPC_VERSION
            || request.request_id != envelope_request_id
            || request.operation.is_empty()
            || request.operation.len() > 128
        {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "插件请求格式无效。",
            ));
        }

        let Some(issued_at) = parse_rpc_time(&request.issued_at) else {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "插件请求格式无效。",
            ));
        };
        let Some(expires_at) = parse_rpc_time(&request.expires_at) else {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "插件请求格式无效。",
            ));
        };
        if expires_at <= now_millis
            || issued_at > now_millis.saturating_add(MAX_CLOCK_SKEW_MILLIS)
            || expires_at.saturating_sub(issued_at) > MAX_LIFETIME_MILLIS
        {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "request-expired",
                "插件请求已过期，请重试。",
            ));
        }
        self.seen_request_ids
            .retain(|_, expiry| *expiry > now_millis);
        if self.seen_request_ids.contains_key(&request_id) {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "request-replayed",
                "插件请求不能重复使用。",
            ));
        }
        self.seen_request_ids.insert(request_id, expires_at);

        if !TAURI_BROWSER_SLICE_OPERATIONS.contains(&request.operation.as_str()) {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "unsupported-operation",
                "该插件操作不被允许。",
            ));
        }
        self.cancelled_passkey_requests.retain(|_, expires| *expires > now_millis);
        if request.operation == "passkeys.cancel" {
            let Ok(Some(target)) = parse_optional_uuid(&request.input, "requestId") else {
                return BrokerLineOutcome::Immediate(rpc_failure(
                    envelope_request_id, "invalid-request", "通行密钥请求编号无效。",
                ));
            };
            // Keep cancellations that race ahead of the original request until
            // even the latest valid envelope for that request would expire.
            self.cancelled_passkey_requests.insert(
                target,
                now_millis.saturating_add(MAX_LIFETIME_MILLIS + MAX_CLOCK_SKEW_MILLIS),
            );
            self.platform.cancel_passkey_unlock(target);
            return BrokerLineOutcome::Immediate(rpc_success(envelope_request_id, json!({})));
        }
        let validity = DeferredBrowserRequest {
            id: request_id,
            generation: self.access_generation,
            expires_at_millis: expires_at,
            passkey: matches!(request.operation.as_str(), "passkeys.create" | "passkeys.get"),
        };
        if validity.passkey
            && let Some(failure) = self.validate_deferred(envelope_request_id, validity, now_millis)
        {
            return BrokerLineOutcome::Immediate(failure);
        }
        if self.runtime.is_unlocked()
            && let Err(error) = self.runtime.refresh_from_disk()
        {
            return BrokerLineOutcome::Immediate(runtime_failure(envelope_request_id, error));
        }
        if self.runtime.sync_relay().merged_generation() != self.sync_merge_generation {
            self.sync_merge_generation = self.runtime.sync_relay().merged_generation();
            self.fill.clear();
            self.confirmations.clear();
            if self.runtime.is_unlocked() {
                let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
            }
            self.record_event("vault-changed", now_millis);
        }
        if matches!(request.operation.as_str(), "vault.unlock" | "pin.unlock" | "vault.lock") {
            self.platform.cancel_authentication();
        }
        let locked_selection_execute = request.operation == "browser.autofill.execute"
            && request.input.get("mode").and_then(Value::as_str) == Some("selection");
        if requires_unlock(&request.operation)
            && !locked_selection_execute
            && !self.runtime.is_unlocked()
        {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            ));
        }
        if (requires_gesture(&request.operation)
            || (request.operation == "browser.autofill.execute" && (request.input.contains_key("nativeItemPlan") || request.input.contains_key("nativeLoginPlan") && request.input.get("mode").and_then(Value::as_str) != Some("automatic"))))
            && !valid_gesture(&request.input) {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "该操作需要新的用户手势。",
            ));
        }
        self.confirmations
            .retain(|_, confirmation| confirmation.expires_at > now_millis);
        if requires_confirmation(&request.operation)
            && !self.consume_confirmation(&request.operation, &request.input, now_millis)
        {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "confirmation-required",
                "请先确认该操作。",
            ));
        }

        if request.operation == "browser.unlock.request" {
            if self.runtime.is_unlocked() {
                return BrokerLineOutcome::Immediate(rpc_success(
                    envelope_request_id,
                    json!({ "unlocked": true, "status": self.runtime.status() }),
                ));
            }
            if let Some(waiter) =
                self.platform
                    .begin_browser_session_unlock(BrowserSessionUnlockRequest {
                        vault_path: self.runtime.current_path(),
                        passkey_request: None,
                        source: BrowserUnlockSource::Popup,
                        origin: None,
                        item_title: None,
                        item_kind: None,
                        master_password_reprompt: false,
                    })
            {
                return BrokerLineOutcome::Deferred(DeferredBrokerExecution {
                    envelope_request_id: envelope_request_id.to_owned(),
                    validity,
                    work: DeferredBrokerWork::BrowserSessionUnlock { waiter },
                });
            }
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            ));
        }

        if request.operation == "browser.autofill.execute" {
            match self.fill.prepare_one_shot_selection(
                &mut self.runtime,
                &self.preauth_preview,
                &request.input,
                now_millis,
            ) {
                Ok(Some(prepared)) => {
                    if prepared.requires_session_unlock && !prepared.master_password_reprompt {
                        if let Some(waiter) =
                            self.platform
                                .begin_browser_session_unlock(BrowserSessionUnlockRequest {
                                    vault_path: self.runtime.current_path(),
                                    passkey_request: None,
                                    source: BrowserUnlockSource::Autofill,
                                    origin: Some(prepared.origin),
                                    item_title: Some(prepared.item_title),
                                    item_kind: Some(prepared.item_kind),
                                    master_password_reprompt: false,
                                })
                        {
                            return BrokerLineOutcome::Deferred(DeferredBrokerExecution {
                                envelope_request_id: envelope_request_id.to_owned(),
                                validity,
                                work: DeferredBrokerWork::AutofillSessionUnlock {
                                    input: request.input,
                                    waiter,
                                },
                            });
                        }
                        return BrokerLineOutcome::Immediate(rpc_failure(
                            envelope_request_id,
                            "unlock-required",
                            "请先在 VaultMesh 插件中单独解锁。",
                        ));
                    }
                    if let Some(waiter) =
                        self.platform
                            .begin_master_password_reprompt(BrowserRepromptRequest {
                                vault_path: self.runtime.current_path(),
                                origin: prepared.origin,
                                item_title: prepared.item_title,
                                item_kind: prepared.item_kind,
                            })
                    {
                        return BrokerLineOutcome::Deferred(DeferredBrokerExecution {
                            envelope_request_id: envelope_request_id.to_owned(),
                            validity,
                            work: DeferredBrokerWork::AutofillReprompt {
                                input: request.input,
                                waiter,
                            },
                        });
                    }
                    if !self.runtime.is_unlocked() {
                        return BrokerLineOutcome::Immediate(rpc_failure(
                            envelope_request_id,
                            "unlock-required",
                            "请先在 VaultMesh 插件中单独解锁。",
                        ));
                    }
                }
                Ok(None) => {
                    if !self.runtime.is_unlocked() {
                        return BrokerLineOutcome::Immediate(rpc_failure(
                            envelope_request_id,
                            "unlock-required",
                            "请先在 VaultMesh 插件中单独解锁。",
                        ));
                    }
                }
                Err(error) => {
                    return BrokerLineOutcome::Immediate(rpc_failure(
                        envelope_request_id,
                        error.code,
                        &error.message,
                    ));
                }
            }
        }

        if validity.passkey {
            if request.input.get("cancellable").and_then(Value::as_bool) != Some(true) {
                return BrokerLineOutcome::Immediate(rpc_failure(
                    envelope_request_id,
                    "passkey-unavailable",
                    "请更新浏览器插件以支持可取消的 VaultMesh 通行密钥请求。",
                ));
            }
            return self.prepare_passkey_broker_outcome(
                envelope_request_id,
                &request.operation,
                &request.input,
                validity,
            );
        }

        BrokerLineOutcome::Immediate(self.dispatch_authenticated_rpc(
            envelope_request_id,
            request,
            now_millis,
        ))
    }

    fn dispatch_authenticated_rpc(
        &mut self,
        envelope_request_id: &str,
        request: RpcRequest,
        now_millis: i64,
    ) -> Value {

        match request.operation.as_str() {
            "vault.status" => {
                let mut status = json!(self.runtime.status());
                status["passkeyCancellation"] = json!(true);
                rpc_success(envelope_request_id, status)
            }
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
                        self.invalidate_deferred();
                        if let Err(error) = self.platform.after_master_unlock(&mut self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
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
                        if let Err(error) = self.platform.after_master_unlock(&mut self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
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
            "vault.lock" => rpc_success(envelope_request_id, self.lock_browser_session(now_millis)),
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
                match self.fill.candidates_with_preview(
                    &mut self.runtime,
                    Some(&self.preauth_preview),
                    &request.input,
                ) {
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
            "passkeys.probe" => {
                let Some(request_json) = request
                    .input
                    .get("requestDetailsJson")
                    .and_then(Value::as_str)
                else {
                    return rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        "Passkey 请求格式无效。",
                    );
                };
                let view = match PasskeyService::get_request_view(request_json) {
                    Ok(view) => view,
                    Err(message) => {
                        return rpc_failure(
                            envelope_request_id,
                            "invalid-request",
                            &message,
                        );
                    }
                };
                if self.runtime.is_unlocked() {
                    let candidates = match self.runtime.matching_passkeys(request_json) {
                        Ok(candidates) => candidates,
                        Err(error) => {
                            return passkey_runtime_failure(
                                envelope_request_id,
                                error,
                                &view.rp_id,
                            );
                        }
                    };
                    let has_login_candidates = self
                        .runtime
                        .execute("browser.autofill.candidates", json!({ "url": view.origin }))
                        .ok()
                        .and_then(|value| value.as_array().map(|items| !items.is_empty()))
                        .unwrap_or(false);
                    let candidate_payloads: Vec<Value> = candidates
                        .iter()
                        .map(|candidate| {
                            json!({
                                "itemId": candidate.item_id.to_string(),
                                "credentialId": candidate.credential_id,
                                "title": candidate.title,
                                "account": candidate.account,
                            })
                        })
                        .collect();
                    let result = if let Some(first) = candidates.first() {
                        json!({
                            "status": "available",
                            "rpId": view.rp_id,
                            "origin": view.origin,
                            "account": first.account,
                            "candidates": candidate_payloads,
                            "hasLoginCandidates": has_login_candidates,
                        })
                    } else {
                        json!({
                            "status": "unavailable",
                            "rpId": view.rp_id,
                            "origin": view.origin,
                            "candidates": [],
                            "hasLoginCandidates": has_login_candidates,
                        })
                    };
                    return rpc_success(envelope_request_id, result);
                }

                let vault_path = self.runtime.current_path();
                let has_login_candidates = self
                    .preauth_preview
                    .has_login_for_origin(vault_path.as_path(), &view.origin);
                let result = match self.preauth_preview.passkey_matches(
                    vault_path.as_path(),
                    &view.rp_id,
                    &view.allow_credentials,
                ) {
                    Some(matches) if !matches.is_empty() => {
                        let first_account = matches[0].account.clone();
                        let candidate_payloads: Vec<Value> = matches
                            .into_iter()
                            .map(|record| {
                                json!({
                                    "itemId": record.item_id,
                                    "credentialId": record.credential_id,
                                    "title": record.title,
                                    "account": record.account,
                                })
                            })
                            .collect();
                        json!({
                            "status": "available",
                            "rpId": view.rp_id,
                            "origin": view.origin,
                            "account": first_account,
                            "candidates": candidate_payloads,
                            "hasLoginCandidates": has_login_candidates,
                        })
                    }
                    Some(_) => json!({
                        "status": "unavailable",
                        "rpId": view.rp_id,
                        "origin": view.origin,
                        "candidates": [],
                        "hasLoginCandidates": has_login_candidates,
                    }),
                    None => json!({
                        "status": "unknown",
                        "rpId": view.rp_id,
                        "origin": view.origin,
                        "candidates": [],
                        "hasLoginCandidates": false,
                    }),
                };
                rpc_success(envelope_request_id, result)
            }
            operation if is_runtime_operation(operation) => {
                match self
                    .runtime
                    .execute(operation, Value::Object(request.input))
                {
                    Ok(result) => {
                        if is_runtime_mutation(operation) {
                            let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                            self.record_event("vault-changed", now_millis);
                            if operation == "vault.change-password" {
                                self.refresh_unlock_history();
                            }
                            if let Err(error) = self.platform.after_runtime_mutation(operation) {
                                if operation == "vault.change-password" {
                                    self.lock_browser_session(now_millis);
                                }
                                return rpc_failure(
                                    envelope_request_id,
                                    error.code,
                                    &error.message,
                                );
                            }
                            if operation == "vault.change-password" {
                                self.lock_browser_session(now_millis);
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
                    let is_master_unlock = operation == "vault.restore";
                    let is_quick_unlock = matches!(operation, "pin.unlock" | "biometric.unlock")
                        || (operation == "biometric.authentication.poll"
                            && result.get("phase").and_then(Value::as_str) == Some("unlocked"));
                    if is_master_unlock {
                        self.invalidate_deferred();
                        if let Err(error) = self.platform.after_master_unlock(&mut self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                        self.refresh_unlock_history();
                    } else if is_quick_unlock {
                        if let Err(error) = self.platform.after_quick_unlock(&mut self.runtime) {
                            self.runtime.lock();
                            return rpc_failure(envelope_request_id, error.code, &error.message);
                        }
                        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                        self.refresh_unlock_history();
                    }
                    if matches!(
                        operation,
                        "vault.restore" | "imports.commit" | "ssh.scan.commit"
                    ) {
                        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                        self.record_event("vault-changed", now_millis);
                    }
                    if matches!(operation, "pin.enable" | "pin.disable") {
                        self.lock_browser_session(now_millis);
                    }
                    if operation == "browser.pairing.revoke" {
                        self.record_event("pairing-revoked", now_millis);
                        self.revoked = true;
                        self.runtime.lock();
                        self.platform.clear();
                        self.preauth_preview.clear();
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

    fn prepare_passkey_broker_outcome(
        &mut self,
        envelope_request_id: &str,
        operation: &str,
        input: &Map<String, Value>,
        validity: DeferredBrowserRequest,
    ) -> BrokerLineOutcome {
        let expires_at_millis = validity.expires_at_millis;
        let Some(request_json) = input
            .get("requestDetailsJson")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "invalid-request",
                "Passkey 请求格式无效。",
            ));
        };
        let kind = if operation == "passkeys.create" {
            PasskeyOpKind::Create
        } else {
            PasskeyOpKind::Get
        };
        let login_id = (kind == PasskeyOpKind::Create)
            .then(|| {
                input
                    .get("loginId")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
            })
            .flatten();
        let requested_item_id = if kind == PasskeyOpKind::Get {
            match parse_optional_uuid(input, "itemId") {
                Ok(id) => id,
                Err(message) => {
                    return BrokerLineOutcome::Immediate(rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        message,
                    ));
                }
            }
        } else {
            None
        };
        let requested_credential_id = if kind == PasskeyOpKind::Get {
            match parse_optional_credential_id(input, "credentialId") {
                Ok(id) => id,
                Err(message) => {
                    return BrokerLineOutcome::Immediate(rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        message,
                    ));
                }
            }
        } else {
            None
        };

        let (rp_id, origin, top_origin, mut account, unlock_title, allow_credentials) = match kind {
            PasskeyOpKind::Create => match describe_passkey_request("create", request_json) {
                Ok(summary) => {
                    let title = summary
                        .account
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .map(|account| format!("创建 Passkey · {account}"))
                        .unwrap_or_else(|| format!("创建 Passkey · {}", summary.rp_id));
                    (
                        summary.rp_id,
                        summary.origin,
                        summary.top_origin,
                        summary.account,
                        title,
                        Vec::new(),
                    )
                }
                Err(error) => {
                    return BrokerLineOutcome::Immediate(rpc_failure(
                        envelope_request_id,
                        passkey_error_code(error),
                        error.public_message(),
                    ));
                }
            },
            PasskeyOpKind::Get => match PasskeyService::get_request_view(request_json) {
                Ok(view) => {
                    let title = format!("Passkey · {}", view.rp_id);
                    (
                        view.rp_id,
                        view.origin,
                        view.top_origin,
                        None,
                        title,
                        view.allow_credentials,
                    )
                }
                Err(message) => {
                    return BrokerLineOutcome::Immediate(rpc_failure(
                        envelope_request_id,
                        "invalid-request",
                        &message,
                    ));
                }
            },
        };

        if self.runtime.is_unlocked() {
            let (selected_item_id, selected_credential_id) = if kind == PasskeyOpKind::Get {
                let candidates = match self.runtime.matching_passkeys(request_json) {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        return BrokerLineOutcome::Immediate(passkey_runtime_failure(
                            envelope_request_id,
                            error,
                            &rp_id,
                        ));
                    }
                };
                let selected = match resolve_passkey_candidate(
                    envelope_request_id,
                    select_passkey_candidate(candidates, |candidate| {
                        requested_item_id.is_none_or(|id| candidate.item_id == id)
                            && requested_credential_id
                                .as_deref()
                                .is_none_or(|cid| candidate.credential_id == cid)
                    }),
                ) {
                    Ok(selected) => selected,
                    Err(response) => return BrokerLineOutcome::Immediate(response),
                };
                account = selected.account;
                (Some(selected.item_id), Some(selected.credential_id))
            } else {
                (None, None)
            };

            return BrokerLineOutcome::Deferred(DeferredBrokerExecution {
                envelope_request_id: envelope_request_id.to_owned(),
                validity,
                work: DeferredBrokerWork::Passkey(DeferredPasskeyWork {
                    kind,
                    request_json: request_json.to_owned(),
                    rp_id,
                    origin,
                    top_origin,
                    account,
                    login_id,
                    requested_item_id,
                    requested_credential_id,
                    selected_item_id,
                    selected_credential_id,
                    expires_at_millis,
                    unlock_waiter: None,
                    platform: Arc::clone(&self.platform),
                }),
            });
        }

        let vault_path = self.runtime.current_path();
        let mut effective_title = unlock_title;
        if kind == PasskeyOpKind::Get {
            if let Some(matches) = self.preauth_preview.passkey_matches(
                vault_path.as_path(),
                &rp_id,
                &allow_credentials,
            ) {
                let selected = match resolve_passkey_candidate(
                    envelope_request_id,
                    select_passkey_candidate(matches, |record| {
                        requested_item_id.is_none_or(|id| record.item_id == id.to_string())
                            && requested_credential_id
                                .as_deref()
                                .is_none_or(|cid| record.credential_id == cid)
                    }),
                ) {
                    Ok(selected) => selected,
                    Err(response) => return BrokerLineOutcome::Immediate(response),
                };
                account = selected.account;
                effective_title = selected.title;
            }
        }

        let Some(waiter) = self.platform.begin_browser_session_unlock(
            BrowserSessionUnlockRequest {
                vault_path,
                passkey_request: Some((validity.id, validity.expires_at_millis)),
                source: BrowserUnlockSource::Passkey,
                origin: Some(origin.clone()),
                item_title: Some(effective_title),
                item_kind: Some("secret".to_owned()),
                master_password_reprompt: false,
            },
        ) else {
            return BrokerLineOutcome::Immediate(rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            ));
        };

        BrokerLineOutcome::Deferred(DeferredBrokerExecution {
            envelope_request_id: envelope_request_id.to_owned(),
            validity,
            work: DeferredBrokerWork::Passkey(DeferredPasskeyWork {
                kind,
                request_json: request_json.to_owned(),
                rp_id,
                origin,
                top_origin,
                account,
                login_id,
                requested_item_id,
                requested_credential_id,
                selected_item_id: None,
                selected_credential_id: None,
                expires_at_millis,
                unlock_waiter: Some(waiter),
                platform: Arc::clone(&self.platform),
            }),
        })
    }

    fn commit_browser_session_unlock_or_rpc(
        &mut self,
        envelope_request_id: &str,
        resolution: &BrowserUnlockResolution,
        now_millis: i64,
    ) -> Result<(), Value> {
        if self.revoked {
            return Err(host_status("unpaired", None));
        }
        let runtime_canonical = self.runtime.current_path().canonicalize().ok();
        let resolved_canonical = resolution.vault_path.canonicalize().ok();
        if runtime_canonical.is_some()
            && resolved_canonical.is_some()
            && runtime_canonical != resolved_canonical
        {
            return Err(rpc_failure(
                envelope_request_id,
                "unlock-required",
                "保险库路径已变更，请重新解锁。",
            ));
        }

        if self.runtime.is_unlocked() {
            if let Err(error) = self.runtime.refresh_from_disk() {
                return Err(runtime_failure(envelope_request_id, error));
            }
            if self.runtime.is_unlocked() {
                if self.runtime.sync_relay().merged_generation() != self.sync_merge_generation {
                    self.sync_merge_generation = self.runtime.sync_relay().merged_generation();
                    self.fill.clear();
                    self.confirmations.clear();
                }
                let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                self.refresh_unlock_history();
                return Ok(());
            }
        }

        let unlock_result = match resolution.factor {
            BrowserUnlockFactor::MasterPassword => self
                .runtime
                .unlock_for_browser_with_verified_key(
                    resolution.vault_path.clone(),
                    resolution.vault_key.as_slice(),
                ),
            BrowserUnlockFactor::Pin => self.runtime.unlock_for_browser_with_quick_key(
                resolution.vault_path.clone(),
                resolution.vault_key.as_slice(),
            ),
            BrowserUnlockFactor::Biometric => self
                .runtime
                .unlock_for_browser_with_biometric_key(
                    resolution.vault_path.clone(),
                    resolution.vault_key.as_slice(),
                ),
        };
        if let Err(error) = unlock_result {
            return Err(runtime_failure(envelope_request_id, error));
        }
        if !self.runtime.is_unlocked() {
            return Err(rpc_failure(envelope_request_id, "unlock-required", "保险库已锁定。"));
        }
        let hook_result = match resolution.factor {
            BrowserUnlockFactor::MasterPassword => self.platform.after_master_unlock(&mut self.runtime),
            BrowserUnlockFactor::Pin | BrowserUnlockFactor::Biometric => {
                self.platform.after_quick_unlock(&mut self.runtime)
            }
        };
        if let Err(error) = hook_result {
            self.runtime.lock();
            return Err(rpc_failure(envelope_request_id, error.code, &error.message));
        }
        self.sync_merge_generation = self.runtime.sync_relay().merged_generation();
        self.fill.clear();
        let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
        self.refresh_unlock_history();
        self.record_event("vault-changed", now_millis);
        Ok(())
    }

    fn commit_browser_passkey_unlock(
        &mut self,
        envelope_request_id: &str,
        work: &mut DeferredPasskeyWork,
        resolution: Result<BrowserUnlockResolution, BrowserPlatformError>,
        now_millis: i64,
    ) -> Result<(), Value> {
        if self.revoked {
            return Err(host_status("unpaired", None));
        }
        let resolution = match resolution {
            Ok(resolution) => resolution,
            Err(error) => return Err(rpc_failure(envelope_request_id, error.code, &error.message)),
        };
        if now_millis >= work.expires_at_millis {
            return Err(rpc_failure(
                envelope_request_id,
                "request-expired",
                "插件请求已过期，请重试。",
            ));
        }
        self.commit_browser_session_unlock_or_rpc(envelope_request_id, &resolution, now_millis)?;
        if work.kind == PasskeyOpKind::Get {
            let candidates = self
                .runtime
                .matching_passkeys(&work.request_json)
                .map_err(|error| passkey_runtime_failure(envelope_request_id, error, &work.rp_id))?;
            let selected = resolve_passkey_candidate(
                envelope_request_id,
                select_passkey_candidate(candidates, |candidate| {
                    work.requested_item_id.is_none_or(|id| candidate.item_id == id)
                        && work
                            .requested_credential_id
                            .as_deref()
                            .is_none_or(|cid| candidate.credential_id == cid)
                }),
            )?;
            work.account = selected.account;
            work.selected_item_id = Some(selected.item_id);
            work.selected_credential_id = Some(selected.credential_id);
        }
        Ok(())
    }

    fn finish_passkey(
        &mut self,
        envelope_request_id: &str,
        prepared: PreparedPasskeyExecution,
        now_millis: i64,
    ) -> Value {
        if self.revoked {
            return host_status("unpaired", None);
        }
        if now_millis >= prepared.expires_at_millis {
            return rpc_failure(
                envelope_request_id,
                "request-expired",
                "插件请求已过期，请重试。",
            );
        }
        let now_iso = DateTime::<Utc>::from_timestamp_millis(now_millis)
            .unwrap_or(DateTime::UNIX_EPOCH)
            .to_rfc3339_opts(SecondsFormat::Millis, true);

        if !self.runtime.is_unlocked() {
            return rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            );
        }
        if let Err(error) = self.runtime.refresh_from_disk() {
            return passkey_runtime_failure(envelope_request_id, error, &prepared.rp_id);
        }
        if !self.runtime.is_unlocked() {
            return rpc_failure(
                envelope_request_id,
                "unlock-required",
                "请先在 VaultMesh 插件中单独解锁。",
            );
        }
        if self.runtime.sync_relay().merged_generation() != self.sync_merge_generation {
            self.sync_merge_generation = self.runtime.sync_relay().merged_generation();
            self.fill.clear();
            self.confirmations.clear();
            let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
        }

        let result = match prepared.kind {
            PasskeyOpKind::Create => self.runtime.create_passkey(
                &prepared.request_json,
                prepared.login_id,
                &now_iso,
            ),
            PasskeyOpKind::Get => self.runtime.sign_passkey_assertion(
                &prepared.request_json,
                prepared.selected_item_id,
                prepared.selected_credential_id.as_deref(),
                &now_iso,
            ),
        };
        match result {
            Ok(response_json) => {
                let _ = self.preauth_preview.sync_from_runtime(&mut self.runtime);
                self.record_event("vault-changed", now_millis);
                rpc_success(envelope_request_id, json!({ "responseJson": response_json }))
            }
            Err(error) => passkey_runtime_failure(envelope_request_id, error, &prepared.rp_id),
        }
    }

    fn finish_browser_session_unlock(
        &mut self,
        envelope_request_id: &str,
        resolution: Result<BrowserUnlockResolution, BrowserPlatformError>,
        now_millis: i64,
    ) -> Value {
        if self.revoked {
            return host_status("unpaired", None);
        }
        let resolution = match resolution {
            Ok(resolution) => resolution,
            Err(error) => return rpc_failure(envelope_request_id, error.code, &error.message),
        };
        if let Err(response) =
            self.commit_browser_session_unlock_or_rpc(envelope_request_id, &resolution, now_millis)
        {
            return response;
        }
        rpc_success(
            envelope_request_id,
            json!({ "unlocked": true, "status": self.runtime.status() }),
        )
    }

    fn execute_autofill_with_optional_password(
        fill: &mut BrowserFillService,
        runtime: &mut DesktopRuntime,
        envelope_request_id: &str,
        input: &Map<String, Value>,
        password: Option<Zeroizing<String>>,
        now_millis: i64,
    ) -> Value {
        let mut effective_input = input.clone();
        if !effective_input.contains_key("masterPassword")
            && let Some(password) = password
        {
            effective_input.insert(
                "masterPassword".to_owned(),
                Value::String(password.as_str().to_owned()),
            );
        }
        let result = fill.execute(runtime, &effective_input, now_millis);
        if let Some(Value::String(mut removed)) = effective_input.remove("masterPassword") {
            removed.zeroize();
        }
        match result {
            Ok(approved) => rpc_success(envelope_request_id, approved),
            Err(error) => rpc_failure(envelope_request_id, error.code, &error.message),
        }
    }

    fn finish_autofill_session_unlock(
        &mut self,
        envelope_request_id: &str,
        input: &Map<String, Value>,
        resolution: Result<BrowserUnlockResolution, BrowserPlatformError>,
        now_millis: i64,
    ) -> Value {
        if self.revoked {
            return host_status("unpaired", None);
        }
        let mut resolution = match resolution {
            Ok(resolution) => resolution,
            Err(error) => return rpc_failure(envelope_request_id, error.code, &error.message),
        };
        if let Err(response) =
            self.commit_browser_session_unlock_or_rpc(envelope_request_id, &resolution, now_millis)
        {
            return response;
        }
        Self::execute_autofill_with_optional_password(
            &mut self.fill,
            &mut self.runtime,
            envelope_request_id,
            input,
            resolution.master_password.take(),
            now_millis,
        )
    }

    fn finish_autofill_reprompt(
        &mut self,
        envelope_request_id: &str,
        input: &Map<String, Value>,
        resolution: Result<BrowserRepromptResolution, BrowserPlatformError>,
        now_millis: i64,
    ) -> Value {
        if self.revoked {
            return host_status("unpaired", None);
        }
        let resolution = match resolution {
            Ok(resolution) => resolution,
            Err(error) => return rpc_failure(envelope_request_id, error.code, &error.message),
        };
        if self.runtime.is_unlocked() {
            return Self::execute_autofill_with_optional_password(
                &mut self.fill,
                &mut self.runtime,
                envelope_request_id,
                input,
                Some(resolution.master_password),
                now_millis,
            );
        }
        let mut temporary = match DesktopRuntime::new(resolution.vault_path.clone()) {
            Ok(runtime) => runtime,
            Err(error) => return runtime_failure(envelope_request_id, error),
        };
        let open_result = match resolution.vault_key.as_deref() {
            Some(key) => temporary.open_ephemeral_with_key(resolution.vault_path.clone(), key),
            None => temporary.open_ephemeral_with_password(
                resolution.vault_path.clone(),
                resolution.master_password.as_str().to_owned(),
            ),
        };
        if let Err(error) = open_result {
            return runtime_failure(envelope_request_id, error);
        }
        if self
            .preauth_preview
            .load_verified_snapshot(&resolution.vault_path)
            .is_none()
        {
            let _ = self.preauth_preview.sync_from_runtime(&mut temporary);
        }
        let response = Self::execute_autofill_with_optional_password(
            &mut self.fill,
            &mut temporary,
            envelope_request_id,
            input,
            Some(resolution.master_password),
            now_millis,
        );
        temporary.lock();
        response
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

enum PasskeyCandidateMatch<T> {
    Single(T),
    None,
    Multiple,
}

fn select_passkey_candidate<T>(
    candidates: Vec<T>,
    matches: impl Fn(&T) -> bool,
) -> PasskeyCandidateMatch<T> {
    let mut matching = candidates.into_iter().filter(matches);
    match (matching.next(), matching.next()) {
        (None, _) => PasskeyCandidateMatch::None,
        (Some(selected), None) => PasskeyCandidateMatch::Single(selected),
        (Some(_), Some(_)) => PasskeyCandidateMatch::Multiple,
    }
}

fn resolve_passkey_candidate<T>(
    envelope_request_id: &str,
    matched: PasskeyCandidateMatch<T>,
) -> Result<T, Value> {
    match matched {
        PasskeyCandidateMatch::Single(selected) => Ok(selected),
        PasskeyCandidateMatch::None => Err(rpc_failure(
            envelope_request_id,
            "passkey-unavailable",
            "VaultMesh 没有该网站可用的 Passkey。",
        )),
        PasskeyCandidateMatch::Multiple => Err(rpc_failure(
            envelope_request_id,
            "passkey-selection-required",
            "找到多个可用 Passkey，请先选择要使用的凭证。",
        )),
    }
}

fn confirm_passkey_outside_lock(
    envelope_request_id: &str,
    work: DeferredPasskeyWork,
    now_millis_fn: impl FnOnce() -> i64,
) -> Result<PreparedPasskeyExecution, Value> {
    if now_millis_fn() >= work.expires_at_millis {
        return Err(rpc_failure(
            envelope_request_id,
            "request-expired",
            "插件请求已过期，请重试。",
        ));
    }

    match work.platform.confirm_passkey(&PasskeyConfirmationRequest {
        kind: work.kind,
        rp_id: work.rp_id.clone(),
        origin: work.origin,
        top_origin: work.top_origin,
        account: work.account,
    }) {
        Ok(true) => Ok(PreparedPasskeyExecution {
            kind: work.kind,
            request_json: work.request_json,
            rp_id: work.rp_id,
            login_id: work.login_id,
            selected_item_id: work.selected_item_id,
            selected_credential_id: work.selected_credential_id,
            expires_at_millis: work.expires_at_millis,
        }),
        Ok(false) => Err(rpc_failure(
            envelope_request_id,
            "cancelled",
            "用户已拒绝通行密钥确认。",
        )),
        Err(error) => Err(rpc_failure(envelope_request_id, error.code, &error.message)),
    }
}

fn parse_optional_uuid(input: &Map<String, Value>, key: &str) -> Result<Option<Uuid>, &'static str> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => Uuid::parse_str(raw)
            .map(Some)
            .map_err(|_| "Passkey 条目编号无效。"),
        Some(_) => Err("Passkey 条目编号无效。"),
    }
}

fn parse_optional_credential_id(
    input: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, &'static str> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if !raw.is_empty() && raw.len() <= 4096 => Ok(Some(raw.clone())),
        Some(_) => Err("Passkey 凭据编号无效。"),
    }
}

fn passkey_error_code(error: PasskeyError) -> &'static str {
    match error {
        PasskeyError::Locked => "unlock-required",
        PasskeyError::NotFound => "passkey-unavailable",
        PasskeyError::RequestTooLarge
        | PasskeyError::InvalidRequest
        | PasskeyError::UnsupportedAlgorithm
        | PasskeyError::CrossPlatformNotSupported
        | PasskeyError::LargeBlobNotSupported
        | PasskeyError::InvalidOrigin
        | PasskeyError::OriginMismatch => "invalid-request",
        _ => "operation-failed",
    }
}

fn passkey_runtime_failure(request_id: &str, error: DesktopRuntimeError, rp_id: &str) -> Value {
    match error.status() {
        VAULTMESH_STATUS_LOCKED => rpc_failure(
            request_id,
            "unlock-required",
            "请先在 VaultMesh 插件中单独解锁。",
        ),
        VAULTMESH_STATUS_NOT_FOUND => rpc_failure(
            request_id,
            "passkey-unavailable",
            "VaultMesh 没有该网站可用的 Passkey。",
        ),
        _ => rpc_failure(
            request_id,
            "operation-failed",
            &format!("{} ({rp_id})", error.public_message()),
        ),
    }
}
