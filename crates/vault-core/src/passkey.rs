use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    NewSecretItem, SecretItem, SecretItemKind, SecretItemUpdate, VaultError, VaultSession,
};

pub const PASSKEY_SCOPE: &str = "vaultmesh:passkey:v1";
pub const PASSKEY_PROVIDER: &str = "VaultMesh Passkey";
const ES256: i64 = -7;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_CHALLENGE_BYTES: usize = 16 * 1024;
const MAX_ORIGIN_LEN: usize = 2048;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PasskeyError {
    #[error("请先解锁保险库。")]
    Locked,
    #[error("需要使用当前主密码再次验证。")]
    MasterPasswordRequired,
    #[error("Passkey 请求过大。")]
    RequestTooLarge,
    #[error("Passkey 请求格式无效。")]
    InvalidRequest,
    #[error("Passkey 请求的签名算法暂不支持。")]
    UnsupportedAlgorithm,
    #[error("该网站仅允许外接安全密钥。")]
    CrossPlatformNotSupported,
    #[error("该网站要求当前版本尚不支持的 largeBlob 扩展。")]
    LargeBlobNotSupported,
    #[error("Passkey 来源无效。")]
    InvalidOrigin,
    #[error("Passkey 来源与网站不匹配。")]
    OriginMismatch,
    #[error("该账户已存在 Passkey。")]
    CredentialAlreadyExists,
    #[error("没有找到该网站可用的 Passkey。")]
    NotFound,
    #[error("Passkey 数据无效。")]
    InvalidStoredPasskey,
    #[error("Passkey 私钥无效。")]
    InvalidPrivateKey,
    #[error("无法创建 Passkey。")]
    Crypto,
    #[error("无法保存 Passkey。")]
    Serialization,
    #[error("Passkey 操作失败。")]
    Core,
}

impl PasskeyError {
    pub const fn public_message(self) -> &'static str {
        match self {
            Self::Locked => "请先解锁保险库。",
            Self::MasterPasswordRequired => "需要使用当前主密码再次验证。",
            Self::RequestTooLarge => "Passkey 请求过大。",
            Self::InvalidRequest => "Passkey 请求格式无效。",
            Self::UnsupportedAlgorithm => "Passkey 请求的签名算法暂不支持。",
            Self::CrossPlatformNotSupported => "该网站仅允许外接安全密钥。",
            Self::LargeBlobNotSupported => "该网站要求当前版本尚不支持的 largeBlob 扩展。",
            Self::InvalidOrigin => "Passkey 来源无效。",
            Self::OriginMismatch => "Passkey 来源与网站不匹配。",
            Self::CredentialAlreadyExists => "该账户已存在 Passkey。",
            Self::NotFound => "没有找到该网站可用的 Passkey。",
            Self::InvalidStoredPasskey => "Passkey 数据无效。",
            Self::InvalidPrivateKey => "Passkey 私钥无效。",
            Self::Crypto => "无法创建 Passkey。",
            Self::Serialization => "无法保存 Passkey。",
            Self::Core => "Passkey 操作失败。",
        }
    }
}

impl From<VaultError> for PasskeyError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::Locked => Self::Locked,
            VaultError::MasterPasswordRequired => Self::MasterPasswordRequired,
            VaultError::ItemNotFound => Self::NotFound,
            VaultError::Crypto => Self::Crypto,
            VaultError::Serialization => Self::Serialization,
            VaultError::InvalidSecretItem => Self::InvalidStoredPasskey,
            _ => Self::Core,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRequestSummary {
    pub rp_id: String,
    pub origin: String,
    pub top_origin: Option<String>,
    pub cross_origin: bool,
    pub account: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyGetRequestView {
    pub rp_id: String,
    pub origin: String,
    pub top_origin: Option<String>,
    pub cross_origin: bool,
    pub allow_credentials: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCandidate {
    pub item_id: Uuid,
    pub credential_id: String,
    pub rp_id: String,
    pub origin: String,
    pub top_origin: Option<String>,
    pub cross_origin: bool,
    pub title: String,
    pub account: Option<String>,
    pub user_name: String,
    pub user_display_name: String,
    pub login_id: Option<Uuid>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Override {
    origin: String,
    same_origin_with_ancestors: bool,
    #[serde(default)]
    top_origin: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Extensions {
    remote_desktop_client_override: Override,
    #[serde(default)]
    cred_props: bool,
    appid: Option<String>,
    large_blob: Option<LargeBlob>,
}

#[derive(Deserialize)]
struct LargeBlob {
    #[serde(default)]
    support: Option<String>,
}

#[derive(Deserialize)]
struct Rp {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct Parameter {
    #[serde(rename = "type")]
    credential_type: String,
    alg: i64,
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "type")]
    credential_type: String,
    id: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    authenticator_attachment: Option<String>,
    resident_key: Option<String>,
    user_verification: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRequest {
    rp: Rp,
    user: User,
    challenge: String,
    pub_key_cred_params: Vec<Parameter>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
    authenticator_selection: Option<Selection>,
    extensions: Extensions,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRequest {
    challenge: String,
    rp_id: String,
    #[serde(default)]
    allow_credentials: Vec<Descriptor>,
    #[serde(default = "preferred")]
    user_verification: String,
    extensions: Extensions,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    d: String,
}

impl Zeroize for PrivateJwk {
    fn zeroize(&mut self) {
        self.kty.zeroize();
        self.crv.zeroize();
        self.x.zeroize();
        self.y.zeroize();
        self.d.zeroize();
    }
}

impl Drop for PrivateJwk {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl fmt::Debug for PrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateJwk")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("d", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPasskey {
    version: u8,
    credential_id: String,
    rp_id: String,
    user_handle: String,
    user_name: String,
    user_display_name: String,
    login_id: Option<Uuid>,
    private_key_jwk: PrivateJwk,
    sign_count: u32,
    #[serde(default)]
    backup_eligible: bool,
    #[serde(default)]
    backup_state: bool,
    created_at: String,
    last_used_at: Option<String>,
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredPasskey")
            .field("version", &self.version)
            .field("credential_id", &self.credential_id)
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("sign_count", &self.sign_count)
            .field("backup_eligible", &self.backup_eligible)
            .field("backup_state", &self.backup_state)
            .field("private_key_jwk", &self.private_key_jwk)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedOrigin {
    origin: String,
    top_origin: Option<String>,
    cross_origin: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: &'a str,
    origin: &'a str,
    cross_origin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_origin: Option<&'a str>,
}

pub fn describe_passkey_request(
    kind: &str,
    request_json: &str,
) -> Result<PasskeyRequestSummary, PasskeyError> {
    match kind {
        "create" => {
            let (request, origin_info) = parse_create_request(request_json)?;
            Ok(PasskeyRequestSummary {
                rp_id: request.rp.id,
                origin: origin_info.origin,
                top_origin: origin_info.top_origin,
                cross_origin: origin_info.cross_origin,
                account: Some(request.user.display_name.unwrap_or(request.user.name)),
            })
        }
        "get" => {
            let (request, origin_info) = parse_get_request(request_json)?;
            Ok(PasskeyRequestSummary {
                rp_id: request.rp_id,
                origin: origin_info.origin,
                top_origin: origin_info.top_origin,
                cross_origin: origin_info.cross_origin,
                account: None,
            })
        }
        _ => Err(PasskeyError::InvalidRequest),
    }
}

pub fn get_passkey_request_view(request_json: &str) -> Result<PasskeyGetRequestView, PasskeyError> {
    let (request, origin_info) = parse_get_request(request_json)?;
    Ok(PasskeyGetRequestView {
        rp_id: request.rp_id,
        origin: origin_info.origin,
        top_origin: origin_info.top_origin,
        cross_origin: origin_info.cross_origin,
        allow_credentials: request
            .allow_credentials
            .into_iter()
            .map(|credential| credential.id)
            .collect(),
    })
}

impl VaultSession {
    /// Returns all valid Passkey metadata candidates matching `rpId` and
    /// `allowCredentials`, ordered newest-created first. Private key material
    /// never leaves `VaultSession`.
    pub fn matching_passkeys(
        &self,
        request_json: &str,
    ) -> Result<Vec<PasskeyCandidate>, PasskeyError> {
        let payload = self.payload()?;
        let (request, origin_info) = parse_get_request(request_json)?;
        let mut candidates = Vec::new();
        for item in payload.secrets.iter().rev() {
            if !is_passkey_item_for_rp(item, &request.rp_id) {
                continue;
            }
            if !request.allow_credentials.is_empty()
                && !request.allow_credentials.iter().any(|descriptor| {
                    scope_value(&item.scopes, "credential:") == Some(descriptor.id.as_str())
                })
            {
                continue;
            }
            let Ok((stored, _)) = load_validated_passkey(item, &item.secret, &request.rp_id) else {
                continue;
            };
            let account = item
                .account
                .clone()
                .filter(|value| !value.is_empty())
                .or_else(|| (!stored.user_name.is_empty()).then(|| stored.user_name.clone()));
            let login_id = stored
                .login_id
                .or_else(|| scope_uuid(&item.scopes, "login:"));
            candidates.push(PasskeyCandidate {
                item_id: item.id,
                credential_id: stored.credential_id.clone(),
                rp_id: request.rp_id.clone(),
                origin: origin_info.origin.clone(),
                top_origin: origin_info.top_origin.clone(),
                cross_origin: origin_info.cross_origin,
                title: item.title.clone(),
                account,
                user_name: stored.user_name.clone(),
                user_display_name: stored.user_display_name.clone(),
                login_id,
                created_at: stored.created_at.clone(),
                last_used_at: stored.last_used_at.clone(),
            });
        }
        Ok(candidates)
    }

    pub fn create_passkey(
        &mut self,
        request_json: &str,
        default_login_id: Option<Uuid>,
        now: &str,
    ) -> Result<String, PasskeyError> {
        self.payload()?;
        let (request, origin_info) = parse_create_request(request_json)?;
        {
            let payload = self.payload()?;
            if payload.secrets.iter().any(|item| {
                is_passkey_item_for_rp(item, &request.rp.id)
                    && request.exclude_credentials.iter().any(|descriptor| {
                        scope_value(&item.scopes, "credential:") == Some(descriptor.id.as_str())
                    })
            }) {
                return Err(PasskeyError::CredentialAlreadyExists);
            }
        }
        let signing = SigningKey::random(&mut OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let x = point.x().ok_or(PasskeyError::Crypto)?;
        let y = point.y().ok_or(PasskeyError::Crypto)?;
        let mut credential = [0_u8; 32];
        OsRng.fill_bytes(&mut credential);
        let credential_id = URL_SAFE_NO_PAD.encode(credential);
        let display = request
            .user
            .display_name
            .clone()
            .unwrap_or_else(|| request.user.name.clone());
        let login_id = matching_login(self, &origin_info.origin, &request.user.name, default_login_id)?;
        let scalar = Zeroizing::new(signing.to_bytes());
        let stored = StoredPasskey {
            version: 1,
            credential_id: credential_id.clone(),
            rp_id: request.rp.id.clone(),
            user_handle: request.user.id.clone(),
            user_name: request.user.name.clone(),
            user_display_name: display.clone(),
            login_id,
            private_key_jwk: PrivateJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
                d: URL_SAFE_NO_PAD.encode(&*scalar),
            },
            sign_count: 0,
            backup_eligible: true,
            backup_state: false,
            created_at: now.into(),
            last_used_at: None,
        };
        let mut stored_json = Zeroizing::new(
            serde_json::to_string(&stored).map_err(|_| PasskeyError::Serialization)?,
        );
        let auth_data = registration_data(&request.rp.id, &credential, x, y)?;
        let client = client_data("webauthn.create", &request.challenge, &origin_info)?;
        let attestation = cbor_map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (
                Cbor::Text("authData".into()),
                Cbor::Bytes(auth_data.clone()),
            ),
        ]);
        let der = signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| PasskeyError::Crypto)?;
        let response = json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client),
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
                "publicKey": URL_SAFE_NO_PAD.encode(der.as_bytes()),
                "publicKeyAlgorithm": ES256,
                "transports": ["internal"]
            },
            "clientExtensionResults": if request.extensions.cred_props {
                json!({ "credProps": { "rk": true } })
            } else {
                json!({})
            }
        })
        .to_string();

        let mut scopes = vec![
            PASSKEY_SCOPE.to_owned(),
            format!("rp:{}", request.rp.id),
            format!("credential:{credential_id}"),
        ];
        if let Some(login_id) = login_id {
            scopes.push(format!("login:{login_id}"));
        }
        let rp_label = if request.rp.name.is_empty() {
            &request.rp.id
        } else {
            &request.rp.name
        };
        self.add_secret(NewSecretItem {
            title: format!("{display} · {rp_label}"),
            kind: SecretItemKind::AuthenticatorKey,
            provider: Some(PASSKEY_PROVIDER.to_owned()),
            account: Some(request.user.name),
            secret: std::mem::take(&mut *stored_json),
            environment: Some("Passkey".to_owned()),
            scopes,
            expires_at: None,
            website: Some(origin_info.origin),
            notes: Some(
                "由 WebAuthn 注册自动创建。私钥仅在桌面端加密保险库内用于签名。".to_owned(),
            ),
            folder: Some("Passkeys".to_owned()),
            favorite: false,
            master_password_reprompt: false,
        })?;
        self.reconcile_service_automatic_links()?;
        Ok(response)
    }

    pub fn sign_passkey_assertion(
        &mut self,
        request_json: &str,
        allowed_item_id: Option<Uuid>,
        credential_id: Option<&str>,
        now: &str,
    ) -> Result<String, PasskeyError> {
        self.payload()?;
        let (request, origin_info) = parse_get_request(request_json)?;
        if let Some(credential_id) = credential_id {
            validate_b64(credential_id)?;
        }
        let selected = self
            .payload()?
            .secrets
            .iter()
            .rev()
            .find(|item| {
                is_passkey_item_for_rp(item, &request.rp_id)
                    && allowed_item_id.is_none_or(|allowed| item.id == allowed)
                    && credential_id.is_none_or(|cid| {
                        scope_value(&item.scopes, "credential:") == Some(cid)
                    })
                    && (request.allow_credentials.is_empty()
                        || request.allow_credentials.iter().any(|descriptor| {
                            scope_value(&item.scopes, "credential:")
                                == Some(descriptor.id.as_str())
                        }))
            })
            .cloned()
            .ok_or(PasskeyError::NotFound)?;

        let secret_json = self.secret_value_for_access(selected.id, None)?;
        let (mut stored, signing) =
            load_validated_passkey(&selected, secret_json.as_str(), &request.rp_id)?;
        let next = if stored.backup_eligible {
            0
        } else {
            stored.sign_count.saturating_add(1)
        };
        let mut auth_data = assertion_data(&request.rp_id, next);
        if stored.backup_eligible {
            auth_data[32] |= 0x08;
            if stored.backup_state {
                auth_data[32] |= 0x10;
            }
        }
        let client = client_data("webauthn.get", &request.challenge, &origin_info)?;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = signing.sign(&signed);
        stored.sign_count = next;
        stored.last_used_at = Some(now.into());
        let mut stored_json = Zeroizing::new(
            serde_json::to_string(&stored).map_err(|_| PasskeyError::Serialization)?,
        );
        let client_extension_results = if request.extensions.appid.is_some() {
            json!({ "appid": false })
        } else {
            json!({})
        };
        let response = json!({
            "id": stored.credential_id,
            "rawId": stored.credential_id,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client),
                "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
                "userHandle": stored.user_handle
            },
            "clientExtensionResults": client_extension_results
        })
        .to_string();

        self.update_secret(SecretItemUpdate {
            id: selected.id,
            title: selected.title.clone(),
            kind: selected.kind.clone(),
            provider: selected.provider.clone(),
            account: selected.account.clone(),
            secret: Some(std::mem::take(&mut *stored_json)),
            environment: selected.environment.clone(),
            scopes: selected.scopes.clone(),
            expires_at: selected.expires_at.clone(),
            website: selected.website.clone(),
            notes: selected.notes.clone(),
            folder: selected.folder.clone(),
            favorite: selected.favorite,
            master_password_reprompt: selected.master_password_reprompt,
        })?;
        self.reconcile_service_automatic_links()?;
        Ok(response)
    }
}

pub(crate) fn passkey_is_backup_eligible(secret_json: &str) -> bool {
    #[derive(Deserialize)]
    struct Eligibility {
        #[serde(rename = "backupEligible", default)]
        eligible: bool,
    }
    serde_json::from_str::<Eligibility>(secret_json).is_ok_and(|s| s.eligible)
}

pub(crate) fn passkey_is_backed_up(secret_json: &str) -> bool {
    #[derive(Deserialize)]
    struct State {
        #[serde(rename = "backupState", default)]
        backed: bool,
    }
    serde_json::from_str::<State>(secret_json).is_ok_and(|s| s.backed)
}

pub(crate) fn passkey_strip_local_sync_state(
    secret_json: &str,
) -> Result<Zeroizing<String>, VaultError> {
    let mut value = SensitiveValue(
        serde_json::from_str(secret_json).map_err(|_| VaultError::InvalidPayload)?,
    );
    let Some(object) = value.0.as_object_mut() else {
        return Err(VaultError::InvalidPayload);
    };
    object.insert("backupState".to_owned(), Value::Bool(false));
    object.insert("lastUsedAt".to_owned(), Value::Null);
    serde_json::to_string(&value.0)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Serialization)
}

pub(crate) fn passkey_apply_local_sync_state(
    secret_json: &str,
    previous_secret_json: Option<&str>,
    backed_up: bool,
) -> Result<Zeroizing<String>, VaultError> {
    let mut value = SensitiveValue(
        serde_json::from_str(secret_json).map_err(|_| VaultError::InvalidPayload)?,
    );
    let Some(object) = value.0.as_object_mut() else {
        return Err(VaultError::InvalidPayload);
    };
    if let Some(previous_secret_json) = previous_secret_json {
        let old = SensitiveValue(
            serde_json::from_str(previous_secret_json).map_err(|_| VaultError::InvalidPayload)?,
        );
        let Some(old_object) = old.0.as_object() else {
            return Err(VaultError::InvalidPayload);
        };
        let last_used = old_object.get("lastUsedAt").cloned().unwrap_or(Value::Null);
        object.insert("lastUsedAt".to_owned(), last_used);
    }
    object.insert("backupState".to_owned(), Value::Bool(backed_up));
    serde_json::to_string(&value.0)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Serialization)
}

pub(crate) fn passkey_mark_backed_up(secret_json: &str) -> Result<Zeroizing<String>, VaultError> {
    let mut value = SensitiveValue(
        serde_json::from_str(secret_json).map_err(|_| VaultError::InvalidPayload)?,
    );
    let Some(object) = value.0.as_object_mut() else {
        return Err(VaultError::InvalidPayload);
    };
    object.insert("backupState".to_owned(), Value::Bool(true));
    serde_json::to_string(&value.0)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Serialization)
}

struct SensitiveValue(Value);

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_json),
        Value::Object(entries) => entries.values_mut().for_each(wipe_json),
        _ => {}
    }
}

fn parse_create_request(
    request_json: &str,
) -> Result<(CreateRequest, ValidatedOrigin), PasskeyError> {
    let request: CreateRequest = parse(request_json)?;
    let origin_info = validate_common(&request.rp.id, &request.challenge, &request.extensions)?;
    if request.rp.name.len() > 256
        || request.user.name.len() > 256
        || request
            .user
            .display_name
            .as_deref()
            .is_some_and(|v| v.len() > 256)
        || request.exclude_credentials.len() > 200
        || request.pub_key_cred_params.is_empty()
        || request.pub_key_cred_params.len() > 64
        || request
            .pub_key_cred_params
            .iter()
            .any(|parameter| parameter.credential_type != "public-key")
        || request
            .authenticator_selection
            .as_ref()
            .is_some_and(|selection| !valid_selection(selection))
    {
        return Err(PasskeyError::InvalidRequest);
    }
    if !request.pub_key_cred_params.iter().any(|p| p.alg == ES256) {
        return Err(PasskeyError::UnsupportedAlgorithm);
    }
    if request
        .authenticator_selection
        .as_ref()
        .and_then(|s| s.authenticator_attachment.as_deref())
        == Some("cross-platform")
    {
        return Err(PasskeyError::CrossPlatformNotSupported);
    }
    if request
        .extensions
        .large_blob
        .as_ref()
        .and_then(|v| v.support.as_deref())
        == Some("required")
    {
        return Err(PasskeyError::LargeBlobNotSupported);
    }
    for descriptor in &request.exclude_credentials {
        validate_descriptor(descriptor)?;
        validate_b64(&descriptor.id)?;
    }
    validate_b64(&request.user.id)?;
    Ok((request, origin_info))
}

fn parse_get_request(request_json: &str) -> Result<(GetRequest, ValidatedOrigin), PasskeyError> {
    let request: GetRequest = parse(request_json)?;
    let origin_info = validate_common(&request.rp_id, &request.challenge, &request.extensions)?;
    if request.allow_credentials.len() > 200
        || !matches!(
            request.user_verification.as_str(),
            "discouraged" | "preferred" | "required"
        )
    {
        return Err(PasskeyError::InvalidRequest);
    }
    for descriptor in &request.allow_credentials {
        validate_descriptor(descriptor)?;
        validate_b64(&descriptor.id)?;
    }
    Ok((request, origin_info))
}

fn is_passkey_item_for_rp(item: &SecretItem, rp_id: &str) -> bool {
    item.kind == SecretItemKind::AuthenticatorKey
        && item.provider.as_deref() == Some(PASSKEY_PROVIDER)
        && item.scopes.iter().any(|s| s == PASSKEY_SCOPE)
        && item
            .scopes
            .iter()
            .any(|s| s.strip_prefix("rp:") == Some(rp_id))
}

fn scope_value<'a>(scopes: &'a [String], prefix: &str) -> Option<&'a str> {
    scopes
        .iter()
        .find_map(|scope| scope.strip_prefix(prefix))
}

fn scope_uuid(scopes: &[String], prefix: &str) -> Option<Uuid> {
    scope_value(scopes, prefix).and_then(|value| Uuid::parse_str(value).ok())
}

fn load_validated_passkey(
    item: &SecretItem,
    secret_json: &str,
    rp_id: &str,
) -> Result<(StoredPasskey, SigningKey), PasskeyError> {
    let stored: StoredPasskey =
        serde_json::from_str(secret_json).map_err(|_| PasskeyError::InvalidStoredPasskey)?;
    if stored.version != 1
        || stored.rp_id != rp_id
        || scope_value(&item.scopes, "credential:") != Some(stored.credential_id.as_str())
        || stored.private_key_jwk.kty != "EC"
        || stored.private_key_jwk.crv != "P-256"
        || validate_b64(&stored.credential_id).is_err()
        || validate_b64(&stored.user_handle).is_err()
    {
        return Err(PasskeyError::InvalidStoredPasskey);
    }
    let d = decode32(&stored.private_key_jwk.d)?;
    let signing =
        SigningKey::from_slice(d.as_ref()).map_err(|_| PasskeyError::InvalidPrivateKey)?;
    let point = signing.verifying_key().to_encoded_point(false);
    if point
        .x()
        .map(|value| URL_SAFE_NO_PAD.encode(value))
        .as_deref()
        != Some(stored.private_key_jwk.x.as_str())
        || point
            .y()
            .map(|value| URL_SAFE_NO_PAD.encode(value))
            .as_deref()
            != Some(stored.private_key_jwk.y.as_str())
    {
        return Err(PasskeyError::InvalidPrivateKey);
    }
    Ok((stored, signing))
}

fn matching_login(
    session: &VaultSession,
    origin: &str,
    user: &str,
    default_login_id: Option<Uuid>,
) -> Result<Option<Uuid>, PasskeyError> {
    let candidates = session.autofill_candidates(origin)?;
    if let Some(default_login_id) = default_login_id
        && candidates
            .iter()
            .any(|candidate| candidate.id == default_login_id)
    {
        return Ok(Some(default_login_id));
    }
    let matched: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.username.trim().eq_ignore_ascii_case(user.trim()))
        .collect();
    Ok((matched.len() == 1).then(|| matched[0].id))
}

fn parse<T: for<'a> Deserialize<'a>>(s: &str) -> Result<T, PasskeyError> {
    if s.len() > MAX_REQUEST_BYTES {
        return Err(PasskeyError::RequestTooLarge);
    }
    serde_json::from_str(s).map_err(|_| PasskeyError::InvalidRequest)
}

fn validate_common(
    rp: &str,
    challenge: &str,
    extensions: &Extensions,
) -> Result<ValidatedOrigin, PasskeyError> {
    if rp.is_empty()
        || rp.len() > 253
        || rp.starts_with('.')
        || rp.ends_with('.')
        || rp.contains("..")
        || rp.chars().any(char::is_whitespace)
    {
        return Err(PasskeyError::InvalidRequest);
    }
    validate_challenge(challenge)?;
    if let Some(appid) = &extensions.appid {
        validate_appid(appid)?;
    }
    validated_origin(rp, &extensions.remote_desktop_client_override)
}

fn validate_appid(appid: &str) -> Result<(), PasskeyError> {
    if appid.len() > 4096 {
        return Err(PasskeyError::InvalidRequest);
    }
    let url = Url::parse(appid).map_err(|_| PasskeyError::InvalidRequest)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(())
}

fn validate_b64(v: &str) -> Result<(), PasskeyError> {
    let decoded = URL_SAFE_NO_PAD.decode(v);
    let canonical = decoded
        .as_ref()
        .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == v);
    if v.is_empty() || v.len() > 4096 || !canonical {
        Err(PasskeyError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_challenge(v: &str) -> Result<(), PasskeyError> {
    let decoded = URL_SAFE_NO_PAD.decode(v);
    let canonical = decoded
        .as_ref()
        .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == v);
    let bounded = decoded
        .as_ref()
        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_CHALLENGE_BYTES);
    if !bounded || !canonical {
        Err(PasskeyError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_descriptor(descriptor: &Descriptor) -> Result<(), PasskeyError> {
    if descriptor.credential_type != "public-key"
        || descriptor.transports.len() > 16
        || descriptor
            .transports
            .iter()
            .any(|transport| transport.len() > 32)
    {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(())
}

fn valid_selection(selection: &Selection) -> bool {
    selection
        .authenticator_attachment
        .as_deref()
        .is_none_or(|value| matches!(value, "platform" | "cross-platform"))
        && selection
            .resident_key
            .as_deref()
            .is_none_or(|value| matches!(value, "discouraged" | "preferred" | "required"))
        && selection
            .user_verification
            .as_deref()
            .is_none_or(|value| matches!(value, "discouraged" | "preferred" | "required"))
}

fn preferred() -> String {
    "preferred".into()
}

fn decode32(v: &str) -> Result<Zeroizing<[u8; 32]>, PasskeyError> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(v)
            .map_err(|_| PasskeyError::InvalidPrivateKey)?,
    );
    if bytes.len() != 32 {
        return Err(PasskeyError::InvalidPrivateKey);
    }
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_canonical_http_origin(raw: &str) -> Result<Url, PasskeyError> {
    if raw.len() > MAX_ORIGIN_LEN {
        return Err(PasskeyError::InvalidOrigin);
    }
    let url = Url::parse(raw).map_err(|_| PasskeyError::InvalidOrigin)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.origin().ascii_serialization() != raw
    {
        return Err(PasskeyError::InvalidOrigin);
    }
    Ok(url)
}

fn validated_origin(rp: &str, o: &Override) -> Result<ValidatedOrigin, PasskeyError> {
    let url = parse_canonical_http_origin(&o.origin)?;
    let host = url
        .host_str()
        .ok_or(PasskeyError::InvalidOrigin)?
        .to_ascii_lowercase();
    let rp_lower = rp.to_ascii_lowercase();
    if host != rp_lower && !host.ends_with(&format!(".{rp_lower}")) {
        return Err(PasskeyError::OriginMismatch);
    }
    let validated_top = match o.top_origin.as_deref() {
        Some(raw) => {
            parse_canonical_http_origin(raw)?;
            Some(raw.to_owned())
        }
        None => None,
    };
    let cross_origin = !o.same_origin_with_ancestors;
    if cross_origin && validated_top.is_none() {
        return Err(PasskeyError::InvalidOrigin);
    }
    Ok(ValidatedOrigin {
        origin: o.origin.clone(),
        top_origin: if cross_origin { validated_top } else { None },
        cross_origin,
    })
}

fn client_data(
    kind: &str,
    challenge: &str,
    origin_info: &ValidatedOrigin,
) -> Result<Vec<u8>, PasskeyError> {
    serde_json::to_vec(&ClientData {
        kind,
        challenge,
        origin: &origin_info.origin,
        cross_origin: origin_info.cross_origin,
        top_origin: if origin_info.cross_origin {
            origin_info.top_origin.as_deref()
        } else {
            None
        },
    })
    .map_err(|_| PasskeyError::InvalidRequest)
}

fn registration_data(
    rp: &str,
    id: &[u8],
    x: &[u8],
    y: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    if id.len() > u16::MAX as usize {
        return Err(PasskeyError::InvalidRequest);
    }
    let key = cbor_map(vec![
        (Cbor::Int(1), Cbor::Int(2)),
        (Cbor::Int(3), Cbor::Int(ES256)),
        (Cbor::Int(-1), Cbor::Int(1)),
        (Cbor::Int(-2), Cbor::Bytes(x.to_vec())),
        (Cbor::Int(-3), Cbor::Bytes(y.to_vec())),
    ]);
    let mut v = Sha256::digest(rp.as_bytes()).to_vec();
    v.push(0x4d);
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&[0; 16]);
    v.extend_from_slice(&(id.len() as u16).to_be_bytes());
    v.extend_from_slice(id);
    v.extend_from_slice(&key);
    Ok(v)
}

fn assertion_data(rp: &str, sign_count: u32) -> Vec<u8> {
    let mut v = Sha256::digest(rp.as_bytes()).to_vec();
    v.push(0x05);
    v.extend_from_slice(&sign_count.to_be_bytes());
    v
}

enum Cbor {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Map(Vec<(Cbor, Cbor)>),
}

fn cbor_map(v: Vec<(Cbor, Cbor)>) -> Vec<u8> {
    cbor(Cbor::Map(v))
}

fn cbor(v: Cbor) -> Vec<u8> {
    match v {
        Cbor::Int(n) => len(
            if n >= 0 { 0 } else { 1 },
            if n >= 0 { n as u64 } else { (-1 - n) as u64 },
        ),
        Cbor::Text(s) => {
            let mut v = len(3, s.len() as u64);
            v.extend_from_slice(s.as_bytes());
            v
        }
        Cbor::Bytes(b) => {
            let mut v = len(2, b.len() as u64);
            v.extend(b);
            v
        }
        Cbor::Map(m) => {
            let mut v = len(5, m.len() as u64);
            for (k, x) in m {
                v.extend(cbor(k));
                v.extend(cbor(x));
            }
            v
        }
    }
}

fn len(m: u8, n: u64) -> Vec<u8> {
    if n < 24 {
        vec![(m << 5) | n as u8]
    } else if n <= 255 {
        vec![m << 5 | 24, n as u8]
    } else if n <= 65535 {
        let mut v = vec![m << 5 | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else {
        let mut v = vec![m << 5 | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NewLoginItem, NewServiceRecord};
    use p256::{
        ecdsa::{VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };

    fn create_req(
        rp_id: &str,
        user_id: &str,
        user_name: &str,
        origin_override: Value,
        exclude: Value,
    ) -> String {
        json!({
            "rp": { "id": rp_id, "name": "Example" },
            "user": { "id": user_id, "name": user_name, "displayName": user_name },
            "challenge": URL_SAFE_NO_PAD.encode(b"registration challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "required",
                "userVerification": "required"
            },
            "extensions": {
                "remoteDesktopClientOverride": origin_override,
                "credProps": true
            }
        })
        .to_string()
    }

    fn get_req(rp_id: &str, origin_override: Value, allow: Value) -> String {
        json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
            "rpId": rp_id,
            "allowCredentials": allow,
            "userVerification": "required",
            "extensions": {
                "remoteDesktopClientOverride": origin_override
            }
        })
        .to_string()
    }

    #[test]
    fn origin_top_origin_and_cbor_are_validated_strictly() {
        let same_origin = Override {
            origin: "https://login.example.com".into(),
            same_origin_with_ancestors: true,
            top_origin: None,
        };
        assert_eq!(
            validated_origin("example.com", &same_origin).unwrap(),
            ValidatedOrigin {
                origin: "https://login.example.com".into(),
                top_origin: None,
                cross_origin: false,
            }
        );
        assert_eq!(
            validated_origin("evil.com", &same_origin),
            Err(PasskeyError::OriginMismatch)
        );
        assert_eq!(cbor(Cbor::Int(-7)), vec![0x26]);

        let missing_top = Override {
            origin: "https://auth.example.com".into(),
            same_origin_with_ancestors: false,
            top_origin: None,
        };
        assert_eq!(
            validated_origin("example.com", &missing_top),
            Err(PasskeyError::InvalidOrigin)
        );

        let non_canonical_top = Override {
            origin: "https://auth.example.com".into(),
            same_origin_with_ancestors: false,
            top_origin: Some("https://top.example.org/path".into()),
        };
        assert_eq!(
            validated_origin("example.com", &non_canonical_top),
            Err(PasskeyError::InvalidOrigin)
        );

        let non_http_top = Override {
            origin: "https://auth.example.com".into(),
            same_origin_with_ancestors: false,
            top_origin: Some("chrome-extension://abcdef".into()),
        };
        assert_eq!(
            validated_origin("example.com", &non_http_top),
            Err(PasskeyError::InvalidOrigin)
        );

        let valid_cross = Override {
            origin: "https://auth.example.com".into(),
            same_origin_with_ancestors: false,
            top_origin: Some("https://shop.partner.test:8443".into()),
        };
        assert_eq!(
            validated_origin("example.com", &valid_cross).unwrap(),
            ValidatedOrigin {
                origin: "https://auth.example.com".into(),
                top_origin: Some("https://shop.partner.test:8443".into()),
                cross_origin: true,
            }
        );
    }

    #[test]
    fn cross_origin_client_data_emits_top_origin_and_same_origin_omits_it() {
        let mut session = VaultSession::create("passkey cross origin master").unwrap();
        let cross_override = json!({
            "origin": "https://auth.example.test",
            "sameOriginWithAncestors": false,
            "topOrigin": "https://embedder.other.test"
        });
        let created_raw = session
            .create_passkey(
                &create_req(
                    "example.test",
                    &URL_SAFE_NO_PAD.encode(b"user-cross"),
                    "cross@example.test",
                    cross_override.clone(),
                    json!([]),
                ),
                None,
                "2027-01-15T08:00:00.000Z",
            )
            .unwrap();
        let created: Value = serde_json::from_str(&created_raw).unwrap();
        let create_client_data: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(created["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(create_client_data["type"], "webauthn.create");
        assert_eq!(create_client_data["origin"], "https://auth.example.test");
        assert_eq!(create_client_data["crossOrigin"], true);
        assert_eq!(
            create_client_data["topOrigin"],
            "https://embedder.other.test"
        );

        let assertion_raw = session
            .sign_passkey_assertion(
                &get_req("example.test", cross_override, json!([])),
                None,
                None,
                "2027-01-15T08:00:01.000Z",
            )
            .unwrap();
        let assertion: Value = serde_json::from_str(&assertion_raw).unwrap();
        let get_client_data: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(assertion["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(get_client_data["type"], "webauthn.get");
        assert_eq!(get_client_data["origin"], "https://auth.example.test");
        assert_eq!(get_client_data["crossOrigin"], true);
        assert_eq!(get_client_data["topOrigin"], "https://embedder.other.test");

        let same_assertion_raw = session
            .sign_passkey_assertion(
                &get_req(
                    "example.test",
                    json!({
                        "origin": "https://auth.example.test",
                        "sameOriginWithAncestors": true
                    }),
                    json!([]),
                ),
                None,
                None,
                "2027-01-15T08:00:02.000Z",
            )
            .unwrap();
        let same_assertion: Value = serde_json::from_str(&same_assertion_raw).unwrap();
        let same_client_data: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(same_assertion["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(same_client_data["crossOrigin"], false);
        assert!(same_client_data.get("topOrigin").is_none());
    }

    #[test]
    fn matching_passkeys_returns_newest_first_and_signs_targeted_candidate() {
        let mut session = VaultSession::create("passkey multi master").unwrap();
        let origin_override = json!({
            "origin": "https://login.example.test",
            "sameOriginWithAncestors": true
        });
        let first_raw = session
            .create_passkey(
                &create_req(
                    "example.test",
                    &URL_SAFE_NO_PAD.encode(b"u-1"),
                    "first@example.test",
                    origin_override.clone(),
                    json!([]),
                ),
                None,
                "2027-01-15T08:00:00.000Z",
            )
            .unwrap();
        let first_json: Value = serde_json::from_str(&first_raw).unwrap();
        let first_cred = first_json["id"].as_str().unwrap().to_owned();
        let first_pub = VerifyingKey::from_public_key_der(
            &URL_SAFE_NO_PAD
                .decode(first_json["response"]["publicKey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        let second_raw = session
            .create_passkey(
                &create_req(
                    "example.test",
                    &URL_SAFE_NO_PAD.encode(b"u-2"),
                    "second@example.test",
                    origin_override.clone(),
                    json!([]),
                ),
                None,
                "2027-01-15T08:00:05.000Z",
            )
            .unwrap();
        let second_json: Value = serde_json::from_str(&second_raw).unwrap();
        let second_cred = second_json["id"].as_str().unwrap().to_owned();

        let candidates = session
            .matching_passkeys(&get_req("example.test", origin_override.clone(), json!([])))
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].credential_id, second_cred);
        assert_eq!(candidates[0].account.as_deref(), Some("second@example.test"));
        assert_eq!(candidates[1].credential_id, first_cred);
        assert_eq!(candidates[1].account.as_deref(), Some("first@example.test"));
        assert!(!format!("{candidates:?}").contains("privateKeyJwk"));

        let older_item_id = candidates[1].item_id;
        let signed_raw = session
            .sign_passkey_assertion(
                &get_req("example.test", origin_override.clone(), json!([])),
                Some(older_item_id),
                None,
                "2027-01-15T08:00:06.000Z",
            )
            .unwrap();
        let signed: Value = serde_json::from_str(&signed_raw).unwrap();
        assert_eq!(signed["id"], first_cred);
        let auth = URL_SAFE_NO_PAD
            .decode(signed["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        let client = URL_SAFE_NO_PAD
            .decode(signed["response"]["clientDataJSON"].as_str().unwrap())
            .unwrap();
        let sig = Signature::from_der(
            &URL_SAFE_NO_PAD
                .decode(signed["response"]["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut msg = auth;
        msg.extend_from_slice(&Sha256::digest(client));
        first_pub.verify(&msg, &sig).unwrap();

        let by_cred_raw = session
            .sign_passkey_assertion(
                &get_req("example.test", origin_override.clone(), json!([])),
                None,
                Some(&first_cred),
                "2027-01-15T08:00:07.000Z",
            )
            .unwrap();
        let by_cred: Value = serde_json::from_str(&by_cred_raw).unwrap();
        assert_eq!(by_cred["id"], first_cred);

        // Mismatched item_id and credential_id returns NotFound.
        assert_eq!(
            session.sign_passkey_assertion(
                &get_req("example.test", origin_override.clone(), json!([])),
                Some(older_item_id),
                Some(&second_cred),
                "2027-01-15T08:00:08.000Z",
            ),
            Err(PasskeyError::NotFound)
        );

        // excludeCredentials rejects duplicate creation for the same credential.
        assert_eq!(
            session.create_passkey(
                &create_req(
                    "example.test",
                    &URL_SAFE_NO_PAD.encode(b"u-1"),
                    "first@example.test",
                    origin_override,
                    json!([{ "type": "public-key", "id": first_cred }]),
                ),
                None,
                "2027-01-15T08:00:09.000Z",
            ),
            Err(PasskeyError::CredentialAlreadyExists)
        );
    }

    #[test]
    fn create_links_login_and_reconciles_service_and_private_jwk_zeroizes_d() {
        let mut session = VaultSession::create("passkey service master").unwrap();
        let login = session
            .add_item(NewLoginItem {
                title: "Example Login".into(),
                username: "ada@example.test".into(),
                password: "synthetic-login-password".into(),
                url: Some("https://example.test/login".into()),
                notes: None,
                folder: None,
                favorite: false,
                totp_secret: None,
                recovery_codes: Vec::new(),
                additional_urls: Vec::new(),
                autofill_on_page_load: true,
                master_password_reprompt: false,
                custom_fields: Vec::new(),
            })
            .unwrap();
        let service = session
            .add_service(NewServiceRecord {
                name: "Example".into(),
                description: None,
                tags: Vec::new(),
                sites: vec!["https://example.test".into()],
            })
            .unwrap();
        session.reconcile_service_automatic_links().unwrap();

        session
            .create_passkey(
                &create_req(
                    "example.test",
                    &URL_SAFE_NO_PAD.encode(b"user-ada"),
                    "ada@example.test",
                    json!({ "origin": "https://example.test", "sameOriginWithAncestors": true }),
                    json!([]),
                ),
                None,
                "2027-01-15T08:00:00.000Z",
            )
            .unwrap();

        let secrets = session.list_secrets().unwrap();
        assert_eq!(secrets.len(), 1);
        assert!(secrets[0].is_passkey);
        assert_eq!(secrets[0].login_id, Some(login.id));

        let detail = session.service_detail(service.id).unwrap();
        assert!(
            detail
                .relationships
                .iter()
                .any(|rel| rel.item_id == login.id)
        );

        let mut jwk = PrivateJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "x".into(),
            y: "y".into(),
            d: "secret-scalar-canary".into(),
        };
        assert!(!format!("{jwk:?}").contains("secret-scalar-canary"));
        jwk.zeroize();
        assert!(jwk.d.is_empty());

        session.lock();
        assert_eq!(
            session.matching_passkeys(&get_req(
                "example.test",
                json!({ "origin": "https://example.test", "sameOriginWithAncestors": true }),
                json!([]),
            )),
            Err(PasskeyError::Locked)
        );
    }

    #[test]
    fn error_messages_preserve_extension_dom_exception_contracts_and_sync_helpers() {
        let base_override = json!({
            "origin": "https://example.test",
            "sameOriginWithAncestors": true
        });
        let cross_platform = json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": "AQ", "name": "a" },
            "challenge": URL_SAFE_NO_PAD.encode(b"challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "authenticatorAttachment": "cross-platform" },
            "extensions": { "remoteDesktopClientOverride": base_override }
        })
        .to_string();
        let err = describe_passkey_request("create", &cross_platform).unwrap_err();
        assert_eq!(err, PasskeyError::CrossPlatformNotSupported);
        assert!(err.public_message().contains("安全密钥"));

        let large_blob = json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": "AQ", "name": "a" },
            "challenge": URL_SAFE_NO_PAD.encode(b"challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "extensions": {
                "remoteDesktopClientOverride": base_override,
                "largeBlob": { "support": "required" }
            }
        })
        .to_string();
        let err = describe_passkey_request("create", &large_blob).unwrap_err();
        assert_eq!(err, PasskeyError::LargeBlobNotSupported);
        assert!(err.public_message().contains("largeBlob"));
        assert!(err.public_message().contains("不支持"));

        let rs256_only = json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": "AQ", "name": "a" },
            "challenge": URL_SAFE_NO_PAD.encode(b"challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }],
            "extensions": { "remoteDesktopClientOverride": base_override }
        })
        .to_string();
        let err = describe_passkey_request("create", &rs256_only).unwrap_err();
        assert_eq!(err, PasskeyError::UnsupportedAlgorithm);
        assert!(err.public_message().contains("算法"));
        assert!(err.public_message().contains("不支持"));

        assert!(!passkey_is_backup_eligible("{\"signCount\":4}"));
        assert!(!passkey_is_backed_up("{\"signCount\":4}"));
        let stripped = passkey_strip_local_sync_state(
            "{\"backupEligible\":true,\"backupState\":true,\"lastUsedAt\":\"2027-01-01T00:00:00Z\",\"signCount\":0}",
        )
        .unwrap();
        assert!(!passkey_is_backed_up(&stripped));
        assert!(stripped.contains("\"lastUsedAt\":null"));
        let applied = passkey_apply_local_sync_state(
            &stripped,
            Some("{\"lastUsedAt\":\"2027-01-02T00:00:00Z\"}"),
            true,
        )
        .unwrap();
        assert!(passkey_is_backed_up(&applied));
        assert!(applied.contains("\"lastUsedAt\":\"2027-01-02T00:00:00Z\""));
        let marked = passkey_mark_backed_up(&stripped).unwrap();
        assert!(passkey_is_backed_up(&marked));
    }
}
