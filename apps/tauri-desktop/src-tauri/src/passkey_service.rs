use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use vaultmesh_ffi::{
    DesktopRuntime, VAULTMESH_ITEM_KIND_SECRET, VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
};
use zeroize::{Zeroize, Zeroizing};

const PASSKEY_SCOPE: &str = "vaultmesh:passkey:v1";
const PASSKEY_PROVIDER: &str = "VaultMesh Passkey";
const ES256: i64 = -7;
const MAX_CHALLENGE_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Override {
    origin: String,
    same_origin_with_ancestors: bool,
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
    support: String,
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

pub struct PasskeyService;

impl PasskeyService {
    pub fn describe(
        kind: &str,
        request_json: &str,
    ) -> Result<(String, String, Option<String>), String> {
        if kind == "create" {
            let request: CreateRequest = parse(request_json)?;
            validate_common(&request.rp.id, &request.challenge, &request.extensions)?;
            let (origin, _) = validated_origin(
                &request.rp.id,
                &request.extensions.remote_desktop_client_override,
            )?;
            return Ok((
                request.rp.id,
                origin,
                Some(request.user.display_name.unwrap_or(request.user.name)),
            ));
        }
        let request: GetRequest = parse(request_json)?;
        validate_common(&request.rp_id, &request.challenge, &request.extensions)?;
        let (origin, _) = validated_origin(
            &request.rp_id,
            &request.extensions.remote_desktop_client_override,
        )?;
        Ok((request.rp_id, origin, None))
    }

    pub fn create(
        runtime: &mut DesktopRuntime,
        request_json: &str,
        default_login_id: Option<Uuid>,
        now: &str,
    ) -> Result<String, String> {
        let request: CreateRequest = parse(request_json)?;
        validate_common(&request.rp.id, &request.challenge, &request.extensions)?;
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
            || !request.pub_key_cred_params.iter().any(|p| p.alg == ES256)
            || request
                .authenticator_selection
                .as_ref()
                .is_some_and(|selection| !valid_selection(selection))
        {
            return Err("Passkey 请求格式无效。".into());
        }
        if request
            .authenticator_selection
            .as_ref()
            .and_then(|s| s.authenticator_attachment.as_deref())
            == Some("cross-platform")
        {
            return Err("该网站仅允许外接安全密钥。".into());
        }
        if request
            .extensions
            .large_blob
            .as_ref()
            .is_some_and(|v| v.support == "required")
        {
            return Err("该网站要求当前版本尚不支持的 largeBlob 扩展。".into());
        }
        for descriptor in &request.exclude_credentials {
            validate_descriptor(descriptor)?;
            validate_b64(&descriptor.id)?;
        }
        let (origin, cross_origin) = validated_origin(
            &request.rp.id,
            &request.extensions.remote_desktop_client_override,
        )?;
        let summaries = passkey_summaries(runtime, &request.rp.id)?;
        if summaries.iter().any(|v| {
            request
                .exclude_credentials
                .iter()
                .any(|d| scope(v, "credential:").as_deref() == Some(&d.id))
        }) {
            return Err("该账户已存在 Passkey。".into());
        }
        validate_b64(&request.user.id)?;
        let signing = SigningKey::random(&mut OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let x = point.x().ok_or("无法创建 Passkey。")?;
        let y = point.y().ok_or("无法创建 Passkey。")?;
        let mut credential = [0_u8; 32];
        OsRng.fill_bytes(&mut credential);
        let credential_id = URL_SAFE_NO_PAD.encode(credential);
        let display = request
            .user
            .display_name
            .clone()
            .unwrap_or_else(|| request.user.name.clone());
        let login_id = matching_login(runtime, &origin, &request.user.name, default_login_id)?;
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
                d: URL_SAFE_NO_PAD.encode(signing.to_bytes()),
            },
            sign_count: 0,
            backup_eligible: true,
            backup_state: false,
            created_at: now.into(),
            last_used_at: None,
        };
        let stored_json =
            Zeroizing::new(serde_json::to_string(&stored).map_err(|_| "无法保存 Passkey。")?);
        let mut scopes = vec![
            PASSKEY_SCOPE.to_owned(),
            format!("rp:{}", request.rp.id),
            format!("credential:{credential_id}"),
        ];
        if let Some(login_id) = login_id {
            scopes.push(format!("login:{login_id}"));
        }
        runtime.execute("secrets.add", json!({
            "title": format!("{} · {}", display, if request.rp.name.is_empty() { &request.rp.id } else { &request.rp.name }),
            "kind": "authenticator-key", "secret": stored_json.as_str(), "provider": PASSKEY_PROVIDER,
            "account": request.user.name, "environment": "Passkey",
            "scopes": scopes,
            "expiresAt": null, "website": origin, "notes": "由 WebAuthn 注册自动创建。私钥仅在桌面端加密保险库内用于签名。",
            "folder": "Passkeys", "favorite": false, "masterPasswordReprompt": false
        })).map_err(|e| e.public_message().to_owned())?;
        let auth_data = registration_data(&request.rp.id, &credential, x, y)?;
        let client = client_data("webauthn.create", &request.challenge, &origin, cross_origin)?;
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
            .map_err(|_| "无法创建 Passkey。")?;
        Ok(json!({"id":credential_id,"rawId":credential_id,"type":"public-key","authenticatorAttachment":"platform","response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"attestationObject":URL_SAFE_NO_PAD.encode(attestation),"authenticatorData":URL_SAFE_NO_PAD.encode(auth_data),"publicKey":URL_SAFE_NO_PAD.encode(der.as_bytes()),"publicKeyAlgorithm":ES256,"transports":["internal"]},"clientExtensionResults": if request.extensions.cred_props { json!({"credProps":{"rk":true}}) } else { json!({}) }}).to_string())
    }

    pub fn get(
        runtime: &mut DesktopRuntime,
        request_json: &str,
        now: &str,
    ) -> Result<String, String> {
        Self::get_for_item(runtime, request_json, now, None)
    }

    pub fn get_for_item(
        runtime: &mut DesktopRuntime,
        request_json: &str,
        now: &str,
        allowed_item_id: Option<Uuid>,
    ) -> Result<String, String> {
        let request: GetRequest = parse(request_json)?;
        validate_common(&request.rp_id, &request.challenge, &request.extensions)?;
        if request.allow_credentials.len() > 200
            || !matches!(
                request.user_verification.as_str(),
                "discouraged" | "preferred" | "required"
            )
        {
            return Err("Passkey 请求格式无效。".into());
        }
        for descriptor in &request.allow_credentials {
            validate_descriptor(descriptor)?;
            validate_b64(&descriptor.id)?;
        }
        let (origin, cross_origin) = validated_origin(
            &request.rp_id,
            &request.extensions.remote_desktop_client_override,
        )?;
        let summaries = passkey_summaries(runtime, &request.rp_id)?;
        let selected = summaries
            .iter()
            .rev()
            .find(|v| {
                let item_allowed = allowed_item_id.is_none_or(|allowed| {
                    v["id"].as_str().and_then(|id| Uuid::parse_str(id).ok()) == Some(allowed)
                });
                item_allowed
                    && (request.allow_credentials.is_empty()
                        || request
                            .allow_credentials
                            .iter()
                            .any(|d| scope(v, "credential:").as_deref() == Some(&d.id)))
            })
            .ok_or("没有找到该网站可用的 Passkey。")?;
        let id = selected["id"].as_str().ok_or("Passkey 数据无效。")?;
        let secret = runtime
            .protected_value(
                VAULTMESH_ITEM_KIND_SECRET,
                VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
                id,
                None,
            )
            .map_err(|e| e.public_message().to_owned())?;
        let mut stored: StoredPasskey =
            serde_json::from_str(secret.as_str()).map_err(|_| "Passkey 数据无效。")?;
        if stored.version != 1
            || stored.rp_id != request.rp_id
            || scope(selected, "credential:").as_deref() != Some(&stored.credential_id)
            || stored.private_key_jwk.kty != "EC"
            || stored.private_key_jwk.crv != "P-256"
            || validate_b64(&stored.credential_id).is_err()
            || validate_b64(&stored.user_handle).is_err()
        {
            return Err("Passkey 数据无效。".into());
        }
        let d = decode32(&stored.private_key_jwk.d)?;
        let signing = SigningKey::from_slice(d.as_ref()).map_err(|_| "Passkey 私钥无效。")?;
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
            return Err("Passkey 私钥无效。".into());
        }
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
        let client = client_data("webauthn.get", &request.challenge, &origin, cross_origin)?;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = signing.sign(&signed);
        stored.sign_count = next;
        stored.last_used_at = Some(now.into());
        let stored_json =
            Zeroizing::new(serde_json::to_string(&stored).map_err(|_| "无法更新 Passkey。")?);
        runtime.execute("secrets.update", json!({
            "id":id,"title":selected["title"],"kind":"authenticator-key","secret":stored_json.as_str(),
            "provider":selected["provider"],"account":selected["account"],"environment":selected["environment"],
            "scopes":selected["scopes"],"expiresAt":selected["expiresAt"],"website":selected["website"],
            "notes":selected["notes"],"folder":selected["folder"],"favorite":selected["favorite"],"masterPasswordReprompt":false
        })).map_err(|e| e.public_message().to_owned())?;
        let client_extension_results = if request.extensions.appid.is_some() {
            json!({"appid": false})
        } else {
            json!({})
        };
        Ok(json!({"id":stored.credential_id,"rawId":stored.credential_id,"type":"public-key","authenticatorAttachment":"platform","response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(auth_data),"signature":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),"userHandle":stored.user_handle},"clientExtensionResults":client_extension_results}).to_string())
    }
}

fn passkey_summaries(runtime: &mut DesktopRuntime, rp: &str) -> Result<Vec<Value>, String> {
    let list = runtime
        .execute("secrets.list", json!({}))
        .map_err(|e| e.public_message().to_owned())?;
    let mut out = vec![];
    for item in list.as_array().ok_or("Passkey 数据无效。")? {
        if item["kind"] == "authenticator-key" && item["provider"] == PASSKEY_PROVIDER {
            let detail = runtime
                .execute("secrets.detail", json!({"id":item["id"]}))
                .map_err(|e| e.public_message().to_owned())?;
            if detail["scopes"].as_array().is_some_and(|s| {
                s.iter().any(|v| v == PASSKEY_SCOPE) && s.iter().any(|v| v == &format!("rp:{rp}"))
            }) {
                out.push(detail);
            }
        }
    }
    Ok(out)
}
fn scope(v: &Value, prefix: &str) -> Option<String> {
    v["scopes"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|s| s.strip_prefix(prefix).map(str::to_owned))
}
fn matching_login(
    runtime: &mut DesktopRuntime,
    origin: &str,
    user: &str,
    default_login_id: Option<Uuid>,
) -> Result<Option<Uuid>, String> {
    let v = runtime
        .execute("browser.autofill.candidates", json!({"url":origin}))
        .map_err(|e| e.public_message().to_owned())?;
    let candidates = v.as_array().into_iter().flatten().collect::<Vec<_>>();
    if let Some(default_login_id) = default_login_id {
        let validated_default = candidates.iter().find_map(|candidate| {
            candidate["id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .filter(|id| *id == default_login_id)
        });
        if validated_default.is_some() {
            return Ok(validated_default);
        }
    }
    let m = candidates
        .into_iter()
        .filter(|x| {
            x["username"]
                .as_str()
                .is_some_and(|u| u.trim().eq_ignore_ascii_case(user.trim()))
        })
        .collect::<Vec<_>>();
    Ok((m.len() == 1)
        .then(|| m[0]["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
        .flatten())
}
fn parse<T: for<'a> Deserialize<'a>>(s: &str) -> Result<T, String> {
    if s.len() > 128 * 1024 {
        return Err("Passkey 请求过大。".into());
    }
    serde_json::from_str(s).map_err(|_| "Passkey 请求格式无效。".into())
}
fn validate_common(rp: &str, challenge: &str, e: &Extensions) -> Result<(), String> {
    if rp.is_empty() || rp.len() > 253 {
        return Err("Passkey 请求格式无效。".into());
    }
    validate_challenge(challenge)?;
    if let Some(appid) = &e.appid {
        validate_appid(appid)?;
    }
    validated_origin(rp, &e.remote_desktop_client_override).map(|_| ())
}
fn validate_appid(appid: &str) -> Result<(), String> {
    if appid.len() > 4096 {
        return Err("Passkey 请求格式无效。".into());
    }
    let url = Url::parse(appid).map_err(|_| "Passkey 请求格式无效。")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Passkey 请求格式无效。".into());
    }
    Ok(())
}
fn validate_b64(v: &str) -> Result<(), String> {
    let decoded = URL_SAFE_NO_PAD.decode(v);
    let canonical = decoded
        .as_ref()
        .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == v);
    if v.is_empty() || v.len() > 4096 || !canonical {
        Err("Passkey 请求格式无效。".into())
    } else {
        Ok(())
    }
}
fn validate_challenge(v: &str) -> Result<(), String> {
    let decoded = URL_SAFE_NO_PAD.decode(v);
    let canonical = decoded
        .as_ref()
        .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == v);
    let bounded = decoded
        .as_ref()
        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_CHALLENGE_BYTES);
    if !bounded || !canonical {
        Err("Passkey 请求格式无效。".into())
    } else {
        Ok(())
    }
}
fn validate_descriptor(descriptor: &Descriptor) -> Result<(), String> {
    if descriptor.credential_type != "public-key"
        || descriptor.transports.len() > 16
        || descriptor
            .transports
            .iter()
            .any(|transport| transport.len() > 32)
    {
        return Err("Passkey 请求格式无效。".into());
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

impl Drop for PrivateJwk {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}
fn decode32(v: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let b = URL_SAFE_NO_PAD
        .decode(v)
        .map_err(|_| "Passkey 私钥无效。")?;
    let a: [u8; 32] = b.try_into().map_err(|_| "Passkey 私钥无效。")?;
    Ok(Zeroizing::new(a))
}
fn validated_origin(rp: &str, o: &Override) -> Result<(String, bool), String> {
    let u = Url::parse(&o.origin).map_err(|_| "Passkey 来源无效。")?;
    if !matches!(u.scheme(), "http" | "https") || u.origin().ascii_serialization() != o.origin {
        return Err("Passkey 来源无效。".into());
    }
    let h = u
        .host_str()
        .ok_or("Passkey 来源无效。")?
        .to_ascii_lowercase();
    let r = rp.to_ascii_lowercase();
    if h != r && !h.ends_with(&format!(".{r}")) {
        return Err("Passkey 来源与网站不匹配。".into());
    }
    Ok((o.origin.clone(), !o.same_origin_with_ancestors))
}
fn client_data(kind: &str, c: &str, o: &str, x: bool) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({"type":kind,"challenge":c,"origin":o,"crossOrigin":x}))
        .map_err(|_| "Passkey 请求格式无效。".into())
}
fn registration_data(rp: &str, id: &[u8], x: &[u8], y: &[u8]) -> Result<Vec<u8>, String> {
    if id.len() > u16::MAX as usize {
        return Err("Passkey 请求格式无效。".into());
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
fn assertion_data(rp: &str, n: u32) -> Vec<u8> {
    let mut v = Sha256::digest(rp.as_bytes()).to_vec();
    v.push(0x05);
    v.extend_from_slice(&n.to_be_bytes());
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
    use p256::{
        ecdsa::{VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };
    use std::fs;

    #[test]
    fn origin_and_cbor_are_bounded() {
        let o = Override {
            origin: "https://login.example.com".into(),
            same_origin_with_ancestors: true,
        };
        assert!(validated_origin("example.com", &o).is_ok());
        assert!(validated_origin("evil.com", &o).is_err());
        assert_eq!(cbor(Cbor::Int(-7)), vec![0x26]);
    }

    #[test]
    fn appid_input_is_https_and_bounded() {
        let request = |appid: Value| {
            json!({
                "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
                "rpId": "example.test",
                "allowCredentials": [],
                "userVerification": "required",
                "extensions": {
                    "remoteDesktopClientOverride": {
                        "origin": "https://example.test",
                        "sameOriginWithAncestors": true
                    },
                    "appid": appid
                }
            })
            .to_string()
        };

        assert!(
            PasskeyService::describe(
                "get",
                &request(json!("https://example.test/legacy-u2f-app-id.json"))
            )
            .is_ok()
        );
        assert!(
            PasskeyService::describe(
                "get",
                &request(json!("http://example.test/legacy-u2f-app-id.json"))
            )
            .is_err()
        );
        assert!(PasskeyService::describe("get", &request(json!(7))).is_err());
        assert!(
            PasskeyService::describe(
                "get",
                &request(json!(format!("https://example.test/{}", "x".repeat(4096))))
            )
            .is_err()
        );
    }

    #[test]
    fn google_sized_challenge_has_a_separate_bounded_limit() {
        let request = |challenge: String| {
            json!({
                "challenge": challenge,
                "rpId": "google.com",
                "allowCredentials": [],
                "userVerification": "preferred",
                "extensions": {
                    "remoteDesktopClientOverride": {
                        "origin": "https://accounts.google.com",
                        "sameOriginWithAncestors": true
                    }
                }
            })
            .to_string()
        };

        let google_sized = URL_SAFE_NO_PAD.encode(vec![0x5a; 5_212]);
        assert!(PasskeyService::describe("get", &request(google_sized)).is_ok());

        let oversized = URL_SAFE_NO_PAD.encode(vec![0x5a; 16 * 1024 + 1]);
        assert!(PasskeyService::describe("get", &request(oversized)).is_err());

        let oversized_identifier = URL_SAFE_NO_PAD.encode(vec![0x5a; 3_073]);
        assert!(validate_b64(&oversized_identifier).is_err());
    }

    #[test]
    fn default_login_is_revalidated_for_the_passkey_origin_before_username_fallback() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-passkey-routing-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("root");
        let mut runtime = DesktopRuntime::new(root.join("routing.vault")).expect("runtime");
        runtime
            .create("passkey routing test master password".into())
            .expect("create vault");
        let add_login =
            |runtime: &mut DesktopRuntime, title: &str, username: &str, url: &str| -> Uuid {
                let login = runtime
                    .execute(
                        "items.add",
                        json!({
                            "title": title, "username": username, "password": "login secret",
                            "url": url, "notes": null, "customFields": []
                        }),
                    )
                    .expect("create login");
                Uuid::parse_str(login["id"].as_str().expect("login id")).expect("login uuid")
            };
        let username_match = add_login(
            &mut runtime,
            "Ada Example",
            "ada@example.test",
            "https://example.test/login",
        );
        let default_login = add_login(
            &mut runtime,
            "Grace Example",
            "grace@example.test",
            "https://example.test/login",
        );
        let cross_origin = add_login(
            &mut runtime,
            "Unrelated",
            "ada@example.test",
            "https://unrelated.test/login",
        );

        assert_eq!(
            matching_login(
                &mut runtime,
                "https://example.test",
                "ada@example.test",
                Some(default_login)
            )
            .expect("validated default"),
            Some(default_login)
        );
        assert_eq!(
            matching_login(
                &mut runtime,
                "https://example.test",
                "ada@example.test",
                Some(cross_origin)
            )
            .expect("username fallback"),
            Some(username_match)
        );

        runtime.lock();
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn create_and_get_round_trip_persists_the_counter_without_exposing_the_private_key() {
        let root = std::env::temp_dir().join(format!("vaultmesh-passkey-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("root");
        let path = root.join("passkey.vault");
        let mut runtime = DesktopRuntime::new(path.clone()).expect("runtime");
        runtime
            .create("passkey test master password".into())
            .expect("create vault");
        let login = runtime
            .execute(
                "items.add",
                json!({
                    "title": "Example",
                    "username": "ada@example.test",
                    "password": "login secret",
                    "url": "https://example.test/login",
                    "notes": null,
                    "customFields": []
                }),
            )
            .expect("create matching login");
        let login_id = login["id"].as_str().expect("login id").to_owned();
        let challenge = URL_SAFE_NO_PAD.encode(b"registration challenge");
        let user_handle = URL_SAFE_NO_PAD.encode(b"user-123");
        let create_request = json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": user_handle, "name": "ada@example.test", "displayName": "Ada" },
            "challenge": challenge,
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": [],
            "authenticatorSelection": { "authenticatorAttachment": "platform", "residentKey": "required", "userVerification": "required" },
            "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true }, "credProps": true }
        })
        .to_string();
        let created = PasskeyService::create(
            &mut runtime,
            &create_request,
            Uuid::parse_str(&login_id).ok(),
            "2027-01-15T08:00:00.000Z",
        )
        .expect("create passkey");
        let created: Value = serde_json::from_str(&created).expect("response");
        let credential_id = created["id"].as_str().expect("credential id");
        assert_eq!(created["type"], "public-key");
        assert_eq!(created["response"]["publicKeyAlgorithm"], -7);
        let registration_auth_data = URL_SAFE_NO_PAD
            .decode(
                created["response"]["authenticatorData"]
                    .as_str()
                    .expect("registration auth data"),
            )
            .expect("decode registration auth data");
        assert_eq!(
            &registration_auth_data[..32],
            Sha256::digest(b"example.test").as_slice()
        );
        assert_eq!(registration_auth_data[32], 0x4d);
        let public_key_der = URL_SAFE_NO_PAD
            .decode(
                created["response"]["publicKey"]
                    .as_str()
                    .expect("public key"),
            )
            .expect("decode public key");
        let verifying_key =
            VerifyingKey::from_public_key_der(&public_key_der).expect("parse public key");
        let summaries = runtime
            .execute("secrets.list", json!({}))
            .expect("summaries");
        assert_eq!(summaries.as_array().map(Vec::len), Some(1));
        assert_eq!(summaries[0]["isPasskey"], true);
        assert_eq!(summaries[0]["loginId"], login_id);
        assert!(!summaries.to_string().contains("privateKeyJwk"));
        let passkey_item_id = summaries[0]["id"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
            .expect("passkey item id");

        let get_request = json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
            "rpId": "example.test",
            "allowCredentials": [{ "type": "public-key", "id": credential_id, "transports": ["internal"] }],
            "userVerification": "required",
            "extensions": {
                "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true },
                "appid": "https://example.test/legacy-u2f-app-id.json"
            }
        })
        .to_string();
        assert!(
            PasskeyService::get_for_item(
                &mut runtime,
                &get_request,
                "2027-01-15T08:00:01.000Z",
                Some(Uuid::new_v4()),
            )
            .is_err(),
            "an Agent assertion must not select a different passkey item"
        );
        for expected_counter in [0_u32, 0] {
            let response = PasskeyService::get_for_item(
                &mut runtime,
                &get_request,
                "2027-01-15T08:00:01.000Z",
                Some(passkey_item_id),
            )
            .expect("get bound passkey");
            let response: Value = serde_json::from_str(&response).expect("assertion response");
            let auth_data = URL_SAFE_NO_PAD
                .decode(
                    response["response"]["authenticatorData"]
                        .as_str()
                        .expect("auth data"),
                )
                .expect("decode auth data");
            assert_eq!(&auth_data[..32], Sha256::digest(b"example.test").as_slice());
            assert_eq!(auth_data[32], 0x0d);
            assert_eq!(
                u32::from_be_bytes(auth_data[33..37].try_into().expect("counter")),
                expected_counter
            );
            assert_eq!(response["id"], credential_id);
            assert_eq!(response["rawId"], credential_id);
            assert_eq!(response["response"]["userHandle"], user_handle);
            assert_eq!(response["clientExtensionResults"]["appid"], false);
            let client_data = URL_SAFE_NO_PAD
                .decode(
                    response["response"]["clientDataJSON"]
                        .as_str()
                        .expect("client data"),
                )
                .expect("decode client data");
            let signature = URL_SAFE_NO_PAD
                .decode(
                    response["response"]["signature"]
                        .as_str()
                        .expect("signature"),
                )
                .expect("decode signature");
            let signature = Signature::from_der(&signature).expect("parse signature");
            let mut signed = auth_data;
            signed.extend_from_slice(&Sha256::digest(client_data));
            verifying_key
                .verify(&signed, &signature)
                .expect("verify assertion signature");
            assert!(!response.to_string().contains("privateKeyJwk"));
        }
        // CT-LAN-SYNC-001: real credential material signs on an independently
        // encrypted replica; neither response exposes the private key.
        let peer = format!("lan-peer-{}", "a".repeat(32));
        let fingerprint = "b".repeat(64);
        let remote_path = path.with_extension("peer.vault");
        let mut remote = DesktopRuntime::new(remote_path.clone()).unwrap();
        remote.create("remote passkey master".into()).unwrap();
        let local_id = runtime.sync_state().unwrap().vault_id;
        let remote_id = remote.sync_state().unwrap().vault_id;
        runtime.sync_authorize(&peer, &fingerprint, true).unwrap();
        remote.sync_authorize(&peer, &fingerprint, true).unwrap();
        runtime
            .sync_bind(&peer, &fingerprint, remote_id, local_id)
            .unwrap();
        remote
            .sync_bind(&peer, &fingerprint, local_id, remote_id)
            .unwrap();
        let records = runtime
            .sync_export(
                &peer,
                &fingerprint,
                remote_id,
                local_id,
                &Default::default(),
            )
            .unwrap();
        remote
            .sync_merge(&peer, &fingerprint, local_id, remote_id, &records)
            .unwrap();
        runtime
            .sync_mark_backed_up(&peer, &fingerprint, remote_id, local_id, &records)
            .unwrap();
        for replica in [&mut runtime, &mut remote] {
            let response: Value = serde_json::from_str(
                &PasskeyService::get_for_item(
                    replica,
                    &get_request,
                    "2027-01-15T08:00:02.000Z",
                    Some(passkey_item_id),
                )
                .unwrap(),
            )
            .unwrap();
            let auth = URL_SAFE_NO_PAD
                .decode(response["response"]["authenticatorData"].as_str().unwrap())
                .unwrap();
            assert_eq!(auth[32], 0x1d);
            assert_eq!(&auth[33..37], &[0; 4]);
            let client = URL_SAFE_NO_PAD
                .decode(response["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap();
            let signature = URL_SAFE_NO_PAD
                .decode(response["response"]["signature"].as_str().unwrap())
                .unwrap();
            let mut signed = auth;
            signed.extend_from_slice(&Sha256::digest(client));
            verifying_key
                .verify(&signed, &Signature::from_der(&signature).unwrap())
                .unwrap();
        }
        remote.lock();
        drop(remote);
        let _ = std::fs::remove_file(remote_path);
        runtime.lock();
        drop(runtime);
        let mut reopened = DesktopRuntime::new(path).expect("reopen runtime");
        reopened
            .unlock("passkey test master password".into())
            .expect("reopen vault");
        let persisted = reopened
            .execute("secrets.list", json!({}))
            .expect("persisted summaries");
        assert_eq!(persisted[0]["isPasskey"], true);
        assert_eq!(persisted[0]["loginId"], login_id);
        assert!(!persisted.to_string().contains("privateKeyJwk"));
        reopened.lock();
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
