use std::collections::{HashMap, HashSet};

use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use url::Url;
use uuid::Uuid;
use vaultmesh_ffi::{
    DesktopRuntime, DesktopRuntimeError, VAULTMESH_ITEM_KIND_LOGIN,
    VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_ITEM_KIND_SECRET,
    VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_CARD_NUMBER,
    VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE, VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD,
    VAULTMESH_PROTECTED_FIELD_SECRET_VALUE, VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE,
    VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD, VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY,
    VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY, VAULTMESH_STATUS_AUTH_FAILED,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_LOCKED, VAULTMESH_STATUS_REAUTH_REQUIRED,
};

use crate::browser_broker::BrowserPlatformError;

const MAX_DISCOVERY_LIFETIME_MILLIS: i64 = 70_000;

#[derive(Default)]
pub struct BrowserFillService {
    seen_discoveries: HashMap<Uuid, i64>,
}

#[derive(Clone)]
pub struct FillPrompt {
    pub item_title: String,
    pub item_kind: String,
    pub origin: String,
}

impl BrowserFillService {
    pub fn clear(&mut self) {
        self.seen_discoveries.clear();
    }

    pub fn profile(&self, runtime: &mut DesktopRuntime, input: &Map<String, Value>) -> Result<Value, BrowserPlatformError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProfileInput { id: Uuid }
        let request: ProfileInput = serde_json::from_value(Value::Object(input.clone()))
            .map_err(|_| invalid("填充规划查询无效。"))?;
        let detail = runtime.execute("items.detail", json!({ "id": request.id })).map_err(runtime_error)?;
        let custom_fields = detail.get("customFields").and_then(Value::as_array)
            .into_iter().flatten().enumerate().take(100).filter_map(|(index, field)| {
                let name = field.get("label")?.as_str()?;
                (!name.is_empty() && name.chars().count() <= 1024).then(|| json!({ "index": index, "name": name }))
            }).collect::<Vec<_>>();
        Ok(json!({ "id": request.id, "customFields": custom_fields }))
    }

    pub fn candidates(
        &self,
        runtime: &mut DesktopRuntime,
        input: &Map<String, Value>,
    ) -> Result<Value, BrowserPlatformError> {
        let input: CandidateInput = serde_json::from_value(Value::Object(input.clone()))
            .map_err(|_| invalid("自动填充候选查询无效。"))?;
        let top_origin = http_origin(&input.top_origin)?;
        let page_url = input.page_url.unwrap_or_else(|| input.top_origin.clone());
        let page = http_page(&page_url)?;
        if page.origin().ascii_serialization() != top_origin {
            return Err(invalid("页面 URL 与顶层来源不匹配。"));
        }
        if !matches!(
            input.field_kind.as_str(),
            "login" | "card" | "identity" | "secret" | "ssh"
        ) || !valid_context(&input.page_context)
        {
            return Err(invalid("自动填充候选查询无效。"));
        }

        let summaries = match input.field_kind.as_str() {
            "login" => runtime.browser_login_metadata(),
            "card" => runtime.execute("cards.list", json!({})),
            "identity" => runtime.execute("identities.list", json!({})),
            "secret" => runtime.execute("secrets.list", json!({})),
            "ssh" => runtime.execute("ssh.list", json!({})),
            _ => unreachable!(),
        }
        .map_err(runtime_error)?;
        let mut candidates = Vec::new();
        for summary in summaries
            .as_array()
            .ok_or_else(|| failure("候选列表无效。"))?
        {
            if candidates.len() == 200 {
                break;
            }
            let id = value_string(summary, "id")?;
            let title = value_string(summary, "title")?;
            let candidate = match input.field_kind.as_str() {
                "login" => {
                    if input.page_context == "otp"
                        && !summary
                            .get("hasTotpSecret")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    let Some(scope) = login_match_scope(&page, summary) else {
                        continue;
                    };
                    json!({
                        "id": id, "kind": "login", "title": title,
                        "subtitle": summary.get("username").and_then(Value::as_str).unwrap_or(""),
                        "matchScope": scope,
                        "autofillOnPageLoad": summary.get("autofillOnPageLoad").and_then(Value::as_bool).unwrap_or(false),
                        "masterPasswordReprompt": summary.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false),
                    })
                }
                "card" => json!({
                    "id": id, "kind": "card", "title": title,
                    "subtitle": summary.get("maskedNumber").and_then(Value::as_str).unwrap_or(""),
                    "masterPasswordReprompt": summary.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false),
                }),
                "identity" => json!({
                    "id": id, "kind": "identity", "title": title,
                    "subtitle": summary.get("displayName").and_then(Value::as_str)
                        .or_else(|| summary.get("organization").and_then(Value::as_str)).unwrap_or(""),
                }),
                "secret" => {
                    if summary.get("isPasskey").and_then(Value::as_bool).unwrap_or(false) { continue; }
                    if input.page_context != "developer-secret"
                        && !summary
                            .get("website")
                            .and_then(Value::as_str)
                            .is_some_and(|website| site_matches(&page, website))
                    {
                        continue;
                    }
                    let subtitle = ["provider", "account", "environment"]
                        .into_iter()
                        .filter_map(|key| summary.get(key).and_then(Value::as_str))
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    json!({
                        "id": id, "kind": "secret", "title": title, "subtitle": subtitle,
                        "masterPasswordReprompt": summary.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false),
                    })
                }
                "ssh" => {
                    if input.page_context != "ssh-console"
                        && !summary
                            .get("host")
                            .and_then(Value::as_str)
                            .is_some_and(|host| {
                                page.host_str().is_some_and(|page_host| {
                                    page_host.eq_ignore_ascii_case(host.trim())
                                })
                            })
                    {
                        continue;
                    }
                    let username = summary
                        .get("username")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let subtitle = summary
                        .get("host")
                        .and_then(Value::as_str)
                        .map(|host| format!("{username}@{host}"))
                        .unwrap_or_else(|| username.to_owned());
                    json!({
                        "id": id, "kind": "ssh", "title": title, "subtitle": subtitle,
                        "masterPasswordReprompt": summary.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false),
                    })
                }
                _ => unreachable!(),
            };
            candidates.push(candidate);
        }
        Ok(json!({ "candidates": candidates }))
    }

    pub fn prompt(
        &self,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Result<FillPrompt, BrowserPlatformError> {
        let request = parse_execute(input, now_millis)?;
        let selected = request
            .discovery
            .selected_item
            .ok_or_else(|| confirmation("请先在插件中选择要填充的项目。"))?;
        Ok(FillPrompt {
            item_title: selected.title,
            item_kind: selected.kind,
            origin: request.discovery.target_origin,
        })
    }

    pub fn execute(
        &mut self,
        runtime: &mut DesktopRuntime,
        input: &Map<String, Value>,
        now_millis: i64,
    ) -> Result<Value, BrowserPlatformError> {
        let request = parse_execute(input, now_millis)?;
        let discovery = request.discovery;
        self.seen_discoveries
            .retain(|_, expiry| *expiry > now_millis);
        if self.seen_discoveries.contains_key(&discovery.request_id) {
            return Err(invalid("自动填充页面字段描述不能重复使用。"));
        }
        self.seen_discoveries
            .insert(discovery.request_id, discovery.expires_millis);

        let selected = discovery
            .selected_item
            .clone()
            .ok_or_else(|| invalid("自动填充请求没有所选项目。"))?;
        if request.mode != "selection" && request.mode != "automatic" {
            return Err(invalid("自动填充模式无效。"));
        }
        if request.mode == "automatic" && selected.kind != "login" {
            return Err(confirmation("自动填充只允许匹配的登录项目。"));
        }

        let detail_operation = match selected.kind.as_str() {
            "login" => "items.detail",
            "card" => "cards.detail",
            "identity" => "identities.detail",
            "secret" => "secrets.detail",
            "ssh" => "ssh.detail",
            _ => return Err(invalid("所选项目类型无效。")),
        };
        let detail = runtime
            .execute(detail_operation, json!({ "id": selected.id }))
            .map_err(|_| confirmation("无法确认所选填充项目。"))?;
        if request.mode == "automatic" {
            let page = http_page(&discovery.target_page_url)?;
            if request.master_password.is_some() || detail.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false)
                || !detail
                .get("autofillOnPageLoad")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || login_match_scope(&page, &detail).is_none()
            {
                return Err(confirmation("该登录项目不能自动填充此页面。"));
            }
        }

        if selected.kind == "secret" && detail.get("isPasskey").and_then(Value::as_bool).unwrap_or(false) {
            return Err(invalid("Passkey 不能通过普通 Secret 填充。"));
        }
        if selected.kind == "card" || request.native_item_plan.is_some() && detail.get("masterPasswordReprompt").and_then(Value::as_bool).unwrap_or(false) {
            let password = request
                .master_password
                .as_deref()
                .ok_or_else(|| reprompt("请在插件中输入主密码确认填充。"))?;
            runtime
                .verify_master_password(password)
                .map_err(|_| failure("主密码不正确，无法完成填充。"))?;
        }

        let values = fill_values(
            runtime,
            &selected.kind,
            &detail,
            request.master_password.as_deref(),
            request.native_item_plan.as_deref(),
        )?;
        let actual_title = detail
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("所选项目无效。"))?;
        let mut frames = Vec::new();
        for frame in &discovery.frames {
            let mut assignments = Vec::new();
            for field in &frame.fields {
                let value = if let Some(plan) = &request.native_item_plan {
                    let entry = plan.iter().find(|entry| entry.handle == field.handle)
                        .ok_or_else(|| invalid("原生填充计划目标无效。"))?;
                    native_item_value(&values, &entry.source)
                } else if let Some(plan) = &request.native_login_plan {
                    let entry = plan.iter().find(|entry| entry.handle == field.handle)
                        .ok_or_else(|| invalid("原生填充计划目标无效。"))?;
                    native_login_value(&values, entry)?
                } else {
                    map_field(&selected.kind, &values, field)
                };
                let Some(value) = value else {
                    continue;
                };
                if value.is_empty() || value.chars().count() > 10_000 {
                    continue;
                }
                assignments.push(json!({
                    "handle": field.handle,
                    "value": value,
                    "overwrite": request.mode == "selection" && selected.kind == "login" && !field.is_empty,
                }));
            }
            if !assignments.is_empty() {
                frames.push(json!({
                    "frameId": frame.frame_id,
                    "documentId": frame.document_id,
                    "frameOrigin": frame.frame_origin,
                    "assignments": assignments,
                }));
            }
        }
        if frames.is_empty() {
            return Err(invalid("页面中没有可安全自动填充的字段。"));
        }
        Ok(json!({
            "kind": "vaultmesh.approved-fill",
            "requestId": discovery.request_id,
            "tabId": discovery.tab_id,
            "topOrigin": discovery.top_origin,
            "expiresAt": discovery.expires_at,
            "selectedItem": { "kind": selected.kind, "id": selected.id, "title": actual_title },
            "frames": frames,
        }))
    }
}

pub fn email_otp_assignment(
    seen_discoveries: &mut HashMap<Uuid, i64>,
    input: &Map<String, Value>,
    code: &str,
    now_millis: i64,
) -> Result<Value, BrowserPlatformError> {
    if !(4..=8).contains(&code.len())
        || !code.bytes().all(|value| value.is_ascii_alphanumeric())
        || !code.bytes().any(|value| value.is_ascii_digit())
    {
        return Err(invalid("邮箱验证码候选无效。"));
    }
    input
        .get("candidateId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| invalid("邮箱验证码候选无效。"))?;
    let mut execute = input.clone();
    execute.remove("candidateId");
    execute.insert("mode".into(), Value::String("selection".into()));
    let request = parse_execute(&execute, now_millis)?;
    let discovery = request.discovery;
    if discovery.selected_item.is_some() {
        return Err(invalid("邮箱验证码填充不能携带 Vault 项目。"));
    }
    if discovery.top_origin != discovery.target_origin {
        return Err(invalid("邮箱验证码只允许填入当前顶层来源。"));
    }
    seen_discoveries.retain(|_, expiry| *expiry > now_millis);
    if seen_discoveries.contains_key(&discovery.request_id) {
        return Err(invalid("邮箱验证码页面字段描述不能重复使用。"));
    }
    seen_discoveries.insert(discovery.request_id, discovery.expires_millis);

    let code_characters = code
        .chars()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let mut frames = Vec::new();
    for frame in &discovery.frames {
        let fields = frame
            .fields
            .iter()
            .filter(|field| field.is_empty && email_otp_field(field, code))
            .collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        let segmented = fields.len() == code_characters.len()
            && fields.len() >= 2
            && fields.iter().all(|field| field.max_length == Some(1));
        let assignments = fields
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                let value = if segmented {
                    code_characters.get(index)?.clone()
                } else {
                    code.to_owned()
                };
                Some(json!({
                    "handle": field.handle,
                    "value": value,
                    "overwrite": false,
                }))
            })
            .collect::<Vec<_>>();
        if !assignments.is_empty() {
            frames.push(json!({
                "frameId": frame.frame_id,
                "documentId": frame.document_id,
                "frameOrigin": frame.frame_origin,
                "assignments": assignments,
            }));
        }
    }
    if frames.is_empty() {
        return Err(invalid("页面中没有可安全填入邮箱验证码的空字段。"));
    }
    Ok(json!({
        "kind": "vaultmesh.approved-fill",
        "requestId": discovery.request_id,
        "tabId": discovery.tab_id,
        "topOrigin": discovery.top_origin,
        "expiresAt": discovery.expires_at,
        "frames": frames,
    }))
}

fn email_otp_field(field: &DiscoveredField, code: &str) -> bool {
    if field.control != "input"
        || field
            .max_length
            .is_some_and(|maximum| code.chars().count() > maximum as usize && maximum != 1)
    {
        return false;
    }
    let input_type = field
        .input_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(input_type.as_str(), "" | "text" | "tel" | "number")
        || input_type == "number" && !code.bytes().all(|value| value.is_ascii_digit())
    {
        return false;
    }
    let metadata = normalize(&format!(
        "{} {} {} {} {}",
        field.label,
        field.name,
        field.id,
        field.placeholder,
        field.autocomplete.join(" ")
    ));
    field.context == "otp"
        || field
            .autocomplete
            .iter()
            .any(|value| value == "one-time-code")
        || contains_any(
            &metadata,
            &[
                "otp",
                "2fa",
                "mfa",
                "onetimecode",
                "verificationcode",
                "securitycode",
                "验证码",
                "校验码",
                "动态码",
            ],
        )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateInput {
    top_origin: String,
    page_url: Option<String>,
    #[serde(default = "login_kind")]
    field_kind: String,
    #[serde(default = "unknown_context")]
    page_context: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteInput {
    discovery: Discovery,
    native_login_plan: Option<Vec<NativeLoginSource>>,
    native_item_plan: Option<Vec<NativeItemSource>>,
    confirmed_target_origin: Option<String>,
    #[serde(default = "automatic_mode")]
    mode: String,
    master_password: Option<String>,
    #[serde(default, rename = "userGestureId")]
    _user_gesture_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeItemSource { handle: Uuid, source: String }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeLoginSource {
    handle: Uuid,
    source: String,
    index: Option<usize>,
    name: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Discovery {
    version: u32,
    request_id: Uuid,
    issued_at: String,
    expires_at: String,
    tab_id: u64,
    top_origin: String,
    target_origin: String,
    target_page_url: String,
    selected_item: Option<SelectedItem>,
    frames: Vec<DiscoveryFrame>,
    #[serde(skip)]
    expires_millis: i64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedItem {
    kind: String,
    id: Uuid,
    title: String,
    #[serde(default, rename = "masterPasswordReprompt")]
    _master_password_reprompt: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiscoveryFrame {
    frame_id: u64,
    document_id: Uuid,
    frame_origin: String,
    fields: Vec<DiscoveredField>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiscoveredField {
    handle: Uuid,
    control: String,
    input_type: Option<String>,
    max_length: Option<u8>,
    is_empty: bool,
    autocomplete: Vec<String>,
    label: String,
    name: String,
    id: String,
    placeholder: String,
    #[serde(default = "unknown_context")]
    context: String,
    options: Option<Vec<SelectOption>>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectOption {
    value: String,
    text: String,
}

#[derive(Default)]
struct FillValues {
    values: HashMap<String, String>,
    custom_fields: Vec<(String, String)>,
    secret_kind: Option<String>,
}

fn parse_execute(
    input: &Map<String, Value>,
    now_millis: i64,
) -> Result<ExecuteInput, BrowserPlatformError> {
    if input.get("nativeLoginPlan").is_some_and(Value::is_null) || input.get("nativeItemPlan").is_some_and(Value::is_null) {
        return Err(invalid("原生 Login 字段计划不能为空。"));
    }
    let mut request: ExecuteInput = serde_json::from_value(Value::Object(input.clone()))
        .map_err(|_| invalid("自动填充页面字段描述无效。"))?;
    let discovery = &mut request.discovery;
    let issued = DateTime::parse_from_rfc3339(&discovery.issued_at)
        .map_err(|_| invalid("自动填充页面字段描述无效。"))?
        .timestamp_millis();
    let expires = DateTime::parse_from_rfc3339(&discovery.expires_at)
        .map_err(|_| invalid("自动填充页面字段描述无效。"))?
        .timestamp_millis();
    discovery.expires_millis = expires;
    if discovery.version != 1
        || expires <= now_millis
        || expires.saturating_sub(issued) > MAX_DISCOVERY_LIFETIME_MILLIS
        || discovery.frames.is_empty()
        || discovery.frames.len() > 16
        || discovery.selected_item.as_ref().is_some_and(|item| {
            item.title.chars().count() > 256
                || !matches!(
                    item.kind.as_str(),
                    "login" | "card" | "identity" | "secret" | "ssh"
                )
        })
    {
        return Err(invalid("自动填充页面字段描述无效或已过期。"));
    }
    let top = http_origin(&discovery.top_origin)?;
    let target = http_origin(&discovery.target_origin)?;
    let page = http_page(&discovery.target_page_url)?;
    if page.origin().ascii_serialization() != target || top != discovery.top_origin {
        return Err(invalid("自动填充来源绑定无效。"));
    }
    let mut handles = HashSet::new();
    let mut documents = HashSet::new();
    let mut field_count = 0usize;
    for frame in &discovery.frames {
        if frame.frame_origin != discovery.target_origin
            || frame.fields.is_empty()
            || frame.fields.len() > 300
            || !documents.insert((frame.frame_id, frame.document_id))
        {
            return Err(invalid("自动填充 frame 绑定无效。"));
        }
        field_count += frame.fields.len();
        for field in &frame.fields {
            if !handles.insert(field.handle) || !valid_field(field) {
                return Err(invalid("自动填充字段描述无效。"));
            }
        }
    }
    if field_count > 1_600
        || request
            .master_password
            .as_ref()
            .is_some_and(|value| !(8..=1_024).contains(&value.len()))
    {
        return Err(invalid("自动填充页面字段描述无效。"));
    }
    if let Some(plan) = &request.native_login_plan {
        if !matches!(request.mode.as_str(), "selection" | "automatic")
            || (request.mode == "selection" && request._user_gesture_id.is_none())
            || (discovery.top_origin != discovery.target_origin && (request.mode != "selection"
                || request.confirmed_target_origin.as_deref() != Some(discovery.target_origin.as_str())))
            || request.confirmed_target_origin.as_ref().is_some_and(|origin| origin != &discovery.target_origin)
            || discovery.frames.len() != 1
            || discovery.selected_item.as_ref().is_none_or(|item| item.kind != "login")
            || plan.is_empty() || plan.len() > 300 || plan.len() != field_count
        {
            return Err(invalid("原生 Login 字段计划必须绑定单 frame，跨源需要显式来源确认。"));
        }
        let mut planned = HashSet::new();
        for entry in plan {
            let field = discovery.frames[0].fields.iter().find(|field| field.handle == entry.handle)
                .ok_or_else(|| invalid("原生 Login 计划目标无效。"))?;
            if !planned.insert(entry.handle) || !valid_native_login_source(field, entry) {
                return Err(invalid("原生 Login 计划字段无效。"));
            }
            if request.mode == "automatic" && (!field.is_empty || !matches!(field.context.as_str(), "login" | "otp") || entry.source == "custom") {
                return Err(invalid("自动填充只允许已识别的空 Login/OTP 字段。"));
            }
        }
    }
    if let Some(plan) = &request.native_item_plan {
        let kind = discovery.selected_item.as_ref().map(|item| item.kind.as_str()).unwrap_or("");
        if request.native_login_plan.is_some() || request.mode != "selection" || request._user_gesture_id.is_none()
            || !matches!(kind, "card" | "identity" | "ssh" | "secret") || discovery.frames.len() != 1
            || plan.is_empty() || plan.len() > 300 || plan.len() != field_count
            || (discovery.top_origin != discovery.target_origin && request.confirmed_target_origin.as_deref() != Some(discovery.target_origin.as_str()))
            || request.confirmed_target_origin.as_ref().is_some_and(|origin| origin != &discovery.target_origin)
            || (kind != "identity" && page.scheme() != "https")
        { return Err(invalid("原生项目计划需要单 frame 显式选择与来源确认。")); }
        let mut planned = HashSet::new();
        for entry in plan {
            let field = discovery.frames[0].fields.iter().find(|field| field.handle == entry.handle)
                .ok_or_else(|| invalid("原生项目计划目标无效。"))?;
            if !planned.insert(entry.handle) || !valid_native_item_source(kind, field, &entry.source) {
                return Err(invalid("原生项目计划来源无效。"));
            }
        }
    }
    if request.confirmed_target_origin.is_some() && request.native_login_plan.is_none() && request.native_item_plan.is_none() {
        return Err(invalid("跨源原生确认不能用于旧字段映射。"));
    }
    Ok(request)
}

fn native_item_key(source: &str) -> Option<&'static str> {
    Some(match source {
        "card:cardholderName" => "cardholderName", "card:number" => "cardNumber",
        "card:code" => "securityCode", "card:brand" => "brand",
        "card:expMonth" => "expirationMonth", "card:expYear" => "expirationYear", "card:exp" => "expiration",
        "identity:fullName" => "fullName", "identity:firstName" => "firstName",
        "identity:middleName" => "middleName", "identity:lastName" => "lastName",
        "identity:email" => "email", "identity:address1" => "addressLine1",
        "identity:address2" => "addressLine2", "identity:fullAddress" => "fullAddress",
        "identity:postalCode" => "postalCode", "identity:city" => "city",
        "identity:state" => "region", "identity:country" => "country",
        "identity:phone" => "phone", "identity:company" => "organization",
        "ssh:title" => "title", "ssh:host" => "host", "ssh:port" => "port", "ssh:username" => "username",
        "ssh:password" => "password", "ssh:publicKey" => "publicKey", "ssh:privateKey" => "privateKey",
        "ssh:keyPassphrase" => "keyPassphrase", "secret:account" => "account", "secret:provider" => "provider",
        "secret:api-key" | "secret:access-token" | "secret:authenticator-key" | "secret:client-secret"
        | "secret:webhook-secret" | "secret:database-credential" | "secret:recovery-codes" | "secret:certificate"
        | "secret:software-license" | "secret:identity-document" | "secret:secure-note" | "secret:crypto-wallet"
        | "secret:other" => "secret", _ => return None,
    })
}

fn valid_native_item_source(kind: &str, field: &DiscoveredField, source: &str) -> bool {
    let metadata = format!("{} {} {} {} {}", field.label, field.name, field.id, field.placeholder, field.autocomplete.join(" "));
    if matches!(kind, "ssh" | "secret") {
        return source.starts_with(&format!("{kind}:")) && native_item_key(source).is_some() && field.is_empty
            && !excluded_fill_field(&metadata)
            && !field.autocomplete.iter().any(|v| matches!(v.as_str(), "new-password" | "one-time-code"))
            && (field.control == "textarea" || field.control == "input"
                && (matches!(field.input_type.as_deref(), Some("text" | "password" | "email" | "tel"))
                    || source == "ssh:port" && field.input_type.as_deref() == Some("number")));
    }
    source.starts_with(&format!("{kind}:")) && native_item_key(source).is_some() && field.is_empty
        && !excluded_fill_field(&metadata)
        && !field.autocomplete.iter().any(|v| matches!(v.as_str(), "new-password" | "current-password" | "one-time-code"))
        && (field.control == "select" || field.control == "textarea" || field.control == "input"
            && matches!(field.input_type.as_deref(), Some("text" | "email" | "tel" | "number" | "month")))
}

fn native_item_value(values: &FillValues, source: &str) -> Option<String> {
    if native_item_key(source) == Some("secret") && values.secret_kind.as_deref() != source.strip_prefix("secret:") { return None; }
    if source == "identity:country" { return values.values.get("country").or_else(|| values.values.get("countryName")).cloned(); }
    native_item_key(source).and_then(|key| values.values.get(key)).cloned()
}

// Authorization guard, not a second heuristic classifier. The upstream engine
// owns source selection; these checks cannot invent or redirect a source.
fn valid_native_login_source(field: &DiscoveredField, entry: &NativeLoginSource) -> bool {
    let metadata = format!("{} {} {} {} {}", field.label, field.name, field.id,
        field.placeholder, field.autocomplete.join(" "));
    if field.control != "input" || excluded_fill_field(&metadata)
        || !matches!(field.context.as_str(), "unknown" | "login" | "otp")
        || field.autocomplete.iter().any(|value| value == "new-password")
    {
        return false;
    }
    if entry.source != "totpCode" && entry.source != "custom" && (entry.index.is_some() || entry.name.is_some()) {
        return false;
    }
    if entry.source != "totpCode" && field.autocomplete.iter().any(|value| value == "one-time-code") {
        return false;
    }
    match entry.source.as_str() {
        "username" => matches!(field.input_type.as_deref(), Some("text" | "email" | "tel")),
        "password" => field.input_type.as_deref() == Some("password"),
        "totpCode" => field.is_empty && entry.name.is_none()
            && entry.index.is_none_or(|index| index < 6)
            && matches!(field.input_type.as_deref(), Some("text" | "tel" | "number"))
            && (entry.index.is_none() || field.max_length == Some(1)),
        "custom" => entry.index.is_some_and(|index| index < 300)
            && entry.name.as_ref().is_some_and(|name| !name.is_empty() && name.chars().count() <= 1024)
            && matches!(field.input_type.as_deref(), Some("text" | "email" | "tel" | "password" | "number")),
        _ => false,
    }
}

fn native_login_value(values: &FillValues, entry: &NativeLoginSource) -> Result<Option<String>, BrowserPlatformError> {
    if entry.source == "custom" {
        let (name, value) = entry.index.and_then(|index| values.custom_fields.get(index))
            .filter(|(name, _)| Some(name) == entry.name.as_ref())
            .ok_or_else(|| invalid("自定义字段已改变，请重新选择填充。"))?;
        let _ = name;
        return Ok(Some(value.clone()));
    }
    let value = values.values.get(&entry.source);
    if entry.source == "totpCode" {
        return Ok(value.filter(|code| code.len() == 6 && code.bytes().all(|ch| ch.is_ascii_digit()))
            .map(|code| entry.index.map_or_else(|| code.clone(), |index| code[index..index + 1].to_owned())));
    }
    Ok(value.cloned())
}

fn valid_field(field: &DiscoveredField) -> bool {
    matches!(
        field.control.as_str(),
        "input" | "textarea" | "select" | "contenteditable"
    ) && field
        .input_type
        .as_ref()
        .is_none_or(|value| text_within(value, 32))
        && field
            .max_length
            .is_none_or(|value| (1..=100).contains(&value))
        && field.autocomplete.len() <= 8
        && field
            .autocomplete
            .iter()
            .all(|value| text_within(value, 64))
        && text_within(&field.label, 240)
        && text_within(&field.name, 160)
        && text_within(&field.id, 160)
        && text_within(&field.placeholder, 160)
        && valid_context(&field.context)
        && field.options.as_ref().is_none_or(|options| {
            options.len() <= 200
                && options
                    .iter()
                    .all(|option| text_within(&option.value, 160) && text_within(&option.text, 160))
        })
}
