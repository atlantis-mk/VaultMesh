fn fill_values(
    runtime: &mut DesktopRuntime,
    kind: &str,
    detail: &Value,
    password: Option<&str>,
    native_sources: Option<&[NativeItemSource]>,
) -> Result<FillValues, BrowserPlatformError> {
    let id = value_string(detail, "id")?;
    let mut result = FillValues::default();
    let requested = |key: &str| native_sources.is_none_or(|entries| entries.iter().any(|entry| native_item_key(&entry.source) == Some(key)));
    match kind {
        "login" => {
            put(&mut result, "username", detail.get("username"));
            let secret = runtime
                .protected_value(
                    VAULTMESH_ITEM_KIND_LOGIN,
                    VAULTMESH_PROTECTED_FIELD_LOGIN_PASSWORD,
                    &id,
                    password,
                )
                .map_err(runtime_error)?;
            result.values.insert("password".into(), secret.to_string());
            if detail
                .get("hasTotpSecret")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let totp = runtime.totp_value(&id, password).map_err(runtime_error)?;
                put(&mut result, "totpCode", totp.get("code"));
            }
            if let Some(fields) = detail.get("customFields").and_then(Value::as_array) {
                for field in fields.iter().take(100) {
                    if let (Some(label), Some(value)) = (
                        field.get("label").and_then(Value::as_str),
                        field.get("value").and_then(Value::as_str),
                    ) {
                        result
                            .custom_fields
                            .push((label.to_owned(), value.to_owned()));
                    }
                }
            }
        }
        "card" => {
            put(&mut result, "brand", detail.get("network"));
            put(&mut result, "cardholderName", detail.get("cardholderName"));
            let number = runtime
                .protected_value(
                    VAULTMESH_ITEM_KIND_PAYMENT_CARD,
                    VAULTMESH_PROTECTED_FIELD_CARD_NUMBER,
                    &id,
                    password,
                )
                .map_err(runtime_error)?;
            result
                .values
                .insert("cardNumber".into(), number.to_string());
            if let Some(month) = detail.get("expirationMonth").and_then(Value::as_u64) {
                result
                    .values
                    .insert("expirationMonth".into(), format!("{month:02}"));
            }
            if let Some(year) = detail.get("expirationYear").and_then(Value::as_u64) {
                result
                    .values
                    .insert("expirationYear".into(), year.to_string());
            }
            if let (Some(month), Some(year)) = (
                result.values.get("expirationMonth"),
                result.values.get("expirationYear"),
            ) {
                result
                    .values
                    .insert("expiration".into(), format!("{month}/{year}"));
            }
            put(&mut result, "billingAddress", detail.get("billingAddress"));
            if detail
                .get("hasSecurityCode")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let code = runtime
                    .protected_value(
                        VAULTMESH_ITEM_KIND_PAYMENT_CARD,
                        VAULTMESH_PROTECTED_FIELD_CARD_SECURITY_CODE,
                        &id,
                        password,
                    )
                    .map_err(runtime_error)?;
                result
                    .values
                    .insert("securityCode".into(), code.to_string());
            }
        }
        "identity" => identity_values(&mut result, detail),
        "secret" => {
            put(&mut result, "account", detail.get("account"));
            put(&mut result, "provider", detail.get("provider"));
            result.secret_kind = detail
                .get("kind")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if !requested("secret") || native_sources.is_some_and(|entries| !entries.iter().any(|entry|
                entry.source.strip_prefix("secret:") == result.secret_kind.as_deref())) { return Ok(result); }
            let secret = runtime
                .protected_value(
                    VAULTMESH_ITEM_KIND_SECRET,
                    VAULTMESH_PROTECTED_FIELD_SECRET_VALUE,
                    &id,
                    password,
                )
                .map_err(runtime_error)?;
            result.values.insert("secret".into(), secret.to_string());
        }
        "ssh" => {
            put(&mut result, "title", detail.get("title"));
            for key in ["host", "username"] {
                put(&mut result, key, detail.get(key));
            }
            if let Some(port) = detail.get("port").and_then(Value::as_u64) {
                result.values.insert("port".into(), port.to_string());
            }
            for (available, key, field) in [
                (
                    "hasPassword",
                    "password",
                    VAULTMESH_PROTECTED_FIELD_SSH_PASSWORD,
                ),
                (
                    "hasPublicKey",
                    "publicKey",
                    VAULTMESH_PROTECTED_FIELD_SSH_PUBLIC_KEY,
                ),
                (
                    "hasPrivateKey",
                    "privateKey",
                    VAULTMESH_PROTECTED_FIELD_SSH_PRIVATE_KEY,
                ),
                (
                    "hasKeyPassphrase",
                    "keyPassphrase",
                    VAULTMESH_PROTECTED_FIELD_SSH_KEY_PASSPHRASE,
                ),
            ] {
                if requested(key) && detail
                    .get(available)
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    let value = runtime
                        .protected_value(VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, field, &id, password)
                        .map_err(runtime_error)?;
                    result.values.insert(key.into(), value.to_string());
                }
            }
        }
        _ => return Err(invalid("所选项目类型无效。")),
    }
    Ok(result)
}

fn identity_values(result: &mut FillValues, detail: &Value) {
    for (source, target) in [
        ("firstName", "firstName"),
        ("middleName", "middleName"),
        ("lastName", "lastName"),
        ("birthDate", "birthDate"),
        ("organization", "organization"),
        ("department", "department"),
        ("jobTitle", "jobTitle"),
        ("website", "website"),
    ] {
        put(result, target, detail.get(source));
    }
    let full_name = ["firstName", "middleName", "lastName"]
        .into_iter()
        .filter_map(|key| result.values.get(key).map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    if !full_name.is_empty() {
        result.values.insert("fullName".into(), full_name);
    }
    for (array_key, target) in [("emails", "email"), ("phones", "phone")] {
        if let Some(entries) = detail.get(array_key).and_then(Value::as_array) {
            let preferred = entries
                .iter()
                .find(|entry| entry.get("preferred").and_then(Value::as_bool) == Some(true))
                .or_else(|| entries.first());
            if let Some(value) = preferred
                .and_then(|entry| entry.get("value"))
                .and_then(Value::as_str)
            {
                result.values.insert(target.into(), value.to_owned());
            }
        }
    }
    if let Some(addresses) = detail.get("addresses").and_then(Value::as_array) {
        let address = addresses
            .iter()
            .find(|entry| entry.get("preferred").and_then(Value::as_bool) == Some(true))
            .or_else(|| addresses.first());
        if let Some(address) = address {
            for (source, target) in [
                ("addressLine1", "addressLine1"),
                ("addressLine2", "addressLine2"),
                ("city", "city"),
                ("region", "region"),
                ("postalCode", "postalCode"),
                ("countryCode", "country"),
                ("country", "countryName"),
            ] {
                put(result, target, address.get(source));
            }
        }
    }
    let address = ["addressLine1", "addressLine2"].into_iter()
        .filter_map(|key| result.values.get(key).map(String::as_str)).collect::<Vec<_>>().join(", ");
    if !address.is_empty() { result.values.insert("fullAddress".into(), address); }
}

fn map_field(kind: &str, values: &FillValues, field: &DiscoveredField) -> Option<String> {
    let autocomplete = field
        .autocomplete
        .iter()
        .map(|value| value.as_str())
        .collect::<Vec<_>>();
    let metadata = format!(
        "{} {} {} {} {}",
        field.label,
        field.name,
        field.id,
        field.placeholder,
        field.autocomplete.join(" ")
    );
    if field.input_type.as_deref() == Some("search") || excluded_fill_field(&metadata) {
        return None;
    }
    match kind {
        "login" => {
            if autocomplete.contains(&"new-password")
                || contains_any(
                    &metadata,
                    &[
                        "newpassword",
                        "setpassword",
                        "createpassword",
                        "confirmpassword",
                        "resetpassword",
                        "新密码",
                        "确认密码",
                        "重置密码",
                    ],
                )
            {
                return None;
            }
            let key = if autocomplete
                .iter()
                .any(|value| matches!(*value, "username" | "email"))
            {
                "username"
            } else if autocomplete.contains(&"current-password") {
                "password"
            } else if autocomplete.contains(&"one-time-code")
                || contains_any(
                    &metadata,
                    &[
                        "otp",
                        "totp",
                        "2fa",
                        "mfa",
                        "onetimecode",
                        "verificationcode",
                        "验证码",
                        "动态码",
                    ],
                )
                || field.context == "otp"
            {
                "totpCode"
            } else if contains_any(&metadata, &["password", "passcode", "密码"])
                || (field.input_type.as_deref() == Some("password") && matches!(field.context.as_str(), "login" | "password-change"))
            {
                "password"
            } else if matches!(field.input_type.as_deref(), Some("email" | "tel")) || contains_any(
                &metadata,
                &[
                    "username",
                    "login",
                    "account",
                    "email",
                    "phone",
                    "mobile",
                    "邮箱",
                    "账号",
                    "用户名",
                    "手机",
                ],
            ) {
                "username"
            } else {
                let matches = values
                    .custom_fields
                    .iter()
                    .filter(|(label, _)| {
                        let label = normalize(label);
                        label.chars().count() > 1 && contains_any(&metadata, &[&label])
                    })
                    .collect::<Vec<_>>();
                return (matches.len() == 1 && field.context != "signup")
                    .then(|| matches[0].1.clone());
            };
            if field.context == "signup" && key != "username" {
                return None;
            }
            if key == "password" && field.control != "input" {
                return None;
            }
            values.values.get(key).cloned()
        }
        "card" => {
            let key = autocomplete
                .iter()
                .find_map(|token| match *token {
                    "cc-name" => Some("cardholderName"),
                    "cc-number" => Some("cardNumber"),
                    "cc-exp" => Some("expiration"),
                    "cc-exp-month" => Some("expirationMonth"),
                    "cc-exp-year" => Some("expirationYear"),
                    "cc-csc" => Some("securityCode"),
                    _ => None,
                })
                .or_else(|| {
                    if contains_any(&metadata, &["cvv", "cvc", "securitycode", "安全码"]) {
                        Some("securityCode")
                    } else if contains_any(&metadata, &["cardholder", "nameoncard", "持卡人"]) {
                        Some("cardholderName")
                    } else if contains_any(&metadata, &["billingaddress", "账单地址"]) {
                        Some("billingAddress")
                    } else if contains_any(&metadata, &["expirationmonth", "expirymonth", "到期月"])
                    {
                        Some("expirationMonth")
                    } else if contains_any(&metadata, &["expirationyear", "expiryyear", "到期年"])
                    {
                        Some("expirationYear")
                    } else if contains_any(&metadata, &["expiration", "expiry", "有效期", "到期"])
                    {
                        Some("expiration")
                    } else if contains_any(&metadata, &["cardnumber", "ccnum", "卡号"]) {
                        Some("cardNumber")
                    } else {
                        None
                    }
                })?;
            select_or_value(field, key, values.values.get(key)?, values)
        }
        "identity" => {
            if contains_any(
                &metadata,
                &[
                    "password",
                    "passcode",
                    "otp",
                    "creditcard",
                    "cvv",
                    "cvc",
                    "ssn",
                    "passport",
                    "身份证",
                    "银行卡",
                    "验证码",
                    "护照",
                ],
            ) {
                return None;
            }
            if field.control == "input"
                && !matches!(
                    field
                        .input_type
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .as_str(),
                    "" | "text" | "email" | "tel" | "url" | "search" | "date" | "month" | "number"
                )
            {
                return None;
            }
            let token = autocomplete.iter().find_map(|token| match *token {
                "given-name" => Some("firstName"),
                "additional-name" => Some("middleName"),
                "family-name" => Some("lastName"),
                "name" => Some("fullName"),
                "bday" => Some("birthDate"),
                "email" => Some("email"),
                "tel" => Some("phone"),
                "organization" => Some("organization"),
                "organization-title" => Some("jobTitle"),
                "url" => Some("website"),
                "address-line1" => Some("addressLine1"),
                "address-line2" => Some("addressLine2"),
                "address-level2" => Some("city"),
                "address-level1" => Some("region"),
                "postal-code" => Some("postalCode"),
                "country" => Some("country"),
                "country-name" => Some("countryName"),
                _ => None,
            });
            let key = token.or_else(|| identity_heuristic(&metadata))?;
            select_or_value(field, key, values.values.get(key)?, values)
        }
        "secret" => {
            if field.control == "select" {
                return None;
            }
            let secret_pattern = secret_pattern(values.secret_kind.as_deref().unwrap_or("other"));
            if contains_any(&metadata, secret_pattern)
                || (field.context == "developer-secret"
                    && contains_any(
                        &metadata,
                        &[
                            "password",
                            "credential",
                            "secret",
                            "token",
                            "key",
                            "密码",
                            "凭据",
                            "密钥",
                            "令牌",
                        ],
                    ))
            {
                values.values.get("secret").cloned()
            } else if contains_any(
                &metadata,
                &[
                    "account",
                    "project",
                    "tenant",
                    "organization",
                    "username",
                    "账号",
                    "项目",
                    "租户",
                ],
            ) {
                values.values.get("account").cloned()
            } else if contains_any(
                &metadata,
                &["provider", "service", "vendor", "服务商", "平台"],
            ) {
                values.values.get("provider").cloned()
            } else {
                None
            }
        }
        "ssh" => {
            if field.control == "select" {
                return None;
            }
            let key = if contains_any(&metadata, &["privatekey", "sshprivate", "私钥"]) {
                "privateKey"
            } else if contains_any(&metadata, &["publickey", "authorizedkey", "sshkey", "公钥"]) {
                "publicKey"
            } else if contains_any(
                &metadata,
                &["passphrase", "keypassword", "私钥口令", "密钥口令"],
            ) {
                "keyPassphrase"
            } else if contains_any(&metadata, &["sshpassword", "loginpassword", "密码"]) {
                "password"
            } else if contains_any(
                &metadata,
                &["sshuser", "username", "login", "账号", "用户名"],
            ) {
                "username"
            } else if contains_any(&metadata, &["hostname", "sshhost", "server", "服务器", "主机"])
                || field.name.eq_ignore_ascii_case("host") || field.id.eq_ignore_ascii_case("host")
            {
                "host"
            } else if contains_any(&metadata, &["port", "端口"]) {
                "port"
            } else {
                return None;
            };
            values.values.get(key).cloned()
        }
        _ => None,
    }
}

fn identity_heuristic(metadata: &str) -> Option<&'static str> {
    let candidates = [
        ("firstName", &["firstname", "givenname", "名字"][..]),
        ("middleName", &["middlename", "中间名"]),
        ("lastName", &["lastname", "familyname", "surname", "姓氏"]),
        ("fullName", &["fullname", "姓名", "真实姓名"]),
        ("email", &["email", "电子邮件", "邮箱"]),
        ("phone", &["phone", "mobile", "telephone", "电话", "手机"]),
        ("birthDate", &["birth", "birthday", "出生日期", "生日"]),
        (
            "organization",
            &[
                "organization",
                "company",
                "employer",
                "单位",
                "公司",
                "组织",
            ],
        ),
        (
            "department",
            &["department", "division", "team", "部门", "团队"],
        ),
        ("jobTitle", &["jobtitle", "position", "职位", "职务"]),
        ("website", &["website", "个人网站"]),
        ("addressLine1", &["addressline1", "street"]),
        (
            "addressLine2",
            &["addressline2", "suite", "unit", "apartment"],
        ),
        ("city", &["city", "城市"]),
        (
            "region",
            &["state", "province", "region", "省", "州", "地区"],
        ),
        ("postalCode", &["postal", "zip", "邮编"]),
        ("country", &["country", "国家"]),
    ];
    let matches = candidates
        .into_iter()
        .filter(|(_, patterns)| contains_any(metadata, patterns))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Some(matches[0].0)
    } else {
        None
    }
}

fn select_or_value(
    field: &DiscoveredField,
    key: &str,
    value: &str,
    values: &FillValues,
) -> Option<String> {
    if field.control != "select" {
        return Some(value.to_owned());
    }
    let normalized = normalize(value);
    let country_name = values
        .values
        .get("countryName")
        .map(|value| normalize(value));
    field
        .options
        .as_ref()?
        .iter()
        .find(|option| {
            normalize(&option.value) == normalized
                || normalize(&option.text) == normalized
                || (key == "country"
                    && country_name
                        .as_ref()
                        .is_some_and(|country| normalize(&option.text) == *country))
                || (key == "expirationMonth"
                    && normalize(&option.value) == value.trim_start_matches('0'))
                || (key == "expirationYear"
                    && normalize(&option.value)
                        == value
                            .chars()
                            .rev()
                            .take(2)
                            .collect::<String>()
                            .chars()
                            .rev()
                            .collect::<String>())
        })
        .map(|option| option.value.clone())
}

fn login_match_scope(page: &Url, detail: &Value) -> Option<&'static str> {
    let urls = detail.get("url").and_then(Value::as_str).into_iter().chain(
        detail
            .get("additionalUrls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    );
    let mut best = None;
    for value in urls {
        let Ok(item) = Url::parse(value) else {
            continue;
        };
        if item.scheme() != page.scheme()
            || item
                .host_str()
                .zip(page.host_str())
                .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
        {
            continue;
        }
        let scope = if item.origin() == page.origin()
            && item.path() != "/"
            && page.path().starts_with(item.path())
        {
            "path"
        } else if item.origin() == page.origin() {
            "origin"
        } else {
            "domain"
        };
        if scope == "path" {
            return Some(scope);
        }
        if scope == "origin" || best.is_none() {
            best = Some(scope);
        }
    }
    best
}

fn site_matches(page: &Url, value: &str) -> bool {
    Url::parse(value).ok().is_some_and(|item| {
        item.scheme() == page.scheme()
            && item
                .host_str()
                .zip(page.host_str())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn http_origin(value: &str) -> Result<String, BrowserPlatformError> {
    let url = http_page(value)?;
    let origin = url.origin().ascii_serialization();
    (origin == value)
        .then_some(origin)
        .ok_or_else(|| invalid("来源必须是 HTTP(S) origin。"))
}

fn http_page(value: &str) -> Result<Url, BrowserPlatformError> {
    let url = Url::parse(value).map_err(|_| invalid("页面 URL 无效。"))?;
    matches!(url.scheme(), "http" | "https")
        .then_some(url)
        .ok_or_else(|| invalid("页面 URL 必须使用 HTTP(S)。"))
}

fn valid_context(value: &str) -> bool {
    matches!(
        value,
        "login"
            | "signup"
            | "password-change"
            | "password-reset"
            | "otp"
            | "checkout"
            | "profile"
            | "developer-secret"
            | "ssh-console"
            | "unknown"
    )
}

fn secret_pattern(kind: &str) -> &'static [&'static str] {
    match kind {
        "api-key" => &["apikey", "apitoken", "接口密钥"],
        "access-token" => &["accesstoken", "bearertoken", "访问令牌"],
        "authenticator-key" => &[
            "authenticatorkey",
            "authenticatorsecret",
            "totpsecret",
            "认证密钥",
        ],
        "client-secret" => &["clientsecret", "oauthsecret", "客户端密钥"],
        "webhook-secret" => &["webhooksecret", "webhooktoken", "签名密钥"],
        "database-credential" => &["database", "connectionstring", "dsn", "数据库", "连接串"],
        "recovery-codes" => &["recoverycode", "backupcode", "恢复码", "备用代码"],
        "certificate" => &["certificate", "pem", "privatekey", "证书", "私钥"],
        "software-license" => &[
            "license",
            "licence",
            "activation",
            "productkey",
            "许可证",
            "激活码",
        ],
        "identity-document" => &[
            "identity",
            "passport",
            "socialsecurity",
            "身份证",
            "护照",
            "证件",
        ],
        "secure-note" => &[
            "securenote",
            "securityquestion",
            "securityanswer",
            "安全笔记",
            "安全问题",
        ],
        "crypto-wallet" => &["wallet", "seedphrase", "mnemonic", "钱包", "助记词"],
        _ => &["secret", "token", "key", "密钥", "令牌"],
    }
}

fn put(result: &mut FillValues, key: &str, value: Option<&Value>) {
    if let Some(value) = value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        result.values.insert(key.to_owned(), value.to_owned());
    }
}

fn value_string(value: &Value, key: &str) -> Result<String, BrowserPlatformError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| failure("保险库条目格式无效。"))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    let words = field_words(value);
    needles.iter().any(|needle| {
        if !needle.is_ascii() { return value.contains(needle); }
        let needle = normalize(needle);
        words.iter().enumerate().any(|(index, _)| {
            let mut combined = String::new();
            for word in &words[index..] {
                combined.push_str(word);
                if combined.len() >= needle.len() { return combined == needle; }
            }
            false
        })
    })
}

fn field_words(value: &str) -> Vec<String> {
    let mut separated = String::new();
    let mut previous_lower = false;
    for character in value.chars() {
        if previous_lower && character.is_ascii_uppercase() { separated.push(' '); }
        previous_lower = character.is_ascii_lowercase();
        separated.push(character.to_ascii_lowercase());
    }
    separated.split(|c: char| !c.is_ascii_alphanumeric()).filter(|word| !word.is_empty()).map(str::to_owned).collect()
}

fn excluded_fill_field(metadata: &str) -> bool {
    static POLICY: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let policy = POLICY.get_or_init(|| serde_json::from_str(include_str!("../../src/shared/autofill-field-policy.json")).expect("bundled field policy"));
    let words = field_words(metadata);
    policy["excludedWords"].as_array().is_some_and(|entries| entries.iter().filter_map(Value::as_str).any(|word| words.iter().any(|entry| entry == word))) ||
        policy["excludedText"].as_array().is_some_and(|entries| entries.iter().filter_map(Value::as_str).any(|word| metadata.contains(word)))
}
fn normalize(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| {
            !character.is_whitespace() && !matches!(character, '.' | '_' | '/' | '-')
        })
        .collect()
}
fn text_within(value: &str, maximum: usize) -> bool {
    value.trim().chars().count() <= maximum
}
fn login_kind() -> String {
    "login".into()
}
fn unknown_context() -> String {
    "unknown".into()
}
fn automatic_mode() -> String {
    "automatic".into()
}

fn runtime_error(error: DesktopRuntimeError) -> BrowserPlatformError {
    let code = match error.status() {
        VAULTMESH_STATUS_LOCKED => "unlock-required",
        VAULTMESH_STATUS_REAUTH_REQUIRED => "re-prompt-required",
        VAULTMESH_STATUS_INVALID_ARGUMENT => "invalid-request",
        VAULTMESH_STATUS_AUTH_FAILED => "operation-failed",
        _ => "operation-failed",
    };
    BrowserPlatformError {
        code,
        message: error.public_message().to_owned(),
    }
}

fn invalid(message: &str) -> BrowserPlatformError {
    BrowserPlatformError {
        code: "invalid-request",
        message: message.to_owned(),
    }
}
fn confirmation(message: &str) -> BrowserPlatformError {
    BrowserPlatformError {
        code: "confirmation-required",
        message: message.to_owned(),
    }
}
fn reprompt(message: &str) -> BrowserPlatformError {
    BrowserPlatformError {
        code: "re-prompt-required",
        message: message.to_owned(),
    }
}
fn failure(message: &str) -> BrowserPlatformError {
    BrowserPlatformError {
        code: "operation-failed",
        message: message.to_owned(),
    }
}

#[cfg(test)]
#[path = "browser_fill_tests.rs"]
mod tests;
