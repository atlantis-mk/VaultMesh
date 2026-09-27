fn scan_account_network(
    account: &EmailAccount,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<EmailAccountScanOutput, String> {
    if !account.enabled {
        return Ok(EmailAccountScanOutput {
            messages: Vec::new(),
            refreshed_credential: None,
        });
    }
    match account.provider.as_str() {
        "gmail" => scan_gmail(account, settings, now),
        "outlook" => scan_outlook(account, settings, now),
        _ => scan_imap(account, settings, now).map(|messages| EmailAccountScanOutput {
            messages,
            refreshed_credential: None,
        }),
    }
}

fn browser_origin_host(origin: &str) -> Result<String, String> {
    let url = Url::parse(origin).map_err(|_| "浏览器来源无效。".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.origin().ascii_serialization() != origin {
        return Err("浏览器来源无效。".to_owned());
    }
    url.host_str()
        .filter(|host| !host.is_empty() && host.parse::<IpAddr>().is_err())
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .ok_or_else(|| "浏览器来源无效。".to_owned())
}

fn sender_domain(sender: &str) -> Option<String> {
    static SENDER_DOMAIN: OnceLock<Regex> = OnceLock::new();
    SENDER_DOMAIN
        .get_or_init(|| {
            Regex::new(
                r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)",
            )
            .expect("sender domain regex")
        })
        .captures(sender)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| domain.contains('.') && domain.parse::<IpAddr>().is_err())
}

fn runtime_value(
    runtime: &mut DesktopRuntime,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    runtime
        .execute(operation, input)
        .map_err(|error| error.public_message().to_owned())
}

fn scan_gmail(
    account: &EmailAccount,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<EmailAccountScanOutput, String> {
    let (token, refreshed_credential) = access_token(account, now)?;
    let client = http_client()?;
    let cutoff = now.saturating_sub(settings.message_lookback_minutes * 60);
    let query = gmail_query(settings, cutoff);
    let response: Value = checked(
        client
            .get("https://gmail.googleapis.com/gmail/v1/users/me/messages")
            .bearer_auth(token.as_str())
            .query(&[
                ("maxResults", MAX_MESSAGES_PER_SCAN.to_string()),
                ("q", query),
            ])
            .send(),
    )?
    .json()
    .map_err(|_| "Gmail 返回了无效响应。".to_owned())?;
    let ids = response
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("id").and_then(Value::as_str))
        .take(MAX_MESSAGES_PER_SCAN);
    let mut messages = Vec::new();
    for id in ids {
        let url = format!("https://gmail.googleapis.com/gmail/v1/users/me/messages/{id}");
        let value: Value = checked(
            client
                .get(url)
                .bearer_auth(token.as_str())
                .query(&[("format", "raw")])
                .send(),
        )?
        .json()
        .map_err(|_| "Gmail 返回了无效邮件。".to_owned())?;
        if let Some(message) = gmail_message(&value).filter(|message| message.received_at >= cutoff)
        {
            messages.push(message);
        }
    }
    Ok(EmailAccountScanOutput {
        messages,
        refreshed_credential,
    })
}

fn gmail_query(settings: &EmailOtpSettings, cutoff: u64) -> String {
    let mut query = format!("after:{cutoff}");
    if settings.only_unread_messages {
        query.push_str(" is:unread");
    }
    query
}

fn gmail_message(value: &Value) -> Option<Message> {
    let raw = value.get("raw")?.as_str()?;
    let maximum_encoded_bytes = MAX_MESSAGE_BYTES.saturating_mul(4).div_ceil(3) + 4;
    if raw.len() > maximum_encoded_bytes {
        return None;
    }
    let bytes = decode_base64url(raw)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let parsed = mailparse::parse_mail(&bytes).ok()?;
    let mut text = String::new();
    collect_mail_text(&parsed, &mut text);
    Some(Message {
        id: value.get("id")?.as_str()?.to_owned(),
        sender: parsed.headers.get_first_value("From").unwrap_or_default(),
        subject: parsed
            .headers
            .get_first_value("Subject")
            .unwrap_or_default(),
        text,
        received_at: value
            .get("internalDate")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value / 1000)
            .unwrap_or(0),
    })
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn scan_outlook(
    account: &EmailAccount,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<EmailAccountScanOutput, String> {
    let (token, refreshed_credential) = access_token(account, now)?;
    let client = http_client()?;
    let response: Value = checked(
        client
            .get("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages")
            .bearer_auth(token.as_str())
            .query(&[
                ("$top", MAX_MESSAGES_PER_SCAN.to_string()),
                (
                    "$select",
                    "id,subject,from,receivedDateTime,bodyPreview,isRead".to_owned(),
                ),
                ("$orderby", "receivedDateTime desc".to_owned()),
            ])
            .send(),
    )?
    .json()
    .map_err(|_| "Microsoft Graph 返回了无效响应。".to_owned())?;
    let cutoff = now.saturating_sub(settings.message_lookback_minutes * 60);
    let messages = response
        .get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|value| {
            !settings.only_unread_messages
                || value.get("isRead").and_then(Value::as_bool) == Some(false)
        })
        .filter_map(|value| {
            let received_at = value
                .get("receivedDateTime")
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())?
                .timestamp()
                .max(0) as u64;
            let id = value.get("id")?.as_str()?.to_owned();
            (received_at >= cutoff).then(|| Message {
                id,
                sender: value
                    .pointer("/from/emailAddress/address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                subject: value
                    .get("subject")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                text: value
                    .get("bodyPreview")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                received_at,
            })
        })
        .collect();
    Ok(EmailAccountScanOutput {
        messages,
        refreshed_credential,
    })
}

fn scan_imap(
    account: &EmailAccount,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<Vec<Message>, String> {
    validate_account_transport(account)?;
    if !account.use_tls {
        return scan_plain_imap(account, settings, now);
    }
    let client = imap::ClientBuilder::new(account.imap_host.as_str(), account.imap_port)
        .mode(imap::ConnectionMode::Tls)
        .connect()
        .map_err(|_| "无法建立 IMAP TLS 连接。".to_owned())?;
    let mut session = client
        .login(account.address.as_str(), account.credential.as_str())
        .map_err(|_| "IMAP 认证失败，请检查专用授权码。".to_owned())?;
    let result = read_imap_messages(&mut session, settings, now);
    let _ = session.logout();
    result
}

fn scan_plain_imap(
    account: &EmailAccount,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<Vec<Message>, String> {
    let client = imap::ClientBuilder::new(account.imap_host.as_str(), account.imap_port)
        .mode(imap::ConnectionMode::Plaintext)
        .connect()
        .map_err(|_| "无法建立开发用 IMAP 连接。".to_owned())?;
    let mut session = client
        .login(account.address.as_str(), account.credential.as_str())
        .map_err(|_| "IMAP 认证失败。".to_owned())?;
    let result = read_imap_messages(&mut session, settings, now);
    let _ = session.logout();
    result
}

fn read_imap_messages<T: std::io::Read + Write>(
    session: &mut imap::Session<T>,
    settings: &EmailOtpSettings,
    now: u64,
) -> Result<Vec<Message>, String> {
    session
        .examine("INBOX")
        .map_err(|_| "无法以只读方式打开 IMAP 收件箱。".to_owned())?;
    let query = if settings.only_unread_messages {
        "UNSEEN"
    } else {
        "ALL"
    };
    let ids = session
        .search(query)
        .map_err(|_| "无法搜索 IMAP 收件箱。".to_owned())?;
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort_unstable_by(|left, right| right.cmp(left));
    let sequence = ids
        .iter()
        .take(MAX_MESSAGES_PER_SCAN)
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if sequence.is_empty() {
        return Ok(Vec::new());
    }
    let fetches = session
        .fetch(sequence, "(UID INTERNALDATE BODY.PEEK[])")
        .map_err(|_| "无法读取 IMAP 邮件。".to_owned())?;
    let cutoff = now.saturating_sub(settings.message_lookback_minutes * 60);
    let mut messages = Vec::new();
    for fetch in fetches.iter() {
        let Some(body) = fetch.body().filter(|body| body.len() <= MAX_MESSAGE_BYTES) else {
            continue;
        };
        let Ok(parsed) = mailparse::parse_mail(body) else {
            continue;
        };
        let received_at = fetch
            .internal_date()
            .map(|date| date.timestamp().max(0) as u64)
            .or_else(|| {
                parsed
                    .headers
                    .get_first_value("Date")
                    .and_then(|date| mailparse::dateparse(&date).ok())
                    .map(|date| date.max(0) as u64)
            })
            .unwrap_or(now);
        if received_at < cutoff {
            continue;
        }
        let mut text = String::new();
        collect_mail_text(&parsed, &mut text);
        messages.push(Message {
            id: parsed
                .headers
                .get_first_value("Message-ID")
                .unwrap_or_else(|| format!("uid:{}", fetch.uid.unwrap_or(fetch.message))),
            sender: parsed.headers.get_first_value("From").unwrap_or_default(),
            subject: parsed
                .headers
                .get_first_value("Subject")
                .unwrap_or_default(),
            text,
            received_at,
        });
    }
    Ok(messages)
}

fn collect_mail_text(mail: &mailparse::ParsedMail<'_>, output: &mut String) {
    if output.len() >= MAX_TEXT_BYTES {
        return;
    }
    if mail.subparts.is_empty() {
        if !mail.ctype.mimetype.starts_with("text/")
            || mail.get_content_disposition().disposition == DispositionType::Attachment
        {
            return;
        }
        if let Ok(body) = mail.get_body() {
            append_bounded_text(output, &body);
            if output.len() < MAX_TEXT_BYTES {
                output.push('\n');
            }
        }
    } else {
        for part in &mail.subparts {
            collect_mail_text(part, output);
        }
    }
}

fn append_bounded_text(output: &mut String, value: &str) {
    for character in value.chars() {
        if output.len() + character.len_utf8() > MAX_TEXT_BYTES {
            break;
        }
        output.push(character);
    }
}

fn access_token(
    account: &EmailAccount,
    now: u64,
) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>), String> {
    let mut credential: OAuthCredential = serde_json::from_str(&account.credential)
        .map_err(|_| "OAuth 授权记录已损坏，请重新连接。".to_owned())?;
    let refreshed_credential = if credential.expires_at <= now.saturating_add(60) {
        refresh_token(&account.provider, &mut credential, now)?;
        Some(Zeroizing::new(
            serde_json::to_string(&credential).map_err(|_| "无法更新 OAuth 授权。".to_owned())?,
        ))
    } else {
        None
    };
    Ok((
        Zeroizing::new(credential.access_token.clone()),
        refreshed_credential,
    ))
}

fn update_oauth_credential(
    runtime: &mut DesktopRuntime,
    account: &EmailAccount,
    credential: &str,
) -> Result<(), String> {
    runtime_value(
        runtime,
        "_native.email.update",
        json!({
            "id": account.id,
            "label": account.label,
            "address": account.address,
            "provider": account.provider,
            "authKind": account.auth_kind,
            "credential": credential,
            "imapHost": account.imap_host,
            "imapPort": account.imap_port,
            "useTls": account.use_tls,
            "enabled": account.enabled,
        }),
    )?;
    Ok(())
}

const GMAIL_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

fn authorize(provider: &str, now: u64) -> Result<(OAuthCredential, String), String> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "无法启动 OAuth 本地回调。".to_owned())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "无法启动 OAuth 本地回调。".to_owned())?;
    let redirect = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .map_err(|_| "无法读取 OAuth 回调地址。")?
            .port()
    );
    let state = random_urlsafe(32);
    let verifier = Zeroizing::new(random_urlsafe(48));
    let challenge = pkce_challenge(verifier.as_str());
    let (client_id, auth_endpoint, scopes) = if provider == "gmail" {
        (
            required_env("VAULTMESH_GOOGLE_OAUTH_CLIENT_ID")?,
            "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            GMAIL_READONLY_SCOPE,
        )
    } else {
        (
            required_env("VAULTMESH_MICROSOFT_OAUTH_CLIENT_ID")?,
            microsoft_endpoint("authorize")?,
            "openid email offline_access Mail.Read",
        )
    };
    let mut url = Url::parse(&auth_endpoint).map_err(|_| "OAuth 地址无效。".to_owned())?;
    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", scopes)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");
    open::that_detached(url.as_str()).map_err(|_| "无法打开系统浏览器完成 OAuth。".to_owned())?;
    let callback = wait_for_callback(&listener)?;
    let code = Zeroizing::new(oauth_callback_code(&callback, &state)?);
    let mut token = exchange_code(
        provider,
        &client_id,
        &redirect,
        verifier.as_str(),
        code.as_str(),
    )?;
    if provider == "gmail" && !gmail_readonly_granted(&token.scope) {
        return Err(
            "未授予 Gmail 阅读权限，请重新连接并允许查看您的电子邮件及设置。".to_owned(),
        );
    }
    let credential = OAuthCredential {
        access_token: std::mem::take(&mut token.access_token),
        refresh_token: token.refresh_token.take(),
        expires_at: now.saturating_add(token.expires_in),
        token_type: std::mem::take(&mut token.token_type),
    };
    let address = oauth_address(provider, &credential.access_token)?;
    Ok((credential, address))
}

fn gmail_readonly_granted(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|granted| granted == GMAIL_READONLY_SCOPE)
}

fn wait_for_callback(listener: &TcpListener) -> Result<String, String> {
    let started = Instant::now();
    while let Some(remaining) = OAUTH_CALLBACK_TIMEOUT.checked_sub(started.elapsed()) {
        match crate::socket_wait::wait_for_connection(listener, remaining.min(Duration::from_secs(1))) {
            Ok(crate::socket_wait::Readiness::Ready) => {}
            Ok(_) => continue,
            Err(_) => return Err("OAuth 回调失败。".to_owned()),
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|_| "OAuth 回调超时。".to_owned())?;
                let mut request = Zeroizing::new(vec![0_u8; 16 * 1024]);
                let size = std::io::Read::read(&mut stream, &mut request)
                    .map_err(|_| "OAuth 回调读取失败。".to_owned())?;
                let first = String::from_utf8_lossy(&request[..size]);
                let target = first
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .filter(|target| target.starts_with('/') && target.len() < 8_192)
                    .ok_or_else(|| "OAuth 回调无效。".to_owned())?;
                let body = b"VaultMesh authorization complete. You may close this window.";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                return Ok(format!("http://127.0.0.1{target}"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("OAuth 回调失败。".to_owned()),
        }
    }
    Err("OAuth 授权已超时或取消。".to_owned())
}

fn exchange_code(
    provider: &str,
    client_id: &str,
    redirect: &str,
    verifier: &str,
    code: &str,
) -> Result<TokenResponse, String> {
    let endpoint = if provider == "gmail" {
        "https://oauth2.googleapis.com/token".to_owned()
    } else {
        microsoft_endpoint("token")?
    };
    let mut form = vec![
        ("client_id", client_id.to_owned()),
        ("redirect_uri", redirect.to_owned()),
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("code_verifier", verifier.to_owned()),
    ];
    if provider == "gmail"
        && let Some(secret) = configured_value("VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET")
    {
        form.push(("client_secret", secret));
    }
    let response = http_client()?.post(endpoint).form(&form).send();
    zeroize_form(&mut form);
    checked_oauth(response, provider, OAuthPhase::Exchange)?
        .json()
        .map_err(|_| "OAuth Token 响应无效。".to_owned())
}

fn refresh_token(provider: &str, credential: &mut OAuthCredential, now: u64) -> Result<(), String> {
    let refresh = credential
        .refresh_token
        .as_deref()
        .ok_or_else(|| "OAuth 授权已过期，请重新连接。".to_owned())?;
    let client_id = if provider == "gmail" {
        required_env("VAULTMESH_GOOGLE_OAUTH_CLIENT_ID")?
    } else {
        required_env("VAULTMESH_MICROSOFT_OAUTH_CLIENT_ID")?
    };
    let endpoint = if provider == "gmail" {
        "https://oauth2.googleapis.com/token".to_owned()
    } else {
        microsoft_endpoint("token")?
    };
    let mut form = vec![
        ("client_id", client_id),
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh.to_owned()),
    ];
    if provider == "gmail"
        && let Some(secret) = configured_value("VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET")
    {
        form.push(("client_secret", secret));
    }
    let response = http_client()?.post(endpoint).form(&form).send();
    zeroize_form(&mut form);
    let mut token: TokenResponse = checked_oauth(response, provider, OAuthPhase::Refresh)?
        .json()
        .map_err(|_| "OAuth 刷新响应无效。".to_owned())?;
    credential.access_token.zeroize();
    credential.access_token = std::mem::take(&mut token.access_token);
    if token.refresh_token.is_some() {
        credential.refresh_token = token.refresh_token.take();
    }
    credential.expires_at = now.saturating_add(token.expires_in);
    credential.token_type = std::mem::take(&mut token.token_type);
    Ok(())
}

fn oauth_address(provider: &str, access_token: &str) -> Result<String, String> {
    let client = http_client()?;
    let value: Value = if provider == "gmail" {
        checked(
            client
                .get("https://gmail.googleapis.com/gmail/v1/users/me/profile")
                .bearer_auth(access_token)
                .send(),
        )?
        .json()
        .map_err(|_| "Gmail 账户信息无效。".to_owned())?
    } else {
        checked(
            client
                .get("https://graph.microsoft.com/v1.0/me")
                .bearer_auth(access_token)
                .query(&[("$select", "mail,userPrincipalName")])
                .send(),
        )?
        .json()
        .map_err(|_| "Microsoft 账户信息无效。".to_owned())?
    };
    provider_address(provider, &value)
}

fn provider_address(provider: &str, value: &Value) -> Result<String, String> {
    let address = if provider == "gmail" {
        value.get("emailAddress")
    } else {
        value
            .get("mail")
            .or_else(|| value.get("userPrincipalName"))
    };
    address
        .and_then(Value::as_str)
        .filter(|value| value.contains('@') && value.len() <= 320)
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Provider 未返回可用邮箱地址。".to_owned())
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("VaultMesh/0.1 email-otp")
        .build()
        .map_err(|_| "无法初始化邮箱网络客户端。".to_owned())
}

fn checked(
    response: Result<reqwest::blocking::Response, reqwest::Error>,
) -> Result<reqwest::blocking::Response, String> {
    let response = response.map_err(|_| "邮箱 Provider 网络请求失败。".to_owned())?;
    if response.status().is_success() {
        Ok(response)
    } else if response.status().as_u16() == 401 {
        Err("邮箱授权已失效，请重新连接。".to_owned())
    } else {
        Err(format!(
            "邮箱 Provider 返回错误（HTTP {}）。",
            response.status().as_u16()
        ))
    }
}

#[derive(Clone, Copy)]
enum OAuthPhase {
    Exchange,
    Refresh,
}

fn checked_oauth(
    response: Result<reqwest::blocking::Response, reqwest::Error>,
    provider: &str,
    phase: OAuthPhase,
) -> Result<reqwest::blocking::Response, String> {
    let response = response.map_err(|_| "邮箱 Provider 网络请求失败。".to_owned())?;
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let mut body = Zeroizing::new(Vec::with_capacity(16 * 1024 + 1));
    let mut limited = std::io::Read::take(response, 16 * 1024 + 1);
    let error_code = std::io::Read::read_to_end(&mut limited, &mut body)
        .ok()
        .filter(|_| body.len() <= 16 * 1024)
        .and_then(|_| serde_json::from_slice::<Value>(&body).ok())
        .and_then(|value| value.get("error").and_then(Value::as_str).map(ToOwned::to_owned));
    Err(oauth_error_message(provider, phase, status, error_code.as_deref()))
}

fn oauth_error_message(
    provider: &str,
    phase: OAuthPhase,
    status: u16,
    error_code: Option<&str>,
) -> String {
    let provider_name = if provider == "gmail" {
        "Google"
    } else {
        "Microsoft"
    };
    match (phase, status, error_code) {
        (OAuthPhase::Exchange, 400, Some("invalid_request" | "invalid_client")) => format!(
            "{provider_name} OAuth 构建凭据配置无效；请安装包含正确 Desktop OAuth 凭据的版本。"
        ),
        (OAuthPhase::Exchange, 400, Some("invalid_grant")) => {
            "OAuth 授权码校验失败，请重新发起授权。".to_owned()
        }
        (OAuthPhase::Refresh, 400, Some("invalid_grant")) => {
            "邮箱 OAuth 授权已失效，请删除账户后重新连接。".to_owned()
        }
        (_, 401, _) => "邮箱授权已失效，请重新连接。".to_owned(),
        _ => format!("邮箱 Provider 返回错误（HTTP {status}）。"),
    }
}

fn zeroize_form(form: &mut [(&str, String)]) {
    for (_, value) in form {
        value.zeroize();
    }
}

fn extract_codes(text: &str) -> Vec<String> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    static BEFORE_CONTEXT: OnceLock<Regex> = OnceLock::new();
    static AFTER_CONTEXT: OnceLock<Regex> = OnceLock::new();
    static SEMANTIC_CONTEXT: OnceLock<Regex> = OnceLock::new();
    const CONTEXT: &str = r"(?:
        验证码|动态码|校验码|登录码|登录代码|认证码|安全码|一次性密码|一次性代码|
        您的?代码|代码(?:\s*(?:是|为|[:：-]))|
        verification(?:\s+code)?|security\s+code|passcode|
        one[-\s]?time(?:\s+(?:password|code))?|otp|
        your(?:\s+(?:sign[-\s]?in|login|authentication|confirmation|access))?\s+code|
        (?:sign[-\s]?in|login|authentication|confirmation|access)\s+code|
        (?:enter|use)\s+(?:the\s+)?code|code(?:\s+is|\s*[:\-])
    )";
    let blocks = normalize_message_blocks(text);
    let token = TOKEN.get_or_init(|| Regex::new(r"(?i)[a-z0-9]{4,8}").expect("fixed regex"));
    let before_context = BEFORE_CONTEXT.get_or_init(|| {
        Regex::new(&format!(
            r"(?ix)
            {CONTEXT}
            [^a-z0-9]{{0,64}}$"
        ))
        .expect("fixed regex")
    });
    let after_context = AFTER_CONTEXT.get_or_init(|| {
        Regex::new(&format!(
            r"(?ix)^
            (?:
                \s+(?:is\s+)?
                |
                \s*(?:是|为)\s*(?:您的?)?\s*
                |
                [\s:：,，-]+
            )
            {CONTEXT}"
        ))
        .expect("fixed regex")
    });
    let semantic_context = SEMANTIC_CONTEXT
        .get_or_init(|| Regex::new(&format!(r"(?ix){CONTEXT}")).expect("fixed regex"));
    let mut values = Vec::new();
    let flattened = blocks.join(" ");
    let flattened_bytes = flattened.as_bytes();
    for candidate in token.find_iter(&flattened) {
        let value = candidate.as_str();
        let has_complete_boundary = (candidate.start() == 0
            || !flattened_bytes[candidate.start() - 1].is_ascii_alphanumeric())
            && (candidate.end() == flattened_bytes.len()
                || !flattened_bytes[candidate.end()].is_ascii_alphanumeric());
        if has_complete_boundary
            && value.bytes().any(|byte| byte.is_ascii_digit())
            && (before_context.is_match(&flattened[..candidate.start()])
                || after_context.is_match(&flattened[candidate.end()..]))
        {
            values.push(value.to_owned());
        }
    }
    for (block_index, block) in blocks.iter().enumerate() {
        let bytes = block.as_bytes();
        for candidate in token.find_iter(block) {
            let value = candidate.as_str();
            let has_complete_boundary = (candidate.start() == 0
                || !bytes[candidate.start() - 1].is_ascii_alphanumeric())
                && (candidate.end() == bytes.len()
                    || !bytes[candidate.end()].is_ascii_alphanumeric());
            let is_standalone = block[..candidate.start()]
                .chars()
                .chain(block[candidate.end()..].chars())
                .all(|character| !character.is_alphanumeric());
            let previous_block = block_index
                .checked_sub(1)
                .and_then(|index| blocks.get(index));
            let next_block = block_index
                .checked_add(1)
                .and_then(|index| blocks.get(index));
            let has_adjacent_context = is_standalone
                && previous_block
                    .into_iter()
                    .chain(next_block)
                    .any(|neighbor| semantic_context.is_match(neighbor));
            if !has_complete_boundary
                || !value.bytes().any(|byte| byte.is_ascii_digit())
                || !has_adjacent_context
            {
                continue;
            }
            values.push(value.to_owned());
        }
    }
    values.sort();
    values.dedup();
    values.truncate(10);
    values
}

fn normalize_message_blocks(text: &str) -> Vec<String> {
    static NON_CONTENT: OnceLock<Regex> = OnceLock::new();
    static HTML_TAG: OnceLock<Regex> = OnceLock::new();
    static NUMERIC_ENTITY: OnceLock<Regex> = OnceLock::new();
    let without_non_content = NON_CONTENT
        .get_or_init(|| {
            Regex::new(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>")
                .expect("fixed regex")
        })
        .replace_all(text, " ");
    let without_tags = HTML_TAG
        .get_or_init(|| Regex::new(r"(?s)<[^>]{0,4096}>").expect("fixed regex"))
        .replace_all(&without_non_content, "\n");
    let decoded = NUMERIC_ENTITY
        .get_or_init(|| {
            Regex::new(r"&#(?:[xX]([0-9a-fA-F]{1,6})|([0-9]{1,7}));").expect("fixed regex")
        })
        .replace_all(&without_tags, |capture: &regex::Captures<'_>| {
            let value = capture
                .get(1)
                .and_then(|value| u32::from_str_radix(value.as_str(), 16).ok())
                .or_else(|| {
                    capture
                        .get(2)
                        .and_then(|value| value.as_str().parse::<u32>().ok())
                });
            value
                .and_then(char::from_u32)
                .map(|value| value.to_string())
                .unwrap_or_else(|| capture[0].to_owned())
        });
    decoded
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .lines()
        .filter_map(|line| {
            let block = line.split_whitespace().collect::<Vec<_>>().join(" ");
            (!block.is_empty()).then_some(block)
        })
        .collect()
}

fn validate_transport_policy(input: &Value) -> Result<(), String> {
    let use_tls = input
        .get("useTls")
        .and_then(Value::as_bool)
        .ok_or_else(|| "邮箱账户参数无效。".to_owned())?;
    let host = input
        .get("imapHost")
        .and_then(Value::as_str)
        .ok_or_else(|| "邮箱账户参数无效。".to_owned())?;
    let provider = input
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| "邮箱账户参数无效。".to_owned())?;
    let auth_kind = input
        .get("authKind")
        .and_then(Value::as_str)
        .ok_or_else(|| "邮箱账户参数无效。".to_owned())?;
    if matches!(provider, "gmail" | "outlook") != (auth_kind == "oauth") {
        return Err("邮箱 Provider 与授权方式不匹配。".to_owned());
    }
    if !use_tls && !is_local_or_private(host) {
        return Err("公网 IMAP 必须启用 TLS。".to_owned());
    }
    Ok(())
}

fn validate_account_transport(account: &EmailAccount) -> Result<(), String> {
    if !account.use_tls && !is_local_or_private(&account.imap_host) {
        Err("公网 IMAP 必须启用 TLS。".to_owned())
    } else {
        Ok(())
    }
}

fn is_local_or_private(host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".local") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(address) => address.is_private() || address.is_loopback(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_loopback(),
    })
}

fn random_urlsafe(size: usize) -> String {
    let mut bytes = vec![0_u8; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn oauth_callback_code(callback: &str, expected_state: &str) -> Result<String, String> {
    let callback = Url::parse(callback).map_err(|_| "OAuth 回调无效。".to_owned())?;
    let parameters = callback.query_pairs().collect::<HashMap<_, _>>();
    if parameters.get("state").map(|value| value.as_ref()) != Some(expected_state) {
        return Err("OAuth state 校验失败。".to_owned());
    }
    if let Some(error) = parameters.get("error") {
        return Err(format!("OAuth 授权未完成：{error}"));
    }
    parameters
        .get("code")
        .map(|value| value.to_string())
        .ok_or_else(|| "OAuth 回调没有授权码。".to_owned())
}

fn uuid_field(input: &Value, key: &str) -> Result<Uuid, String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| "请求参数无效。".to_owned())
}

fn configured_env(key: &str) -> bool {
    configured_value(key).is_some()
}

fn required_env(key: &str) -> Result<String, String> {
    configured_value(key).ok_or_else(|| format!("{key} 尚未配置。"))
}

fn configured_value(key: &str) -> Option<String> {
    let runtime = std::env::var(key).ok();
    let built_in = match key {
        "VAULTMESH_GOOGLE_OAUTH_CLIENT_ID" => option_env!("VAULTMESH_GOOGLE_OAUTH_CLIENT_ID"),
        "VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET" => {
            option_env!("VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET")
        }
        "VAULTMESH_MICROSOFT_OAUTH_CLIENT_ID" => {
            option_env!("VAULTMESH_MICROSOFT_OAUTH_CLIENT_ID")
        }
        "VAULTMESH_MICROSOFT_OAUTH_TENANT" => option_env!("VAULTMESH_MICROSOFT_OAUTH_TENANT"),
        _ => None,
    };
    runtime
        .or_else(|| built_in.map(ToOwned::to_owned))
        .filter(|value| !value.trim().is_empty())
}

fn microsoft_endpoint(action: &str) -> Result<String, String> {
    let tenant =
        configured_value("VAULTMESH_MICROSOFT_OAUTH_TENANT").unwrap_or_else(|| "common".to_owned());
    let tenant_valid = matches!(tenant.as_str(), "common" | "organizations" | "consumers")
        || Uuid::parse_str(&tenant).is_ok();
    if !tenant_valid || !matches!(action, "authorize" | "token") {
        return Err("Microsoft OAuth Tenant 配置无效。".to_owned());
    }
    Ok(format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{action}"
    ))
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn load_settings(path: &Path) -> EmailOtpSettings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<EmailOtpSettings>(&bytes).ok())
        .filter(EmailOtpSettings::validate)
        .unwrap_or_default()
}

fn persist_settings(path: &Path, settings: &EmailOtpSettings) -> Result<(), String> {
    let bytes = serde_json::to_vec(settings).map_err(|_| "无法保存邮箱读取设置。".to_owned())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "无法保存邮箱读取设置。".to_owned())?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes).map_err(|_| "无法保存邮箱读取设置。".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "无法保存邮箱读取设置。".to_owned())?;
    }
    std::fs::rename(temporary, path).map_err(|_| "无法保存邮箱读取设置。".to_owned())
}

#[cfg(test)]
#[path = "email_otp_tests.rs"]
mod tests;
