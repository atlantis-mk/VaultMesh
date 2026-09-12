use super::*;
use std::fs;

const NOW: i64 = 1_800_000_000_000;
const PASSWORD: &str = "browser lifecycle test password";

#[test]
fn native_managed_assignments_use_real_core_reprompt_and_replay_checks() {
    let (root, _path, mut broker, secret) = setup("native-managed-plans");
    assert_eq!(call(&mut broker, &secret, "vault.unlock", json!({"masterPassword":PASSWORD,"userGestureId":Uuid::new_v4()}), Uuid::new_v4())["ok"], true);
    let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).expect("synthetic key");
    let public_key = key.public_key().to_openssh().expect("synthetic public encoding");
    let private_key = key.to_openssh(ssh_key::LineEnding::LF).expect("synthetic private encoding");
    let key_item = json!({"title":"Synthetic SSH Key","recordKind":"key","host":null,"port":22,"username":"","password":null,"publicKey":public_key,"privateKey":private_key.as_str(),"keyPassphrase":null,"notes":null,"folder":null,"favorite":false,"masterPasswordReprompt":true});
    for (kind, operation, item, source, expected) in [
        ("card", "cards.add", json!({"title":"Synthetic Card","cardholderName":"Synthetic","cardNumber":"4111111111111111","expirationMonth":9,"expirationYear":2031,"securityCode":"123","pin":null,"notes":null,"folder":null,"favorite":false,"issuer":null,"network":"Visa","billingAddress":null,"masterPasswordReprompt":false}), "card:number", "4111111111111111"),
        ("identity", "identities.add", json!({"title":"Synthetic Identity","firstName":"Synthetic","middleName":null,"lastName":"Name","birthDate":null,"organization":null,"department":null,"jobTitle":null,"website":null,"notes":null,"folder":null,"favorite":false,"emails":[],"phones":[],"addresses":[]}), "identity:fullName", "Synthetic Name"),
        ("ssh", "ssh.add", json!({"title":"Synthetic SSH","recordKind":"account","host":"example.test","port":22,"username":"synthetic","password":"synthetic-ssh-password","publicKey":null,"privateKey":null,"keyPassphrase":null,"notes":null,"folder":null,"favorite":false,"masterPasswordReprompt":true}), "ssh:password", "synthetic-ssh-password"),
        ("ssh", "ssh.add", key_item.clone(), "ssh:publicKey", public_key.as_str()),
        ("ssh", "ssh.add", key_item.clone(), "ssh:privateKey", private_key.as_str()),
        ("secret", "secrets.add", json!({"title":"Synthetic API key","kind":"api-key","secret":"synthetic-api-key","provider":null,"account":null,"environment":null,"scopes":["read"],"expiresAt":null,"website":"https://example.com","notes":null,"folder":null,"favorite":false,"masterPasswordReprompt":true}), "secret:api-key", "synthetic-api-key"),
        ("secret", "secrets.add", json!({"title":"Synthetic protected Passkey record","kind":"authenticator-key","secret":"synthetic-internal-record","provider":null,"account":null,"environment":null,"scopes":["vaultmesh:passkey:v1"],"expiresAt":null,"website":"https://example.com","notes":null,"folder":null,"favorite":false,"masterPasswordReprompt":false}), "secret:authenticator-key", "")
    ] {
        let mut add = item; add["userGestureId"] = json!(Uuid::new_v4());
        let added = call(&mut broker, &secret, operation, add, Uuid::new_v4());
        assert_eq!(added["ok"], true, "{operation}: {}", added.get("error").unwrap_or(&Value::Null));
        let handle = Uuid::new_v4();
        let mut input = json!({"mode":"selection","userGestureId":Uuid::new_v4(),"nativeItemPlan":[{"handle":handle,"source":source}],
            "discovery":{"version":1,"requestId":Uuid::new_v4(),"issuedAt":"2027-01-15T08:00:00.000Z","expiresAt":"2027-01-15T08:00:30.000Z",
                "tabId":1,"topOrigin":"https://example.com","targetOrigin":"https://example.com","targetPageUrl":"https://example.com/checkout",
                "selectedItem":{"kind":kind,"id":added["result"]["id"],"title":"Synthetic"},
                "frames":[{"frameId":0,"documentId":Uuid::new_v4(),"frameOrigin":"https://example.com","fields":[{"handle":handle,"control":"input","inputType":"text","isEmpty":true,"autocomplete":[],"name":"","id":"","label":"","placeholder":"","context":"unknown"}]}]}});
        if expected.is_empty() {
            assert_eq!(added["result"]["isPasskey"], true);
            assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input, Uuid::new_v4())["ok"], false);
            let candidates = call(&mut broker, &secret, "browser.autofill.candidates",
                json!({"topOrigin":"https://example.com","pageUrl":"https://example.com","fieldKind":"secret","pageContext":"developer-secret"}), Uuid::new_v4());
            assert_eq!(candidates["ok"], true);
            assert!(candidates["result"]["candidates"].as_array().unwrap().iter().all(|candidate| candidate["id"] != added["result"]["id"]));
            continue;
        }
        if kind != "identity" {
            assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input.clone(), Uuid::new_v4())["error"]["code"], "re-prompt-required");
            input["discovery"]["requestId"] = json!(Uuid::new_v4()); input["masterPassword"] = json!("wrong-synthetic-password");
            assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input.clone(), Uuid::new_v4())["ok"], false);
            input["discovery"]["requestId"] = json!(Uuid::new_v4()); input["masterPassword"] = json!(PASSWORD);
        }
        let response = call(&mut broker, &secret, "browser.autofill.execute", input.clone(), Uuid::new_v4());
        assert_eq!(response["ok"], true);
        assert!(response["result"]["frames"][0]["assignments"] == json!([{"handle":handle,"value":expected,"overwrite":false}]), "exact single-source assignment");
        if kind == "secret" {
            let mut wrong_kind = input.clone(); wrong_kind["discovery"]["requestId"] = json!(Uuid::new_v4());
            wrong_kind["nativeItemPlan"][0]["source"] = json!("secret:client-secret");
            let response = call(&mut broker, &secret, "browser.autofill.execute", wrong_kind, Uuid::new_v4());
            assert_eq!(response["ok"], false); // no assignment for a different Secret subtype
        }
        assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input, Uuid::new_v4())["ok"], false);
    }
    drop(broker); fs::remove_dir_all(root).expect("cleanup synthetic vault");
}

#[test]
fn parallel_browser_identities_have_independent_authentication_and_unlock_owners() {
    let (root, path, mut existing, existing_secret) = setup("parallel-identities");
    let dev_secret = [0x6b; 32];
    let mut development = BrowserBrokerCore::new(path, Zeroizing::new(dev_secret)).unwrap();
    let unlock = || json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() });
    assert_eq!(call(&mut existing, &existing_secret, "vault.unlock", unlock(), Uuid::new_v4())["ok"], true);
    assert_eq!(call(&mut development, &dev_secret, "items.list", json!({}), Uuid::new_v4())["error"]["code"], "unlock-required");
    assert_eq!(call(&mut development, &existing_secret, "vault.unlock", unlock(), Uuid::new_v4())["status"], "unpaired");
    assert_eq!(call(&mut existing, &dev_secret, "items.list", json!({}), Uuid::new_v4())["status"], "unpaired");
    assert_eq!(call(&mut development, &dev_secret, "vault.unlock", unlock(), Uuid::new_v4())["ok"], true);
    existing.lock_for_system();
    assert_eq!(call(&mut development, &dev_secret, "items.list", json!({}), Uuid::new_v4())["ok"], true);
    development.lock_for_system();
    assert_eq!(call(&mut development, &dev_secret, "items.list", json!({}), Uuid::new_v4())["error"]["code"], "unlock-required");
    drop(development); drop(existing);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn authorization_fast_check_matches_status_without_constructing_item_summaries() {
    let (root, _path, mut broker, secret) = setup("authorization-fast-check");
    assert!(!broker.runtime.is_unlocked());
    assert_eq!(broker.runtime.is_unlocked(), broker.runtime.status().unlocked);
    assert_eq!(call(&mut broker, &secret, "vault.unlock", json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }), Uuid::new_v4())["ok"], true);
    assert!(broker.runtime.is_unlocked());
    assert_eq!(broker.runtime.is_unlocked(), broker.runtime.status().unlocked);
    broker.lock_for_system();
    assert!(!broker.runtime.is_unlocked());
    assert_eq!(call(&mut broker, &secret, "items.list", json!({}), Uuid::new_v4())["error"]["code"], "unlock-required");
    drop(broker);
    fs::remove_dir_all(root).expect("cleanup synthetic vault");
}

#[test]
fn native_login_plan_uses_authenticated_execute_and_one_use_assignments() {
    let (root, _path, mut broker, secret) = setup("native-login-plan");
    assert_eq!(call(&mut broker, &secret, "vault.unlock", json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }), Uuid::new_v4())["ok"], true);
    let items = call(&mut broker, &secret, "items.list", json!({}), Uuid::new_v4());
    let handle = Uuid::new_v4();
    let input = json!({
        "mode": "selection", "userGestureId": Uuid::new_v4(),
        "nativeLoginPlan": [{ "handle": handle, "source": "password" }],
        "discovery": {
            "version": 1, "requestId": Uuid::new_v4(), "issuedAt": "2027-01-15T08:00:00.000Z", "expiresAt": "2027-01-15T08:00:30.000Z",
            "tabId": 4, "topOrigin": "https://example.com", "targetOrigin": "https://example.com", "targetPageUrl": "https://example.com/login",
            "selectedItem": { "kind": "login", "id": items["result"][0]["id"], "title": "Example" },
            "frames": [{ "frameId": 0, "documentId": Uuid::new_v4(), "frameOrigin": "https://example.com", "fields": [{
                "handle": handle, "control": "input", "inputType": "password", "isEmpty": true, "autocomplete": [],
                "label": "", "name": "", "id": "", "placeholder": "", "context": "unknown"
            }] }]
        }
    });
    let result = call(&mut broker, &secret, "browser.autofill.execute", input.clone(), Uuid::new_v4());
    assert_eq!(result["ok"], true);
    assert_eq!(result["result"]["frames"][0]["assignments"], json!([{ "handle": handle, "value": "secret", "overwrite": false }]));
    assert_eq!(result["result"]["frames"][0]["documentId"], input["discovery"]["frames"][0]["documentId"]);
    assert!(result["result"].get("password").is_none());
    assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input.clone(), Uuid::new_v4())["ok"], false);
    let updated = call(&mut broker, &secret, "items.update", json!({
        "id": items["result"][0]["id"], "title": "Example", "username": "alice", "password": null,
        "url": "https://example.com", "notes": null, "folder": null, "favorite": false,
        "additionalUrls": [], "autofillOnPageLoad": false, "masterPasswordReprompt": true,
        "customFields": [{ "label": "tenant", "value": "synthetic-custom" }], "totpSecret": null, "clearTotpSecret": false,
        "recoveryCodes": null, "clearRecoveryCodes": false, "userGestureId": Uuid::new_v4(),
    }), Uuid::new_v4());
    assert_eq!(updated["ok"], true);
    let profile = call(&mut broker, &secret, "browser.autofill.profile", json!({ "id": items["result"][0]["id"] }), Uuid::new_v4());
    assert_eq!(profile["ok"], true);
    assert_eq!(profile["result"], json!({ "id": items["result"][0]["id"], "customFields": [{ "index": 0, "name": "tenant" }] }));
    assert!(!profile.to_string().contains("synthetic-custom"));
    let mut reprompt = input.clone();
    reprompt["discovery"]["requestId"] = json!(Uuid::new_v4());
    assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", reprompt.clone(), Uuid::new_v4())["error"]["code"], "re-prompt-required");
    reprompt["discovery"]["requestId"] = json!(Uuid::new_v4());
    reprompt["masterPassword"] = json!(PASSWORD);
    assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", reprompt, Uuid::new_v4())["ok"], true);
    call(&mut broker, &secret, "vault.lock", json!({ "userGestureId": Uuid::new_v4() }), Uuid::new_v4());
    assert_eq!(call(&mut broker, &secret, "browser.autofill.execute", input, Uuid::new_v4())["error"]["code"], "unlock-required");
    assert_eq!(call(&mut broker, &secret, "browser.autofill.profile", json!({ "id": items["result"][0]["id"] }), Uuid::new_v4())["error"]["code"], "unlock-required");
    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

fn setup(name: &str) -> (PathBuf, PathBuf, BrowserBrokerCore, [u8; 32]) {
    let root =
        std::env::temp_dir().join(format!("vaultmesh-tauri-browser-{name}-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("test root");
    let path = root.join("browser.vault");
    let mut creator = DesktopRuntime::new(path.clone()).expect("creator");
    creator.create(PASSWORD.into()).expect("create vault");
    creator
        .execute(
            "items.add",
            json!({
                "title": "Example", "username": "alice", "password": "secret",
                "url": "https://example.com", "notes": null
            }),
        )
        .expect("seed login");
    creator.lock();
    drop(creator);
    let secret = [0x5a; 32];
    let broker = BrowserBrokerCore::new(path.clone(), Zeroizing::new(secret)).expect("broker");
    (root, path, broker, secret)
}

fn request(operation: &str, input: Value, request_id: Uuid) -> Value {
    json!({
        "kind": "vaultmesh.rpc", "version": RPC_VERSION, "requestId": request_id,
        "issuedAt": "2027-01-15T08:00:00.000Z", "expiresAt": "2027-01-15T08:01:00.000Z",
        "operation": operation, "input": input
    })
}

fn envelope(message: &Value, secret: &[u8; 32]) -> Vec<u8> {
    let request_id = message["requestId"].as_str().expect("request id");
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(message).expect("message"));
    let body = serde_json::to_vec(&AuthenticatedBody {
        request_id,
        payload: &payload,
    })
    .expect("body");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(&body);
    serde_json::to_vec(&json!({
            "requestId": request_id, "auth": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()), "payload": payload
        })).expect("envelope")
}

fn call(
    broker: &mut BrowserBrokerCore,
    secret: &[u8; 32],
    operation: &str,
    input: Value,
    request_id: Uuid,
) -> Value {
    broker.handle_line_at(
        &envelope(&request(operation, input, request_id), secret),
        NOW,
    )
}

#[test]
fn authenticated_browser_unlock_and_lock_are_independent_from_desktop() {
    let (root, path, mut broker, secret) = setup("lifecycle");
    let mut desktop = DesktopRuntime::new(path).expect("desktop");
    desktop.unlock(PASSWORD.into()).expect("desktop unlock");
    let status = call(
        &mut broker,
        &secret,
        "vault.status",
        json!({}),
        Uuid::new_v4(),
    );
    assert_eq!(status["result"]["unlocked"], false);
    assert!(desktop.status().unlocked);
    let unlocked = call(
        &mut broker,
        &secret,
        "vault.unlock",
        json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked["result"]["status"]["unlocked"], true);
    let locked = call(
        &mut broker,
        &secret,
        "vault.lock",
        json!({ "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(locked["result"]["unlocked"], false);
    assert!(desktop.status().unlocked);
    let events = call(
        &mut broker,
        &secret,
        "events.poll",
        json!({ "after": 0 }),
        Uuid::new_v4(),
    );
    assert_eq!(events["result"]["events"][0]["type"], "vault-locked");
    desktop.lock();
    drop(desktop);
    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn authentication_gesture_expiry_replay_and_version_fail_closed() {
    let (root, _path, mut broker, secret) = setup("boundaries");
    let request_id = Uuid::new_v4();
    let status_request = request("vault.status", json!({}), request_id);
    let valid = envelope(&status_request, &secret);
    let mut wrong_secret = secret;
    wrong_secret[0] ^= 0xff;
    assert_eq!(
        broker.handle_line_at(&envelope(&status_request, &wrong_secret), NOW)["status"],
        "unpaired"
    );
    assert_eq!(broker.handle_line_at(&valid, NOW)["ok"], true);
    assert_eq!(
        broker.handle_line_at(&valid, NOW)["error"]["code"],
        "request-replayed"
    );
    let no_gesture = call(
        &mut broker,
        &secret,
        "vault.unlock",
        json!({ "masterPassword": PASSWORD }),
        Uuid::new_v4(),
    );
    assert_eq!(no_gesture["error"]["code"], "invalid-request");
    let expired = envelope(&request("vault.status", json!({}), Uuid::new_v4()), &secret);
    assert_eq!(
        broker.handle_line_at(&expired, NOW + 61_000)["error"]["code"],
        "request-expired"
    );
    let mut wrong_version = request("vault.status", json!({}), Uuid::new_v4());
    wrong_version["version"] = json!(99);
    assert_eq!(
        broker.handle_line_at(&envelope(&wrong_version, &secret), NOW)["error"]["code"],
        "update-required"
    );
    let locked_read = call(
        &mut broker,
        &secret,
        "items.list",
        json!({}),
        Uuid::new_v4(),
    );
    assert_eq!(locked_read["error"]["code"], "unlock-required");
    let unsupported = call(
        &mut broker,
        &secret,
        "future.route",
        json!({}),
        Uuid::new_v4(),
    );
    assert_eq!(unsupported["error"]["code"], "unsupported-operation");
    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn unlocked_browser_reads_workspace_lists_and_gesture_bounded_login_detail() {
    let (root, _path, mut broker, secret) = setup("readonly");
    let unlocked = call(
        &mut broker,
        &secret,
        "vault.unlock",
        json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked["ok"], true);

    let workspace = call(
        &mut broker,
        &secret,
        "vault.workspace",
        json!({}),
        Uuid::new_v4(),
    );
    assert_eq!(workspace["result"]["status"]["unlocked"], true);
    assert_eq!(
        workspace["result"]["items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(workspace["result"]["items"][0]["hasPassword"], true);
    assert!(workspace["result"]["items"][0].get("password").is_none());
    assert_eq!(
        workspace["result"]["cards"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        workspace["result"]["identities"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        workspace["result"]["sshCredentials"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        workspace["result"]["secrets"].as_array().map(Vec::len),
        Some(0)
    );

    for operation in [
        "items.list",
        "cards.list",
        "identities.list",
        "ssh.list",
        "secrets.list",
    ] {
        let response = call(&mut broker, &secret, operation, json!({}), Uuid::new_v4());
        assert_eq!(response["ok"], true, "{operation}");
    }
    let health = call(
        &mut broker,
        &secret,
        "password.health",
        json!({}),
        Uuid::new_v4(),
    );
    assert!(health["result"]["score"].is_u64());

    let item_id = workspace["result"]["items"][0]["id"]
        .as_str()
        .expect("login id");
    let candidates = call(
        &mut broker,
        &secret,
        "browser.autofill.candidates",
        json!({
            "topOrigin": "https://example.com",
            "pageUrl": "https://example.com/login",
            "fieldKind": "login",
            "pageContext": "login"
        }),
        Uuid::new_v4(),
    );
    assert_eq!(candidates["ok"], true);
    assert_eq!(candidates["result"]["candidates"][0]["id"], item_id);
    let discovery_id = Uuid::new_v4();
    let discovery = json!({
        "version": 1,
        "requestId": discovery_id,
        "issuedAt": "2027-01-15T08:00:00.000Z",
        "expiresAt": "2027-01-15T08:01:00.000Z",
        "tabId": 7,
        "topOrigin": "https://example.com",
        "targetOrigin": "https://example.com",
        "targetPageUrl": "https://example.com/login",
        "selectedItem": { "kind": "login", "id": item_id, "title": "Example" },
        "frames": [{
            "frameId": 0,
            "documentId": Uuid::new_v4(),
            "frameOrigin": "https://example.com",
            "fields": [
                {
                    "handle": Uuid::new_v4(), "control": "input", "inputType": "text",
                    "isEmpty": true, "autocomplete": ["username"], "label": "Username",
                    "name": "username", "id": "username", "placeholder": "", "context": "login"
                },
                {
                    "handle": Uuid::new_v4(), "control": "input", "inputType": "password",
                    "isEmpty": true, "autocomplete": ["current-password"], "label": "Password",
                    "name": "password", "id": "password", "placeholder": "", "context": "login"
                }
            ]
        }]
    });
    let approved = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        json!({ "discovery": discovery.clone(), "mode": "selection" }),
        Uuid::new_v4(),
    );
    assert_eq!(approved["ok"], true);
    assert_eq!(approved["result"]["tabId"], 7);
    assert_eq!(
        approved["result"]["frames"][0]["assignments"][0]["value"],
        "alice"
    );
    assert_eq!(
        approved["result"]["frames"][0]["assignments"][1]["value"],
        "secret"
    );
    let replayed_discovery = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        json!({ "discovery": discovery, "mode": "selection" }),
        Uuid::new_v4(),
    );
    assert_eq!(replayed_discovery["error"]["code"], "invalid-request");
    let fill_history = call(
        &mut broker,
        &secret,
        "browser.fill.history",
        json!({}),
        Uuid::new_v4(),
    );
    assert_eq!(fill_history["result"].as_array().map(Vec::len), Some(0));

    for operation in [
        "items.trash.list",
        "cards.trash.list",
        "identities.trash.list",
        "ssh.trash.list",
    ] {
        let response = call(&mut broker, &secret, operation, json!({}), Uuid::new_v4());
        assert_eq!(response["ok"], true, "{operation}");
        assert_eq!(response["result"].as_array().map(Vec::len), Some(0));
    }
    let item_history = call(
        &mut broker,
        &secret,
        "items.history.list",
        json!({ "id": item_id }),
        Uuid::new_v4(),
    );
    assert_eq!(item_history["ok"], true);

    let missing_gesture = call(
        &mut broker,
        &secret,
        "items.detail",
        json!({ "id": item_id }),
        Uuid::new_v4(),
    );
    assert_eq!(missing_gesture["error"]["code"], "invalid-request");
    let detail = call(
        &mut broker,
        &secret,
        "items.detail",
        json!({ "id": item_id, "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(detail["result"]["title"], "Example");
    assert!(detail["result"].get("password").is_none());

    for operation in [
        "cards.detail",
        "identities.detail",
        "ssh.detail",
        "secrets.detail",
        "cards.history.list",
        "identities.history.list",
        "ssh.history.list",
    ] {
        let response = call(
            &mut broker,
            &secret,
            operation,
            json!({ "id": Uuid::new_v4() }),
            Uuid::new_v4(),
        );
        assert_eq!(response["error"]["code"], "operation-failed", "{operation}");
    }

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn authenticated_body_matches_the_node_native_host_wire_vector() {
    let request_id = "11111111-1111-4111-8111-111111111111";
    let payload = "eyJraW5kIjoidmF1bHRtZXNoLnJwYyJ9";
    let body = serde_json::to_vec(&AuthenticatedBody {
        request_id,
        payload,
    })
    .expect("body");
    assert_eq!(
        String::from_utf8(body.clone()).expect("UTF-8 body"),
        r#"{"requestId":"11111111-1111-4111-8111-111111111111","payload":"eyJraW5kIjoidmF1bHRtZXNoLnJwYyJ9"}"#
    );
    let mut mac = HmacSha256::new_from_slice(&[0x5a; 32]).expect("hmac");
    mac.update(&body);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        "UmOPFUCPmSAoH5_bYvnIx_5s5LRPwGDO_wdz1O-QYig"
    );
}

#[test]
fn operation_policy_is_exhaustive_and_confirmation_tokens_are_single_use() {
    let operations = TAURI_BROWSER_SLICE_OPERATIONS
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(TAURI_BROWSER_SLICE_OPERATIONS.len(), 113);
    assert_eq!(operations.len(), 113);
    for operation in TAURI_BROWSER_SLICE_OPERATIONS {
        let owners = [
            is_broker_operation(operation),
            is_runtime_operation(operation),
            crate::browser_platform::is_platform_operation(operation),
        ]
        .into_iter()
        .filter(|owned| *owned)
        .count();
        assert_eq!(owners, 1, "{operation} must have exactly one Tauri owner");
    }
    assert!(!requires_unlock("vault.unlock"));
    assert!(requires_unlock("items.list"));
    assert!(!requires_gesture("cards.detail"));
    assert!(requires_gesture("cards.add"));
    assert!(requires_unlock("browser.generated.copy"));
    assert!(requires_gesture("browser.generated.copy"));
    assert!(requires_confirmation("items.delete"));
    assert!(!requires_confirmation("items.update"));

    let (root, _path, mut broker, secret) = setup("confirmation");
    let locked_gesture = Uuid::new_v4();
    let create_confirmation = call(
        &mut broker,
        &secret,
        "confirmation.request",
        json!({ "operation": "vault.create", "userGestureId": locked_gesture }),
        Uuid::new_v4(),
    );
    assert_eq!(create_confirmation["ok"], true);
    let locked_delete_confirmation = call(
        &mut broker,
        &secret,
        "confirmation.request",
        json!({ "operation": "items.delete", "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(
        locked_delete_confirmation["error"]["code"],
        "unlock-required"
    );
    let unlocked = call(
        &mut broker,
        &secret,
        "vault.unlock",
        json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked["ok"], true);
    let items = call(
        &mut broker,
        &secret,
        "items.list",
        json!({}),
        Uuid::new_v4(),
    );
    let item_id = items["result"][0]["id"].as_str().expect("item id");
    let gesture = Uuid::new_v4();
    let unconfirmed = call(
        &mut broker,
        &secret,
        "items.delete",
        json!({ "id": item_id, "userGestureId": gesture }),
        Uuid::new_v4(),
    );
    assert_eq!(unconfirmed["error"]["code"], "confirmation-required");
    let confirmation = call(
        &mut broker,
        &secret,
        "confirmation.request",
        json!({ "operation": "items.delete", "userGestureId": gesture }),
        Uuid::new_v4(),
    );
    let token = confirmation["result"]["confirmationToken"]
        .as_str()
        .expect("confirmation token");
    let deleted = call(
        &mut broker,
        &secret,
        "items.delete",
        json!({ "id": item_id, "userGestureId": gesture, "confirmationToken": token }),
        Uuid::new_v4(),
    );
    assert_eq!(deleted["ok"], true);
    let replayed = call(
        &mut broker,
        &secret,
        "items.delete",
        json!({ "id": item_id, "userGestureId": gesture, "confirmationToken": token }),
        Uuid::new_v4(),
    );
    assert_eq!(replayed["error"]["code"], "confirmation-required");

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn unix_listener_round_trips_the_native_host_envelope_and_is_owner_only() {
    use std::{
        io::{Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixStream},
    };

    let (root, _path, broker, secret) = setup("unix-listener");
    let endpoint = std::env::temp_dir().join(format!("vmb-{}.sock", Uuid::new_v4()));
    let listener = BrowserBrokerUnixListener::start(endpoint.clone(), Arc::new(Mutex::new(broker)))
        .expect("listener");
    assert_eq!(
        fs::metadata(&endpoint)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let now = Utc::now();
    let request_id = Uuid::new_v4();
    let message = json!({
        "kind": "vaultmesh.rpc", "version": RPC_VERSION, "requestId": request_id,
        "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expiresAt": (now + chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true),
        "operation": "vault.status", "input": {}
    });
    let mut line = envelope(&message, &secret);
    line.push(b'\n');
    let mut stream = UnixStream::connect(&endpoint).expect("connect");
    stream.write_all(&line).expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response");
    let response: Value = serde_json::from_slice(&response).expect("response JSON");
    assert_eq!(response["ok"], true);
    assert_eq!(response["requestId"], request_id.to_string());

    drop(listener);
    assert!(!endpoint.exists());
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn unix_listener_writes_large_responses_past_the_first_socket_buffer() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    struct LargeResponsePlatform;
    impl BrowserBrokerPlatform for LargeResponsePlatform {
        fn dispatch(
            &self,
            _runtime: &mut DesktopRuntime,
            operation: &str,
            _input: &Map<String, Value>,
            _now_millis: i64,
        ) -> Option<Result<Value, BrowserPlatformError>> {
            (operation == "security.settings.get")
                .then(|| Ok(json!({ "largeSafeSummary": "x".repeat(32 * 1024) })))
        }
    }

    let (root, path, _broker, secret) = setup("unix-large-response");
    let mut broker = BrowserBrokerCore::new_with_platform(
        path,
        Zeroizing::new(secret),
        Arc::new(LargeResponsePlatform),
    )
    .expect("broker");
    assert_eq!(
        call(
            &mut broker,
            &secret,
            "vault.unlock",
            json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
            Uuid::new_v4(),
        )["ok"],
        true
    );

    let endpoint = std::env::temp_dir().join(format!("vmb-large-{}.sock", Uuid::new_v4()));
    let listener = BrowserBrokerUnixListener::start(endpoint.clone(), Arc::new(Mutex::new(broker)))
        .expect("listener");
    let now = Utc::now();
    let request_id = Uuid::new_v4();
    let message = json!({
        "kind": "vaultmesh.rpc", "version": RPC_VERSION, "requestId": request_id,
        "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expiresAt": (now + chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true),
        "operation": "security.settings.get", "input": {}
    });
    let mut line = envelope(&message, &secret);
    line.push(b'\n');
    let mut stream = UnixStream::connect(&endpoint).expect("connect");
    stream.write_all(&line).expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response");
    assert!(response.len() > 32 * 1024);
    let response: Value = serde_json::from_slice(&response).expect("complete response JSON");
    assert_eq!(response["ok"], true);
    assert_eq!(response["requestId"], request_id.to_string());
    assert_eq!(
        response["result"]["largeSafeSummary"]
            .as_str()
            .expect("summary")
            .len(),
        32 * 1024
    );

    drop(listener);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn ct_lan_sync_system_lock_clears_browser_unlock_without_revoking_pairing() {
    let (path, other, mut broker, secret) = setup("system-lock-sync");
    let result = call(&mut broker, &secret, "vault.unlock", json!({"masterPassword": PASSWORD, "userGestureId": Uuid::new_v4()}), Uuid::new_v4());
    assert_eq!(result["result"]["status"]["unlocked"], true);
    broker.lock_for_system();
    let status = call(&mut broker, &secret, "vault.status", json!({}), Uuid::new_v4());
    assert_eq!(status["result"]["unlocked"], false);
    let result = call(&mut broker, &secret, "vault.unlock", json!({"masterPassword": PASSWORD, "userGestureId": Uuid::new_v4()}), Uuid::new_v4());
    assert_eq!(result["result"]["status"]["unlocked"], true);
    drop(broker); let _ = std::fs::remove_file(other); std::fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn ct_lan_sync_listener_stop_drops_browser_unlock_owner() {
    let (root, _, mut broker, secret) = setup("listener-owner-sync");
    let result = call(&mut broker, &secret, "vault.unlock", json!({"masterPassword": PASSWORD, "userGestureId": Uuid::new_v4()}), Uuid::new_v4());
    assert_eq!(result["result"]["status"]["unlocked"], true);
    let broker = Arc::new(Mutex::new(broker));
    let weak = Arc::downgrade(&broker);
    let socket = std::env::temp_dir().join(format!("vm-test-{}.sock", Uuid::new_v4()));
    let listener = BrowserBrokerUnixListener::start(socket, broker).unwrap();
    listener.stop();
    assert!(weak.upgrade().is_none(), "stopped listener must not retain an unlocked core");
    std::fs::remove_dir_all(root).unwrap();
}
