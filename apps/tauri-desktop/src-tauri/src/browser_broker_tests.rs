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
    assert_eq!(TAURI_BROWSER_SLICE_OPERATIONS.len(), 124);
    assert_eq!(operations.len(), 124);
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
    assert!(!requires_unlock("browser.unlock.request"));
    assert!(requires_gesture("browser.unlock.request"));
    assert!(!requires_confirmation("browser.unlock.request"));
    for op in ["device.assist.capabilities", "device.assist.start", "device.assist.poll", "device.assist.select", "device.assist.finish", "device.assist.cancel"] {
        assert!(requires_unlock(op));
        assert!(!requires_confirmation(op));
        assert_eq!(requires_gesture(op), matches!(op, "device.assist.start" | "device.assist.select" | "device.assist.finish"));
    }
    assert!(!requires_unlock("vault.unlock"));
    assert!(!requires_unlock("passkeys.probe"));
    assert!(!requires_unlock("passkeys.create"));
    assert!(!requires_unlock("passkeys.get"));
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

#[test]
fn ct_browser_002_locked_candidates_use_verified_preauth_preview_without_unlocking_session() {
    let (root, _path, mut broker, secret) = setup("locked-preauth-candidates");

    // Before first unlock sync, locked candidates returns empty array + requiresUnlock: true (no error).
    let cold = call(
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
    assert_eq!(cold["ok"], true);
    assert_eq!(cold["result"]["candidates"], json!([]));
    assert_eq!(cold["result"]["requiresUnlock"], json!(true));

    // Unlock syncs the encrypted pre-auth preview index; while unlocked requiresUnlock is false.
    let unlocked = call(
        &mut broker,
        &secret,
        "vault.unlock",
        json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked["ok"], true);

    let live = call(
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
    assert_eq!(live["ok"], true);
    assert_eq!(live["result"]["requiresUnlock"], json!(false));
    assert_eq!(live["result"]["candidates"].as_array().map(Vec::len), Some(1));

    // Lock the browser session; locked candidate search still returns metadata with requiresUnlock: true,
    // while Popup workspace / item list and automatic page-load fill remain locked.
    let locked = call(
        &mut broker,
        &secret,
        "vault.lock",
        json!({ "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(locked["result"]["unlocked"], json!(false));

    let locked_candidates = call(
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
    assert_eq!(locked_candidates["ok"], true);
    assert_eq!(locked_candidates["result"]["requiresUnlock"], json!(true));
    assert_eq!(
        locked_candidates["result"]["candidates"][0]["title"],
        json!("Example")
    );
    assert_eq!(
        locked_candidates["result"]["candidates"][0]["subtitle"],
        json!("alice")
    );
    assert!(!locked_candidates.to_string().contains("secret"));

    // Unrelated origin returns zero candidates even while preview index is populated.
    let unrelated = call(
        &mut broker,
        &secret,
        "browser.autofill.candidates",
        json!({
            "topOrigin": "https://other.example.org",
            "pageUrl": "https://other.example.org/login",
            "fieldKind": "login",
            "pageContext": "login"
        }),
        Uuid::new_v4(),
    );
    assert_eq!(unrelated["ok"], true);
    assert_eq!(unrelated["result"]["candidates"], json!([]));
    assert_eq!(unrelated["result"]["requiresUnlock"], json!(true));

    // Popup workspace and automatic page-load fill must still fail closed with unlock-required.
    assert_eq!(
        call(&mut broker, &secret, "vault.workspace", json!({}), Uuid::new_v4())["error"]["code"],
        "unlock-required"
    );
    let auto_fill = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        json!({
            "mode": "automatic",
            "discovery": {
                "version": 1,
                "requestId": Uuid::new_v4(),
                "issuedAt": "2027-01-15T08:00:00.000Z",
                "expiresAt": "2027-01-15T08:00:30.000Z",
                "tabId": 1,
                "topOrigin": "https://example.com",
                "targetOrigin": "https://example.com",
                "targetPageUrl": "https://example.com/login",
                "frames": []
            }
        }),
        Uuid::new_v4(),
    );
    assert_eq!(auto_fill["error"]["code"], "unlock-required");

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn ct_passkey_001_locked_probe_uses_verified_non_secret_passkey_metadata() {
    let (root, _path, mut broker, secret) = setup("locked-passkey-probe");
    let credential_id = "c3ludGhldGljIGNyZWRlbnRpYWw";
    let request_json = json!({
        "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
        "rpId": "example.test",
        "allowCredentials": [{ "type": "public-key", "id": credential_id }],
        "userVerification": "preferred",
        "extensions": {
            "remoteDesktopClientOverride": {
                "origin": "https://example.test",
                "sameOriginWithAncestors": true
            }
        }
    })
    .to_string();

    let cold = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": request_json }),
        Uuid::new_v4(),
    );
    assert_eq!(cold["ok"], true, "{cold}");
    assert_eq!(cold["result"]["status"], "unknown");

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
    let unlocked_without_match = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": request_json }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked_without_match["result"]["status"], "unavailable");

    let added = call(
        &mut broker,
        &secret,
        "secrets.add",
        json!({
            "title": "Synthetic Passkey",
            "kind": "authenticator-key",
            "secret": "synthetic-private-key-material",
            "provider": "VaultMesh Passkey",
            "account": "ada@example.test",
            "environment": "Passkey",
            "scopes": [
                "vaultmesh:passkey:v1",
                "rp:example.test",
                "credential:c3ludGhldGljIGNyZWRlbnRpYWw"
            ],
            "expiresAt": null,
            "website": "https://example.test",
            "notes": null,
            "folder": "Passkeys",
            "favorite": false,
            "masterPasswordReprompt": false,
            "userGestureId": Uuid::new_v4()
        }),
        Uuid::new_v4(),
    );
    assert_eq!(added["ok"], true);

    assert_eq!(
        call(
            &mut broker,
            &secret,
            "vault.lock",
            json!({ "userGestureId": Uuid::new_v4() }),
            Uuid::new_v4(),
        )["result"]["unlocked"],
        false
    );
    let available = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": request_json }),
        Uuid::new_v4(),
    );
    assert_eq!(available["ok"], true);
    assert_eq!(available["result"]["status"], "available");
    assert_eq!(available["result"]["rpId"], "example.test");
    assert_eq!(available["result"]["origin"], "https://example.test");
    assert_eq!(available["result"]["account"], "ada@example.test");
    assert!(!available.to_string().contains("synthetic-private-key-material"));

    let mismatched_request =
        request_json.replace(credential_id, "ZGlmZmVyZW50IGNyZWRlbnRpYWw");
    let unavailable = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": mismatched_request }),
        Uuid::new_v4(),
    );
    assert_eq!(unavailable["result"]["status"], "unavailable");

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

struct MockBrowserUnlockPlatform {
    preview: crate::browser_preauth_preview::BrowserPreAuthPreviewStore,
    seen_requests: Mutex<Vec<(BrowserUnlockSource, String, String, String, bool)>>,
    seen_reprompts: Mutex<Vec<(String, String, String)>>,
    handler: Mutex<
        Option<
            Box<
                dyn FnMut(&BrowserSessionUnlockRequest) -> Result<BrowserUnlockResolution, BrowserPlatformError>
                    + Send,
            >,
        >,
    >,
    reprompt_handler: Mutex<
        Option<
            Box<
                dyn FnMut(&BrowserRepromptRequest) -> Result<Zeroizing<String>, BrowserPlatformError>
                    + Send,
            >,
        >,
    >,
}

impl BrowserBrokerPlatform for MockBrowserUnlockPlatform {
    fn dispatch(
        &self,
        _runtime: &mut DesktopRuntime,
        _operation: &str,
        _input: &Map<String, Value>,
        _now_millis: i64,
    ) -> Option<Result<Value, BrowserPlatformError>> {
        None
    }

    fn preauth_preview_store(
        &self,
    ) -> Option<crate::browser_preauth_preview::BrowserPreAuthPreviewStore> {
        Some(self.preview.clone())
    }

    fn begin_browser_session_unlock(
        &self,
        request: BrowserSessionUnlockRequest,
    ) -> Option<BrowserSessionUnlockWaiter> {
        self.seen_requests.lock().expect("seen lock").push((
            request.source,
            request.origin.clone().unwrap_or_default(),
            request.item_title.clone().unwrap_or_default(),
            request.item_kind.clone().unwrap_or_default(),
            request.master_password_reprompt,
        ));
        let result = self
            .handler
            .lock()
            .expect("handler lock")
            .as_mut()
            .expect("configured handler")(&request);
        Some(BrowserSessionUnlockWaiter::new(move || result))
    }

    fn begin_master_password_reprompt(
        &self,
        request: BrowserRepromptRequest,
    ) -> Option<BrowserRepromptWaiter> {
        self.seen_reprompts.lock().expect("reprompt lock").push((
            request.origin.clone(),
            request.item_title.clone(),
            request.item_kind.clone(),
        ));
        let mut guard = self.reprompt_handler.lock().expect("reprompt handler lock");
        let handler = guard.as_mut()?;
        let result = handler(&request);
        Some(BrowserRepromptWaiter::new(move || result))
    }
}

#[test]
fn ct_browser_002_persistent_session_unlock_and_zero_popup_subsequent_autofill() {
    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-browser-persistent-session-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("test root");
    let vault_path = root.join("browser.vault");
    let preview = crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory();

    let (item_id, quick_key) = {
        let mut creator = DesktopRuntime::new(vault_path.clone()).expect("creator");
        creator.create(PASSWORD.into()).expect("create vault");
        let added = creator
            .execute(
                "items.add",
                json!({
                    "title": "Example",
                    "username": "alice@example.com",
                    "password": "one-shot-secret-password",
                    "url": "https://example.com/login",
                    "notes": null,
                    "folder": null,
                    "favorite": true,
                    "additionalUrls": [],
                    "autofillOnPageLoad": false,
                    "masterPasswordReprompt": false,
                    "customFields": []
                }),
            )
            .expect("seed login");
        preview
            .sync_from_runtime(&mut creator)
            .expect("sync preview");
        let (_, key) = creator.quick_unlock_material().expect("quick unlock key");
        creator.lock();
        (added["id"].as_str().expect("id").to_owned(), key)
    };

    let key_for_handler = quick_key.clone();
    let platform = Arc::new(MockBrowserUnlockPlatform {
        preview,
        seen_requests: Mutex::new(Vec::new()),
        seen_reprompts: Mutex::new(Vec::new()),
        handler: Mutex::new(Some(Box::new(|_| {
            Err(BrowserPlatformError {
                code: "cancelled",
                message: "已取消本次自动填充。".to_owned(),
            })
        }))),
        reprompt_handler: Mutex::new(None),
    });

    let secret = [0x42_u8; 32];
    let mut broker = BrowserBrokerCore::new_with_platform(
        vault_path.clone(),
        Zeroizing::new(secret),
        platform.clone(),
    )
    .expect("broker");
    assert!(!broker.runtime.is_unlocked());

    let user_handle = Uuid::new_v4();
    let pass_handle = Uuid::new_v4();
    let execute_input = json!({
        "mode": "selection",
        "discovery": {
            "version": 1,
            "requestId": Uuid::new_v4(),
            "issuedAt": "2027-01-15T08:00:00.000Z",
            "expiresAt": "2027-01-15T08:00:30.000Z",
            "tabId": 9,
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
                        "handle": user_handle, "control": "input", "inputType": "email",
                        "isEmpty": true, "autocomplete": ["username"], "label": "Email",
                        "name": "email", "id": "email", "placeholder": "", "context": "login"
                    },
                    {
                        "handle": pass_handle, "control": "input", "inputType": "password",
                        "isEmpty": true, "autocomplete": ["current-password"], "label": "Password",
                        "name": "password", "id": "password", "placeholder": "", "context": "login"
                    }
                ]
            }]
        }
    });

    // Cancellation from the unlock window returns `cancelled` without unlocking broker.
    let cancelled = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        execute_input.clone(),
        Uuid::new_v4(),
    );
    assert_eq!(cancelled["error"]["code"], json!("cancelled"));
    assert!(!broker.runtime.is_unlocked());

    // Now configure persistent Pin resolution on locked autofill.
    *platform.handler.lock().unwrap() = Some(Box::new(move |req| {
        Ok(BrowserUnlockResolution {
            factor: BrowserUnlockFactor::Pin,
            vault_path: req.vault_path.clone(),
            vault_key: Zeroizing::new(key_for_handler.to_vec()),
            master_password: None,
        })
    }));
    let mut second_input = execute_input.clone();
    second_input["discovery"]["requestId"] = json!(Uuid::new_v4());
    let approved = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        second_input.clone(),
        Uuid::new_v4(),
    );
    assert_eq!(approved["ok"], true, "{approved}");
    assert_eq!(
        approved["result"]["frames"][0]["assignments"][0]["value"],
        json!("alice@example.com")
    );
    assert_eq!(
        approved["result"]["frames"][0]["assignments"][1]["value"],
        json!("one-shot-secret-password")
    );
    assert_eq!(platform.seen_requests.lock().unwrap().len(), 2);

    // Browser session MUST now remain persistently unlocked!
    assert!(broker.runtime.is_unlocked());
    assert_eq!(
        call(&mut broker, &secret, "vault.status", json!({}), Uuid::new_v4())["result"]["unlocked"],
        json!(true)
    );
    assert_eq!(
        call(&mut broker, &secret, "vault.workspace", json!({}), Uuid::new_v4())["ok"],
        json!(true)
    );

    // Subsequent ordinary autofill and browser.unlock.request succeed with ZERO popup.
    let mut third_input = execute_input.clone();
    third_input["discovery"]["requestId"] = json!(Uuid::new_v4());
    let zero_popup_fill = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        third_input.clone(),
        Uuid::new_v4(),
    );
    assert_eq!(zero_popup_fill["ok"], json!(true));
    assert_eq!(platform.seen_requests.lock().unwrap().len(), 2);

    let already_unlocked_req = call(
        &mut broker,
        &secret,
        "browser.unlock.request",
        json!({ "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(already_unlocked_req["result"]["unlocked"], json!(true));
    assert_eq!(platform.seen_requests.lock().unwrap().len(), 2);

    // Replaying an already-executed discovery requestId (from either locked or unlocked path) fails closed.
    let replayed_second = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        second_input,
        Uuid::new_v4(),
    );
    assert_eq!(replayed_second["error"]["code"], json!("invalid-request"));
    let replayed_third = call(
        &mut broker,
        &secret,
        "browser.autofill.execute",
        third_input,
        Uuid::new_v4(),
    );
    assert_eq!(replayed_third["error"]["code"], json!("invalid-request"));
    assert_eq!(platform.seen_requests.lock().unwrap().len(), 2);

    let pin_history = call(
        &mut broker,
        &secret,
        "vault.unlock-history",
        json!({}),
        Uuid::new_v4(),
    );
    let pin_sources: Vec<&str> = pin_history["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["source"].as_str())
        .collect();
    assert!(pin_sources.contains(&"extension-pin"));

    // Lock and unlock via `browser.unlock.request` with verified master key (zero second Argon2).
    assert_eq!(
        call(
            &mut broker,
            &secret,
            "vault.lock",
            json!({ "userGestureId": Uuid::new_v4() }),
            Uuid::new_v4()
        )["result"]["unlocked"],
        json!(false)
    );
    let key_for_popup = quick_key;
    *platform.handler.lock().unwrap() = Some(Box::new(move |req| {
        Ok(BrowserUnlockResolution {
            factor: BrowserUnlockFactor::MasterPassword,
            vault_path: req.vault_path.clone(),
            vault_key: Zeroizing::new(key_for_popup.to_vec()),
            master_password: None,
        })
    }));
    let unlocked_popup = call(
        &mut broker,
        &secret,
        "browser.unlock.request",
        json!({ "userGestureId": Uuid::new_v4() }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked_popup["ok"], json!(true));
    assert_eq!(unlocked_popup["result"]["unlocked"], json!(true));
    assert_eq!(unlocked_popup["result"]["status"]["unlocked"], json!(true));
    assert!(broker.runtime.is_unlocked());
    assert_eq!(platform.seen_requests.lock().unwrap()[2].0, BrowserUnlockSource::Popup);

    let history = call(
        &mut broker,
        &secret,
        "vault.unlock-history",
        json!({}),
        Uuid::new_v4(),
    );
    let sources: Vec<&str> = history["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["source"].as_str())
        .collect();
    assert!(sources.contains(&"extension-master-password"));

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn ct_browser_002_one_shot_fill_enforces_master_password_reprompt_and_lock_free_wait() {
    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-browser-reprompt-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("test root");
    let vault_path = root.join("browser.vault");
    let preview = crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory();

    let (reprompt_id, quick_key) = {
        let mut creator = DesktopRuntime::new(vault_path.clone()).expect("creator");
        creator.create(PASSWORD.into()).expect("create vault");
        let added = creator
            .execute(
                "items.add",
                json!({
                    "title": "Protected Bank",
                    "username": "banker",
                    "password": "protected-bank-password",
                    "url": "https://bank.example.com/login",
                    "notes": null,
                    "folder": null,
                    "favorite": false,
                    "additionalUrls": [],
                    "autofillOnPageLoad": false,
                    "masterPasswordReprompt": true,
                    "customFields": []
                }),
            )
            .expect("seed reprompt login");
        preview
            .sync_from_runtime(&mut creator)
            .expect("sync preview");
        let (_, key) = creator.quick_unlock_material().expect("quick unlock key");
        creator.lock();
        (added["id"].as_str().expect("id").to_owned(), key)
    };

    // 1. Even if a faulty handler returned Pin without `master_password`,
    // `vault-core` still enforces `masterPasswordReprompt` and rejects with `re-prompt-required`.
    let key_without_pw = quick_key.clone();
    let platform = Arc::new(MockBrowserUnlockPlatform {
        preview,
        seen_requests: Mutex::new(Vec::new()),
        seen_reprompts: Mutex::new(Vec::new()),
        handler: Mutex::new(Some(Box::new(move |req| {
            Ok(BrowserUnlockResolution {
                factor: BrowserUnlockFactor::Pin,
                vault_path: req.vault_path.clone(),
                vault_key: Zeroizing::new(key_without_pw.to_vec()),
                master_password: None,
            })
        }))),
        reprompt_handler: Mutex::new(Some(Box::new(|_| {
            Ok(Zeroizing::new(PASSWORD.to_owned()))
        }))),
    });

    let secret = [0x55_u8; 32];
    let broker = Arc::new(Mutex::new(
        BrowserBrokerCore::new_with_platform(
            vault_path.clone(),
            Zeroizing::new(secret),
            platform.clone(),
        )
        .expect("broker"),
    ));

    let make_live_execute = || {
        let now = Utc::now();
        let issued = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let expires = (now + chrono::Duration::seconds(30)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let pass_handle = Uuid::new_v4();
        (
            pass_handle,
            json!({
                "mode": "selection",
                "discovery": {
                    "version": 1,
                    "requestId": Uuid::new_v4(),
                    "issuedAt": issued,
                    "expiresAt": expires,
                    "tabId": 3,
                    "topOrigin": "https://bank.example.com",
                    "targetOrigin": "https://bank.example.com",
                    "targetPageUrl": "https://bank.example.com/login",
                    "selectedItem": { "kind": "login", "id": reprompt_id, "title": "Protected Bank" },
                    "frames": [{
                        "frameId": 0,
                        "documentId": Uuid::new_v4(),
                        "frameOrigin": "https://bank.example.com",
                        "fields": [{
                            "handle": pass_handle, "control": "input", "inputType": "password",
                            "isEmpty": true, "autocomplete": ["current-password"], "label": "Password",
                            "name": "password", "id": "password", "placeholder": "", "context": "login"
                        }]
                    }]
                }
            }),
        )
    };

    let make_live_envelope = |operation: &str, input: Value| -> Vec<u8> {
        let now = Utc::now();
        let request_id = Uuid::new_v4();
        let rpc = json!({
            "kind": "vaultmesh.rpc",
            "version": 2,
            "requestId": request_id,
            "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expiresAt": (now + chrono::Duration::seconds(30)).to_rfc3339_opts(SecondsFormat::Millis, true),
            "operation": operation,
            "input": input,
        });
        envelope(&rpc, &secret)
    };

    let (_, missing_pw_input) = make_live_execute();
    let rejected = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("browser.autofill.execute", missing_pw_input),
    );
    assert_eq!(rejected["error"]["code"], json!("re-prompt-required"));
    assert_eq!(
        platform.seen_requests.lock().unwrap()[0].4,
        true,
        "preview index must mark item as masterPasswordReprompt = true"
    );

    // 1b. Now that broker is unlocked, another selection fill on `reprompt_id` triggers `begin_master_password_reprompt`
    // and keeps the vault persistently unlocked afterward!
    let (reprompt_handle, unlocked_reprompt_input) = make_live_execute();
    let reprompt_ok = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("browser.autofill.execute", unlocked_reprompt_input),
    );
    assert_eq!(reprompt_ok["ok"], json!(true), "{reprompt_ok}");
    assert_eq!(
        reprompt_ok["result"]["frames"][0]["assignments"][0]["value"],
        json!("protected-bank-password")
    );
    assert_eq!(platform.seen_reprompts.lock().unwrap().len(), 1);
    assert!(broker.lock().unwrap().runtime.is_unlocked());
    let _ = reprompt_handle;

    // 2. Verify lock-free wait while `browser.autofill.execute` waits for user master-password
    // unlock on a background thread: `vault.status` from Popup completes immediately without blocking.
    struct BlockingSessionPlatform {
        quick_key: Zeroizing<[u8; 32]>,
        entered_tx: std::sync::mpsc::SyncSender<()>,
        release_rx: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    }
    impl BrowserBrokerPlatform for BlockingSessionPlatform {
        fn dispatch(
            &self,
            _runtime: &mut DesktopRuntime,
            _operation: &str,
            _input: &Map<String, Value>,
            _now_millis: i64,
        ) -> Option<Result<Value, BrowserPlatformError>> {
            None
        }
        fn begin_browser_session_unlock(
            &self,
            request: BrowserSessionUnlockRequest,
        ) -> Option<BrowserSessionUnlockWaiter> {
            let entered_tx = self.entered_tx.clone();
            let release_rx = Arc::clone(&self.release_rx);
            let key = self.quick_key.clone();
            Some(BrowserSessionUnlockWaiter::new(move || {
                let _ = entered_tx.send(());
                release_rx
                    .lock()
                    .expect("rx lock")
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("release signal");
                Ok(BrowserUnlockResolution {
                    factor: BrowserUnlockFactor::MasterPassword,
                    vault_path: request.vault_path,
                    vault_key: Zeroizing::new(key.to_vec()),
                    master_password: Some(Zeroizing::new(PASSWORD.to_owned())),
                })
            }))
        }
    }

    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let shared_broker = Arc::new(Mutex::new(
        BrowserBrokerCore::new_with_platform(
            vault_path,
            Zeroizing::new(secret),
            Arc::new(BlockingSessionPlatform {
                quick_key,
                entered_tx,
                release_rx: Arc::new(Mutex::new(release_rx)),
            }),
        )
        .expect("shared broker"),
    ));

    let (pass_handle, valid_input) = make_live_execute();
    let fill_line = make_live_envelope("browser.autofill.execute", valid_input);
    let worker_broker = Arc::clone(&shared_broker);
    let worker = std::thread::spawn(move || {
        BrowserBrokerCore::handle_line_shared(&worker_broker, &fill_line)
    });

    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("waiter entered without holding broker lock");

    let popup_status = BrowserBrokerCore::handle_line_shared(
        &shared_broker,
        &make_live_envelope("vault.status", json!({})),
    );
    assert_eq!(popup_status["ok"], json!(true));
    assert_eq!(popup_status["result"]["unlocked"], json!(false));

    release_tx.send(()).expect("release waiter");
    let fill_result = worker.join().expect("join worker");
    assert_eq!(fill_result["ok"], json!(true), "{fill_result}");
    assert_eq!(
        fill_result["result"]["frames"][0]["assignments"],
        json!([{
            "handle": pass_handle,
            "value": "protected-bank-password",
            "overwrite": false
        }])
    );
    assert!(shared_broker.lock().unwrap().runtime.is_unlocked());

    drop(shared_broker);
    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn test_browser_broker_http_listener_discover_and_security_and_rpc() {
    let (root, _path, broker, secret) = setup("http-broker-test");
    let listener = BrowserBrokerHttpListener::start_with_port(
        Arc::new(Mutex::new(broker)),
        0,
    )
    .expect("start http listener on port 0");
    let port = listener.port();
    assert!(port > 0);
    assert!(listener.is_healthy());

    // 1. GET /discover (valid)
    {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"GET /discover HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").expect("write");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_str.contains("\"service\":\"vaultmesh-desktop\""));
        assert!(resp_str.contains(&format!("\"port\":{port}")));
        assert!(!resp_str.to_lowercase().contains("access-control-allow-origin"));
    }

    // 2. GET /discover with Origin: header -> MUST BE 403 Forbidden
    {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"GET /discover HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.com\r\nConnection: close\r\n\r\n").expect("write");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403 Forbidden"), "evil origin must be blocked");
    }

    // 3. POST /rpc with Sec-Fetch-Site -> MUST BE 403 Forbidden
    {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n").expect("write");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403 Forbidden"), "sec-fetch must be blocked");
    }

    // 4. OPTIONS /rpc -> MUST BE 403 Forbidden
    {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"OPTIONS /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").expect("write");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403 Forbidden"), "OPTIONS must be blocked");
    }

    // 5. POST /rpc with missing or invalid X-VaultMesh-Browser-Origin -> 403
    {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nX-VaultMesh-Browser-Origin: invalid-id\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").expect("write");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403 Forbidden"));
    }

    // 6. POST /rpc with valid origin and valid envelope -> 200 OK
    {
        let now = Utc::now();
        let request_id = Uuid::new_v4();
        let message = json!({
            "kind": "vaultmesh.rpc",
            "version": RPC_VERSION,
            "requestId": request_id,
            "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expiresAt": (now + chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true),
            "operation": "vault.status",
            "input": {}
        });
        let body = envelope(&message, &secret);
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let header = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nX-VaultMesh-Browser-Origin: chrome-extension://bdneegbnjbheblmamalplnddbodcghbg\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).expect("write header");
        stream.write_all(&body).expect("write body");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"), "{resp_str}");
        assert!(resp_str.contains("\"ok\":true"));
        assert!(resp_str.contains(&request_id.to_string()));
    }

    // 7. POST /rpc with direct raw JSON message (no envelope) -> 200 OK
    {
        let now = Utc::now();
        let request_id = Uuid::new_v4();
        let raw_message = json!({
            "kind": "vaultmesh.rpc",
            "version": RPC_VERSION,
            "requestId": request_id,
            "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expiresAt": (now + chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true),
            "operation": "vault.status",
            "input": {}
        });
        let body = serde_json::to_vec(&raw_message).unwrap();
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let header = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nX-VaultMesh-Browser-Origin: chrome-extension://bdneegbnjbheblmamalplnddbodcghbg\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).expect("write header");
        stream.write_all(&body).expect("write body");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"), "{resp_str}");
        assert!(resp_str.contains("\"ok\":true"));
        assert!(resp_str.contains(&request_id.to_string()));
    }

    listener.stop();
    assert!(!listener.is_healthy());
    drop(listener);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn ct_passkey_002_multi_candidate_probe_in_unlocked_and_locked_states() {
    struct ApprovingPasskeyPlatform {
        preview: crate::browser_preauth_preview::BrowserPreAuthPreviewStore,
        confirmations: Mutex<Vec<PasskeyConfirmationRequest>>,
    }
    impl BrowserBrokerPlatform for ApprovingPasskeyPlatform {
        fn dispatch(
            &self,
            _runtime: &mut DesktopRuntime,
            _operation: &str,
            _input: &Map<String, Value>,
            _now_millis: i64,
        ) -> Option<Result<Value, BrowserPlatformError>> {
            None
        }
        fn preauth_preview_store(
            &self,
        ) -> Option<crate::browser_preauth_preview::BrowserPreAuthPreviewStore> {
            Some(self.preview.clone())
        }
        fn confirm_passkey(
            &self,
            request: &PasskeyConfirmationRequest,
        ) -> Result<bool, BrowserPlatformError> {
            self.confirmations.lock().unwrap().push(request.clone());
            Ok(true)
        }
    }

    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-browser-passkey-probe-multi-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("test root");
    let vault_path = root.join("browser.vault");
    {
        let mut creator = DesktopRuntime::new(vault_path.clone()).expect("creator");
        creator.create(PASSWORD.into()).expect("create vault");
        creator
            .execute(
                "items.add",
                json!({
                    "title": "Example Login",
                    "username": "ada@example.test",
                    "password": "synthetic-login-password",
                    "url": "https://www.example.test/login",
                    "notes": null
                }),
            )
            .expect("seed login");
        creator.lock();
    }

    let preview = crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory();
    let platform = Arc::new(ApprovingPasskeyPlatform {
        preview,
        confirmations: Mutex::new(Vec::new()),
    });
    let secret = [0x61_u8; 32];
    let mut broker = BrowserBrokerCore::new_with_platform(
        vault_path,
        Zeroizing::new(secret),
        platform.clone(),
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

    let make_create = |user_id: &[u8], user_name: &str| {
        json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": URL_SAFE_NO_PAD.encode(user_id), "name": user_name, "displayName": user_name },
            "challenge": URL_SAFE_NO_PAD.encode(b"reg-challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": [],
            "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
        })
        .to_string()
    };

    let created_first = call(
        &mut broker,
        &secret,
        "passkeys.create",
        json!({ "requestDetailsJson": make_create(b"user-ada", "ada@example.test") }),
        Uuid::new_v4(),
    );
    assert_eq!(created_first["ok"], true, "{created_first}");
    let first_cred = serde_json::from_str::<Value>(
        created_first["result"]["responseJson"].as_str().unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let created_second = call(
        &mut broker,
        &secret,
        "passkeys.create",
        json!({ "requestDetailsJson": make_create(b"user-grace", "grace@example.test") }),
        Uuid::new_v4(),
    );
    assert_eq!(created_second["ok"], true, "{created_second}");
    let second_cred = serde_json::from_str::<Value>(
        created_second["result"]["responseJson"].as_str().unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let make_get = |allow: Value, rp_id: &str, origin: &str| {
        json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
            "rpId": rp_id,
            "allowCredentials": allow,
            "userVerification": "preferred",
            "extensions": {
                "remoteDesktopClientOverride": {
                    "origin": origin,
                    "sameOriginWithAncestors": true
                }
            }
        })
        .to_string()
    };

    let all_get = make_get(json!([]), "example.test", "https://example.test");
    let unlocked_probe = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": all_get }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked_probe["ok"], true, "{unlocked_probe}");
    assert_eq!(unlocked_probe["result"]["status"], "available");
    assert_eq!(unlocked_probe["result"]["account"], "grace@example.test");
    assert_eq!(unlocked_probe["result"]["hasLoginCandidates"], true);
    let unlocked_candidates = unlocked_probe["result"]["candidates"].as_array().unwrap();
    assert_eq!(unlocked_candidates.len(), 2);
    assert_eq!(unlocked_candidates[0]["credentialId"], second_cred);
    assert_eq!(unlocked_candidates[0]["account"], "grace@example.test");
    assert_eq!(unlocked_candidates[1]["credentialId"], first_cred);
    assert_eq!(unlocked_candidates[1]["account"], "ada@example.test");

    let filtered_get = make_get(
        json!([{ "type": "public-key", "id": first_cred }]),
        "example.test",
        "https://example.test",
    );
    let filtered_probe = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": filtered_get }),
        Uuid::new_v4(),
    );
    assert_eq!(filtered_probe["result"]["status"], "available");
    assert_eq!(filtered_probe["result"]["account"], "ada@example.test");
    assert_eq!(
        filtered_probe["result"]["candidates"].as_array().map(Vec::len),
        Some(1)
    );

    let other_get = make_get(json!([]), "other.example.test", "https://other.example.test");
    let unlocked_unavailable = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": other_get }),
        Uuid::new_v4(),
    );
    assert_eq!(unlocked_unavailable["result"]["status"], "unavailable");
    assert_eq!(unlocked_unavailable["result"]["candidates"], json!([]));
    assert_eq!(unlocked_unavailable["result"]["hasLoginCandidates"], false);

    assert_eq!(
        call(
            &mut broker,
            &secret,
            "vault.lock",
            json!({ "userGestureId": Uuid::new_v4() }),
            Uuid::new_v4(),
        )["result"]["unlocked"],
        false
    );

    let locked_probe = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": all_get }),
        Uuid::new_v4(),
    );
    assert_eq!(locked_probe["ok"], true, "{locked_probe}");
    assert_eq!(locked_probe["result"]["status"], "available");
    assert_eq!(locked_probe["result"]["account"], "grace@example.test");
    assert_eq!(locked_probe["result"]["hasLoginCandidates"], true);
    let locked_candidates = locked_probe["result"]["candidates"].as_array().unwrap();
    assert_eq!(locked_candidates.len(), 2);
    assert_eq!(locked_candidates[0]["credentialId"], second_cred);
    assert_eq!(locked_candidates[1]["credentialId"], first_cred);

    let locked_unavailable = call(
        &mut broker,
        &secret,
        "passkeys.probe",
        json!({ "requestDetailsJson": other_get }),
        Uuid::new_v4(),
    );
    assert_eq!(locked_unavailable["result"]["status"], "unavailable");
    assert_eq!(locked_unavailable["result"]["candidates"], json!([]));
    assert_eq!(locked_unavailable["result"]["hasLoginCandidates"], false);

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn ct_passkey_002_lock_free_deferred_confirmation_and_one_shot_unlock() {
    struct ControllablePasskeyPlatform {
        preview: crate::browser_preauth_preview::BrowserPreAuthPreviewStore,
        quick_key: Option<Zeroizing<[u8; 32]>>,
        allow_one_shot: Mutex<bool>,
        approve_confirm: Mutex<bool>,
        unlock_entered_tx: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        unlock_release_rx: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
        confirm_entered_tx: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        confirm_release_rx: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
        seen_unlocks: Mutex<Vec<BrowserSessionUnlockRequest>>,
        seen_confirmations: Mutex<Vec<PasskeyConfirmationRequest>>,
    }

    impl BrowserBrokerPlatform for ControllablePasskeyPlatform {
        fn dispatch(
            &self,
            _runtime: &mut DesktopRuntime,
            _operation: &str,
            _input: &Map<String, Value>,
            _now_millis: i64,
        ) -> Option<Result<Value, BrowserPlatformError>> {
            None
        }

        fn preauth_preview_store(
            &self,
        ) -> Option<crate::browser_preauth_preview::BrowserPreAuthPreviewStore> {
            Some(self.preview.clone())
        }

        fn begin_browser_session_unlock(
            &self,
            request: BrowserSessionUnlockRequest,
        ) -> Option<BrowserSessionUnlockWaiter> {
            if !*self.allow_one_shot.lock().unwrap() {
                return None;
            }
            let key = self.quick_key.clone()?;
            self.seen_unlocks.lock().unwrap().push(BrowserSessionUnlockRequest {
                vault_path: request.vault_path.clone(),
                source: request.source,
                origin: request.origin.clone(),
                item_title: request.item_title.clone(),
                item_kind: request.item_kind.clone(),
                master_password_reprompt: request.master_password_reprompt,
            });
            let tx = self.unlock_entered_tx.lock().unwrap().take();
            let rx_holder = Arc::clone(&self.unlock_release_rx);
            Some(BrowserSessionUnlockWaiter::new(move || {
                if let Some(tx) = tx {
                    let _ = tx.send(());
                }
                if let Some(rx) = rx_holder.lock().unwrap().take() {
                    rx.recv_timeout(std::time::Duration::from_secs(5))
                        .expect("unlock release");
                }
                Ok(BrowserUnlockResolution {
                    factor: BrowserUnlockFactor::Pin,
                    vault_path: request.vault_path,
                    vault_key: Zeroizing::new(key.to_vec()),
                    master_password: None,
                })
            }))
        }

        fn confirm_passkey(
            &self,
            request: &PasskeyConfirmationRequest,
        ) -> Result<bool, BrowserPlatformError> {
            self.seen_confirmations.lock().unwrap().push(request.clone());
            if let Some(tx) = self.confirm_entered_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.confirm_release_rx.lock().unwrap().take() {
                rx.recv_timeout(std::time::Duration::from_secs(5))
                    .expect("confirm release");
            }
            Ok(*self.approve_confirm.lock().unwrap())
        }
    }

    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-browser-passkey-oneshot-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("test root");
    let vault_path = root.join("browser.vault");
    let preview = crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory();
    let quick_key = {
        let mut creator = DesktopRuntime::new(vault_path.clone()).expect("creator");
        creator.create(PASSWORD.into()).expect("create vault");
        preview.sync_from_runtime(&mut creator).expect("sync empty preview");
        let (_, key) = creator.quick_unlock_material().expect("quick unlock key");
        creator.lock();
        key
    };

    let secret = [0x71_u8; 32];
    let make_live_envelope = |operation: &str, input: Value| -> Vec<u8> {
        let now = Utc::now();
        let request_id = Uuid::new_v4();
        let rpc = json!({
            "kind": "vaultmesh.rpc",
            "version": RPC_VERSION,
            "requestId": request_id,
            "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expiresAt": (now + chrono::Duration::seconds(30)).to_rfc3339_opts(SecondsFormat::Millis, true),
            "operation": operation,
            "input": input,
        });
        envelope(&rpc, &secret)
    };

    let platform = Arc::new(ControllablePasskeyPlatform {
        preview: preview.clone(),
        quick_key: Some(quick_key),
        allow_one_shot: Mutex::new(false),
        approve_confirm: Mutex::new(true),
        unlock_entered_tx: Mutex::new(None),
        unlock_release_rx: Arc::new(Mutex::new(None)),
        confirm_entered_tx: Mutex::new(None),
        confirm_release_rx: Arc::new(Mutex::new(None)),
        seen_unlocks: Mutex::new(Vec::new()),
        seen_confirmations: Mutex::new(Vec::new()),
    });

    let broker = Arc::new(Mutex::new(
        BrowserBrokerCore::new_with_platform(
            vault_path.clone(),
            Zeroizing::new(secret),
            platform.clone(),
        )
        .expect("broker"),
    ));

    let make_create = |user_id: &[u8], user_name: &str, cross: bool| {
        let override_val = if cross {
            json!({
                "origin": "https://auth.example.test",
                "sameOriginWithAncestors": false,
                "topOrigin": "https://top.partner.test"
            })
        } else {
            json!({
                "origin": "https://example.test",
                "sameOriginWithAncestors": true
            })
        };
        json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": URL_SAFE_NO_PAD.encode(user_id), "name": user_name, "displayName": user_name },
            "challenge": URL_SAFE_NO_PAD.encode(b"reg-challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": [],
            "extensions": { "remoteDesktopClientOverride": override_val }
        })
        .to_string()
    };

    let make_get = |cross: bool| {
        let override_val = if cross {
            json!({
                "origin": "https://auth.example.test",
                "sameOriginWithAncestors": false,
                "topOrigin": "https://top.partner.test"
            })
        } else {
            json!({
                "origin": "https://example.test",
                "sameOriginWithAncestors": true
            })
        };
        json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
            "rpId": "example.test",
            "allowCredentials": [],
            "userVerification": "preferred",
            "extensions": { "remoteDesktopClientOverride": override_val }
        })
        .to_string()
    };

    // 1. Fail closed with unlock-required when locked and begin_one_shot_unlock_for_fill returns None.
    let no_platform_create = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope(
            "passkeys.create",
            json!({ "requestDetailsJson": make_create(b"u0", "none@example.test", false) }),
        ),
    );
    assert_eq!(no_platform_create["error"]["code"], "unlock-required");

    // 2. When locked and preauth preview knows there is no matching passkey, passkeys.get returns
    // passkey-unavailable immediately without opening the unlock window.
    *platform.allow_one_shot.lock().unwrap() = true;
    let preview_unavailable_get = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope(
            "passkeys.get",
            json!({ "requestDetailsJson": make_get(false) }),
        ),
    );
    assert_eq!(preview_unavailable_get["error"]["code"], "passkey-unavailable");
    assert!(platform.seen_unlocks.lock().unwrap().is_empty());

    // 3. Locked passkeys.create releases broker lock while awaiting unlock AND confirmation;
    // persistent session unlocks after unlock step before entering native confirmation.
    let (u_entered_tx, u_entered_rx) = std::sync::mpsc::sync_channel(1);
    let (u_release_tx, u_release_rx) = std::sync::mpsc::sync_channel(1);
    let (c_entered_tx, c_entered_rx) = std::sync::mpsc::sync_channel(1);
    let (c_release_tx, c_release_rx) = std::sync::mpsc::sync_channel(1);
    *platform.unlock_entered_tx.lock().unwrap() = Some(u_entered_tx);
    *platform.unlock_release_rx.lock().unwrap() = Some(u_release_rx);
    *platform.confirm_entered_tx.lock().unwrap() = Some(c_entered_tx);
    *platform.confirm_release_rx.lock().unwrap() = Some(c_release_rx);

    let worker_broker = Arc::clone(&broker);
    let create_line = make_live_envelope(
        "passkeys.create",
        json!({ "requestDetailsJson": make_create(b"u-ada", "ada@example.test", true) }),
    );
    let worker = std::thread::spawn(move || {
        BrowserBrokerCore::handle_line_shared(&worker_broker, &create_line)
    });

    u_entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("session unlock entered lock-free");
    let status_during_unlock = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("vault.status", json!({})),
    );
    assert_eq!(status_during_unlock["ok"], true);
    assert_eq!(status_during_unlock["result"]["unlocked"], false);

    u_release_tx.send(()).expect("release unlock");
    c_entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("native confirmation entered lock-free");
    let status_during_confirm = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("vault.status", json!({})),
    );
    assert_eq!(status_during_confirm["ok"], true);
    assert_eq!(status_during_confirm["result"]["unlocked"], true);

    c_release_tx.send(()).expect("release confirm");
    let created_ada = worker.join().expect("join create");
    assert_eq!(created_ada["ok"], true, "{created_ada}");
    assert!(broker.lock().unwrap().runtime.is_unlocked());

    let seen_unlock = platform.seen_unlocks.lock().unwrap().pop().unwrap();
    assert_eq!(seen_unlock.source, BrowserUnlockSource::Passkey);
    assert_eq!(seen_unlock.item_kind.as_deref(), Some("secret"));
    assert_eq!(seen_unlock.master_password_reprompt, false);
    assert_eq!(seen_unlock.origin.as_deref(), Some("https://auth.example.test"));

    let seen_confirm = platform.seen_confirmations.lock().unwrap().pop().unwrap();
    assert_eq!(seen_confirm.kind, PasskeyOpKind::Create);
    assert_eq!(seen_confirm.origin, "https://auth.example.test");
    assert_eq!(seen_confirm.top_origin.as_deref(), Some("https://top.partner.test"));

    // Create a second passkey while unlocked -> goes straight to confirmation (no unlock prompt).
    let created_grace = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope(
            "passkeys.create",
            json!({ "requestDetailsJson": make_create(b"u-grace", "grace@example.test", false) }),
        ),
    );
    assert_eq!(created_grace["ok"], true, "{created_grace}");
    assert!(platform.seen_unlocks.lock().unwrap().is_empty());

    // Lock the vault again before testing locked passkeys.probe + locked passkeys.get.
    assert_eq!(
        BrowserBrokerCore::handle_line_shared(
            &broker,
            &make_live_envelope("vault.lock", json!({ "userGestureId": Uuid::new_v4() })),
        )["result"]["unlocked"],
        false
    );

    let probe_after_oneshot = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope(
            "passkeys.probe",
            json!({ "requestDetailsJson": make_get(false) }),
        ),
    );
    assert_eq!(probe_after_oneshot["result"]["status"], "available");
    let probe_candidates = probe_after_oneshot["result"]["candidates"].as_array().unwrap();
    assert_eq!(probe_candidates.len(), 2);
    let ada_item_id = probe_candidates[1]["itemId"].as_str().unwrap().to_owned();
    let ada_cred_id = probe_candidates[1]["credentialId"].as_str().unwrap().to_owned();

    // 4. Locked passkeys.get unlocks persistent session first, matches candidate, then confirms.
    let get_ada = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope(
            "passkeys.get",
            json!({
                "requestDetailsJson": make_get(true),
                "itemId": ada_item_id
            }),
        ),
    );
    assert_eq!(get_ada["ok"], true, "{get_ada}");
    let signed_ada: Value =
        serde_json::from_str(get_ada["result"]["responseJson"].as_str().unwrap()).unwrap();
    assert_eq!(signed_ada["id"], ada_cred_id);
    let confirm_ada = platform.seen_confirmations.lock().unwrap().pop().unwrap();
    assert_eq!(confirm_ada.kind, PasskeyOpKind::Get);
    assert_eq!(confirm_ada.account.as_deref(), Some("ada@example.test"));
    assert_eq!(confirm_ada.top_origin.as_deref(), Some("https://top.partner.test"));
    assert!(broker.lock().unwrap().runtime.is_unlocked());

    // 5. Unlocked passkeys.get releases lock during native confirmation; locking midway returns unlock-required.
    let _ = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("vault.lock", json!({ "userGestureId": Uuid::new_v4() })),
    );
    assert_eq!(
        BrowserBrokerCore::handle_line_shared(
            &broker,
            &make_live_envelope(
                "vault.unlock",
                json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
            ),
        )["ok"],
        true
    );
    let (uc_entered_tx, uc_entered_rx) = std::sync::mpsc::sync_channel(1);
    let (uc_release_tx, uc_release_rx) = std::sync::mpsc::sync_channel(1);
    *platform.confirm_entered_tx.lock().unwrap() = Some(uc_entered_tx);
    *platform.confirm_release_rx.lock().unwrap() = Some(uc_release_rx);

    let worker_broker2 = Arc::clone(&broker);
    let get_line = make_live_envelope(
        "passkeys.get",
        json!({ "requestDetailsJson": make_get(false) }),
    );
    let worker2 = std::thread::spawn(move || {
        BrowserBrokerCore::handle_line_shared(&worker_broker2, &get_line)
    });

    uc_entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("unlocked passkeys.get entered confirmation lock-free");

    // Lock vault while confirmation is on screen!
    let locked_midway = BrowserBrokerCore::handle_line_shared(
        &broker,
        &make_live_envelope("vault.lock", json!({ "userGestureId": Uuid::new_v4() })),
    );
    assert_eq!(locked_midway["result"]["unlocked"], false);

    uc_release_tx.send(()).expect("release unlocked confirm");
    let get_after_lock = worker2.join().expect("join worker2");
    assert_eq!(get_after_lock["error"]["code"], "unlock-required");

    // 6. Revoking pairing mid-flight while waiting on one-shot unlock returns unpaired cleanly.
    let (ru_entered_tx, ru_entered_rx) = std::sync::mpsc::sync_channel(1);
    let (ru_release_tx, ru_release_rx) = std::sync::mpsc::sync_channel(1);
    *platform.unlock_entered_tx.lock().unwrap() = Some(ru_entered_tx);
    *platform.unlock_release_rx.lock().unwrap() = Some(ru_release_rx);

    let worker_broker3 = Arc::clone(&broker);
    let create_revoked_line = make_live_envelope(
        "passkeys.create",
        json!({ "requestDetailsJson": make_create(b"u-revoked", "revoked@example.test", false) }),
    );
    let worker3 = std::thread::spawn(move || {
        BrowserBrokerCore::handle_line_shared(&worker_broker3, &create_revoked_line)
    });

    ru_entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("entered unlock");
    broker.lock().unwrap().revoked = true;
    ru_release_tx.send(()).expect("release unlock");
    let revoked_result = worker3.join().expect("join worker3");
    assert_eq!(revoked_result["status"], "unpaired");

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn ct_passkey_002_declined_confirmation_and_pre_or_post_confirm_expiry_leave_vault_unchanged() {
    struct DeadlineAndCancelPasskeyPlatform {
        preview: crate::browser_preauth_preview::BrowserPreAuthPreviewStore,
        quick_key: Zeroizing<[u8; 32]>,
        approve_confirm: Mutex<bool>,
        unlock_wait_until_ms: Mutex<Option<i64>>,
        confirm_wait_until_ms: Mutex<Option<i64>>,
        confirm_calls: Mutex<usize>,
    }

    impl BrowserBrokerPlatform for DeadlineAndCancelPasskeyPlatform {
        fn dispatch(
            &self,
            _runtime: &mut DesktopRuntime,
            _operation: &str,
            _input: &Map<String, Value>,
            _now_millis: i64,
        ) -> Option<Result<Value, BrowserPlatformError>> {
            None
        }

        fn preauth_preview_store(
            &self,
        ) -> Option<crate::browser_preauth_preview::BrowserPreAuthPreviewStore> {
            Some(self.preview.clone())
        }

        fn begin_browser_session_unlock(
            &self,
            request: BrowserSessionUnlockRequest,
        ) -> Option<BrowserSessionUnlockWaiter> {
            let key = self.quick_key.clone();
            let wait_until = self.unlock_wait_until_ms.lock().unwrap().take();
            Some(BrowserSessionUnlockWaiter::new(move || {
                if let Some(deadline) = wait_until {
                    while Utc::now().timestamp_millis() <= deadline {
                        std::thread::sleep(std::time::Duration::from_millis(15));
                    }
                }
                Ok(BrowserUnlockResolution {
                    factor: BrowserUnlockFactor::Pin,
                    vault_path: request.vault_path,
                    vault_key: Zeroizing::new(key.to_vec()),
                    master_password: None,
                })
            }))
        }

        fn confirm_passkey(
            &self,
            _request: &PasskeyConfirmationRequest,
        ) -> Result<bool, BrowserPlatformError> {
            *self.confirm_calls.lock().unwrap() += 1;
            if let Some(deadline) = self.confirm_wait_until_ms.lock().unwrap().take() {
                while Utc::now().timestamp_millis() <= deadline {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
            }
            Ok(*self.approve_confirm.lock().unwrap())
        }
    }

    let root = std::env::temp_dir().join(format!(
        "vaultmesh-tauri-browser-passkey-cancel-expiry-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("test root");
    let vault_path = root.join("browser.vault");
    let preview = crate::browser_preauth_preview::BrowserPreAuthPreviewStore::in_memory();

    let create_req = |user_id: &[u8], user_name: &str| {
        json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": URL_SAFE_NO_PAD.encode(user_id), "name": user_name, "displayName": user_name },
            "challenge": URL_SAFE_NO_PAD.encode(b"reg-challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": [],
            "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
        })
        .to_string()
    };
    let get_req = json!({
        "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
        "rpId": "example.test",
        "allowCredentials": [],
        "userVerification": "preferred",
        "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
    })
    .to_string();

    let quick_key = {
        let mut creator = DesktopRuntime::new(vault_path.clone()).expect("creator");
        creator.create(PASSWORD.into()).expect("create vault");
        creator
            .create_passkey(&create_req(b"seed-user", "seed@example.test"), None, "2027-01-15T08:00:00.000Z")
            .expect("seed passkey");
        preview.sync_from_runtime(&mut creator).expect("sync preview");
        let (_, key) = creator.quick_unlock_material().expect("quick unlock key");
        creator.lock();
        key
    };

    let secret = [0x83_u8; 32];
    let make_live_envelope_with_ttl = |operation: &str, input: Value, ttl_ms: i64| -> (Vec<u8>, i64) {
        let now = Utc::now();
        let expires = now + chrono::Duration::milliseconds(ttl_ms);
        let rpc = json!({
            "kind": "vaultmesh.rpc",
            "version": RPC_VERSION,
            "requestId": Uuid::new_v4(),
            "issuedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expiresAt": expires.to_rfc3339_opts(SecondsFormat::Millis, true),
            "operation": operation,
            "input": input,
        });
        (envelope(&rpc, &secret), expires.timestamp_millis())
    };

    let platform = Arc::new(DeadlineAndCancelPasskeyPlatform {
        preview,
        quick_key,
        approve_confirm: Mutex::new(false),
        unlock_wait_until_ms: Mutex::new(None),
        confirm_wait_until_ms: Mutex::new(None),
        confirm_calls: Mutex::new(0),
    });

    let broker = Arc::new(Mutex::new(
        BrowserBrokerCore::new_with_platform(
            vault_path.clone(),
            Zeroizing::new(secret),
            platform.clone(),
        )
        .expect("broker"),
    ));

    let baseline_vault_bytes = fs::read(&vault_path).expect("baseline vault bytes");
    let baseline_seq = {
        let (line, _) = make_live_envelope_with_ttl("events.poll", json!({ "after": 0 }), 30_000);
        BrowserBrokerCore::handle_line_shared(&broker, &line)["result"]["sequence"]
            .as_u64()
            .unwrap()
    };

    // 1. Declining confirmation on locked passkeys.create returns "cancelled" while preserving the persistent browser unlock without writing any passkey.
    let (cancel_create_line, _) = make_live_envelope_with_ttl(
        "passkeys.create",
        json!({ "requestDetailsJson": create_req(b"u-cancel", "cancel@example.test") }),
        30_000,
    );
    let cancel_create_resp = BrowserBrokerCore::handle_line_shared(&broker, &cancel_create_line);
    assert_eq!(cancel_create_resp["error"]["code"], "cancelled");
    assert!(broker.lock().unwrap().runtime.is_unlocked());
    let (probe_after_cancel_create, _) = make_live_envelope_with_ttl(
        "passkeys.probe",
        json!({ "requestDetailsJson": get_req }),
        30_000,
    );
    assert_eq!(
        BrowserBrokerCore::handle_line_shared(&broker, &probe_after_cancel_create)["result"]["candidates"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    // 2. Declining confirmation on locked passkeys.get returns "cancelled" while keeping persistent unlock without signing or mutating vault.
    let (lock_line1, _) = make_live_envelope_with_ttl(
        "vault.lock",
        json!({ "userGestureId": Uuid::new_v4() }),
        30_000,
    );
    assert_eq!(BrowserBrokerCore::handle_line_shared(&broker, &lock_line1)["result"]["unlocked"], false);
    let (cancel_get_line, _) = make_live_envelope_with_ttl(
        "passkeys.get",
        json!({ "requestDetailsJson": get_req }),
        30_000,
    );
    let cancel_get_resp = BrowserBrokerCore::handle_line_shared(&broker, &cancel_get_line);
    assert_eq!(cancel_get_resp["error"]["code"], "cancelled");
    assert!(broker.lock().unwrap().runtime.is_unlocked());

    // 3. Pre-confirm expiry: lock first, unlock finishes after expiresAt -> request-expired, confirm_passkey skipped, vault remains locked and bytes unchanged.
    let (lock_line2, _) = make_live_envelope_with_ttl(
        "vault.lock",
        json!({ "userGestureId": Uuid::new_v4() }),
        30_000,
    );
    assert_eq!(BrowserBrokerCore::handle_line_shared(&broker, &lock_line2)["result"]["unlocked"], false);
    let pre_exp_baseline_bytes = fs::read(&vault_path).expect("pre-exp vault bytes");
    *platform.approve_confirm.lock().unwrap() = true;
    *platform.confirm_calls.lock().unwrap() = 0;
    let (pre_exp_line, pre_exp_ms) = make_live_envelope_with_ttl(
        "passkeys.create",
        json!({ "requestDetailsJson": create_req(b"u-pre-exp", "preexp@example.test") }),
        150,
    );
    *platform.unlock_wait_until_ms.lock().unwrap() = Some(pre_exp_ms + 25);
    let pre_exp_resp = BrowserBrokerCore::handle_line_shared(&broker, &pre_exp_line);
    assert_eq!(pre_exp_resp["error"]["code"], "request-expired");
    assert_eq!(*platform.confirm_calls.lock().unwrap(), 0);
    assert!(!broker.lock().unwrap().runtime.is_unlocked());
    assert_eq!(fs::read(&vault_path).expect("vault bytes"), pre_exp_baseline_bytes);

    // 4. Post-confirm expiry while unlocked: user approves native dialog after expiresAt -> finish_passkey rejects with request-expired without mutating vault.
    let (unlock_line, _) = make_live_envelope_with_ttl(
        "vault.unlock",
        json!({ "masterPassword": PASSWORD, "userGestureId": Uuid::new_v4() }),
        30_000,
    );
    assert_eq!(BrowserBrokerCore::handle_line_shared(&broker, &unlock_line)["ok"], true);
    let unlocked_baseline_vault_bytes = fs::read(&vault_path).expect("unlocked baseline vault bytes");
    let seq_before_post_exp = {
        let (line, _) = make_live_envelope_with_ttl("events.poll", json!({ "after": 0 }), 30_000);
        BrowserBrokerCore::handle_line_shared(&broker, &line)["result"]["sequence"]
            .as_u64()
            .unwrap()
    };

    let (post_exp_line, post_exp_ms) = make_live_envelope_with_ttl(
        "passkeys.create",
        json!({ "requestDetailsJson": create_req(b"u-post-exp", "postexp@example.test") }),
        500,
    );
    *platform.confirm_wait_until_ms.lock().unwrap() = Some(post_exp_ms + 25);
    let post_exp_resp = BrowserBrokerCore::handle_line_shared(&broker, &post_exp_line);
    assert_eq!(post_exp_resp["error"]["code"], "request-expired");
    assert_eq!(*platform.confirm_calls.lock().unwrap(), 1);
    assert!(broker.lock().unwrap().runtime.is_unlocked());
    assert_eq!(fs::read(&vault_path).expect("vault bytes"), unlocked_baseline_vault_bytes);

    // Also verify post-confirm expiry on unlocked passkeys.get does not sign or write lastUsedAt.
    let (unlocked_post_exp_line, unlocked_post_exp_ms) = make_live_envelope_with_ttl(
        "passkeys.get",
        json!({ "requestDetailsJson": get_req }),
        500,
    );
    *platform.confirm_wait_until_ms.lock().unwrap() = Some(unlocked_post_exp_ms + 25);
    let unlocked_post_exp_resp =
        BrowserBrokerCore::handle_line_shared(&broker, &unlocked_post_exp_line);
    assert_eq!(unlocked_post_exp_resp["error"]["code"], "request-expired");
    assert_eq!(fs::read(&vault_path).expect("vault bytes"), unlocked_baseline_vault_bytes);

    let (probe_line, _) = make_live_envelope_with_ttl(
        "passkeys.probe",
        json!({ "requestDetailsJson": get_req }),
        30_000,
    );
    let probe_after = BrowserBrokerCore::handle_line_shared(&broker, &probe_line);
    assert_eq!(probe_after["result"]["status"], "available");
    assert_eq!(
        probe_after["result"]["candidates"].as_array().map(Vec::len),
        Some(1)
    );

    let (events_line, _) = make_live_envelope_with_ttl("events.poll", json!({ "after": 0 }), 30_000);
    let events_after = BrowserBrokerCore::handle_line_shared(&broker, &events_line);
    assert_eq!(events_after["result"]["sequence"].as_u64(), Some(seq_before_post_exp));
    let _ = baseline_vault_bytes;
    let _ = baseline_seq;

    drop(broker);
    fs::remove_dir_all(root).expect("cleanup");
}
