use super::*;

fn native_plan_fixture() -> Value {
    let handle = Uuid::new_v4();
    json!({
        "mode": "selection", "userGestureId": Uuid::new_v4(),
        "nativeLoginPlan": [{ "handle": handle, "source": "password" }],
        "discovery": {
            "version": 1, "requestId": Uuid::new_v4(), "issuedAt": "2027-01-15T08:00:00.000Z", "expiresAt": "2027-01-15T08:00:30.000Z",
            "tabId": 1, "topOrigin": "https://example.test", "targetOrigin": "https://example.test", "targetPageUrl": "https://example.test/login",
            "selectedItem": { "kind": "login", "id": Uuid::new_v4(), "title": "Synthetic" },
            "frames": [{ "frameId": 0, "documentId": Uuid::new_v4(), "frameOrigin": "https://example.test", "fields": [{
                "handle": handle, "control": "input", "inputType": "password", "isEmpty": true, "autocomplete": [],
                "label": "", "name": "", "id": "", "placeholder": "", "context": "unknown"
            }] }]
        }
    })
}

#[test]
fn native_login_plan_rejects_unbound_unsupported_and_non_explicit_sources() {
    let now = DateTime::parse_from_rfc3339("2027-01-15T08:00:01.000Z").unwrap().timestamp_millis();
    let original = native_plan_fixture();
    assert!(parse_execute(original.as_object().unwrap(), now).is_ok());
    let cases: Vec<(&str, Value)> = vec![
        ("/mode", json!("automatic")), ("/userGestureId", Value::Null),
        ("/nativeLoginPlan/0/source", json!("totpCode")),
        ("/nativeLoginPlan/0/handle", json!(Uuid::new_v4())),
        ("/nativeLoginPlan", json!([])),
        ("/nativeLoginPlan", Value::Null),
        ("/discovery/topOrigin", json!("https://untrusted.test")),
        ("/discovery/selectedItem/kind", json!("card")),
        ("/discovery/frames/0/fields/0/inputType", json!("text")),
        ("/discovery/frames/0/fields/0/name", json!("couponCode")),
        ("/discovery/frames/0/fields/0/autocomplete", json!(["new-password"])),
        ("/discovery/frames/0/fields/0/context", json!("signup")),
    ];
    for (pointer, value) in cases {
        let mut input = original.clone();
        *input.pointer_mut(pointer).unwrap() = value;
        assert!(parse_execute(input.as_object().unwrap(), now).is_err(), "{pointer}");
    }
    let mut duplicate = original.clone();
    duplicate["nativeLoginPlan"].as_array_mut().unwrap().push(original["nativeLoginPlan"][0].clone());
    assert!(parse_execute(duplicate.as_object().unwrap(), now).is_err());
    let mut with_value = original.clone();
    with_value["discovery"]["frames"][0]["fields"][0]["value"] = json!("must-never-be-discovery");
    assert!(parse_execute(with_value.as_object().unwrap(), now).is_err());
}

#[test]
fn native_login_plan_allows_bound_iframe_totp_and_custom_sources() {
    let now = DateTime::parse_from_rfc3339("2027-01-15T08:00:01.000Z").unwrap().timestamp_millis();
    let mut input = native_plan_fixture();
    input["discovery"]["frames"][0]["frameId"] = json!(4);
    assert!(parse_execute(input.as_object().unwrap(), now).is_ok());
    let mut cross = input.clone();
    cross["discovery"]["topOrigin"] = json!("https://parent.test");
    assert!(parse_execute(cross.as_object().unwrap(), now).is_err());
    cross["confirmedTargetOrigin"] = json!("https://example.test");
    assert!(parse_execute(cross.as_object().unwrap(), now).is_ok());
    cross["confirmedTargetOrigin"] = json!("https://wrong.test");
    assert!(parse_execute(cross.as_object().unwrap(), now).is_err());
    let mut automatic = input.clone();
    automatic["mode"] = json!("automatic");
    automatic.as_object_mut().unwrap().remove("userGestureId");
    automatic["discovery"]["frames"][0]["fields"][0]["context"] = json!("login");
    assert!(parse_execute(automatic.as_object().unwrap(), now).is_ok());
    automatic["discovery"]["frames"][0]["fields"][0]["isEmpty"] = json!(false);
    assert!(parse_execute(automatic.as_object().unwrap(), now).is_err());
    input["nativeLoginPlan"][0]["source"] = json!("totpCode");
    input["nativeLoginPlan"][0]["index"] = json!(0);
    input["discovery"]["frames"][0]["fields"][0]["inputType"] = json!("text");
    input["discovery"]["frames"][0]["fields"][0]["maxLength"] = json!(1);
    input["discovery"]["frames"][0]["fields"][0]["autocomplete"] = json!(["one-time-code"]);
    assert!(parse_execute(input.as_object().unwrap(), now).is_ok());
    for (pointer, value) in [
        ("/nativeLoginPlan/0/index", json!(6)),
        ("/discovery/frames/0/fields/0/isEmpty", json!(false)),
        ("/discovery/frames/0/fields/0/maxLength", json!(6)),
    ] {
        let mut bad = input.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(parse_execute(bad.as_object().unwrap(), now).is_err(), "{pointer}");
    }
    let mut values = FillValues::default();
    values.values.insert("totpCode".into(), "654321".into());
    values.custom_fields.push(("tenant".into(), "synthetic-custom".into()));
    let mut entry = NativeLoginSource { handle: Uuid::new_v4(), source: "totpCode".into(), index: Some(1), name: None };
    assert_eq!(native_login_value(&values, &entry).ok(), Some(Some("5".into())));
    entry.index = None;
    assert_eq!(native_login_value(&values, &entry).ok(), Some(Some("654321".into())));
    entry.source = "custom".into(); entry.index = Some(0); entry.name = Some("tenant".into());
    assert_eq!(native_login_value(&values, &entry).ok(), Some(Some("synthetic-custom".into())));
    entry.name = Some("stale-name".into());
    assert!(native_login_value(&values, &entry).is_err());
}

#[test]
fn maps_qualified_bare_login_controls_and_ssh_host_without_inventing_metadata() {
    let mut values = FillValues::default();
    values.values.insert("username".into(), "synthetic-user".into());
    values.values.insert("password".into(), "synthetic-password".into());
    values.values.insert("host".into(), "server.example.test".into());
    let mut field = DiscoveredField {
        handle: Uuid::new_v4(), control: "input".into(), input_type: Some("password".into()),
        max_length: None, is_empty: true, autocomplete: vec![], label: String::new(),
        name: String::new(), id: String::new(), placeholder: String::new(), context: "login".into(), options: None,
    };
    assert_eq!(map_field("login", &values, &field), Some("synthetic-password".into()));
    field.context = "password-reset".into();
    assert_eq!(map_field("login", &values, &field), None);
    field.context = "login".into();
    field.input_type = Some("email".into());
    assert_eq!(map_field("login", &values, &field), Some("synthetic-user".into()));
    field.input_type = Some("text".into());
    field.context = "ssh-console".into();
    field.name = "host".into();
    assert_eq!(map_field("ssh", &values, &field), Some("server.example.test".into()));
    field.name = "ghost".into();
    assert_eq!(map_field("ssh", &values, &field), None);
}

#[test]
fn maps_account_name_field_to_login_username() {
    let mut values = FillValues::default();
    values
        .values
        .insert("username".into(), "alice@example.test".into());
    let field = DiscoveredField {
        handle: Uuid::new_v4(),
        control: "input".into(),
        input_type: Some("text".into()),
        max_length: None,
        is_empty: true,
        autocomplete: vec!["off".into()],
        label: String::new(),
        name: String::new(),
        id: "account_name_text_field".into(),
        placeholder: String::new(),
        context: "login".into(),
        options: None,
    };

    assert_eq!(
        map_field("login", &values, &field),
        Some("alice@example.test".into())
    );
}

#[test]
fn identity_heuristic_handles_zero_or_ambiguous_matches_without_panicking() {
    assert_eq!(identity_heuristic("save button"), None);
    assert_eq!(identity_heuristic("email field"), Some("email"));
    assert_eq!(identity_heuristic("email phone field"), None);
}

#[test]
fn field_word_boundaries_and_shared_exclusions_prevent_substring_matches() {
    for name in ["statement", "hometown", "transport", "timezone"] {
        assert_eq!(identity_heuristic(name), None, "{name}");
    }
    for name in ["firstName", "first_name", "First name", "firstname"] {
        assert_eq!(identity_heuristic(name), Some("firstName"), "{name}");
    }
    for name in ["searchEmail", "coupon_code", "feedback message", "图形验证码"] {
        assert!(excluded_fill_field(name), "{name}");
    }
    for name in ["researcherEmail", "discountedName", "username", "one-time-code"] {
        assert!(!excluded_fill_field(name), "{name}");
    }
}

#[test]
fn rejects_cross_origin_and_duplicate_handles() {
    let id = Uuid::new_v4();
    let document = Uuid::new_v4();
    let handle = Uuid::new_v4();
    let input = json!({
        "discovery": {
            "version": 1, "requestId": id, "issuedAt": "2027-01-15T08:00:00.000Z", "expiresAt": "2027-01-15T08:01:00.000Z",
            "tabId": 1, "topOrigin": "https://example.test", "targetOrigin": "https://example.test", "targetPageUrl": "https://example.test/login",
            "selectedItem": { "kind": "login", "id": Uuid::new_v4(), "title": "Example" },
            "frames": [{ "frameId": 0, "documentId": document, "frameOrigin": "https://evil.test", "fields": [{
                "handle": handle, "control": "input", "inputType": "text", "isEmpty": true, "autocomplete": ["username"],
                "label": "Username", "name": "username", "id": "username", "placeholder": "", "context": "login"
            }] }]
        }, "mode": "selection"
    });
    let error = parse_execute(input.as_object().unwrap(), 1_800_000_000_000)
        .err()
        .expect("cross-origin discovery must fail");
    assert_eq!(error.code, "invalid-request");
}

#[test]
fn email_otp_assignment_is_empty_field_only_segmented_and_one_use() {
    let request_id = Uuid::new_v4();
    let document_id = Uuid::new_v4();
    let handles = (0..6).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let issued = "2027-01-15T08:00:00.000Z";
    let now = DateTime::parse_from_rfc3339(issued)
        .expect("time")
        .timestamp_millis()
        + 1_000;
    let fields = handles
            .iter()
            .enumerate()
            .map(|(index, handle)| json!({
                "handle": handle, "control": "input", "inputType": "tel", "maxLength": 1,
                "isEmpty": true, "autocomplete": ["off"], "label": format!("验证码数字 {}", index + 1),
                "name": "verification_code", "id": format!("verification_code_{index}"), "placeholder": "", "context": "otp"
            }))
            .collect::<Vec<_>>();
    let input = json!({
        "candidateId": Uuid::new_v4(),
        "userGestureId": Uuid::new_v4(),
        "discovery": {
            "version": 1, "requestId": request_id, "issuedAt": issued, "expiresAt": "2027-01-15T08:01:00.000Z",
            "tabId": 7, "topOrigin": "https://example.test", "targetOrigin": "https://example.test", "targetPageUrl": "https://example.test/register",
            "frames": [{ "frameId": 0, "documentId": document_id, "frameOrigin": "https://example.test", "fields": fields }]
        }
    });
    let mut seen = HashMap::new();
    let approval =
        email_otp_assignment(&mut seen, input.as_object().expect("input"), "482103", now)
            .unwrap_or_else(|error| panic!("email OTP assignment: {}", error.message));
    let assignments = approval["frames"][0]["assignments"]
        .as_array()
        .expect("assignments");
    assert_eq!(assignments.len(), 6);
    assert_eq!(assignments[0]["value"], "4");
    assert_eq!(assignments[5]["value"], "3");
    assert!(assignments.iter().all(|value| value["overwrite"] == false));
    assert!(
        email_otp_assignment(&mut seen, input.as_object().expect("input"), "482103", now,).is_err()
    );

    let mut cross_origin = input.clone();
    cross_origin["discovery"]["requestId"] = json!(Uuid::new_v4());
    cross_origin["discovery"]["targetOrigin"] = json!("https://auth.example.test");
    cross_origin["discovery"]["targetPageUrl"] = json!("https://auth.example.test/register");
    cross_origin["discovery"]["frames"][0]["frameOrigin"] = json!("https://auth.example.test");
    assert!(
        email_otp_assignment(
            &mut seen,
            cross_origin.as_object().expect("cross-origin input"),
            "482103",
            now,
        )
        .is_err()
    );
}
