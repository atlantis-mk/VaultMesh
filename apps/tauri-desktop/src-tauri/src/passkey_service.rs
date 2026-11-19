use uuid::Uuid;
pub use vaultmesh_core::PasskeyGetRequestView;
use vaultmesh_core::{describe_passkey_request, get_passkey_request_view};
use vaultmesh_ffi::DesktopRuntime;

pub struct PasskeyGetSelection {
    pub item_id: Uuid,
    pub rp_id: String,
    pub origin: String,
    pub account: Option<String>,
}

pub struct PasskeyService;

impl PasskeyService {
    pub fn describe(
        kind: &str,
        request_json: &str,
    ) -> Result<(String, String, Option<String>), String> {
        let summary = describe_passkey_request(kind, request_json)
            .map_err(|error| error.public_message().to_owned())?;
        Ok((summary.rp_id, summary.origin, summary.account))
    }

    pub fn get_request_view(request_json: &str) -> Result<PasskeyGetRequestView, String> {
        get_passkey_request_view(request_json)
            .map_err(|error| error.public_message().to_owned())
    }

    pub fn prepare_get(
        runtime: &mut DesktopRuntime,
        request_json: &str,
    ) -> Result<Option<PasskeyGetSelection>, String> {
        let mut candidates = runtime
            .matching_passkeys(request_json)
            .map_err(|error| error.public_message().to_owned())?;
        if candidates.is_empty() {
            return Ok(None);
        }
        let selected = candidates.swap_remove(0);
        Ok(Some(PasskeyGetSelection {
            item_id: selected.item_id,
            rp_id: selected.rp_id,
            origin: selected.origin,
            account: selected.account,
        }))
    }

    pub fn create(
        runtime: &mut DesktopRuntime,
        request_json: &str,
        default_login_id: Option<Uuid>,
        now: &str,
    ) -> Result<String, String> {
        runtime
            .create_passkey(request_json, default_login_id, now)
            .map_err(|error| error.public_message().to_owned())
    }

    pub fn get_for_item(
        runtime: &mut DesktopRuntime,
        request_json: &str,
        now: &str,
        allowed_item_id: Option<Uuid>,
    ) -> Result<String, String> {
        runtime
            .sign_passkey_assertion(request_json, allowed_item_id, None, now)
            .map_err(|error| error.public_message().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{Signature, VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs;

    #[test]
    fn origin_and_rp_matching_are_bounded() {
        let request = |rp_id: &str| {
            json!({
                "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
                "rpId": rp_id,
                "allowCredentials": [],
                "userVerification": "preferred",
                "extensions": {
                    "remoteDesktopClientOverride": {
                        "origin": "https://login.example.com",
                        "sameOriginWithAncestors": true
                    }
                }
            })
            .to_string()
        };
        assert!(PasskeyService::describe("get", &request("example.com")).is_ok());
        assert!(PasskeyService::describe("get", &request("evil.com")).is_err());
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
        let request = |challenge: String, allow: Value| {
            json!({
                "challenge": challenge,
                "rpId": "google.com",
                "allowCredentials": allow,
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
        assert!(PasskeyService::describe("get", &request(google_sized, json!([]))).is_ok());

        let valid_challenge = URL_SAFE_NO_PAD.encode(b"challenge");
        let oversized = URL_SAFE_NO_PAD.encode(vec![0x5a; 16 * 1024 + 1]);
        assert!(PasskeyService::describe("get", &request(oversized, json!([]))).is_err());

        let oversized_identifier = URL_SAFE_NO_PAD.encode(vec![0x5a; 3_073]);
        assert!(
            PasskeyService::describe(
                "get",
                &request(
                    valid_challenge,
                    json!([{ "type": "public-key", "id": oversized_identifier }])
                )
            )
            .is_err()
        );
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

        let make_create = |user_id: &[u8]| {
            json!({
                "rp": { "id": "example.test", "name": "Example" },
                "user": { "id": URL_SAFE_NO_PAD.encode(user_id), "name": "ada@example.test", "displayName": "Ada" },
                "challenge": URL_SAFE_NO_PAD.encode(b"registration challenge"),
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                "excludeCredentials": [],
                "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
            })
            .to_string()
        };

        PasskeyService::create(
            &mut runtime,
            &make_create(b"u-default"),
            Some(default_login),
            "2027-01-15T08:00:00.000Z",
        )
        .expect("create with validated default");
        PasskeyService::create(
            &mut runtime,
            &make_create(b"u-fallback"),
            Some(cross_origin),
            "2027-01-15T08:00:01.000Z",
        )
        .expect("create with username fallback");

        let secrets = runtime.execute("secrets.list", json!({})).expect("secrets");
        assert_eq!(secrets[0]["loginId"], default_login.to_string());
        assert_eq!(secrets[1]["loginId"], username_match.to_string());

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
        let prepared = PasskeyService::prepare_get(&mut runtime, &get_request)
            .expect("prepare matching Passkey")
            .expect("matching Passkey");
        assert_eq!(prepared.item_id, passkey_item_id);
        assert_eq!(prepared.rp_id, "example.test");
        assert_eq!(prepared.origin, "https://example.test");
        assert_eq!(prepared.account.as_deref(), Some("ada@example.test"));
        let other_credential_id = URL_SAFE_NO_PAD.encode(b"different credential");
        let missing_request = get_request.replace(credential_id, &other_credential_id);
        assert!(
            PasskeyService::prepare_get(&mut runtime, &missing_request)
                .expect("valid unmatched request")
                .is_none()
        );
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

    #[test]
    fn cross_origin_requires_top_origin_and_emits_it_in_client_data_json() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-passkey-cross-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("root");
        let mut runtime = DesktopRuntime::new(root.join("cross.vault")).expect("runtime");
        runtime
            .create("passkey cross origin master password".into())
            .expect("create vault");

        let create_with_override = |override_value: Value| {
            json!({
                "rp": { "id": "example.test", "name": "Example" },
                "user": { "id": URL_SAFE_NO_PAD.encode(b"user-cross"), "name": "ada@example.test", "displayName": "Ada" },
                "challenge": URL_SAFE_NO_PAD.encode(b"reg-challenge"),
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                "excludeCredentials": [],
                "extensions": { "remoteDesktopClientOverride": override_value }
            })
            .to_string()
        };

        assert!(
            PasskeyService::describe(
                "create",
                &create_with_override(json!({
                    "origin": "https://auth.example.test",
                    "sameOriginWithAncestors": false
                }))
            )
            .is_err()
        );
        assert!(
            PasskeyService::describe(
                "create",
                &create_with_override(json!({
                    "origin": "https://auth.example.test",
                    "sameOriginWithAncestors": false,
                    "topOrigin": "https://top.partner.test/path"
                }))
            )
            .is_err()
        );

        let created = PasskeyService::create(
            &mut runtime,
            &create_with_override(json!({
                "origin": "https://auth.example.test",
                "sameOriginWithAncestors": false,
                "topOrigin": "https://top.partner.test"
            })),
            None,
            "2027-01-15T08:00:00.000Z",
        )
        .expect("cross-origin create");
        let created: Value = serde_json::from_str(&created).expect("created json");
        let create_client_data: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(created["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(create_client_data["crossOrigin"], true);
        assert_eq!(create_client_data["topOrigin"], "https://top.partner.test");
        let verifying_key = VerifyingKey::from_public_key_der(
            &URL_SAFE_NO_PAD
                .decode(created["response"]["publicKey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        let cross_get = json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"get-challenge"),
            "rpId": "example.test",
            "allowCredentials": [],
            "userVerification": "preferred",
            "extensions": {
                "remoteDesktopClientOverride": {
                    "origin": "https://auth.example.test",
                    "sameOriginWithAncestors": false,
                    "topOrigin": "https://top.partner.test"
                }
            }
        })
        .to_string();
        let view = PasskeyService::get_request_view(&cross_get).expect("cross get view");
        assert!(view.cross_origin);
        assert_eq!(view.top_origin.as_deref(), Some("https://top.partner.test"));

        let assertion = PasskeyService::get_for_item(
            &mut runtime,
            &cross_get,
            "2027-01-15T08:00:01.000Z",
            None,
        )
        .expect("cross-origin get");
        let assertion: Value = serde_json::from_str(&assertion).expect("assertion json");
        let client_bytes = URL_SAFE_NO_PAD
            .decode(assertion["response"]["clientDataJSON"].as_str().unwrap())
            .unwrap();
        let get_client_data: Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(get_client_data["crossOrigin"], true);
        assert_eq!(get_client_data["topOrigin"], "https://top.partner.test");

        let auth = URL_SAFE_NO_PAD
            .decode(assertion["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        let signature = Signature::from_der(
            &URL_SAFE_NO_PAD
                .decode(assertion["response"]["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(&client_bytes));
        verifying_key.verify(&signed, &signature).expect("verify");

        runtime.lock();
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn multi_passkey_selects_and_signs_by_item_id() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-passkey-multi-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("root");
        let mut runtime = DesktopRuntime::new(root.join("multi.vault")).expect("runtime");
        runtime
            .create("passkey multi account master password".into())
            .expect("create vault");

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

        let first_raw = PasskeyService::create(
            &mut runtime,
            &make_create(b"u-ada", "ada@example.test"),
            None,
            "2027-01-15T08:00:00.000Z",
        )
        .expect("create first");
        let first: Value = serde_json::from_str(&first_raw).unwrap();
        let first_cred = first["id"].as_str().unwrap().to_owned();
        let first_key = VerifyingKey::from_public_key_der(
            &URL_SAFE_NO_PAD
                .decode(first["response"]["publicKey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        let second_raw = PasskeyService::create(
            &mut runtime,
            &make_create(b"u-grace", "grace@example.test"),
            None,
            "2027-01-15T08:00:02.000Z",
        )
        .expect("create second");
        let second: Value = serde_json::from_str(&second_raw).unwrap();
        let second_cred = second["id"].as_str().unwrap().to_owned();

        let get_request = json!({
            "challenge": URL_SAFE_NO_PAD.encode(b"assertion challenge"),
            "rpId": "example.test",
            "allowCredentials": [],
            "userVerification": "required",
            "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
        })
        .to_string();

        let candidates = runtime
            .matching_passkeys(&get_request)
            .expect("matching candidates");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].credential_id, second_cred);
        assert_eq!(candidates[1].credential_id, first_cred);

        let prepared = PasskeyService::prepare_get(&mut runtime, &get_request)
            .expect("prepare")
            .expect("some");
        assert_eq!(prepared.item_id, candidates[0].item_id);
        assert_eq!(prepared.account.as_deref(), Some("grace@example.test"));

        let signed_first_raw = PasskeyService::get_for_item(
            &mut runtime,
            &get_request,
            "2027-01-15T08:00:03.000Z",
            Some(candidates[1].item_id),
        )
        .expect("sign selected older item_id");
        let signed_first: Value = serde_json::from_str(&signed_first_raw).unwrap();
        assert_eq!(signed_first["id"], first_cred);
        let auth = URL_SAFE_NO_PAD
            .decode(signed_first["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        let client = URL_SAFE_NO_PAD
            .decode(signed_first["response"]["clientDataJSON"].as_str().unwrap())
            .unwrap();
        let sig = Signature::from_der(
            &URL_SAFE_NO_PAD
                .decode(signed_first["response"]["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(client));
        first_key.verify(&signed, &sig).expect("verify first key");

        // Error messages preserve exact extension domException patterns across DesktopRuntime.
        let cross_platform_req = json!({
            "rp": { "id": "example.test", "name": "Example" },
            "user": { "id": "AQ", "name": "a" },
            "challenge": URL_SAFE_NO_PAD.encode(b"challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "authenticatorAttachment": "cross-platform" },
            "extensions": { "remoteDesktopClientOverride": { "origin": "https://example.test", "sameOriginWithAncestors": true } }
        })
        .to_string();
        let err = runtime
            .create_passkey(&cross_platform_req, None, "2027-01-15T08:00:04.000Z")
            .unwrap_err();
        assert!(err.public_message().contains("安全密钥"));

        runtime.lock();
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
