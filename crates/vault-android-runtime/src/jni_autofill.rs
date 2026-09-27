use super::*;
use crate::autofill::AutofillTarget;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillPreviewFingerprint(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    app_data_dir: JString<'_>,
) -> jstring {
    let Ok(app_data_dir) = read_string(&mut env, app_data_dir) else {
        return return_string(&mut env, "invalid_input");
    };
    match with_runtime_result(|runtime| runtime.autofill_preview_fingerprint(&app_data_dir)) {
        Ok(digest) => return_string(&mut env, &digest),
        Err(error) => return_string(&mut env, error.code()),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillBegin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    request_id: JString<'_>,
    target: JString<'_>,
    password: JString<'_>,
) -> jstring {
    let (Ok(request_id), Ok(target), Ok(password)) = (
        read_string(&mut env, request_id),
        read_string(&mut env, target),
        read_secret(&mut env, password),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    if target.len() > 8192 {
        return return_string(&mut env, "invalid_input");
    }
    let Ok(target) = serde_json::from_str::<AutofillTarget>(&target) else {
        return return_string(&mut env, "invalid_input");
    };
    let result =
        with_runtime_result(|runtime| runtime.autofill_begin(&request_id, target, &password));
    match result {
        Ok(token) => return_string(&mut env, &format!("token:{token}")),
        Err(error) => return_string(&mut env, error.code()),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillBeginBiometric(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    request_id: JString<'_>,
    target: JString<'_>,
    secret: JString<'_>,
) -> jstring {
    let (Ok(request_id), Ok(target), Ok(secret)) = (
        read_string(&mut env, request_id),
        read_string(&mut env, target),
        read_secret(&mut env, secret),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    if target.len() > 8192 {
        return return_string(&mut env, "invalid_input");
    }
    let Ok(target) = serde_json::from_str::<AutofillTarget>(&target) else {
        return return_string(&mut env, "invalid_input");
    };
    match with_runtime_result(|runtime| {
        runtime.autofill_begin_biometric(&request_id, target, &secret)
    }) {
        Ok(token) => return_string(&mut env, &format!("token:{token}")),
        Err(error) => return_string(&mut env, error.code()),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillBeginPin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    request_id: JString<'_>,
    target: JString<'_>,
    pin: JString<'_>,
    device_secret: JString<'_>,
) -> jstring {
    let (Ok(request_id), Ok(target), Ok(pin), Ok(device_secret)) = (
        read_string(&mut env, request_id),
        read_string(&mut env, target),
        read_secret(&mut env, pin),
        read_secret(&mut env, device_secret),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    if target.len() > 8192 {
        return return_string(&mut env, "invalid_input");
    }
    let Ok(target) = serde_json::from_str::<AutofillTarget>(&target) else {
        return return_string(&mut env, "invalid_input");
    };
    match with_runtime_result(|runtime| {
        runtime.autofill_begin_pin(&request_id, target, &pin, &device_secret)
    }) {
        Ok(token) => return_string(&mut env, &format!("token:{token}")),
        Err(error) => return_string(&mut env, error.code()),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillCandidates(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    token: JString<'_>,
    query: JString<'_>,
    app_label: JString<'_>,
    recent_ids: JString<'_>,
) -> jstring {
    let (Ok(token), Ok(query), Ok(app_label), Ok(recent_ids)) = (
        read_string(&mut env, token),
        read_string(&mut env, query),
        read_string(&mut env, app_label),
        read_string(&mut env, recent_ids),
    ) else {
        return return_string(&mut env, r#"{"error":"invalid_input"}"#);
    };
    if recent_ids.len() > 1024 {
        return return_string(&mut env, r#"{"error":"invalid_input"}"#);
    }
    let Ok(recent_ids) = serde_json::from_str::<Vec<String>>(&recent_ids) else {
        return return_string(&mut env, r#"{"error":"invalid_input"}"#);
    };
    let result = json_result(with_runtime_result(|runtime| {
        runtime.autofill_candidates(&token, &query, &app_label, &recent_ids)
    }));
    return_string(&mut env, &result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillFill(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    token: JString<'_>,
    request_id: JString<'_>,
    id: JString<'_>,
    confirmed: jboolean,
    remember_association: jboolean,
    include_password: jboolean,
) -> jstring {
    let (Ok(token), Ok(request_id), Ok(id)) = (
        read_string(&mut env, token),
        read_string(&mut env, request_id),
        read_string(&mut env, id),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    protected_result(
        &mut env,
        with_runtime_result(|runtime| {
            runtime.autofill_fill(
                &token,
                &request_id,
                &id,
                confirmed != 0,
                remember_association != 0,
                include_password != 0,
            )
        }),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillSave(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    token: JString<'_>,
    request_id: JString<'_>,
    id: JString<'_>,
    title: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
) -> jstring {
    let (Ok(token), Ok(request_id), Ok(id), Ok(title), Ok(username), Ok(password)) = (
        read_string(&mut env, token),
        read_string(&mut env, request_id),
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_secret(&mut env, username),
        read_secret(&mut env, password),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime(|runtime| {
        runtime.autofill_save(&token, &request_id, &id, &title, &username, &password)?;
        Ok("ok")
    });
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_autofillCancel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    token: JString<'_>,
) -> jstring {
    let Ok(token) = read_string(&mut env, token) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime(|runtime| {
        runtime.autofill_cancel(&token);
        Ok("ok")
    });
    return_string(&mut env, result)
}
