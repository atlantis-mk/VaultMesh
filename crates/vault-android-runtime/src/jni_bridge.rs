use std::sync::{Mutex, OnceLock};

use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jboolean, jstring},
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

static RUNTIME: OnceLock<Mutex<Option<AndroidVaultRuntime>>> = OnceLock::new();

fn runtime() -> &'static Mutex<Option<AndroidVaultRuntime>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn return_string(env: &mut JNIEnv<'_>, value: &str) -> jstring {
    env.new_string(value)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn read_secret(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<Zeroizing<String>, ()> {
    env.get_string(&value)
        .map(|value| Zeroizing::new(value.into()))
        .map_err(|_| ())
}

fn read_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, ()> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|_| ())
}

fn optional_string(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn json_result<T: Serialize>(result: Result<T, AndroidRuntimeError>) -> String {
    match result {
        Ok(value) => {
            serde_json::to_string(&value).unwrap_or_else(|_| r#"{"error":"io_error"}"#.into())
        }
        Err(error) => format!(r#"{{"error":"{}"}}"#, error.code()),
    }
}

fn with_runtime_result<T>(
    operation: impl FnOnce(&mut AndroidVaultRuntime) -> Result<T, AndroidRuntimeError>,
) -> Result<T, AndroidRuntimeError> {
    let mut guard = runtime().lock().map_err(|_| AndroidRuntimeError::Io)?;
    let runtime = guard.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?;
    operation(runtime)
}

fn with_runtime(
    operation: impl FnOnce(&mut AndroidVaultRuntime) -> Result<&'static str, AndroidRuntimeError>,
) -> &'static str {
    with_runtime_result(operation).unwrap_or_else(AndroidRuntimeError::code)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_initialize(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    app_data_dir: JString<'_>,
) -> jstring {
    let Ok(path) = env
        .get_string(&app_data_dir)
        .map(|value| String::from(value))
    else {
        return return_string(&mut env, "io_error");
    };
    let Ok(candidate) = AndroidVaultRuntime::new(path) else {
        return return_string(&mut env, "io_error");
    };
    let result = match runtime().lock() {
        Ok(mut guard) => {
            if let Some(current) = guard.as_mut() {
                current.lock();
            }
            *guard = Some(candidate);
            "ok"
        }
        Err(_) => "io_error",
    };
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_status(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime(|runtime| Ok(runtime.status().code()));
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_create(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    master_password: JString<'_>,
) -> jstring {
    let Ok(password) = read_secret(&mut env, master_password) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime(|runtime| {
        runtime.create(password.as_str())?;
        Ok("ok")
    });
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_unlock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    master_password: JString<'_>,
) -> jstring {
    let Ok(password) = read_secret(&mut env, master_password) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime(|runtime| {
        runtime.unlock(password.as_str())?;
        Ok("ok")
    });
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime(|runtime| {
        runtime.lock();
        Ok("ok")
    });
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_listLogins(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = json_result(with_runtime_result(|runtime| runtime.list_logins()));
    return_string(&mut env, &json)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    url: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(username), Ok(mut password), Ok(url)) = (
        read_string(&mut env, title),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_string(&mut env, url),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let password = std::mem::take(&mut *password);
    let result = with_runtime_result(|runtime| {
        runtime.add_login(title, username, password, optional_string(url))
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    replace_password: jboolean,
    url: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(title), Ok(username), Ok(mut password), Ok(url)) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_string(&mut env, url),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let replacement = (replace_password != 0).then(|| std::mem::take(&mut *password));
    let result = with_runtime_result(|runtime| {
        runtime.update_login(&id, title, username, replacement, optional_string(url))
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_deleteLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
) -> jstring {
    let Ok(id) = read_string(&mut env, id) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.delete_login(&id))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_listTrash(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = json_result(with_runtime_result(|runtime| runtime.list_trash()));
    return_string(&mut env, &json)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_restoreLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    trash_id: JString<'_>,
) -> jstring {
    let Ok(trash_id) = read_string(&mut env, trash_id) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.restore_login(&trash_id))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_purgeLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    trash_id: JString<'_>,
) -> jstring {
    let Ok(trash_id) = read_string(&mut env, trash_id) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.purge_login(&trash_id))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_emptyTrash(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(AndroidVaultRuntime::empty_trash)
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}
