#[path = "jni_autofill.rs"]
mod autofill;
#[path = "jni_sync.rs"]
mod sync;
#[path = "jni_assist.rs"]
mod assist;
use std::sync::{Mutex, OnceLock};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jboolean, jint, jstring},
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::lan_pairing::AndroidLanPairing;
use crate::{AndroidRuntimeError, AndroidVaultRuntime};

static RUNTIME: OnceLock<Mutex<Option<AndroidVaultRuntime>>> = OnceLock::new();
static LAN_PAIRING: OnceLock<Mutex<Option<AndroidLanPairing>>> = OnceLock::new();

fn runtime() -> &'static Mutex<Option<AndroidVaultRuntime>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn lan_pairing() -> &'static Mutex<Option<AndroidLanPairing>> {
    LAN_PAIRING.get_or_init(|| Mutex::new(None))
}

fn close_lan_pairing() -> Result<(), AndroidRuntimeError> {
    let mut guard = lan_pairing().lock().map_err(|_| AndroidRuntimeError::Io)?;
    if let Some(mut service) = guard.take() {
        let mut vault = runtime().lock().map_err(|_| AndroidRuntimeError::Io)?;
        if let Some(vault) = vault.as_mut() {
            service.stop(vault);
        }
    }
    Ok(())
}

fn with_lan_result<T>(
    operation: impl FnOnce(
        &mut AndroidLanPairing,
        &mut AndroidVaultRuntime,
    ) -> Result<T, AndroidRuntimeError>,
) -> Result<T, AndroidRuntimeError> {
    let mut lan = lan_pairing().lock().map_err(|_| AndroidRuntimeError::Io)?;
    let service = lan.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?;
    let mut vault = runtime().lock().map_err(|_| AndroidRuntimeError::Io)?;
    operation(
        service,
        vault.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?,
    )
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
            const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
            struct BoundedJson(Vec<u8>);
            impl std::io::Write for BoundedJson {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    if bytes.len() > MAX_JSON_BYTES.saturating_sub(self.0.len()) {
                        return Err(std::io::Error::other("android_json_limit"));
                    }
                    self.0.extend_from_slice(bytes);
                    Ok(bytes.len())
                }

                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut output = BoundedJson(Vec::new());
            if serde_json::to_writer(&mut output, &value).is_err() {
                return r#"{"error":"io_error"}"#.into();
            }
            String::from_utf8(output.0).unwrap_or_else(|_| r#"{"error":"io_error"}"#.into())
        }
        Err(error) => format!(r#"{{"error":"{}"}}"#, error.code()),
    }
}

fn protected_result(
    env: &mut JNIEnv<'_>,
    result: Result<Zeroizing<String>, AndroidRuntimeError>,
) -> jstring {
    match result {
        Ok(value) => {
            let mut response = Zeroizing::new(String::from("value:"));
            response.push_str(&value);
            return_string(env, &response)
        }
        Err(error) => return_string(env, error.code()),
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
    sync::close();
    let _ = close_lan_pairing();
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
            if !guard
                .as_ref()
                .is_some_and(|current| current.vault_path == candidate.vault_path)
            {
                if let Some(current) = guard.as_mut() {
                    current.lock();
                }
                *guard = Some(candidate);
            }
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
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_changeMasterPassword(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    current_password: JString<'_>,
    new_password: JString<'_>,
) -> jstring {
    let (Ok(current), Ok(next)) = (
        read_secret(&mut env, current_password),
        read_secret(&mut env, new_password),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime(|runtime| {
        runtime.change_master_password(current.as_str(), next.as_str())?;
        Ok("ok")
    });
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_prepareBiometricUnlock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    protected_result(
        &mut env,
        with_runtime_result(|runtime| runtime.prepare_biometric_unlock()),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_unlockWithBiometricSecret(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    secret: JString<'_>,
) -> jstring {
    let Ok(secret) = read_secret(&mut env, secret) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.unlock_with_biometric_secret(&secret))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_disableBiometricUnlock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|runtime| runtime.disable_biometric_unlock())
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_pinStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|runtime| runtime.pin_status());
    return_string(&mut env, &json_result(result))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_enablePinUnlock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    pin: JString<'_>,
    device_secret: JString<'_>,
) -> jstring {
    let (Ok(pin), Ok(device_secret)) = (
        read_secret(&mut env, pin),
        read_secret(&mut env, device_secret),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.enable_pin_unlock(&pin, &device_secret))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_unlockWithPin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    pin: JString<'_>,
    device_secret: JString<'_>,
) -> jstring {
    let (Ok(pin), Ok(device_secret)) = (
        read_secret(&mut env, pin),
        read_secret(&mut env, device_secret),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.unlock_with_pin(&pin, &device_secret))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_disablePinUnlock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|runtime| runtime.disable_pin_unlock())
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_prepareEncryptedBackup(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_runtime_result(|runtime| runtime.prepare_encrypted_backup())
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_restoreStagedBackup(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    master_password: JString<'_>,
) -> jstring {
    let Ok(password) = read_secret(&mut env, master_password) else {
        return return_string(&mut env, "invalid_input");
    };
    sync::close();
    let result = with_runtime_result(|runtime| runtime.restore_staged_backup(password.as_str()))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lock(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let _ = close_lan_pairing();
    let result = sync::lock_vault().map(|_| "ok").unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    wrapping_key: JByteArray<'_>,
) -> jstring {
    let Ok(key) = env.convert_byte_array(&wrapping_key).map(Zeroizing::new) else {
        return return_string(&mut env, "invalid_input");
    };
    if key.len() != 32 {
        return return_string(&mut env, "invalid_input");
    }
    let mut fixed = Zeroizing::new([0u8; 32]);
    fixed.copy_from_slice(&key);
    let result = (|| {
        let mut lan = lan_pairing().lock().map_err(|_| AndroidRuntimeError::Io)?;
        let mut vault = runtime().lock().map_err(|_| AndroidRuntimeError::Io)?;
        let runtime = vault.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?;
        if let Some(mut previous) = lan.take() {
            previous.stop(runtime);
        }
        *lan = Some(AndroidLanPairing::open(runtime, *fixed)?);
        Ok::<_, AndroidRuntimeError>(())
    })();
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let response = json_result(with_lan_result(|lan, vault| lan.status(vault)));
    return_string(&mut env, &response)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let response = json_result(with_lan_result(|lan, vault| lan.start(vault)));
    return_string(&mut env, &response)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanStop(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = with_lan_result(|lan, vault| {
        if vault.status() != crate::RuntimeStatus::Unlocked {
            return Err(AndroidRuntimeError::Locked);
        }
        lan.stop(vault);
        Ok("ok")
    });
    return_string(&mut env, result.unwrap_or_else(AndroidRuntimeError::code))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanBegin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    reference: JString<'_>,
    code: JString<'_>,
) -> jstring {
    let (Ok(reference), Ok(code)) = (
        read_string(&mut env, reference),
        read_secret(&mut env, code),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_lan_result(|lan, vault| lan.begin(vault, &reference, code));
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = close_lan_pairing();
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanRevoke(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    reference: JString<'_>,
) -> jstring {
    let Ok(reference) = read_string(&mut env, reference) else {
        return return_string(&mut env, "invalid_input");
    };
    sync::close();
    let result = with_lan_result(|lan, vault| lan.revoke(vault, &reference));
    sync::close();
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_lanRename(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    reference: JString<'_>,
    label: JString<'_>,
) -> jstring {
    let (Ok(reference), Ok(label)) = (
        read_string(&mut env, reference),
        read_string(&mut env, label),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_lan_result(|lan, vault| lan.rename(vault, &reference, &label));
    return_string(
        &mut env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
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
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addLoginComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    url: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(username), Ok(mut password), Ok(url), Ok(extras_json)) = (
        read_string(&mut env, title),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_string(&mut env, url),
        read_secret(&mut env, extras_json),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::login_fields::parse_login_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_login_complete(
            title,
            username,
            std::mem::take(&mut *password),
            optional_string(url),
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateLoginComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    url: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(title), Ok(username), Ok(mut password), Ok(url), Ok(extras_json)) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_string(&mut env, url),
        read_secret(&mut env, extras_json),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::login_fields::parse_login_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_login_complete(
            &id,
            title,
            username,
            optional_string(std::mem::take(&mut *password)),
            optional_string(url),
            extras,
        )
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

macro_rules! jni_list {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(mut env: JNIEnv<'_>, _class: JClass<'_>) -> jstring {
            let json = json_result(with_runtime_result(|runtime| runtime.$method()));
            return_string(&mut env, &json)
        }
    };
}

macro_rules! jni_id_mutation {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            mut env: JNIEnv<'_>,
            _class: JClass<'_>,
            id: JString<'_>,
        ) -> jstring {
            let Ok(id) = read_string(&mut env, id) else {
                return return_string(&mut env, "invalid_input");
            };
            let result = with_runtime_result(|runtime| runtime.$method(&id))
                .map(|_| "ok")
                .unwrap_or_else(AndroidRuntimeError::code);
            return_string(&mut env, result)
        }
    };
}

macro_rules! jni_empty_mutation {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(mut env: JNIEnv<'_>, _class: JClass<'_>) -> jstring {
            let result = with_runtime_result(AndroidVaultRuntime::$method)
                .map(|_| "ok")
                .unwrap_or_else(AndroidRuntimeError::code);
            return_string(&mut env, result)
        }
    };
}

macro_rules! jni_history_list {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            mut env: JNIEnv<'_>,
            _class: JClass<'_>,
            id: JString<'_>,
        ) -> jstring {
            let Ok(id) = read_string(&mut env, id) else {
                return return_string(&mut env, "invalid_input");
            };
            let json = json_result(with_runtime_result(|runtime| runtime.$method(&id)));
            return_string(&mut env, &json)
        }
    };
}

macro_rules! jni_revision_mutation {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            mut env: JNIEnv<'_>,
            _class: JClass<'_>,
            id: JString<'_>,
            revision_id: JString<'_>,
        ) -> jstring {
            let (Ok(id), Ok(revision_id)) = (
                read_string(&mut env, id),
                read_string(&mut env, revision_id),
            ) else {
                return return_string(&mut env, "invalid_input");
            };
            let result = with_runtime_result(|runtime| runtime.$method(&id, &revision_id))
                .map(|_| "ok")
                .unwrap_or_else(AndroidRuntimeError::code);
            return_string(&mut env, result)
        }
    };
}

macro_rules! jni_protected_copy {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            mut env: JNIEnv<'_>,
            _class: JClass<'_>,
            id: JString<'_>,
            master_password: JString<'_>,
        ) -> jstring {
            let (Ok(id), Ok(password)) = (
                read_string(&mut env, id),
                read_secret(&mut env, master_password),
            ) else {
                return return_string(&mut env, "invalid_input");
            };
            let result = with_runtime_result(|runtime| runtime.$method(&id, password.as_str()));
            protected_result(&mut env, result)
        }
    };
}

jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listLoginHistory,
    list_login_history
);
jni_revision_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreLoginRevision,
    restore_login_revision
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_clearLoginHistory,
    clear_login_history
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listCardHistory,
    list_card_history
);
jni_revision_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreCardRevision,
    restore_card_revision
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_clearCardHistory,
    clear_card_history
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listSshHistory,
    list_ssh_history
);
jni_revision_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreSshRevision,
    restore_ssh_revision
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_clearSshHistory,
    clear_ssh_history
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listIdentityHistory,
    list_identity_history
);
jni_revision_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreIdentityRevision,
    restore_identity_revision
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_clearIdentityHistory,
    clear_identity_history
);

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_setLoginTotp(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    secret: JString<'_>,
    clear: jboolean,
) -> jstring {
    let (Ok(id), Ok(mut secret)) = (read_string(&mut env, id), read_secret(&mut env, secret))
    else {
        return return_string(&mut env, "invalid_input");
    };
    let replacement = (!secret.is_empty()).then(|| std::mem::take(&mut *secret));
    let result =
        with_runtime_result(|runtime| runtime.set_login_totp(&id, replacement, clear != 0))
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copyLoginTotpCode,
    copy_login_totp_code
);
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_setLoginRecoveryCodes(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    input: JString<'_>,
    clear: jboolean,
) -> jstring {
    let (Ok(id), Ok(mut input)) = (read_string(&mut env, id), read_secret(&mut env, input)) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.set_login_recovery_codes(&id, std::mem::take(&mut *input), clear != 0)
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_viewLoginRecoveryCodes(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    master_password: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(password)) = (
        read_string(&mut env, id),
        read_secret(&mut env, master_password),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.view_login_recovery_codes(&id, &password));
    protected_result(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_copyLoginRecoveryCode(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    index: jint,
    master_password: JString<'_>,
) -> jstring {
    if index < 0 {
        return return_string(&mut env, "invalid_input");
    }
    let (Ok(id), Ok(password)) = (
        read_string(&mut env, id),
        read_secret(&mut env, master_password),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.copy_login_recovery_code(&id, index as usize, &password)
    });
    protected_result(&mut env, result)
}
jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_passwordHealth,
    password_health
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_cardEditorDetail,
    card_editor_detail
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_loginEditorDetail,
    login_editor_detail
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_secretEditorDetail,
    secret_editor_detail
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_sshEditorDetail,
    ssh_editor_detail
);
jni_history_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_identityEditorDetail,
    identity_editor_detail
);

jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listCards,
    list_cards
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_deleteCard,
    delete_card
);
jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listCardTrash,
    list_card_trash
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreCard,
    restore_card
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_purgeCard,
    purge_card
);
jni_empty_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_emptyCardTrash,
    empty_card_trash
);

jni_list!(Java_com_vaultmesh_app_VaultNativeBridge_listSsh, list_ssh);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_deleteSsh,
    delete_ssh
);
jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listSshTrash,
    list_ssh_trash
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreSsh,
    restore_ssh
);
jni_id_mutation!(Java_com_vaultmesh_app_VaultNativeBridge_purgeSsh, purge_ssh);
jni_empty_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_emptySshTrash,
    empty_ssh_trash
);

jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listIdentities,
    list_identities
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_deleteIdentity,
    delete_identity
);
jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listIdentityTrash,
    list_identity_trash
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_restoreIdentity,
    restore_identity
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_purgeIdentity,
    purge_identity
);
jni_empty_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_emptyIdentityTrash,
    empty_identity_trash
);

jni_list!(
    Java_com_vaultmesh_app_VaultNativeBridge_listSecrets,
    list_secrets
);
jni_id_mutation!(
    Java_com_vaultmesh_app_VaultNativeBridge_deleteSecret,
    delete_secret
);

jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copyLoginPassword,
    copy_login_password
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copyCardNumber,
    copy_card_number
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copyCardSecurityCode,
    copy_card_security_code
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copyCardPin,
    copy_card_pin
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copySshPassword,
    copy_ssh_password
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copySshPublicKey,
    copy_ssh_public_key
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copySshPrivateKey,
    copy_ssh_private_key
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copySshKeyPassphrase,
    copy_ssh_key_passphrase
);
jni_protected_copy!(
    Java_com_vaultmesh_app_VaultNativeBridge_copySecretValue,
    copy_secret_value
);

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addCard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    cardholder_name: JString<'_>,
    card_number: JString<'_>,
    month: jint,
    year: jint,
    security_code: JString<'_>,
    pin: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(holder), Ok(mut number), Ok(month), Ok(year), Ok(mut code), Ok(mut pin)) = (
        read_string(&mut env, title),
        read_string(&mut env, cardholder_name),
        read_secret(&mut env, card_number),
        u8::try_from(month),
        u16::try_from(year),
        read_secret(&mut env, security_code),
        read_secret(&mut env, pin),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_card(
            title,
            holder,
            std::mem::take(&mut *number),
            month,
            year,
            optional_string(std::mem::take(&mut *code)),
            optional_string(std::mem::take(&mut *pin)),
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addCardComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    cardholder_name: JString<'_>,
    card_number: JString<'_>,
    month: jint,
    year: jint,
    security_code: JString<'_>,
    pin: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (
        Ok(title),
        Ok(holder),
        Ok(mut number),
        Ok(month),
        Ok(year),
        Ok(mut code),
        Ok(mut pin),
        Ok(extras_json),
    ) = (
        read_string(&mut env, title),
        read_string(&mut env, cardholder_name),
        read_secret(&mut env, card_number),
        u8::try_from(month),
        u16::try_from(year),
        read_secret(&mut env, security_code),
        read_secret(&mut env, pin),
        read_secret(&mut env, extras_json),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_card_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_card_complete(
            title,
            holder,
            std::mem::take(&mut *number),
            month,
            year,
            optional_string(std::mem::take(&mut *code)),
            optional_string(std::mem::take(&mut *pin)),
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateCard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    cardholder_name: JString<'_>,
    card_number: JString<'_>,
    month: jint,
    year: jint,
    security_code: JString<'_>,
    clear_security_code: jboolean,
    pin: JString<'_>,
    clear_pin: jboolean,
) -> jstring {
    let (
        Ok(id),
        Ok(title),
        Ok(holder),
        Ok(mut number),
        Ok(month),
        Ok(year),
        Ok(mut code),
        Ok(mut pin),
    ) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, cardholder_name),
        read_secret(&mut env, card_number),
        u8::try_from(month),
        u16::try_from(year),
        read_secret(&mut env, security_code),
        read_secret(&mut env, pin),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_card(
            &id,
            title,
            holder,
            optional_string(std::mem::take(&mut *number)),
            month,
            year,
            optional_string(std::mem::take(&mut *code)),
            clear_security_code != 0,
            optional_string(std::mem::take(&mut *pin)),
            clear_pin != 0,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateCardComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    cardholder_name: JString<'_>,
    card_number: JString<'_>,
    month: jint,
    year: jint,
    security_code: JString<'_>,
    clear_security_code: jboolean,
    pin: JString<'_>,
    clear_pin: jboolean,
    extras_json: JString<'_>,
) -> jstring {
    let (
        Ok(id),
        Ok(title),
        Ok(holder),
        Ok(mut number),
        Ok(month),
        Ok(year),
        Ok(mut code),
        Ok(mut pin),
        Ok(extras_json),
    ) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, cardholder_name),
        read_secret(&mut env, card_number),
        u8::try_from(month),
        u16::try_from(year),
        read_secret(&mut env, security_code),
        read_secret(&mut env, pin),
        read_secret(&mut env, extras_json),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_card_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_card_complete(
            &id,
            title,
            holder,
            optional_string(std::mem::take(&mut *number)),
            month,
            year,
            optional_string(std::mem::take(&mut *code)),
            clear_security_code != 0,
            optional_string(std::mem::take(&mut *pin)),
            clear_pin != 0,
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addSsh(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    host: JString<'_>,
    port: jint,
    username: JString<'_>,
    password: JString<'_>,
    public_key: JString<'_>,
    private_key: JString<'_>,
    key_passphrase: JString<'_>,
) -> jstring {
    let (
        Ok(title),
        Ok(host),
        Ok(port),
        Ok(username),
        Ok(mut password),
        Ok(mut public_key),
        Ok(mut private_key),
        Ok(mut passphrase),
    ) = (
        read_string(&mut env, title),
        read_string(&mut env, host),
        u16::try_from(port),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_secret(&mut env, public_key),
        read_secret(&mut env, private_key),
        read_secret(&mut env, key_passphrase),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_ssh(
            title,
            host,
            port,
            username,
            optional_string(std::mem::take(&mut *password)),
            optional_string(std::mem::take(&mut *public_key)),
            optional_string(std::mem::take(&mut *private_key)),
            optional_string(std::mem::take(&mut *passphrase)),
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateSsh(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    host: JString<'_>,
    port: jint,
    username: JString<'_>,
    password: JString<'_>,
    clear_password: jboolean,
    public_key: JString<'_>,
    clear_public_key: jboolean,
    private_key: JString<'_>,
    clear_private_key: jboolean,
    key_passphrase: JString<'_>,
    clear_key_passphrase: jboolean,
) -> jstring {
    let (
        Ok(id),
        Ok(title),
        Ok(host),
        Ok(port),
        Ok(username),
        Ok(mut password),
        Ok(mut public_key),
        Ok(mut private_key),
        Ok(mut passphrase),
    ) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, host),
        u16::try_from(port),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_secret(&mut env, public_key),
        read_secret(&mut env, private_key),
        read_secret(&mut env, key_passphrase),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_ssh(
            &id,
            title,
            host,
            port,
            username,
            optional_string(std::mem::take(&mut *password)),
            clear_password != 0,
            optional_string(std::mem::take(&mut *public_key)),
            clear_public_key != 0,
            optional_string(std::mem::take(&mut *private_key)),
            clear_private_key != 0,
            optional_string(std::mem::take(&mut *passphrase)),
            clear_key_passphrase != 0,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addSshComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    host: JString<'_>,
    port: jint,
    username: JString<'_>,
    password: JString<'_>,
    public_key: JString<'_>,
    private_key: JString<'_>,
    key_passphrase: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (
        Ok(title),
        Ok(host),
        Ok(port),
        Ok(username),
        Ok(mut password),
        Ok(mut public_key),
        Ok(mut private_key),
        Ok(mut passphrase),
        Ok(extras_json),
    ) = (
        read_string(&mut env, title),
        read_string(&mut env, host),
        u16::try_from(port),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_secret(&mut env, public_key),
        read_secret(&mut env, private_key),
        read_secret(&mut env, key_passphrase),
        read_secret(&mut env, extras_json),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_ssh_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_ssh_complete(
            title,
            host,
            port,
            username,
            optional_string(std::mem::take(&mut *password)),
            optional_string(std::mem::take(&mut *public_key)),
            optional_string(std::mem::take(&mut *private_key)),
            optional_string(std::mem::take(&mut *passphrase)),
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateSshComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    host: JString<'_>,
    port: jint,
    username: JString<'_>,
    password: JString<'_>,
    clear_password: jboolean,
    public_key: JString<'_>,
    clear_public_key: jboolean,
    private_key: JString<'_>,
    clear_private_key: jboolean,
    key_passphrase: JString<'_>,
    clear_key_passphrase: jboolean,
    extras_json: JString<'_>,
) -> jstring {
    let (
        Ok(id),
        Ok(title),
        Ok(host),
        Ok(port),
        Ok(username),
        Ok(mut password),
        Ok(mut public_key),
        Ok(mut private_key),
        Ok(mut passphrase),
        Ok(extras_json),
    ) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, host),
        u16::try_from(port),
        read_string(&mut env, username),
        read_secret(&mut env, password),
        read_secret(&mut env, public_key),
        read_secret(&mut env, private_key),
        read_secret(&mut env, key_passphrase),
        read_secret(&mut env, extras_json),
    )
    else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_ssh_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_ssh_complete(
            &id,
            title,
            host,
            port,
            username,
            optional_string(std::mem::take(&mut *password)),
            clear_password != 0,
            optional_string(std::mem::take(&mut *public_key)),
            clear_public_key != 0,
            optional_string(std::mem::take(&mut *private_key)),
            clear_private_key != 0,
            optional_string(std::mem::take(&mut *passphrase)),
            clear_key_passphrase != 0,
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_identityBasic(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
) -> jstring {
    let Ok(id) = read_string(&mut env, id) else {
        return return_string(&mut env, r#"{"error":"invalid_input"}"#);
    };
    let json = json_result(with_runtime_result(|runtime| runtime.identity_basic(&id)));
    return_string(&mut env, &json)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    first_name: JString<'_>,
    last_name: JString<'_>,
    organization: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(first_name), Ok(last_name), Ok(organization)) = (
        read_string(&mut env, title),
        read_string(&mut env, first_name),
        read_string(&mut env, last_name),
        read_string(&mut env, organization),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_identity(title, first_name, last_name, organization)
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    first_name: JString<'_>,
    last_name: JString<'_>,
    organization: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(title), Ok(first_name), Ok(last_name), Ok(organization)) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, first_name),
        read_string(&mut env, last_name),
        read_string(&mut env, organization),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_identity(&id, title, first_name, last_name, organization)
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addIdentityComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    input_json: JString<'_>,
) -> jstring {
    let Ok(input_json) = read_secret(&mut env, input_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(input) = crate::items::parse_identity_input_json(&input_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.add_identity_complete(input))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateIdentityComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    input_json: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(input_json)) = (read_string(&mut env, id), read_secret(&mut env, input_json))
    else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(input) = crate::items::parse_identity_input_json(&input_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| runtime.update_identity_complete(&id, input))
        .map(|_| "ok")
        .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addSecret(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    kind: JString<'_>,
    provider: JString<'_>,
    account: JString<'_>,
    value: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(kind), Ok(provider), Ok(account), Ok(mut value)) = (
        read_string(&mut env, title),
        read_string(&mut env, kind),
        read_string(&mut env, provider),
        read_string(&mut env, account),
        read_secret(&mut env, value),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_secret(title, &kind, provider, account, std::mem::take(&mut *value))
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_addSecretComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    title: JString<'_>,
    kind: JString<'_>,
    provider: JString<'_>,
    account: JString<'_>,
    value: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (Ok(title), Ok(kind), Ok(provider), Ok(account), Ok(mut value), Ok(extras_json)) = (
        read_string(&mut env, title),
        read_string(&mut env, kind),
        read_string(&mut env, provider),
        read_string(&mut env, account),
        read_secret(&mut env, value),
        read_secret(&mut env, extras_json),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_secret_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.add_secret_complete(
            title,
            &kind,
            provider,
            account,
            std::mem::take(&mut *value),
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateSecret(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    provider: JString<'_>,
    account: JString<'_>,
    value: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(title), Ok(provider), Ok(account), Ok(mut value)) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, provider),
        read_string(&mut env, account),
        read_secret(&mut env, value),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_secret(
            &id,
            title,
            provider,
            account,
            optional_string(std::mem::take(&mut *value)),
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_updateSecretComplete(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
    title: JString<'_>,
    provider: JString<'_>,
    account: JString<'_>,
    value: JString<'_>,
    extras_json: JString<'_>,
) -> jstring {
    let (Ok(id), Ok(title), Ok(provider), Ok(account), Ok(mut value), Ok(extras_json)) = (
        read_string(&mut env, id),
        read_string(&mut env, title),
        read_string(&mut env, provider),
        read_string(&mut env, account),
        read_secret(&mut env, value),
        read_secret(&mut env, extras_json),
    ) else {
        return return_string(&mut env, "invalid_input");
    };
    let Ok(extras) = crate::items::parse_secret_extras_json(&extras_json) else {
        return return_string(&mut env, "invalid_input");
    };
    let result = with_runtime_result(|runtime| {
        runtime.update_secret_complete(
            &id,
            title,
            provider,
            account,
            optional_string(std::mem::take(&mut *value)),
            extras,
        )
    })
    .map(|_| "ok")
    .unwrap_or_else(AndroidRuntimeError::code);
    return_string(&mut env, result)
}
