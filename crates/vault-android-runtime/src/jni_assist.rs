//! Fixed platform adapter for device assist; never returns an OTP to Compose.
use super::*;
use crate::lan_credentials::AndroidLanCredentials;
use std::sync::Arc;
use vaultmesh_lan_pairing::assist::AssistHost;
static ASSIST: OnceLock<Mutex<Option<AssistHost>>> = OnceLock::new();
fn service() -> &'static Mutex<Option<AssistHost>> {
    ASSIST.get_or_init(|| Mutex::new(None))
}
fn with<T>(f: impl FnOnce(&mut AssistHost) -> Result<T, ()>) -> Result<T, AndroidRuntimeError> {
    let mut guard = service().lock().map_err(|_| AndroidRuntimeError::Io)?;
    f(guard.as_mut().ok_or(AndroidRuntimeError::NotInitialized)?)
        .map_err(|_| AndroidRuntimeError::InvalidInput)
}
fn reply(env: &mut JNIEnv<'_>, result: Result<(), AndroidRuntimeError>) -> jstring {
    return_string(
        env,
        result
            .map(|_| "ok")
            .unwrap_or_else(AndroidRuntimeError::code),
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistOpen(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    key: JByteArray<'_>,
) -> jstring {
    let result = (|| {
        let key = Zeroizing::new(
            env.convert_byte_array(&key)
                .map_err(|_| AndroidRuntimeError::InvalidInput)?,
        );
        if key.len() != 32 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let path = with_runtime_result(|r| Ok(r.vault_path.clone()))?;
        let directory = path.parent().ok_or(AndroidRuntimeError::Io)?;
        let mut fixed = Zeroizing::new([0; 32]);
        fixed.copy_from_slice(&key);
        let credentials = Arc::new(AndroidLanCredentials::new(directory.join("lan-pairing-secrets"), *fixed)
            .map_err(|_| AndroidRuntimeError::Io)?);
        let binding = with_runtime_result(|r| {
            if r.vault_path != path { return Err(AndroidRuntimeError::Locked); }
            r.open_assist_binding(credentials.clone())
        })?;
        let mut guard = service().lock().map_err(|_| AndroidRuntimeError::Io)?;
        if guard.as_ref().is_some_and(|s| s.matches_binding(&binding)) {
            return Ok(());
        }
        guard.take();
        let expected = binding.clone();
        let expected_path = path.clone();
        let valid = Arc::new(move || {
            with_runtime_result(|r| {
                use sha2::{Digest, Sha256};
                Ok(r.vault_path == expected_path
                    && r.assist_binding.as_ref() == Some(&expected)
                    && r.persisted_fingerprint.is_some_and(|fp| {
                        crate::read_vault(&r.vault_path)
                            .map(|b| Sha256::digest(b).as_slice() == fp)
                            .unwrap_or(false)
                    }))
            })
            .unwrap_or(false)
        });
        *guard = Some(
            AssistHost::new(
                directory.join("lan-pairing-peers.json"),
                credentials,
                binding,
                valid,
            )
            .map_err(|_| AndroidRuntimeError::Io)?,
        );
        Ok(())
    })();
    reply(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistStatus(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
) -> jstring {
    let result = with(|s| {
        Ok(
            serde_json::json!({"grants":s.grants()?.iter().map(|g|serde_json::json!({"peer":g.peer,"phone":g.phone,"sms":g.sms})).collect::<Vec<_>>(),"requests":s.pending()}),
        )
    });
    return_string(&mut env, &json_result(result))
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistGrant(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    peer: JString<'_>,
    phone: jboolean,
    sms: jboolean,
) -> jstring {
    let result = (|| {
        with_runtime_result(|r| {
            if r.session.is_some() {
                Ok(())
            } else {
                Err(AndroidRuntimeError::Locked)
            }
        })?;
        let peer = read_string(&mut env, peer).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        with(|s| s.set_grant(&peer, phone != 0, sms != 0))
    })();
    reply(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistTick(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    network: jboolean,
    phone: JString<'_>,
    sms_allowed: jboolean,
) -> jstring {
    let result = (|| {
        let phone = read_secret(&mut env, phone).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        with(|s| {
            if network == 0 {
                s.stop();
                return Ok(());
            }
            s.set_phone(&phone)?;
            if sms_allowed == 0 {
                s.clear_sms();
            }
            s.start()
        })
    })();
    reply(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistStop(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
) -> jstring {
    let result = with(|s| {
        s.stop();
        Ok(())
    });
    reply(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vaultmesh_app_VaultNativeBridge_assistCode(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    code: JString<'_>,
    source: JString<'_>,
    age: jni::sys::jlong,
    dedup: JString<'_>,
    request: JString<'_>,
) -> jstring {
    let result = (|| {
        let code = read_secret(&mut env, code).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let source =
            read_string(&mut env, source).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let dedup = read_string(&mut env, dedup).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let request =
            read_string(&mut env, request).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        if age < 0 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        with(|s| {
            s.add_code(
                &code,
                &source,
                age as u64,
                &dedup,
                if request.is_empty() {
                    None
                } else {
                    Some(&request)
                },
            )
        })
    })();
    reply(&mut env, result)
}
