//! Login recovery-code operations. Secret values only leave through explicit reauthentication.

use uuid::Uuid;
use vaultmesh_core::LoginItemUpdate;
use zeroize::Zeroizing;

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

const MAX_INPUT_BYTES: usize = 32 * 1024;

fn parse_codes(input: &str) -> Result<Vec<String>, AndroidRuntimeError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    if let Some(codes) = parse_numbered_google_codes(input)? {
        return Ok(codes);
    }
    let lines = input.split('\n').enumerate().map(|(index, raw)| {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        }
    });
    let mut codes = Zeroizing::new(Vec::new());
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if line.encode_utf16().count() > 256 || codes.len() == 100 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        codes.push(line.to_owned());
    }
    if codes.is_empty() {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(std::mem::take(&mut *codes))
}

fn parse_numbered_google_codes(input: &str) -> Result<Option<Vec<String>>, AndroidRuntimeError> {
    let mut numbered = Zeroizing::new(Vec::<(usize, String)>::new());
    for (line_index, raw) in input.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let line = if line_index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.is_empty() || columns.len() % 3 != 0 {
            continue;
        }
        let mut entries = Vec::new();
        for parts in columns.chunks_exact(3) {
            let Some(ordinal) = parts[0].strip_suffix('.') else {
                entries.clear();
                break;
            };
            let Some(index) = ordinal.parse::<usize>().ok().filter(|index| *index > 0) else {
                entries.clear();
                break;
            };
            if parts[1].len() != 4
                || parts[2].len() != 4
                || !parts[1].bytes().all(|byte| byte.is_ascii_digit())
                || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
            {
                entries.clear();
                break;
            }
            entries.push((index, format!("{} {}", parts[1], parts[2])));
        }
        numbered.extend(entries);
    }
    if numbered.len() < 2 {
        return Ok(None);
    }
    numbered.sort_unstable_by_key(|(index, _)| *index);
    if numbered.len() > 100
        || numbered
            .iter()
            .enumerate()
            .any(|(offset, (index, _))| *index != offset + 1)
    {
        return Err(AndroidRuntimeError::InvalidInput);
    }
    Ok(Some(numbered.drain(..).map(|(_, code)| code).collect()))
}

impl AndroidVaultRuntime {
    pub fn set_login_recovery_codes(
        &mut self,
        id: &str,
        input: String,
        clear: bool,
    ) -> Result<(), AndroidRuntimeError> {
        let mut input = Zeroizing::new(input);
        if clear == !input.is_empty() {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        let mut codes = Zeroizing::new(if clear {
            Vec::new()
        } else {
            parse_codes(&input)?
        });
        input.clear();
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        self.mutate_and_commit(|session| {
            let current = session.item_detail(id)?;
            session.update_item(LoginItemUpdate {
                id,
                title: current.title,
                username: current.username,
                password: None,
                url: current.url,
                notes: current.notes,
                folder: current.folder,
                favorite: current.favorite,
                totp_secret: None,
                clear_totp_secret: false,
                recovery_codes: (!clear).then(|| std::mem::take(&mut *codes)),
                clear_recovery_codes: clear,
                additional_urls: current.additional_urls,
                autofill_on_page_load: current.autofill_on_page_load,
                master_password_reprompt: current.master_password_reprompt,
                custom_fields: current.custom_fields,
            })?;
            Ok(())
        })
    }

    pub fn view_login_recovery_codes(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let codes = session.recovery_codes_for_access(id, Some(master_password))?;
        let serialized = serde_json::to_string(codes).map_err(|_| AndroidRuntimeError::Io)?;
        if serialized.len() > MAX_INPUT_BYTES * 2 {
            return Err(AndroidRuntimeError::InvalidInput);
        }
        Ok(Zeroizing::new(serialized))
    }

    pub fn copy_login_recovery_code(
        &self,
        id: &str,
        index: usize,
        master_password: &str,
    ) -> Result<Zeroizing<String>, AndroidRuntimeError> {
        let id = Uuid::parse_str(id).map_err(|_| AndroidRuntimeError::InvalidInput)?;
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let codes = session.recovery_codes_for_access(id, Some(master_password))?;
        let code = codes
            .get(index)
            .ok_or(AndroidRuntimeError::ValueUnavailable)?;
        Ok(Zeroizing::new(code.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FAIL_NEXT_WRITE, VAULT_FILE_NAME};
    use std::fs;

    #[test]
    fn recovery_codes_require_reauthentication_and_commit_atomically() {
        let dir =
            std::env::temp_dir().join(format!("vaultmesh-android-recovery-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("vault-password").unwrap();
        runtime
            .add_login("Login".into(), "alice".into(), "secret".into(), None)
            .unwrap();
        let id = runtime.list_logins().unwrap()[0].id.clone();
        assert_eq!(
            runtime.set_login_recovery_codes(&id, " \n".into(), false),
            Err(AndroidRuntimeError::InvalidInput)
        );
        runtime
            .set_login_recovery_codes(&id, "first\r\n\nsecond".into(), false)
            .unwrap();
        assert!(runtime.list_logins().unwrap()[0].has_recovery_codes);
        assert_eq!(
            runtime.view_login_recovery_codes(&id, "wrong"),
            Err(AndroidRuntimeError::UnlockFailed)
        );
        assert_eq!(
            runtime
                .view_login_recovery_codes(&id, "vault-password")
                .unwrap()
                .as_str(),
            "[\"first\",\"second\"]"
        );
        assert_eq!(
            runtime
                .copy_login_recovery_code(&id, 1, "vault-password")
                .unwrap()
                .as_str(),
            "second"
        );
        assert_eq!(
            runtime.copy_login_recovery_code(&id, 2, "vault-password"),
            Err(AndroidRuntimeError::ValueUnavailable)
        );
        let before = fs::read(dir.join(VAULT_FILE_NAME)).unwrap();
        FAIL_NEXT_WRITE.with(|flag| flag.set(true));
        assert_eq!(
            runtime.set_login_recovery_codes(&id, "replacement".into(), false),
            Err(AndroidRuntimeError::Io)
        );
        assert_eq!(fs::read(dir.join(VAULT_FILE_NAME)).unwrap(), before);
        assert_eq!(
            runtime
                .copy_login_recovery_code(&id, 0, "vault-password")
                .unwrap()
                .as_str(),
            "first"
        );
        runtime
            .set_login_recovery_codes(&id, "".into(), true)
            .unwrap();
        runtime.lock();
        assert_eq!(
            runtime.view_login_recovery_codes(&id, "vault-password"),
            Err(AndroidRuntimeError::Locked)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovery_parser_accepts_google_table_and_rejects_broken_numbering() {
        assert_eq!(
            parse_codes("Header\n1. 1111 0001 2. 2222 0002\n").unwrap(),
            vec!["1111 0001", "2222 0002"]
        );
        assert_eq!(
            parse_codes("1. 1111 0001\n3. 3333 0003"),
            Err(AndroidRuntimeError::InvalidInput)
        );
        assert_eq!(
            parse_codes(&"x\n".repeat(101)),
            Err(AndroidRuntimeError::InvalidInput)
        );
        assert_eq!(
            parse_codes(&"x".repeat(257)),
            Err(AndroidRuntimeError::InvalidInput)
        );
    }
}
