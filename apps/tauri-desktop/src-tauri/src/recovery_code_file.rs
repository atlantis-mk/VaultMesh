use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAX_RECOVERY_CODE_FILE_BYTES: u64 = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceFileStatus {
    Deleted,
    Kept,
    Failed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeFileResult {
    pub codes: Vec<String>,
    pub file_name: String,
    pub source_file_status: SourceFileStatus,
}

pub struct PreparedRecoveryCodeFile {
    path: PathBuf,
    digest: [u8; 32],
    codes: Vec<String>,
    file_name: String,
}

/// Contains no codes. Only the privileged desktop owns this bounded cleanup target.
pub struct RecoveryFileCleanup {
    path: PathBuf,
    digest: [u8; 32],
    pub file_name: String,
    pub expires_at: i64,
}

impl RecoveryFileCleanup {
    pub fn finish(self, confirmed: bool, now: i64) -> SourceFileStatus {
        if confirmed && now < self.expires_at {
            delete_unchanged_file(&self.path, self.digest)
        } else {
            SourceFileStatus::Kept
        }
    }
}

#[derive(Default)]
pub struct RecoveryFileCleanupSessions(HashMap<Uuid, RecoveryFileCleanup>);

impl RecoveryFileCleanupSessions {
    pub fn stage(
        &mut self,
        prepared: PreparedRecoveryCodeFile,
        now: i64,
    ) -> Result<(RecoveryCodeFileResult, Uuid, i64), String> {
        self.0.retain(|_, entry| entry.expires_at > now);
        if self.0.len() >= 4 {
            return Err("待完成的恢复码导入过多，请稍后重试。".into());
        }
        let id = Uuid::new_v4();
        let expires_at = now.saturating_add(5 * 60_000);
        self.0.insert(
            id,
            RecoveryFileCleanup {
                path: prepared.path,
                digest: prepared.digest,
                file_name: prepared.file_name.clone(),
                expires_at,
            },
        );
        Ok((
            RecoveryCodeFileResult {
                codes: prepared.codes,
                file_name: prepared.file_name,
                source_file_status: SourceFileStatus::Kept,
            },
            id,
            expires_at,
        ))
    }
    pub fn take(&mut self, id: Uuid, now: i64) -> Result<RecoveryFileCleanup, String> {
        self.0.retain(|_, entry| entry.expires_at > now);
        self.0
            .remove(&id)
            .ok_or_else(|| "导入文件清理已过期或已处理，原文件保持不变。".into())
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl PreparedRecoveryCodeFile {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| "无法读取恢复码文件。".to_owned())?;
        validate_file(metadata.file_type().is_file(), metadata.len())?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "恢复码文件名称无效。".to_owned())?
            .to_owned();
        let bytes =
            Zeroizing::new(std::fs::read(&path).map_err(|_| "无法读取恢复码文件。".to_owned())?);
        validate_file(true, bytes.len() as u64)?;
        let digest = Sha256::digest(bytes.as_slice()).into();
        let codes = parse_recovery_code_file(bytes.as_slice())?;
        Ok(Self {
            path,
            digest,
            codes,
            file_name,
        })
    }

    pub fn code_count(&self) -> usize {
        self.codes.len()
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn finish(self, delete_confirmed: bool) -> RecoveryCodeFileResult {
        let source_file_status = if delete_confirmed {
            delete_unchanged_file(&self.path, self.digest)
        } else {
            SourceFileStatus::Kept
        };
        RecoveryCodeFileResult {
            codes: self.codes,
            file_name: self.file_name,
            source_file_status,
        }
    }
}

pub fn parse_recovery_code_file(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() as u64 > MAX_RECOVERY_CODE_FILE_BYTES {
        return Err(file_limit_message());
    }
    let contents =
        std::str::from_utf8(bytes).map_err(|_| "恢复码文件必须使用 UTF-8 编码。".to_owned())?;
    if let Some(codes) = parse_numbered_google_codes(contents)? {
        return Ok(codes);
    }
    let mut codes = Zeroizing::new(Vec::new());
    for (index, raw_line) in contents.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let line = if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        if line.trim().is_empty() {
            continue;
        }
        if line.encode_utf16().count() > 256 {
            return Err("每个恢复码不得超过 256 个字符。".to_owned());
        }
        if codes.len() == 100 {
            return Err("恢复码文件最多包含 100 个非空恢复码。".to_owned());
        }
        codes.push(line.to_owned());
    }
    if codes.is_empty() {
        return Err("恢复码文件中没有可用的恢复码。".to_owned());
    }
    Ok(std::mem::take(&mut *codes))
}

fn parse_numbered_google_codes(contents: &str) -> Result<Option<Vec<String>>, String> {
    let mut numbered_codes = Zeroizing::new(Vec::<(usize, String)>::new());
    for (index, raw_line) in contents.split('\n').enumerate() {
        let line = normalized_line(index, raw_line);
        let Some(entries) = parse_numbered_google_line(line) else {
            continue;
        };
        numbered_codes.extend(entries);
    }
    if numbered_codes.len() < 2 {
        return Ok(None);
    }

    numbered_codes.sort_unstable_by_key(|(index, _)| *index);
    if numbered_codes.len() > 100
        || numbered_codes
            .iter()
            .enumerate()
            .any(|(offset, (index, _))| *index != offset + 1)
    {
        return Err("检测到编号恢复码表，但编号不完整或重复。".to_owned());
    }

    let mut codes = Zeroizing::new(Vec::with_capacity(numbered_codes.len()));
    for (_, code) in std::mem::take(&mut *numbered_codes) {
        codes.push(code);
    }
    Ok(Some(std::mem::take(&mut *codes)))
}

fn parse_numbered_google_line(line: &str) -> Option<Vec<(usize, String)>> {
    let columns = line.split_whitespace().collect::<Vec<_>>();
    if columns.is_empty() || columns.len() % 3 != 0 {
        return None;
    }

    let mut entries = Vec::with_capacity(columns.len() / 3);
    for entry in columns.chunks_exact(3) {
        let ordinal = entry[0].strip_suffix('.')?;
        if ordinal.is_empty() || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let index = ordinal.parse::<usize>().ok()?;
        if index == 0
            || entry[1].len() != 4
            || entry[2].len() != 4
            || !entry[1].bytes().all(|byte| byte.is_ascii_digit())
            || !entry[2].bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        entries.push((index, format!("{} {}", entry[1], entry[2])));
    }
    Some(entries)
}

fn normalized_line(index: usize, raw_line: &str) -> &str {
    let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
    if index == 0 {
        line.strip_prefix('\u{feff}').unwrap_or(line)
    } else {
        line
    }
}

fn validate_file(is_file: bool, size: u64) -> Result<(), String> {
    if !is_file || size > MAX_RECOVERY_CODE_FILE_BYTES {
        Err(file_limit_message())
    } else {
        Ok(())
    }
}

fn file_limit_message() -> String {
    "恢复码文件必须是不超过 32 KiB 的普通文件。".to_owned()
}

fn delete_unchanged_file(path: &Path, expected_digest: [u8; 32]) -> SourceFileStatus {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return SourceFileStatus::Failed;
    };
    if validate_file(metadata.file_type().is_file(), metadata.len()).is_err() {
        return SourceFileStatus::Failed;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return SourceFileStatus::Failed;
    };
    let unchanged = Sha256::digest(&bytes).as_slice() == expected_digest;
    drop(Zeroizing::new(bytes));
    if !unchanged {
        return SourceFileStatus::Failed;
    }
    if std::fs::remove_file(path).is_ok() {
        SourceFileStatus::Deleted
    } else {
        SourceFileStatus::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utf8_bom_crlf_and_preserves_non_empty_content() {
        assert_eq!(
            parse_recovery_code_file("\u{feff}alpha\r\n\r\n beta code \n\t\ncharlie".as_bytes())
                .expect("parse"),
            vec!["alpha", " beta code ", "charlie"]
        );
    }

    #[test]
    fn parses_google_numbered_two_column_export_without_boilerplate() {
        let contents = concat!(
            "备用验证码\r\n",
            "请妥善保存这些代码\r\n",
            "\r\n",
            "1. 1111 0001   6. 6666 0006\r\n",
            "2. 2222 0002   7. 7777 0007\r\n",
            "3. 3333 0003   8. 8888 0008\r\n",
            "4. 4444 0004   9. 9999 0009\r\n",
            "5. 5555 0005  10. 1010 0010\r\n",
            "\r\n",
            "* account.example.test\r\n",
            "* 每个验证码只能使用一次\r\n",
        );

        assert_eq!(
            parse_recovery_code_file(contents.as_bytes()).expect("parse Google export"),
            vec![
                "1111 0001",
                "2222 0002",
                "3333 0003",
                "4444 0004",
                "5555 0005",
                "6666 0006",
                "7777 0007",
                "8888 0008",
                "9999 0009",
                "1010 0010",
            ]
        );
    }

    #[test]
    fn rejects_incomplete_or_duplicate_google_numbered_tables() {
        assert!(parse_recovery_code_file(b"1. 1111 0001\n3. 3333 0003\n").is_err());
        assert!(parse_recovery_code_file(b"1. 1111 0001\n1. 2222 0002\n").is_err());
    }

    #[test]
    fn rejects_invalid_or_oversized_recovery_code_files() {
        assert!(parse_recovery_code_file(&[0xff, 0xfe]).is_err());
        assert!(parse_recovery_code_file(b"\n\t\r\n").is_err());
        assert!(parse_recovery_code_file("x\n".repeat(101).as_bytes()).is_err());
        assert!(parse_recovery_code_file("x".repeat(257).as_bytes()).is_err());
        assert!(
            parse_recovery_code_file(&vec![b'x'; MAX_RECOVERY_CODE_FILE_BYTES as usize + 1])
                .is_err()
        );
    }

    #[test]
    fn deletes_only_the_unchanged_selected_file_after_confirmation() {
        let root = std::env::temp_dir().join(format!(
            "vaultmesh-recovery-code-file-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("create temp root");
        let deleted_path = root.join("delete.txt");
        std::fs::write(&deleted_path, b"alpha\nbeta\n").expect("write delete fixture");
        let prepared = PreparedRecoveryCodeFile::load(deleted_path.clone()).expect("prepare");
        let result = prepared.finish(true);
        assert_eq!(result.source_file_status, SourceFileStatus::Deleted);
        assert!(!deleted_path.exists());

        let changed_path = root.join("changed.txt");
        std::fs::write(&changed_path, b"alpha\n").expect("write changed fixture");
        let prepared = PreparedRecoveryCodeFile::load(changed_path.clone()).expect("prepare");
        std::fs::write(&changed_path, b"replacement\n").expect("replace fixture");
        let result = prepared.finish(true);
        assert_eq!(result.source_file_status, SourceFileStatus::Failed);
        assert!(changed_path.exists());

        let kept_path = root.join("kept.txt");
        std::fs::write(&kept_path, b"alpha\n").expect("write kept fixture");
        let result = PreparedRecoveryCodeFile::load(kept_path.clone())
            .expect("prepare")
            .finish(false);
        assert_eq!(result.source_file_status, SourceFileStatus::Kept);
        assert!(kept_path.exists());

        std::fs::remove_file(changed_path).expect("cleanup changed fixture");
        std::fs::remove_file(kept_path).expect("cleanup kept fixture");
        std::fs::remove_dir(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_recovery_code_files() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "vaultmesh-recovery-code-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("create temp root");
        let target = root.join("target.txt");
        let link = root.join("link.txt");
        std::fs::write(&target, b"alpha\n").expect("write target");
        symlink(&target, &link).expect("create symlink");
        assert!(PreparedRecoveryCodeFile::load(link.clone()).is_err());
        assert!(target.exists());
        std::fs::remove_file(link).expect("cleanup link");
        std::fs::remove_file(target).expect("cleanup target");
        std::fs::remove_dir(root).expect("cleanup temp root");
    }

    #[test]
    fn staged_cleanup_is_bounded_one_use_and_never_deletes_on_cancel_expiry_or_revoke() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-staged-recovery-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("synthetic.txt");
        std::fs::write(&path, b"synthetic-alpha\n synthetic-beta \n").unwrap();
        let mut sessions = RecoveryFileCleanupSessions::default();
        let (result, id, expiry) = sessions
            .stage(PreparedRecoveryCodeFile::load(path.clone()).unwrap(), 1000)
            .unwrap();
        assert!(path.exists());
        assert_eq!(result.source_file_status, SourceFileStatus::Kept);
        assert_eq!(result.codes, vec!["synthetic-alpha", " synthetic-beta "]);
        let ticket = sessions.take(id, 1001).unwrap();
        assert!(sessions.take(id, 1001).is_err());
        assert_eq!(ticket.finish(true, expiry), SourceFileStatus::Kept);
        assert!(path.exists());
        let (_, id, _) = sessions
            .stage(PreparedRecoveryCodeFile::load(path.clone()).unwrap(), 1000)
            .unwrap();
        assert_eq!(
            sessions.take(id, 1001).unwrap().finish(false, 1002),
            SourceFileStatus::Kept
        );
        let (_, id, _) = sessions
            .stage(PreparedRecoveryCodeFile::load(path.clone()).unwrap(), 1000)
            .unwrap();
        sessions.clear();
        assert!(sessions.take(id, 1001).is_err());
        for _ in 0..4 {
            sessions
                .stage(PreparedRecoveryCodeFile::load(path.clone()).unwrap(), 1000)
                .unwrap();
        }
        assert!(
            sessions
                .stage(PreparedRecoveryCodeFile::load(path.clone()).unwrap(), 1000)
                .is_err()
        );
        let (_, id, _) = sessions
            .stage(
                PreparedRecoveryCodeFile::load(path.clone()).unwrap(),
                expiry,
            )
            .unwrap();
        std::fs::write(&path, b"changed-content\n").unwrap();
        assert_eq!(
            sessions
                .take(id, expiry + 1)
                .unwrap()
                .finish(true, expiry + 2),
            SourceFileStatus::Failed
        );
        assert!(path.exists());
        let (_, id, _) = sessions
            .stage(
                PreparedRecoveryCodeFile::load(path.clone()).unwrap(),
                expiry + 3,
            )
            .unwrap();
        assert_eq!(
            sessions
                .take(id, expiry + 4)
                .unwrap()
                .finish(true, expiry + 5),
            SourceFileStatus::Deleted
        );
        assert!(!path.exists());
        std::fs::remove_dir(root).unwrap();
    }
}
