//! A sealed routing proof for locked assist restart; never an unlock capability.
use super::*;
use crate::lan_credentials::AndroidLanCredentials;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vaultmesh_lan_pairing::CredentialStore;

const RECORD: &str = "device-assist-resume-v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeProof {
    version: u8,
    binding: String,
    fingerprint: [u8; 32],
}

impl AndroidVaultRuntime {
    pub(crate) fn open_assist_binding(&mut self, credentials: Arc<AndroidLanCredentials>) -> Result<String, AndroidRuntimeError> {
        let fingerprint: [u8; 32] = Sha256::digest(read_vault(&self.vault_path)?).into();
        let binding = if self.session.is_some() {
            if self.persisted_fingerprint != Some(fingerprint) { return Err(AndroidRuntimeError::Locked); }
            let binding = self.assist_binding.clone().ok_or(AndroidRuntimeError::Locked)?;
            let proof = ResumeProof { version: 1, binding: binding.clone(), fingerprint };
            credentials.set(RECORD, &serde_json::to_vec(&proof).map_err(|_| AndroidRuntimeError::Io)?)
                .map_err(|_| AndroidRuntimeError::Io)?;
            binding
        } else {
            let bytes = credentials.get(RECORD).map_err(|_| AndroidRuntimeError::Locked)?
                .ok_or(AndroidRuntimeError::Locked)?;
            let proof: ResumeProof = serde_json::from_slice(&bytes).map_err(|_| AndroidRuntimeError::Locked)?;
            let valid_binding = proof.binding.split_once(':').is_some_and(|(vault, replica)|
                Uuid::parse_str(vault).is_ok() && Uuid::parse_str(replica).is_ok());
            if proof.version != 1 || !valid_binding || proof.fingerprint != fingerprint {
                return Err(AndroidRuntimeError::Locked);
            }
            proof.binding
        };
        self.assist_binding = Some(binding.clone());
        self.persisted_fingerprint = Some(fingerprint);
        self.assist_resume_credentials = Some(credentials);
        Ok(binding)
    }

    // Only called after a successful Vault commit/session replacement. Failure
    // leaves a stale proof whose fingerprint cannot authorize a cold restart.
    pub(crate) fn checkpoint_assist_resume(&self) {
        let Some(credentials) = &self.assist_resume_credentials else { return; };
        let result = (|| -> Result<(), ()> {
            let bytes = credentials.get(RECORD)?.ok_or(())?;
            let old: ResumeProof = serde_json::from_slice(&bytes).map_err(|_| ())?;
            let binding = self.assist_binding.as_ref().ok_or(())?;
            if old.binding != *binding { return credentials.delete(RECORD); }
            let proof = ResumeProof { version: 1, binding: binding.clone(), fingerprint: self.persisted_fingerprint.ok_or(())? };
            credentials.set(RECORD, &serde_json::to_vec(&proof).map_err(|_| ())?)
        })();
        if result.is_err() { let _ = credentials.delete(RECORD); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, Arc<AndroidLanCredentials>, AndroidVaultRuntime) {
        let dir = std::env::temp_dir().join(format!("vaultmesh-assist-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let credentials = Arc::new(AndroidLanCredentials::new(dir.join("credentials"), [7; 32]).unwrap());
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("synthetic-assist-master").unwrap();
        (dir, credentials, runtime)
    }
    #[test]
    fn cold_restart_uses_sealed_proof_without_unlocking_or_inheriting_grants() {
        let (dir, credentials, mut runtime) = fixture();
        let mut cold = AndroidVaultRuntime::new(&dir).unwrap();
        assert_eq!(cold.open_assist_binding(credentials.clone()), Err(AndroidRuntimeError::Locked));
        let binding = runtime.open_assist_binding(credentials.clone()).unwrap();
        drop(runtime);
        assert_eq!(cold.open_assist_binding(credentials.clone()).unwrap(), binding);
        assert_eq!(cold.status(), RuntimeStatus::Locked);
        assert!(cold.list_logins().is_err());
        let wrong = Arc::new(AndroidLanCredentials::new(dir.join("credentials"), [8; 32]).unwrap());
        assert!(AndroidVaultRuntime::new(&dir).unwrap().open_assist_binding(wrong).is_err());
        credentials.set(RECORD, b"corrupt").unwrap();
        assert!(AndroidVaultRuntime::new(&dir).unwrap().open_assist_binding(credentials).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn commits_refresh_proof_and_replacement_or_rollback_fails_closed() {
        let (dir, credentials, mut runtime) = fixture();
        let binding = runtime.open_assist_binding(credentials.clone()).unwrap();
        let old_vault = fs::read(&runtime.vault_path).unwrap();
        runtime.add_login("synthetic".into(), "test".into(), "secret".into(), Some("https://example.test".into())).unwrap();
        let mut cold = AndroidVaultRuntime::new(&dir).unwrap();
        assert_eq!(cold.open_assist_binding(credentials.clone()).unwrap(), binding);
        fs::write(&runtime.vault_path, &old_vault).unwrap();
        assert!(AndroidVaultRuntime::new(&dir).unwrap().open_assist_binding(credentials.clone()).is_err());
        let replacement = VaultSession::create("synthetic-replacement").unwrap();
        write_vault(&runtime.vault_path, &replacement.save().unwrap()).unwrap();
        runtime.replace_session(replacement);
        assert!(credentials.get(RECORD).unwrap().is_none());
        assert!(AndroidVaultRuntime::new(&dir).unwrap().open_assist_binding(credentials).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
