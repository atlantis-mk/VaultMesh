//! Safe password-health projection; core alone inspects Login passwords.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::{AndroidRuntimeError, AndroidVaultRuntime};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidPasswordHealth {
    pub score: u32,
    pub weak_item_ids: Vec<String>,
    pub reused_item_ids: Vec<String>,
    pub old_item_ids: Vec<String>,
}

impl AndroidVaultRuntime {
    pub fn password_health(&self) -> Result<AndroidPasswordHealth, AndroidRuntimeError> {
        let session = self.session.as_ref().ok_or(AndroidRuntimeError::Locked)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AndroidRuntimeError::Io)?
            .as_secs();
        let report = session.password_health(now)?;
        Ok(AndroidPasswordHealth {
            score: report.score,
            weak_item_ids: report
                .weak_item_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            reused_item_ids: report
                .reused_item_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            old_item_ids: report
                .old_item_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn health_report_is_id_only_and_locked_access_fails() {
        let dir = std::env::temp_dir().join(format!("vaultmesh-android-health-{}", Uuid::new_v4()));
        let mut runtime = AndroidVaultRuntime::new(&dir).unwrap();
        runtime.create("master-password").unwrap();
        runtime
            .add_login("One".into(), "alice".into(), "weak".into(), None)
            .unwrap();
        runtime
            .add_login("Two".into(), "bob".into(), "weak".into(), None)
            .unwrap();
        let report = runtime.password_health().unwrap();
        assert_eq!(report.score, 0);
        assert_eq!(report.weak_item_ids.len(), 2);
        assert_eq!(report.reused_item_ids.len(), 2);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("\"weak\""));
        assert!(!json.contains("alice"));
        runtime.lock();
        assert_eq!(
            runtime.password_health().unwrap_err(),
            AndroidRuntimeError::Locked
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
