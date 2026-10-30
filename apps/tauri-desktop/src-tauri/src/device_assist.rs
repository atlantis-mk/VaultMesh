use crate::{
    browser_broker::BrowserPlatformError,
    browser_fill::{device_assignment, validate_device_discovery},
};
use serde_json::{json, Map, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use vaultmesh_lan_pairing::assist::{AssistClient, Kind};
use vaultmesh_lan_pairing::CredentialStore;
struct Request {
    discovery: Value,
    kind: Kind,
    expires: i64,
    selected: bool,
}
pub struct DeviceAssistBroker {
    path: PathBuf,
    credentials: Arc<dyn CredentialStore>,
    client: Option<AssistClient>,
    scope: Option<String>,
    requests: HashMap<String, Request>,
}
fn error() -> BrowserPlatformError {
    BrowserPlatformError {
        code: "invalid-input",
        message: "设备互通请求不可用或已失效，请重新打开候选。".into(),
    }
}
impl DeviceAssistBroker {
    pub fn new(path: PathBuf, credentials: Arc<dyn CredentialStore>) -> Self {
        Self {
            path,
            credentials,
            client: None,
            scope: None,
            requests: HashMap::new(),
        }
    }
    pub fn prepare(&mut self, scope: String) -> Result<(), BrowserPlatformError> {
        if self.scope.as_ref() == Some(&scope) && self.client.is_some() {
            return Ok(());
        }
        self.clear();
        let mut client =
            AssistClient::with_credentials(self.path.clone(), self.credentials.clone())
                .map_err(|_| error())?;
        client.enable_registration(&scope).map_err(|_| error())?;
        self.client = Some(client);
        self.scope = Some(scope);
        Ok(())
    }
    pub fn clear(&mut self) {
        self.requests.clear();
        self.client.take();
        self.scope = None;
    }
    pub fn dispatch(
        &mut self,
        op: &str,
        input: &Map<String, Value>,
        now: i64,
    ) -> Result<Value, BrowserPlatformError> {
        let expired: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.requests.remove(&id);
            if let Some(c) = &self.client {
                c.cancel(&id);
            }
        }
        if op == "device.assist.capabilities" {
            return Ok(json!({"version":1,"phone":true,"sms":true}));
        }
        if op == "device.assist.start" {
            if self.requests.len() >= 32 {
                return Err(error());
            }
            let kind: Kind = serde_json::from_value(input.get("kind").cloned().ok_or_else(error)?)
                .map_err(|_| error())?;
            let discovery = input.get("discovery").cloned().ok_or_else(error)?;
            validate_device_discovery(&discovery, kind, now)?;
            let origin = discovery
                .get("topOrigin")
                .and_then(Value::as_str)
                .ok_or_else(error)?;
            let expires = chrono::DateTime::parse_from_rfc3339(
                discovery
                    .get("expiresAt")
                    .and_then(Value::as_str)
                    .ok_or_else(error)?,
            )
            .map_err(|_| error())?
            .timestamp_millis();
            if self.client.is_none() {
                self.client = Some(
                    AssistClient::with_credentials(self.path.clone(), self.credentials.clone())
                        .map_err(|_| error())?,
                );
            }
            let id = self
                .client
                .as_ref()
                .unwrap()
                .begin(kind, origin)
                .map_err(|_| error())?;
            self.requests.insert(
                id.clone(),
                Request {
                    discovery,
                    kind,
                    expires,
                    selected: false,
                },
            );
            return Ok(json!({"id":id}));
        }
        let id = input
            .get("id")
            .and_then(Value::as_str)
            .filter(|v| v.len() == 32)
            .ok_or_else(error)?;
        let r = self.requests.get_mut(id).ok_or_else(error)?;
        let c = self.client.as_ref().ok_or_else(error)?;
        match op {
            "device.assist.poll" => {
                let status = c.status(id).map_err(|_| error())?;
                if !r.selected {
                    c.refresh(id).map_err(|_| error())?;
                }
                Ok(status)
            }
            "device.assist.select" => {
                if r.selected {
                    return Err(error());
                }
                validate_device_discovery(&r.discovery, r.kind, now)?;
                let candidate = input
                    .get("candidateId")
                    .and_then(Value::as_str)
                    .filter(|s| s.len() <= 128)
                    .ok_or_else(error)?;
                c.consume(id, candidate).map_err(|_| error())?;
                r.selected = true;
                Ok(json!({"status":"waiting"}))
            }
            "device.assist.finish" => {
                if !r.selected {
                    return Err(error());
                }
                let code = c.take(id).map_err(|_| error())?;
                let r = self.requests.remove(id).ok_or_else(error)?;
                device_assignment(r.discovery, r.kind, &code, now)
            }
            "device.assist.cancel" => {
                c.cancel(id);
                self.requests.remove(id);
                Ok(json!({"status":"cancelled"}))
            }
            _ => Err(error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_credentials::test_helpers::temp_store;

    #[test]
    fn ct_device_assist_broker_uses_injected_credential_store() {
        let (store, dir, _legacy) = temp_store();
        let scoped = Arc::new(store.scoped("com.vaultmesh.desktop.lan-pairing"));
        let trust_path = dir.0.join("lan-peer-trust.json");
        let mut broker = DeviceAssistBroker::new(trust_path, scoped.clone());

        assert!(broker.prepare("test-scope-1".into()).is_ok());
        // Verify registration scopes were saved into the scoped credential store, not the OS keyring
        let scopes = scoped.get("device-assist-registration-scopes-v2").unwrap();
        assert!(scopes.is_some());
    }
}
