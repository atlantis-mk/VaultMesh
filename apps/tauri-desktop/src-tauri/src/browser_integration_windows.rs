#![cfg(target_os = "windows")]

use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::Serialize;

use crate::{
    browser_broker::BrowserBrokerCore,
    browser_broker_windows::BrowserBrokerWindowsListener,
    browser_host_registration::{configured_extension_id, install_windows_browser_host},
};

type BrokerFactory =
    Arc<dyn Fn() -> Result<BrowserBrokerCore, BrowserIntegrationError> + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserIntegrationError {
    PairingUnavailable,
    BrokerUnavailable,
    ListenerUnavailable,
    ListenerStopped,
    HostMissing,
    RegistrationUnavailable,
    IdentityInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserIntegrationStatus {
    pub supported: bool,
    pub ready: bool,
    pub broker_ready: bool,
    pub host_registered: bool,
    pub extension_id: String,
    pub error_code: Option<BrowserIntegrationError>,
}

pub struct WindowsBrowserIntegration {
    app_data: PathBuf,
    broker_factory: BrokerFactory,
    listener: Option<Arc<BrowserBrokerWindowsListener>>,
    host_registered: bool,
    error_code: Option<BrowserIntegrationError>,
}

impl WindowsBrowserIntegration {
    pub(crate) fn lock_vault(&self) {
        if let Some(listener) = &self.listener {
            listener.lock_vault();
        }
    }
    pub fn new(app_data: PathBuf, broker_factory: BrokerFactory) -> Self {
        Self {
            app_data,
            broker_factory,
            listener: None,
            host_registered: false,
            error_code: None,
        }
    }

    pub fn start(&mut self) -> BrowserIntegrationStatus {
        self.repair()
    }

    pub fn status(&mut self) -> BrowserIntegrationStatus {
        if self
            .listener
            .as_ref()
            .is_some_and(|listener| !listener.is_healthy())
        {
            if let Some(listener) = self.listener.take() {
                listener.stop();
            }
            self.error_code = Some(BrowserIntegrationError::ListenerStopped);
        }
        self.snapshot()
    }

    pub fn repair(&mut self) -> BrowserIntegrationStatus {
        self.error_code = None;
        if self
            .listener
            .as_ref()
            .is_some_and(|listener| !listener.is_healthy())
            && let Some(listener) = self.listener.take()
        {
            listener.stop();
        }
        if self.listener.is_none() {
            match (self.broker_factory)().and_then(|broker| {
                BrowserBrokerWindowsListener::start(Arc::new(Mutex::new(broker)))
                    .map_err(|_| BrowserIntegrationError::ListenerUnavailable)
            }) {
                Ok(listener) => self.listener = Some(Arc::new(listener)),
                Err(error) => self.error_code = Some(error),
            }
        }

        self.host_registered = match install_windows_browser_host(&self.app_data) {
            Ok(()) => true,
            Err(error) => {
                if self.error_code.is_none() {
                    self.error_code = Some(registration_error(&error));
                }
                false
            }
        };
        self.snapshot()
    }

    pub fn stop(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.stop();
        }
    }

    fn snapshot(&self) -> BrowserIntegrationStatus {
        let broker_ready = self
            .listener
            .as_ref()
            .is_some_and(|listener| listener.is_healthy());
        let extension_id = configured_extension_id().unwrap_or_default().to_owned();
        let identity_error = extension_id
            .is_empty()
            .then_some(BrowserIntegrationError::IdentityInvalid);
        BrowserIntegrationStatus {
            supported: true,
            ready: broker_ready && self.host_registered && identity_error.is_none(),
            broker_ready,
            host_registered: self.host_registered,
            extension_id,
            error_code: identity_error.or(self.error_code),
        }
    }
}

fn registration_error(error: &io::Error) -> BrowserIntegrationError {
    match error.kind() {
        io::ErrorKind::NotFound => BrowserIntegrationError::HostMissing,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            BrowserIntegrationError::IdentityInvalid
        }
        _ => BrowserIntegrationError::RegistrationUnavailable,
    }
}

impl Drop for WindowsBrowserIntegration {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_failures_are_public_stable_categories() {
        assert_eq!(
            registration_error(&io::Error::new(io::ErrorKind::NotFound, "sensitive path")),
            BrowserIntegrationError::HostMissing
        );
        assert_eq!(
            registration_error(&io::Error::new(io::ErrorKind::PermissionDenied, "registry")),
            BrowserIntegrationError::RegistrationUnavailable
        );
        assert_eq!(
            registration_error(&io::Error::new(io::ErrorKind::InvalidData, "identity")),
            BrowserIntegrationError::IdentityInvalid
        );
    }
}
