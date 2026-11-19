use std::io;
#[cfg(any(target_os = "windows", test))]
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use atomic_write_file::OpenOptions as AtomicOpenOptions;
#[cfg(any(target_os = "windows", test))]
use serde_json::json;
#[cfg(target_os = "windows")]
use std::io::Write;

#[cfg(target_os = "macos")]
#[path = "browser_host_registration_macos.rs"]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::install_macos_browser_host;

pub const BROWSER_HOST_NAME: &str = "com.vaultmesh.browser";
#[cfg(any(target_os = "windows", test))]
pub const BROWSER_PIPE_NAME: &str = r"\\.\pipe\VaultMesh.BrowserBroker.v2";
#[cfg(any(target_os = "windows", test))]
pub const BROWSER_PAIRING_SERVICE: &str = "com.vaultmesh.desktop.browser-pairing";
#[cfg(any(target_os = "windows", test))]
pub const BROWSER_PAIRING_ACCOUNT: &str = "native-host-hmac-v1";
pub const DEFAULT_DEVELOPMENT_EXTENSION_ID: &str = "bdneegbnjbheblmamalplnddbodcghbg";
pub const FIREFOX_EXTENSION_ID: &str = "vaultmesh@atlantis-mk.github.io";
#[cfg(any(target_os = "windows", test))]
const HOST_CONFIG_NAME: &str = "browser-host-config.json";
#[cfg(any(target_os = "windows", test))]
const HOST_MANIFEST_NAME: &str = "com.vaultmesh.browser.json";
#[cfg(any(target_os = "windows", test))]
const FIREFOX_HOST_MANIFEST_NAME: &str = "com.vaultmesh.browser.firefox.json";

#[cfg(any(target_os = "windows", test))]
struct WindowsHostRegistration {
    browser: &'static str,
    registry_root: &'static str,
    firefox: bool,
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_HOST_REGISTRATIONS: &[WindowsHostRegistration] = &[
    WindowsHostRegistration {
        browser: "chrome",
        registry_root: r"Google\Chrome",
        firefox: false,
    },
    WindowsHostRegistration {
        browser: "edge",
        registry_root: r"Microsoft\Edge",
        firefox: false,
    },
    WindowsHostRegistration {
        browser: "firefox",
        registry_root: "Mozilla",
        firefox: true,
    },
];

#[cfg(any(target_os = "windows", test))]
impl WindowsHostRegistration {
    fn registry_key(&self) -> String {
        format!(r"Software\{}\NativeMessagingHosts\{BROWSER_HOST_NAME}", self.registry_root)
    }
}

#[cfg(any(target_os = "windows", test))]
pub struct WindowsBrowserHostPlan {
    pub config_path: PathBuf,
    pub chromium_manifest_path: PathBuf,
    pub firefox_manifest_path: PathBuf,
    pub config: Vec<u8>,
    pub chromium_manifest: Vec<u8>,
    pub firefox_manifest: Vec<u8>,
}

#[cfg(any(target_os = "windows", target_os = "macos", test))]
pub fn configured_extension_id() -> io::Result<&'static str> {
    let extension_id =
        option_env!("VAULTMESH_BROWSER_EXTENSION_ID").unwrap_or(DEFAULT_DEVELOPMENT_EXTENSION_ID);
    valid_extension_id(extension_id)
        .then_some(extension_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid browser extension ID"))
}

pub fn allowed_origin(extension_id: &str) -> io::Result<String> {
    valid_extension_id(extension_id)
        .then(|| format!("chrome-extension://{extension_id}/"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid browser extension ID"))
}

#[cfg(any(target_os = "windows", test))]
pub fn windows_browser_host_plan(
    app_data: &Path,
    native_host_path: &Path,
    extension_id: &str,
) -> io::Result<WindowsBrowserHostPlan> {
    if !app_data.is_absolute() || !native_host_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "browser host paths must be absolute",
        ));
    }
    let native_host_path = native_host_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "browser host path must be valid Unicode",
        )
    })?;
    let origin = allowed_origin(extension_id)?;
    let chromium_manifest_path = app_data.join(HOST_MANIFEST_NAME);
    let firefox_manifest_path = app_data.join(FIREFOX_HOST_MANIFEST_NAME);
    let config = serde_json::to_vec(&json!({
        "version": 2,
        "brokerPipe": BROWSER_PIPE_NAME,
        "keychainService": BROWSER_PAIRING_SERVICE,
        "keychainAccount": BROWSER_PAIRING_ACCOUNT,
        "chromiumAllowedOrigin": origin,
        "firefoxExtensionId": FIREFOX_EXTENSION_ID,
        "firefoxManifestPath": firefox_manifest_path,
    }))
    .map_err(io::Error::other)?;
    let chromium_manifest = serde_json::to_vec(&json!({
        "name": BROWSER_HOST_NAME,
        "description": "VaultMesh Tauri protocol v2 native messaging host",
        "path": native_host_path,
        "type": "stdio",
        "allowed_origins": [origin],
    }))
    .map_err(io::Error::other)?;
    let firefox_manifest = serde_json::to_vec(&json!({
        "name": BROWSER_HOST_NAME,
        "description": "VaultMesh Tauri protocol v2 native messaging host",
        "path": native_host_path,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }))
    .map_err(io::Error::other)?;
    Ok(WindowsBrowserHostPlan {
        config_path: app_data.join(HOST_CONFIG_NAME),
        chromium_manifest_path,
        firefox_manifest_path,
        config,
        chromium_manifest,
        firefox_manifest,
    })
}

fn valid_extension_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

#[cfg(target_os = "windows")]
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let mut file = AtomicOpenOptions::new().open(path)?;
    file.write_all(bytes)?;
    file.commit()
}

#[cfg(target_os = "windows")]
pub fn install_windows_browser_host(app_data: &Path) -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "desktop executable has no parent directory",
        )
    })?;
    let native_host = parent.join("vaultmesh-native-host.exe");
    if !std::fs::metadata(&native_host).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "packaged browser native host is missing",
        ));
    }
    let plan = windows_browser_host_plan(app_data, &native_host, configured_extension_id()?)?;
    write_atomic(&plan.config_path, &plan.config)?;
    write_atomic(&plan.chromium_manifest_path, &plan.chromium_manifest)?;
    write_atomic(&plan.firefox_manifest_path, &plan.firefox_manifest)?;
    register_native_host_manifests(&plan.chromium_manifest_path, &plan.firefox_manifest_path)
}

#[cfg(target_os = "windows")]
pub(crate) fn check_windows_browser_registration(
    app_data: &Path,
    native_host: Option<&Path>,
    browser: &str,
) -> (bool, Option<String>) {
    inspect_windows_browser_registration(app_data, native_host, browser, read_windows_host_registration)
}

#[cfg(any(target_os = "windows", test))]
fn inspect_windows_browser_registration(
    app_data: &Path,
    native_host: Option<&Path>,
    browser: &str,
    lookup: impl FnOnce(&str) -> Option<PathBuf>,
) -> (bool, Option<String>) {
    let Some(registration) = WINDOWS_HOST_REGISTRATIONS.iter().find(|entry| entry.browser == browser) else {
        return (false, None);
    };
    let Some(registered_path) = lookup(&registration.registry_key()) else {
        return (false, None);
    };
    let valid = (|| -> Option<()> {
        let native_host = native_host?;
        let plan = windows_browser_host_plan(app_data, native_host, configured_extension_id().ok()?).ok()?;
        let (path, bytes) = if registration.firefox {
            (plan.firefox_manifest_path, plan.firefox_manifest)
        } else {
            (plan.chromium_manifest_path, plan.chromium_manifest)
        };
        if !registered_path.as_os_str().eq_ignore_ascii_case(path.as_os_str()) {
            return None;
        }

        // Read only the manifest at the app-owned path. A stale registry value
        // must not make Doctor read an arbitrary file.
        let actual: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let expected: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let host_matches = actual["path"].as_str()?.eq_ignore_ascii_case(native_host.to_str()?);
        (host_matches && ["name", "type", "allowed_origins", "allowed_extensions"]
            .iter().all(|&field| actual[field] == expected[field]))
            .then_some(())
    })().is_some();
    (valid, Some(registered_path.display().to_string()))
}

#[cfg(target_os = "windows")]
fn read_windows_host_registration(key: &str) -> Option<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::{null, null_mut}};
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_SZ, RegGetValueW};
    let key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
    let mut bytes = 0u32;
    // Query the default value from the same registry view used by the installer.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER, key.as_ptr(), null(), RRF_RT_REG_SZ,
            null_mut(), null_mut(), &mut bytes,
        )
    };
    if status != 0 || !(2..=65536).contains(&bytes) || bytes % 2 != 0 {
        return None;
    }
    let mut value = vec![0u16; bytes as usize / 2];
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER, key.as_ptr(), null(), RRF_RT_REG_SZ,
            null_mut(), value.as_mut_ptr().cast(), &mut bytes,
        )
    };
    if status != 0 {
        return None;
    }
    let length = value.iter().position(|&unit| unit == 0)?;
    (length > 0).then(|| PathBuf::from(OsString::from_wide(&value[..length])))
}

#[cfg(target_os = "windows")]
fn register_native_host_manifests(
    chromium_manifest_path: &Path,
    firefox_manifest_path: &Path,
) -> io::Result<()> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegSetValueExW,
    };

    struct RegistryKey(HKEY);
    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    for registration in WINDOWS_HOST_REGISTRATIONS {
        let manifest_path = if registration.firefox { firefox_manifest_path } else { chromium_manifest_path };
        let manifest = wide(manifest_path.as_os_str());
        let registry_key = registration.registry_key();
        let subkey = wide(OsStr::new(&registry_key));
        let mut key = std::ptr::null_mut();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let key = RegistryKey(key);
        let status = unsafe {
            RegSetValueExW(
                key.0,
                null(),
                0,
                REG_SZ,
                manifest.as_ptr().cast(),
                (manifest.len() * std::mem::size_of::<u16>()) as u32,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_plan_binds_manifest_config_and_compiled_extension_identity() {
        let root = std::env::temp_dir();
        let app_data = root.join("com.vaultmesh.desktop");
        let host = root.join("VaultMesh").join("vaultmesh-native-host.exe");
        let plan = windows_browser_host_plan(&app_data, &host, DEFAULT_DEVELOPMENT_EXTENSION_ID)
            .expect("plan");
        let config: serde_json::Value = serde_json::from_slice(&plan.config).expect("config");
        let chromium_manifest: serde_json::Value =
            serde_json::from_slice(&plan.chromium_manifest).expect("manifest");
        let firefox_manifest: serde_json::Value =
            serde_json::from_slice(&plan.firefox_manifest).expect("firefox manifest");
        let origin = format!("chrome-extension://{DEFAULT_DEVELOPMENT_EXTENSION_ID}/");
        assert_eq!(plan.config_path, app_data.join(HOST_CONFIG_NAME));
        assert_eq!(
            plan.chromium_manifest_path,
            app_data.join(HOST_MANIFEST_NAME)
        );
        assert_eq!(
            plan.firefox_manifest_path,
            app_data.join(FIREFOX_HOST_MANIFEST_NAME)
        );
        assert_eq!(config["version"], 2);
        assert_eq!(config["brokerPipe"], BROWSER_PIPE_NAME);
        assert_eq!(config["chromiumAllowedOrigin"], origin);
        assert_eq!(config["firefoxExtensionId"], FIREFOX_EXTENSION_ID);
        assert_eq!(
            config["firefoxManifestPath"].as_str(),
            plan.firefox_manifest_path.to_str()
        );
        assert_eq!(chromium_manifest["name"], BROWSER_HOST_NAME);
        assert_eq!(chromium_manifest["path"], host.to_str().expect("host path"));
        assert_eq!(chromium_manifest["allowed_origins"], json!([origin]));
        assert_eq!(firefox_manifest["name"], BROWSER_HOST_NAME);
        assert_eq!(
            firefox_manifest["allowed_extensions"],
            json!([FIREFOX_EXTENSION_ID])
        );
    }

    #[test]
    fn ct_native_browser_001_windows_doctor_checks_each_registry_entry_and_manifest_identity() {
        let root = std::env::temp_dir().join(format!("vaultmesh-doctor-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let native_host = root.join("vaultmesh-native-host.exe");
        let plan = windows_browser_host_plan(&root, &native_host, configured_extension_id().unwrap()).unwrap();
        std::fs::write(&plan.chromium_manifest_path, &plan.chromium_manifest).unwrap();
        std::fs::write(&plan.firefox_manifest_path, &plan.firefox_manifest).unwrap();

        let inspect = |browser: &str, lookup: &dyn Fn(&str) -> Option<PathBuf>| {
            inspect_windows_browser_registration(&root, Some(&native_host), browser, lookup)
        };
        // A present manifest does not imply any registration for this browser.
        assert_eq!(inspect("chrome", &|_| None), (false, None));

        let lookup = |key: &str| match key {
            r"Software\Google\Chrome\NativeMessagingHosts\com.vaultmesh.browser" =>
                Some(plan.chromium_manifest_path.clone()),
            r"Software\Mozilla\NativeMessagingHosts\com.vaultmesh.browser" =>
                Some(plan.firefox_manifest_path.clone()),
            _ => None,
        };
        assert!(inspect("chrome", &lookup).0);
        assert!(!inspect("edge", &lookup).0);
        assert!(!inspect("brave", &lookup).0);
        assert!(inspect("firefox", &lookup).0);
        assert!(!inspect("firefox", &|_| Some(plan.chromium_manifest_path.clone())).0);

        let mut stale: serde_json::Value = serde_json::from_slice(&plan.chromium_manifest).unwrap();
        stale["allowed_origins"] = json!(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]);
        std::fs::write(&plan.chromium_manifest_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(!inspect("chrome", &lookup).0);

        let mut stale: serde_json::Value = serde_json::from_slice(&plan.chromium_manifest).unwrap();
        stale["path"] = json!(root.join("old").join("vaultmesh-native-host.exe"));
        std::fs::write(&plan.chromium_manifest_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(!inspect("chrome", &lookup).0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn browser_identity_rejects_unbound_or_path_like_values() {
        assert!(allowed_origin(DEFAULT_DEVELOPMENT_EXTENSION_ID).is_ok());
        assert!(allowed_origin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(allowed_origin("../../aaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(
            windows_browser_host_plan(
                Path::new("relative"),
                Path::new("relative.exe"),
                DEFAULT_DEVELOPMENT_EXTENSION_ID,
            )
            .is_err()
        );
    }
}
