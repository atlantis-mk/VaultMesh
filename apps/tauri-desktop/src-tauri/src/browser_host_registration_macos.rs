//! User-scoped production registration. Debug profiles remain owned by browser:dev.
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use atomic_write_file::{
    OpenOptions as AtomicOpenOptions, unix::OpenOptionsExt as AtomicOptionsExt,
};
use serde_json::json;

#[cfg(not(debug_assertions))]
use super::configured_extension_id;
use super::{
    BROWSER_HOST_NAME, BROWSER_PAIRING_ACCOUNT, BROWSER_PAIRING_SERVICE, FIREFOX_EXTENSION_ID,
    allowed_origin,
};

struct MacOSBrowserHostPlan {
    native_host_path: PathBuf,
    files: Vec<(PathBuf, Vec<u8>)>,
}

fn macos_browser_host_plan(
    home: &Path,
    temporary_directory: &Path,
    desktop_executable: &Path,
    extension_id: &str,
) -> io::Result<MacOSBrowserHostPlan> {
    if !home.is_absolute()
        || !temporary_directory.is_absolute()
        || !desktop_executable.is_absolute()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host paths must be absolute",
        ));
    }
    let native_host_path = crate::keychain_share::in_bundle_executable_paths(desktop_executable)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?
        .native_host;
    let host = native_host_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "host path must be valid Unicode",
        )
    })?;
    let origin = allowed_origin(extension_id)?;
    let broker_socket = temporary_directory.join("vaultmesh-tauri-browser.sock");
    if broker_socket.as_os_str().len() > 103 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker socket exceeds macOS path limit",
        ));
    }
    let support = home.join("Library/Application Support");
    let manifest_name = format!("{BROWSER_HOST_NAME}.json");
    let firefox_manifest_path = support
        .join("Mozilla/NativeMessagingHosts")
        .join(&manifest_name);
    let config = json!({
        "version": 2,
        "brokerSocket": broker_socket,
        "keychainService": BROWSER_PAIRING_SERVICE,
        "keychainAccount": BROWSER_PAIRING_ACCOUNT,
        "chromiumAllowedOrigin": origin,
        "firefoxExtensionId": FIREFOX_EXTENSION_ID,
        "firefoxManifestPath": firefox_manifest_path,
    });
    let chromium_manifest = json!({
        "name": BROWSER_HOST_NAME,
        "description": "VaultMesh Tauri protocol v2 native messaging host",
        "path": host,
        "type": "stdio",
        "allowed_origins": [origin],
    });
    let firefox_manifest = json!({
        "name": BROWSER_HOST_NAME,
        "description": "VaultMesh Tauri protocol v2 native messaging host",
        "path": host,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    });
    let encode = |value: &serde_json::Value| serde_json::to_vec(value).map_err(io::Error::other);
    Ok(MacOSBrowserHostPlan {
        native_host_path,
        files: vec![
            (
                support.join("com.vaultmesh.desktop/browser-host-config.json"),
                encode(&config)?,
            ),
            (
                support
                    .join("Google/Chrome/NativeMessagingHosts")
                    .join(&manifest_name),
                encode(&chromium_manifest)?,
            ),
            (
                support
                    .join("Microsoft Edge/NativeMessagingHosts")
                    .join(&manifest_name),
                encode(&chromium_manifest)?,
            ),
            (firefox_manifest_path, encode(&firefox_manifest)?),
        ],
    })
}

fn validate_directory(directory: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe host directory",
        ));
    }
    Ok(())
}

fn validate_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } => {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe host registration target",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn install_plan(plan: &MacOSBrowserHostPlan) -> io::Result<()> {
    let host = fs::symlink_metadata(&plan.native_host_path)?;
    if !host.is_file() || host.len() == 0 || host.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "packaged native host unavailable",
        ));
    }
    // Preflight every target before changing any registration/configuration bytes.
    for (path, _) in &plan.files {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("host path has no parent"))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        validate_directory(parent)?;
        validate_target(path)?;
    }
    for (path, bytes) in &plan.files {
        let metadata = fs::symlink_metadata(path);
        if metadata.is_ok_and(|metadata| {
            metadata.mode() & 0o777 == 0o600 && metadata.len() == bytes.len() as u64
        }) && fs::read(path).is_ok_and(|current| current == *bytes)
        {
            continue;
        }
        let mut options = AtomicOpenOptions::new();
        AtomicOptionsExt::preserve_mode(&mut options, false);
        OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.commit()?;
    }
    Ok(())
}

// This entry point is intentionally absent in debug desktop builds.
#[cfg(not(debug_assertions))]
pub fn install_macos_browser_host() -> io::Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory unavailable"))?;
    let plan = macos_browser_host_plan(
        &home,
        &std::env::temp_dir(),
        &std::env::current_exe()?,
        configured_extension_id()?,
    )?;
    install_plan(&plan)
}

#[cfg(test)]
mod tests {
    use super::super::DEFAULT_DEVELOPMENT_EXTENSION_ID;
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "vaultmesh-host-registration-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn plan(&self, app: &str) -> MacOSBrowserHostPlan {
            let executable = self
                .0
                .join(app)
                .join("Contents/MacOS/vaultmesh-tauri-desktop");
            let plan = macos_browser_host_plan(
                &self.0.join("home"),
                Path::new("/tmp"),
                &executable,
                DEFAULT_DEVELOPMENT_EXTENSION_ID,
            )
            .unwrap();
            fs::create_dir_all(plan.native_host_path.parent().unwrap()).unwrap();
            fs::write(
                &plan.native_host_path,
                b"fixture executable, never launched",
            )
            .unwrap();
            fs::set_permissions(&plan.native_host_path, fs::Permissions::from_mode(0o755)).unwrap();
            plan
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // The absolute root was created above and is owned by this fixture only.
            assert!(
                self.0.is_absolute()
                    && self
                        .0
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("vaultmesh-host-registration-")
            );
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn macos_plan_binds_config_separate_browser_manifests_and_actual_bundle_location() {
        let fixture = Fixture::new();
        let plan = fixture.plan("Moved VaultMesh.app");
        let values: Vec<serde_json::Value> = plan
            .files
            .iter()
            .map(|(_, bytes)| serde_json::from_slice(bytes).unwrap())
            .collect();
        assert_eq!(
            values[0],
            json!({
                "version": 2,
                "brokerSocket": "/tmp/vaultmesh-tauri-browser.sock",
                "keychainService": BROWSER_PAIRING_SERVICE,
                "keychainAccount": BROWSER_PAIRING_ACCOUNT,
                "chromiumAllowedOrigin": format!("chrome-extension://{DEFAULT_DEVELOPMENT_EXTENSION_ID}/"),
                "firefoxExtensionId": FIREFOX_EXTENSION_ID,
                "firefoxManifestPath": plan.files[3].0,
            })
        );
        assert!(
            plan.files[0]
                .0
                .ends_with("com.vaultmesh.desktop/browser-host-config.json")
        );
        assert!(
            plan.files[1]
                .0
                .ends_with("Google/Chrome/NativeMessagingHosts/com.vaultmesh.browser.json")
        );
        assert!(
            plan.files[2]
                .0
                .ends_with("Microsoft Edge/NativeMessagingHosts/com.vaultmesh.browser.json")
        );
        assert!(
            plan.files[3]
                .0
                .ends_with("Mozilla/NativeMessagingHosts/com.vaultmesh.browser.json")
        );
        for value in &values[1..] {
            assert_eq!(value["path"], plan.native_host_path.to_str().unwrap());
            assert_eq!(value["name"], BROWSER_HOST_NAME);
            assert_eq!(value["type"], "stdio");
        }
        assert!(
            plan.native_host_path
                .ends_with("Contents/MacOS/vaultmesh-native-host")
        );
        assert!(
            !plan
                .native_host_path
                .to_string_lossy()
                .contains("bitwarden")
        );
        assert!(
            !plan
                .native_host_path
                .to_string_lossy()
                .contains("agent-mcp")
        );
        assert_eq!(values[1], values[2]);
        assert_eq!(
            values[1]["allowed_origins"],
            json!([format!(
                "chrome-extension://{DEFAULT_DEVELOPMENT_EXTENSION_ID}/"
            )])
        );
        assert!(values[1].get("allowed_extensions").is_none());
        assert_eq!(
            values[3]["allowed_extensions"],
            json!([FIREFOX_EXTENSION_ID])
        );
        assert!(values[3].get("allowed_origins").is_none());
    }

    #[test]
    fn macos_registration_rejects_hosts_outside_the_app_bundle() {
        let fixture = Fixture::new();
        let loose = fixture.0.join("vaultmesh-tauri-desktop");
        assert!(
            macos_browser_host_plan(
                &fixture.0.join("home"),
                Path::new("/tmp"),
                &loose,
                DEFAULT_DEVELOPMENT_EXTENSION_ID,
            )
            .is_err()
        );
        let dev_host = fixture
            .0
            .join("VaultMesh.app/Contents/MacOS/vaultmesh-bitwarden-dev-host");
        assert!(
            macos_browser_host_plan(
                &fixture.0.join("home"),
                Path::new("/tmp"),
                &dev_host,
                DEFAULT_DEVELOPMENT_EXTENSION_ID,
            )
            .is_err()
        );
        let agent = fixture
            .0
            .join("VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp");
        assert!(
            macos_browser_host_plan(
                &fixture.0.join("home"),
                Path::new("/tmp"),
                &agent,
                DEFAULT_DEVELOPMENT_EXTENSION_ID,
            )
            .is_err()
        );
    }

    #[test]
    fn macos_install_is_private_idempotent_and_repairs_deleted_or_stale_registration() {
        let fixture = Fixture::new();
        let plan = fixture.plan("VaultMesh.app");
        let pairing = fixture
            .0
            .join("home/Library/Application Support/com.vaultmesh.desktop/browser-pairing.json");
        fs::create_dir_all(pairing.parent().unwrap()).unwrap();
        fs::write(&pairing, b"nonsecret pairing record canary").unwrap();
        install_plan(&plan).unwrap();
        let inodes: Vec<u64> = plan
            .files
            .iter()
            .map(|(path, _)| fs::metadata(path).unwrap().ino())
            .collect();
        install_plan(&plan).unwrap();
        for ((path, bytes), inode) in plan.files.iter().zip(inodes) {
            assert_eq!(fs::read(path).unwrap(), *bytes);
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(
                metadata.ino(),
                inode,
                "unchanged registration must not be rewritten"
            );
        }
        let chrome = &plan.files[1].0;
        assert!(chrome.starts_with(&fixture.0));
        fs::remove_file(chrome).unwrap();
        fs::write(&plan.files[2].0, b"stale manifest").unwrap();
        fs::set_permissions(&plan.files[0].0, fs::Permissions::from_mode(0o644)).unwrap();
        let relocated = fixture.plan("Relocated VaultMesh.app");
        install_plan(&relocated).unwrap();
        for (path, bytes) in &relocated.files {
            assert_eq!(fs::read(path).unwrap(), *bytes);
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
        }
        assert_eq!(
            fs::read(pairing).unwrap(),
            b"nonsecret pairing record canary"
        );
    }

    #[test]
    fn macos_registration_rejects_missing_or_nonexecutable_host_before_writing() {
        let fixture = Fixture::new();
        let plan = fixture.plan("VaultMesh.app");
        fs::set_permissions(&plan.native_host_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(install_plan(&plan).is_err());
        assert!(plan.files.iter().all(|(path, _)| !path.exists()));
        assert!(plan.native_host_path.starts_with(&fixture.0));
        fs::remove_file(&plan.native_host_path).unwrap();
        assert_eq!(
            install_plan(&plan).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(plan.files.iter().all(|(path, _)| !path.exists()));
    }

    #[test]
    fn macos_registration_rejects_symlink_targets_and_preserves_existing_config_on_failure() {
        let fixture = Fixture::new();
        let plan = fixture.plan("VaultMesh.app");
        install_plan(&plan).unwrap();
        let canary = fixture.0.join("canary");
        fs::write(&canary, b"unrelated file").unwrap();
        let chrome = &plan.files[1].0;
        assert!(chrome.starts_with(&fixture.0));
        fs::remove_file(chrome).unwrap();
        symlink(&canary, chrome).unwrap();
        let relocated = fixture.plan("Moved.app");
        assert_eq!(
            install_plan(&relocated).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&canary).unwrap(), b"unrelated file");
        assert_eq!(fs::read(&plan.files[0].0).unwrap(), plan.files[0].1);
    }

    #[test]
    fn macos_registration_enforces_socket_path_byte_limit() {
        let home = Path::new("/Users/test");
        let desktop =
            Path::new("/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-tauri-desktop");
        let filename = "vaultmesh-tauri-browser.sock";
        let directory_length = 103 - filename.len() - 2;
        let boundary = PathBuf::from(format!("/{}", "t".repeat(directory_length)));
        assert_eq!(boundary.join(filename).as_os_str().len(), 103);
        assert!(
            macos_browser_host_plan(home, &boundary, desktop, DEFAULT_DEVELOPMENT_EXTENSION_ID)
                .is_ok()
        );
        let too_long = PathBuf::from(format!("/{}", "t".repeat(directory_length + 1)));
        assert!(
            macos_browser_host_plan(home, &too_long, desktop, DEFAULT_DEVELOPMENT_EXTENSION_ID)
                .is_err()
        );
        let multibyte = PathBuf::from(format!("/{}", "é".repeat(directory_length)));
        assert!(
            macos_browser_host_plan(home, &multibyte, desktop, DEFAULT_DEVELOPMENT_EXTENSION_ID)
                .is_err()
        );
    }

    #[test]
    fn macos_registration_rejects_relative_paths_and_invalid_identity() {
        let home = Path::new("/Users/test");
        let tmp = Path::new("/tmp");
        let desktop =
            Path::new("/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-tauri-desktop");
        assert!(macos_browser_host_plan(home, tmp, desktop, "*").is_err());
        assert!(
            macos_browser_host_plan(
                Path::new("relative"),
                tmp,
                desktop,
                DEFAULT_DEVELOPMENT_EXTENSION_ID
            )
            .is_err()
        );
        assert!(
            macos_browser_host_plan(
                home,
                Path::new("relative"),
                desktop,
                DEFAULT_DEVELOPMENT_EXTENSION_ID
            )
            .is_err()
        );
        assert!(
            macos_browser_host_plan(
                home,
                tmp,
                Path::new("relative"),
                DEFAULT_DEVELOPMENT_EXTENSION_ID
            )
            .is_err()
        );
    }
}
