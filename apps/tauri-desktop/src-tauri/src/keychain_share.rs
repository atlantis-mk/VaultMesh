//! Rules for which macOS binaries may share the desktop root Keychain item.
//!
//! The signed in-bundle main executable and `vaultmesh-native-host` are the only
//! clients. Development hosts, the agent sidecar, and binaries outside the
//! `.app` bundle are rejected before any ACL or access group is built.

use std::fs;
use std::path::{Path, PathBuf};

pub const APP_DATA_DIR_NAME: &str = "com.vaultmesh.desktop";
pub const MAIN_EXECUTABLE_NAME: &str = "vaultmesh-tauri-desktop";
pub const NATIVE_HOST_EXECUTABLE_NAME: &str = "vaultmesh-native-host";
pub const KEYCHAIN_ACCESS_GROUP_SUFFIX: &str = "com.vaultmesh.desktop";

pub const LEGACY_CREDENTIAL_SERVICES: &[&str] = &[
    "com.vaultmesh.desktop.desktop-biometric",
    "com.vaultmesh.desktop.agent-biometric",
    "com.vaultmesh.desktop.browser-biometric",
    "com.vaultmesh.desktop.agent-pairing",
    "com.vaultmesh.desktop.agent-authorization",
    "com.vaultmesh.desktop.browser-pairing",
    "com.vaultmesh.desktop.lan-pairing",
    "com.vaultmesh.desktop.pin",
    "com.vaultmesh.desktop.browser-pin",
    "com.vaultmesh.desktop.agent-pin",
];

const MIGRATION_MARKER_SERVICE: &str = "com.vaultmesh.desktop.migration";
const MIGRATION_MARKER_ACCOUNT: &str = "legacy-services-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InBundleExecutables {
    pub macos_dir: PathBuf,
    pub main_executable: PathBuf,
    pub native_host: PathBuf,
}

pub fn migration_marker_key() -> String {
    format!("{MIGRATION_MARKER_SERVICE}::{MIGRATION_MARKER_ACCOUNT}")
}

pub fn is_allowed_bundle_executable(name: &str) -> bool {
    name == MAIN_EXECUTABLE_NAME || name == NATIVE_HOST_EXECUTABLE_NAME
}

pub fn is_forbidden_trusted_executable(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    !is_allowed_bundle_executable(name)
        || lowered.contains("bitwarden")
        || lowered.contains("dev-host")
        || lowered.contains("agent-mcp")
}

/// Locate the two product executables inside `Something.app/Contents/MacOS`.
/// Path shape only: the files do not need to exist yet.
pub fn in_bundle_executable_paths(current: &Path) -> Result<InBundleExecutables, &'static str> {
    if !current.is_absolute() {
        return Err("executable path must be absolute");
    }
    let name = current
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !is_allowed_bundle_executable(name) || is_forbidden_trusted_executable(name) {
        return Err("executable cannot share the desktop root keychain item");
    }
    if current.components().any(|component| match component {
        std::path::Component::Normal(part) => {
            let text = part.to_string_lossy();
            text.contains("bitwarden-dev-host") || text.contains("vaultmesh-bitwarden")
        }
        _ => false,
    }) {
        return Err("development host cannot share the desktop root keychain item");
    }
    let macos_dir = current
        .parent()
        .ok_or("executable is outside Contents/MacOS")?;
    if macos_dir.file_name().and_then(|value| value.to_str()) != Some("MacOS") {
        return Err("executable is outside Contents/MacOS");
    }
    let contents = macos_dir
        .parent()
        .ok_or("executable is outside the app bundle")?;
    if contents.file_name().and_then(|value| value.to_str()) != Some("Contents") {
        return Err("executable is outside the app bundle");
    }
    let app = contents
        .parent()
        .ok_or("executable is outside a .app bundle")?;
    let app_name = app
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if app_name.len() <= 4 || !app_name.ends_with(".app") {
        return Err("executable is outside a .app bundle");
    }
    Ok(InBundleExecutables {
        main_executable: macos_dir.join(MAIN_EXECUTABLE_NAME),
        native_host: macos_dir.join(NATIVE_HOST_EXECUTABLE_NAME),
        macos_dir: macos_dir.to_path_buf(),
    })
}

/// A regular, non-symlink executable whose canonical path stays inside `Contents/MacOS`.
pub fn is_direct_bundle_executable(path: &Path, macos_dir: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !is_allowed_bundle_executable(name) || is_forbidden_trusted_executable(name) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    let Ok(canonical_path) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(canonical_dir) = fs::canonicalize(macos_dir) else {
        return false;
    };
    canonical_path.parent() == Some(canonical_dir.as_path())
}

pub fn valid_team_id(team_id: &str) -> bool {
    team_id.len() == 10
        && team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

pub fn valid_cdhash(cdhash: &str) -> bool {
    let hex = cdhash.trim().to_ascii_lowercase();
    (hex.len() == 40 || hex.len() == 64) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Access group recorded in the signed entitlement, including the Team ID prefix.
pub fn entitled_access_group(team_id: &str, groups: &[impl AsRef<str>]) -> Option<String> {
    if !valid_team_id(team_id) {
        return None;
    }
    let expected = format!("{team_id}.{KEYCHAIN_ACCESS_GROUP_SUFFIX}");
    groups
        .iter()
        .find(|group| group.as_ref() == expected)
        .map(|_| expected)
}

/// Partition IDs written on create and update of the legacy file-keychain item.
/// Same Team ID contributes `teamid:`; ad-hoc signatures contribute only the two cdhashes.
pub fn partition_ids_for_share(
    main_team: Option<&str>,
    host_team: Option<&str>,
    main_cdhash: &str,
    host_cdhash: &str,
) -> Option<Vec<String>> {
    let main_cdhash = main_cdhash.trim().to_ascii_lowercase();
    let host_cdhash = host_cdhash.trim().to_ascii_lowercase();
    if !valid_cdhash(&main_cdhash) || !valid_cdhash(&host_cdhash) || main_cdhash == host_cdhash {
        return None;
    }
    let main_team = main_team.map(str::trim).filter(|value| !value.is_empty());
    let host_team = host_team.map(str::trim).filter(|value| !value.is_empty());
    let mut ids = Vec::with_capacity(3);
    match (main_team, host_team) {
        (Some(main), Some(host)) if main == host && valid_team_id(main) => {
            ids.push(format!("teamid:{main}"));
        }
        (None, None) => {}
        _ => return None,
    }
    ids.push(format!("cdhash:{main_cdhash}"));
    ids.push(format!("cdhash:{host_cdhash}"));
    Some(ids)
}

pub fn partition_plist_hex(partitions: &[String]) -> Option<String> {
    if partitions.is_empty()
        || partitions.iter().any(|partition| {
            !(partition.starts_with("teamid:") || partition.starts_with("cdhash:"))
                || partition
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b':'))
        })
    {
        return None;
    }
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Partitions</key>
	<array>
"#,
    );
    for partition in partitions {
        xml.push_str("\t\t<string>");
        xml.push_str(partition);
        xml.push_str("</string>\n");
    }
    xml.push_str("\t</array>\n</dict>\n</plist>\n");
    Some(xml.bytes().fold(String::new(), |mut hex, byte| {
        hex.push_str(&format!("{byte:02x}"));
        hex
    }))
}

pub fn description_contains_partitions(description: &str, partitions: &[String]) -> bool {
    let decoded = decode_hex_text(description).unwrap_or_else(|| description.to_owned());
    partitions
        .iter()
        .all(|partition| decoded.contains(partition))
}

fn decode_hex_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() < 2 || trimmed.len() % 2 != 0 {
        return None;
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<u8> = trimmed.bytes().collect();
    for pair in chars.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(text, 16).ok()?);
    }
    String::from_utf8(bytes).ok()
}

/// Release builds must not keep a direct Keychain side path for PIN or biometrics.
pub const fn production_direct_keyring_allowed() -> bool {
    cfg!(debug_assertions)
}

#[cfg(not(debug_assertions))]
const _: () = assert!(!production_direct_keyring_allowed());

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn touch_executable(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn bundle_paths_accept_only_the_two_product_executables() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("vaultmesh-keychain-share-{nonce}"));
        let macos = root.join("VaultMesh.app/Contents/MacOS");
        let main = macos.join(MAIN_EXECUTABLE_NAME);
        let host = macos.join(NATIVE_HOST_EXECUTABLE_NAME);
        touch_executable(&main);
        touch_executable(&host);
        let paths = in_bundle_executable_paths(&main).unwrap();
        assert_eq!(paths.main_executable, main);
        assert_eq!(paths.native_host, host);
        assert!(is_direct_bundle_executable(&main, &paths.macos_dir));
        assert!(is_direct_bundle_executable(&host, &paths.macos_dir));

        let outside = root.join(MAIN_EXECUTABLE_NAME);
        touch_executable(&outside);
        assert!(in_bundle_executable_paths(&outside).is_err());

        let agent = macos.join("vaultmesh-agent-mcp");
        touch_executable(&agent);
        assert!(in_bundle_executable_paths(&agent).is_err());

        let dev_host = macos.join("vaultmesh-bitwarden-dev-host");
        touch_executable(&dev_host);
        assert!(in_bundle_executable_paths(&dev_host).is_err());
        assert!(is_forbidden_trusted_executable(
            "vaultmesh-bitwarden-dev-host"
        ));
        assert!(is_forbidden_trusted_executable("vaultmesh-agent-mcp"));

        let escaped = root.join("Other.app/Contents/MacOS/helper");
        touch_executable(&escaped);
        fs::remove_file(&host).unwrap();
        std::os::unix::fs::symlink(&escaped, &host).unwrap();
        assert!(
            !is_direct_bundle_executable(&host, &macos),
            "a symlink to a binary outside Contents/MacOS must not be trusted"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn access_group_requires_the_same_team_prefix() {
        let groups = [
            "ABCD123456.com.vaultmesh.desktop".to_owned(),
            "ABCD123456.com.vaultmesh.other".to_owned(),
        ];
        assert_eq!(
            entitled_access_group("ABCD123456", &groups).as_deref(),
            Some("ABCD123456.com.vaultmesh.desktop")
        );
        assert!(entitled_access_group("", &groups).is_none());
        assert!(entitled_access_group("not-a-team", &groups).is_none());
        assert!(
            entitled_access_group("ABCD123456", &["com.vaultmesh.desktop".to_owned()]).is_none()
        );
        assert!(
            entitled_access_group(
                "ABCD123456",
                &["ABCD123456.com.vaultmesh.desktop.bitwarden-dev".to_owned()]
            )
            .is_none()
        );
    }

    #[test]
    fn partition_list_covers_same_team_or_both_adhoc_cdhashes_only() {
        let main = "a".repeat(40);
        let host = "b".repeat(40);
        let same_team =
            partition_ids_for_share(Some("ABCD123456"), Some("ABCD123456"), &main, &host).unwrap();
        assert_eq!(
            same_team,
            vec![
                "teamid:ABCD123456".to_owned(),
                format!("cdhash:{main}"),
                format!("cdhash:{host}"),
            ]
        );
        let adhoc = partition_ids_for_share(None, None, &main, &host).unwrap();
        assert_eq!(
            adhoc,
            vec![format!("cdhash:{main}"), format!("cdhash:{host}")]
        );
        assert!(partition_ids_for_share(Some("ABCD123456"), None, &main, &host).is_none());
        assert!(
            partition_ids_for_share(Some("ABCD123456"), Some("ZZZZZZZZZZ"), &main, &host).is_none()
        );
        assert!(partition_ids_for_share(None, None, &main, &main).is_none());
        assert!(partition_ids_for_share(None, None, "unsigned", &host).is_none());
        let hex = partition_plist_hex(&adhoc).unwrap();
        assert!(description_contains_partitions(&hex, &adhoc));
        assert!(partition_plist_hex(&["apple:".to_owned()]).is_none());
        assert!(partition_plist_hex(&["cdhash:<script>".to_owned()]).is_none());
    }

    #[test]
    fn legacy_service_list_does_not_add_root_or_development_services() {
        assert!(!LEGACY_CREDENTIAL_SERVICES.contains(&"com.vaultmesh.desktop"));
        assert!(
            !LEGACY_CREDENTIAL_SERVICES
                .iter()
                .any(|service| service.contains("bitwarden") || service.contains("dev"))
        );
        assert!(LEGACY_CREDENTIAL_SERVICES.contains(&"com.vaultmesh.desktop.browser-pairing"));
    }
}
