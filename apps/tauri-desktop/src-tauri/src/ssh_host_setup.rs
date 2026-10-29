use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use rand_core::OsRng;
use serde::Deserialize;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::ssh_service::{PrivateKeyMaterial, SshTarget};

const MAX_LOCAL_SSH_FILE_BYTES: u64 = 1024 * 1024;
const MANAGED_COMMENT: &str = "# VaultMesh managed SSH hosts";
const MANAGED_INCLUDE: &str = "Include ~/.ssh/vaultmesh/config.d/*";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySshHostManifest {
    version: u8,
    alias: String,
    account_ref: String,
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
}

pub struct GeneratedSshHostIdentity {
    pub public_key: Zeroizing<String>,
    pub private_key: Zeroizing<String>,
}

#[derive(Debug)]
struct SshHostPaths {
    managed_root: PathBuf,
    host_directory: PathBuf,
    private_key: PathBuf,
    public_key: PathBuf,
    legacy_manifest: PathBuf,
    fragment_directory: PathBuf,
    fragment: PathBuf,
    user_config: PathBuf,
}

pub struct PreparedSshHostIdentity {
    alias: String,
    public_key: Zeroizing<String>,
    public_fingerprint: String,
    verification_key: PrivateKeyMaterial,
    config_ready: bool,
    target: SshTarget,
    paths: SshHostPaths,
}

pub struct SshHostSetupCommit {
    pub alias: String,
    pub public_fingerprint: String,
    pub config_ready: bool,
    target: SshTarget,
    paths: SshHostPaths,
}

impl SshHostSetupCommit {
    pub fn commit_config(&self) -> Result<(), String> {
        commit_config(&self.paths, &self.alias, &self.target)
    }
}

impl PreparedSshHostIdentity {
    pub fn into_parts(self) -> (SshHostSetupCommit, Zeroizing<String>, PrivateKeyMaterial) {
        (
            SshHostSetupCommit {
                alias: self.alias,
                public_fingerprint: self.public_fingerprint,
                config_ready: self.config_ready,
                target: self.target,
                paths: self.paths,
            },
            self.public_key,
            self.verification_key,
        )
    }
}

pub fn generate_ssh_host_identity(alias: &str) -> Result<GeneratedSshHostIdentity, String> {
    validate_ssh_host_alias(alias)?;
    let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|_| "VaultMesh could not generate the SSH identity.".to_owned())?;
    private_key.set_comment(format!("vaultmesh:{alias}"));
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|_| "VaultMesh could not encode the SSH public key.".to_owned())?;
    let private_key = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|_| "VaultMesh could not encode the SSH private key.".to_owned())?;
    Ok(GeneratedSshHostIdentity {
        public_key: Zeroizing::new(public_key),
        private_key,
    })
}

/// Performs the non-mutating local checks required before a new encrypted
/// binding is created. A pre-existing identity or fragment without a Vault
/// owner is never adopted implicitly.
pub fn preflight_new_ssh_host_identity(
    ssh_directory: &Path,
    alias: &str,
    target: &SshTarget,
) -> Result<(), String> {
    validate_ssh_host_alias(alias)?;
    validate_config_token(&target.host)?;
    validate_config_token(&target.username)?;
    let paths = managed_paths(ssh_directory, alias);
    validate_managed_path_boundaries(&paths)?;
    preflight_user_config(&paths, alias)?;
    if paths.host_directory.exists() || paths.fragment.exists() {
        return Err("The SSH alias has local files without an encrypted Vault owner.".to_owned());
    }
    Ok(())
}

/// Imports a sidecar created by the unreleased manifest-backed implementation.
/// The caller must atomically persist the returned exact key pair in the Vault
/// before asking `prepare_ssh_host_identity` to remove the obsolete manifest.
pub fn read_legacy_ssh_host_identity(
    ssh_directory: &Path,
    account_ref: &str,
    alias: &str,
    target: &SshTarget,
    host_key_sha256: &str,
) -> Result<Option<GeneratedSshHostIdentity>, String> {
    validate_ssh_host_alias(alias)?;
    validate_config_token(&target.host)?;
    validate_config_token(&target.username)?;
    let paths = managed_paths(ssh_directory, alias);
    validate_managed_path_boundaries(&paths)?;
    preflight_user_config(&paths, alias)?;
    if !paths.legacy_manifest.exists() {
        return Ok(None);
    }
    let manifest: LegacySshHostManifest =
        serde_json::from_slice(&read_bounded_regular_file(&paths.legacy_manifest)?)
            .map_err(|_| "The obsolete SSH setup manifest is invalid.".to_owned())?;
    let matches = manifest.version == 1
        && manifest.alias == alias
        && manifest.account_ref == account_ref
        && manifest
            .host
            .trim()
            .eq_ignore_ascii_case(target.host.trim())
        && manifest.port == target.port
        && manifest.username.trim() == target.username.trim()
        && manifest.host_key_sha256 == host_key_sha256;
    if !matches {
        return Err(
            "The obsolete SSH setup manifest does not match the approved account.".to_owned(),
        );
    }
    let private_bytes = Zeroizing::new(read_bounded_regular_file(&paths.private_key)?);
    let private_key = PrivateKey::from_openssh(private_bytes.as_slice())
        .map_err(|_| "The managed SSH private key is invalid.".to_owned())?;
    if private_key.is_encrypted() {
        return Err("The managed SSH private key is unexpectedly encrypted.".to_owned());
    }
    let local_public = String::from_utf8(read_bounded_regular_file(&paths.public_key)?)
        .map_err(|_| "The managed SSH public key is invalid.".to_owned())?;
    let derived_public = private_key
        .public_key()
        .to_openssh()
        .map_err(|_| "The managed SSH public key is invalid.".to_owned())?;
    if local_public.trim() != derived_public.trim() {
        return Err("The obsolete managed SSH key pair does not match.".to_owned());
    }
    Ok(Some(GeneratedSshHostIdentity {
        public_key: Zeroizing::new(derived_public),
        private_key: private_key
            .to_openssh(LineEnding::LF)
            .map_err(|_| "The managed SSH private key is invalid.".to_owned())?,
    }))
}

/// Materializes and validates only the OpenSSH files required by the client.
/// Binding ownership and the canonical key pair live in the encrypted Vault;
/// no plaintext sidecar manifest is created.
pub fn prepare_ssh_host_identity(
    ssh_directory: &Path,
    alias: &str,
    target: &SshTarget,
    vault_public_key: &str,
    vault_private_key: &str,
) -> Result<PreparedSshHostIdentity, String> {
    validate_ssh_host_alias(alias)?;
    validate_config_token(&target.host)?;
    validate_config_token(&target.username)?;
    let identity = parse_vault_identity(vault_public_key, vault_private_key)?;
    let paths = managed_paths(ssh_directory, alias);
    validate_managed_path_boundaries(&paths)?;
    preflight_user_config(&paths, alias)?;
    ensure_owner_only_directory(&paths.managed_root)?;
    ensure_owner_only_directory(
        paths
            .host_directory
            .parent()
            .ok_or_else(|| "The managed SSH host directory is invalid.".to_owned())?,
    )?;

    let existing_identity = paths.host_directory.exists();
    if existing_identity {
        validate_existing_identity(&paths, vault_public_key)?;
        if paths.legacy_manifest.exists() {
            migrate_legacy_fragment(&paths, alias, target)?;
            remove_legacy_manifest(&paths)?;
        }
    } else {
        create_local_identity(&paths, vault_public_key, vault_private_key)?;
    }
    let config_ready = config_matches(&paths, alias, target)?;
    Ok(PreparedSshHostIdentity {
        alias: alias.to_owned(),
        public_fingerprint: identity
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
        public_key: Zeroizing::new(vault_public_key.to_owned()),
        verification_key: PrivateKeyMaterial {
            public_key: Some(Zeroizing::new(vault_public_key.to_owned())),
            private_key: Zeroizing::new(vault_private_key.to_owned()),
            passphrase: None,
        },
        config_ready,
        target: target.clone(),
        paths,
    })
}

pub(crate) fn validate_ssh_host_alias(alias: &str) -> Result<(), String> {
    let bytes = alias.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
        || bytes.iter().any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && !matches!(byte, b'.' | b'_' | b'-')
        })
        || alias == "."
        || alias == ".."
    {
        return Err("The SSH host alias is invalid.".to_owned());
    }
    Ok(())
}

fn validate_config_token(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("The SSH account cannot be represented safely in OpenSSH config.".to_owned());
    }
    Ok(())
}

fn parse_vault_identity(public_key: &str, private_key: &str) -> Result<PrivateKey, String> {
    let identity = PrivateKey::from_openssh(private_key.as_bytes())
        .map_err(|_| "The Vault-managed SSH private key is invalid.".to_owned())?;
    if identity.is_encrypted() {
        return Err("The Vault-managed SSH private key is unexpectedly encrypted.".to_owned());
    }
    let expected_public = identity
        .public_key()
        .to_openssh()
        .map_err(|_| "The Vault-managed SSH public key is invalid.".to_owned())?;
    if expected_public.trim() != public_key.trim() {
        return Err("The Vault-managed SSH key pair does not match.".to_owned());
    }
    Ok(identity)
}

fn managed_paths(ssh_directory: &Path, alias: &str) -> SshHostPaths {
    let managed_root = ssh_directory.join("vaultmesh");
    let host_directory = managed_root.join("hosts").join(alias);
    let fragment_directory = managed_root.join("config.d");
    SshHostPaths {
        private_key: host_directory.join("id_ed25519"),
        public_key: host_directory.join("id_ed25519.pub"),
        legacy_manifest: host_directory.join("manifest.json"),
        fragment: fragment_directory.join(format!("{alias}.conf")),
        user_config: ssh_directory.join("config"),
        managed_root,
        host_directory,
        fragment_directory,
    }
}

fn validate_managed_path_boundaries(paths: &SshHostPaths) -> Result<(), String> {
    for path in [
        &paths.managed_root,
        paths.host_directory.parent().expect("host parent"),
        &paths.host_directory,
        &paths.fragment_directory,
        &paths.private_key,
        &paths.public_key,
        &paths.legacy_manifest,
        &paths.fragment,
        &paths.user_config,
        paths.user_config.parent().expect("SSH directory"),
    ] {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            return Err("VaultMesh will not follow an SSH setup symlink.".to_owned());
        }
    }
    Ok(())
}

fn create_local_identity(
    paths: &SshHostPaths,
    public_key: &str,
    private_key: &str,
) -> Result<(), String> {
    let host_parent = paths
        .host_directory
        .parent()
        .ok_or_else(|| "The managed SSH host directory is invalid.".to_owned())?;
    let staging_directory = host_parent.join(format!(".setup-{}", uuid::Uuid::new_v4()));
    ensure_owner_only_directory(&staging_directory)?;
    let staging_private = staging_directory.join("id_ed25519");
    let staging_public = staging_directory.join("id_ed25519.pub");
    let result = (|| {
        write_new_file(&staging_private, private_key.as_bytes(), 0o600)?;
        write_new_file(&staging_public, public_key.as_bytes(), 0o600)?;
        fs::rename(&staging_directory, &paths.host_directory)
            .map_err(|_| "VaultMesh will not overwrite a managed SSH identity.".to_owned())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging_public);
        let _ = fs::remove_file(&staging_private);
        let _ = fs::remove_dir(&staging_directory);
    }
    result
}

fn validate_existing_identity(paths: &SshHostPaths, vault_public_key: &str) -> Result<(), String> {
    let private_bytes = Zeroizing::new(read_bounded_regular_file(&paths.private_key)?);
    let private_key = PrivateKey::from_openssh(private_bytes.as_slice())
        .map_err(|_| "The managed SSH private key is invalid.".to_owned())?;
    if private_key.is_encrypted() {
        return Err("The managed SSH private key is unexpectedly encrypted.".to_owned());
    }
    let local_public = String::from_utf8(read_bounded_regular_file(&paths.public_key)?)
        .map_err(|_| "The managed SSH public key is invalid.".to_owned())?;
    let derived_public = private_key
        .public_key()
        .to_openssh()
        .map_err(|_| "The managed SSH public key is invalid.".to_owned())?;
    if local_public.trim() != derived_public.trim()
        || derived_public.trim() != vault_public_key.trim()
    {
        return Err("The local SSH key pair does not match its encrypted Vault record.".to_owned());
    }
    Ok(())
}

fn remove_legacy_manifest(paths: &SshHostPaths) -> Result<(), String> {
    if !paths.legacy_manifest.exists() {
        return Ok(());
    }
    let _ = read_bounded_regular_file(&paths.legacy_manifest)?;
    fs::remove_file(&paths.legacy_manifest)
        .map_err(|_| "VaultMesh could not remove the obsolete SSH setup manifest.".to_owned())
}

fn migrate_legacy_fragment(
    paths: &SshHostPaths,
    alias: &str,
    target: &SshTarget,
) -> Result<(), String> {
    if !paths.fragment.exists() {
        return Ok(());
    }
    let existing = String::from_utf8(read_bounded_regular_file(&paths.fragment)?)
        .map_err(|_| "The managed SSH config fragment is invalid.".to_owned())?;
    let canonical = render_fragment(alias, target);
    if existing == canonical {
        return Ok(());
    }
    let old_body = existing.lines().skip(1).collect::<Vec<_>>().join("\n");
    let canonical_body = canonical.lines().skip(1).collect::<Vec<_>>().join("\n");
    if old_body != canonical_body {
        return Err("The obsolete managed SSH config fragment has changed.".to_owned());
    }
    write_atomic_private(&paths.fragment, canonical.as_bytes())
}

fn config_matches(paths: &SshHostPaths, alias: &str, target: &SshTarget) -> Result<bool, String> {
    if !paths.fragment.exists() || !paths.user_config.exists() {
        return Ok(false);
    }
    let fragment = String::from_utf8(read_bounded_regular_file(&paths.fragment)?)
        .map_err(|_| "The managed SSH config fragment is invalid.".to_owned())?;
    if fragment != render_fragment(alias, target) {
        return Err("The managed SSH alias config has changed.".to_owned());
    }
    let config = String::from_utf8(read_bounded_regular_file(&paths.user_config)?)
        .map_err(|_| "The OpenSSH user config is not UTF-8.".to_owned())?;
    Ok(first_effective_line(&config) == Some(MANAGED_INCLUDE))
}

fn preflight_user_config(paths: &SshHostPaths, alias: &str) -> Result<(), String> {
    if !paths.user_config.exists() {
        return Ok(());
    }
    let config = String::from_utf8(read_bounded_regular_file(&paths.user_config)?)
        .map_err(|_| "The OpenSSH user config is not UTF-8.".to_owned())?;
    if has_conflicting_host(&config, alias) {
        return Err("The SSH alias already exists outside VaultMesh management.".to_owned());
    }
    Ok(())
}

pub fn register_ephemeral_session_fragment(
    ssh_directory: &Path,
    session_ref: &str,
    target: &crate::ssh_external::LaunchTarget,
    socket_path: &str,
) -> Result<PathBuf, String> {
    let fragment_dir = ssh_directory.join("vaultmesh").join("config.d");
    ensure_owner_only_directory(&fragment_dir)?;

    let user_config = ssh_directory.join("config");
    ensure_managed_include_in_config(&user_config)?;

    let fragment_path = fragment_dir.join(format!("session-{session_ref}"));
    let content = format!(
        "# VaultMesh Ephemeral Session: {session_ref}\nHost {}\n  HostName {}\n  User {}\n  Port {}\n  IdentityAgent {}\n  IdentitiesOnly yes\n",
        target.host(), target.host(), target.username(), target.port(), socket_path
    );
    write_atomic_private(&fragment_path, content.as_bytes())?;
    Ok(fragment_path)
}

fn ensure_managed_include_in_config(user_config: &Path) -> Result<(), String> {
    let existing = if user_config.exists() {
        String::from_utf8(read_bounded_regular_file(user_config)?)
            .map_err(|_| "The OpenSSH user config is not UTF-8.".to_owned())?
    } else {
        String::new()
    };

    if first_effective_line(&existing) == Some(MANAGED_INCLUDE) {
        return Ok(());
    }

    let mut remaining = existing
        .lines()
        .filter(|line| {
            let line = line.trim();
            line != MANAGED_INCLUDE && line != MANAGED_COMMENT
        })
        .collect::<Vec<_>>()
        .join("\n");
    while remaining.starts_with('\n') {
        remaining.remove(0);
    }
    let next = if remaining.is_empty() {
        format!("{MANAGED_COMMENT}\n{MANAGED_INCLUDE}\n")
    } else {
        format!("{MANAGED_COMMENT}\n{MANAGED_INCLUDE}\n\n{remaining}\n")
    };
    write_atomic_private(user_config, next.as_bytes())
}

fn commit_config(paths: &SshHostPaths, alias: &str, target: &SshTarget) -> Result<(), String> {
    validate_managed_path_boundaries(paths)?;
    let existing = if paths.user_config.exists() {
        String::from_utf8(read_bounded_regular_file(&paths.user_config)?)
            .map_err(|_| "The OpenSSH user config is not UTF-8.".to_owned())?
    } else {
        String::new()
    };
    if has_conflicting_host(&existing, alias) {
        return Err("The SSH alias already exists outside VaultMesh management.".to_owned());
    }
    ensure_owner_only_directory(&paths.fragment_directory)?;
    let fragment = render_fragment(alias, target);
    if paths.fragment.exists() {
        let existing = String::from_utf8(read_bounded_regular_file(&paths.fragment)?)
            .map_err(|_| "The managed SSH config fragment is invalid.".to_owned())?;
        if existing != fragment {
            return Err("The managed SSH alias config has changed.".to_owned());
        }
    } else {
        write_new_file(&paths.fragment, fragment.as_bytes(), 0o600)?;
    }

    let mut remaining = existing
        .lines()
        .filter(|line| {
            let line = line.trim();
            line != MANAGED_INCLUDE && line != MANAGED_COMMENT
        })
        .collect::<Vec<_>>()
        .join("\n");
    while remaining.starts_with('\n') {
        remaining.remove(0);
    }
    let next = if remaining.is_empty() {
        format!("{MANAGED_COMMENT}\n{MANAGED_INCLUDE}\n")
    } else {
        format!("{MANAGED_COMMENT}\n{MANAGED_INCLUDE}\n\n{remaining}\n")
    };
    write_atomic_private(&paths.user_config, next.as_bytes())
}

fn render_fragment(alias: &str, target: &SshTarget) -> String {
    format!(
        "# Managed by VaultMesh\nHost {}\n  HostName {}\n  User {}\n  Port {}\n  IdentityFile ~/.ssh/vaultmesh/hosts/{}/id_ed25519\n  IdentitiesOnly yes\n",
        alias, target.host, target.username, target.port, alias,
    )
}

fn has_conflicting_host(config: &str, alias: &str) -> bool {
    config.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            return false;
        }
        let mut fields = trimmed.split_ascii_whitespace();
        fields
            .next()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case("Host"))
            && fields.any(|pattern| pattern.eq_ignore_ascii_case(alias))
    })
}

fn first_effective_line(config: &str) -> Option<&str> {
    config
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "A managed SSH setup file is unavailable.".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_LOCAL_SSH_FILE_BYTES
    {
        return Err("A managed SSH setup file is unsafe.".to_owned());
    }
    fs::read(path).map_err(|_| "A managed SSH setup file could not be read.".to_owned())
}

fn ensure_owner_only_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err("The managed SSH directory is unsafe.".to_owned());
    }
    fs::create_dir_all(path)
        .map_err(|_| "VaultMesh could not create the managed SSH directory.".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "VaultMesh could not protect the managed SSH directory.".to_owned())?;
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8], unix_mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    #[cfg(not(unix))]
    let _ = unix_mode;
    let mut file = options
        .open(path)
        .map_err(|_| "VaultMesh will not overwrite an SSH setup file.".to_owned())?;
    let result = file
        .write_all(contents)
        .and_then(|()| {
            if contents.ends_with(b"\n") {
                Ok(())
            } else {
                file.write_all(b"\n")
            }
        })
        .and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err("VaultMesh could not persist an SSH setup file.".to_owned());
    }
    Ok(())
}

fn write_atomic_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "The OpenSSH config path is invalid.".to_owned())?;
    ensure_owner_only_directory(parent)?;
    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;
        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "VaultMesh could not prepare the OpenSSH config update.".to_owned())?;
    file.write_all(contents)
        .and_then(|()| file.commit())
        .map_err(|_| "VaultMesh could not atomically update the OpenSSH config.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SshTarget {
        SshTarget {
            host: "home.example.test".to_owned(),
            port: 2222,
            username: "deploy".to_owned(),
        }
    }

    fn generated_identity() -> GeneratedSshHostIdentity {
        generate_ssh_host_identity("home-server").expect("generate")
    }

    #[test]
    fn alias_grammar_rejects_openssh_patterns_and_paths() {
        for allowed in ["home-server", "home_server", "home.server", "h1"] {
            assert!(validate_ssh_host_alias(allowed).is_ok(), "{allowed}");
        }
        for denied in [
            "",
            "-home",
            "../home",
            "home server",
            "home*",
            "home?",
            "#home",
            "Home",
        ] {
            assert!(validate_ssh_host_alias(denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn vault_identity_materializes_without_manifest_and_is_idempotent() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-host-setup-{}", uuid::Uuid::new_v4()));
        let ssh_directory = root.join(".ssh");
        fs::create_dir_all(&ssh_directory).expect("ssh directory");
        fs::write(
            ssh_directory.join("config"),
            "Host existing\n  HostName old.example.test\n",
        )
        .expect("existing config");
        let generated = generated_identity();

        let prepared = prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &generated.public_key,
            &generated.private_key,
        )
        .expect("prepare");
        assert!(!prepared.config_ready);
        assert!(!prepared.public_key.contains("PRIVATE"));
        let fingerprint = prepared.public_fingerprint.clone();
        let (commit, _, _) = prepared.into_parts();
        commit.commit_config().expect("commit config");

        let paths = managed_paths(&ssh_directory, "home-server");
        assert!(!paths.legacy_manifest.exists());
        assert!(preflight_new_ssh_host_identity(&ssh_directory, "home-server", &target()).is_err());
        let config = fs::read_to_string(&paths.user_config).expect("config");
        assert_eq!(first_effective_line(&config), Some(MANAGED_INCLUDE));
        assert!(config.contains("Host existing"));
        let fragment = fs::read_to_string(&paths.fragment).expect("fragment");
        assert!(fragment.contains("Host home-server"));
        assert!(fragment.contains("IdentitiesOnly yes"));
        assert!(!fragment.contains("account="));
        assert!(!fragment.contains("host-key="));

        let repeated = prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &generated.public_key,
            &generated.private_key,
        )
        .expect("repeat");
        assert!(repeated.config_ready);
        assert_eq!(fingerprint, repeated.public_fingerprint);
        let (commit, _, _) = repeated.into_parts();
        commit.commit_config().expect("repeat commit");
        let repeated_config = fs::read_to_string(&paths.user_config).expect("config");
        assert_eq!(repeated_config.matches(MANAGED_INCLUDE).count(), 1);
        assert_eq!(repeated_config.matches(MANAGED_COMMENT).count(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn local_key_or_config_drift_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "vaultmesh-host-setup-drift-{}",
            uuid::Uuid::new_v4()
        ));
        let ssh_directory = root.join(".ssh");
        fs::create_dir_all(&ssh_directory).expect("ssh directory");
        fs::write(
            ssh_directory.join("config"),
            "Host home-server\n  HostName user-owned.example.test\n",
        )
        .expect("existing config");
        let generated = generated_identity();
        assert!(
            prepare_ssh_host_identity(
                &ssh_directory,
                "home-server",
                &target(),
                &generated.public_key,
                &generated.private_key,
            )
            .is_err()
        );
        fs::write(ssh_directory.join("config"), "").expect("clear config conflict");
        prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &generated.public_key,
            &generated.private_key,
        )
        .expect("initial identity");
        let other = generated_identity();
        assert!(
            prepare_ssh_host_identity(
                &ssh_directory,
                "home-server",
                &target(),
                &other.public_key,
                &other.private_key,
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn obsolete_manifest_is_removed_after_vault_key_validation() {
        let root = std::env::temp_dir().join(format!(
            "vaultmesh-host-setup-manifest-{}",
            uuid::Uuid::new_v4()
        ));
        let ssh_directory = root.join(".ssh");
        fs::create_dir_all(&ssh_directory).expect("ssh directory");
        let generated = generated_identity();
        let prepared = prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &generated.public_key,
            &generated.private_key,
        )
        .expect("initial identity");
        let (commit, _, _) = prepared.into_parts();
        commit.commit_config().expect("initial config");
        let paths = managed_paths(&ssh_directory, "home-server");
        let account_ref = "11111111-1111-4111-8111-111111111111";
        let host_key = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        fs::write(
            &paths.legacy_manifest,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "alias": "home-server",
                "accountRef": account_ref,
                "host": target().host,
                "port": target().port,
                "username": target().username,
                "hostKeySha256": host_key,
            }))
            .expect("manifest JSON"),
        )
        .expect("legacy manifest");
        let old_fragment = fs::read_to_string(&paths.fragment)
            .expect("fragment")
            .replacen(
                "# Managed by VaultMesh",
                &format!("# Managed by VaultMesh; account={account_ref} host-key={host_key}"),
                1,
            );
        fs::write(&paths.fragment, old_fragment).expect("old fragment");
        let imported = read_legacy_ssh_host_identity(
            &ssh_directory,
            account_ref,
            "home-server",
            &target(),
            host_key,
        )
        .expect("read legacy")
        .expect("legacy identity");
        assert_eq!(imported.public_key.trim(), generated.public_key.trim());
        let migrated = prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &imported.public_key,
            &imported.private_key,
        )
        .expect("migrate");
        assert!(migrated.config_ready);
        assert!(!paths.legacy_manifest.exists());
        assert_eq!(
            fs::read_to_string(&paths.fragment).expect("migrated fragment"),
            render_fragment("home-server", &target())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn managed_key_and_config_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "vaultmesh-host-setup-mode-{}",
            uuid::Uuid::new_v4()
        ));
        let ssh_directory = root.join(".ssh");
        fs::create_dir_all(&ssh_directory).expect("ssh directory");
        let generated = generated_identity();
        let prepared = prepare_ssh_host_identity(
            &ssh_directory,
            "home-server",
            &target(),
            &generated.public_key,
            &generated.private_key,
        )
        .expect("prepare");
        let (commit, _, _) = prepared.into_parts();
        commit.commit_config().expect("config");
        let paths = managed_paths(&ssh_directory, "home-server");
        assert_eq!(
            fs::metadata(paths.private_key)
                .expect("private")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(paths.user_config)
                .expect("config")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_managed_root_or_user_config_fails_closed() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "vaultmesh-host-setup-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        let ssh_directory = root.join(".ssh");
        let outside = root.join("outside");
        fs::create_dir_all(&ssh_directory).expect("ssh directory");
        fs::create_dir_all(&outside).expect("outside");
        let generated = generated_identity();
        symlink(&outside, ssh_directory.join("vaultmesh")).expect("managed symlink");
        assert!(
            prepare_ssh_host_identity(
                &ssh_directory,
                "home-server",
                &target(),
                &generated.public_key,
                &generated.private_key,
            )
            .is_err()
        );
        fs::remove_file(ssh_directory.join("vaultmesh")).expect("remove managed symlink");
        symlink(outside.join("config"), ssh_directory.join("config")).expect("config symlink");
        assert!(
            prepare_ssh_host_identity(
                &ssh_directory,
                "home-server",
                &target(),
                &generated.public_key,
                &generated.private_key,
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ephemeral_session_fragment_registers_and_cleans_up() {
        let root = std::env::temp_dir().join(format!("vm-ephemeral-session-{}", uuid::Uuid::new_v4()));
        let ssh_directory = root.join(".ssh");
        fs::create_dir_all(&ssh_directory).unwrap();
        let target = crate::ssh_external::LaunchTarget::new("192.168.1.100", 2222, "deploy").unwrap();
        let socket_path = "/tmp/vaultmesh-501/sess_test.sock";

        let fragment = register_ephemeral_session_fragment(
            &ssh_directory,
            "test_session",
            &target,
            socket_path,
        )
        .expect("fragment");

        assert!(fragment.exists());
        let content = fs::read_to_string(&fragment).unwrap();
        assert!(content.contains("Host 192.168.1.100"));
        assert!(content.contains("IdentityAgent /tmp/vaultmesh-501/sess_test.sock"));
        assert!(content.contains("Port 2222"));
        assert!(content.contains("User deploy"));

        let user_config = fs::read_to_string(ssh_directory.join("config")).unwrap();
        assert!(user_config.contains(MANAGED_INCLUDE));

        fs::remove_file(&fragment).unwrap();
        assert!(!fragment.exists());
        let _ = fs::remove_dir_all(root);
    }
}
