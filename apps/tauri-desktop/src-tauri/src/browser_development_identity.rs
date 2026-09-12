//! Fixed opt-in identity for the independent Bitwarden development fork.
//! These are public identifiers, never pairing secrets or release identities.
pub const HOST_NAME: &str = "com.vaultmesh.bitwarden.dev";
pub const EXTENSION_ID: &str = "edggbpbfcfagdnhiameocjapmggojhka";
pub const FIREFOX_ID: &str = "bitwarden-dev@vaultmesh.local";
pub const CONFIG_NAME: &str = "bitwarden-dev-host-config.json";
pub const DIRECTORY: &str = "bitwarden-development";
pub const SOCKET_NAME: &str = "vaultmesh-bitwarden-dev.sock";
pub const PIPE_NAME: &str = r"\\.\pipe\VaultMesh.BitwardenDevelopment.v2";
pub const PAIRING_SERVICE: &str = "com.vaultmesh.desktop.bitwarden-dev-pairing";
pub const PAIRING_ACCOUNT: &str = "native-host-hmac-v1";

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    #[test]
    fn development_identity_matches_public_key_and_never_aliases_the_existing_host() {
        let identity: serde_json::Value = serde_json::from_str(include_str!(
            "../../../bitwarden-browser/development-identity.json"
        ))
        .unwrap();
        assert_eq!(identity["hostName"], HOST_NAME);
        assert_eq!(identity["extensionId"], EXTENSION_ID);
        assert_eq!(identity["firefoxId"], FIREFOX_ID);
        let key = STANDARD.decode(identity["key"].as_str().unwrap()).unwrap();
        let digest = Sha256::digest(key);
        let id: String = digest[..16]
            .iter()
            .flat_map(|b| [char::from(b'a' + (b >> 4)), char::from(b'a' + (b & 15))])
            .collect();
        assert_eq!(id, EXTENSION_ID);
        assert_ne!(HOST_NAME, "com.vaultmesh.browser");
        assert_ne!(EXTENSION_ID, "dmmjcaemejijgkpginfccokjmbknbgif");
        assert_ne!(FIREFOX_ID, "vaultmesh@atlantis-mk.github.io");
        assert_ne!(PAIRING_SERVICE, "com.vaultmesh.desktop.browser-pairing");
    }
}
