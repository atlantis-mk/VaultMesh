const BITWARDEN_DEVELOPMENT_HOST: bool = false;
#[path = "../browser_development_identity.rs"]
#[allow(dead_code)]
mod development_identity;
include!("../native_host.inc.rs");
