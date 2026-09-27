//! Platform-neutral ciphertext cache and privileged runtime contract.
pub mod relay;
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
use vaultmesh_core::{SyncChannel, SyncState};

pub trait SyncRuntime: Send + 'static {
    type Error;
    fn current_path(&self) -> PathBuf;
    fn is_unlocked(&self) -> bool;
    fn sync_relay(&self) -> Arc<relay::RelayHub>;
    fn sync_state(&mut self) -> Result<SyncState, Self::Error>;
    fn sync_pump(&mut self) -> Result<(), Self::Error>;
    fn sync_channel_offer(&self, peer: &str) -> Result<SyncChannel, Self::Error>;
    fn sync_accept_channel(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        offer: &SyncChannel,
    ) -> Result<(), Self::Error>;
}
