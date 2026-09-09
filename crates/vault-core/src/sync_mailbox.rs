//! Pairwise sealed mailboxes. Direction keys never leave the encrypted Vault
//! except during an explicitly authorized, pinned mutual-TLS bootstrap.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncChannel {
    pub id: Uuid,
    key: String,
}
impl std::fmt::Debug for SyncChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncChannel([REDACTED])")
    }
}
impl Drop for SyncChannel {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl SyncChannel {
    pub(crate) fn new() -> Self {
        let mut key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(key.as_mut());
        Self {
            id: Uuid::new_v4(),
            key: B64.encode(key.as_ref()),
        }
    }
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let bytes = Zeroizing::new(
            B64.decode(&self.key)
                .map_err(|_| VaultError::InvalidPayload)?,
        );
        if self.id.is_nil() || bytes.len() != 32 {
            return Err(VaultError::InvalidPayload);
        }
        Ok(bytes)
    }
}

/// Public routing facts; no record identifiers, digests, or direction keys.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRoute {
    pub peer: String,
    pub fingerprint: String,
    pub local: Uuid,
    pub remote: Option<Uuid>,
    pub outgoing: Uuid,
    pub incoming: Option<Uuid>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncPacket {
    pub channel: Uuid,
    pub id: String,
    pub nonce: String,
    pub ciphertext: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncMailboxReceipt {
    pub packet: String,
    pub manifest: SyncManifest,
}

fn aad(sender: Uuid, target: Uuid, channel: Uuid, kind: &str) -> Vec<u8> {
    format!("VaultMesh/mailbox/v2/{sender}/{target}/{channel}/{kind}").into_bytes()
}
fn subkey(secret: &[u8], purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| VaultError::Crypto)?;
    mac.update(b"VaultMesh/mailbox/v2/subkey/");
    mac.update(purpose);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}
fn seal<T: Serialize>(
    key: &SyncChannel,
    sender: Uuid,
    target: Uuid,
    kind: &str,
    body: &T,
) -> Result<SyncPacket, VaultError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(body).map_err(|_| VaultError::Serialization)?);
    if plaintext.len() > SYNC_MAX_BYTES {
        return Err(VaultError::InvalidPayload);
    }
    let secret = key.bytes()?;
    let encryption_key = subkey(&secret, b"aead")?;
    let identity_key = subkey(&secret, b"content-id")?;
    let aad = aad(sender, target, key.id, kind);
    // Keyed content identity avoids both redundant encryption/transmission and
    // exposing a dictionary-testable plaintext digest in the locked cache.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity_key.as_ref())
        .map_err(|_| VaultError::Crypto)?;
    mac.update(&aad);
    mac.update(&plaintext);
    let id = B64.encode(mac.finalize().into_bytes());
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_ref())
        .map_err(|_| VaultError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(SyncPacket {
        channel: key.id,
        id,
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}
fn open<T: for<'de> Deserialize<'de>>(
    key: &SyncChannel,
    sender: Uuid,
    target: Uuid,
    kind: &str,
    packet: &SyncPacket,
) -> Result<T, VaultError> {
    if packet.channel != key.id
        || packet.ciphertext.len() > (SYNC_MAX_BYTES + 16).div_ceil(3) * 4
        || packet.nonce.len() != 32
        || packet.id.len() != 44
    {
        return Err(VaultError::InvalidPayload);
    }
    let nonce = B64
        .decode(&packet.nonce)
        .map_err(|_| VaultError::InvalidPayload)?;
    let ciphertext = B64
        .decode(&packet.ciphertext)
        .map_err(|_| VaultError::InvalidPayload)?;
    if nonce.len() != 24 {
        return Err(VaultError::InvalidPayload);
    }
    let secret = key.bytes()?;
    let aad = aad(sender, target, key.id, kind);
    let encryption_key = subkey(&secret, b"aead")?;
    let identity_key = subkey(&secret, b"content-id")?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_ref())
        .map_err(|_| VaultError::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::InvalidPayload)?,
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity_key.as_ref())
        .map_err(|_| VaultError::Crypto)?;
    mac.update(&aad);
    mac.update(&plaintext);
    let tag = B64
        .decode(&packet.id)
        .map_err(|_| VaultError::InvalidPayload)?;
    mac.verify_slice(&tag)
        .map_err(|_| VaultError::InvalidPayload)?;
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidPayload)
}

impl VaultSession {
    fn mailbox_auth(&self, peer: &str) -> Result<&SyncAuthorization, VaultError> {
        self.sync_state()?
            .authorizations
            .iter()
            .find(|a| a.peer == peer && a.enabled && a.outgoing.is_some())
            .ok_or(VaultError::InvalidPayload)
    }
    pub fn sync_routes(&self) -> Result<Vec<SyncRoute>, VaultError> {
        let state = self.sync_state()?;
        Ok(state
            .authorizations
            .iter()
            .filter(|a| a.enabled && a.outgoing.is_some())
            .map(|a| SyncRoute {
                peer: a.peer.clone(),
                fingerprint: a.fingerprint.clone(),
                local: state.vault_id,
                remote: a.remote_vault,
                outgoing: a.outgoing.as_ref().unwrap().id,
                incoming: a.incoming.as_ref().map(|k| k.id),
            })
            .collect())
    }
    pub fn sync_channel_offer(&self, peer: &str) -> Result<SyncChannel, VaultError> {
        Ok(self.mailbox_auth(peer)?.outgoing.clone().unwrap())
    }
    pub fn sync_accept_channel(
        &mut self,
        peer: &str,
        fingerprint: &str,
        remote: Uuid,
        offer: &SyncChannel,
    ) -> Result<(), VaultError> {
        offer.bytes()?;
        self.mailbox_auth(peer)?;
        self.sync_bind(peer, fingerprint, remote)?;
        let auth = self
            .payload_mut()?
            .sync
            .authorizations
            .iter_mut()
            .find(|a| a.peer == peer)
            .unwrap();
        // An existing authorized peer can rotate its direction after re-enable,
        // but only through the unlocked, pinned TLS bootstrap for the same Vault.
        if auth.incoming.as_ref() != Some(offer) {
            auth.applied_packet = None;
            auth.confirmed_packet = None;
        }
        auth.incoming = Some(offer.clone());
        Ok(())
    }
    pub fn sync_mailbox_export(&self, peer: &str) -> Result<Option<SyncPacket>, VaultError> {
        let a = self.mailbox_auth(peer)?;
        let Some(remote) = a.remote_vault.filter(|_| a.incoming.is_some()) else {
            return Ok(None);
        };
        let records = self.sync_export(&a.confirmed)?;
        if records.is_empty() {
            return Ok(None);
        }
        seal(
            a.outgoing.as_ref().unwrap(),
            self.sync_state()?.vault_id,
            remote,
            "records",
            &records,
        )
        .map(Some)
    }
    /// Caller commits the resulting Vault before publishing this receipt.
    pub fn sync_mailbox_apply(
        &mut self,
        peer: &str,
        packet: &SyncPacket,
        now: u64,
    ) -> Result<(usize, SyncPacket), VaultError> {
        let a = self.mailbox_auth(peer)?;
        let remote = a.remote_vault.ok_or(VaultError::InvalidPayload)?;
        let local = self.sync_state()?.vault_id;
        let records: Vec<SyncRecord> = open(
            a.incoming.as_ref().ok_or(VaultError::InvalidPayload)?,
            remote,
            local,
            "records",
            packet,
        )?;
        let manifest = records
            .iter()
            .map(|r| (r.key.clone(), r.entry.clone()))
            .collect();
        let count = self.sync_merge(&records, now)?;
        let a = self
            .payload_mut()?
            .sync
            .authorizations
            .iter_mut()
            .find(|a| a.peer == peer)
            .unwrap();
        a.applied_packet = Some(packet.id.clone());
        let receipt = seal(
            a.outgoing.as_ref().unwrap(),
            local,
            remote,
            "receipt",
            &SyncMailboxReceipt {
                packet: packet.id.clone(),
                manifest,
            },
        )?;
        Ok((count, receipt))
    }
    pub fn sync_mailbox_confirm(
        &mut self,
        peer: &str,
        packet: &SyncPacket,
    ) -> Result<(), VaultError> {
        let a = self.mailbox_auth(peer)?;
        let receipt: SyncMailboxReceipt = open(
            a.incoming.as_ref().ok_or(VaultError::InvalidPayload)?,
            a.remote_vault.ok_or(VaultError::InvalidPayload)?,
            self.sync_state()?.vault_id,
            "receipt",
            packet,
        )?;
        if receipt.manifest.len() > SYNC_MAX_RECORDS {
            return Err(VaultError::InvalidPayload);
        }
        self.sync_confirm_manifest(&receipt.manifest)?;
        let a = self
            .payload_mut()?
            .sync
            .authorizations
            .iter_mut()
            .find(|a| a.peer == peer)
            .unwrap();
        a.confirmed_packet = Some(packet.id.clone());
        for (key, entry) in receipt.manifest {
            if a.confirmed
                .get(&key)
                .is_none_or(|old| old.version < entry.version || old == &entry)
            {
                a.confirmed.insert(key, entry);
            }
        }
        if a.confirmed.len() > SYNC_MAX_RECORDS {
            return Err(VaultError::InvalidPayload);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mesh(count: usize) -> Vec<VaultSession> {
        let mut peers: Vec<_> = (0..count)
            .map(|_| VaultSession::create("synthetic mesh password").unwrap())
            .collect();
        for i in 0..count {
            for j in 0..count {
                if i != j {
                    peers[i]
                        .sync_authorize(&format!("lan-peer-{j}"), &format!("{j:064x}"), true)
                        .unwrap();
                }
            }
        }
        for i in 0..count {
            for j in 0..count {
                if i != j {
                    let key = peers[j]
                        .sync_channel_offer(&format!("lan-peer-{i}"))
                        .unwrap();
                    let remote = peers[j].sync_state().unwrap().vault_id;
                    peers[i]
                        .sync_accept_channel(
                            &format!("lan-peer-{j}"),
                            &format!("{j:064x}"),
                            remote,
                            &key,
                        )
                        .unwrap();
                }
            }
        }
        peers
    }
    fn deliver(peers: &mut [VaultSession], i: usize, j: usize) {
        if let Some(packet) = peers[i]
            .sync_mailbox_export(&format!("lan-peer-{j}"))
            .unwrap()
        {
            let (_, ack) = peers[j]
                .sync_mailbox_apply(&format!("lan-peer-{i}"), &packet, 1)
                .unwrap();
            peers[j].sync_checkpoint(1).unwrap();
            peers[i]
                .sync_mailbox_confirm(&format!("lan-peer-{j}"), &ack)
                .unwrap();
        }
    }
    #[test]
    fn ct_lan_sync_five_mailboxes_offline_conflict_reordering_and_duplicate_forwarding() {
        let mut peers = mesh(5);
        peers[0].payload_mut().unwrap().items.push(LoginItem::new(
            "mesh".into(),
            "u".into(),
            "initial".into(),
        ));
        peers[0].sync_checkpoint(100).unwrap();
        for j in 1..5 {
            deliver(&mut peers, 0, j);
        }
        for (i, p) in peers.iter_mut().enumerate() {
            p.payload_mut().unwrap().items[0].password = format!("synthetic concurrent {i}");
            p.sync_checkpoint(90 - i as u64).unwrap(); // wall-clock rollback
        }
        let stale = peers[0].sync_mailbox_export("lan-peer-1").unwrap().unwrap();
        for _ in 0..5 {
            for i in (0..5).rev() {
                for j in 0..5 {
                    if i != j {
                        deliver(&mut peers, i, j);
                    }
                }
            }
        }
        for p in &peers[1..] {
            assert_eq!(
                p.sync_state().unwrap().entries,
                peers[0].sync_state().unwrap().entries
            );
            assert_eq!(
                p.payload().unwrap().items[0].password,
                peers[0].payload().unwrap().items[0].password
            );
            assert_eq!(p.sync_state().unwrap().conflicts.len(), 4);
        }
        let before = peers[1].sync_state().unwrap().entries.clone();
        peers[1]
            .sync_mailbox_apply("lan-peer-0", &stale, 0)
            .unwrap();
        assert_eq!(peers[1].sync_state().unwrap().entries, before);
        // A ciphertext intended for B cannot be opened on the A→C channel.
        assert!(
            peers[2]
                .sync_mailbox_apply("lan-peer-0", &stale, 0)
                .is_err()
        );
    }
    #[test]
    fn ct_lan_sync_sealed_passkey_receipt_is_per_peer_and_requires_applied_copy() {
        let mut peers = mesh(3);
        let secret: SecretItem = serde_json::from_value(serde_json::json!({"id":Uuid::new_v4(),"title":"synthetic key","kind":"authenticator-key","provider":null,"account":null,"secret":"{\"backupEligible\":true,\"backupState\":false,\"signCount\":0}","environment":null,"scopes":["vaultmesh:passkey:v1"],"expires_at":null,"website":null,"notes":null,"folder":null,"favorite":false,"master_password_reprompt":false})).unwrap();
        peers[0].payload_mut().unwrap().secrets.push(secret);
        peers[0].sync_checkpoint(1).unwrap();
        let for_b = peers[0].sync_mailbox_export("lan-peer-1").unwrap().unwrap();
        let for_c = peers[0].sync_mailbox_export("lan-peer-2").unwrap().unwrap();
        assert_ne!(for_b.channel, for_c.channel);
        let backup = |s: &VaultSession| {
            serde_json::from_str::<serde_json::Value>(&s.payload().unwrap().secrets[0].secret)
                .unwrap()["backupState"]
                .as_bool()
                .unwrap()
        };
        assert!(!backup(&peers[0])); // Merely sealing or storing never marks BS.
        let (_, ack) = peers[1]
            .sync_mailbox_apply("lan-peer-0", &for_b, 2)
            .unwrap();
        assert!(backup(&peers[1]));
        assert!(peers[0].sync_mailbox_confirm("lan-peer-2", &ack).is_err());
        assert!(!backup(&peers[0]));
        peers[0].sync_mailbox_confirm("lan-peer-1", &ack).unwrap();
        assert!(backup(&peers[0]));
        assert!(
            peers[0]
                .sync_mailbox_export("lan-peer-1")
                .unwrap()
                .is_none()
        );
        assert!(
            peers[0]
                .sync_mailbox_export("lan-peer-2")
                .unwrap()
                .is_some()
        );
        peers[1]
            .sync_authorize("lan-peer-0", &format!("{:064x}", 0), false)
            .unwrap();
        assert!(
            peers[1]
                .sync_mailbox_apply("lan-peer-0", &for_b, 3)
                .is_err()
        );
        peers[2].sync_reset_after_restore().unwrap();
        assert!(
            peers[2]
                .sync_mailbox_apply("lan-peer-0", &for_c, 3)
                .is_err()
        );
    }
    #[test]
    fn ct_lan_sync_mailbox_rejects_wrong_peer_tamper_and_receipt_domain() {
        let a = SyncChannel::new();
        let b = SyncChannel::new();
        let sender = Uuid::new_v4();
        let receiver = Uuid::new_v4();
        let packet = seal(&a, sender, receiver, "records", &vec!["synthetic secret"]).unwrap();
        assert!(
            !serde_json::to_string(&packet)
                .unwrap()
                .contains("synthetic secret")
        );
        assert_eq!(
            open::<Vec<String>>(&a, sender, receiver, "records", &packet).unwrap(),
            vec!["synthetic secret"]
        );
        assert!(open::<Vec<String>>(&b, sender, receiver, "records", &packet).is_err());
        assert!(open::<Vec<String>>(&a, sender, Uuid::new_v4(), "records", &packet).is_err());
        assert!(open::<Vec<String>>(&a, sender, receiver, "receipt", &packet).is_err());
        let mut tampered = packet.clone();
        tampered.id.replace_range(0..1, "!");
        assert!(open::<Vec<String>>(&a, sender, receiver, "records", &tampered).is_err());
    }
}
