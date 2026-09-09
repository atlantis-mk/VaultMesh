//! Persistent protocol v2. Only sealed packets cross the post-bootstrap wire.
use super::*;
use vaultmesh_ffi::sync_relay::{RELAY_MAX_PACKET, RelayBlob, RelaySummary};
use vaultmesh_ffi::{SyncChannel, SyncPacket};
const FRAME_LIMIT: usize = 128 * 1024;
const CHUNK: usize = 32 * 1024;
const HEARTBEAT: Duration = Duration::from_secs(15);
const STALL: Duration = Duration::from_secs(30);
static RECEIVING: AtomicU64 = AtomicU64::new(0);
const RECEIVE_BUDGET: u64 = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    instance: String,
    nonce: String,
    vault: Uuid,
    sending: Uuid,
    receiving: Option<Uuid>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Frame {
    State {
        summary: RelaySummary,
    },
    Want {
        receipt: bool,
        id: String,
        offset: usize,
    },
    Chunk {
        receipt: bool,
        id: String,
        offset: usize,
        data: String,
    },
    Gone {
        receipt: bool,
        id: String,
    },
    Ping,
}
struct Incoming {
    info: RelayBlob,
    data: String,
    started: Instant,
}
impl Incoming {
    fn new(info: RelayBlob) -> Result<Self, ()> {
        if info.size == 0
            || info.size > RELAY_MAX_PACKET
            || info.id.len() != 44
            || info.nonce.len() != 32
            || info.channel.is_nil()
        {
            return Err(());
        }
        RECEIVING
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n.saturating_add(info.size as u64) <= RECEIVE_BUDGET)
                    .then_some(n + info.size as u64)
            })
            .map_err(|_| ())?;
        Ok(Self {
            info,
            data: String::new(),
            started: Instant::now(),
        })
    }
}
impl Drop for Incoming {
    fn drop(&mut self) {
        RECEIVING.fetch_sub(self.info.size as u64, Ordering::AcqRel);
    }
}
struct PeerGuard {
    active: Arc<Mutex<HashSet<String>>>,
    peer: String,
}
impl Drop for PeerGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.active.lock() {
            peers.remove(&self.peer);
        }
    }
}
struct HandshakeGuard(Arc<AtomicUsize>);
impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn send_frame<T: Serialize>(tls: &mut TlsStream, frame: &T) -> Result<(), ()> {
    let bytes = Zeroizing::new(serde_json::to_vec(frame).map_err(|_| ())?);
    if bytes.len() > FRAME_LIMIT {
        return Err(());
    }
    tls.write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    tls.write_all(&bytes).map_err(|_| ())?;
    tls.flush().map_err(|_| ())
}
fn bootstrap<T: Serialize, R: for<'de> Deserialize<'de>>(
    tls: &mut TlsStream,
    client: bool,
    value: &T,
) -> Result<R, ()> {
    fn read<R: for<'de> Deserialize<'de>>(tls: &mut TlsStream) -> Result<R, ()> {
        let mut len = [0; 4];
        tls.read_exact(&mut len).map_err(|_| ())?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > FRAME_LIMIT {
            return Err(());
        }
        let mut bytes = Zeroizing::new(vec![0; len]);
        tls.read_exact(&mut bytes).map_err(|_| ())?;
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
    if client {
        send_frame(tls, value)?;
        read(tls)
    } else {
        let v = read(tls)?;
        send_frame(tls, value)?;
        Ok(v)
    }
}
fn route(context: &Context, peer: &str) -> Result<vaultmesh_ffi::SyncRoute, ()> {
    let route = context.hub.route(peer)?;
    if route.local != context.local {
        return Err(());
    }
    Ok(route)
}
fn publish_status(
    context: &Context,
    peer: &str,
    ours: &RelaySummary,
    theirs: Option<&RelaySummary>,
) {
    let state = if context.hub.failed() {
        "failed"
    } else if theirs.is_some_and(|r| {
        ours.data.is_none()
            && r.data
                .as_ref()
                .is_none_or(|p| ours.applied.as_ref() == Some(&p.id))
    }) {
        "synced"
    } else if theirs.is_some_and(|r| {
        ours.data
            .as_ref()
            .is_some_and(|p| r.received.as_ref() == Some(&p.id))
    }) {
        "delivered"
    } else {
        "syncing"
    };
    update(context, peer, state, state == "synced");
}
/// Polling only the socket preserves partial TLS/frame reads. It does not read
/// the Vault or emit idle manifests; either endpoint can push independently.
struct Reader {
    bytes: Vec<u8>,
    started: Option<Instant>,
}
impl Reader {
    fn next(&mut self, tls: &mut TlsStream) -> Result<Option<Frame>, ()> {
        if self.started.is_some_and(|t| t.elapsed() > STALL) {
            return Err(());
        }
        let needed = if self.bytes.len() < 4 {
            4
        } else {
            let size = u32::from_be_bytes(self.bytes[..4].try_into().unwrap()) as usize;
            if size == 0 || size > FRAME_LIMIT {
                return Err(());
            }
            size + 4
        };
        if self.bytes.len() == needed && needed > 4 {
            let frame = serde_json::from_slice(&self.bytes[4..]).map_err(|_| ())?;
            self.bytes.clear();
            self.started = None;
            return Ok(Some(frame));
        }
        let mut buf = [0; 16 * 1024];
        let take = buf.len().min(needed - self.bytes.len());
        match tls.read(&mut buf[..take]) {
            Ok(0) => Err(()),
            Ok(n) => {
                self.started.get_or_insert_with(Instant::now);
                self.bytes.extend_from_slice(&buf[..n]);
                Ok(None)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(_) => Err(()),
        }
    }
}
pub(super) fn exchange(
    mut socket: TcpStream,
    client: bool,
    expected: Option<(String, String)>,
    context: &Context,
) -> Result<(), ()> {
    if context.stop.load(Ordering::Acquire) {
        return Err(());
    }
    context
        .handshakes
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_HANDSHAKES).then_some(n + 1)
        })
        .map_err(|_| ())?;
    let mut handshake_guard = Some(HandshakeGuard(context.handshakes.clone()));
    let session = context
        .sessions
        .register_with_limit(&socket, MAX_PEERS + MAX_HANDSHAKES)?;
    socket.set_nodelay(true).map_err(|_| ())?;
    let deadline_socket = socket.try_clone().map_err(|_| ())?;
    let (cancel, wait) = mpsc::channel::<()>();
    thread::spawn(move || {
        if matches!(
            wait.recv_timeout(STALL),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = deadline_socket.shutdown(std::net::Shutdown::Both);
        }
    });
    // Bootstrap includes durable key binding and reconstructing a large
    // outbox. Its absolute watchdog remains 30 s; a peer waiting for that
    // commit must not use the shorter ordinary write timeout.
    socket.set_read_timeout(Some(STALL)).map_err(|_| ())?;
    socket.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let cert = if client {
        write_cert(&mut socket, &context.identity.cert)?;
        read_cert(&mut socket)?
    } else {
        let c = read_cert(&mut socket)?;
        write_cert(&mut socket, &context.identity.cert)?;
        c
    };
    let fingerprint = hex_digest(&cert);
    let peer = trusted(context, &fingerprint)?;
    {
        let mut peers = context.active_peers.lock().map_err(|_| ())?;
        if !peers.insert(peer.clone()) {
            return Err(());
        }
    }
    let _guard = PeerGuard {
        active: context.active_peers.clone(),
        peer: peer.clone(),
    };
    let mut tls = if client {
        client_tls(socket, &context.identity, &cert)?
    } else {
        server_tls(socket, &context.identity, &cert)?
    };
    tls.complete_handshake()?;
    context.sessions.bind_peer(&session, &peer)?;
    let result = (|| {
        let initial = route(context, &peer)?;
        let remote: Hello = bootstrap(
            &mut tls,
            client,
            &Hello {
                version: SYNC_PROTOCOL,
                instance: context.instance.clone(),
                nonce: context.nonce.clone(),
                vault: context.local,
                sending: initial.outgoing,
                receiving: initial.incoming,
            },
        )?;
        if remote.version != SYNC_PROTOCOL
            || !valid_token(&remote.instance)
            || !valid_token(&remote.nonce)
            || remote.vault.is_nil()
            || initial.remote.is_some_and(|v| v != remote.vault)
            || expected
                .as_ref()
                .is_some_and(|(i, n)| i != &remote.instance || n != &remote.nonce)
        {
            return Err(());
        }
        let needs_key = initial.incoming != Some(remote.sending);
        let peer_needs_key = remote.receiving != Some(initial.outgoing);
        if needs_key || peer_needs_key {
            let sensitive = {
                let runtime = context.runtime.lock().map_err(|_| ())?;
                if !runtime.is_unlocked() {
                    return Err(());
                }
                match &tls {
                    TlsStream::Client(s) => context.bootstraps.register(&s.sock)?,
                    TlsStream::Server(s) => context.bootstraps.register(&s.sock)?,
                }
            };
            let offer = if peer_needs_key {
                Some(
                    context
                        .runtime
                        .lock()
                        .map_err(|_| ())?
                        .sync_channel_offer(&peer)
                        .map_err(|_| ())?,
                )
            } else {
                None
            };
            let other: Option<SyncChannel> = bootstrap(&mut tls, client, &offer)?;
            drop(offer);
            if needs_key {
                if other.as_ref().is_none_or(|key| key.id != remote.sending) {
                    return Err(());
                }
                context
                    .runtime
                    .lock()
                    .map_err(|_| ())?
                    .sync_accept_channel(
                        &peer,
                        &fingerprint,
                        remote.vault,
                        other.as_ref().ok_or(())?,
                    )
                    .map_err(|_| ())?;
            }
            drop(other);
            let ready: bool = bootstrap(&mut tls, client, &true)?;
            if !ready {
                return Err(());
            }
            drop(sensitive);
        }
        let bound = route(context, &peer)?;
        if bound.remote != Some(remote.vault) || bound.incoming.is_none() {
            return Err(());
        }
        // The persistent loop has per-frame, transfer and liveness deadlines;
        // its overall lifetime is intentionally unbounded while authorized.
        let _ = cancel.send(());
        drop(handshake_guard.take());
        match &tls {
            TlsStream::Client(s) => s.sock.set_read_timeout(Some(Duration::from_millis(100))),
            TlsStream::Server(s) => s.sock.set_read_timeout(Some(Duration::from_millis(100))),
        }
        .map_err(|_| ())?;
        let mut reader = Reader {
            bytes: Vec::new(),
            started: None,
        };
        let mut received = [None::<Incoming>, None];
        let mut last_summary = None;
        let mut remote_summary = None;
        let mut last_sent = Instant::now();
        let mut last_received = Instant::now();
        let mut last_trust = Instant::now();
        let mut generation = 0;
        loop {
            if context.stop.load(Ordering::Acquire) {
                return Ok(());
            }
            if route(context, &peer)? != bound {
                return Err(());
            }
            if last_trust.elapsed() >= Duration::from_secs(1) {
                trusted(context, &fingerprint)?;
                last_trust = Instant::now();
            }
            if last_received.elapsed() > STALL {
                return Err(());
            }
            if received
                .iter()
                .flatten()
                .any(|x| x.started.elapsed() > Duration::from_secs(120))
            {
                return Err(());
            }
            let current_generation = context.hub.generation();
            if generation != current_generation {
                let summary = context.hub.summary(&peer)?;
                if last_summary.as_ref() != Some(&summary) {
                    #[cfg(test)]
                    if summary.receipt.is_some()
                        && context.drop_receipt.swap(false, Ordering::AcqRel)
                    {
                        return Err(());
                    }
                    send_frame(
                        &mut tls,
                        &Frame::State {
                            summary: summary.clone(),
                        },
                    )?;
                    publish_status(context, &peer, &summary, remote_summary.as_ref());
                    last_summary = Some(summary);
                    last_sent = Instant::now();
                }
                generation = current_generation;
            }
            if last_sent.elapsed() >= HEARTBEAT {
                send_frame(&mut tls, &Frame::Ping)?;
                last_sent = Instant::now();
            }
            let Some(frame) = reader.next(&mut tls)? else {
                continue;
            };
            last_received = Instant::now();
            match frame {
                Frame::Ping => {}
                Frame::State { summary } => {
                    let ours = context.hub.summary(&peer)?;
                    publish_status(context, &peer, &ours, Some(&summary));
                    remote_summary = Some(summary.clone());
                    for (index, info, have) in [
                        (0, summary.data, ours.received),
                        (1, summary.receipt, ours.received_receipt),
                    ] {
                        let Some(info) = info else {
                            received[index] = None;
                            continue;
                        };
                        if info.channel != bound.incoming.ok_or(())? {
                            return Err(());
                        }
                        if have.as_ref() == Some(&info.id) {
                            continue;
                        }
                        if received[index]
                            .as_ref()
                            .is_some_and(|p| p.info.id == info.id)
                        {
                            continue;
                        }
                        received[index] = Some(Incoming::new(info.clone())?);
                        send_frame(
                            &mut tls,
                            &Frame::Want {
                                receipt: index == 1,
                                id: info.id,
                                offset: 0,
                            },
                        )?;
                    }
                }
                Frame::Want {
                    receipt,
                    id,
                    offset,
                } => {
                    if id.len() != 44 {
                        return Err(());
                    }
                    if let Some(data) = context.hub.chunk(&peer, receipt, &id, offset, CHUNK)? {
                        send_frame(
                            &mut tls,
                            &Frame::Chunk {
                                receipt,
                                id,
                                offset,
                                data,
                            },
                        )?;
                    } else {
                        send_frame(&mut tls, &Frame::Gone { receipt, id })?;
                    }
                }
                Frame::Gone { receipt, id } => {
                    let slot = &mut received[usize::from(receipt)];
                    if slot.as_ref().is_some_and(|p| p.info.id == id) {
                        *slot = None;
                    }
                }
                Frame::Chunk {
                    receipt,
                    id,
                    offset,
                    data,
                } => {
                    let slot = &mut received[usize::from(receipt)];
                    // An old transfer can have one in-flight chunk after a new
                    // cumulative version supersedes it. Discard that chunk.
                    let Some(p) = slot.as_mut().filter(|p| p.info.id == id) else {
                        continue;
                    };
                    if offset != p.data.len()
                        || data.is_empty()
                        || data.len() > CHUNK
                        || !data.is_ascii()
                        || offset.saturating_add(data.len()) > p.info.size
                    {
                        return Err(());
                    }
                    p.data.push_str(&data);
                    if p.data.len() == p.info.size {
                        let packet = SyncPacket {
                            channel: p.info.channel,
                            id: p.info.id.clone(),
                            nonce: p.info.nonce.clone(),
                            ciphertext: std::mem::take(&mut p.data),
                        };
                        context.hub.store(&peer, packet, receipt)?;
                        *slot = None;
                        let mut runtime = context.runtime.lock().map_err(|_| ())?;
                        let _ = runtime.sync_pump();
                        context.changes.fetch_add(1, Ordering::AcqRel);
                    } else {
                        send_frame(
                            &mut tls,
                            &Frame::Want {
                                receipt,
                                id,
                                offset: p.data.len(),
                            },
                        )?;
                    }
                }
            }
        }
    })();
    let result = if context.stop.load(Ordering::Acquire) {
        Ok(())
    } else {
        result
    };
    update(
        context,
        &peer,
        if result.is_ok() { "offline" } else { "failed" },
        false,
    );
    result
}
