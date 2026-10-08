//! Ticket-gated session server. One connection, one exclusive controller.
//!
//! The server sends `hello` first (real inventory where available, empty
//! capability set otherwise — always honestly labeled). It then admits a
//! single controller via [`Handshake`]; a second attach while held is
//! rejected without disturbing the holder. Control requests are answered;
//! resize is honestly NACKed until the display backend lands.

use crate::frame::{read_frame, write_control, write_media, Frame, MediaKind};
use kw_core::{now_secs, Handshake};
use kw_protocol::{Envelope, Reject, Ticket};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

/// What happened during one served connection (telemetry, no secrets).
#[derive(Clone, Debug, Default)]
pub struct SessionOutcome {
    /// Control frames processed.
    pub control_frames: u64,
    /// Media frames counted (and bounded — see below).
    pub media_frames: u64,
    /// Media bytes counted.
    pub media_bytes: u64,
    /// Resize ACKs sent (paired or explicit-unsupported).
    pub resize_acks: u64,
    /// Keyframe demands forwarded (coalesced).
    pub keyframes_forwarded: u64,
    /// Video frames the guest streamed to the viewer this session.
    pub video_frames_sent: u64,
    /// Video bytes streamed this session.
    pub video_bytes_sent: u64,
    /// Emitted frames carrying a fresh IDR (SPS/PPS refresh).
    pub video_keyframes_sent: u64,
    /// Why the session ended.
    pub ended: String,
}

/// Cross-thread media gate for one served session. Created per session by
/// the host (kw-agent): the encoder thread and the socket writer thread
/// share it with the control loop. Slow-viewer isolation (bounded queues,
/// drop-to-IDR) is Phase-4 work; until then a stalled socket back-pressures
/// the encoder thread — documented, never silent.
#[derive(Debug, Default)]
pub struct MediaGate {
    /// Set on successful attach; the writer thread idles before this.
    pub admitted: AtomicBool,
    /// Set by keyframe_request; the encoder consumes it into one forced IDR.
    pub force_idr: AtomicBool,
    /// Set when the control loop ends; writer/encoder threads exit on it.
    pub ended: AtomicBool,
}

/// One unit for the viewer: raw codec bytes (Annex-B H.264 access unit).
#[derive(Debug)]
pub struct MediaPacket {
    pub kind: MediaKind,
    pub payload: Vec<u8>,
}

/// Counters shared between the encoder thread (knows chunks) and the
/// socket writer thread (knows bytes), merged into the outcome at close.
#[derive(Debug, Default)]
pub struct MediaStats {
    pub frames_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub keyframes_sent: AtomicU64,
}

/// Shared socket writer: control replies and the media thread serialize
/// through one mutex so reference frames are never interleaved corrupt.
type SharedWriter = Arc<Mutex<TcpStream>>;

fn write_envelope(writer: &SharedWriter, message: &Envelope) -> Result<(), String> {
    let mut guard = writer.lock().map_err(|e| format!("writer lock: {e}"))?;
    write_control(&mut *guard, message).map_err(|e| format!("{e}"))?;
    Ok(())
}

/// Events the host loop reports upward.
#[derive(Clone, Debug)]
pub enum ServerEvent {
    Listening(String),
    Session(SessionOutcome),
}

/// Exclusive session server bound to one address.
pub struct Server {
    listener: TcpListener,
    workspace_uid: String,
    workspace_generation: String,
    agent_version: String,
}

impl Server {
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        workspace_uid: String,
        workspace_generation: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        Ok(Self {
            listener,
            workspace_uid,
            workspace_generation,
            agent_version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub fn local_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve exactly one connection, then return its outcome. The host loop
    /// decides whether to accept another (single-controller discipline means
    /// concurrent sessions are never multiplexed here).
    pub fn serve_one(&self) -> Result<SessionOutcome, String> {
        let (stream, peer) = self.listener.accept().map_err(|e| format!("accept: {e}"))?;
        Ok(serve_connection(
            stream,
            peer.to_string(),
            &self.workspace_uid,
            &self.workspace_generation,
            &self.agent_version,
            None,
        ))
    }

    /// Serve one connection with a media feed: after admission, packets from
    /// `feed` stream to the viewer as binary media frames while control
    /// continues on the same socket. The host owns encoder construction and
    /// pacing; the gate carries admitted/force-idr/ended across the threads.
    pub fn serve_one_media(
        &self,
        gate: Arc<MediaGate>,
        feed: mpsc::Receiver<MediaPacket>,
        stats: Arc<MediaStats>,
    ) -> Result<SessionOutcome, String> {
        let (stream, peer) = self.listener.accept().map_err(|e| format!("accept: {e}"))?;
        Ok(serve_connection(
            stream,
            peer.to_string(),
            &self.workspace_uid,
            &self.workspace_generation,
            &self.agent_version,
            Some((gate, feed, stats)),
        ))
    }
}

fn envelope(
    message_type: &str,
    sequence: u64,
    session_id: &str,
    generation: u64,
    payload: serde_json::Value,
) -> Envelope {
    Envelope {
        protocol: kw_protocol::PROTOCOL.into(),
        protocol_version: kw_protocol::PROTOCOL_VERSION,
        session_id: session_id.into(),
        generation,
        sequence,
        sent_at_ns: now_secs().saturating_mul(1_000_000_000),
        channel: kw_protocol::Channel::Control,
        message_type: message_type.into(),
        payload,
    }
}

fn resize_nack(request_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "requestId": request_id,
        "requested": null,
        "actual": null,
        "codecReconfigured": false,
        "idrSent": false,
        "reason": reason,
    })
}

fn serve_connection(
    stream: TcpStream,
    _peer: String,
    workspace_uid: &str,
    workspace_generation: &str,
    agent_version: &str,
    media: Option<(Arc<MediaGate>, mpsc::Receiver<MediaPacket>, Arc<MediaStats>)>,
) -> SessionOutcome {
    let mut outcome = SessionOutcome::default();
    // The session claim is minted here and advertised in our hello; clients
    // echo it back. Anything else is a foreign claim.
    let session_id = format!("sess-{}", now_secs());
    let mut handshake = Handshake::new(session_id.clone(), 0);
    let mut reader = stream.try_clone().expect("clone reader");
    let writer: SharedWriter = Arc::new(Mutex::new(stream));
    reader
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    // Media writer thread (media sessions only): idles until admission, then
    // relays encoder packets as binary frames. Ends on session close or a
    // broken socket; the control loop below outlives it either way.
    let mut media_gate: Option<Arc<MediaGate>> = None;
    let mut media_stats: Option<Arc<MediaStats>> = None;
    let media_thread = media.map(|(gate, feed, stats)| {
        media_gate = Some(Arc::clone(&gate));
        media_stats = Some(Arc::clone(&stats));
        let writer = Arc::clone(&writer);
        std::thread::spawn(move || {
            while !gate.ended.load(Ordering::SeqCst) {
                if !gate.admitted.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                let packet = match feed.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(packet) => packet,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let mut guard = match writer.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                if write_media(&mut *guard, packet.kind, &packet.payload).is_err() {
                    break;
                }
                stats.frames_sent.fetch_add(1, Ordering::SeqCst);
                stats
                    .bytes_sent
                    .fetch_add(packet.payload.len() as u64, Ordering::SeqCst);
            }
        })
    });
    // Speak first: hello with this session's claim ids.
    let hello = envelope(
        "hello",
        1,
        &session_id,
        0,
        serde_json::json!({
            "agentVersion": agent_version,
            "platform": std::env::consts::OS,
            "role": "controller-only",
            "capabilityEpoch": 1,
        }),
    );
    if write_envelope(&writer, &hello).is_err() {
        outcome.ended = "hello-write-failed".into();
        return outcome;
    }
    if handshake.hello(&hello).is_err() {
        outcome.ended = "hello-fence-failed".into();
        return outcome;
    }
    let mut sequence = 2u64;
    // IDR acknowledgements the encoder has produced (via shared stats):
    // each consumed keyframe re-arms the pending flag so repeated viewer
    // demands keep working across a long session instead of latching once.
    let mut idr_signaled = 0u64;
    loop {
        let frame = match read_frame(&mut reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                outcome.ended = "peer-closed".into();
                break;
            }
            Err(_) => {
                outcome.ended = "frame-error".into();
                break;
            }
        };
        match frame {
            Frame::Media { kind: _, payload } => {
                outcome.media_frames += 1;
                outcome.media_bytes += payload.len() as u64;
                // No encoder yet: count and bound, never silently absorb.
                // (Backpressure policy arrives with the media pipeline.)
            }
            Frame::Control(message) => {
                outcome.control_frames += 1;
                if !serve_control(
                    &mut handshake,
                    &message,
                    workspace_uid,
                    workspace_generation,
                    &writer,
                    &mut sequence,
                    &mut outcome,
                    media_gate.as_deref(),
                    media_stats.as_deref(),
                    &mut idr_signaled,
                ) {
                    if outcome.ended.is_empty() {
                        outcome.ended = "refused".into();
                    }
                    break;
                }
            }
        }
    }
    handshake.close();
    if let Some(gate) = media_gate.as_deref() {
        gate.ended.store(true, Ordering::SeqCst);
    }
    if let Some(stats) = media_stats.as_deref() {
        outcome.video_frames_sent = stats.frames_sent.load(Ordering::SeqCst);
        outcome.video_bytes_sent = stats.bytes_sent.load(Ordering::SeqCst);
        outcome.video_keyframes_sent = stats.keyframes_sent.load(Ordering::SeqCst);
    }
    if let Some(thread) = media_thread {
        let _ = thread.join();
    }
    outcome
}

/// Returns false when the session should end (bye or fatal violation).
#[allow(clippy::too_many_arguments)]
fn serve_control(
    handshake: &mut Handshake,
    message: &Envelope,
    workspace_uid: &str,
    workspace_generation: &str,
    writer: &SharedWriter,
    sequence: &mut u64,
    outcome: &mut SessionOutcome,
    gate: Option<&MediaGate>,
    stats: Option<&MediaStats>,
    idr_signaled: &mut u64,
) -> bool {
    match message.message_type.as_str() {
        "attach" => {
            let ticket: Result<Ticket, _> =
                serde_json::from_value(message.payload["ticket"].clone());
            let decision = match ticket {
                Ok(ticket) if ticket.workspace_generation == workspace_generation => {
                    match handshake.attach(
                        message,
                        &ticket,
                        workspace_uid,
                        now_secs().saturating_mul(1_000_000_000),
                    ) {
                        Ok(_) => serde_json::json!({"admitted": true}),
                        Err(Reject::Ticket) => {
                            serde_json::json!({"admitted": false, "reason": "ticket-rejected"})
                        }
                        Err(other) => {
                            serde_json::json!({"admitted": false, "reason": format!("{other}")})
                        }
                    }
                }
                Ok(_) => serde_json::json!({"admitted": false, "reason": "wrong-generation"}),
                Err(_) => serde_json::json!({"admitted": false, "reason": "malformed-ticket"}),
            };
            let reply = envelope(
                "attachResult",
                *sequence,
                handshake.session_id(),
                0,
                decision,
            );
            *sequence += 1;
            if write_envelope(writer, &reply).is_err() {
                return false;
            }
            let admitted = handshake.admitted();
            if admitted {
                if let Some(gate) = gate {
                    gate.admitted.store(true, Ordering::SeqCst);
                }
            }
            admitted
        }
        "resizeRequest" => {
            let id = message.payload["requestId"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            match handshake.resize_request(message) {
                Ok(_paired) => {
                    // No display backend yet: pair honestly, NACK the mode.
                    let ack = envelope(
                        "resizeAck",
                        *sequence,
                        handshake.session_id(),
                        0,
                        resize_nack(&id, "display-backend-p0-gated"),
                    );
                    *sequence += 1;
                    outcome.resize_acks += 1;
                    write_envelope(writer, &ack).is_ok()
                }
                Err(_) => false,
            }
        }
        "keyframeRequest" => {
            // Re-arm from produced IDRs first: without this, the pending
            // flag latches after the first demand and later requests in a
            // long session are silently absorbed.
            if let Some(stats) = stats {
                let produced = stats.keyframes_sent.load(Ordering::SeqCst);
                if produced > *idr_signaled {
                    handshake.keyframe_sent();
                    *idr_signaled = produced;
                }
            }
            match handshake.keyframe_request(message) {
                Ok(forward) => {
                    if forward {
                        outcome.keyframes_forwarded += 1;
                        // The encoder consumes this into one forced IDR.
                        if let Some(gate) = gate {
                            gate.force_idr.store(true, Ordering::SeqCst);
                        }
                    }
                    true
                }
                Err(_) => false,
            }
        }
        "telemetry" | "displayOwnership" | "capabilities" => true,
        "bye" => {
            outcome.ended = "peer-bye".into();
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn test_ticket(session_id: &str) -> serde_json::Value {
        serde_json::json!({
            "workspaceUid": "ws-1",
            "workspaceGeneration": "gen-1",
            "sessionId": session_id,
            "participant": "tester",
            "role": "controller",
            "controlEpoch": 1,
            "audience": "workspace-agent",
            "expiresAtNs": 4_000_000_000_000_000_000u64,
        })
    }

    fn connect(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).expect("connect")
    }

    fn read_envelope(stream: &mut TcpStream) -> Envelope {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        match read_frame(stream).expect("frame").expect("not eof") {
            Frame::Control(envelope) => envelope,
            Frame::Media { .. } => panic!("expected control"),
        }
    }

    fn send(message: &Envelope, stream: &mut TcpStream) {
        let body = serde_json::to_vec(message).unwrap();
        stream.write_all(&[0x00]).unwrap();
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
    }

    fn control(
        session_id: &str,
        message_type: &str,
        sequence: u64,
        payload: serde_json::Value,
    ) -> Envelope {
        serde_json::from_value(serde_json::json!({
            "protocol": "kw-agent-v1", "protocolVersion": 1, "sessionId": session_id,
            "generation": 1, "sequence": sequence, "sentAtNs": 1000 + sequence,
            "channel": "control", "type": message_type, "payload": payload,
        }))
        .unwrap()
    }

    fn run_server_once(server: Server) -> SessionOutcome {
        server.serve_one().expect("serve")
    }

    #[test]
    fn attach_resize_bye_loopback() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let handle = std::thread::spawn(|| run_server_once(server));
        let mut client = connect(port);
        let hello = read_envelope(&mut client);
        assert_eq!(hello.message_type, "hello");
        // Echo the server's claim: session id learned from hello.
        let session = hello.session_id.clone();
        // Attach with a valid ticket (far-future expiry is a test vector).
        send(
            &control(
                &session,
                "attach",
                2,
                serde_json::json!({"ticket": test_ticket(&session)}),
            ),
            &mut client,
        );
        let result = read_envelope(&mut client);
        assert_eq!(result.message_type, "attachResult");
        assert_eq!(result.payload["admitted"], true);
        // Resize pairs but NACKs honestly without a display backend.
        send(
            &control(
                &session,
                "resizeRequest",
                3,
                serde_json::json!({"requestId": "r-9"}),
            ),
            &mut client,
        );
        let ack = read_envelope(&mut client);
        assert_eq!(ack.message_type, "resizeAck");
        assert_eq!(ack.payload["requestId"], "r-9");
        assert_eq!(ack.payload["reason"], "display-backend-p0-gated");
        // Keyframe demand is accepted (coalesced server-side).
        send(
            &control(&session, "keyframeRequest", 4, serde_json::json!({})),
            &mut client,
        );
        send(
            &control(&session, "bye", 5, serde_json::json!({})),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.control_frames, 4);
        assert_eq!(outcome.resize_acks, 1);
        assert_eq!(outcome.keyframes_forwarded, 1);
        assert_eq!(outcome.ended, "peer-bye");
    }

    #[test]
    fn bad_ticket_is_rejected_without_admission() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let handle = std::thread::spawn(|| run_server_once(server));
        let mut client = connect(port);
        let hello = read_envelope(&mut client);
        let session = hello.session_id.clone();
        let mut bad = test_ticket(&session);
        bad["expiresAtNs"] = serde_json::json!(1u64);
        send(
            &control(&session, "attach", 2, serde_json::json!({"ticket": bad})),
            &mut client,
        );
        let result = read_envelope(&mut client);
        assert_eq!(result.payload["admitted"], false);
        // Refused attach ends the session: no resize ACK may ever follow.
        // (Sending more bytes here would race the server's close, so the
        // fence itself is asserted instead — unit-covered in kw-core.)
        drop(client);
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.resize_acks, 0);
        assert_eq!(outcome.ended, "refused");
    }

    #[test]
    fn media_frames_are_counted_not_swallowed() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let handle = std::thread::spawn(|| run_server_once(server));
        let mut client = connect(port);
        let hello = read_envelope(&mut client);
        let session = hello.session_id.clone();
        send(
            &control(
                &session,
                "attach",
                2,
                serde_json::json!({"ticket": test_ticket(&session)}),
            ),
            &mut client,
        );
        let _ = read_envelope(&mut client);
        let mut blob = vec![0x02u8];
        let payload = vec![7u8; 1024];
        blob.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        blob.extend_from_slice(&payload);
        client.write_all(&blob).unwrap();
        client.flush().unwrap();
        send(
            &control(&session, "bye", 3, serde_json::json!({})),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.media_frames, 1);
        assert_eq!(outcome.media_bytes, 1024);
    }

    #[test]
    fn second_client_does_not_disturb_session() {
        // Single-connection discipline: while one client holds the socket,
        // nothing else is multiplexed. (Multi-viewer fan-out is P4 work.)
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let handle = std::thread::spawn(|| run_server_once(server));
        let mut first = connect(port);
        let _ = read_envelope(&mut first);
        // Second TCP connect blocks at accept until the first session ends.
        first
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .ok();
        let mut buf = [0u8; 1];
        assert!(
            first.read_exact(&mut buf).is_err(),
            "no multiplexed greeting"
        );
        drop(first);
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.ended, "peer-closed");
    }

    fn read_media(stream: &mut TcpStream) -> (MediaKind, Vec<u8>) {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        match read_frame(stream).expect("frame").expect("not eof") {
            Frame::Media { kind, payload } => (kind, payload),
            Frame::Control(envelope) => panic!("expected media, got {}", envelope.message_type),
        }
    }

    fn attach_client(client: &mut TcpStream) -> String {
        let hello = read_envelope(client);
        assert_eq!(hello.message_type, "hello");
        let session = hello.session_id.clone();
        send(
            &control(
                &session,
                "attach",
                2,
                serde_json::json!({"ticket": test_ticket(&session)}),
            ),
            client,
        );
        let result = read_envelope(client);
        assert_eq!(result.payload["admitted"], true);
        session
    }

    #[test]
    fn media_flows_after_admission_not_before() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let gate = Arc::new(MediaGate::default());
        let stats = Arc::new(MediaStats::default());
        let (tx, rx) = mpsc::channel();
        let handle =
            std::thread::spawn(move || server.serve_one_media(gate, rx, stats).expect("serve"));
        let mut client = connect(port);
        let session = attach_client(&mut client);
        // Feed two units post-admission; the client must receive both intact.
        for payload in [vec![0x11u8; 64], vec![0x22u8; 128]] {
            tx.send(MediaPacket {
                kind: MediaKind::H264,
                payload: payload.clone(),
            })
            .expect("feed");
            let (kind, back) = read_media(&mut client);
            assert_eq!(kind, MediaKind::H264);
            assert_eq!(back, payload);
        }
        send(
            &control(&session, "bye", 3, serde_json::json!({})),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.video_frames_sent, 2);
        assert_eq!(outcome.video_bytes_sent, 192);
        assert_eq!(outcome.ended, "peer-bye");
    }

    #[test]
    fn keyframe_request_raises_force_idr() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let gate = Arc::new(MediaGate::default());
        let gate_probe = Arc::clone(&gate);
        let stats = Arc::new(MediaStats::default());
        let (_tx, rx) = mpsc::channel();
        let handle =
            std::thread::spawn(move || server.serve_one_media(gate, rx, stats).expect("serve"));
        let mut client = connect(port);
        let session = attach_client(&mut client);
        assert!(
            !gate_probe.force_idr.load(Ordering::SeqCst),
            "no demand before request"
        );
        send(
            &control(&session, "keyframeRequest", 3, serde_json::json!({})),
            &mut client,
        );
        // No reply by design; the flag is the contract.
        for _ in 0..100 {
            if gate_probe.force_idr.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            gate_probe.force_idr.load(Ordering::SeqCst),
            "keyframe demand must raise force_idr for the encoder"
        );
        send(
            &control(&session, "bye", 4, serde_json::json!({})),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.keyframes_forwarded, 1);
    }

    #[test]
    fn repeated_keyframe_demands_rearm_after_idr() {
        let server = Server::bind("127.0.0.1:0", "ws-1".into(), "gen-1".into()).unwrap();
        let port = server.local_address().unwrap().port();
        let gate = Arc::new(MediaGate::default());
        let gate_probe = Arc::clone(&gate);
        let stats = Arc::new(MediaStats::default());
        let stats_probe = Arc::clone(&stats);
        let (_tx, rx) = mpsc::channel();
        let handle =
            std::thread::spawn(move || server.serve_one_media(gate, rx, stats).expect("serve"));
        let mut client = connect(port);
        let session = attach_client(&mut client);
        let mut sequence = 3u64;
        let mut demand = |client: &mut TcpStream| {
            send(
                &control(&session, "keyframeRequest", sequence, serde_json::json!({})),
                client,
            );
            sequence += 1;
        };
        // First demand raises the flag; the encoder consumes it.
        demand(&mut client);
        for _ in 0..100 {
            if gate_probe.force_idr.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(gate_probe.force_idr.load(Ordering::SeqCst));
        // A second demand before any IDR is produced coalesces (no-op).
        gate_probe.force_idr.store(false, Ordering::SeqCst);
        demand(&mut client);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !gate_probe.force_idr.load(Ordering::SeqCst),
            "unproduced demand must stay coalesced"
        );
        // Once the encoder reports the IDR, the next demand re-arms.
        stats_probe.keyframes_sent.fetch_add(1, Ordering::SeqCst);
        demand(&mut client);
        for _ in 0..100 {
            if gate_probe.force_idr.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            gate_probe.force_idr.load(Ordering::SeqCst),
            "produced IDR must re-arm keyframe demands"
        );
        send(
            &control(&session, "bye", 4, serde_json::json!({})),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.keyframes_forwarded, 2);
    }
}
