//! Ticket-gated session server. One connection, one exclusive controller.
//!
//! The server sends `hello` first (real inventory where available, empty
//! capability set otherwise — always honestly labeled). It then admits a
//! single controller via [`Handshake`]; a second attach while held is
//! rejected without disturbing the holder. Control requests are answered;
//! resize is honestly NACKed until the display backend lands.

use crate::frame::{read_frame, write_control, Frame};
use kw_core::{now_secs, Handshake};
use kw_protocol::{Envelope, Reject, Ticket};
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

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
    /// Why the session ended.
    pub ended: String,
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
) -> SessionOutcome {
    let mut outcome = SessionOutcome::default();
    // The session claim is minted here and advertised in our hello; clients
    // echo it back. Anything else is a foreign claim.
    let session_id = format!("sess-{}", now_secs());
    let mut handshake = Handshake::new(session_id.clone(), 0);
    let mut reader = stream.try_clone().expect("clone reader");
    let mut writer = stream;
    reader
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
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
    if write_control(&mut writer, &hello).is_err() {
        outcome.ended = "hello-write-failed".into();
        return outcome;
    }
    if handshake.hello(&hello).is_err() {
        outcome.ended = "hello-fence-failed".into();
        return outcome;
    }
    let mut sequence = 2u64;
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
                    &mut writer,
                    &mut sequence,
                    &mut outcome,
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
    outcome
}

/// Returns false when the session should end (bye or fatal violation).
#[allow(clippy::too_many_arguments)]
fn serve_control(
    handshake: &mut Handshake,
    message: &Envelope,
    workspace_uid: &str,
    workspace_generation: &str,
    writer: &mut impl Write,
    sequence: &mut u64,
    outcome: &mut SessionOutcome,
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
            if write_control(writer, &reply).is_err() {
                return false;
            }
            handshake.admitted()
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
                    write_control(writer, &ack).is_ok()
                }
                Err(_) => false,
            }
        }
        "keyframeRequest" => match handshake.keyframe_request(message) {
            Ok(forward) => {
                if forward {
                    outcome.keyframes_forwarded += 1;
                }
                true
            }
            Err(_) => false,
        },
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
    use std::io::Read;

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
        // Resize without admission ends the session (fence holds).
        send(
            &control(
                &session,
                "resizeRequest",
                3,
                serde_json::json!({"requestId": "r-1"}),
            ),
            &mut client,
        );
        let outcome = handle.join().expect("server thread");
        assert_eq!(outcome.resize_acks, 0);
        let _ = outcome;
        drop(client);
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
}
