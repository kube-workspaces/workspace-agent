//! Minimal diagnostic client: hello → attach → resize → keyframe → bye.
//!
//! Mints its own ticket from the given workspace binding (proof and
//! loopback diagnostics only — product tickets are issued by the API and
//! validated the same way by the server).

use crate::frame::{read_frame, Frame};
use kw_protocol::Envelope;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};

/// What the diagnostic run observed.
#[derive(Clone, Debug)]
pub struct ClientOutcome {
    pub admitted: bool,
    pub resize_paired: bool,
    pub resize_reason: String,
    pub server_hello_ok: bool,
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
    .expect("control envelope")
}

fn send(stream: &mut TcpStream, message: &Envelope) -> Result<(), String> {
    let body = serde_json::to_vec(message).map_err(|e| format!("encode: {e}"))?;
    stream.write_all(&[0x00]).map_err(|e| format!("io: {e}"))?;
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|e| format!("io: {e}"))?;
    stream.write_all(&body).map_err(|e| format!("io: {e}"))?;
    stream.flush().map_err(|e| format!("io: {e}"))?;
    Ok(())
}

fn recv(stream: &mut TcpStream) -> Result<Envelope, String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .map_err(|e| format!("io: {e}"))?;
    match read_frame(stream).map_err(|e| format!("frame: {e}"))? {
        Some(Frame::Control(envelope)) => Ok(envelope),
        Some(Frame::Media { .. }) => Err("unexpected media frame".into()),
        None => Err("server closed".into()),
    }
}

/// Run the full diagnostic exchange against `address`.
pub fn run(
    address: &str,
    workspace_uid: &str,
    workspace_generation: &str,
) -> Result<ClientOutcome, String> {
    let socket: std::net::SocketAddr = address
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .next()
        .ok_or("unresolvable address")?;
    let mut stream = TcpStream::connect_timeout(&socket, std::time::Duration::from_secs(10))
        .map_err(|e| format!("connect: {e}"))?;
    let hello = recv(&mut stream)?;
    let server_hello_ok = hello.message_type == "hello";
    let session = hello.session_id.clone();
    let ticket = serde_json::json!({
        "workspaceUid": workspace_uid,
        "workspaceGeneration": workspace_generation,
        "sessionId": session,
        "participant": "connect-test",
        "role": "controller",
        "controlEpoch": 1,
        "audience": "workspace-agent",
        "expiresAtNs": 4_000_000_000_000_000_000u64,
    });
    send(
        &mut stream,
        &control(&session, "attach", 2, serde_json::json!({"ticket": ticket})),
    )?;
    let admitted = recv(&mut stream)?.payload["admitted"] == true;
    send(
        &mut stream,
        &control(
            &session,
            "resizeRequest",
            3,
            serde_json::json!({"requestId": "connect-test-1"}),
        ),
    )?;
    let ack = recv(&mut stream)?;
    let resize_paired = ack.payload["requestId"] == "connect-test-1";
    let resize_reason = ack.payload["reason"].as_str().unwrap_or("").to_owned();
    send(
        &mut stream,
        &control(&session, "keyframeRequest", 4, serde_json::json!({})),
    )?;
    send(
        &mut stream,
        &control(&session, "bye", 5, serde_json::json!({})),
    )?;
    Ok(ClientOutcome {
        admitted,
        resize_paired,
        resize_reason,
        server_hello_ok,
    })
}
