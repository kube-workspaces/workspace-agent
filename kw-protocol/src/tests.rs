//! Unit + fixture tests. The `vectors` test parses every JSON conformance
//! vector through [`crate::Envelope`] and re-checks the cross-vector rules,
//! so the spec document, the fixtures and this crate stay consistent.

use super::*;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("protocol")
        .join("v1")
        .join("vectors")
}

fn load_vectors() -> Vec<(String, Envelope)> {
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(vectors_dir())
        .expect("vectors dir exists")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    for path in names {
        let text = std::fs::read_to_string(&path).expect("vector readable");
        let message: Envelope = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let stem = path
            .file_stem()
            .expect("stem")
            .to_string_lossy()
            .into_owned();
        out.push((stem, message));
    }
    assert!(!out.is_empty(), "no vectors found");
    out
}

#[test]
fn vectors_parse_and_validate() {
    let vectors = load_vectors();
    let mut ordered: Vec<(u64, u64, String)> = Vec::new();
    let mut by_name = std::collections::HashMap::new();
    for (name, message) in &vectors {
        check_envelope(message).unwrap_or_else(|error| panic!("{name}: {error}"));
        ordered.push((message.sent_at_ns, message.sequence, name.clone()));
        by_name.insert(name.clone(), message.clone());
    }
    let mut sorted = ordered.clone();
    sorted.sort();
    for pair in sorted.windows(2) {
        assert!(
            pair[0] < pair[1],
            "clocks/sequences must increase across vectors"
        );
    }

    // First milestone is exclusive-controller only.
    let hello = &by_name["hello"];
    assert_eq!(hello.payload["role"], "controller-only");
    assert!(hello.payload["inputAvailable"].is_boolean());
    assert!(hello.payload["resizeAvailable"].is_boolean());

    // An admitted attach produces a registered attachResult control type.
    let attach_result = &by_name["attach-result"];
    assert_eq!(attach_result.payload["admitted"], true);

    // Input events parse with their kind tag and enforce bounded ranges.
    for name in ["input", "input-pointer", "input-wheel"] {
        let event: InputEvent = serde_json::from_value(by_name[name].payload.clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        check_input(&event).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    assert_eq!(
        check_input(&InputEvent::Wheel {
            dx: INPUT_MAX_WHEEL + 1,
            dy: 0
        }),
        Err(Reject::Malformed)
    );
    assert_eq!(
        check_input(&InputEvent::Key {
            keysym: INPUT_MAX_KEYSYM + 1,
            down: true
        }),
        Err(Reject::Malformed)
    );

    // Resize ACK echoes the request and reconfigures with a fresh IDR.
    let request_id = by_name["resize-request"].payload["requestId"].as_str();
    let ack = &by_name["resize-ack"].payload;
    assert!(request_id.is_some() && !request_id.unwrap().is_empty());
    assert_eq!(ack["requestId"].as_str(), request_id);
    assert_eq!(ack["codecReconfigured"], true);
    assert_eq!(ack["idrSent"], true);

    // Keyframe vector carries codec config (no arbitrary reference drops).
    let keyframe = &by_name["keyframe"].payload;
    assert_eq!(keyframe["keyframe"], true);
    assert_eq!(keyframe["codecConfig"], true);

    // The expiry vector's ticket is already expired at send time.
    let expiry = &by_name["ticket-expiry"];
    let ticket: Ticket = serde_json::from_value(expiry.payload["ticket"].clone()).expect("ticket");
    assert!(ticket.expires_at_ns <= expiry.sent_at_ns);
    let scope = Scope {
        workspace_uid: &ticket.workspace_uid,
        session_id: &ticket.session_id,
        audience: &ticket.audience,
        min_control_epoch: ticket.control_epoch,
    };
    assert_eq!(
        admit_ticket(&ticket, &scope, expiry.sent_at_ns),
        Err(Reject::Ticket)
    );
}

#[test]
fn rejects_wrong_protocol() {
    let mut message: Envelope =
        serde_json::from_str(r#"{"protocol":"selkies","protocolVersion":1,"sessionId":"s","generation":0,"sequence":0,"sentAtNs":0,"channel":"control","type":"hello","payload":{}}"#)
            .unwrap();
    assert_eq!(check_envelope(&message), Err(Reject::Protocol));
    message.protocol = PROTOCOL.into();
    message.protocol_version = 99;
    assert_eq!(check_envelope(&message), Err(Reject::Protocol));
}

#[test]
fn rejects_unknown_type() {
    let message: Envelope =
        serde_json::from_str(r#"{"protocol":"kw-agent-v1","protocolVersion":1,"sessionId":"s","generation":0,"sequence":0,"sentAtNs":0,"channel":"media","type":"hello","payload":{}}"#)
            .unwrap();
    assert_eq!(check_envelope(&message), Err(Reject::UnknownType));
}

#[test]
fn fence_rejects_replay_and_regression() {
    let mut fence = ChannelFence::new();
    assert!(fence.admit(7, 100).is_ok());
    assert_eq!(fence.admit(7, 100), Err(Reject::Replay));
    assert_eq!(fence.admit(7, 99), Err(Reject::Replay));
    assert_eq!(fence.rejected, 2);
    // New generation still needs a newer clock (single shared sender clock).
    assert!(fence.admit(8, 101).is_ok());
    assert_eq!(fence.admit(8, 101), Err(Reject::Replay));
}

#[test]
fn ticket_fences_epochs_and_scope() {
    let ticket = Ticket {
        workspace_uid: "ws".into(),
        workspace_generation: "gen".into(),
        session_id: "sess".into(),
        participant: "controller".into(),
        role: "controller".into(),
        control_epoch: 9,
        audience: "workspace-agent".into(),
        expires_at_ns: 1000,
    };
    let scope = Scope {
        workspace_uid: "ws",
        session_id: "sess",
        audience: "workspace-agent",
        min_control_epoch: 9,
    };
    assert!(admit_ticket(&ticket, &scope, 999).is_ok());
    // Expiring exactly now is already expired.
    assert_eq!(admit_ticket(&ticket, &scope, 1000), Err(Reject::Ticket));
    // Demoted epoch fences the old ticket.
    let demoted = Scope {
        min_control_epoch: 10,
        ..scope
    };
    assert_eq!(admit_ticket(&ticket, &demoted, 999), Err(Reject::Ticket));
    // Wrong audience or session never admits.
    let foreign = Scope {
        audience: "someone-else",
        ..scope
    };
    assert_eq!(admit_ticket(&ticket, &foreign, 999), Err(Reject::Ticket));
}
