#!/usr/bin/env python3
"""Validate kw-agent-v1 conformance fixtures. No third-party dependencies."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "protocol" / "v1" / "vectors"
CONTROL_TYPES = {"hello", "capabilities", "attach", "attachResult", "input",
                 "keyframeRequest", "resizeRequest", "resizeAck", "clipboardGet",
                 "clipboardSet", "clipboardResult", "displayOwnership",
                 "telemetry", "bye"}
MEDIA_TYPES = {"video", "audio"}

# Bounds mirrored from kw-protocol::{check_input, INPUT_*}: keep in step with
# the Rust validator, or the two disagree about what the protocol allows.
INPUT_MAX_WHEEL = 1000
INPUT_MAX_COORD = 1_000_000
INPUT_MAX_KEYSYM = 0x0010FFFF


def check_input(name, payload):
    ok = True
    kind = payload.get("kind")
    if kind == "key":
        keysym = payload.get("keysym")
        if not isinstance(keysym, int) or isinstance(keysym, bool) or not 0 <= keysym <= INPUT_MAX_KEYSYM:
            ok = fail(f"{name}: key keysym out of range") and False
        if not isinstance(payload.get("down"), bool):
            ok = fail(f"{name}: key down must be a boolean") and False
    elif kind == "pointer":
        for field in ("x", "y"):
            value = payload.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= INPUT_MAX_COORD:
                ok = fail(f"{name}: pointer {field} out of range") and False
        buttons = payload.get("buttons")
        if not isinstance(buttons, int) or isinstance(buttons, bool) or not 0 <= buttons <= 255:
            ok = fail(f"{name}: pointer buttons out of range") and False
    elif kind == "wheel":
        for field in ("dx", "dy"):
            value = payload.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or abs(value) > INPUT_MAX_WHEEL:
                ok = fail(f"{name}: wheel {field} out of range") and False
    else:
        ok = fail(f"{name}: unknown input kind {kind!r}") and False
    return ok


def fail(message):
    print(f"FAIL: {message}")
    return False


def check_envelope(name, message):
    ok = True
    for field in ("protocol", "protocolVersion", "sessionId", "generation",
                  "sequence", "sentAtNs", "channel", "type", "payload"):
        if field not in message:
            ok = fail(f"{name}: missing {field}") and False
    if message.get("protocol") != "kw-agent-v1":
        ok = fail(f"{name}: wrong protocol") and False
    if message.get("protocolVersion") != 1:
        ok = fail(f"{name}: unsupported protocolVersion") and False
    if message.get("channel") == "control" and message.get("type") not in CONTROL_TYPES:
        ok = fail(f"{name}: unknown control type") and False
    if message.get("channel") == "media" and message.get("type") not in MEDIA_TYPES:
        ok = fail(f"{name}: unknown media type") and False
    for field in ("generation", "sequence", "sentAtNs"):
        if not isinstance(message.get(field), int) or message.get(field) < 0:
            ok = fail(f"{name}: {field} must be a non-negative integer") and False
    return ok


def main():
    vectors = sorted(VECTORS.glob("*.json"))
    if not vectors:
        print("FAIL: no vectors")
        return 1
    messages = {}
    ok = True
    ordered = []
    for path in vectors:
        try:
            message = json.loads(path.read_text())
        except (OSError, ValueError) as error:
            ok = fail(f"{path.name}: unreadable ({error})") and False
            continue
        messages[path.stem] = message
        ok = check_envelope(path.name, message) and ok
        ordered.append((message["sentAtNs"], message["sequence"], path.name))
    for (clock_a, seq_a, name_a), (clock_b, seq_b, name_b) in zip(sorted(ordered), sorted(ordered)[1:]):
        if (clock_b, seq_b) <= (clock_a, seq_a):
            ok = fail(f"{name_b}: clocks/sequences must increase across vectors") and False
    hello = messages.get("hello", {})
    if hello.get("payload", {}).get("role") != "controller-only":
        ok = fail("hello: first milestone must advertise controller-only") and False
    hello_payload = hello.get("payload", {})
    for field in ("inputAvailable", "resizeAvailable"):
        if not isinstance(hello_payload.get(field), bool):
            ok = fail(f"hello: {field} must be a boolean") and False
    request = messages.get("resize-request", {}).get("payload", {})
    ack = messages.get("resize-ack", {}).get("payload", {})
    if ack.get("requestId") != request.get("requestId") or not ack.get("requestId"):
        ok = fail("resize-ack: must echo the resize-request requestId") and False
    if ack and not (ack.get("idrSent") and ack.get("codecReconfigured")):
        ok = fail("resize-ack: actual mode change requires codec reconfig + IDR") and False
    keyframe = messages.get("keyframe", {}).get("payload", {})
    if keyframe.get("keyframe") and not keyframe.get("codecConfig"):
        ok = fail("keyframe: keyframe vector must carry codec config") and False
    ticket = messages.get("ticket-expiry", {}).get("payload", {})
    if not (ticket.get("decision") == "reject-expired"
            and ticket.get("ticket", {}).get("expiresAtNs", 1) <= messages["ticket-expiry"]["sentAtNs"]):
        ok = fail("ticket-expiry: expired ticket must be rejected") and False
    for name, message in messages.items():
        if message.get("type") != "input":
            continue
        payload = message.get("payload")
        if not isinstance(payload, dict):
            ok = fail(f"{name}: input payload must be an object") and False
        else:
            ok = check_input(name, payload) and ok
    attach_result = messages.get("attach-result", {}).get("payload", {})
    if not isinstance(attach_result.get("admitted"), bool):
        ok = fail("attach-result: admitted must be a boolean") and False
    print(f"checked {len(vectors)} vectors")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
