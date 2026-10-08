#!/usr/bin/env python3
"""Validate kw-agent-v1 conformance fixtures. No third-party dependencies."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "protocol" / "v1" / "vectors"
CONTROL_TYPES = {"hello", "capabilities", "attach", "keyframeRequest",
                 "resizeRequest", "resizeAck", "clipboardGet", "clipboardSet",
                 "clipboardResult", "displayOwnership", "telemetry", "bye"}
MEDIA_TYPES = {"video", "audio"}


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
    print(f"checked {len(vectors)} vectors")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
