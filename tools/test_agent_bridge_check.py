#!/usr/bin/env python3
"""Unit tests for agent_bridge_check (no network; socketpair loopback only)."""

import base64
import json
import socket
import struct
import unittest

import agent_bridge_check as abc


def make_ticket_bearer(payload):
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"sessid123.{raw}.fakesig"


class BridgeCheckTests(unittest.TestCase):
    def test_ticket_decode_round_trip(self):
        payload = {
            "workspaceUid": "ws-1",
            "workspaceGeneration": "gen-7",
            "sessionId": "",
            "participant": "viewer",
            "role": "controller",
            "controlEpoch": 1,
            "audience": "workspace-agent",
            "expiresAtNs": 999,
        }
        session_id, decoded = abc.decode_ticket(make_ticket_bearer(payload))
        self.assertEqual(session_id, "sessid123")
        self.assertEqual(decoded, payload)

    def test_ticket_decode_rejects_malformed(self):
        for bad in ("", "a.b", "a.b.c.d", ".e30.sig"):
            with self.assertRaises(ValueError, msg=bad):
                abc.decode_ticket(bad)

    def test_control_frame_round_trip_over_ws(self):
        left, right = socket.socketpair()
        try:
            ticket = {"workspaceUid": "ws", "sessionId": "sess-1"}
            abc.send_control(left, "sess-1", "attach", 2, {"ticket": ticket})
            msg = abc.recv_control(right)
        finally:
            left.close()
            right.close()
        self.assertEqual(msg["protocol"], "kw-agent-v1")
        self.assertEqual(msg["protocolVersion"], 1)
        self.assertEqual(msg["sessionId"], "sess-1")
        self.assertEqual(msg["generation"], 1)
        self.assertEqual(msg["sequence"], 2)
        self.assertEqual(msg["channel"], "control")
        self.assertEqual(msg["type"], "attach")
        self.assertEqual(msg["payload"]["ticket"], ticket)

    def test_ws_binary_frame_large_payload(self):
        left, right = socket.socketpair()
        try:
            body = bytes(range(256)) * 400  # forces 16-bit extended length
            abc.ws_send(left, body)
            self.assertEqual(abc.ws_recv(right), body)
        finally:
            left.close()
            right.close()

    def test_frame_tag_and_length_prefix(self):
        left, right = socket.socketpair()
        try:
            abc.send_control(left, "s", "bye", 5, {})
            raw = abc.ws_recv(right)
        finally:
            left.close()
            right.close()
        self.assertEqual(raw[0], 0x00)
        (length,) = struct.unpack("!I", raw[1:5])
        self.assertEqual(length, len(raw) - 5)
        self.assertEqual(json.loads(raw[5:])["type"], "bye")


if __name__ == "__main__":
    unittest.main()
