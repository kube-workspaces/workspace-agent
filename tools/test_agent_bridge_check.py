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

    def test_percentile_nearest_rank(self):
        self.assertIsNone(abc.percentile([], 50))
        vals = [10, 20, 30, 40]
        self.assertEqual(abc.percentile(vals, 50), 20)
        self.assertEqual(abc.percentile(vals, 95), 40)
        self.assertEqual(abc.percentile(vals, 1), 10)

    def test_annexb_idr_detection(self):
        self.assertTrue(abc.annexb_has_idr(bytes([0, 0, 0, 1, 0x65, 1, 2, 3])))
        self.assertFalse(abc.annexb_has_idr(bytes([0, 0, 0, 1, 0x41, 1, 2, 3])))
        self.assertFalse(abc.annexb_has_idr(b"\x01\x02\x03"))

    def test_measure_stats_summary(self):
        st = abc.MeasureStats()
        st.add_video(1000, True, 0.0)
        st.add_video(2000, False, 33.0)
        st.add_video(1500, False, 66.0)
        st.add_audio(100, 0.0)
        st.add_audio(100, 20.0)
        st.add_telemetry_rtt(12.0)
        st.add_telemetry_rtt(18.0)
        out = st.summary(0.1)
        self.assertEqual(out["video"]["frames"], 3)
        self.assertEqual(out["video"]["idr_frames"], 1)
        self.assertEqual(out["video"]["fps"], 30.0)
        self.assertEqual(out["video"]["bitrate_bps"], 360000)
        self.assertEqual(out["video"]["gap_ms_p50"], 33.0)
        self.assertEqual(out["audio"]["packets"], 2)
        self.assertEqual(out["audio"]["gap_ms_p50"], 20.0)
        self.assertEqual(out["telemetry"]["responses"], 2)
        self.assertEqual(out["telemetry"]["rtt_ms_p50"], 12.0)

    def test_measure_stats_empty(self):
        out = abc.MeasureStats().summary(1.0)
        self.assertEqual(out["video"]["frames"], 0)
        self.assertIsNone(out["video"]["gap_ms_p95"])
        self.assertIsNone(out["telemetry"]["rtt_ms_p50"])

    def test_run_measure_collects_media(self):
        import threading

        frames = [
            (0x01, bytes([0, 0, 0, 1, 0x65]) + bytes(500)),   # IDR video
            (0x01, bytes([0, 0, 0, 1, 0x41]) + bytes(300)),   # delta video
            (0x02, bytes(120)),                                # opus
            (0x00, json.dumps({"type": "telemetry"}).encode()),
        ]

        def recvn(s, n):
            out = b""
            while len(out) < n:
                chunk = s.recv(n - len(out))
                if not chunk:
                    raise ConnectionError("closed")
                out += chunk
            return out

        def scripted(sock, payloads):
            try:
                for tag, body in payloads:
                    frame = bytes([tag]) + struct.pack("!I", len(body)) + body
                    if len(frame) > 125:
                        sock.sendall(struct.pack("!BBH", 0x82, 126, len(frame)) + frame)
                    else:
                        sock.sendall(struct.pack("!BB", 0x82, len(frame)) + frame)
                    # Drain whatever the client sends (keyframe/telemetry);
                    # first quiet period ends the script.
                    sock.settimeout(0.1)
                    try:
                        while True:
                            hdr = recvn(sock, 2)
                            ln = hdr[1] & 0x7F
                            if ln == 126:
                                (ln,) = struct.unpack("!H", recvn(sock, 2))
                            elif ln == 127:
                                (ln,) = struct.unpack("!Q", recvn(sock, 8))
                            if hdr[1] & 0x80:
                                recvn(sock, 4)
                            if ln:
                                recvn(sock, ln)
                    except (socket.timeout, ConnectionError):
                        pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        client, guest = socket.socketpair()
        try:
            writer = threading.Thread(target=scripted, args=(guest, frames))
            writer.start()
            stats, seq = abc.run_measure(client, "sess", 10, 2.0)
            writer.join()
        finally:
            client.close()
            guest.close()
        self.assertEqual(stats.video_frames, 2)
        self.assertEqual(stats.video_idrs, 1)
        self.assertEqual(stats.audio_packets, 1)
        self.assertEqual(len(stats.telemetry_rtts), 1)
        self.assertGreater(seq, 10)


if __name__ == "__main__":
    unittest.main()
