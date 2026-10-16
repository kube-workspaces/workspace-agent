#!/usr/bin/env python3
"""Live steel-thread check: API ticket -> proxy /agent/ bridge -> guest agent.

Exercises the full guest->proxy->viewer data path for one workspace:

  1. POST /v1/workspaces/<name>/agent/attach  (platform auth, gets ticket)
  2. Decode the ticket payload segment (id.payload.signature, base64url JSON)
  3. Open wss://<ingress>/proxy/<ns>/<name>/agent/  (same platform auth)
  4. Read the guest hello, STAMP its live session claim into the ticket
     (the API mints sessionId empty -- "whoever holds the live claim";
     the guest rejects an unstamped ticket), send attach
  5. Expect attachResult admitted:true, then resizeRequest -> resizeAck
     (paired requestId; reason is display-backend-p0-gated until the
     display backend lands -- pairing is the proof, not the mode change)
  6. keyframeRequest, bye, REST release, optional second-connection 409 check

Stdlib only (no pip dependencies) so it runs anywhere python3 exists.
Exits 0 with a JSON summary when every expectation holds, 1 otherwise.
Never prints the platform token or the full ticket signature.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

PROTOCOL = "kw-agent-v1"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# The platform edge blocks non-browser User-Agents (observed: 403 error 1010
# for Python-urllib). Identify as a browser client like the product frontend.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) kw-agent-bridge-check/0.1"


def b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_ticket(ticket_string):
    parts = ticket_string.split(".")
    if len(parts) != 3 or not parts[0]:
        raise ValueError("ticket is not id.payload.signature")
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    return parts[0], payload


def api_call(api_base, namespace, name, action, token, session_id=None, timeout=10):
    # The API requires a JSON body on these POSTs (Goa answers
    # missing-payload to bodiless posts): {} for attach (name rides the
    # path), session correlation for renew/release (also carried in the
    # X-KW-Agent-Session header per the API contract).
    if action == "attach" or not session_id:
        body = b"{}"
    else:
        body = json.dumps({"session_id": session_id}).encode()
    url = (
        f"{api_base.rstrip('/')}/v1/workspaces/"
        f"{urllib.parse.quote(name)}/agent/{action}"
        f"?namespace={urllib.parse.quote(namespace)}"
    )
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    if session_id:
        req.add_header("X-KW-Agent-Session", session_id)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            body = ""
        return exc.code, {"_http_error": body[:200]}


def ws_connect(host, port, use_tls, path, token, timeout=15):
    raw = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n"
        f"User-Agent: {USER_AGENT}\r\n\r\n"
    )
    raw.sendall(req.encode())
    raw.settimeout(timeout)
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = raw.recv(4096)
        if not chunk:
            raise ConnectionError("proxy closed during WebSocket handshake")
        head += chunk
    status_line = head.split(b"\r\n", 1)[0].decode("latin1")
    code = int(status_line.split(" ", 2)[1])
    if code != 101:
        raise ConnectionError(f"WebSocket upgrade refused: {status_line}")
    return raw


def ws_send(sock, payload):
    if len(payload) > 0xFFFF:
        header = struct.pack("!BBQ", 0x82, 0xFF, len(payload))
    else:
        header = struct.pack("!BBH", 0x82, 0x80 | 126, len(payload))
    mask = os.urandom(4)
    sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def ws_recv(sock):
    hdr = _recvn(sock, 2)
    opcode = hdr[0] & 0x0F
    length = hdr[1] & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", _recvn(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", _recvn(sock, 8))
    if hdr[1] & 0x80:
        mask = _recvn(sock, 4)
    else:
        mask = None
    data = _recvn(sock, length) if length else b""
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    if opcode == 0x8:
        raise ConnectionError("peer sent WebSocket close")
    if opcode == 0x9:  # ping -> pong
        sock.sendall(b"\x8a\x80" + os.urandom(4))
        return ws_recv(sock)
    if opcode != 0x2:
        raise ConnectionError(f"unexpected WebSocket opcode {opcode}")
    return data


def _recvn(sock, count):
    out = b""
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        out += chunk
    return out


def send_control(sock, session_id, msg_type, sequence, payload):
    body = json.dumps(
        {
            "protocol": PROTOCOL,
            "protocolVersion": 1,
            "sessionId": session_id,
            "generation": 1,
            "sequence": sequence,
            "sentAtNs": time.monotonic_ns(),
            "channel": "control",
            "type": msg_type,
            "payload": payload,
        }
    ).encode()
    ws_send(sock, b"\x00" + struct.pack("!I", len(body)) + body)


def recv_control(sock):
    data = ws_recv(sock)
    if len(data) < 5 or data[0] != 0x00:
        raise ConnectionError("non-control frame from bridge")
    (length,) = struct.unpack("!I", data[1:5])
    return json.loads(data[5 : 5 + length].decode("utf-8"))


def percentile(sorted_vals, pct):
    """Nearest-rank percentile over an already-sorted list (None when empty).
    pct is 0-100; rank = ceil(pct/100 * N), 1-based into the list."""
    if not sorted_vals:
        return None
    rank = min(len(sorted_vals), max(1, -(-pct * len(sorted_vals) // 100)))
    return sorted_vals[int(rank) - 1]


def annexb_has_idr(unit):
    """True when an H.264 Annex-B access unit carries an IDR slice (NAL type 5)."""
    zeros = 0
    for i, byte in enumerate(unit):
        if byte == 0:
            zeros += 1
            continue
        if byte == 1 and zeros >= 2 and i + 1 < len(unit) and unit[i + 1] & 0x1F == 5:
            return True
        zeros = 0
    return False


class MeasureStats:
    """W6 transport/quality counters for one measurement window (no I/O)."""

    NOMINAL_VIDEO_MS = 1000.0 / 30
    NOMINAL_AUDIO_MS = 20.0

    def __init__(self):
        self.video_frames = 0
        self.video_bytes = 0
        self.video_sizes = []
        self.video_idrs = 0
        self.video_gaps = []
        self.audio_packets = 0
        self.audio_bytes = 0
        self.audio_gaps = []
        self.telemetry_rtts = []
        self._last_video_at = None
        self._last_audio_at = None

    def add_video(self, size, idr, at_ms):
        self.video_frames += 1
        self.video_bytes += size
        self.video_sizes.append(size)
        if idr:
            self.video_idrs += 1
        if self._last_video_at is not None:
            self.video_gaps.append(at_ms - self._last_video_at)
        self._last_video_at = at_ms

    def add_audio(self, size, at_ms):
        self.audio_packets += 1
        self.audio_bytes += size
        if self._last_audio_at is not None:
            self.audio_gaps.append(at_ms - self._last_audio_at)
        self._last_audio_at = at_ms

    def add_telemetry_rtt(self, rtt_ms):
        self.telemetry_rtts.append(rtt_ms)

    def summary(self, duration_s):
        out = {"duration_s": round(duration_s, 3)}
        gaps = sorted(self.video_gaps)
        sizes = sorted(self.video_sizes)
        out["video"] = {
            "frames": self.video_frames,
            "bytes": self.video_bytes,
            "fps": round(self.video_frames / duration_s, 2) if duration_s > 0 else 0,
            "bitrate_bps": round(self.video_bytes * 8 / duration_s) if duration_s > 0 else 0,
            "idr_frames": self.video_idrs,
            "frame_bytes_p50": percentile(sizes, 50),
            "frame_bytes_p95": percentile(sizes, 95),
            "gap_ms_p50": percentile(gaps, 50),
            "gap_ms_p95": percentile(gaps, 95),
        }
        agaps = sorted(self.audio_gaps)
        out["audio"] = {
            "packets": self.audio_packets,
            "bytes": self.audio_bytes,
            "pps": round(self.audio_packets / duration_s, 2) if duration_s > 0 else 0,
            "gap_ms_p50": percentile(agaps, 50),
            "gap_ms_p95": percentile(agaps, 95),
        }
        rtts = sorted(self.telemetry_rtts)
        out["telemetry"] = {
            "responses": len(rtts),
            "rtt_ms_p50": percentile(rtts, 50),
            "rtt_ms_p95": percentile(rtts, 95),
        }
        return out


def run_measure(sock, live_session, seq, seconds):
    """Collect media/cadence evidence for W6: keyframe, then count H.264
    access units and Opus packets for `seconds` while pinging telemetry
    ~1/s. Telemetry RTT is send-to-next-response (approximation: the guest
    answers state pushes, not addressed replies). Returns (MeasureStats,
    next_seq). Never raises on guest silence; raises ConnectionError only
    when the bridge itself dies.
    """
    stats = MeasureStats()
    start = time.monotonic()
    deadline = start + seconds
    sock.settimeout(0.5)
    send_control(sock, live_session, "keyframeRequest", seq, {})
    seq += 1
    next_telemetry_at = start
    pending_telemetry_at = None
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_telemetry_at:
                send_control(sock, live_session, "telemetry", seq, {})
                seq += 1
                pending_telemetry_at = now
                next_telemetry_at = now + 1.0
            try:
                data = ws_recv(sock)
            except socket.timeout:
                continue
            except ConnectionError:
                break  # Bridge died mid-measure: keep partial evidence.
            at_ms = (time.monotonic() - start) * 1000.0
            if len(data) < 5:
                continue
            tag = data[0]
            (length,) = struct.unpack("!I", data[1:5])
            body = data[5 : 5 + length]
            if tag == 0x01:
                stats.add_video(len(body), annexb_has_idr(body), at_ms)
            elif tag == 0x02:
                stats.add_audio(len(body), at_ms)
            elif tag == 0x00 and pending_telemetry_at is not None:
                try:
                    if json.loads(body.decode("utf-8")).get("type") == "telemetry":
                        stats.add_telemetry_rtt((time.monotonic() - pending_telemetry_at) * 1000.0)
                        pending_telemetry_at = None
                except (ValueError, UnicodeDecodeError):
                    pass
    finally:
        sock.settimeout(None)
    return stats, seq


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api-base", required=True, help="API origin, e.g. https://api.example.com")
    ap.add_argument("--ingress-host", required=True, help="Ingress host serving /proxy/...")
    ap.add_argument("--ingress-port", type=int, default=443)
    ap.add_argument("--no-tls", action="store_true", help="use ws:// + port 80")
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--token", default=os.environ.get("KW_TOKEN"), help="platform bearer token (or $KW_TOKEN)")
    ap.add_argument("--busy-test", action="store_true", help="hold the bridge and expect a second connect to fail busy")
    ap.add_argument("--skip-release", action="store_true")
    ap.add_argument("--measure", type=float, default=0, metavar="SECONDS",
                    help="after admission, collect media/cadence evidence for SECONDS "
                         "(W6 reference measurement; needs the display seat)")
    args = ap.parse_args()
    if not args.token:
        print("error: --token or $KW_TOKEN is required", file=sys.stderr)
        return 2

    use_tls = not args.no_tls
    if args.no_tls and args.ingress_port == 443:
        args.ingress_port = 80
    summary = {"workspace": f"{args.namespace}/{args.workspace}", "checks": {}}
    failures = []

    def check(name, ok, detail=""):
        summary["checks"][name] = {"ok": bool(ok), "detail": detail}
        if not ok:
            failures.append(name)

    # 1. API ticket.
    code, attach = api_call(args.api_base, args.namespace, args.workspace, "attach", args.token)
    check("api-attach", code == 200, f"http={code}")
    if code != 200:
        return finish(summary, failures)
    try:
        session_id, ticket = decode_ticket(attach["ticket"])
    except (KeyError, ValueError) as exc:
        check("ticket-decodes", False, str(exc))
        return finish(summary, failures)
    check("ticket-decodes", True, f"uid={ticket.get('workspaceUid','')[:8]}... expires_in_s="
          f"{(ticket.get('expiresAtNs', 0) - time.time_ns()) // 1_000_000_000}")
    check("ticket-protocol", attach.get("protocol") == 1, f"protocol={attach.get('protocol')}")

    # 2. Bridge + hello.
    path = f"/proxy/{args.namespace}/{args.workspace}/agent/"
    try:
        sock = ws_connect(args.ingress_host, args.ingress_port, use_tls, path, args.token)
    except (ConnectionError, OSError, ssl.SSLError) as exc:
        check("bridge-open", False, str(exc)[:160])
        return finish(summary, failures)
    check("bridge-open", True, path)
    try:
        hello = recv_control(sock)
    except ConnectionError as exc:
        check("guest-hello", False, str(exc)[:160])
        return finish(summary, failures)
    live_session = hello.get("sessionId", "")
    check("guest-hello", hello.get("type") == "hello" and bool(live_session), f"type={hello.get('type')}")

    # 3. Optional busy check: a second bridge must not steal the seat.
    if args.busy_test:
        try:
            second = ws_connect(args.ingress_host, args.ingress_port, use_tls, path, args.token)
            second.close()
            check("seat-busy", False, "second bridge was admitted while first holds the seat")
        except ConnectionError as exc:
            check("seat-busy", "409" in str(exc) or "refused" in str(exc), str(exc)[:160])

    # 4. Stamp the live claim into the ticket and attach.
    ticket["sessionId"] = live_session
    send_control(sock, live_session, "attach", 2, {"ticket": ticket})
    try:
        result = recv_control(sock)
    except ConnectionError as exc:
        check("attach-admitted", False, str(exc)[:160])
        return finish(summary, failures, sock)
    check("attach-admitted", result.get("payload", {}).get("admitted") is True,
          f"type={result.get('type')} payload={result.get('payload')}")
    seq = 3

    # 4b. Optional W6 measurement before the resize round-trip disturbs the mode.
    if args.measure > 0:
        admitted = result.get("payload", {}).get("admitted") is True
        if not admitted:
            check("measure", False, "skipped: attach not admitted")
        else:
            try:
                stats, seq = run_measure(sock, live_session, seq, args.measure)
                summary["measure"] = stats.summary(args.measure)
                check("measure", True, f"fps={summary['measure']['video']['fps']} "
                      f"video_bps={summary['measure']['video']['bitrate_bps']} "
                      f"audio_pps={summary['measure']['audio']['pps']}")
            except ConnectionError as exc:
                check("measure", False, str(exc)[:160])
                return finish(summary, failures, sock)

    # 5. Resize round-trip (pairing is the proof; the mode NACK is expected pre-display-backend).
    rid = "bridge-check-1"
    send_control(sock, live_session, "resizeRequest", seq, {"requestId": rid})
    seq += 1
    try:
        ack = recv_control(sock)
    except ConnectionError as exc:
        check("resize-paired", False, str(exc)[:160])
        return finish(summary, failures, sock)
    check("resize-paired", ack.get("type") == "resizeAck" and ack.get("payload", {}).get("requestId") == rid,
          f"reason={ack.get('payload', {}).get('reason')}")

    # 6. Keyframe (no reply by design) + orderly bye + release.
    send_control(sock, live_session, "keyframeRequest", seq, {})
    seq += 1
    send_control(sock, live_session, "bye", seq, {})
    seq += 1
    sock.close()
    check("bye-sent", True)
    if not args.skip_release:
        code, _ = api_call(args.api_base, args.namespace, args.workspace, "release", args.token, session_id)
        check("api-release", code == 200, f"http={code}")
    return finish(summary, failures)


def finish(summary, failures, sock=None):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
    summary["verdict"] = "PASS" if not failures else "FAIL"
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
