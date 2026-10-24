"""Private, bounded Gio/GStreamer adapter for GNOME Wayland.

Invoked only by the agent over an inherited socketpair. No listener, network
fetch, shell operation or user-supplied pipeline is accepted. Never logs pixels,
clipboard content or credentials. Mutter sessions belong to this D-Bus client
and are revoked by the compositor when the helper exits.
"""
import json
import os
import select
import struct
import subprocess
import sys
import time
import zlib

MAX_HEADER = 128 * 1024
MAX_PAYLOAD = 128 * 1024 * 1024
MAX_TEXT = 64 * 1024


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise EOFError()
        result.extend(chunk)
    return bytes(result)


def receive():
    size = struct.unpack(">I", exact(sys.stdin.buffer, 4))[0]
    if size > MAX_HEADER:
        raise ValueError("header-too-large")
    request = json.loads(exact(sys.stdin.buffer, size))
    size = request.get("bytes", 0)
    if not isinstance(size, int) or not 0 <= size <= MAX_PAYLOAD:
        raise ValueError("payload-too-large")
    return request, exact(sys.stdin.buffer, size)


def respond(metadata, payload=b""):
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload-too-large")
    metadata["bytes"] = len(payload)
    header = json.dumps(metadata, separators=(",", ":")).encode()
    if len(header) > MAX_HEADER:
        raise ValueError("header-too-large")
    sys.stdout.buffer.write(struct.pack(">I", len(header)) + header + payload)
    sys.stdout.buffer.flush()


def gi_modules():
    import gi
    gi.require_version("Gst", "1.0")
    gi.require_version("GstVideo", "1.0")
    from gi.repository import Gio, GLib, Gst, GstVideo
    Gst.init(None)
    return Gio, GLib, Gst, GstVideo


class Backend:
    def __init__(self, role):
        self.Gio, self.GLib, self.Gst, self.GstVideo = gi_modules()
        self.role = role
        self.pipeline = None
        self.bus = None
        self.rd = None
        self.cast = None
        self.stream = None
        self.node = None
        self.text = None
        self.selection_owned = False
        self.clipboard_enabled = False
        self.clipboard_types = []
        self.closed = False
        self.held_keys = set()
        self.held_buttons = set()
        self.pointer = (0, 0)

    def call(self, destination, path, interface, method, signature=None, args=()):
        try:
            return self.bus.call_sync(destination, path, interface, method,
                                      self.GLib.Variant(signature, args) if signature else None,
                                      None, self.Gio.DBusCallFlags.NONE, 3000, None).unpack()
        except self.GLib.Error:
            raise RuntimeError("dbus-" + interface + "." + method + "-failed") from None

    def properties(self, destination, path, interface):
        return self.call(destination, path, "org.freedesktop.DBus.Properties", "GetAll",
                         "(s)", (interface,))[0]

    def session(self):
        if os.getuid() == 0 or os.environ.get("XDG_SESSION_TYPE") != "wayland":
            raise RuntimeError("active-user-wayland-session-required")
        bus = self.Gio.bus_get_sync(self.Gio.BusType.SYSTEM, None)
        result = bus.call_sync("org.freedesktop.login1", "/org/freedesktop/login1",
                              "org.freedesktop.login1.Manager", "GetUser",
                              self.GLib.Variant("(u)", (os.getuid(),)), None,
                              self.Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
        props = bus.call_sync("org.freedesktop.login1", result,
                              "org.freedesktop.DBus.Properties", "GetAll",
                              self.GLib.Variant("(s)", ("org.freedesktop.login1.User",)), None,
                              self.Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
        session_id, path = props["Display"]
        if not session_id:
            raise RuntimeError("no-local-console-session")
        if os.environ.get("XDG_SESSION_ID", session_id) != session_id:
            raise RuntimeError("process-is-not-local-console-session")
        props = bus.call_sync("org.freedesktop.login1", path,
                              "org.freedesktop.DBus.Properties", "GetAll",
                              self.GLib.Variant("(s)", ("org.freedesktop.login1.Session",)), None,
                              self.Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
        if not props.get("Active") or props.get("Remote") or props.get("LockedHint") or props.get("Type") != "wayland":
            raise RuntimeError("console-session-inactive-or-locked")
        if self.bus is None:
            self.bus = self.Gio.bus_get_sync(self.Gio.BusType.SESSION, None)
        return zlib.crc32(session_id.encode()) or 1

    def monitors(self):
        self.session()
        return self.call("org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig",
                         "org.gnome.Mutter.DisplayConfig", "GetCurrentState")

    def outputs(self):
        _, monitors, logical, _ = self.monitors()
        primary = next((m[5][0][0] for m in logical if m[4] and m[5]), None)
        result = []
        for spec, modes, _ in monitors:
            current = next((mode for mode in modes if mode[6].get("is-current")), None)
            if current is None:
                continue
            result.append({"name": spec[0], "attached": True, "width": current[1], "height": current[2],
                           "modes": [{"width": m[1], "height": m[2], "refreshHz": round(m[3]), "bitsPerPixel": 32}
                                     for m in modes if 320 <= m[1] <= 8192 and 200 <= m[2] <= 8192]})
        result.sort(key=lambda o: (o["name"] != primary, o["name"]))
        return result

    def inventory(self):
        outputs = self.outputs()
        encoders = ["GStreamer x264enc"] if self.Gst.ElementFactory.find("x264enc") else []
        endpoints = []
        try:
            sink = subprocess.run(["/usr/bin/pactl", "get-default-sink"], capture_output=True,
                                  text=True, check=True, timeout=2).stdout.strip()
            if sink:
                endpoints = [sink]
        except (OSError, subprocess.SubprocessError):
            pass
        return {"inventory": {"agentVersion": "linux-backend", "platform": "linux-" + os.uname().machine,
                "d3d11WarpOk": False, "adapters": [{"description": "GNOME Mutter/PipeWire (render adapter unobserved)",
                "vendorId": 0, "deviceId": 0, "dedicatedVramBytes": 0, "software": False,
                "d3d11Ok": False, "d3d11Level": 0, "outputs": outputs}],
                "audioRenderEndpoints": endpoints, "softwareH264Encoders": encoders}}

    def open_desktop(self, name=None):
        self.session()
        output = next((o for o in self.outputs() if name is None or o["name"] == name), None)
        if output is None:
            raise RuntimeError("display-output-unavailable")
        self.output = output["name"]
        self.rd = self.call("org.gnome.Mutter.RemoteDesktop", "/org/gnome/Mutter/RemoteDesktop",
                             "org.gnome.Mutter.RemoteDesktop", "CreateSession")[0]
        session_id = self.properties("org.gnome.Mutter.RemoteDesktop", self.rd,
                                     "org.gnome.Mutter.RemoteDesktop.Session")["SessionId"]
        self.cast = self.call("org.gnome.Mutter.ScreenCast", "/org/gnome/Mutter/ScreenCast",
                              "org.gnome.Mutter.ScreenCast", "CreateSession", "(a{sv})",
                              ({"remote-desktop-session-id": self.GLib.Variant("s", session_id)},))[0]
        self.stream = self.call("org.gnome.Mutter.ScreenCast", self.cast,
                                "org.gnome.Mutter.ScreenCast.Session", "RecordMonitor", "(sa{sv})",
                                (self.output, {"cursor-mode": self.GLib.Variant("u", 1)}))[0]
        self.bus.signal_subscribe("org.gnome.Mutter.ScreenCast", "org.gnome.Mutter.ScreenCast.Stream",
                                  "PipeWireStreamAdded", self.stream, None, self.Gio.DBusSignalFlags.NONE,
                                  lambda *args: setattr(self, "node", args[-1].unpack()[0]))
        self.bus.signal_subscribe("org.gnome.Mutter.RemoteDesktop", "org.gnome.Mutter.RemoteDesktop.Session",
                                  None, self.rd, None, self.Gio.DBusSignalFlags.NONE, self.rd_signal)
        self.rd_call("Start")
        deadline = time.monotonic() + 4
        while self.node is None and time.monotonic() < deadline:
            self.pump()
            time.sleep(0.005)
        if self.node is None:
            raise RuntimeError("pipewire-node-timeout")
        self.capture_size = (output["width"], output["height"])
        self.start_capture()
        return output

    def start_capture(self):
        if self.pipeline is not None:
            self.pipeline.set_state(self.Gst.State.NULL)
        self.pipeline = self.Gst.parse_launch(
            f'pipewiresrc path={self.node} do-timestamp=true ! videoconvert ! video/x-raw,format=BGRA '
            '! appsink name=sink max-buffers=1 drop=true sync=false')
        self.pipeline.set_state(self.Gst.State.PLAYING)
        self.sink = self.pipeline.get_by_name("sink")

    def rd_call(self, method, signature=None, args=()):
        return self.call("org.gnome.Mutter.RemoteDesktop", self.rd,
                         "org.gnome.Mutter.RemoteDesktop.Session", method, signature, args)

    def pump(self):
        context = self.GLib.MainContext.default()
        while context.pending():
            context.iteration(False)
        if self.closed:
            raise RuntimeError("desktop-session-closed")

    def rd_signal(self, _bus, _sender, path, _interface, signal, parameters):
        if path != self.rd:
            return
        if signal == "Closed":
            self.closed = True
        elif signal == "SelectionOwnerChanged":
            options = parameters.unpack()[0]
            self.selection_owned = options.get("session-is-owner", False)
            if not self.selection_owned:
                types = options.get("mime-types", [])
                # Mutter's compatibility projection can wrap the string array
                # in a tuple inside the variant (GNOME 51).
                if len(types) == 1 and isinstance(types[0], (list, tuple)):
                    types = types[0]
                self.clipboard_types = types
        elif signal == "SelectionTransfer":
            mime, serial = parameters.unpack()
            try:
                result, fds = self.bus.call_with_unix_fd_list_sync(
                    "org.gnome.Mutter.RemoteDesktop", self.rd, "org.gnome.Mutter.RemoteDesktop.Session",
                    "SelectionWrite", self.GLib.Variant("(u)", (serial,)), None,
                    self.Gio.DBusCallFlags.NONE, 3000, None, None)
                fd = fds.get(result.unpack()[0])
                try:
                    os.set_blocking(fd, False)
                    data = (self.text or "").encode()
                    deadline = time.monotonic() + 1
                    while data and time.monotonic() < deadline:
                        if select.select([], [fd], [], 0.05)[1]:
                            data = data[os.write(fd, data):]
                    success = not data
                finally:
                    os.close(fd)
                self.rd_call("SelectionWriteDone", "(ub)", (serial, success))
            except Exception:
                self.rd_call("SelectionWriteDone", "(ub)", (serial, False))

    def sample(self, timeout_ms):
        sample = self.sink.emit("try-pull-sample", min(max(timeout_ms, 0), 2000) * self.Gst.MSECOND)
        if sample is None:
            message = self.pipeline.get_bus().pop_filtered(self.Gst.MessageType.ERROR | self.Gst.MessageType.EOS)
            if message is not None:
                raise RuntimeError("media-pipeline-ended")
        return sample

    def encoder(self, req):
        settings = req["settings"]
        w, h, fps, bitrate, gop = (int(settings[k]) for k in ("width", "height", "fps", "bitrate_bps", "max_keyframe_spacing"))
        if not (16 <= w <= 8192 and 16 <= h <= 8192 and w % 16 == h % 16 == 0 and 1 <= fps <= 120 and 1 <= gop <= 1000 and 1000 <= bitrate <= 100_000_000):
            raise ValueError("invalid-encoder-settings")
        self.frame_size = w * h * 3 // 2
        self.encoder_pts_offset = None
        self.pipeline = self.Gst.parse_launch(
            f'appsrc name=source format=time is-live=true block=true caps="video/x-raw,format=NV12,width={w},height={h},framerate={fps}/1" '
            f'! x264enc tune=zerolatency speed-preset=ultrafast bitrate={max(1, bitrate // 1000)} key-int-max={gop} bframes=0 byte-stream=true '
            '! h264parse config-interval=-1 ! video/x-h264,stream-format=byte-stream,alignment=au,profile=baseline '
            '! appsink name=sink sync=false max-buffers=2')
        self.source = self.pipeline.get_by_name("source")
        self.sink = self.pipeline.get_by_name("sink")
        self.pipeline.set_state(self.Gst.State.PLAYING)
        return {}

    def dispatch(self, req, payload):
        op = req["op"]
        if self.role == "inventory" and op == "inventory":
            return self.inventory(), b""
        if self.role == "inventory" and op == "session":
            return {"session": self.session()}, b""
        if self.role == "encoder":
            if op == "open":
                return self.encoder(req), b""
            if op == "encode":
                if len(payload) != self.frame_size:
                    raise ValueError("invalid-frame-size")
                pts = int(req["timestamp100ns"]) * 100
                if pts < 0:
                    raise ValueError("invalid-frame-timestamp")
                if req.get("forceIdr"):
                    event = self.GstVideo.video_event_new_downstream_force_key_unit(
                        self.Gst.CLOCK_TIME_NONE, self.Gst.CLOCK_TIME_NONE, self.Gst.CLOCK_TIME_NONE, True, 0)
                    if not self.source.get_static_pad("src").push_event(event):
                        raise RuntimeError("encoder-keyframe-request-refused")
                buffer = self.Gst.Buffer.new_allocate(None, len(payload), None)
                buffer.fill(0, payload)
                buffer.pts = pts
                buffer.dts = pts
                if self.source.emit("push-buffer", buffer) != self.Gst.FlowReturn.OK:
                    raise RuntimeError("encoder-input-refused")
                sample = self.sample(2000)
                if sample is None:
                    raise RuntimeError("encoder-output-timeout")
                buffer = sample.get_buffer()
                # x264enc shifts PTS by a large constant to accommodate DTS.
                # Measure it once and verify one-to-one timestamp correspondence
                # on every access unit; preserve the caller's common A/V clock.
                if self.encoder_pts_offset is None:
                    self.encoder_pts_offset = buffer.pts - pts
                actual_pts = buffer.pts - self.encoder_pts_offset
                if actual_pts != pts:
                    raise RuntimeError("encoder-timestamp-mismatch")
                return {"timestamp100ns": actual_pts // 100}, buffer.extract_dup(0, buffer.get_size())
        if self.role == "desktop":
            if op == "open":
                return {"output": self.open_desktop(req.get("name"))}, b""
            self.session()
            self.pump()
            if op == "frame":
                sample = self.sample(req.get("timeoutMs", 100))
                if sample is None:
                    return {"empty": True}, b""
                caps = sample.get_caps()
                info = self.GstVideo.VideoInfo.new_from_caps(caps)
                buffer = sample.get_buffer()
                return {"width": info.width, "height": info.height, "stride": info.stride[0]}, buffer.extract_dup(0, buffer.get_size())
            if op == "geometry":
                return {"output": next(o for o in self.outputs() if o["name"] == self.output)}, b""
            if op == "captureOpen":
                requested = (int(req["width"]), int(req["height"]))
                if req["name"] != self.output:
                    raise RuntimeError("capture-output-mismatch")
                if requested != self.capture_size:
                    # Stable Mutter versions retain the original monitor
                    # geometry in the screencast. Reopen the paired session;
                    # per-stream Stop/Start is not available in GNOME 51.
                    own_text = self.text if self.selection_owned else None
                    keys, buttons = list(self.held_keys), list(self.held_buttons)
                    self.pipeline.set_state(self.Gst.State.NULL)
                    self.rd_call("Stop")
                    self.rd = None
                    self.closed = False
                    self.node = None
                    self.clipboard_enabled = False
                    self.selection_owned = False
                    self.clipboard_types = []
                    self.open_desktop(self.output)
                    if own_text is not None:
                        self.clipboard("clipboardWrite", own_text.encode())
                    for key in keys:
                        self.dispatch({"op": "key", "keysym": key, "down": True}, b"")
                    self.dispatch({"op": "pointer", "x": min(self.pointer[0], requested[0] - 1),
                                   "y": min(self.pointer[1], requested[1] - 1),
                                   "buttons": [(b, True) for b in buttons]}, b"")
                return {}, b""
            if op == "key":
                keysym, down = int(req["keysym"]), bool(req["down"])
                if not down and keysym not in self.held_keys:
                    return {}, b""
                # Modifiers/navigation are physical keys. Sending a modifier
                # through keyval synthesis can undo its own modifier state.
                keycodes = {0xff1b: 1, 0xff08: 14, 0xff09: 15, 0xff0d: 28,
                            0xffe1: 42, 0xffe2: 54, 0xffe3: 29, 0xffe4: 97,
                            0xffe9: 56, 0xffea: 100, 0xffeb: 125, 0xffec: 126,
                            0xff50: 102, 0xff51: 105, 0xff52: 103, 0xff53: 106,
                            0xff54: 108, 0xff55: 104, 0xff56: 109, 0xff57: 107,
                            0xffff: 111, 0xff63: 110}
                if keysym in keycodes:
                    self.rd_call("NotifyKeyboardKeycode", "(ub)", (keycodes[keysym], down))
                else:
                    self.rd_call("NotifyKeyboardKeysym", "(ub)", (keysym, down))
                if down:
                    self.held_keys.add(keysym)
                else:
                    self.held_keys.discard(keysym)
            elif op == "pointer":
                self.rd_call("NotifyPointerMotionAbsolute", "(sdd)", (self.stream, float(req["x"]), float(req["y"])))
                self.pointer = (int(req["x"]), int(req["y"]))
                for button, down in req.get("buttons", []):
                    if button not in (272, 273, 274):
                        raise ValueError("invalid-pointer-button")
                    if not down and button not in self.held_buttons:
                        continue
                    self.rd_call("NotifyPointerButton", "(ib)", (button, bool(down)))
                    if down:
                        self.held_buttons.add(button)
                    else:
                        self.held_buttons.discard(button)
            elif op == "wheel":
                self.rd_call("NotifyPointerAxis", "(ddu)", (float(req["dx"]) * 10, float(req["dy"]) * 10, 3))
            elif op == "resize":
                self.resize(int(req["width"]), int(req["height"]))
            elif op in ("clipboardRead", "clipboardWrite"):
                return self.clipboard(op, payload)
            else:
                raise ValueError("unsupported-desktop-operation")
            return {}, b""
        if self.role == "audio":
            if op == "open":
                self.session()
                sink = subprocess.run(["/usr/bin/pactl", "get-default-sink"], capture_output=True, text=True, check=True, timeout=2).stdout.strip()
                if not sink or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in sink):
                    raise RuntimeError("audio-render-endpoint-unavailable")
                self.pipeline = self.Gst.parse_launch(
                    f'pulsesrc device="{sink}.monitor" ! audioconvert ! audioresample '
                    '! audio/x-raw,format=F32LE,channels=2,rate=48000,layout=interleaved '
                    '! appsink name=sink sync=false max-buffers=8 drop=true')
                self.sink = self.pipeline.get_by_name("sink")
                self.pipeline.set_state(self.Gst.State.PLAYING)
                self.audio_sink = sink
                self.volume_at = 0
                self.volume = 1.0
                self.muted = False
                return {}, b""
            if op == "audio":
                sample = self.sample(req.get("timeoutMs", 200))
                try:
                    self.session()
                except RuntimeError as error:
                    if str(error) == "console-session-inactive-or-locked":
                        return {"empty": True}, b""
                    raise
                if sample is None:
                    return {"empty": True}, b""
                buffer = sample.get_buffer()
                if time.monotonic() - self.volume_at > 0.25:
                    sinks = json.loads(subprocess.run(["/usr/bin/pactl", "-f", "json", "list", "sinks"],
                                       capture_output=True, text=True, check=True, timeout=2).stdout)
                    sink = next(s for s in sinks if s["name"] == self.audio_sink)
                    self.volume = max(v["value"] for v in sink["volume"].values()) / 65536
                    self.muted = sink["mute"]
                    self.volume_at = time.monotonic()
                return {"volume": self.volume, "muted": self.muted}, buffer.extract_dup(0, buffer.get_size())
        raise ValueError("unsupported-operation")

    def resize(self, width, height):
        serial, monitors, logical, _ = self.monitors()
        selected = next(m for m in monitors if m[0][0] == self.output)
        mode = next((m for m in selected[1] if m[1] == width and m[2] == height), None)
        if mode is None:
            raise ValueError("display-mode-not-advertised")
        configs = []
        for x, y, scale, transform, primary, specs, _ in logical:
            choices = []
            for spec in specs:
                monitor = next(m for m in monitors if m[0] == spec)
                current = next(m for m in monitor[1] if m[6].get("is-current"))
                choices.append((spec[0], mode[0] if spec[0] == self.output else current[0], {}))
            configs.append((x, y, scale, transform, primary, choices))
        self.call("org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig",
                  "org.gnome.Mutter.DisplayConfig", "ApplyMonitorsConfig", "(uua(iiduba(ssa{sv}))a{sv})",
                  (serial, 1, configs, {}))

    def clipboard(self, op, payload):
        if not self.clipboard_enabled:
            self.rd_call("EnableClipboard", "(a{sv})", ({},))
            self.clipboard_enabled = True
        if op == "clipboardWrite":
            if len(payload) > MAX_TEXT or b"\x00" in payload:
                raise ValueError("invalid-clipboard-text")
            self.text = payload.decode("utf-8")
            self.rd_call("SetSelection", "(a{sv})", ({"mime-types": self.GLib.Variant("as", ["text/plain;charset=utf-8", "text/plain"])},))
            self.selection_owned = True
            return {}, b""
        if self.selection_owned and self.text is not None:
            return {"present": True, "owned": True}, self.text.encode()
        mime = next((m for m in ("text/plain;charset=utf-8", "UTF8_STRING", "text/plain") if m in self.clipboard_types), None)
        if mime is None:
            return {"present": False, "mimeTypes": self.clipboard_types, "owned": self.selection_owned}, b""
        result, fds = self.bus.call_with_unix_fd_list_sync(
            "org.gnome.Mutter.RemoteDesktop", self.rd, "org.gnome.Mutter.RemoteDesktop.Session",
            "SelectionRead", self.GLib.Variant("(s)", (mime,)), None,
            self.Gio.DBusCallFlags.NONE, 3000, None, None)
        fd = fds.get(result.unpack()[0])
        data = bytearray()
        deadline = time.monotonic() + 1
        try:
            os.set_blocking(fd, False)
            while time.monotonic() < deadline:
                self.pump()
                if select.select([fd], [], [], 0.02)[0]:
                    chunk = os.read(fd, min(8192, MAX_TEXT + 1 - len(data)))
                    if not chunk:
                        text = data.decode("utf-8")
                        if "\x00" in text:
                            raise ValueError("invalid-clipboard-text")
                        return {"present": True, "mime": mime}, bytes(data)
                    data.extend(chunk)
                    if len(data) > MAX_TEXT:
                        raise ValueError("clipboard-text-too-large")
            raise RuntimeError("clipboard-read-timeout")
        finally:
            os.close(fd)


def main():
    try:
        backend = Backend(sys.argv[1])
    except Exception:
        # Consume the caller's first request before replying so shutdown of
        # the inherited socket does not discard an unread request on Linux.
        try:
            receive()
            respond({"error": "linux-media-dependencies-unavailable"})
        except (EOFError, OSError):
            pass
        return
    try:
        while True:
            # Keep D-Bus clipboard/Closed signals serviced between requests.
            if not select.select([sys.stdin.buffer], [], [], 0.02)[0]:
                backend.pump()
                continue
            req, payload = receive()
            try:
                metadata, body = backend.dispatch(req, payload)
                respond(metadata, body)
            except Exception as error:
                # Error class only: GLib diagnostics may contain user/session
                # content. A failed operation terminates this backend instance.
                reason = str(error) if type(error) in (RuntimeError, ValueError) else type(error).__name__
                respond({"error": "linux-backend-" + reason})
                return
    except EOFError:
        pass
    finally:
        if backend.pipeline is not None:
            backend.pipeline.set_state(backend.Gst.State.NULL)
        if backend.rd is not None:
            try:
                backend.rd_call("Stop")
            except Exception:
                pass


if __name__ == "__main__":
    main()
