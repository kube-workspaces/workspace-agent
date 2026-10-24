"""Bounded disposable GTK desktop for linux-desktop-check, not a user app."""
import json
import math
import sys
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gst", "1.0")
from gi.repository import Gtk, GLib, Gst

Gst.init(None)
app = Gtk.Application(application_id="io.kubeworkspaces.AgentDesktopCheck")
state = {"clipboard": None, "frame": 0}


def activate(app):
    window = Gtk.ApplicationWindow(application=app)
    window.set_title("Workspace Agent Disposable Desktop Check")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    entry = Gtk.Entry()
    entry.set_size_request(-1, 140)
    box.append(entry)
    area = Gtk.DrawingArea()
    area.set_vexpand(True)
    def draw(_area, cr, width, height):
        cr.set_source_rgb((math.sin(state["frame"] / 5) + 1) / 2, 0.2, 0.7)
        cr.paint()
        cr.set_source_rgb(1, 1, 1)
        cr.rectangle(state["frame"] * 7 % max(width, 1), 20, 100, max(height - 40, 20))
        cr.fill()
    area.set_draw_func(draw)
    box.append(area)
    window.set_child(box)
    window.fullscreen()
    window.present()
    entry.grab_focus()
    tone = Gst.parse_launch("audiotestsrc wave=sine freq=440 volume=0.15 ! audioconvert ! pulsesink")
    tone.set_state(Gst.State.PLAYING)
    def animate():
        state["frame"] += 1
        area.queue_draw()
        return True
    GLib.timeout_add(50, animate)
    GLib.timeout_add(700, lambda: (print("ready", flush=True), False)[1])
    def copy_read(_clipboard, result):
        try:
            state["clipboard"] = window.get_clipboard().read_text_finish(result)
            window.get_clipboard().set("GNOME→agent λ")
        except GLib.Error:
            state["clipboard"] = "unavailable"
        print(json.dumps({"text": entry.get_text(), "clipboard": state["clipboard"], "active": window.is_active()}), flush=True)
    def request_clipboard(_fd, _condition):
        if sys.stdin.readline().strip() != "check":
            app.quit()
            return False
        window.get_clipboard().read_text_async(None, copy_read)
        return False
    GLib.io_add_watch(sys.stdin, GLib.IO_IN, request_clipboard)
    def finish():
        tone.set_state(Gst.State.NULL)
        app.quit()
        return False
    GLib.timeout_add(12000, finish)


app.connect("activate", activate)
app.run([])
