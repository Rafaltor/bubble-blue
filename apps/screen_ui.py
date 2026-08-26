#!/usr/bin/env python3
"""
Bubble Blue screen app: the touch UI that talks to meshd.

Runs on the distribution Python (PyGObject is not built for 3.14) and as an
unprivileged user — all Bluetooth work happens in the daemon behind the socket:

    python3 apps/screen_ui.py                 # windowed, for development
    cage -- python3 apps/screen_ui.py --kiosk # fullscreen on the board

Sized for the 1024x600 capacitive panel. It carries its own on-screen keyboard
because the boards have no physical one and a kiosk session has no shell to
launch a system OSK from.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.protocol import encode, read_frames, socket_path  # noqa: E402

RECONNECT_DELAY_S = 2.0

CSS = b"""
window { background: #0f1620; }

.statusbar {
    background: #16202e;
    border-bottom: 1px solid #24313f;
    padding: 6px 14px;
}
.brand { font-size: 17px; font-weight: 700; color: #4aa3ff; }
.identity { font-size: 12px; color: #7d8da0; font-family: monospace; }

.badge {
    font-size: 12px; font-weight: 700;
    padding: 3px 10px; border-radius: 11px;
    background: #24313f; color: #9fb0c4;
}
.badge.relay { background: #1d4a2b; color: #6ee89a; }
.badge.online { background: #123a5c; color: #6ec2ff; }
.badge.offline { background: #4a1d1d; color: #ff8a8a; }

.chat { padding: 10px 14px; }

.bubble {
    padding: 8px 13px;
    border-radius: 14px;
    background: #1c2836;
    color: #e6edf5;
    font-size: 15px;
}
.bubble.mine { background: #1f5f9e; color: #ffffff; }
.bubble.system { background: transparent; color: #6b7b8d; font-size: 12px; font-style: italic; }
.sender { font-size: 11px; color: #7d8da0; font-family: monospace; padding: 0 6px; }

.composer { background: #16202e; border-top: 1px solid #24313f; padding: 8px; }
entry {
    font-size: 16px; padding: 10px 12px; border-radius: 10px;
    background: #0f1620; color: #e6edf5; border: 1px solid #2c3a4a;
}
entry:focus { border-color: #4aa3ff; }

.sendbtn {
    font-size: 15px; font-weight: 700;
    padding: 10px 20px; border-radius: 10px;
    background: #1f6feb; color: #ffffff; border: none;
}
.sendbtn:hover { background: #2d7ff5; }
.sendbtn:disabled { background: #24313f; color: #5c6b7d; }

.keyboard { background: #131c27; border-top: 1px solid #24313f; padding: 5px; }
.key {
    font-size: 16px; min-width: 52px; min-height: 46px;
    border-radius: 8px; background: #26333f; color: #e6edf5; border: none;
    margin: 2px;
}
.key:hover { background: #33424f; }
.key.wide { min-width: 80px; font-size: 13px; font-weight: 700; }
.key.space { min-width: 280px; }
.key.accent { background: #1f6feb; color: #ffffff; font-weight: 700; }
"""

# AZERTY, because the boards live in a French lab and the panel has no legend.
_ROWS_LOWER = ["azertyuiop", "qsdfghjklm", "wxcvbn'-"]
_ROWS_UPPER = ["AZERTYUIOP", "QSDFGHJKLM", "WXCVBN?!"]
_ROW_DIGITS = "1234567890"


class MeshClient:
    """Socket side of the UI. Reconnects on its own so the app can start before
    the daemon does, and survive a daemon restart without being relaunched."""

    def __init__(self, path: str, on_event, on_state):
        self.path = path
        self._on_event = on_event
        self._on_state = on_state
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._next_id = 1

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.path)
            except OSError:
                GLib.idle_add(self._on_state, False, f"démon introuvable ({self.path})")
                self._stop.wait(RECONNECT_DELAY_S)
                continue

            with self._lock:
                self._sock = sock
            GLib.idle_add(self._on_state, True, "")

            for frame in read_frames(sock):
                GLib.idle_add(self._on_event, frame)

            with self._lock:
                self._sock = None
            try:
                sock.close()
            except OSError:
                pass
            if not self._stop.is_set():
                GLib.idle_add(self._on_state, False, "démon déconnecté")
                self._stop.wait(RECONNECT_DELAY_S)

    def send_text(self, text: str) -> bool:
        with self._lock:
            sock = self._sock
            if sock is None:
                return False
            req_id, self._next_id = self._next_id, self._next_id + 1
            try:
                sock.sendall(encode({"cmd": "send", "text": text, "id": req_id}))
            except OSError:
                return False
        return True


class ChatWindow(Gtk.ApplicationWindow):
    def __init__(self, app, sock_path: str, kiosk: bool):
        super().__init__(application=app, title="Bubble Blue")
        self.set_default_size(1024, 600)
        if kiosk:
            self.fullscreen()
            self.set_cursor(Gdk.Cursor.new_from_name("none", None))

        self._local = ""
        self._shift = False
        self._seen_history = False

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(root)
        root.append(self._build_statusbar())
        root.append(self._build_chat())
        root.append(self._build_composer())
        self._keyboard = self._build_keyboard()
        root.append(self._keyboard)
        # Reading is the common case and the panel is only 600 px tall, so the
        # keyboard stays out of the way until the entry is actually tapped.
        # Tap rather than focus: the entry is focused at startup, which would
        # otherwise raise the keyboard before anyone has touched the screen.
        self._keyboard.set_visible(False)
        tap = Gtk.GestureClick()
        tap.connect("pressed", lambda *_: self._keyboard.set_visible(True))
        self._entry.add_controller(tap)

        self.client = MeshClient(sock_path, self._on_event, self._on_state)
        self.client.start()

    # ---- widgets --------------------------------------------------------

    def _build_statusbar(self) -> Gtk.Widget:
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.add_css_class("statusbar")

        brand = Gtk.Label(label="Bubble Blue")
        brand.add_css_class("brand")
        bar.append(brand)

        self._identity = Gtk.Label(label="—")
        self._identity.add_css_class("identity")
        bar.append(self._identity)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bar.append(spacer)

        self._peers_badge = Gtk.Label(label="0 voisin")
        self._peers_badge.add_css_class("badge")
        bar.append(self._peers_badge)

        self._relay_badge = Gtk.Label(label="LEAF")
        self._relay_badge.add_css_class("badge")
        bar.append(self._relay_badge)

        self._link_badge = Gtk.Label(label="hors ligne")
        self._link_badge.add_css_class("badge")
        self._link_badge.add_css_class("offline")
        bar.append(self._link_badge)
        return bar

    def _build_chat(self) -> Gtk.Widget:
        self._messages = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        self._messages.add_css_class("chat")
        self._messages.set_valign(Gtk.Align.END)

        self._scroll = Gtk.ScrolledWindow()
        self._scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._scroll.set_vexpand(True)
        self._scroll.set_child(self._messages)
        return self._scroll

    def _build_composer(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.add_css_class("composer")

        self._entry = Gtk.Entry()
        self._entry.set_placeholder_text("Écrire un message…")
        self._entry.set_hexpand(True)
        self._entry.connect("activate", lambda *_: self._submit())
        box.append(self._entry)

        self._send = Gtk.Button(label="Envoyer")
        self._send.add_css_class("sendbtn")
        self._send.connect("clicked", lambda *_: self._submit())
        box.append(self._send)

        toggle = Gtk.Button(label="⌨")
        toggle.add_css_class("sendbtn")
        toggle.connect("clicked", self._toggle_keyboard)
        box.append(toggle)
        return box

    def _build_keyboard(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        box.add_css_class("keyboard")
        box.set_halign(Gtk.Align.CENTER)

        digits = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        digits.set_halign(Gtk.Align.CENTER)
        for ch in _ROW_DIGITS:
            digits.append(self._key(ch, lambda _b, c=ch: self._type(c)))
        box.append(digits)

        self._letter_rows = []
        for index in range(len(_ROWS_LOWER)):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
            row.set_halign(Gtk.Align.CENTER)
            keys = []
            if index == 2:
                shift = self._key("⇧", self._toggle_shift, extra="wide")
                row.append(shift)
            for pos, ch in enumerate(_ROWS_LOWER[index]):
                btn = self._key(ch, lambda _b, i=index, p=pos: self._type_letter(i, p))
                keys.append(btn)
                row.append(btn)
            if index == 2:
                row.append(self._key("⌫", lambda _b: self._backspace(), extra="wide"))
            self._letter_rows.append(keys)
            box.append(row)

        last = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        last.set_halign(Gtk.Align.CENTER)
        for ch in ".,@":
            last.append(self._key(ch, lambda _b, c=ch: self._type(c)))
        last.append(self._key("espace", lambda _b: self._type(" "), extra="space"))
        last.append(self._key("Envoyer", lambda _b: self._submit(), extra="wide accent"))
        box.append(last)
        return box

    def _key(self, label: str, handler, extra: str = "") -> Gtk.Button:
        btn = Gtk.Button(label=label)
        btn.add_css_class("key")
        for cls in extra.split():
            btn.add_css_class(cls)
        btn.set_can_focus(False)  # keep the caret in the entry
        btn.connect("clicked", handler)
        return btn

    # ---- keyboard behaviour --------------------------------------------

    def _toggle_keyboard(self, _btn) -> None:
        self._keyboard.set_visible(not self._keyboard.get_visible())

    def _toggle_shift(self, _btn) -> None:
        self._shift = not self._shift
        rows = _ROWS_UPPER if self._shift else _ROWS_LOWER
        for index, keys in enumerate(self._letter_rows):
            for pos, btn in enumerate(keys):
                btn.set_label(rows[index][pos])

    def _type_letter(self, row: int, pos: int) -> None:
        rows = _ROWS_UPPER if self._shift else _ROWS_LOWER
        self._type(rows[row][pos])
        if self._shift:
            self._toggle_shift(None)  # shift is one-shot, like a phone keyboard

    def _type(self, ch: str) -> None:
        buf = self._entry.get_buffer()
        buf.set_text(buf.get_text() + ch, -1)
        self._entry.set_position(-1)

    def _backspace(self) -> None:
        buf = self._entry.get_buffer()
        buf.set_text(buf.get_text()[:-1], -1)
        self._entry.set_position(-1)

    # ---- chat -----------------------------------------------------------

    def _submit(self) -> None:
        text = self._entry.get_buffer().get_text().strip()
        if not text:
            return
        if not self.client.send_text(text):
            self._add_system("message non envoyé — démon injoignable")
            return
        self._entry.get_buffer().set_text("", -1)

    def _add_message(self, sender: str, text: str, mine: bool, ts: float) -> None:
        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        column.set_halign(Gtk.Align.END if mine else Gtk.Align.START)

        clock = time.strftime("%H:%M", time.localtime(ts)) if ts else ""
        label = Gtk.Label(label=f"{'moi' if mine else sender}  {clock}")
        label.add_css_class("sender")
        label.set_halign(Gtk.Align.END if mine else Gtk.Align.START)
        column.append(label)

        bubble = Gtk.Label(label=text)
        bubble.add_css_class("bubble")
        if mine:
            bubble.add_css_class("mine")
        bubble.set_wrap(True)
        bubble.set_max_width_chars(46)
        bubble.set_xalign(0.0)
        bubble.set_halign(Gtk.Align.END if mine else Gtk.Align.START)
        column.append(bubble)

        self._messages.append(column)
        GLib.idle_add(self._scroll_to_end)

    def _add_system(self, text: str) -> None:
        label = Gtk.Label(label=text)
        label.add_css_class("bubble")
        label.add_css_class("system")
        label.set_halign(Gtk.Align.CENTER)
        self._messages.append(label)
        GLib.idle_add(self._scroll_to_end)

    def _scroll_to_end(self) -> bool:
        adj = self._scroll.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())
        return False

    # ---- daemon events --------------------------------------------------

    def _on_state(self, connected: bool, reason: str) -> bool:
        self._link_badge.set_label("en ligne" if connected else "hors ligne")
        self._link_badge.remove_css_class("online" if not connected else "offline")
        self._link_badge.add_css_class("online" if connected else "offline")
        self._send.set_sensitive(connected)
        if not connected and reason:
            self._add_system(reason)
        return False

    def _on_event(self, frame: dict) -> bool:
        ev = frame.get("ev")
        if ev == "hello":
            self._local = frame.get("local", "")
            self._identity.set_label(self._local)
            self._update_peers(frame.get("peers", []), frame.get("relay", False))
            if not self._seen_history:
                self._seen_history = True
                for msg in frame.get("history", []):
                    self._add_message(
                        msg.get("from", "?"),
                        msg.get("text", ""),
                        bool(msg.get("mine")),
                        float(msg.get("ts", 0)),
                    )
        elif ev == "message":
            self._add_message(
                frame.get("from", "?"),
                frame.get("text", ""),
                bool(frame.get("mine")),
                float(frame.get("ts", 0)),
            )
        elif ev == "peers":
            self._update_peers(frame.get("peers", []), frame.get("relay", False))
        elif ev == "ack" and not frame.get("ok", True):
            self._add_system(f"envoi refusé : {frame.get('error', 'inconnu')}")
        return False

    def _update_peers(self, peers: list, relay: bool) -> None:
        count = len(peers)
        self._peers_badge.set_label(f"{count} voisin{'s' if count > 1 else ''}")
        self._relay_badge.set_label("RELAY" if relay else "LEAF")
        if relay:
            self._relay_badge.add_css_class("relay")
        else:
            self._relay_badge.remove_css_class("relay")


class ScreenApp(Gtk.Application):
    def __init__(self, sock_path: str, kiosk: bool):
        super().__init__(application_id="fr.inria.bubbleblue.Screen")
        self._sock_path = sock_path
        self._kiosk = kiosk
        self._window: ChatWindow | None = None

    def do_activate(self):
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        if self._window is None:
            self._window = ChatWindow(self, self._sock_path, self._kiosk)
        self._window.present()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default=socket_path())
    ap.add_argument("--kiosk", action="store_true", help="fullscreen, no cursor")
    args = ap.parse_args()
    return ScreenApp(args.socket, args.kiosk).run([])


if __name__ == "__main__":
    raise SystemExit(main())
