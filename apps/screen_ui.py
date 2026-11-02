#!/usr/bin/env python3
"""
Bubble Blue screen app: the touch UI that talks to meshd.

Runs on the distribution Python (PyGObject is not built for 3.14) and as an
unprivileged user — all Bluetooth work happens in the daemon behind the socket:

    python3 apps/screen_ui.py                         # windowed, for development
    cage -- python3 apps/screen_ui.py --kiosk         # fullscreen on the board
    cage -- python3 apps/screen_ui.py --kiosk --admin # + the mesh restart button

The kiosk has a Desktop button (two taps). It stops this service and starts
GDM, so the board's Ubuntu session is reachable for Wi-Fi and the rest.
The next boot takes the panel back.

Sized for the 1024x600 capacitive panel and for a demo stand: the chat sits
next to a live map of the mesh, where every message is drawn hopping from
board to board before it lands, and sending is a tap on a preset message —
visitors should not have to type on a panel with no legend.
"""

from __future__ import annotations

import argparse
import math
import os
import socket
import subprocess
import sys
import threading
import time
from collections import deque

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gsk", "4.0")
gi.require_version("Graphene", "1.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, GLib, Graphene, Gsk, Gtk, Pango  # noqa: E402

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.protocol import encode, read_frames, socket_path  # noqa: E402

RECONNECT_DELAY_S = 2.0
# Every tap floods every link, and on the UNO Q each received packet spends a
# kernel L2CAP ident: a crowd hammering the buttons must not become the load.
SEND_COOLDOWN_S = 1.5
RESTART_CONFIRM_S = 4.0
DESKTOP_CONFIRM_S = 4.0
# How long one hop takes on the map. Slower than the radio on purpose: the
# point is that people can follow it.
HOP_S = 0.6

_PRESETS_FILE = os.path.join(os.path.dirname(__file__), "presets.txt")
_DEFAULT_PRESETS = ["Hello from {name}!", "Can you read me?", "Received, thanks!"]

# Hard-wired 1-to-1 pair for the stand: only these two boards decrypt the
# packet. Relays forward it; every other screen stays blank.
_PRIVATE_PAIR = {
    "40:D9:5A:8B:69:3F": ("9C:B8:B4:9F:2D:75", "Rubik INRIA"),
    "9C:B8:B4:9F:2D:75": ("40:D9:5A:8B:69:3F", "Rubik Q"),
}
_PRIVATE_TEXT = "Private 1-to-1 from {name}: only we two can read this"

# Sender colours, shared by the chat bubbles and the pulses on the map.
PALETTE = ["#4aa3ff", "#ff9f43", "#6ee89a", "#ff6b9a", "#c49bff", "#ffd166"]

CSS = b"""
window { background: #0b121b; }

.statusbar {
    background: #131d2a;
    border-bottom: 1px solid #22303f;
    padding: 6px 14px;
}
.brand { font-size: 18px; font-weight: 800; color: #4aa3ff; }
.identity { font-size: 14px; font-weight: 700; color: #e6edf5; }
.address { font-size: 11px; color: #6b7b8d; font-family: monospace; }

.badge {
    font-size: 12px; font-weight: 700;
    padding: 3px 10px; border-radius: 11px;
    background: #24313f; color: #9fb0c4;
}
.badge.relay { background: #1d4a2b; color: #6ee89a; }
.badge.online { background: #123a5c; color: #6ec2ff; }
.badge.offline { background: #4a1d1d; color: #ff8a8a; }

.restart {
    font-size: 12px; font-weight: 700; padding: 4px 12px; border-radius: 11px;
    background: #2a3441; color: #c9d4e0; border: none;
}
.restart.confirm { background: #b3261e; color: #ffffff; }
.desktop { background: #1a3348; color: #9fd0ff; }
.revoke { background: #6b2a1a; color: #ffb4a2; }
.reset { background: #1d3a2a; color: #9be7b8; }

.chatcol { background: #0f1822; border-right: 1px solid #1d2a38; }
.chat { padding: 10px 12px; }

.bubble {
    padding: 8px 12px;
    border-radius: 14px;
    background: #1a2634;
    color: #e6edf5;
    font-size: 15px;
    border-left: 4px solid #4aa3ff;
}
.bubble.mine { background: #1f5f9e; color: #ffffff; border-left: none; }
.bubble.system {
    background: transparent; color: #6b7b8d; font-size: 12px;
    font-style: italic; border: none;
}
.bubble.c0 { border-left-color: #4aa3ff; }
.bubble.c1 { border-left-color: #ff9f43; }
.bubble.c2 { border-left-color: #6ee89a; }
.bubble.c3 { border-left-color: #ff6b9a; }
.bubble.c4 { border-left-color: #c49bff; }
.bubble.c5 { border-left-color: #ffd166; }
.sender { font-size: 12px; font-weight: 700; color: #9fb0c4; padding: 0 6px; }
.route { font-size: 11px; color: #6b7b8d; padding: 0 6px; }

.presets { background: #131d2a; border-top: 1px solid #22303f; padding: 8px; }
.preset {
    font-size: 14px; font-weight: 600; min-height: 44px;
    border-radius: 10px; background: #1f3350; color: #e6edf5; border: none;
    padding: 4px 8px;
}
.preset:hover { background: #28436a; }
.preset:disabled { background: #1a2430; color: #5c6b7d; }
.preset.private { background: #3a2a55; color: #e8d6ff; }
.preset.private:hover { background: #4a3870; }
.bubble.private { background: #3a2a55; color: #f3e8ff; border-left: 4px solid #c49bff; }
.bubble.mine.private { background: #5a3d8a; color: #ffffff; border-left: none; }
"""


def _sender_color_index(bd: str) -> int:
    # Not hash(): that is salted per process, and both screens must agree.
    return sum(bd.encode()) % len(PALETTE)


def _rgba(hex_color: str, alpha: float = 1.0) -> Gdk.RGBA:
    c = Gdk.RGBA()
    c.parse(hex_color)
    c.alpha = alpha
    return c


def load_presets(path: str | None) -> list[str]:
    try:
        with open(path or _PRESETS_FILE, encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        lines = []
    return lines or list(_DEFAULT_PRESETS)


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
                GLib.idle_add(self._on_state, False, "mesh daemon not reachable")
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
                GLib.idle_add(self._on_state, False, "mesh daemon disconnected")
                self._stop.wait(RECONNECT_DELAY_S)

    def command(self, cmd: str, **fields) -> bool:
        with self._lock:
            sock = self._sock
            if sock is None:
                return False
            req_id, self._next_id = self._next_id, self._next_id + 1
            try:
                sock.sendall(encode(dict(fields, cmd=cmd, id=req_id)))
            except OSError:
                return False
        return True


class TopologyView(Gtk.Widget):
    """The mesh as a live diagram, with messages drawn hop by hop."""

    def __init__(self):
        super().__init__()
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_size_request(480, 420)
        self._local = ""
        self._nodes: dict[str, dict] = {}
        self._edges: set[frozenset] = set()
        self._edge_born: dict[frozenset, float] = {}
        self._pos: dict[str, list[float]] = {}
        self._target: dict[str, tuple[float, float]] = {}
        self._pulses: list[dict] = []
        self._rings: list[tuple[str, float, str]] = []
        self._arrivals: list[tuple[float, object]] = []
        self._banner = ""
        self._revoked: set[str] = set()
        self._selected = ""
        self._on_select = None
        self._last_draw = 0.0
        click = Gtk.GestureClick.new()
        click.connect("pressed", self._on_pressed)
        self.add_controller(click)
        self.add_tick_callback(self._tick)

    # ---- state ----------------------------------------------------------

    def set_topology(self, local: str, nodes: list[dict]) -> None:
        self._local = local.upper()
        self._nodes = {
            str(n.get("bd", "")).upper(): {
                "name": str(n.get("name") or n.get("bd", "?")),
                "kind": str(n.get("kind") or "relay"),
                "relay": bool(n.get("relay")),
            }
            for n in nodes if n.get("bd")
        }
        edges = set()
        for n in nodes:
            a = str(n.get("bd", "")).upper()
            for b in n.get("peers", []):
                b = str(b).upper()
                if a != b and a in self._nodes and b in self._nodes:
                    edges.add(frozenset((a, b)))
        now = time.monotonic()
        for e in edges - self._edges:
            self._edge_born[e] = now
        self._edges = edges
        self._target = self._layout()
        for bd, xy in self._target.items():
            self._pos.setdefault(bd, list(xy))
        for bd in list(self._pos):
            if bd not in self._target:
                del self._pos[bd]
        self.queue_draw()

    def set_revoked(self, bds) -> None:
        self._revoked = {str(bd).upper() for bd in bds}
        self.queue_draw()

    def set_selected(self, bd: str) -> None:
        self._selected = str(bd).upper()
        self.queue_draw()

    def _on_pressed(self, _gesture, _n, x, y) -> None:
        w, h = float(self.get_width()), float(self.get_height())
        best, best_d = "", 46.0
        for bd in self._nodes:
            if bd == self._local or bd in self._revoked:
                continue
            px, py = self._xy(bd, w, h)
            d = math.hypot(px - x, py - y)
            if d < best_d:
                best, best_d = bd, d
        if best and self._on_select:
            self._on_select(best)

    def set_banner(self, text: str) -> None:
        self._banner = text
        self.queue_draw()

    def name_of(self, bd: str) -> str:
        node = self._nodes.get(str(bd).upper())
        return node["name"] if node else str(bd)

    def link_count(self) -> int:
        return len(self._edges)

    def _layout(self) -> dict[str, tuple[float, float]]:
        # Screens on the outside, relays in between: the story told at the
        # stand is "this screen talks to that one through those boxes".
        screens = sorted(
            (bd for bd, n in self._nodes.items() if n["kind"] == "screen" and bd != self._local),
            key=lambda bd: self._nodes[bd]["name"],
        )
        if self._local in self._nodes:
            screens.insert(0, self._local)
        relays = sorted(
            (bd for bd in self._nodes if bd not in screens),
            key=lambda bd: self._nodes[bd]["name"],
        )
        pos: dict[str, tuple[float, float]] = {}
        for column, x in ((screens[0::2], 0.1), (screens[1::2], 0.9)):
            for i, bd in enumerate(column):
                pos[bd] = (x, (i + 1) / (len(column) + 1))
        n = len(relays)
        for i, bd in enumerate(relays):
            y = 0.5 if n == 1 else 0.12 + 0.76 * i / (n - 1)
            x = 0.5 if n < 3 else 0.5 + (0.1 if i % 2 else -0.1)
            pos[bd] = (x, y)
        return pos

    # ---- messages -------------------------------------------------------

    def animate(self, src: str, via: str = "", on_arrival=None) -> None:
        """
        Draw ``src``'s message flooding the mesh, the way the forwarder floods
        it: a board passes it on if it relays or bridges two links.

        The last hop into this screen is the one the daemon actually saw it
        arrive on (``via``); ``on_arrival`` runs when the pulse gets here.
        """
        src, via = src.upper(), via.upper()
        adj: dict[str, set[str]] = {}
        for e in self._edges:
            a, b = tuple(e)
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
        color = PALETTE[_sender_color_index(src)]
        now = time.monotonic()
        local = self._local

        reached = {src: now}
        queue = deque([src])
        if src in adj:
            self._rings.append((src, now, color))
        while queue:
            u = queue.popleft()
            node = self._nodes.get(u, {})
            forwards = u in (src, via) or node.get("relay") or len(adj.get(u, ())) >= 2
            if not forwards:
                continue
            for v in sorted(adj.get(u, ())):
                if v in reached:
                    continue
                if v == local and via and via != u and via in adj.get(local, ()):
                    continue
                reached[v] = reached[u] + HOP_S
                self._pulses.append({"a": u, "b": v, "t0": reached[u], "color": color})
                self._rings.append((v, reached[v], color))
                queue.append(v)

        if on_arrival is not None:
            when = reached.get(local, now) if src != local else now
            self._arrivals.append((when, on_arrival))
        self.queue_draw()

    # ---- animation ------------------------------------------------------

    def _tick(self, _widget, _clock) -> bool:
        now = time.monotonic()
        due = [a for a in self._arrivals if a[0] <= now]
        if due:
            self._arrivals = [a for a in self._arrivals if a[0] > now]
            for _, fn in due:
                fn()
        moving = False
        for bd, (tx, ty) in self._target.items():
            p = self._pos.get(bd)
            if p and (abs(p[0] - tx) > 1e-3 or abs(p[1] - ty) > 1e-3):
                p[0] += (tx - p[0]) * 0.12
                p[1] += (ty - p[1]) * 0.12
                moving = True
        self._pulses = [p for p in self._pulses if now - p["t0"] < HOP_S]
        self._rings = [r for r in self._rings if now - r[1] < 1.0]
        busy = moving or self._pulses or self._rings or any(
            now - t < 1.0 for t in self._edge_born.values())
        # Idle, the only motion is the slow "you are here" halo: 10 fps is plenty,
        # and rubik-inria renders in software.
        if busy or now - self._last_draw > 0.1:
            self._last_draw = now
            self.queue_draw()
        return GLib.SOURCE_CONTINUE

    # ---- drawing --------------------------------------------------------

    def _xy(self, bd: str, w: float, h: float) -> tuple[float, float]:
        x, y = self._pos.get(bd, (0.5, 0.5))
        top, bottom, side = 78.0, 58.0, 48.0
        return side + x * (w - 2 * side), top + y * (h - top - bottom)

    def _text(self, snapshot, text, font, color, x, y, *, center=False, width=0):
        layout = self.create_pango_layout(text)
        layout.set_font_description(Pango.FontDescription.from_string(font))
        if width:
            layout.set_width(int(width * Pango.SCALE))
            layout.set_ellipsize(Pango.EllipsizeMode.END)
        tw, th = layout.get_pixel_size()
        snapshot.save()
        snapshot.translate(Graphene.Point().init(x - (tw / 2 if center else 0), y))
        snapshot.append_layout(layout, color)
        snapshot.restore()
        return th

    @staticmethod
    def _circle(snapshot, x, y, r, color) -> None:
        b = Gsk.PathBuilder.new()
        b.add_circle(Graphene.Point().init(x, y), r)
        snapshot.append_fill(b.to_path(), Gsk.FillRule.WINDING, color)

    @staticmethod
    def _ring(snapshot, x, y, r, width, color) -> None:
        b = Gsk.PathBuilder.new()
        b.add_circle(Graphene.Point().init(x, y), r)
        snapshot.append_stroke(b.to_path(), Gsk.Stroke.new(width), color)

    @staticmethod
    def _line(snapshot, x1, y1, x2, y2, width, color) -> None:
        b = Gsk.PathBuilder.new()
        b.move_to(x1, y1)
        b.line_to(x2, y2)
        stroke = Gsk.Stroke.new(width)
        stroke.set_line_cap(Gsk.LineCap.ROUND)
        snapshot.append_stroke(b.to_path(), stroke, color)

    @staticmethod
    def _rounded(snapshot, x, y, w, h, radius, color) -> None:
        rr = Gsk.RoundedRect()
        rr.init_from_rect(Graphene.Rect().init(x, y, w, h), radius)
        b = Gsk.PathBuilder.new()
        b.add_rounded_rect(rr)
        snapshot.append_fill(b.to_path(), Gsk.FillRule.WINDING, color)

    def do_snapshot(self, snapshot) -> None:
        w, h = float(self.get_width()), float(self.get_height())
        now = time.monotonic()

        self._text(snapshot, "Live mesh", "Sans Bold 17", _rgba("#e6edf5"), 22, 14)
        self._text(snapshot, "Bluetooth LE only · no Wi-Fi · no cellular · no Internet",
                   "Sans 11", _rgba("#6b7b8d"), 22, 40)

        if not self._nodes:
            self._text(snapshot, self._banner or "Waiting for the mesh…", "Sans 15",
                       _rgba("#6b7b8d"), w / 2, h / 2 - 10, center=True)
            return

        # links
        for e in self._edges:
            a, b = tuple(e)
            (x1, y1), (x2, y2) = self._xy(a, w, h), self._xy(b, w, h)
            fade = min(1.0, (now - self._edge_born.get(e, 0.0)) / 0.8)
            self._line(snapshot, x1, y1, x2, y2, 10.0, _rgba("#4aa3ff", 0.07 * fade))
            self._line(snapshot, x1, y1, x2, y2, 3.0, _rgba("#4aa3ff", 0.45 * fade))

        # messages in flight
        for p in self._pulses:
            t = (now - p["t0"]) / HOP_S
            if t < 0.0:
                continue
            t = 0.5 - math.cos(math.pi * t) / 2  # ease in and out
            (x1, y1), (x2, y2) = self._xy(p["a"], w, h), self._xy(p["b"], w, h)
            x, y = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
            self._line(snapshot, x1, y1, x, y, 4.0, _rgba(p["color"], 0.85))
            self._circle(snapshot, x, y, 15.0, _rgba(p["color"], 0.15))
            self._circle(snapshot, x, y, 9.0, _rgba(p["color"], 0.35))
            self._circle(snapshot, x, y, 5.0, _rgba("#ffffff"))

        for bd, t0, color in self._rings:
            t = now - t0
            if 0.0 <= t < 1.0 and bd in self._pos:
                x, y = self._xy(bd, w, h)
                self._ring(snapshot, x, y, 30.0 + 34.0 * t, 3.0, _rgba(color, 0.8 * (1.0 - t)))

        # boards
        for bd, node in self._nodes.items():
            x, y = self._xy(bd, w, h)
            local = bd == self._local
            revoked = bd in self._revoked
            if bd == self._selected:
                self._ring(snapshot, x, y, 40.0, 3.0, _rgba("#ffd166"))
            if revoked:
                self._ring(snapshot, x, y, 36.0, 3.0, _rgba("#ff5a5a"))
            if local:
                halo = 0.5 + 0.5 * math.sin(now * 2.0)
                self._ring(snapshot, x, y, 44.0 + 4.0 * halo, 2.0, _rgba("#4aa3ff", 0.25 + 0.3 * halo))
            if node["kind"] == "screen":
                self._rounded(snapshot, x - 34, y - 25, 68, 50, 10, _rgba("#1f6feb" if local else "#2b5d9e"))
                self._rounded(snapshot, x - 27, y - 18, 54, 32, 4, _rgba("#0b1a2e"))
                self._circle(snapshot, x, y + 20, 2.0, _rgba("#9fc8ff"))
            else:
                active = node["relay"]
                self._circle(snapshot, x, y, 26.0, _rgba("#1d7a46" if active else "#3a4756"))
                self._circle(snapshot, x, y, 17.0, _rgba("#0e2a1a" if active else "#222c37"))
                self._circle(snapshot, x, y, 6.0, _rgba("#6ee89a" if active else "#7d8da0"))
            label_y = y + 32
            self._text(snapshot, node["name"], "Sans Bold 12", _rgba("#e6edf5"), x, label_y,
                       center=True)
            if revoked:
                role = "revoked"
            elif local:
                role = "this screen"
            elif node["kind"] == "screen":
                role = "screen"
            else:
                role = "relay" if node["relay"] else "standby"
            self._text(snapshot, role, "Sans 10",
                       _rgba("#ff8a8a" if revoked else "#7d8da0"), x, label_y + 18, center=True)

        n, links = len(self._nodes), len(self._edges)
        self._text(snapshot, f"{n} device{'s' if n != 1 else ''} · {links} link{'s' if links != 1 else ''}",
                   "Sans 11", _rgba("#6b7b8d"), 22, h - 30)

        if self._banner:
            self._rounded(snapshot, 0, 0, w, h, 0, _rgba("#0b121b", 0.75))
            self._text(snapshot, self._banner, "Sans Bold 18", _rgba("#ffd166"), w / 2, h / 2 - 12,
                       center=True)


class ChatWindow(Gtk.ApplicationWindow):
    def __init__(self, app, sock_path: str, kiosk: bool, admin: bool, presets: list[str]):
        super().__init__(application=app, title="Bubble Blue")
        self.set_default_size(1024, 600)
        if kiosk:
            self.fullscreen()
            self.set_cursor(Gdk.Cursor.new_from_name("none", None))

        self._local = ""
        self._name = ""
        self._seen_history = False
        self._connected = False
        self._cooling = False
        self._restart_armed = 0
        self._revoke_armed = 0
        self._reset_armed = 0
        self._selected = ""
        self._revoked: set[str] = set()
        self._excluded = False
        self._restarting_until = 0.0
        self._awaiting_reconnect = False
        self._desktop_armed = 0
        self._preset_templates = presets
        self._preset_buttons: list[Gtk.Button] = []
        self._private_btn: Gtk.Button | None = None
        self._private_label: Gtk.Label | None = None

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(root)
        root.append(self._build_statusbar(admin, kiosk))

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        body.set_vexpand(True)
        root.append(body)

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        left.add_css_class("chatcol")
        left.set_size_request(430, -1)
        left.set_hexpand(False)
        left.append(self._build_chat())
        left.append(self._build_presets())
        body.append(left)

        self._topology = TopologyView()
        if admin:
            self._topology._on_select = self._on_node_selected
        body.append(self._topology)

        self.client = MeshClient(sock_path, self._on_event, self._on_state)
        self.client.start()

    # ---- widgets --------------------------------------------------------

    def _build_statusbar(self, admin: bool, kiosk: bool) -> Gtk.Widget:
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.add_css_class("statusbar")

        brand = Gtk.Label(label="Bubble Blue")
        brand.add_css_class("brand")
        bar.append(brand)

        self._identity = Gtk.Label(label="—")
        self._identity.add_css_class("identity")
        bar.append(self._identity)

        self._address = Gtk.Label(label="")
        self._address.add_css_class("address")
        bar.append(self._address)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        bar.append(spacer)

        self._peers_badge = Gtk.Label(label="0 neighbours")
        self._peers_badge.add_css_class("badge")
        bar.append(self._peers_badge)

        self._relay_badge = Gtk.Label(label="LEAF")
        self._relay_badge.add_css_class("badge")
        bar.append(self._relay_badge)

        self._link_badge = Gtk.Label(label="offline")
        self._link_badge.add_css_class("badge")
        self._link_badge.add_css_class("offline")
        bar.append(self._link_badge)

        if admin:
            self._revoke_btn = Gtk.Button(label="Revoke")
            self._revoke_btn.add_css_class("restart")
            self._revoke_btn.add_css_class("revoke")
            self._revoke_btn.set_sensitive(False)
            self._revoke_btn.connect("clicked", self._on_revoke_clicked)
            bar.append(self._revoke_btn)

            self._reset_btn = Gtk.Button(label="Reset demo")
            self._reset_btn.add_css_class("restart")
            self._reset_btn.add_css_class("reset")
            self._reset_btn.connect("clicked", self._on_reset_clicked)
            bar.append(self._reset_btn)

            self._restart_btn = Gtk.Button(label="Restart mesh")
            self._restart_btn.add_css_class("restart")
            self._restart_btn.connect("clicked", self._on_restart_clicked)
            bar.append(self._restart_btn)

        if kiosk:
            self._desktop_btn = Gtk.Button(label="Desktop")
            self._desktop_btn.add_css_class("restart")
            self._desktop_btn.add_css_class("desktop")
            self._desktop_btn.connect("clicked", self._on_desktop_clicked)
            bar.append(self._desktop_btn)
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

    def _build_presets(self) -> Gtk.Widget:
        grid = Gtk.Grid(column_spacing=8, row_spacing=8)
        grid.add_css_class("presets")
        grid.set_column_homogeneous(True)
        for i, template in enumerate(self._preset_templates):
            btn = Gtk.Button()
            label = Gtk.Label(label=template)
            label.set_wrap(True)
            label.set_justify(Gtk.Justification.CENTER)
            label.set_max_width_chars(18)
            btn.set_child(label)
            btn.add_css_class("preset")
            btn.set_sensitive(False)
            btn.connect("clicked", lambda _b, t=template: self._send_preset(t))
            grid.attach(btn, i % 2, i // 2, 1, 1)
            self._preset_buttons.append(btn)
        rows = (len(self._preset_templates) + 1) // 2
        self._private_btn = Gtk.Button()
        self._private_label = Gtk.Label(label="Private 1-to-1")
        self._private_label.set_wrap(True)
        self._private_label.set_justify(Gtk.Justification.CENTER)
        self._private_label.set_max_width_chars(28)
        self._private_btn.set_child(self._private_label)
        self._private_btn.add_css_class("preset")
        self._private_btn.add_css_class("private")
        self._private_btn.set_sensitive(False)
        self._private_btn.connect("clicked", lambda _b: self._send_private())
        grid.attach(self._private_btn, 0, rows, 2, 1)
        return grid

    def _private_peer(self) -> tuple[str, str] | None:
        return _PRIVATE_PAIR.get(self._local.upper()) if self._local else None

    def _refresh_presets(self) -> None:
        ready = self._connected and not self._cooling and not self._excluded
        for btn, template in zip(self._preset_buttons, self._preset_templates):
            btn.get_child().set_label(self._fill(template))
            btn.set_sensitive(ready)
        peer = self._private_peer()
        if self._private_btn is not None and self._private_label is not None:
            if peer:
                self._private_label.set_label(f"Private 1-to-1 → {peer[1]}")
                self._private_btn.set_sensitive(ready)
                self._private_btn.set_visible(True)
            else:
                self._private_btn.set_sensitive(False)
                self._private_btn.set_visible(False)

    def _fill(self, template: str) -> str:
        return template.replace("{name}", self._name or "this screen")

    # ---- sending --------------------------------------------------------

    def _send_preset(self, template: str) -> None:
        if self._cooling:
            return
        if not self.client.command("send", text=self._fill(template)):
            self._add_system("not sent — mesh daemon unreachable")
            return
        self._begin_cooldown()

    def _send_private(self) -> None:
        if self._cooling:
            return
        peer = self._private_peer()
        if peer is None:
            return
        dest, name = peer
        text = self._fill(_PRIVATE_TEXT)
        if not self.client.command("send", text=text, to=dest):
            self._add_system("not sent — mesh daemon unreachable")
            return
        self._begin_cooldown()

    def _begin_cooldown(self) -> None:
        self._cooling = True
        self._refresh_presets()
        GLib.timeout_add(int(SEND_COOLDOWN_S * 1000), self._end_cooldown)

    def _end_cooldown(self) -> bool:
        self._cooling = False
        self._refresh_presets()
        return False

    def _on_restart_clicked(self, _btn) -> None:
        # Two taps: the stand is crowded and a restart costs a minute of demo.
        if not self._restart_armed:
            self._restart_armed = GLib.timeout_add(
                int(RESTART_CONFIRM_S * 1000), self._on_restart_timeout)
            self._restart_btn.set_label("Tap again to restart")
            self._restart_btn.add_css_class("confirm")
            return
        GLib.source_remove(self._restart_armed)
        self._disarm_restart()
        if not self.client.command("restart_mesh"):
            self._add_system("restart not sent — mesh daemon unreachable")

    def _on_restart_timeout(self) -> bool:
        self._disarm_restart()
        return False

    def _disarm_restart(self) -> None:
        self._restart_armed = 0
        self._restart_btn.set_label("Restart mesh")
        self._restart_btn.remove_css_class("confirm")

    def _on_desktop_clicked(self, _btn) -> None:
        # Two taps: leaving the kiosk drops the demo until the next boot.
        if not self._desktop_armed:
            self._desktop_armed = GLib.timeout_add(
                int(DESKTOP_CONFIRM_S * 1000), self._on_desktop_timeout)
            self._desktop_btn.set_label("Tap again to leave")
            self._desktop_btn.add_css_class("confirm")
            return
        GLib.source_remove(self._desktop_armed)
        self._desktop_armed = 0
        self._desktop_btn.set_label("Desktop")
        self._desktop_btn.remove_css_class("confirm")
        self._leave_to_desktop()

    def _on_desktop_timeout(self) -> bool:
        self._desktop_armed = 0
        self._desktop_btn.set_label("Desktop")
        self._desktop_btn.remove_css_class("confirm")
        return False

    def _leave_to_desktop(self) -> None:
        script = os.path.join(_ROOT, "scripts", "leave_kiosk.sh")
        try:
            proc = subprocess.run(
                ["systemd-run", "--collect", script],
                capture_output=True, text=True, timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._add_system(f"could not open the desktop: {exc}")
            return
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "systemd-run failed").strip().splitlines()
            self._add_system("could not open the desktop: " + (detail[-1] if detail else "systemd-run failed"))

    def _on_node_selected(self, bd: str) -> None:
        self._selected = bd
        self._topology.set_selected(bd)
        self._revoke_armed = 0
        name = self._topology.name_of(bd)
        self._revoke_btn.set_label(f"Revoke {name}")
        self._revoke_btn.set_sensitive(True)
        self._revoke_btn.remove_css_class("confirm")

    def _on_revoke_clicked(self, _btn) -> None:
        if not self._selected:
            return
        if not self._revoke_armed:
            self._revoke_armed = GLib.timeout_add(
                int(RESTART_CONFIRM_S * 1000), self._on_revoke_timeout)
            self._revoke_btn.set_label("Tap again to revoke")
            self._revoke_btn.add_css_class("confirm")
            return
        GLib.source_remove(self._revoke_armed)
        self._revoke_armed = 0
        target = self._selected
        self._revoke_btn.remove_css_class("confirm")
        if not self.client.command("revoke", bd=target):
            self._add_system("revoke not sent — mesh daemon unreachable")
            self._on_node_selected(target)

    def _on_revoke_timeout(self) -> bool:
        self._revoke_armed = 0
        if self._selected:
            self._on_node_selected(self._selected)
        else:
            self._revoke_btn.set_label("Revoke")
            self._revoke_btn.remove_css_class("confirm")
        return False

    def _on_reset_clicked(self, _btn) -> None:
        if not self._reset_armed:
            self._reset_armed = GLib.timeout_add(
                int(RESTART_CONFIRM_S * 1000), self._on_reset_timeout)
            self._reset_btn.set_label("Tap again to reset")
            self._reset_btn.add_css_class("confirm")
            return
        GLib.source_remove(self._reset_armed)
        self._reset_armed = 0
        self._reset_btn.set_label("Reset demo")
        self._reset_btn.remove_css_class("confirm")
        if not self.client.command("reset_demo"):
            self._add_system("reset not sent — mesh daemon unreachable")

    def _on_reset_timeout(self) -> bool:
        self._reset_armed = 0
        self._reset_btn.set_label("Reset demo")
        self._reset_btn.remove_css_class("confirm")
        return False

    def _clear_chat(self) -> None:
        child = self._messages.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._messages.remove(child)
            child = nxt

    def _apply_revoked(self, bds, excluded: bool) -> None:
        self._revoked = {str(bd).upper() for bd in bds}
        self._excluded = excluded
        self._topology.set_revoked(self._revoked)
        if self._selected in self._revoked:
            self._selected = ""
            self._topology.set_selected("")
            if hasattr(self, "_revoke_btn"):
                self._revoke_btn.set_label("Revoke")
                self._revoke_btn.set_sensitive(False)
        self._refresh_presets()
        if excluded:
            self._topology.set_banner("Excluded from the group")
        elif not self._restarting_until:
            self._topology.set_banner("")

    # ---- chat -----------------------------------------------------------

    def _add_message(self, frame: dict) -> None:
        mine = bool(frame.get("mine"))
        sender = str(frame.get("from", "?"))
        name = frame.get("name") or self._topology.name_of(sender)
        ts = float(frame.get("ts", 0))
        align = Gtk.Align.END if mine else Gtk.Align.START

        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        column.set_halign(align)

        clock = time.strftime("%H:%M", time.localtime(ts)) if ts else ""
        sender_u = sender.upper()
        private = bool(frame.get("private") or frame.get("to"))
        dest_name = frame.get("to_name") or self._topology.name_of(str(frame.get("to", "")))
        peer = self._private_peer()
        if (
            not private
            and not mine
            and peer
            and sender_u == peer[0]
            and str(frame.get("text", "")).startswith("Private 1-to-1")
        ):
            private = True
            dest_name = self._name or "You"
        if private:
            who = f"You → {dest_name}" if mine else f"{name} → You"
            head_text = f"Private · {who}  {clock}".rstrip()
        else:
            head_text = f"{'You' if mine else name}  {clock}"
        head = Gtk.Label(label=head_text)
        head.add_css_class("sender")
        head.set_halign(align)
        column.append(head)

        bubble = Gtk.Label(label=str(frame.get("text", "")))
        bubble.add_css_class("bubble")
        bubble.add_css_class("mine" if mine else f"c{_sender_color_index(sender.upper())}")
        if private:
            bubble.add_css_class("private")
        bubble.set_wrap(True)
        bubble.set_max_width_chars(34)
        bubble.set_xalign(0.0)
        bubble.set_halign(align)
        column.append(bubble)

        hops = int(frame.get("hops") or 0)
        if not mine and hops:
            via = frame.get("via_name") or self._topology.name_of(frame.get("via", ""))
            route = "direct link" if hops == 1 else f"{hops} hops · last one via {via}"
            meta = Gtk.Label(label=route)
            meta.add_css_class("route")
            meta.set_halign(align)
            column.append(meta)

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
        was = self._connected
        self._connected = connected
        if connected and not was:
            self._awaiting_reconnect = False
        self._link_badge.set_label("online" if connected else "offline")
        self._link_badge.remove_css_class("online" if not connected else "offline")
        self._link_badge.add_css_class("online" if connected else "offline")
        self._refresh_presets()
        # While the mesh restarts the daemon is expected to vanish: say so once.
        if not connected and was and reason and time.monotonic() > self._restarting_until:
            self._add_system(reason)
        return False

    def _set_identity(self, local: str) -> None:
        if local and local != self._local:
            self._local = local
            self._address.set_label(local)
            self._refresh_presets()

    def _set_name(self, name: str) -> None:
        if name and name != self._name:
            self._name = name
            self._identity.set_label(name)
            self._refresh_presets()

    def _on_event(self, frame: dict) -> bool:
        ev = frame.get("ev")
        if ev == "hello":
            self._set_identity(frame.get("local", ""))
            self._update_peers(frame.get("peers", []), frame.get("relay", False))
            if not self._seen_history:
                self._seen_history = True
                for msg in frame.get("history", []):
                    self._add_message(msg)
            if hasattr(self, "_revoke_btn"):
                self._apply_revoked(frame.get("revoked", []), bool(frame.get("excluded")))
        elif ev == "topology":
            local = str(frame.get("local", ""))
            self._set_identity(local)
            self._topology.set_topology(local, frame.get("nodes", []))
            self._set_name(self._topology.name_of(local) if local else "")
            # The old daemon keeps publishing during its grace period, so only a
            # link seen after reconnecting to the new one means it is back.
            back = not self._awaiting_reconnect and self._topology.link_count()
            if self._restarting_until and (back or time.monotonic() > self._restarting_until):
                self._restarting_until = 0.0
                self._topology.set_banner("")
                self._add_system("mesh is back")
        elif ev == "message":
            if frame.get("mine"):
                self._add_message(frame)
                self._topology.animate(self._local)
            else:
                self._topology.animate(
                    str(frame.get("from", "")),
                    str(frame.get("via", "")),
                    on_arrival=lambda f=frame: self._add_message(f),
                )
        elif ev == "peers":
            # Carries the address too: connecting while the daemon is still
            # starting yields a hello with none.
            self._set_identity(frame.get("local", ""))
            self._update_peers(frame.get("peers", []), frame.get("relay", False))
        elif ev == "revoked":
            self._revoked.add(str(frame.get("bd", "")).upper())
            self._apply_revoked(self._revoked, self._excluded or bool(frame.get("self")))
            if frame.get("self"):
                self._add_system("this screen is excluded — it can no longer read the group")
            else:
                self._add_system(f"{frame.get('name', 'a board')} revoked")
        elif ev == "demo_reset":
            self._clear_chat()
            self._seen_history = True
            self._apply_revoked([], False)
            self._add_system("demo reset — everyone is back in the group")
        elif ev == "restarting":
            self._restarting_until = time.monotonic() + 120.0
            self._awaiting_reconnect = True
            self._add_system("restarting the whole mesh — back in about a minute")
            self._topology.set_banner("Restarting the mesh…")
        elif ev == "ack" and not frame.get("ok", True):
            self._add_system(f"not sent: {frame.get('error', 'unknown error')}")
        return False

    def _update_peers(self, peers: list, relay: bool) -> None:
        count = len(peers)
        self._peers_badge.set_label(f"{count} neighbour{'s' if count != 1 else ''}")
        self._relay_badge.set_label("RELAY" if relay else "LEAF")
        if relay:
            self._relay_badge.add_css_class("relay")
        else:
            self._relay_badge.remove_css_class("relay")


class ScreenApp(Gtk.Application):
    def __init__(self, sock_path: str, kiosk: bool, admin: bool, presets: list[str]):
        super().__init__(application_id="fr.inria.bubbleblue.Screen")
        self._args = (sock_path, kiosk, admin, presets)
        self._window: ChatWindow | None = None

    def do_activate(self):
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        if self._window is None:
            self._window = ChatWindow(self, *self._args)
        self._window.present()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default=socket_path())
    ap.add_argument("--kiosk", action="store_true", help="fullscreen, no cursor")
    ap.add_argument("--admin", action="store_true", help="show the mesh restart button")
    ap.add_argument("--presets", default=None, help=f"one message per line (default {_PRESETS_FILE})")
    args = ap.parse_args()

    # Launched over SSH with no panel attached this would otherwise die deep
    # inside GTK on a null display, which says nothing useful.
    # init_check() alone still reports success with no panel attached, so the
    # display itself is what has to be checked.
    if not Gtk.init_check() or Gdk.Display.get_default() is None:
        print(
            "aucun affichage disponible.\n"
            "  - sur un bureau : lancer depuis la session graphique\n"
            "  - sur une board dédiée : cage -- python3 apps/screen_ui.py --kiosk\n"
            "  - sans écran du tout : python3 scripts/meshd_client.py",
            file=sys.stderr,
        )
        return 1
    return ScreenApp(args.socket, args.kiosk, args.admin, load_presets(args.presets)).run([])


if __name__ == "__main__":
    raise SystemExit(main())
