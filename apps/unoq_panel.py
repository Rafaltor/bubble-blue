#!/usr/bin/env python3
"""
Drives the UNO Q status panel from the mesh.

This is the Linux half of ``apps/unoq/panel/panel.ino``. It reads the mesh
through the meshd socket and pushes what to display over the Arduino Router
Bridge, then relays preset button taps back into the chat.

    python3 apps/unoq_panel.py --preset "OK|Bien recu" --preset "ARRIVE|J'arrive"

It runs unprivileged under the distribution Python — the router socket is
world-writable and only meshd needs root. That makes this the third process in
the same pattern as the GTK UI: meshd owns the radio, everything else is a
client that can be restarted without disturbing the links.

The MCU gets text that is already ASCII and already truncated, because the
built-in GFX font has no accents and the sketch has no RAM budget for string
juggling.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import unicodedata

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.protocol import encode, read_frames, socket_path  # noqa: E402

# Where scripts/install_unoq_bridge.sh drops the Router Bridge client. It is not
# a system package — it is lifted out of the App Lab image — so point at it here
# rather than asking every caller to export PYTHONPATH.
_PYLIB = os.environ.get("BB_PYLIB") or os.path.expanduser("~/.local/lib/bubble-blue")
if os.path.isdir(_PYLIB) and _PYLIB not in sys.path:
    sys.path.append(_PYLIB)

# Mirrors the layout constants in panel.ino. Truncating here rather than there
# keeps the two in step: the sketch draws whatever it is handed.
MSG_COLS, MSG_ROWS = 25, 3
MAX_TEXT = MSG_COLS * MSG_ROWS
MAX_LABEL = 13
MAX_ADDR = 19

# The sketch shows "LIEN LINUX PERDU" after 10 s of silence, so push well
# inside that even when nothing changes.
HEARTBEAT_S = 3.0


def to_ascii(text: str) -> str:
    """Fold text onto the ASCII the GFX font can actually draw."""
    folded = unicodedata.normalize("NFKD", text)
    out = folded.encode("ascii", "ignore").decode("ascii")
    return "".join(c if 32 <= ord(c) < 127 else " " for c in out)


def parse_preset(spec: str) -> tuple[str, str]:
    """``"LABEL|text"`` or plain ``"text"``, in which case the label is derived."""
    label, sep, text = spec.partition("|")
    if not sep:
        text = label
    text = text.strip()
    label = to_ascii(label.strip() if sep else text)[:MAX_LABEL].strip()
    if not text:
        raise ValueError(f"preset vide: {spec!r}")
    return label or text[:MAX_LABEL], text


class BridgeLink:
    """The real transport: Arduino Router Bridge to the sketch."""

    def __init__(self) -> None:
        from arduino.app_utils import Bridge  # noqa: PLC0415 — absent off-board

        self._bridge = Bridge

    def provide_preset(self, handler, health) -> None:
        self._bridge.provide("panel_preset", handler)
        self._bridge.provide("panel_health", health)
        self._bridge.provide("panel_touch_raw", lambda x, y: None)

    def tap(self, index: int) -> None:
        """Fire a preset as if the screen had been touched.

        Goes through the same RPC name the sketch uses, so it reaches whichever
        unoq_panel.py is running and sends that instance's preset text — no need
        to repeat --preset here, and no second source of truth.
        """
        self._bridge.notify("panel_preset", index)

    def push(self, method: str, *params) -> None:
        # Short timeout: a sketch that is flashing or rebooting must not stall
        # the pusher, and the next heartbeat will catch up anyway.
        self._bridge.call(method, *params, timeout=2)


class PanelBridge:
    """Holds the panel's view of the mesh and keeps the sketch in step."""

    def __init__(self, link, presets: list[tuple[str, str]], mesh_socket: str) -> None:
        self.link = link
        self.presets = presets
        self.mesh_socket = mesh_socket

        self.local = ""
        self.peers = 0
        self.relay = False
        self.epoch = 0
        self.msg_from = ""
        self.msg_text = ""

        self._lock = threading.Lock()
        self._dirty = threading.Event()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._req_id = 0
        self._last_error = ""

    # ---- mesh side -------------------------------------------------------

    def apply(self, frame: dict) -> None:
        """Fold one meshd frame into the panel state."""
        ev = frame.get("ev")
        with self._lock:
            if ev == "hello":
                self.local = str(frame.get("local", ""))
                self.peers = len(frame.get("peers") or [])
                self.relay = bool(frame.get("relay"))
                self.epoch = int(frame.get("epoch") or 0)
                history = frame.get("history") or []
                if history:
                    last = history[-1]
                    self.msg_from = str(last.get("from", ""))
                    self.msg_text = str(last.get("text", ""))
            elif ev == "peers":
                self.peers = len(frame.get("peers") or [])
                self.relay = bool(frame.get("relay"))
                # Also carries the address and epoch, which the hello may have
                # been too early to know.
                self.local = str(frame.get("local") or self.local)
                self.epoch = int(frame.get("epoch") or self.epoch)
            elif ev == "ack":
                if not frame.get("ok", True):
                    print(f"panel: envoi refuse ({frame.get('error', 'inconnu')})",
                          file=sys.stderr, flush=True)
                return
            elif ev == "message":
                self.msg_from = str(frame.get("from", ""))
                self.msg_text = str(frame.get("text", ""))
            else:
                return
        self._dirty.set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "local": to_ascii(self.local)[:MAX_ADDR],
                "peers": int(self.peers),
                "relay": bool(self.relay),
                "epoch": int(self.epoch),
                "msg_from": to_ascii(self.msg_from)[:MAX_ADDR],
                "msg_text": to_ascii(self.msg_text)[:MAX_TEXT],
            }

    def send_preset(self, index) -> None:
        """Called from the Bridge thread when a button is tapped."""
        try:
            idx = int(index)
        except (TypeError, ValueError):
            return
        if not 0 <= idx < len(self.presets):
            return
        label, text = self.presets[idx]
        # A tap is a deliberate act by whoever is standing at the board, so it
        # belongs in the log whether or not the mesh accepts it.
        print(f"panel: bouton {idx} ({label}) -> {text!r}", flush=True)
        self._send({"cmd": "send", "text": text, "id": self._next_id()})

    def _next_id(self) -> int:
        with self._send_lock:
            self._req_id += 1
            return self._req_id

    def _send(self, frame: dict) -> None:
        sock = self._sock
        if sock is None:
            return
        with self._send_lock:
            try:
                sock.sendall(encode(frame))
            except OSError:
                pass

    # ---- sketch side -----------------------------------------------------

    def push_all(self) -> bool:
        """Push the whole panel state. Returns False if the sketch is unreachable."""
        s = self.snapshot()
        try:
            self.link.push("panel_status", s["local"], s["peers"], s["relay"], s["epoch"])
            self.link.push("panel_message", s["msg_from"], s["msg_text"])
            self.link.push("panel_presets", *[p[0] for p in self.presets])
        except Exception as e:  # noqa: BLE001 — sketch may be rebooting
            text = f"{type(e).__name__}: {e}"
            if text != self._last_error:
                # Only on change: a detached sketch would otherwise fill the log
                # with one identical line every heartbeat.
                print(f"panel: sketch injoignable ({text})", file=sys.stderr, flush=True)
                self._last_error = text
            return False
        if self._last_error:
            print("panel: sketch de nouveau joignable", file=sys.stderr, flush=True)
            self._last_error = ""
        return True

    def _push_loop(self) -> None:
        while not self._stop.is_set():
            self._dirty.wait(timeout=HEARTBEAT_S)
            self._dirty.clear()
            self.push_all()

    # ---- lifecycle -------------------------------------------------------

    def on_health(self, touch_ok) -> None:
        """The sketch reporting whether its touch controller answered."""
        if touch_ok:
            print("panel: tactile operationnel", flush=True)
        else:
            print("panel: TACTILE HS — boutons inertes, utiliser --tap 0|1",
                  file=sys.stderr, flush=True)

    def run(self) -> int:
        self.link.provide_preset(self.send_preset, self.on_health)
        threading.Thread(target=self._push_loop, daemon=True).start()

        while not self._stop.is_set():
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.mesh_socket)
            except OSError as e:
                print(f"panel: meshd injoignable ({e}), nouvel essai dans 2 s",
                      file=sys.stderr, flush=True)
                time.sleep(2.0)
                continue

            self._sock = sock
            print(f"panel: connecte a {self.mesh_socket}", flush=True)
            for frame in read_frames(sock):
                self.apply(frame)
            self._sock = None
            sock.close()

            # meshd went away: blank the numbers rather than leave the panel
            # showing a mesh that may no longer exist.
            with self._lock:
                self.peers, self.relay = 0, False
            self._dirty.set()
            if not self._stop.is_set():
                print("panel: meshd deconnecte", file=sys.stderr, flush=True)
                time.sleep(2.0)
        return 0

    def stop(self) -> None:
        self._stop.set()
        self._dirty.set()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default=socket_path(), help="meshd AF_UNIX path")
    ap.add_argument(
        "--preset",
        action="append",
        default=[],
        metavar="[LABEL|]TEXTE",
        help="message pre-enregistre (deux fois; LABEL est ce qui s'affiche)",
    )
    ap.add_argument(
        "--tap",
        type=int,
        choices=(0, 1),
        help="declencher un bouton sans toucher l'ecran, puis quitter "
             "(demande un unoq_panel.py deja lance)",
    )
    args = ap.parse_args()

    if args.tap is not None:
        try:
            BridgeLink().tap(args.tap)
        except ImportError:
            print("panel: bibliotheque arduino absente — lancer "
                  "scripts/install_unoq_bridge.sh", file=sys.stderr)
            return 1
        return 0

    specs = args.preset or ["OK|Bien recu", "ARRIVE|J'arrive"]
    if len(specs) != 2:
        print("panel: il faut exactement deux --preset", file=sys.stderr)
        return 2
    try:
        presets = [parse_preset(s) for s in specs]
    except ValueError as e:
        print(f"panel: {e}", file=sys.stderr)
        return 2

    try:
        link = BridgeLink()
    except ImportError:
        print(
            "panel: bibliotheque arduino absente — lancer scripts/install_unoq_bridge.sh",
            file=sys.stderr,
        )
        return 1

    bridge = PanelBridge(link, presets, args.socket)
    try:
        return bridge.run()
    except KeyboardInterrupt:
        bridge.stop()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
