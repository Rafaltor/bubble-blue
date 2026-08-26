#!/usr/bin/env python3
"""
A meshd that speaks the real protocol without touching Bluetooth.

Lets the screen app be developed and demoed on any machine — no adapter, no
root, no mesh convergence wait:

    python3 scripts/meshd_fake.py --socket /tmp/bb.sock
    python3 apps/screen_ui.py    --socket /tmp/bb.sock

Peers appear and drop on a timer and scripted chatter arrives, so the UI can be
checked against the states it will actually meet on the boards.
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.meshd import MeshDaemon  # noqa: E402

_PEERS = [
    "14:B5:CD:E8:75:33",
    "14:B5:CD:EA:AB:B3",
    "9C:B8:B4:9F:2D:75",
    "40:D9:5A:89:B6:2B",
]

_CHATTER = [
    "salut la bulle",
    "je suis en RELAY ici",
    "quelqu'un capte arduino3 ?",
    "test de portée depuis le couloir",
    "ok reçu 5/5",
    "je passe au bout du couloir, je perds un lien",
    "epoch 2 appliquée de mon côté",
    "message un peu plus long pour vérifier que le retour à la ligne "
    "se fait correctement dans la bulle",
]


class FakeNode:
    """BBNode's surface, backed by a script instead of a radio."""

    def __init__(self, local: str) -> None:
        self.local_bd_addr = local
        self.on_message = None
        self.on_log = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self._peers: list[str] = []
        self._relay = False
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self, l2cap_accept_all: bool = True) -> None:
        threading.Thread(target=self._churn, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def send(self, text: str) -> None:
        with self._lock:
            if not self._peers:
                raise RuntimeError("no peer connected")

    def peers(self) -> list[str]:
        with self._lock:
            return list(self._peers)

    def is_relay(self) -> bool:
        return self._relay

    def current_epoch(self) -> int:
        return 1

    def _churn(self) -> None:
        # Mirrors a real board: links come up over the first ~40 s, then the
        # mesh sits still and only chatter moves.
        for peer in _PEERS[:3]:
            if self._stop.wait(random.uniform(2.0, 5.0)):
                return
            with self._lock:
                self._peers.append(peer)
            self._relay = len(self._peers) >= 2
            if self.on_peer_connected:
                self.on_peer_connected(peer)

        while not self._stop.wait(random.uniform(6.0, 12.0)):
            if self.on_message:
                self.on_message(random.choice(self._peers), random.choice(_CHATTER))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default="/tmp/bubble-blue-fake.sock")
    ap.add_argument("--local", default="40:D9:5A:8B:69:3F", help="fake local address")
    args = ap.parse_args()

    daemon = MeshDaemon("hci0", args.socket, node=FakeNode(args.local))
    signal.signal(signal.SIGINT, lambda *_: daemon.shutdown())
    signal.signal(signal.SIGTERM, lambda *_: daemon.shutdown())
    print(f"fake meshd on {args.socket} (local={args.local})", flush=True)
    return daemon.run(group=None, accept_all=True)


if __name__ == "__main__":
    raise SystemExit(main())
