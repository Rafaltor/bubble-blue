#!/usr/bin/env python3
"""
A meshd that speaks the real protocol without touching Bluetooth.

Lets the screen app be developed and demoed on any machine — no adapter, no
root, no mesh convergence wait:

    python3 scripts/meshd_fake.py --socket /tmp/bb.sock
    python3 apps/screen_ui.py    --socket /tmp/bb.sock

It plays the demo stand: two Rubik screens bridged by three UNO Q relays.
Remote boards report their links and chat through the same control messages
the real daemons exchange, links drop and come back the way the UNO Q link
recycling makes them, and a restart order re-executes the fake like the real
daemon does.
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import sys
import threading
from collections import deque

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.mesh_control import decode_control, encode_control, load_node_names  # noqa: E402
from apps.meshd import MeshDaemon, reexec  # noqa: E402

_RUBIK_Q = "40:D9:5A:8B:69:3F"
_RUBIK_INRIA = "9C:B8:B4:9F:2D:75"
_UNO1 = "14:B5:CD:E2:12:4F"
_UNO2 = "14:B5:CD:E8:75:33"
_UNO3 = "14:B5:CD:EA:AB:B3"

_LINKS = {
    frozenset(p) for p in [
        (_RUBIK_Q, _UNO1), (_RUBIK_Q, _UNO2),
        (_RUBIK_INRIA, _UNO2), (_RUBIK_INRIA, _UNO3),
        (_UNO1, _UNO2), (_UNO2, _UNO3), (_UNO1, _UNO3),
    ]
}

_CHATTER = [
    "Hello from the other side of the stand!",
    "Olá NetMob!",
    "No Wi-Fi, no 4G, only Bluetooth relays",
    "Message received, loud and clear",
    "Meet us at the INRIA booth",
]


class FakeNode:
    """BBNode's surface, backed by a script instead of a radio."""

    def __init__(self, local: str) -> None:
        self.local_bd_addr = local
        self.on_message = None
        self.on_message_route = None
        self.on_log = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self._names = load_node_names()
        self._links = set(_LINKS)
        self._up: set[frozenset] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self, l2cap_accept_all: bool = True) -> None:
        threading.Thread(target=self._converge_then_churn, daemon=True).start()
        threading.Thread(target=self._report_loop, daemon=True).start()
        threading.Thread(target=self._chatter_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def send(self, text: str) -> None:
        if not self.peers():
            raise RuntimeError("no peer connected")
        if decode_control(text) is None and random.random() < 0.6:
            reply = random.choice(["Got it!", "Received on the other screen", "Obrigado!"])
            threading.Timer(2.5, self._deliver, args=(_RUBIK_INRIA, reply)).start()

    def peers(self) -> list[str]:
        with self._lock:
            return sorted(
                next(iter(link - {self.local_bd_addr}))
                for link in self._up if self.local_bd_addr in link
            )

    def is_relay(self) -> bool:
        return len(self.peers()) >= 2

    def current_epoch(self) -> int:
        return 1

    # ---- simulated mesh -------------------------------------------------

    def _neighbours(self, bd: str) -> list[str]:
        with self._lock:
            return sorted(next(iter(l - {bd})) for l in self._up if bd in l)

    def _route(self, src: str) -> tuple[str, int] | None:
        """(last hop into us, hop count) along a shortest path from ``src``."""
        parent, dist = {src: ""}, {src: 0}
        queue = deque([src])
        while queue:
            node = queue.popleft()
            for nxt in self._neighbours(node):
                if nxt not in parent:
                    parent[nxt], dist[nxt] = node, dist[node] + 1
                    queue.append(nxt)
        local = self.local_bd_addr
        return (parent[local], dist[local]) if local in parent and local != src else None

    def _deliver(self, src: str, text: str) -> None:
        route = self._route(src)
        if route is None or self._stop.is_set():
            return
        via, hops = route
        self.on_message_route(src, text, via, hops)

    def _set_link(self, link: frozenset, up: bool) -> None:
        with self._lock:
            (self._up.add if up else self._up.discard)(link)
        if self.local_bd_addr in link:
            peer = next(iter(link - {self.local_bd_addr}))
            cb = self.on_peer_connected if up else self.on_peer_disconnected
            if cb:
                cb(peer)

    def _converge_then_churn(self) -> None:
        # Links come up over the first ~20 s, like a real stand after boot.
        for link in random.sample(sorted(self._links, key=sorted), len(self._links)):
            if self._stop.wait(random.uniform(1.0, 3.5)):
                return
            self._set_link(link, True)
        # Then an UNO Q link recycles every so often: down a few seconds, back.
        while not self._stop.wait(random.uniform(20.0, 35.0)):
            link = random.choice([l for l in self._links if _UNO1 in l or _UNO3 in l])
            self._set_link(link, False)
            if self._stop.wait(random.uniform(3.0, 6.0)):
                return
            self._set_link(link, True)

    def _report_loop(self) -> None:
        while not self._stop.wait(random.uniform(3.0, 6.0)):
            for bd in (_RUBIK_INRIA, _UNO1, _UNO2, _UNO3):
                peers = self._neighbours(bd)
                kind, name = self._names.get(bd, ("relay", bd))
                report = encode_control(
                    "topo", peers=peers, relay=len(peers) >= 2, name=name, kind=kind)
                self._deliver(bd, report)

    def _chatter_loop(self) -> None:
        while not self._stop.wait(random.uniform(10.0, 18.0)):
            self._deliver(random.choice([_RUBIK_INRIA, _RUBIK_INRIA, _UNO2]),
                          random.choice(_CHATTER))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default="/tmp/bubble-blue-fake.sock")
    ap.add_argument("--local", default=_RUBIK_Q, help="fake local address")
    args = ap.parse_args()

    daemon = MeshDaemon("hci0", args.socket, node=FakeNode(args.local.upper()))
    signal.signal(signal.SIGINT, lambda *_: daemon.shutdown())
    signal.signal(signal.SIGTERM, lambda *_: daemon.shutdown())
    print(f"fake meshd on {args.socket} (local={args.local})", flush=True)
    rc = daemon.run(group=None, accept_all=True)
    if daemon.restart_requested:
        reexec(restart_bluez=False)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
