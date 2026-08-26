#!/usr/bin/env python3
"""
Multi-board soak probe: link stability + chat delivery in one run.

Run the same command on every board (root required for L2CAP + MGMT):

    sudo python3.14 scripts/bb_probe.py --duration 300 --send-every 20

Each board dials the open mesh, beacons a chat message on a fixed period and
records every peer connect/disconnect. The JSON summary on stdout is meant to
be diffed across boards: ``flaps`` should stay near zero and every board should
appear in another board's ``senders``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.api.bb_api import BBNode  # noqa: E402

# Links formed during this window are still the mesh converging, not flapping.
WARMUP_S = 25.0


class Probe:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.events: list[tuple[float, str, str]] = []
        self.received: list[tuple[float, str, str]] = []
        self.sent = 0
        self.peak_peers = 0

    def _t(self) -> float:
        return round(time.monotonic() - self.started, 1)

    def on_connect(self, bd: str) -> None:
        with self.lock:
            self.events.append((self._t(), "up", bd))
        print(f"[{self._t():7.1f}] + {bd}", flush=True)

    def on_disconnect(self, bd: str) -> None:
        with self.lock:
            self.events.append((self._t(), "down", bd))
        print(f"[{self._t():7.1f}] - {bd}", flush=True)

    def on_message(self, sender: str, text: str) -> None:
        with self.lock:
            self.received.append((self._t(), sender, text))
        print(f"[{self._t():7.1f}] RX {sender}: {text}", flush=True)

    def summary(self, node: BBNode) -> dict:
        with self.lock:
            # A flap is a link that dropped after the mesh had time to settle.
            flaps = [e for e in self.events if e[1] == "down" and e[0] > WARMUP_S]
            peers_seen = sorted({e[2] for e in self.events})
            senders = sorted({s for _t, s, _txt in self.received})
            return {
                "tag": self.tag,
                "local": node.local_bd_addr,
                "duration_s": self._t(),
                "peers_seen": peers_seen,
                "peers_final": sorted(node.peers()),
                "peak_peers": self.peak_peers,
                "is_relay": node.is_relay(),
                "links_up": sum(1 for e in self.events if e[1] == "up"),
                "links_down": sum(1 for e in self.events if e[1] == "down"),
                "flaps_after_warmup": len(flaps),
                "msgs_sent": self.sent,
                "msgs_received": len(self.received),
                "senders": senders,
            }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=float, default=300.0, help="run time (s)")
    ap.add_argument("--send-every", type=float, default=20.0, help="chat period (s)")
    ap.add_argument("--tag", default=os.uname().nodename, help="board label")
    ap.add_argument("--interface", default="hci0")
    ap.add_argument("--json-out", default="", help="also write summary to this file")
    args = ap.parse_args()

    probe = Probe(args.tag)
    node = BBNode(interface=args.interface, quiet=True)
    node.on_message = probe.on_message
    node.on_peer_connected = probe.on_connect
    node.on_peer_disconnected = probe.on_disconnect

    node.start(l2cap_accept_all=True)
    print(f"probe {args.tag} local={node.local_bd_addr} duration={args.duration}s", flush=True)

    deadline = time.monotonic() + args.duration
    next_send = time.monotonic() + args.send_every
    try:
        while time.monotonic() < deadline:
            time.sleep(1.0)
            probe.peak_peers = max(probe.peak_peers, len(node.peers()))
            if time.monotonic() >= next_send:
                next_send += args.send_every
                try:
                    node.send(f"{args.tag}#{probe.sent}")
                    probe.sent += 1
                except Exception as e:  # noqa: BLE001 — no peer yet is normal early on
                    print(f"[{probe._t():7.1f}] send skipped: {e}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        summary = probe.summary(node)
        node.stop()

    print("\n=== SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
