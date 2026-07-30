#!/usr/bin/env python3.14
"""Longer mesh harness: flags death-by-quarantine / empty dial / refused."""
from __future__ import annotations

import socket
import sys
import time

from src.api.bb_api import BBNode

DURATION_S = float(sys.argv[1]) if len(sys.argv) > 1 else 360.0
T0 = time.time()


def stamp() -> float:
    return round(time.time() - T0, 1)


def main() -> int:
    node = BBNode(interface="hci0", quiet=True)
    counts = {"conn": 0, "disc": 0}
    peak = 0
    zero_streak = 0

    def on_conn(bd: str) -> None:
        nonlocal peak, zero_streak
        counts["conn"] += 1
        zero_streak = 0
        n = len(node.peers())
        peak = max(peak, n)
        print(f"{stamp()} CONNECT {bd} n={n}", flush=True)

    def on_disc(bd: str) -> None:
        counts["disc"] += 1
        n = len(node.peers())
        print(f"{stamp()} DISCONNECT {bd} n={n}", flush=True)

    keys = (
        "expuls",
        "quarant",
        "failed",
        "backoff",
        "candidat",
        "admis",
        "connect ",
        "silence",
        "refused",
        "ARQ",
    )

    def on_log(m: str, err: bool) -> None:
        low = m.lower()
        if any(k in low for k in keys):
            print(f"{stamp()} LOG {m}", flush=True)

    node.on_message = lambda _s, _t: None
    node.on_log = on_log
    node.on_peer_connected = on_conn
    node.on_peer_disconnected = on_disc

    node.start(None, l2cap_accept_all=True)
    print(
        f"0.0 START host={socket.gethostname()} local={node.local_bd_addr}",
        flush=True,
    )
    end = time.time() + DURATION_S
    while time.time() < end:
        n = len(node.peers())
        peak = max(peak, n)
        if n == 0:
            zero_streak += 1
        else:
            zero_streak = 0
        if int(time.time() - T0) % 30 == 0:
            role = "RELAY" if node.is_relay() else "LEAF"
            print(
                f"{stamp()} SNAP role={role} n={n} zero_streak={zero_streak}s "
                f"peers={sorted(node.peers())}",
                flush=True,
            )
            time.sleep(1.0)
        time.sleep(1.0)

    role = "RELAY" if node.is_relay() else "LEAF"
    print(
        f"{stamp()} SUMMARY role={role} connects={counts['conn']} "
        f"disconnects={counts['disc']} peak={peak} final={len(node.peers())} "
        f"peers={sorted(node.peers())}",
        flush=True,
    )
    node.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
