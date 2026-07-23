"""Temp multi-node stability harness (not committed).

Starts a BBNode (advertise + MGMT scan + full-mesh auto-connect), runs for a
duration, and prints a timestamped connect/disconnect timeline plus a summary
(total connects/disconnects, peak simultaneous peers). Used to diagnose churn
at scale across several boards."""

from __future__ import annotations

import socket
import sys
import time

from src.api.bb_api import BBNode

DURATION_S = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
HOST = socket.gethostname()
T0 = time.time()


def stamp() -> float:
    return round(time.time() - T0, 1)


def main() -> int:
    node = BBNode(interface="hci0", quiet=True, setup_pairing_agent=False)
    counts = {"conn": 0, "disc": 0}

    def on_conn(bd: str) -> None:
        counts["conn"] += 1
        print(f"{stamp()} CONNECT {bd} n={len(node.peers())}", flush=True)

    def on_disc(bd: str) -> None:
        counts["disc"] += 1
        print(f"{stamp()} DISCONNECT {bd} n={len(node.peers())}", flush=True)

    keys = ("expuls", "quarant", "error", "permission", "failed", "backoff", "candidat", "admis")

    def on_log(m: str, err: bool) -> None:
        low = m.lower()
        if any(k in low for k in keys):
            print(f"{stamp()} LOG {m}", flush=True)

    node.on_message = lambda s, t: None
    node.on_log = on_log
    node.on_peer_connected = on_conn
    node.on_peer_disconnected = on_disc

    node.start(None, l2cap_accept_all=True)
    print(f"0.0 START host={HOST} local={node.local_bd_addr}", flush=True)

    peak = 0
    while time.time() - T0 < DURATION_S:
        time.sleep(3)
        try:
            peers = sorted(node.peers())
        except Exception as exc:
            peers = [f"<err {exc}>"]
        peak = max(peak, len(peers))
        try:
            ntargets = len(node.connect_targets())
        except Exception:
            ntargets = -1
        print(f"{stamp()} TICK n={len(peers)} targets={ntargets} peers={peers}", flush=True)

    node.stop()
    print(
        f"{stamp()} SUMMARY host={HOST} connects={counts['conn']} "
        f"disconnects={counts['disc']} peak_peers={peak}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
