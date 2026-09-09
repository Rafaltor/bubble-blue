#!/usr/bin/env python3
"""
Per-board probe: convergence, link stability and chat delivery in one run.

Run the same command on every board (root required for L2CAP + MGMT), or let
``scripts/bb_bench.py`` do it over SSH and aggregate the results:

    sudo python3.14 scripts/bb_probe.py --duration 300 --send-every 20 --expect 6

Each board dials the open mesh, beacons a chat message on a fixed period, and
records every peer connect/disconnect plus a once-per-second sample of peer
count and CDS role. The JSON summary on stdout is meant to be diffed across
boards: ``flaps_after_warmup`` should stay near zero and every board should
appear in another board's ``senders``.

``--expect`` is what turns the soak into a benchmark: knowing how many boards
are taking part is the only way to say when the mesh is *converged* rather than
merely connected, so without it the convergence fields stay null and the rest
still works.

Two conventions matter when reading the numbers:

- **Warm-up.** Links formed in the first ``WARMUP_S`` are the mesh converging,
  not flapping. Stability metrics ignore that window; convergence metrics are
  measured *inside* it and so are deliberately not clipped by it.
- **Steady state.** Everything after warm-up. Reported separately because a
  mean peer count that includes the ramp-up says nothing about either.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from typing import NamedTuple

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.api.bb_api import BBNode  # noqa: E402

# Links formed during this window are still the mesh converging, not flapping.
WARMUP_S = 25.0


class Sample(NamedTuple):
    """One second of observation.

    ``wall`` is here so samples from different boards can be lined up: the
    boards run NTP and agree to within tens of milliseconds, which is ample
    against a departure delay measured in seconds.

    ``peers`` and ``presence`` are deliberately separate views. ``peers`` counts
    open L2CAP links, which die with the socket the moment a process stops.
    ``presence`` is the neighbour table, which only forgets a node after the
    configured number of missed Hellos — so it is the one that shows what
    BUBBLE_BLUE_HELLO_MISSES actually does.
    """

    t: float
    wall: float
    peers: int
    relay: bool
    presence: tuple[str, ...]


class Probe:
    def __init__(self, tag: str, expect_peers: int | None = None) -> None:
        self.tag = tag
        # How many *other* boards should be reachable. None when the caller did
        # not say, in which case convergence cannot be defined.
        self.expect_peers = expect_peers
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.events: list[tuple[float, str, str, float]] = []
        self.received: list[tuple[float, str, str]] = []
        # Once per second, kept raw so a run can be replotted — or correlated
        # against another board's run — without re-running six boards.
        self.samples: list[Sample] = []
        self.sent = 0
        self.peak_peers = 0

    def _t(self) -> float:
        return round(time.monotonic() - self.started, 1)

    def on_connect(self, bd: str) -> None:
        with self.lock:
            self.events.append((self._t(), "up", bd, time.time()))
        print(f"[{self._t():7.1f}] + {bd}", flush=True)

    def on_disconnect(self, bd: str) -> None:
        with self.lock:
            self.events.append((self._t(), "down", bd, time.time()))
        print(f"[{self._t():7.1f}] - {bd}", flush=True)

    def on_message(self, sender: str, text: str) -> None:
        with self.lock:
            self.received.append((self._t(), sender, text))
        print(f"[{self._t():7.1f}] RX {sender}: {text}", flush=True)

    def sample(self, node: BBNode) -> None:
        """One observation of links, presence and CDS role. Once per second."""
        n = len(node.peers())
        relay = node.is_relay()
        local = (node.local_bd_addr or "").upper()
        presence = tuple(
            sorted(a for a in node.resolved_member_addresses() if a != local)
        )
        with self.lock:
            self.samples.append(Sample(self._t(), time.time(), n, relay, presence))
            self.peak_peers = max(self.peak_peers, n)

    def _convergence(self) -> dict:
        """When the mesh became usable, and when it became complete.

        Both are measured from process start, so they include discovery and
        dialling — that is the number an operator actually waits through.
        """
        first = next((s.t for s in self.samples if s.peers >= 1), None)
        out: dict[str, object] = {
            "expect_peers": self.expect_peers,
            "time_to_first_peer_s": first,
            "time_to_full_mesh_s": None,
            "full_mesh_frac_steady": None,
        }
        if not self.expect_peers:
            return out

        want = self.expect_peers
        out["time_to_full_mesh_s"] = next(
            (s.t for s in self.samples if s.peers >= want), None
        )
        steady = [s for s in self.samples if s.t > WARMUP_S]
        if steady:
            full = sum(1 for s in steady if s.peers >= want)
            out["full_mesh_frac_steady"] = round(full / len(steady), 3)
        return out

    def _stability(self) -> dict:
        """Steady-state behaviour only: the ramp-up would flatter every figure."""
        steady = [s for s in self.samples if s.t > WARMUP_S]
        flaps = [e for e in self.events if e[1] == "down" and e[0] > WARMUP_S]
        span_s = max(self._t() - WARMUP_S, 0.0)

        out: dict[str, object] = {
            "flaps_after_warmup": len(flaps),
            "flap_rate_per_h": round(len(flaps) / span_s * 3600, 2) if span_s > 0 else None,
            "mean_peers_steady": None,
            "min_peers_steady": None,
            # A relay that keeps changing its mind is as costly as a flapping
            # link: every transition re-plumbs who forwards for whom.
            "relay_transitions": 0,
            "relay_frac_steady": None,
        }
        if not steady:
            return out

        counts = [s.peers for s in steady]
        roles = [s.relay for s in steady]
        out["mean_peers_steady"] = round(sum(counts) / len(counts), 2)
        out["min_peers_steady"] = min(counts)
        out["relay_transitions"] = sum(1 for a, b in zip(roles, roles[1:]) if a != b)
        out["relay_frac_steady"] = round(sum(roles) / len(roles), 3)
        return out

    def summary(self, node: BBNode) -> dict:
        with self.lock:
            peers_seen = sorted({e[2] for e in self.events})
            presence_final = self.samples[-1].presence if self.samples else ()
            senders = sorted({s for _t, s, _txt in self.received})
            out = {
                "tag": self.tag,
                "local": node.local_bd_addr,
                "duration_s": self._t(),
                "warmup_s": WARMUP_S,
                "peers_seen": peers_seen,
                "peers_final": sorted(node.peers()),
                "presence_final": list(presence_final),
                "peak_peers": self.peak_peers,
                "is_relay": node.is_relay(),
                "links_up": sum(1 for e in self.events if e[1] == "up"),
                "links_down": sum(1 for e in self.events if e[1] == "down"),
                "msgs_sent": self.sent,
                "msgs_received": len(self.received),
                "senders": senders,
            }
            out.update(self._convergence())
            out.update(self._stability())
            # Last, and raw: the aggregate reads the fields above, but a plot for
            # the paper needs the series, and a churn scenario needs to line
            # this board's timeline up against another's.
            out["samples"] = [
                [s.t, round(s.wall, 3), s.peers, int(s.relay), list(s.presence)]
                for s in self.samples
            ]
            out["events"] = [[t, kind, bd, round(wall, 3)] for t, kind, bd, wall in self.events]
            return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=float, default=300.0, help="run time (s)")
    ap.add_argument("--send-every", type=float, default=20.0, help="chat period (s)")
    ap.add_argument("--tag", default=os.uname().nodename, help="board label")
    ap.add_argument(
        "--expect",
        type=int,
        default=0,
        help="total boards in the run (this one included); enables convergence metrics",
    )
    ap.add_argument("--interface", default="hci0")
    ap.add_argument("--json-out", default="", help="also write summary to this file")
    args = ap.parse_args()

    expect_peers = max(0, args.expect - 1) or None
    probe = Probe(args.tag, expect_peers=expect_peers)
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
            probe.sample(node)
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
