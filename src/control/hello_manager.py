from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

from config import BubbleBlueConfig
from src.control.hello import build_hello, compute_anon_id, parse_hello_private, parse_hello_public
from src.control.neighbors import NeighborTable
from src.forwarding.cds import am_i_cds

if TYPE_CHECKING:
    from src.transport.l2cap import L2CAPTransport


def _fmt_anon_id(aid: bytes) -> str:
    return aid.hex()


class HelloManager:
    """
    Background Hello control-plane manager.

    - Sends periodic Hello packets to all connected L2CAP peers
    - Updates NeighborTable on received Hellos
    - Prints 1-hop / 2-hop tables every hello_interval_s
    """

    def __init__(self, cfg: BubbleBlueConfig, transport: L2CAPTransport, *, quiet: bool = False) -> None:
        self._cfg = cfg
        self._transport = transport
        self._quiet = quiet
        self._group_key = cfg.group_key
        self._local_bd = cfg.local_bd_addr.upper()
        self._interval_s = max(1, int(cfg.hello_interval_s))
        self._timeout_ms = int(cfg.neighbor_timeout_s) * 1000

        self.anon_id = compute_anon_id(self._group_key, self._local_bd)
        self.table = NeighborTable()
        self.table.resolve_member(
            self.anon_id,
            self._local_bd,
            time.time_ns() // 1_000_000,
        )

        self._seq = 0
        self._seq_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._is_cds = False
        self.refresh_cds_role(verbose=False)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="bb-hello-mgr", daemon=True)
        self._thread.start()
        if not self._quiet:
            print(
                f"[APP] HelloManager started (anon_id={self.anon_id.hex()}, interval={self._interval_s}s)",
                flush=True,
            )

    def stop(self) -> None:
        self._stop.set()

    @property
    def is_relay(self) -> bool:
        """True when this node should relay PKT_DATA (CDS RELAY role)."""
        return self._is_cds

    def l2cap_peer_anon_ids(self) -> frozenset[bytes]:
        """Anon_ids for active L2CAP peers (transport.connections() only)."""
        return self._l2cap_peer_anon_ids()

    def on_receive(self, peer_bd_addr: str, data: bytes) -> None:
        """Parse and ingest a received Hello packet (topology only — not L2CAP peers)."""
        _ = peer_bd_addr  # sender BD available for future link-local validation
        pub = parse_hello_public(data)
        priv = parse_hello_private(data, self._group_key)
        self.table.update_from_hello(pub, priv)
        # CDS uses transport.connections() only; table update must not change l2cap_peers.
        self.refresh_cds_role(verbose=not self._quiet)

    def get_resolved_members(self) -> list[dict[str, Any]]:
        """Group members with resolved anon_id → BD address mappings."""
        return self.table.get_resolved_members()

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def _l2cap_peer_anon_ids(self) -> frozenset[bytes]:
        """
        Anon_ids for nodes with an active L2CAP socket to this node.

        Only transport.connections() — never Hello-advertised neighbors.
        """
        return frozenset(
            compute_anon_id(self._group_key, bd_addr) for bd_addr in self._transport.connections()
        )

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        """Recompute RELAY/LEAF from current L2CAP peers and Hello tables."""
        self._is_cds = am_i_cds(self.anon_id, self.table, self._l2cap_peer_anon_ids())
        if verbose:
            if self._is_cds:
                print("[CDS] I am a relay node", flush=True)
            else:
                print("[CDS] I am a leaf node", flush=True)

    def _known_neighbor_bd_addrs(self) -> list[str]:
        """BD addresses with active L2CAP to us (advertised in our Hello)."""
        addrs: set[str] = {bd.upper() for bd in self._transport.connections()}
        if self._cfg.remote_bd_addr not in ("00:00:00:00:00:00", self._local_bd):
            addrs.add(self._cfg.remote_bd_addr.upper())
        addrs.discard(self._local_bd)
        return sorted(addrs)

    def _send_hellos(self) -> None:
        peers = list(self._transport.connections())
        if not peers:
            peers = [b for b in self._cfg.group_members if b != self._local_bd]
            if not peers and self._cfg.remote_bd_addr not in ("00:00:00:00:00:00",):
                peers = [self._cfg.remote_bd_addr.upper()]

        if not peers:
            return

        neighbors = self._known_neighbor_bd_addrs()
        seq = self._next_seq()
        pkt = build_hello(self._group_key, self._local_bd, seq, neighbors)

        for peer in peers:
            try:
                self._transport.send(peer, pkt)
            except OSError as e:
                if not self._quiet:
                    print(f"[APP] Hello send failed peer={peer}: {e}", flush=True)

    def print_neighbor_tables(self) -> None:
        if self._quiet:
            return
        """Print 1-hop / 2-hop / known member BD addresses."""
        one_hop = self.table.get_1hop()
        two_hop = self.table.get_2hop()

        anon_ids = [_fmt_anon_id(e["anon_id"]) for e in one_hop]
        two_fmt: dict[str, list[str]] = {
            _fmt_anon_id(relay): [_fmt_anon_id(t) for t in sorted(targets)]
            for relay, targets in sorted(two_hop.items(), key=lambda kv: kv[0])
        }

        resolved = self.get_resolved_members()
        resolved_fmt = [
            f"anon_id={_fmt_anon_id(m['anon_id'])} bd_addr={m['bd_addr']}"
            for m in resolved
        ]

        role = "RELAY" if self._is_cds else "LEAF"
        print(f"CDS role: {role}", flush=True)
        print(f"1-hop: [{', '.join(anon_ids)}]", flush=True)
        print(f"2-hop: {two_fmt}", flush=True)
        print(f"known members (resolved): [{', '.join(resolved_fmt)}]", flush=True)

    def _loop(self) -> None:
        # Send one Hello immediately, then on every interval.
        while not self._stop.is_set():
            self.table.expire(self._timeout_ms)
            self.refresh_cds_role(verbose=False)
            self._send_hellos()
            if not self._quiet:
                self.print_neighbor_tables()
            if self._stop.wait(self._interval_s):
                break
