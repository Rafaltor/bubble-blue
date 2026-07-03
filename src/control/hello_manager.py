from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from config import BubbleBlueConfig
from src.control.hello import build_hello, compute_anon_id, parse_hello_private, parse_hello_public
from src.control.neighbors import NeighborTable
from src.forwarding.cds import CDSAlgorithm, am_i_cds, compute_local_mpr
from src.security.epoch import EpochStore, is_coordinator
from src.security.keys import BBKeyStore

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

    def __init__(
        self,
        cfg: BubbleBlueConfig,
        transport: L2CAPTransport,
        key_store: BBKeyStore,
        epoch_store: EpochStore,
        *,
        quiet: bool = False,
        cds_algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._key_store = key_store
        self._epoch_store = epoch_store
        self._quiet = quiet
        self._cds_algorithm = cds_algorithm
        self._bootstrap_key = cfg.group_key
        self._local_bd = cfg.local_bd_addr.upper()
        self._interval_s = max(1, int(cfg.hello_interval_s))
        self._timeout_ms = int(cfg.neighbor_timeout_s) * 1000
        self._peer_epochs: dict[str, int] = {}
        self._learned_anon_ids: dict[str, bytes] = {}
        self._rekey_catchup: Callable[[str], None] | None = None

        self.anon_id = compute_anon_id(self._bootstrap_key, self._local_bd)
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

    @property
    def key_store(self) -> BBKeyStore:
        """X25519 identity and per-peer pairwise keys (fed from Hello private parts)."""
        return self._key_store

    @property
    def epoch_store(self) -> EpochStore:
        return self._epoch_store

    def set_rekey_catchup(self, handler: Callable[[str], None]) -> None:
        """Register callback to pairwise-flood PKT_REKEY when a peer's epoch is stale."""
        self._rekey_catchup = handler

    def get_peer_epoch(self, bd_addr: str) -> int:
        return int(self._peer_epochs.get(bd_addr.strip().upper(), 0))

    def is_coordinator(self) -> bool:
        """True if this node has the smallest anon_id among resolved members."""
        member_aids = [
            bytes(m["anon_id"])
            for m in self.get_resolved_members()
            if str(m["bd_addr"]).upper() != self._local_bd
        ]
        return is_coordinator(self.anon_id, member_aids)

    def l2cap_peer_anon_ids(self) -> frozenset[bytes]:
        """Anon_ids for active L2CAP peers (transport.connections() only)."""
        return self._l2cap_peer_anon_ids()

    def local_anon_id(self) -> bytes:
        """8-byte anonymous ID for this node."""
        return self.anon_id

    def anon_id_for(self, bd_addr: str) -> bytes:
        """Learned 8-byte anon_id for an L2CAP peer (from received Hellos)."""
        bd = bd_addr.strip().upper()
        if bd not in self._learned_anon_ids:
            raise KeyError(f"no learned anon_id for peer {bd} (Hello not yet received)")
        return self._learned_anon_ids[bd]

    def has_learned_public_hello(self, bd_addr: str) -> bool:
        """True after a well-formed public Hello was received from this L2CAP peer."""
        return bd_addr.strip().upper() in self._learned_anon_ids

    def _parse_hello_member(self, data: bytes) -> dict[str, Any] | None:
        """Decrypt Hello private part with current or bootstrap group key."""
        for key in (self._epoch_store.current_group_key(), self._bootstrap_key):
            priv = parse_hello_private(data, key)
            if priv is not None:
                return priv
        return None

    def on_receive(self, peer_bd_addr: str, data: bytes) -> None:
        """Parse and ingest a received Hello packet."""
        peer_bd = peer_bd_addr.strip().upper()
        pub = parse_hello_public(data)
        self._learned_anon_ids[peer_bd] = bytes(pub["anon_id"])
        priv = self._parse_hello_member(data)
        self.table.update_from_hello(pub, priv)
        if priv is not None:
            public_key = priv.get("public_key")
            bd_addr = priv.get("bd_addr")
            peer_epoch = int(priv.get("epoch", 0))
            if public_key is not None and bd_addr is not None:
                bd_u = str(bd_addr).upper()
                self._peer_epochs[bd_u] = peer_epoch
                self._key_store.register_peer(bd_u, public_key)
                if (
                    peer_epoch < self._epoch_store.current_epoch()
                    and not self._epoch_store.is_revoked_pubkey(public_key)
                    and self._rekey_catchup is not None
                ):
                    self._rekey_catchup(bd_u)
        self.refresh_cds_role(verbose=not self._quiet)

    def on_peer_disconnected(self, peer_bd_addr: str) -> None:
        """Drop learned anon_id for a peer that left the L2CAP mesh."""
        self._learned_anon_ids.pop(peer_bd_addr.strip().upper(), None)

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
            self._learned_anon_ids[bd.upper()]
            for bd in self._transport.connections()
            if bd.upper() in self._learned_anon_ids
        )

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        """Recompute RELAY/LEAF from current L2CAP peers and Hello tables."""
        self._is_cds = am_i_cds(
            self.anon_id,
            self.table,
            self._l2cap_peer_anon_ids(),
            algorithm=self._cds_algorithm,
        )
        if verbose:
            if self._is_cds:
                print("[CDS] I am a relay node", flush=True)
            else:
                print("[CDS] I am a leaf node", flush=True)

    def set_cds_algorithm(self, algorithm: CDSAlgorithm) -> None:
        """Switch CDS election strategy and recompute the local relay role."""
        self._cds_algorithm = algorithm
        self.refresh_cds_role(verbose=False)

    def _known_neighbor_pairs(self) -> list[tuple[bytes, str]]:
        """
        L2CAP peers whose anon_id was learned from a received Hello.

        Peers connected but not yet heard from are omitted (preprint list A).
        """
        out: list[tuple[bytes, str]] = []
        for bd in sorted(self._transport.connections()):
            bd_u = bd.upper()
            aid = self._learned_anon_ids.get(bd_u)
            if aid is None:
                continue
            out.append((aid, bd_u))
        return out

    def _send_hellos(self) -> None:
        peers = list(self._transport.connections())
        if not peers:
            return

        neighbors = self._known_neighbor_pairs()

        # Advertise our own MPR set so peers can apply MPR-CDS rule (b) at runtime.
        mpr = compute_local_mpr(self.table, self.anon_id)
        advertised_neighbor_aids = {aid for aid, _ in neighbors}
        mpr_filtered = sorted(advertised_neighbor_aids & mpr)

        seq = self._next_seq()
        pkt = build_hello(
            self._epoch_store.current_group_key(),
            self._local_bd,
            seq,
            neighbors,
            self._key_store.local_public_key,
            epoch=self._epoch_store.current_epoch(),
            anon_id_key=self._bootstrap_key,
            mpr_anon_ids=mpr_filtered or None,
        )

        for peer in peers:
            try:
                self._transport.send(peer, pkt)
            except (OSError, RuntimeError) as e:
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
