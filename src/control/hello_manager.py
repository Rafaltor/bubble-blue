from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from config import (
    ANNOUNCE_BURST_COUNT,
    ANNOUNCE_BURST_GAP_S,
    ANNOUNCE_INTERVAL_S,
    BubbleBlueConfig,
)
from src.control.announce import announce_signed_message, build_announce
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

        # Connectionless presence plane: anon_ids whose public Hello we heard
        # over the air (broadcast), independent of any L2CAP link. When enabled,
        # the CDS election runs on this heard set instead of transport peers.
        self._connectionless = False
        self._heard_ttl_s = max(1.0, float(cfg.neighbor_timeout_s))
        self._heard: dict[bytes, float] = {}
        # anon_id -> CDS relay flag advertised in that peer's public Hello.
        self._peer_is_relay: dict[bytes, bool] = {}
        self._heard_lock = threading.Lock()

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
        self._announce_thread: threading.Thread | None = None
        self._is_cds = False
        self.refresh_cds_role(verbose=False)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="bb-hello-mgr", daemon=True)
        self._thread.start()
        self._announce_thread = threading.Thread(
            target=self._announce_loop, name="bb-announce-mgr", daemon=True
        )
        self._announce_thread.start()
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

    def anon_id_for_or_compute(self, bd_addr: str) -> bytes:
        """
        Prefer Hello-learned anon_id; else compute from bootstrap PSK.

        Needed for PKT_REKEY_FLOOD cases when a peer is known only via
        PKT_ANNOUNCE (no direct Hello yet). Bootstrap HMAC matches the
        peer's self-advertised anon_id.
        """
        bd = bd_addr.strip().upper()
        learned = self._learned_anon_ids.get(bd)
        if learned is not None:
            return learned
        return compute_anon_id(self._bootstrap_key, bd)

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
                signing_pub = priv.get("signing_public_key")
                self._key_store.register_peer_from_hello(
                    bd_u,
                    public_key,
                    signing_public_key=(
                        bytes(signing_pub)
                        if isinstance(signing_pub, (bytes, bytearray))
                        else None
                    ),
                )
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
        """
        Recompute RELAY/LEAF from the current neighbor set and Hello tables.

        In connectionless mode the symmetric-neighbor set comes from public Hellos
        heard over the air (:meth:`heard_anon_ids`) — the CDS backbone is elected
        WITHOUT needing an L2CAP link to every neighbor. Otherwise it falls back to
        ``transport.connections()`` (legacy link-driven election).
        """
        peers = self.heard_anon_ids() if self._connectionless else self._l2cap_peer_anon_ids()
        self._is_cds = am_i_cds(
            self.anon_id,
            self.table,
            peers,
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

    # ------------------------------------------------------------------
    # Connectionless presence plane (public Hello broadcast via advertising)
    # ------------------------------------------------------------------
    def enable_connectionless_topology(self, *, ttl_s: float | None = None) -> None:
        """
        Elect the CDS backbone from over-the-air public Hellos, not L2CAP links.

        Once enabled, :meth:`ingest_public_hello` feeds the neighbor table from
        broadcast Hellos and :meth:`refresh_cds_role` uses the heard set — so a
        node knows who is around and whether it is a relay before opening any link.
        """
        self._connectionless = True
        if ttl_s is not None:
            self._heard_ttl_s = max(1.0, float(ttl_s))

    def ingest_public_hello(
        self,
        anon_id: bytes,
        seq: int,
        neighbor_anon_ids: list[bytes],
        mpr_anon_ids: list[bytes] | None = None,
        *,
        is_relay: bool = False,
    ) -> None:
        """
        Ingest a public Hello heard over the air (no L2CAP link, no private part).

        Updates the neighbor/topology tables (advertised 1-hop lists + MPR set),
        records the sender's advertised CDS role, marks it as currently heard, then
        refreshes our own relay role. Ignores our own broadcast.
        """
        aid = bytes(anon_id)
        if aid == self.anon_id:
            return
        ts_ms = time.time_ns() // 1_000_000
        parsed_public = {
            "anon_id": aid,
            "ts_ms": ts_ms,
            "seq": int(seq),
            "neighbor_anon_ids": [bytes(a) for a in neighbor_anon_ids],
            "mpr_anon_ids": [bytes(a) for a in (mpr_anon_ids or [])],
        }
        self.table.update_from_hello(parsed_public, None)
        with self._heard_lock:
            self._heard[aid] = time.monotonic()
            self._peer_is_relay[aid] = bool(is_relay)
        self.refresh_cds_role(verbose=not self._quiet)

    @property
    def is_connectionless(self) -> bool:
        """True when the CDS backbone is elected from over-the-air Hellos."""
        return self._connectionless

    def connectionless_link_plan(self) -> dict[str, Any]:
        """
        CDS-backbone link plan (anon_ids) for the connectionless connection policy.

        Returns ``am_relay`` (this node is a CDS relay), ``sym`` (symmetric heard
        neighbors), ``relays`` (symmetric neighbors that are CDS relays) and
        ``cds`` (the elected relay set over the heard topology). The bb_api layer
        maps these anon_ids to BD addresses to decide which links to open.
        """
        from src.forwarding.cds import local_symmetric_peers

        heard = self.heard_anon_ids()
        sym = {bytes(a) for a in local_symmetric_peers(self.table, self.anon_id, heard)}
        with self._heard_lock:
            relays = {a for a in sym if self._peer_is_relay.get(a, False)}
        return {
            "am_relay": bool(self._is_cds),
            "sym": sym,
            "relays": relays,
        }

    def heard_anon_ids(self) -> frozenset[bytes]:
        """anon_ids whose public Hello was heard within the TTL (excludes self)."""
        now = time.monotonic()
        with self._heard_lock:
            fresh = {
                aid
                for aid, ts in self._heard.items()
                if now - ts <= self._heard_ttl_s and aid != self.anon_id
            }
            # Opportunistically drop stale entries so the set stays bounded.
            self._heard = {aid: ts for aid, ts in self._heard.items() if now - ts <= self._heard_ttl_s}
        return frozenset(fresh)

    def build_local_presence_value(self, *, max_value_len: int | None = None) -> bytes:
        """
        Build the Manufacturer Specific Data VALUE for our own public Hello.

        Advertises our anon_id, a fresh sequence number, our currently-heard
        symmetric neighbors and the MPR set we elect over them — everything a
        peer needs to place us in the mesh graph without connecting. Pass
        ``max_value_len`` (e.g. ``LEGACY_PRESENCE_MAX_VALUE_LEN``) to produce a
        compact Hello that fits a legacy 31-byte advertisement — required so
        controllers that can only do legacy scanning still hear our presence.
        """
        from src.transport.advertising import (
            _MAX_PRESENCE_VALUE_LEN,
            build_presence_manufacturer_value,
        )

        heard = self.heard_anon_ids()
        neighbors = sorted(heard)
        mpr = {bytes(a) for a in compute_local_mpr(self.table, self.anon_id)} & set(heard)
        seq = self._next_seq()
        return build_presence_manufacturer_value(
            self.anon_id,
            seq,
            neighbors,
            sorted(mpr),
            is_relay=bool(self._is_cds),
            bd_addr=self._local_bd,
            max_value_len=_MAX_PRESENCE_VALUE_LEN if max_value_len is None else int(max_value_len),
        )

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
            local_signing_public_key=self._key_store.local_signing_public_key,
        )

        for peer in peers:
            try:
                self._transport.send(peer, pkt)
            except (OSError, RuntimeError) as e:
                if not self._quiet:
                    print(f"[APP] Hello send failed peer={peer}: {e}", flush=True)

    def emit_announce(self) -> None:
        """
        Flood one PKT_ANNOUNCE (bd_addr → local X25519 pubkey) under current group key.

        Safe to call after successful epoch adoption; no-op if no L2CAP peers.
        """
        peers = list(self._transport.connections())
        if not peers:
            return
        seq = self._next_seq()
        try:
            epoch = self._epoch_store.current_epoch()
            signed = announce_signed_message(
                self._local_bd,
                epoch,
                self._key_store.local_public_key,
                self._key_store.local_signing_public_key,
            )
            pkt = build_announce(
                self._epoch_store.current_group_key(),
                self._local_bd,
                seq,
                None,
                epoch,
                self._key_store.local_public_key,
                self._cfg.ttl_max,
                signing_public_key=self._key_store.local_signing_public_key,
                signature=self._key_store.sign(signed),
            )
        except (ValueError, RuntimeError) as e:
            if not self._quiet:
                print(f"[APP] Announce build failed: {e}", flush=True)
            return
        for peer in peers:
            try:
                self._transport.send(peer, pkt)
            except (OSError, RuntimeError) as e:
                if not self._quiet:
                    print(f"[APP] Announce send failed peer={peer}: {e}", flush=True)

    def _announce_loop(self) -> None:
        # Burst at startup so joiners learn pubkeys quickly, then periodic.
        for _ in range(ANNOUNCE_BURST_COUNT):
            if self._stop.is_set():
                return
            self.emit_announce()
            if self._stop.wait(ANNOUNCE_BURST_GAP_S):
                return
        while not self._stop.wait(ANNOUNCE_INTERVAL_S):
            self.emit_announce()

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
