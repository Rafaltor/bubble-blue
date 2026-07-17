from __future__ import annotations

import os
import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from cryptography.exceptions import InvalidTag

from config import (
    PKT_ANNOUNCE,
    PKT_DATA,
    PKT_REKEY,
    PKT_REKEY_FLOOD,
    PKT_SUBGROUP,
    BubbleBlueConfig,
    max_payload,
    mtu_for_transport,
)
from src.control.announce import parse_announce
from src.security.crypto import decrypt_with_key, encrypt_with_key, unwrap_msg_key, wrap_msg_key
from src.security.keys import derive_packet_key, derive_wrap_key
from src.security.rekey import (
    pack_rekey_plaintext,
    pack_signed_rekey_plaintext,
    partition_rekey_targets,
    sender_is_coordinator,
    unpack_rekey_plaintext,
    verify_rekey_attestation,
)
from src.security.replay import ReplayFilter
from src.security.packet import (
    ROUTING_HEADER_SIZE,
    BROADCAST_BD_ADDR,
    build_bb_packet,
    build_routing_header,
    build_subgroup_packet,
    parse_bb_packet,
    parse_routing_header,
    parse_subgroup_packet,
    routing_header_aad,
    subgroup_cases_digest,
    validate_timestamp,
)

_FWD_PKT_TYPES = frozenset(
    {PKT_DATA, PKT_SUBGROUP, PKT_REKEY, PKT_ANNOUNCE, PKT_REKEY_FLOOD}
)

if TYPE_CHECKING:
    from src.control.hello_manager import HelloManager
    from src.transport.l2cap import L2CAPTransport

OnMessageCallback = Callable[[str, str], None]
LogCallback = Callable[[str], None]
OnDecryptFailCallback = Callable[[str], None]

_TTL_OFFSET = 13
_SUBGROUP_MODE_MARKER = bytes([PKT_SUBGROUP])
_REKEY_FLOOD_MODE_MARKER = bytes([PKT_REKEY_FLOOD])
_ANON_TAG_SIZE = 8

DeliverCallback = Callable[[str, bytes, dict[str, Any]], None]


class PayloadTooLarge(Exception):
    """Plaintext or wire frame exceeds the current transport MTU budget."""

    def __init__(self, limit: int, actual: int) -> None:
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"payload {actual} B exceeds transport limit {limit} B "
            "(fragmentation not enabled — shorten message or use bt_classic)"
        )


class _ForwardCache:
    """
    Bounded deduplication cache for relay forwarding.
    Evicts entries older than ttl_s seconds.
    Key = (src: str, seq: int)
    """

    def __init__(self, ttl_s: float = 240.0, max_size: int = 4096) -> None:
        self._ttl_s = ttl_s
        self._max_size = max_size
        self._entries: dict[tuple[str, int], float] = {}
        self._lock = threading.Lock()

    def _evict(self) -> None:
        now = time.monotonic()
        stale = [k for k, ts in self._entries.items() if (now - ts) > self._ttl_s]
        for key in stale:
            del self._entries[key]
        if len(self._entries) > self._max_size:
            drop_n = self._max_size // 4
            oldest = sorted(self._entries.items(), key=lambda item: item[1])[:drop_n]
            for key, _ in oldest:
                del self._entries[key]

    def seen(self, src: str, seq: int) -> bool:
        """Return True if already forwarded (duplicate). Also evicts stale entries."""
        key = (src.upper(), int(seq))
        with self._lock:
            self._evict()
            return key in self._entries

    def mark(self, src: str, seq: int) -> None:
        """Record this (src, seq) as forwarded."""
        key = (src.upper(), int(seq))
        with self._lock:
            self._entries[key] = time.monotonic()


class PacketForwarder:
    """
    PKT_DATA plane: CDS relays flood opaque packets (TTL decremented on wire);
    local delivery when dst is this node or broadcast.
    """

    def __init__(
        self,
        cfg: BubbleBlueConfig,
        transport: L2CAPTransport,
        hello_mgr: HelloManager,
        *,
        on_message: OnMessageCallback,
        on_log: LogCallback | None = None,
        on_decrypt_fail: OnDecryptFailCallback | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._hello_mgr = hello_mgr
        self._on_message = on_message
        self._on_log = on_log
        self._on_decrypt_fail = on_decrypt_fail
        self._fwd_cache = _ForwardCache()
        self._replay: dict[str, ReplayFilter] = {}
        self._relay_replay: dict[str, ReplayFilter] = {}
        self._replay_lock = threading.RLock()
        self._fwd_lock = threading.RLock()
        self._seq_lock = threading.Lock()
        self._tx_seq = 0

    def _log(self, msg: str) -> None:
        if self._on_log:
            self._on_log(msg)

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._tx_seq += 1
            return self._tx_seq

    def _current_epoch(self) -> int:
        return self._hello_mgr.epoch_store.current_epoch()

    def _group_key(self) -> bytes:
        return self._hello_mgr.epoch_store.current_group_key()

    def _pair_key(self, bd_addr: str, *, wire_epoch: int | None = None) -> bytes | None:
        ep = self._hello_mgr.get_peer_epoch(bd_addr) if wire_epoch is None else int(wire_epoch)
        return self._hello_mgr.key_store.get_pair_key(bd_addr, epoch=ep)

    def _check_plaintext_payload(self, payload: bytes) -> None:
        limit = max_payload(self._cfg.transport_kind)
        if len(payload) > limit:
            raise PayloadTooLarge(limit, len(payload))

    def _check_wire_packet(self, packet: bytes) -> None:
        limit = mtu_for_transport(self._cfg.transport_kind)
        if len(packet) > limit:
            raise PayloadTooLarge(limit, len(packet))

    def build_data_packet(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str,
        *,
        private: bool = False,
    ) -> bytes:
        """
        Build a PKT_DATA wire packet using per-packet key derivation.

        Group traffic uses ``group_key``; private unicast uses the pairwise key for ``dst``.

        Plaintext is capped by ``max_payload(transport_kind)`` (470 B on BLE, 979 B on
        BT Classic) so the full wire frame fits without L2CAP fragmentation.
        """
        payload = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        self._check_plaintext_payload(payload)
        dst = dst_bd_addr.upper()
        src = self._cfg.local_bd_addr.upper()

        if private:
            base_key = self._pair_key(dst, wire_epoch=self._current_epoch())
            if base_key is None:
                raise RuntimeError(f"No pairwise key for {dst}, Hello not yet received")
        else:
            base_key = self._group_key()

        seq = self._next_seq()
        ts_ms = time.time_ns() // 1_000_000
        rh = build_routing_header(PKT_DATA, src, dst, self._cfg.ttl_max, seq, ts_ms)
        packet_key = derive_packet_key(base_key, src, seq, ts_ms)
        enc = encrypt_with_key(packet_key, payload, routing_header_aad(rh))
        return build_bb_packet(rh, enc["ciphertext"])

    def build_subgroup_data_packet(
        self,
        plaintext: str | bytes,
        recipients: list[str],
    ) -> bytes:
        """
        Build a PKT_SUBGROUP wire packet for à la carte multicast to subset S.

        Each recipient gets a pairwise-wrapped copy of a fresh per-message key;
        membership tags are carried inside the encrypted payload.
        """
        if not recipients:
            raise RuntimeError("no recipients for subgroup multicast")

        payload = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        self._check_plaintext_payload(payload)
        src = self._cfg.local_bd_addr.upper()
        seq = self._next_seq()
        ts_ms = time.time_ns() // 1_000_000
        k_msg = os.urandom(32)

        cases: list[tuple[bytes, bytes]] = []
        recipient_tags: list[bytes] = []
        for bd in recipients:
            addr = bd.strip().upper()
            pair_key = self._pair_key(addr, wire_epoch=self._current_epoch())
            if pair_key is None:
                raise RuntimeError(f"No pairwise key for {addr}")
            recipient_tag = self._hello_mgr.anon_id_for(addr)
            wrap_key = derive_wrap_key(pair_key, src, seq, ts_ms)
            blob = wrap_msg_key(wrap_key, k_msg, aad=recipient_tag)
            cases.append((recipient_tag, blob))
            recipient_tags.append(recipient_tag)

        rh = build_routing_header(
            PKT_SUBGROUP, src, BROADCAST_BD_ADDR, self._cfg.ttl_max, seq, ts_ms
        )
        cases_digest = subgroup_cases_digest(cases)
        s_tags = b"".join(recipient_tags)
        payload_plaintext = bytes([len(recipients)]) + s_tags + payload
        aad = routing_header_aad(rh) + _SUBGROUP_MODE_MARKER + cases_digest
        enc = encrypt_with_key(k_msg, payload_plaintext, aad)
        packet = build_subgroup_packet(rh, cases, enc["ciphertext"])
        self._check_wire_packet(packet)
        return packet

    def build_rekey_packet(self, dst_bd_addr: str, *, peer_epoch: int | None = None) -> bytes:
        """Build PKT_REKEY unicast carrying the current epoch state for ``dst_bd_addr``."""
        dst = dst_bd_addr.upper()
        src = self._cfg.local_bd_addr.upper()
        ep = self._hello_mgr.get_peer_epoch(dst) if peer_epoch is None else int(peer_epoch)
        pair_key = self._pair_key(dst, wire_epoch=ep)
        if pair_key is None:
            raise RuntimeError(f"No pairwise key for {dst}")

        plain = self._signed_rekey_plaintext(
            self._hello_mgr.epoch_store.current_epoch(),
            self._hello_mgr.epoch_store.current_group_key(),
            self._hello_mgr.epoch_store.revoked_pubkeys(),
        )
        seq = self._next_seq()
        ts_ms = time.time_ns() // 1_000_000
        rh = build_routing_header(PKT_REKEY, src, dst, self._cfg.ttl_max, seq, ts_ms)
        packet_key = derive_packet_key(pair_key, src, seq, ts_ms)
        enc = encrypt_with_key(packet_key, plain, routing_header_aad(rh))
        return build_bb_packet(rh, enc["ciphertext"])

    def _signed_rekey_plaintext(
        self,
        epoch: int,
        group_key: bytes,
        revoked: list[bytes] | frozenset[bytes],
    ) -> bytes:
        """Core rekey body + Ed25519 signature under the local signing key."""
        core = pack_rekey_plaintext(epoch, group_key, revoked)
        sig = self._hello_mgr.key_store.sign(core)
        return pack_signed_rekey_plaintext(epoch, group_key, revoked, sig)

    def _member_anon_ids_for_coordinator_check(self) -> list[bytes]:
        """Anon_ids of known live members (resolved + peers with pubkey + self)."""
        local = self._cfg.local_bd_addr.upper()
        aids: dict[str, bytes] = {local: self._hello_mgr.local_anon_id()}
        for m in self._hello_mgr.get_resolved_members():
            bd = str(m["bd_addr"]).upper()
            aid = m.get("anon_id")
            if isinstance(aid, (bytes, bytearray)) and len(aid) == 8:
                aids[bd] = bytes(aid)
            else:
                tag_fn = getattr(self._hello_mgr, "anon_id_for_or_compute", None)
                if callable(tag_fn):
                    aids[bd] = tag_fn(bd)
        for bd in self._hello_mgr.key_store.known_peers():
            if bd in aids:
                continue
            tag_fn = getattr(self._hello_mgr, "anon_id_for_or_compute", None)
            if callable(tag_fn):
                aids[bd] = tag_fn(bd)
            else:
                try:
                    aids[bd] = self._hello_mgr.anon_id_for(bd)
                except (KeyError, AttributeError):
                    continue
        return list(aids.values())

    def _accept_rekey_from(self, src: str, body: dict[str, object]) -> bool:
        """
        Require Ed25519 attestation under src's known signing key and
        that src is the min-anon_id coordinator among known members.
        """
        src_u = src.strip().upper()
        sig_pub = self._hello_mgr.key_store.get_peer_signing_public_key(src_u)
        if sig_pub is None:
            self._log(f"[SEC] rekey rejected from {src_u}: no signing key")
            return False
        if not verify_rekey_attestation(body, src_signing_public_key=sig_pub):
            self._log(f"[SEC] rekey rejected from {src_u}: bad signature")
            return False
        tag_fn = getattr(self._hello_mgr, "anon_id_for_or_compute", None)
        if callable(tag_fn):
            src_aid = tag_fn(src_u)
        else:
            try:
                src_aid = self._hello_mgr.anon_id_for(src_u)
            except (KeyError, AttributeError):
                self._log(f"[SEC] rekey rejected from {src_u}: unknown anon_id")
                return False
        members = self._member_anon_ids_for_coordinator_check()
        # Exclude src from "other members" list — is_coordinator adds self.
        others = [a for a in members if a != src_aid]
        if not sender_is_coordinator(src_aid, others):
            self._log(f"[SEC] rekey rejected from {src_u}: not coordinator")
            return False
        return True

    def send_rekey_catchup(self, dst_bd_addr: str) -> None:
        """Gossip: send current PKT_REKEY to a peer with a stale epoch (pairwise)."""
        dst = dst_bd_addr.upper()
        peer = self.route_l2cap_peer(dst)
        packet = self.build_rekey_packet(dst)
        self._transport.send(peer, packet)

    def _rekey_flood_targets(self, *, exclude_bd: str | None = None) -> list[str]:
        """
        Same membership resolution as the historical unicast flood:
        L2CAP connections + resolved Hello members + announce-learned peers.
        """
        local = self._cfg.local_bd_addr.upper()
        exclude = exclude_bd.strip().upper() if exclude_bd else None
        revoked = self._hello_mgr.epoch_store.revoked_pubkeys()
        targets: set[str] = {bd.upper() for bd in self._transport.connections()}
        targets.discard(local)
        for m in self._hello_mgr.get_resolved_members():
            targets.add(str(m["bd_addr"]).upper())
        for bd in self._hello_mgr.key_store.known_peers():
            targets.add(bd.upper())
        if exclude:
            targets.discard(exclude)

        out: list[str] = []
        for bd in sorted(targets):
            if bd == local:
                continue
            pub = self._hello_mgr.key_store.get_peer_public_key(bd)
            if pub is None:
                self._log(f"[FWD] rekey-flood skip {bd}: no pubkey (wait for ANNOUNCE/Hello)")
                continue
            if pub in revoked:
                continue
            out.append(bd)
        return out

    def build_rekey_flood_packets(
        self,
        revoked_pubkey: bytes,
        *,
        wrap_epoch: int,
        new_epoch: int,
        new_group_key: bytes,
        revoked_set: frozenset[bytes],
        targets: list[str],
        pair_keys: dict[str, bytes],
    ) -> list[bytes]:
        """
        Build one or more self-contained PKT_REKEY_FLOOD packets.

        Wraps use ``pair_keys`` derived at ``wrap_epoch`` (pre-bump). Each
        partition has its own seq/ts/k_msg and identical rekey plaintext body.
        """
        _ = revoked_pubkey
        src = self._cfg.local_bd_addr.upper()
        plain = self._signed_rekey_plaintext(new_epoch, new_group_key, revoked_set)
        body_len = len(plain)
        mtu = mtu_for_transport(self._cfg.transport_kind)
        partitions = partition_rekey_targets(targets, body_len, mtu)
        if not partitions:
            return []

        packets: list[bytes] = []
        for part in partitions:
            seq = self._next_seq()
            ts_ms = time.time_ns() // 1_000_000
            k_msg = os.urandom(32)
            cases: list[tuple[bytes, bytes]] = []
            for bd in part:
                pair_key = pair_keys.get(bd)
                if pair_key is None:
                    self._log(f"[FWD] rekey-flood missing pair_key for {bd}")
                    continue
                tag_fn = getattr(
                    self._hello_mgr, "anon_id_for_or_compute", None
                )
                if callable(tag_fn):
                    recipient_tag = tag_fn(bd)
                else:
                    recipient_tag = self._hello_mgr.anon_id_for(bd)
                wrap_key = derive_wrap_key(pair_key, src, seq, ts_ms)
                blob = wrap_msg_key(wrap_key, k_msg, aad=recipient_tag)
                cases.append((recipient_tag, blob))
            if not cases:
                continue

            rh = build_routing_header(
                PKT_REKEY_FLOOD, src, BROADCAST_BD_ADDR, self._cfg.ttl_max, seq, ts_ms
            )
            cases_digest = subgroup_cases_digest(cases)
            aad = routing_header_aad(rh) + _REKEY_FLOOD_MODE_MARKER + cases_digest
            enc = encrypt_with_key(k_msg, plain, aad)
            packet = build_subgroup_packet(rh, cases, enc["ciphertext"])
            self._check_wire_packet(packet)
            packets.append(packet)
        return packets

    def revoke_member(self, bd_addr: str) -> None:
        """
        Coordinator-initiated revocation: bump epoch, rotate group key,
        flood PKT_REKEY_FLOOD (multi-recipient wrap header).

        Wraps are under the pre-bump epoch pairwise keys. Late joiners are
        caught up by existing PKT_REKEY unicast gossip (``send_rekey_catchup``).
        """
        if not self._hello_mgr.is_coordinator():
            raise RuntimeError("only the coordinator (min anon_id) may initiate revocation")
        target = bd_addr.strip().upper()
        pubkey = self._hello_mgr.key_store.get_peer_public_key(target)
        if pubkey is None:
            raise RuntimeError(f"no public key for {target} — wait for Hello")
        if self._hello_mgr.epoch_store.is_revoked_pubkey(pubkey):
            raise RuntimeError(f"{target} is already revoked")

        # Capture wrap epoch and derive all K_pair before prepare_revocation /
        # clear_pair_key_cache invalidate the cache domain.
        wrap_epoch = self._hello_mgr.epoch_store.current_epoch()
        targets = self._rekey_flood_targets(exclude_bd=target)
        pair_keys: dict[str, bytes] = {}
        for bd in targets:
            pk = self._pair_key(bd, wire_epoch=wrap_epoch)
            if pk is None:
                self._log(f"[FWD] rekey-flood skip {bd}: no pairwise key at epoch {wrap_epoch}")
                continue
            pair_keys[bd] = pk
        targets = [bd for bd in targets if bd in pair_keys]

        new_epoch, new_key, revoked_set = self._hello_mgr.epoch_store.prepare_revocation(
            pubkey
        )
        packets = self.build_rekey_flood_packets(
            pubkey,
            wrap_epoch=wrap_epoch,
            new_epoch=new_epoch,
            new_group_key=new_key,
            revoked_set=revoked_set,
            targets=targets,
            pair_keys=pair_keys,
        )
        self._hello_mgr.key_store.clear_pair_key_cache()
        emit = getattr(self._hello_mgr, "emit_announce", None)
        if callable(emit):
            emit()

        peers = self._other_peers(exclude=None)
        if not peers:
            self._log("[FWD] rekey-flood: no L2CAP peers to send on")
            return
        for packet in packets:
            for peer in peers:
                try:
                    self._transport.send(peer, packet)
                except OSError as e:
                    self._log(f"[FWD] rekey-flood send {peer}: {e}")

    def flood_rekey_state(self) -> None:
        """
        Unicast PKT_REKEY gossip of current epoch state to all known members.

        Kept for catch-up / diagnostics. Initial revocation uses
        :meth:`revoke_member` → PKT_REKEY_FLOOD instead.
        """
        revoked = self._hello_mgr.epoch_store.revoked_pubkeys()
        targets: set[str] = {bd.upper() for bd in self._transport.connections()}
        targets.discard(self._cfg.local_bd_addr.upper())
        for m in self._hello_mgr.get_resolved_members():
            targets.add(str(m["bd_addr"]).upper())
        for bd in self._hello_mgr.key_store.known_peers():
            targets.add(bd.upper())
        for bd in sorted(targets):
            pub = self._hello_mgr.key_store.get_peer_public_key(bd)
            if pub is not None and pub in revoked:
                continue
            if pub is None:
                continue
            try:
                peer = self.route_l2cap_peer(bd)
                self._transport.send(peer, self.build_rekey_packet(bd))
            except (OSError, RuntimeError) as e:
                self._log(f"[FWD] rekey flood {bd}: {e}")

    def send_data(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str,
        *,
        private: bool = False,
        l2cap_peer: str | None = None,
    ) -> None:
        """Send PKT_DATA to ``dst_bd_addr`` (flood if broadcast, else one L2CAP link)."""
        packet = self.build_data_packet(plaintext, dst_bd_addr, private=private)
        dst = dst_bd_addr.upper()

        if dst == BROADCAST_BD_ADDR:
            peers = self._other_peers(exclude=None)
            if not peers:
                raise RuntimeError("no L2CAP peers connected")
            for peer in peers:
                self._transport.send(peer, packet)
            return

        if not l2cap_peer:
            raise RuntimeError("l2cap_peer required for unicast send_data")
        self._transport.send(l2cap_peer.upper(), packet)

    def send_broadcast(self, text: str | bytes) -> None:
        self.send_data(text, BROADCAST_BD_ADDR, private=False)

    def send_subgroup(self, text: str | bytes, recipients: list[str]) -> None:
        """Flood PKT_SUBGROUP to all L2CAP peers (subset multicast)."""
        packet = self.build_subgroup_data_packet(text, recipients)
        peers = self._other_peers(exclude=None)
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        for peer in peers:
            self._transport.send(peer, packet)

    def send_unicast(
        self,
        text: str | bytes,
        dst_bd_addr: str,
        *,
        l2cap_peer: str,
        private: bool = False,
    ) -> None:
        self.send_data(text, dst_bd_addr, private=private, l2cap_peer=l2cap_peer)

    def handle(self, ingress_peer: str, data: bytes) -> None:
        ingress = ingress_peer.upper()
        try:
            if len(data) < ROUTING_HEADER_SIZE:
                return
            hdr = parse_routing_header(data)
            pkt_type = hdr["type"]
            if pkt_type not in _FWD_PKT_TYPES or not validate_timestamp(hdr["ts_ms"]):
                return

            local = self._cfg.local_bd_addr.upper()
            dst = hdr["dst"].upper()
            src = hdr["src"].upper()
            seq = int(hdr["seq"])

            if pkt_type == PKT_REKEY:
                deliver_fn = self._try_deliver_rekey
            elif pkt_type == PKT_REKEY_FLOOD:
                deliver_fn = self._try_deliver_rekey_flood
            elif pkt_type == PKT_SUBGROUP:
                deliver_fn = self._try_deliver_subgroup
            elif pkt_type == PKT_ANNOUNCE:
                deliver_fn = self._try_deliver_announce
            else:
                deliver_fn = self._try_deliver

            self._hello_mgr.refresh_cds_role()
            if self._hello_mgr.is_relay:
                self._relay_then_deliver(ingress, data, hdr, src, seq, dst, local, deliver_fn)
            elif self._for_us(dst, local):
                deliver_fn(ingress, data, hdr)
        except Exception as e:  # noqa: BLE001
            self._log(f"[FWD] {ingress}: {e}")

    def _relay_then_deliver(
        self,
        ingress: str,
        data: bytes,
        hdr: dict[str, Any],
        src: str,
        seq: int,
        dst: str,
        local: str,
        deliver_fn: DeliverCallback,
    ) -> None:
        ttl = int(hdr["ttl"])
        ts_ms = int(hdr["ts_ms"])
        if dst != local and ttl > 0:
            new_ttl = ttl - 1
            if new_ttl > 0 and self._check_relay_ingress(src, seq, ts_ms):
                with self._fwd_lock:
                    if not self._fwd_cache.seen(src, seq):
                        self._fwd_cache.mark(src, seq)
                        wire = _decrement_ttl(data, new_ttl)
                        for peer in self._other_peers(exclude=ingress):
                            try:
                                self._transport.send(peer, wire)
                            except OSError as e:
                                self._log(f"[FWD] relay {peer}: {e}")

        if self._for_us(dst, local):
            deliver_fn(ingress, data, hdr)

    def _check_relay_ingress(self, src: str, seq: int, ts_ms: int) -> bool:
        """
        Sliding-window anti-replay on the relay path (ingress before forward).

        Separate from delivery replay state: the same packet may be delivered
        locally and forwarded without either path treating the other as a replay.
        """
        _ = ts_ms
        src_u = src.upper()
        # Lock ordering: PacketForwarder._replay_lock, then ReplayFilter._lock
        # (inside check_and_update). Never acquire _replay_lock from ReplayFilter.
        with self._replay_lock:
            rf = self._relay_replay.get(src_u)
            if rf is None:
                rf = ReplayFilter()
                self._relay_replay[src_u] = rf
            if rf.check_and_update(src_u, seq):
                return True
        self._log(f"[FWD] relay-replay dropped src={src_u} seq={seq}")
        return False

    def _check_replay(self, src: str, seq: int, ts_ms: int) -> bool:
        """
        Sliding-window anti-replay for local delivery (per sender).

        Timestamp tolerance is enforced in ``handle()`` before delivery;
        ``ts_ms`` is accepted here for API symmetry with the packet header.
        """
        _ = ts_ms
        src_u = src.upper()
        with self._replay_lock:
            rf = self._replay.get(src_u)
            if rf is None:
                rf = ReplayFilter()
                self._replay[src_u] = rf
            if rf.check_and_update(src_u, seq):
                return True
        self._log(f"[FWD] replay dropped src={src_u} seq={seq}")
        return False

    def _try_deliver(self, ingress_peer: str, data: bytes, hdr: dict[str, Any]) -> None:
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        if not self._check_replay(src, seq, ts_ms):
            return

        local = self._cfg.local_bd_addr.upper()
        dst = hdr["dst"].upper()

        if dst == local:
            base_key = self._pair_key(src, wire_epoch=self._current_epoch())
            if base_key is None:
                self._log(f"[FWD] no pairwise key for {src}")
                return
        else:
            base_key = self._group_key()

        try:
            parsed = parse_bb_packet(data)
            packet_key = derive_packet_key(base_key, src, seq, int(hdr["ts_ms"]))
            plaintext = decrypt_with_key(
                packet_key,
                parsed["ciphertext"],
                routing_header_aad(parsed["routing_header"]),
            )
        except InvalidTag:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] decrypt failed src={src}")
            return

        self._on_deliver(ingress_peer, plaintext, hdr)

    def _try_deliver_rekey(self, ingress_peer: str, data: bytes, hdr: dict[str, Any]) -> None:
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        if not self._check_replay(src, seq, ts_ms):
            return

        pair_key = None
        plain = None
        parsed = parse_bb_packet(data)
        aad = routing_header_aad(parsed["routing_header"])
        for ep in dict.fromkeys((self._current_epoch(), self._hello_mgr.get_peer_epoch(src))):
            pk = self._pair_key(src, wire_epoch=ep)
            if pk is None:
                continue
            try:
                packet_key = derive_packet_key(pk, src, seq, ts_ms)
                plain = decrypt_with_key(packet_key, parsed["ciphertext"], aad)
                pair_key = pk
                break
            except InvalidTag:
                continue
        if pair_key is None or plain is None:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] rekey decrypt failed src={src}")
            return

        try:
            body = unpack_rekey_plaintext(plain)
        except ValueError:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] rekey parse failed src={src}")
            return

        if not self._accept_rekey_from(src, body):
            return

        epoch = int(body["epoch"])
        group_key = bytes(body["group_key"])  # type: ignore[arg-type]
        revoked = list(body["revoked_pubkeys"])  # type: ignore[arg-type]

        if self._hello_mgr.epoch_store.adopt_rekey(epoch, group_key, revoked):
            self._hello_mgr.key_store.clear_pair_key_cache()
            self._log(f"[FWD] adopted epoch {epoch} from {src}")
            # Re-announce under the new group key so multi-hop peers learn us.
            emit = getattr(self._hello_mgr, "emit_announce", None)
            if callable(emit):
                emit()

    def _try_deliver_rekey_flood(
        self, ingress_peer: str, data: bytes, hdr: dict[str, Any]
    ) -> None:
        """
        Local delivery of PKT_REKEY_FLOOD (relay already done by handle path).

        Absent own case → silent (revoked or different partition fragment).
        InvalidTag anywhere → drop with debug log; never raise.
        """
        _ = ingress_peer
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        if not self._check_replay(src, seq, ts_ms):
            return
        if src == self._cfg.local_bd_addr.upper():
            return

        my_tag = self._hello_mgr.local_anon_id()
        try:
            parsed = parse_subgroup_packet(data)
            our_blob: bytes | None = None
            for tag, blob in parsed["cases"]:
                if tag == my_tag:
                    our_blob = blob
                    break
            if our_blob is None:
                return

            pair_key = self._pair_key(src, wire_epoch=self._current_epoch())
            if pair_key is None:
                self._log(f"[FWD] rekey-flood no pairwise key for {src}")
                return

            wrap_key = derive_wrap_key(pair_key, src, seq, ts_ms)
            k_msg = unwrap_msg_key(wrap_key, our_blob, aad=my_tag)
            aad = (
                routing_header_aad(parsed["routing_header"])
                + _REKEY_FLOOD_MODE_MARKER
                + subgroup_cases_digest(parsed["cases"])
            )
            plain = decrypt_with_key(k_msg, parsed["ciphertext"], aad)
            body = unpack_rekey_plaintext(plain)
        except InvalidTag:
            self._log(f"[FWD] rekey-flood decrypt failed src={src}")
            return
        except ValueError as e:
            self._log(f"[FWD] rekey-flood parse failed src={src}: {e}")
            return

        if not self._accept_rekey_from(src, body):
            return

        epoch = int(body["epoch"])
        group_key = bytes(body["group_key"])  # type: ignore[arg-type]
        revoked = list(body["revoked_pubkeys"])  # type: ignore[arg-type]

        if self._hello_mgr.epoch_store.adopt_rekey(epoch, group_key, revoked):
            self._hello_mgr.key_store.clear_pair_key_cache()
            self._log(f"[FWD] adopted epoch {epoch} from rekey-flood src={src}")
            emit = getattr(self._hello_mgr, "emit_announce", None)
            if callable(emit):
                emit()

    def _try_deliver_announce(self, ingress_peer: str, data: bytes, hdr: dict[str, Any]) -> None:
        """Relay already done; parse group-encrypted pubkey binding locally."""
        _ = ingress_peer
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        if not self._check_replay(src, seq, ts_ms):
            return
        if src == self._cfg.local_bd_addr.upper():
            return

        keys = [
            self._hello_mgr.epoch_store.current_group_key(),
            self._hello_mgr.epoch_store.bootstrap_group_key,
        ]
        # Deduplicate while preserving order (current then bootstrap).
        group_keys = list(dict.fromkeys(keys))
        body = parse_announce(data, group_keys)
        if body is None:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] announce decrypt failed src={src}")
            return

        bd = str(body["bd_addr"]).upper()
        public_key = bytes(body["public_key"])  # type: ignore[arg-type]
        peer_epoch = int(body["epoch"])
        result = self._hello_mgr.key_store.apply_announce_binding(
            bd,
            public_key,
            signing_public_key=bytes(body["signing_public_key"]),  # type: ignore[arg-type]
            signature=bytes(body["signature"]),  # type: ignore[arg-type]
            signed_message=bytes(body["signed_message"]),  # type: ignore[arg-type]
        )
        if result == "rejected_sig":
            self._log(f"[SEC] ANNOUNCE signature invalide pour {bd}")
        elif result == "ignored_hello":
            self._log(f"[SEC] conflit de binding pubkey pour {bd} (announce ignoré)")
        elif result == "ignored_first":
            self._log(
                f"[SEC] conflit de binding pubkey pour {bd} "
                "(premier vu conservé, announce ignoré)"
            )
        elif result == "registered":
            # Soft epoch hint for catch-up (same as Hello private epoch field).
            if hasattr(self._hello_mgr, "_peer_epochs"):
                self._hello_mgr._peer_epochs[bd] = peer_epoch  # noqa: SLF001
            self._log(f"[FWD] announce learned {bd} epoch={peer_epoch}")
        elif result == "noop":
            if hasattr(self._hello_mgr, "_peer_epochs"):
                self._hello_mgr._peer_epochs[bd] = peer_epoch  # noqa: SLF001

    def _try_deliver_subgroup(self, ingress_peer: str, data: bytes, hdr: dict[str, Any]) -> None:
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        if not self._check_replay(src, seq, ts_ms):
            return

        my_tag = self._hello_mgr.local_anon_id()
        try:
            parsed = parse_subgroup_packet(data)
            our_blob: bytes | None = None
            for tag, blob in parsed["cases"]:
                if tag == my_tag:
                    our_blob = blob
                    break
            if our_blob is None:
                return

            pair_key = self._pair_key(src, wire_epoch=self._current_epoch())
            if pair_key is None:
                self._log(f"[FWD] no pairwise key for {src}")
                return

            wrap_key = derive_wrap_key(pair_key, src, seq, ts_ms)
            k_msg = unwrap_msg_key(wrap_key, our_blob, aad=my_tag)
            aad = (
                routing_header_aad(parsed["routing_header"])
                + _SUBGROUP_MODE_MARKER
                + subgroup_cases_digest(parsed["cases"])
            )
            payload = decrypt_with_key(k_msg, parsed["ciphertext"], aad)
        except InvalidTag:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] subgroup decrypt failed src={src}")
            return

        n = payload[0]
        s_tags = payload[1 : 1 + _ANON_TAG_SIZE * n]
        msg = payload[1 + _ANON_TAG_SIZE * n :]
        if len(s_tags) != _ANON_TAG_SIZE * n:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] subgroup membership parse failed src={src}")
            return

        membership = [s_tags[i : i + _ANON_TAG_SIZE] for i in range(0, len(s_tags), _ANON_TAG_SIZE)]
        if my_tag not in membership:
            if self._on_decrypt_fail:
                self._on_decrypt_fail(src)
            else:
                self._log(f"[FWD] subgroup ghost membership src={src}")
            return

        text = msg.decode("utf-8", errors="replace")
        self._on_message(src, text)

    def _on_deliver(self, ingress_peer: str, plaintext: bytes, hdr: dict[str, Any]) -> None:
        _ = ingress_peer
        text = plaintext.decode("utf-8", errors="replace")
        self._on_message(hdr["src"].upper(), text)

    @staticmethod
    def _for_us(dst: str, local: str) -> bool:
        return dst == local or dst == BROADCAST_BD_ADDR

    def route_l2cap_peer(self, dst_bd_addr: str) -> str:
        """Pick an L2CAP link to reach ``dst_bd_addr`` (direct neighbor or multihop relay)."""
        dst = dst_bd_addr.upper()
        local = self._cfg.local_bd_addr.upper()
        if dst == local:
            raise RuntimeError("cannot send to yourself")
        peers = self._other_peers(exclude=None)
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        if dst in peers:
            return dst
        return peers[0]

    def _other_peers(self, *, exclude: str | None) -> list[str]:
        local = self._cfg.local_bd_addr.upper()
        ex = exclude.upper() if exclude else None
        return sorted(
            p.upper()
            for p in self._transport.connections()
            if p.upper() not in (local, ex)
        )


def _decrement_ttl(data: bytes, new_ttl: int) -> bytes:
    buf = bytearray(data)
    buf[_TTL_OFFSET] = new_ttl & 0xFF
    return bytes(buf)
