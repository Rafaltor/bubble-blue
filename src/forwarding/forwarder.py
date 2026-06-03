from __future__ import annotations

import hashlib
import threading
from typing import TYPE_CHECKING, Callable

from cryptography.exceptions import InvalidTag

from config import PKT_DATA, BubbleBlueConfig
from src.security.crypto import decrypt_from_group, encrypt_for_group
from src.security.packet import (
    ROUTING_HEADER_SIZE,
    build_bb_packet,
    build_routing_header,
    parse_bb_packet,
    parse_routing_header,
    validate_timestamp,
)

if TYPE_CHECKING:
    from src.control.hello_manager import HelloManager
    from src.transport.l2cap import L2CAPTransport

OnMessageCallback = Callable[[str, str], None]

BROADCAST_BD_ADDR = "FF:FF:FF:FF:FF:FF"
_TTL_OFFSET = 13


class PacketBloomFilter:
    """Dedup (src, seq) before forwarding — per-node, forward path only."""

    def __init__(self, *, m_bits: int = 65536, k_hashes: int = 4) -> None:
        self._m = max(64, int(m_bits))
        self._k = max(1, min(8, int(k_hashes)))
        self._bits = bytearray((self._m + 7) // 8)
        self._lock = threading.RLock()

    def _indexes(self, key: bytes) -> list[int]:
        indexes: list[int] = []
        seed = key
        for _ in range(self._k):
            digest = hashlib.blake2b(seed, digest_size=8).digest()
            indexes.append(int.from_bytes(digest, "big") % self._m)
            seed = digest
        return indexes

    def _get_bit(self, idx: int) -> bool:
        byte_i, bit_i = divmod(idx, 8)
        return bool(self._bits[byte_i] & (1 << bit_i))

    def _set_bit(self, idx: int) -> None:
        byte_i, bit_i = divmod(idx, 8)
        self._bits[byte_i] |= 1 << bit_i

    @staticmethod
    def _key(src_addr: str, seq: int) -> bytes:
        return f"{src_addr.upper()}:{int(seq)}".encode()

    def contains(self, src_addr: str, seq: int) -> bool:
        key = self._key(src_addr, seq)
        with self._lock:
            return all(self._get_bit(i) for i in self._indexes(key))

    def add(self, src_addr: str, seq: int) -> None:
        key = self._key(src_addr, seq)
        with self._lock:
            for i in self._indexes(key):
                self._set_bit(i)


class PacketForwarder:
    """
    PKT_DATA: RELAY nodes forward first (raw bytes, TTL--), then try local chat delivery.
    LEAF nodes only deliver when dst is us or broadcast.
    """

    def __init__(
        self,
        cfg: BubbleBlueConfig,
        transport: L2CAPTransport,
        hello_mgr: HelloManager,
        *,
        topology: frozenset[str] | None = None,
        on_message: OnMessageCallback | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._hello_mgr = hello_mgr
        self._topology = frozenset(topology) if topology else None
        self._on_message = on_message or _default_on_message
        self._forward_bloom = PacketBloomFilter()
        self._delivered: set[tuple[str, int]] = set()
        self._delivered_lock = threading.RLock()
        self._seq_lock = threading.Lock()
        self._tx_seq = 0

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._tx_seq += 1
            return self._tx_seq

    def is_relay(self) -> bool:
        self._hello_mgr.refresh_cds_role()
        return self._hello_mgr.is_relay

    def build_data_packet(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str = BROADCAST_BD_ADDR,
    ) -> bytes:
        if isinstance(plaintext, str):
            payload = plaintext.encode("utf-8")
        else:
            payload = bytes(plaintext)

        rh = build_routing_header(
            PKT_DATA,
            self._cfg.local_bd_addr,
            dst_bd_addr.upper(),
            ttl=self._cfg.ttl_max,
            seq=self._next_seq(),
        )
        enc = encrypt_for_group(self._cfg.group_key, payload, rh)
        return build_bb_packet(
            rh,
            enc["session_key_enc"],
            enc["nonce"],
            enc["ciphertext"],
        )

    def broadcast(self, plaintext: str | bytes) -> None:
        """Chat: one broadcast packet (dst=FF:FF:…) sent on every L2CAP / topology link."""
        packet = self.build_data_packet(plaintext, BROADCAST_BD_ADDR)
        targets = self._all_peer_targets(exclude=None)
        if not targets:
            raise RuntimeError("No L2CAP peers; cannot send chat message")
        for peer in targets:
            self._transport.send(peer, packet)
            print(f"[FWD] chat → {peer} dst={BROADCAST_BD_ADDR} bytes={len(packet)}", flush=True)

    def send_data(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str = BROADCAST_BD_ADDR,
        *,
        l2cap_peer: str | None = None,
    ) -> None:
        packet = self.build_data_packet(plaintext, dst_bd_addr)
        peer = (l2cap_peer or self._cfg.remote_bd_addr).upper()
        if peer in ("00:00:00:00:00:00", self._cfg.local_bd_addr):
            targets = self._all_peer_targets(exclude=None)
            if not targets:
                raise RuntimeError("No L2CAP peers connected; cannot send PKT_DATA")
            peer = targets[0]
        self._transport.send(peer, packet)

    def handle(self, ingress_peer: str, data: bytes) -> None:
        ingress = ingress_peer.upper()
        try:
            if len(data) < ROUTING_HEADER_SIZE:
                return
            hdr = parse_routing_header(data)
            if hdr["type"] != PKT_DATA:
                return
            if not validate_timestamp(hdr["ts_ms"]):
                print(f"[FWD] drop from={ingress}: bad timestamp", flush=True)
                return

            local = self._cfg.local_bd_addr.upper()
            dst = hdr["dst"].upper()
            src = hdr["src"].upper()
            seq = int(hdr["seq"])

            self._hello_mgr.refresh_cds_role()
            outbound = self._all_peer_targets(exclude=ingress)

            # Multihop chat: forward broadcast to every other hop in topology,
            # even when CDS says LEAF (common when only one L2CAP socket is up).
            if dst == BROADCAST_BD_ADDR and outbound:
                self._handle_relay(ingress, data, hdr, src, seq, dst, local)
            elif self._hello_mgr.is_relay:
                self._handle_relay(ingress, data, hdr, src, seq, dst, local)
            else:
                self._handle_leaf(data, hdr, src, seq, dst, local)

        except Exception as e:  # noqa: BLE001
            print(f"[FWD] rx from={ingress} error={e}", flush=True)

    def _handle_relay(
        self,
        ingress: str,
        data: bytes,
        hdr: dict,
        src: str,
        seq: int,
        dst: str,
        local: str,
    ) -> None:
        ttl = int(hdr["ttl"])
        if ttl == 0:
            print(f"[FWD] drop relay src={src} seq={seq}: ttl=0", flush=True)
            return

        new_ttl = ttl - 1

        # 1) Forward first (broadcast or not for us)
        if self._should_relay(dst, local) and new_ttl > 0:
            if self._forward_bloom.contains(src, seq):
                print(f"[FWD] skip forward src={src} seq={seq}: already relayed", flush=True)
            else:
                self._forward_bloom.add(src, seq)
                out = _packet_with_ttl(data, new_ttl)
                self._relay(ingress, out, hdr)
        elif self._should_relay(dst, local):
            print(f"[FWD] drop forward src={src} seq={seq}: ttl exhausted after decrement", flush=True)

        # 2) Local chat delivery (broadcast or unicast to us)
        if self._should_deliver(dst, local):
            self._try_deliver(src, seq, data)

    def _handle_leaf(
        self,
        data: bytes,
        hdr: dict,
        src: str,
        seq: int,
        dst: str,
        local: str,
    ) -> None:
        if self._should_deliver(dst, local):
            self._try_deliver(src, seq, data)

    @staticmethod
    def _should_deliver(dst: str, local: str) -> bool:
        return dst == local or dst == BROADCAST_BD_ADDR

    @staticmethod
    def _should_relay(dst: str, local: str) -> bool:
        return dst != local

    def _try_deliver(self, src: str, seq: int, data: bytes) -> None:
        key = (src, seq)
        with self._delivered_lock:
            if key in self._delivered:
                return
            self._delivered.add(key)

        try:
            parsed = parse_bb_packet(data)
            plaintext = decrypt_from_group(
                self._cfg.group_key,
                parsed["session_key_enc"],
                parsed["nonce"],
                parsed["ciphertext"],
                parsed["routing_header"],
            )
        except InvalidTag:
            return

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(plaintext)
        self._on_message(src, text)

    def _all_peer_targets(self, *, exclude: str | None) -> list[str]:
        """L2CAP connections plus topology allowlist (for multihop relay/send)."""
        local = self._cfg.local_bd_addr.upper()
        ex = exclude.upper() if exclude else None
        out: set[str] = set()
        for p in self._transport.connections():
            pu = p.upper()
            if pu != local and pu != ex:
                out.add(pu)
        if self._topology:
            for p in self._topology:
                if p != local and p != ex:
                    out.add(p)
        return sorted(out)

    def _relay(self, ingress: str, data: bytes, hdr: dict) -> None:
        targets = self._all_peer_targets(exclude=ingress)
        if not targets:
            print(
                f"[FWD] relay FAILED src={hdr['src']} seq={hdr['seq']}: "
                f"no peers except ingress={ingress} "
                f"(connections={self._transport.connections()} "
                f"topology={sorted(self._topology) if self._topology else None})",
                flush=True,
            )
            return

        cds = "CDS" if self._hello_mgr.is_relay else "topology"
        for peer in targets:
            try:
                self._transport.send(peer, data)
                print(
                    f"[FWD] relay ({cds}) → {peer} src={hdr['src']} dst={hdr['dst']} "
                    f"seq={hdr['seq']} ttl={data[_TTL_OFFSET]}",
                    flush=True,
                )
            except OSError as e:
                print(f"[FWD] relay send failed peer={peer}: {e}", flush=True)


def _packet_with_ttl(data: bytes, new_ttl: int) -> bytes:
    buf = bytearray(data)
    buf[_TTL_OFFSET] = new_ttl & 0xFF
    return bytes(buf)


def _default_on_message(sender_bd_addr: str, text: str) -> None:
    print(f"[{sender_bd_addr}] {text}", flush=True)
