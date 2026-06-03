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

# Broadcast destination — RELAY forwards; unicast selective routing TBD.
BROADCAST_BD_ADDR = "FF:FF:FF:FF:FF:FF"

# TTL byte offset: type(1) + src(6) + dst(6) = 13
_TTL_OFFSET = 13


class PacketBloomFilter:
    """Probabilistic (src, seq) deduplication for relay and leaf paths."""

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
        """True if (src, seq) was already seen (may be false positive)."""
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
    PKT_DATA receive path.

    RELAY: Bloom dedup → mark seen → decrement TTL → forward wire copy →
           try local decrypt (on_message / silent InvalidTag).

    LEAF: Bloom dedup → mark seen → try local decrypt only.
    """

    def __init__(
        self,
        cfg: BubbleBlueConfig,
        transport: L2CAPTransport,
        hello_mgr: HelloManager,
        *,
        on_message: OnMessageCallback | None = None,
        on_deliver: OnMessageCallback | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._hello_mgr = hello_mgr
        self._on_message = on_message or on_deliver or _default_on_message
        self._bloom = PacketBloomFilter()
        self._seq_lock = threading.Lock()
        self._tx_seq = 0

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._tx_seq += 1
            return self._tx_seq

    def is_relay(self) -> bool:
        return self._hello_mgr.is_relay

    def build_data_packet(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str = BROADCAST_BD_ADDR,
    ) -> bytes:
        """Build a signed/encrypted PKT_DATA BB packet for transmission."""
        if isinstance(plaintext, str):
            payload = plaintext.encode("utf-8")
        else:
            payload = bytes(plaintext)

        dst = dst_bd_addr.upper()
        rh = build_routing_header(
            PKT_DATA,
            self._cfg.local_bd_addr,
            dst,
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

    def send_data(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str = BROADCAST_BD_ADDR,
        *,
        l2cap_peer: str | None = None,
    ) -> None:
        """Send PKT_DATA to ``l2cap_peer`` (or first connected peer)."""
        packet = self.build_data_packet(plaintext, dst_bd_addr)
        peer = (l2cap_peer or self._cfg.remote_bd_addr).upper()
        if peer in ("00:00:00:00:00:00", self._cfg.local_bd_addr):
            peers = self._transport.connections()
            if not peers:
                raise RuntimeError("No L2CAP peers connected; cannot send PKT_DATA")
            peer = peers[0]
        self._transport.send(peer, packet)
        print(
            f"[FWD] sent PKT_DATA l2cap_peer={peer} dst={dst_bd_addr.upper()} "
            f"bytes={len(packet)}",
            flush=True,
        )

    def handle(self, ingress_peer: str, data: bytes) -> None:
        """Process an incoming PKT_DATA frame from ``ingress_peer``."""
        ingress = ingress_peer.upper()

        try:
            if len(data) < ROUTING_HEADER_SIZE:
                return
            hdr = parse_routing_header(data)
            if hdr["type"] != PKT_DATA:
                return

            if not validate_timestamp(hdr["ts_ms"]):
                print(
                    f"[FWD] rejected from={ingress}: timestamp out of window",
                    flush=True,
                )
                return

            src = hdr["src"].upper()
            seq = int(hdr["seq"])

            if self._bloom.contains(src, seq):
                return

            self._bloom.add(src, seq)

            if self._hello_mgr.is_relay:
                self._handle_relay(ingress, data, hdr)
            else:
                self._handle_leaf(data, hdr)

        except Exception as e:  # noqa: BLE001
            print(f"[FWD] rx from={ingress} bytes={len(data)} error={e}", flush=True)

    def _handle_relay(self, ingress_peer: str, data: bytes, hdr: dict) -> None:
        """Forward first, then attempt local delivery."""
        ttl = int(hdr["ttl"])
        if ttl == 0:
            return

        new_ttl = ttl - 1
        if new_ttl == 0:
            return

        if self._should_forward(hdr["dst"]):
            out = _packet_with_ttl(data, new_ttl)
            self._relay(ingress_peer, out, hdr)

        self._try_deliver(hdr["src"], data)

    def _handle_leaf(self, data: bytes, hdr: dict) -> None:
        """Decrypt locally only; no relay."""
        self._try_deliver(hdr["src"], data)

    def _should_forward(self, dst: str) -> bool:
        """Broadcast always; unicast selective forwarding not implemented yet."""
        return dst.upper() == BROADCAST_BD_ADDR

    def _try_deliver(self, src: str, data: bytes) -> None:
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

        self._on_message(src.upper(), text)

    def _relay(self, ingress_peer: str, data: bytes, hdr: dict) -> None:
        peers = [p.upper() for p in self._transport.connections() if p.upper() != ingress_peer]
        if not peers:
            return

        for peer in peers:
            try:
                self._transport.send(peer, data)
                print(
                    f"[FWD] relay → {peer} src={hdr['src']} dst={hdr['dst']} "
                    f"seq={hdr['seq']} ttl={data[_TTL_OFFSET]}",
                    flush=True,
                )
            except OSError as e:
                print(f"[FWD] relay send failed peer={peer}: {e}", flush=True)


def _packet_with_ttl(data: bytes, new_ttl: int) -> bytes:
    """Copy wire packet with decremented TTL (only routing-header TTL changes)."""
    if len(data) < ROUTING_HEADER_SIZE:
        raise ValueError("packet too short")
    if not (0 <= new_ttl <= 0xFF):
        raise ValueError("ttl out of range")
    buf = bytearray(data)
    buf[_TTL_OFFSET] = new_ttl
    return bytes(buf)


def _default_on_message(sender_bd_addr: str, text: str) -> None:
    print(f"[{sender_bd_addr}] {text}", flush=True)
