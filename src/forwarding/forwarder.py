from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from cryptography.exceptions import InvalidTag

from config import PKT_DATA, BubbleBlueConfig
from src.security.crypto import decrypt_with_key, encrypt_with_key
from src.security.keys import derive_packet_key
from src.security.packet import (
    ROUTING_HEADER_SIZE,
    BROADCAST_BD_ADDR,
    build_bb_packet,
    build_routing_header,
    parse_bb_packet,
    parse_routing_header,
    routing_header_aad,
    validate_timestamp,
)

if TYPE_CHECKING:
    from src.control.hello_manager import HelloManager
    from src.transport.l2cap import L2CAPTransport

OnMessageCallback = Callable[[str, str], None]
LogCallback = Callable[[str], None]
OnDecryptFailCallback = Callable[[str], None]

_TTL_OFFSET = 13
_MAX_SEEN_PACKETS = 4096


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
        self._forwarded: set[tuple[str, int]] = set()
        self._delivered: set[tuple[str, int]] = set()
        self._fwd_lock = threading.RLock()
        self._deliver_lock = threading.RLock()
        self._seq_lock = threading.Lock()
        self._tx_seq = 0

    def _log(self, msg: str) -> None:
        if self._on_log:
            self._on_log(msg)

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._tx_seq += 1
            return self._tx_seq

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
        """
        payload = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        dst = dst_bd_addr.upper()
        src = self._cfg.local_bd_addr.upper()

        if private:
            base_key = self._hello_mgr.key_store.get_pair_key(dst)
            if base_key is None:
                raise RuntimeError(f"No pairwise key for {dst}, Hello not yet received")
        else:
            base_key = self._cfg.group_key

        seq = self._next_seq()
        ts_ms = time.time_ns() // 1_000_000
        rh = build_routing_header(PKT_DATA, src, dst, self._cfg.ttl_max, seq, ts_ms)
        packet_key = derive_packet_key(base_key, src, seq, ts_ms)
        enc = encrypt_with_key(packet_key, payload, routing_header_aad(rh))
        return build_bb_packet(rh, enc["ciphertext"])

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
            if hdr["type"] != PKT_DATA or not validate_timestamp(hdr["ts_ms"]):
                return

            local = self._cfg.local_bd_addr.upper()
            dst = hdr["dst"].upper()
            src = hdr["src"].upper()
            seq = int(hdr["seq"])

            self._hello_mgr.refresh_cds_role()
            if self._hello_mgr.is_relay:
                self._relay_then_deliver(ingress, data, hdr, src, seq, dst, local)
            elif self._for_us(dst, local):
                self._try_deliver(ingress, data, hdr)
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
    ) -> None:
        ttl = int(hdr["ttl"])
        if dst != local and ttl > 0:
            new_ttl = ttl - 1
            if new_ttl > 0:
                key = (src, seq)
                with self._fwd_lock:
                    if key not in self._forwarded:
                        self._forwarded.add(key)
                        wire = _decrement_ttl(data, new_ttl)
                        for peer in self._other_peers(exclude=ingress):
                            try:
                                self._transport.send(peer, wire)
                            except OSError as e:
                                self._log(f"[FWD] relay {peer}: {e}")

        if self._for_us(dst, local):
            self._try_deliver(ingress, data, hdr)

    def _mark_deliver_once(self, key: tuple[str, int]) -> bool:
        """Return True if this (src, seq) should be processed; False if duplicate."""
        with self._deliver_lock:
            if key in self._delivered:
                return False
            self._delivered.add(key)
            if len(self._delivered) > _MAX_SEEN_PACKETS:
                drop = len(self._delivered) - _MAX_SEEN_PACKETS // 2
                for old in list(self._delivered)[:drop]:
                    self._delivered.discard(old)
            return True

    def _try_deliver(self, ingress_peer: str, data: bytes, hdr: dict[str, Any]) -> None:
        src = hdr["src"].upper()
        seq = int(hdr["seq"])
        if not self._mark_deliver_once((src, seq)):
            return

        local = self._cfg.local_bd_addr.upper()
        dst = hdr["dst"].upper()

        if dst == local:
            base_key = self._hello_mgr.key_store.get_pair_key(src)
            if base_key is None:
                self._log(f"[FWD] no pairwise key for {src}")
                return
        else:
            base_key = self._cfg.group_key

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

    def _on_deliver(self, ingress_peer: str, plaintext: bytes, hdr: dict[str, Any]) -> None:
        _ = ingress_peer
        text = plaintext.decode("utf-8", errors="replace")
        self._on_message(hdr["src"].upper(), text)

    @staticmethod
    def _for_us(dst: str, local: str) -> bool:
        return dst == local or dst == BROADCAST_BD_ADDR

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
