from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Callable

from cryptography.exceptions import InvalidTag

from config import PKT_DATA, BubbleBlueConfig
from src.security.crypto import decrypt_from_group, encrypt_for_group
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

_TTL_OFFSET = 13


class PacketForwarder:
    """PKT_DATA: relay raw packets (TTL--), deliver chat when dst is us or broadcast."""

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
        self._forwarded: set[tuple[str, int]] = set()
        self._fwd_lock = threading.RLock()
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
        enc = encrypt_for_group(self._cfg.group_key, payload, routing_header_aad(rh))
        return build_bb_packet(
            rh,
            enc["session_key_enc"],
            enc["nonce"],
            enc["ciphertext"],
        )

    def broadcast(self, plaintext: str | bytes) -> None:
        packet = self.build_data_packet(plaintext, BROADCAST_BD_ADDR)
        for peer in self._peer_targets(exclude=None):
            self._transport.send(peer, packet)

    def send_data(
        self,
        plaintext: str | bytes,
        dst_bd_addr: str = BROADCAST_BD_ADDR,
        *,
        l2cap_peer: str | None = None,
    ) -> None:
        packet = self.build_data_packet(plaintext, dst_bd_addr)
        peer = (l2cap_peer or "").upper()
        if not peer or peer in ("00:00:00:00:00:00", self._cfg.local_bd_addr):
            targets = self._peer_targets(exclude=None)
            if not targets:
                raise RuntimeError("No L2CAP peers connected")
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
                return

            local = self._cfg.local_bd_addr.upper()
            dst = hdr["dst"].upper()
            src = hdr["src"].upper()
            seq = int(hdr["seq"])

            self._hello_mgr.refresh_cds_role()
            outbound = self._peer_targets(exclude=ingress)
            use_relay = self._hello_mgr.is_relay or (
                dst == BROADCAST_BD_ADDR and bool(outbound)
            )

            if use_relay:
                self._relay_packet(ingress, data, hdr, src, seq, dst, local)
            elif dst == local or dst == BROADCAST_BD_ADDR:
                self._deliver(src, data)

        except Exception as e:  # noqa: BLE001
            print(f"[FWD] error from={ingress}: {e}", flush=True)

    def _relay_packet(
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
            return

        new_ttl = ttl - 1
        if dst != local and new_ttl > 0:
            key = (src, seq)
            with self._fwd_lock:
                if key not in self._forwarded:
                    self._forwarded.add(key)
                    out = _packet_with_ttl(data, new_ttl)
                    for peer in self._peer_targets(exclude=ingress):
                        try:
                            self._transport.send(peer, out)
                            print(f"[FWD] relay → {peer} seq={seq} ttl={new_ttl}", flush=True)
                        except OSError as e:
                            print(f"[FWD] relay failed {peer}: {e}", flush=True)

        if dst == local or dst == BROADCAST_BD_ADDR:
            self._deliver(src, data)

    def _deliver(self, src: str, data: bytes) -> None:
        try:
            parsed = parse_bb_packet(data)
            plaintext = decrypt_from_group(
                self._cfg.group_key,
                parsed["session_key_enc"],
                parsed["nonce"],
                parsed["ciphertext"],
                routing_header_aad(parsed["routing_header"]),
            )
        except InvalidTag:
            print(f"[FWD] decrypt failed from={src} (check group key)", flush=True)
            return

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(plaintext)
        self._on_message(src.upper(), text)

    def _peer_targets(self, *, exclude: str | None) -> list[str]:
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


def _packet_with_ttl(data: bytes, new_ttl: int) -> bytes:
    buf = bytearray(data)
    buf[_TTL_OFFSET] = new_ttl & 0xFF
    return bytes(buf)


def _default_on_message(sender_bd_addr: str, text: str) -> None:
    print(f"[{sender_bd_addr}] {text}", flush=True)
