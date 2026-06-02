from __future__ import annotations

import threading
from collections import deque
from typing import TYPE_CHECKING, Callable

from config import PKT_DATA, BubbleBlueConfig
from src.security.crypto import decrypt_from_group, encrypt_for_group
from src.security.packet import (
    build_bb_packet,
    build_routing_header,
    parse_bb_packet,
    parse_routing_header,
    validate_timestamp,
)
from src.security.replay import ReplayFilter

if TYPE_CHECKING:
    from src.control.hello_manager import HelloManager
    from src.transport.l2cap import L2CAPTransport

DeliverCallback = Callable[[str, bytes, dict], None]


class ForwardDedup:
    """
    Bounded (src, seq) cache so a relay does not forward the same packet twice.

    Separate from ReplayFilter: ingress uses ReplayFilter for security;
    this guards the forward path if the same packet is reconsidered.
    """

    def __init__(self, *, max_entries: int = 4096) -> None:
        self._max = max(1, int(max_entries))
        self._lock = threading.RLock()
        self._seen: dict[tuple[str, int], None] = {}
        self._order: deque[tuple[str, int]] = deque()

    def mark(self, src_addr: str, seq: int) -> bool:
        """Return True if this (src, seq) is new; False if already forwarded."""
        key = (str(src_addr).upper(), int(seq))
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = None
            self._order.append(key)
            while len(self._order) > self._max:
                old = self._order.popleft()
                self._seen.pop(old, None)
            return True


class PacketForwarder:
    """
    PKT_DATA receive path: validate, deliver locally, relay if CDS RELAY.

    RELAY: flood to all L2CAP peers except ingress (opaque wire copy).
    LEAF: decrypt and deliver only when dst is this node.
    """

    def __init__(
        self,
        cfg: BubbleBlueConfig,
        transport: L2CAPTransport,
        hello_mgr: HelloManager,
        *,
        on_deliver: DeliverCallback | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._hello_mgr = hello_mgr
        self._on_deliver = on_deliver or _default_deliver
        self._replay = ReplayFilter()
        self._forward_dedup = ForwardDedup()
        self._seq_lock = threading.Lock()
        self._tx_seq = 0

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._tx_seq += 1
            return self._tx_seq

    def is_relay(self) -> bool:
        return self._hello_mgr.is_relay

    def build_data_packet(self, plaintext: str | bytes, dst_bd_addr: str) -> bytes:
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

    def send_data(self, plaintext: str | bytes, dst_bd_addr: str, *, l2cap_peer: str | None = None) -> None:
        """
        Send PKT_DATA to ``l2cap_peer`` (or first connected peer).

        Routing header ``dst`` may differ from the L2CAP hop (multihop).
        """
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
            if len(data) < 26:
                raise ValueError("too short for routing header")
            hdr = parse_routing_header(data)
            if hdr["type"] != PKT_DATA:
                return

            if not validate_timestamp(hdr["ts_ms"]):
                print(
                    f"[FWD] rejected from={ingress}: timestamp out of window",
                    flush=True,
                )
                return

            if not self._replay.check_and_update(hdr["src"], hdr["seq"]):
                print(f"[FWD] rejected from={ingress}: replay", flush=True)
                return

            local = self._cfg.local_bd_addr
            dst = hdr["dst"].upper()
            is_relay = self._is_relay_now()

            if dst == local:
                self._try_deliver(ingress, data, hdr)

            if not is_relay:
                return

            if dst == local:
                # Destination is us; no onward relay.
                return

            if not self._forward_dedup.mark(hdr["src"], hdr["seq"]):
                print(
                    f"[FWD] skip duplicate forward src={hdr['src']} seq={hdr['seq']}",
                    flush=True,
                )
                return

            self._relay(ingress, data, hdr)

        except Exception as e:  # noqa: BLE001
            print(f"[FWD] rx from={ingress} bytes={len(data)} error={e}", flush=True)

    def _is_relay_now(self) -> bool:
        return self._hello_mgr.is_relay

    def _try_deliver(self, ingress_peer: str, data: bytes, hdr: dict) -> None:
        try:
            parsed = parse_bb_packet(data)
            plaintext = decrypt_from_group(
                self._cfg.group_key,
                parsed["session_key_enc"],
                parsed["nonce"],
                parsed["ciphertext"],
                parsed["routing_header"],
            )
            self._on_deliver(ingress_peer, plaintext, hdr)
        except Exception as e:  # noqa: BLE001
            print(f"[FWD] deliver failed from={ingress_peer}: {e}", flush=True)

    def _relay(self, ingress_peer: str, data: bytes, hdr: dict) -> None:
        peers = [p.upper() for p in self._transport.connections() if p.upper() != ingress_peer]
        if not peers:
            print(f"[FWD] relay skipped: no peers besides ingress={ingress_peer}", flush=True)
            return

        for peer in peers:
            try:
                self._transport.send(peer, data)
                print(
                    f"[FWD] relay → {peer} src={hdr['src']} dst={hdr['dst']} "
                    f"seq={hdr['seq']} ttl={hdr['ttl']}",
                    flush=True,
                )
            except OSError as e:
                print(f"[FWD] relay send failed peer={peer}: {e}", flush=True)


def _default_deliver(ingress_peer: str, plaintext: bytes, hdr: dict) -> None:
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        text = repr(plaintext)
    print(
        f"[APP] DATA delivered from={ingress_peer} src={hdr['src']} dst={hdr['dst']} "
        f"ttl={hdr['ttl']} seq={hdr['seq']} text={text}",
        flush=True,
    )
