from __future__ import annotations

import os
import sys
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.crypto import decrypt_from_group  # noqa: E402
from src.security.packet import (  # noqa: E402
    BROADCAST_BD_ADDR,
    parse_bb_packet,
    routing_header_aad,
)


class _FakeHelloMgr:
    def __init__(self, *, relay: bool) -> None:
        self.is_relay = relay
        self.anon_id = b"\xab" * 8
        self.table = MagicMock()

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose


class _FakeTransport:
    def __init__(self, peers: list[str]) -> None:
        self._peers = [p.upper() for p in peers]
        self.sent: list[tuple[str, bytes]] = []

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:
        self.sent.append((bd_addr.upper(), bytes(data)))


def _cfg():
    return replace(load_config(), group_key=b"\x01" * 32, local_bd_addr="AA:BB:CC:DD:EE:01", ttl_max=10)


def test_relay_decrypts_after_ttl_change() -> None:
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    fwd = PacketForwarder(cfg, transport, hello, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    pkt = fwd.build_packet(b"hop", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    wire = transport.sent[0][1]
    parsed = parse_bb_packet(wire)
    plain = decrypt_from_group(
        cfg.group_key,
        parsed["session_key_enc"],
        parsed["nonce"],
        parsed["ciphertext"],
        routing_header_aad(parsed["routing_header"]),
    )
    assert plain == b"hop"


def test_leaf_delivers_broadcast() -> None:
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False)
    got: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: got.append(t),
    )  # type: ignore[arg-type]
    fwd.handle("AA:BB:CC:DD:EE:02", fwd.build_packet(b"hi", BROADCAST_BD_ADDR))
    assert got == ["hi"]


if __name__ == "__main__":
    test_relay_decrypts_after_ttl_change()
    test_leaf_delivers_broadcast()
    print("✅ forwarder tests passed")
