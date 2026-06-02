from __future__ import annotations

import os
import sys
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_DATA, BubbleBlueConfig, load_config  # noqa: E402
from src.forwarding.forwarder import ForwardDedup, PacketForwarder  # noqa: E402
from src.security.packet import parse_routing_header  # noqa: E402


class _FakeHelloMgr:
    def __init__(self, *, relay: bool) -> None:
        self.is_relay = relay
        self.anon_id = b"\xab" * 8
        self.table = MagicMock()


class _FakeTransport:
    def __init__(self, peers: list[str]) -> None:
        self._peers = [p.upper() for p in peers]
        self.sent: list[tuple[str, bytes]] = []

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:
        self.sent.append((bd_addr.upper(), bytes(data)))


def _test_cfg() -> BubbleBlueConfig:
    cfg = load_config()
    return replace(cfg, group_key=b"\x01" * 32, local_bd_addr="AA:BB:CC:DD:EE:01")


def test_forward_dedup() -> None:
    d = ForwardDedup(max_entries=4)
    assert d.mark("40:D9:5A:8B:69:3F", 1) is True
    assert d.mark("40:D9:5A:8B:69:3F", 1) is False
    assert d.mark("40:D9:5A:8B:69:3F", 2) is True


def test_relay_forwards_except_ingress() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", "AA:BB:CC:DD:EE:03")
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"
    assert transport.sent[0][1] == pkt


def test_leaf_does_not_forward() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=False)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", "AA:BB:CC:DD:EE:03")
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert transport.sent == []


def test_deliver_when_dst_is_local() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False)
    delivered: list[bytes] = []

    def on_deliver(_peer: str, plaintext: bytes, _hdr: dict) -> None:
        delivered.append(plaintext)

    fwd = PacketForwarder(cfg, transport, hello, on_deliver=on_deliver)  # type: ignore[arg-type]
    pkt = fwd.build_data_packet(b"Hello via CDS", cfg.local_bd_addr)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert delivered == [b"Hello via CDS"]
    assert transport.sent == []


def test_build_packet_header() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport([])
    hello = _FakeHelloMgr(relay=False)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]
    pkt = fwd.build_data_packet("x", "AA:BB:CC:DD:EE:99")
    hdr = parse_routing_header(pkt)
    assert hdr["type"] == PKT_DATA
    assert hdr["src"] == cfg.local_bd_addr
    assert hdr["dst"] == "AA:BB:CC:DD:EE:99"


if __name__ == "__main__":
    test_forward_dedup()
    test_relay_forwards_except_ingress()
    test_leaf_does_not_forward()
    test_deliver_when_dst_is_local()
    test_build_packet_header()
    print("✅ All forwarder tests passed")
