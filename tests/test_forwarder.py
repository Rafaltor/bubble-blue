from __future__ import annotations

import os
import sys
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_DATA, BubbleBlueConfig, load_config  # noqa: E402
from src.forwarding.forwarder import (  # noqa: E402
    BROADCAST_BD_ADDR,
    PacketBloomFilter,
    PacketForwarder,
)
from src.security.packet import parse_routing_header  # noqa: E402


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


def _test_cfg() -> BubbleBlueConfig:
    cfg = load_config()
    return replace(cfg, group_key=b"\x01" * 32, local_bd_addr="AA:BB:CC:DD:EE:01", ttl_max=10)


def test_bloom_filter() -> None:
    bloom = PacketBloomFilter(m_bits=1024, k_hashes=3)
    assert bloom.contains("40:D9:5A:8B:69:3F", 1) is False
    bloom.add("40:D9:5A:8B:69:3F", 1)
    assert bloom.contains("40:D9:5A:8B:69:3F", 1) is True


def test_relay_forwards_broadcast_with_decremented_ttl() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"
    relayed = transport.sent[0][1]
    assert parse_routing_header(relayed)["ttl"] == 9


def test_relay_uses_topology_when_one_connection() -> None:
    """Middle relay may only have inbound socket; topology lists the other hop."""
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=True)
    topo = frozenset({"AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"})
    fwd = PacketForwarder(cfg, transport, hello, topology=topo)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hop", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"


def test_relay_delivers_broadcast_when_ttl_is_one() -> None:
    cfg = replace(_test_cfg(), ttl_max=1)
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    messages: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: messages.append(t),
    )  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"last-hop", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert messages == ["last-hop"]
    assert transport.sent == []


def test_leaf_forwards_broadcast_via_topology() -> None:
    """Middle node with one socket but 2-hop topology must still relay chat."""
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False)
    topo = frozenset({"AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"})
    fwd = PacketForwarder(cfg, transport, hello, topology=topo)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"multihop", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"


def test_leaf_does_not_forward_without_other_hop() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", BROADCAST_BD_ADDR)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert transport.sent == []


def test_deliver_on_leaf() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False)
    messages: list[tuple[str, str]] = []

    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda s, t: messages.append((s, t)),
    )  # type: ignore[arg-type]
    pkt = fwd.build_data_packet(b"Hello via CDS", BROADCAST_BD_ADDR)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert messages == [(cfg.local_bd_addr, "Hello via CDS")]


if __name__ == "__main__":
    test_bloom_filter()
    test_relay_forwards_broadcast_with_decremented_ttl()
    test_relay_uses_topology_when_one_connection()
    test_relay_delivers_broadcast_when_ttl_is_one()
    test_leaf_forwards_broadcast_via_topology()
    test_leaf_does_not_forward_without_other_hop()
    test_deliver_on_leaf()
    print("✅ All forwarder tests passed")
