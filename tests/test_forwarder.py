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
    assert bloom.contains("40:D9:5A:8B:69:3F", 2) is False


def test_relay_forwards_broadcast_with_decremented_ttl() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", BROADCAST_BD_ADDR)
    assert parse_routing_header(pkt)["ttl"] == 10
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"
    relayed = transport.sent[0][1]
    assert relayed != pkt
    assert parse_routing_header(relayed)["ttl"] == 9
    assert relayed[26:] == pkt[26:]


def test_relay_forwards_unicast_dst() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", "AA:BB:CC:DD:EE:99")
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert len(transport.sent) == 1
    assert transport.sent[0][0] == "AA:BB:CC:DD:EE:03"


def test_relay_skips_deliver_for_unicast_to_other() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    messages: list[tuple[str, str]] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda s, t: messages.append((s, t)),
    )  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hello", "AA:BB:CC:DD:EE:99")
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert messages == []


def test_relay_delivers_broadcast_locally() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True)
    messages: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: messages.append(t),
    )  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"group", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert messages == ["group"]
    assert len(transport.sent) == 1


def test_leaf_does_not_forward() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
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

    def on_message(sender: str, text: str) -> None:
        messages.append((sender, text))

    fwd = PacketForwarder(cfg, transport, hello, on_message=on_message)  # type: ignore[arg-type]
    pkt = fwd.build_data_packet(b"Hello via CDS", BROADCAST_BD_ADDR)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    assert messages == [(cfg.local_bd_addr, "Hello via CDS")]
    assert transport.sent == []


def test_broadcast_sends_to_all_peers() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=False)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]

    fwd.broadcast("hi")
    assert len(transport.sent) == 2
    assert transport.sent[0][1] == transport.sent[1][1]
    assert parse_routing_header(transport.sent[0][1])["dst"] == BROADCAST_BD_ADDR


def test_leaf_skips_unicast_to_other() -> None:
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

    pkt = fwd.build_data_packet(b"nope", "AA:BB:CC:DD:EE:99")
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert messages == []


def test_build_packet_broadcast_default() -> None:
    cfg = _test_cfg()
    transport = _FakeTransport([])
    hello = _FakeHelloMgr(relay=False)
    fwd = PacketForwarder(cfg, transport, hello)  # type: ignore[arg-type]
    pkt = fwd.build_data_packet("x")
    hdr = parse_routing_header(pkt)
    assert hdr["type"] == PKT_DATA
    assert hdr["src"] == cfg.local_bd_addr
    assert hdr["dst"] == BROADCAST_BD_ADDR


if __name__ == "__main__":
    test_bloom_filter()
    test_relay_forwards_broadcast_with_decremented_ttl()
    test_relay_forwards_unicast_dst()
    test_relay_skips_deliver_for_unicast_to_other()
    test_relay_delivers_broadcast_locally()
    test_leaf_does_not_forward()
    test_deliver_on_leaf()
    test_broadcast_sends_to_all_peers()
    test_leaf_skips_unicast_to_other()
    test_build_packet_broadcast_default()
    print("✅ All forwarder tests passed")
