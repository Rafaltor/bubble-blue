from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.crypto import decrypt_with_key  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import derive_packet_key  # noqa: E402
from src.security.packet import (  # noqa: E402
    BROADCAST_BD_ADDR,
    parse_bb_packet,
    routing_header_aad,
)


class _FakeKeyStore:
    def __init__(self) -> None:
        self.local_public_key = os.urandom(32)

    def get_pair_key(self, bd_addr: str) -> bytes | None:
        _ = bd_addr
        return b"\x02" * 32


class _FakeHelloMgr:
    def __init__(self, *, relay: bool, group_key: bytes | None = None) -> None:
        self.is_relay = relay
        self.anon_id = b"\xab" * 8
        self.table = MagicMock()
        self.key_store = _FakeKeyStore()
        gk = group_key if group_key is not None else b"\x01" * 32
        _fd, path = tempfile.mkstemp(prefix="bb-epoch-test-")
        os.close(_fd)
        self.epoch_store = EpochStore(
            gk, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01"
        )

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose

    def local_anon_id(self) -> bytes:
        return self.anon_id

    def anon_id_for(self, _bd: str) -> bytes:
        return b"\xab" * 8

    def get_peer_epoch(self, _bd: str) -> int:
        return 0


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
    hello = _FakeHelloMgr(relay=True, group_key=cfg.group_key)
    fwd = PacketForwarder(cfg, transport, hello, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    pkt = fwd.build_data_packet(b"hop", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)

    wire = transport.sent[0][1]
    parsed = parse_bb_packet(wire)
    ph = parsed["parsed_header"]
    packet_key = derive_packet_key(cfg.group_key, ph["src"], ph["seq"], ph["ts_ms"])
    plain = decrypt_with_key(
        packet_key,
        parsed["ciphertext"],
        routing_header_aad(parsed["routing_header"]),
    )
    assert plain == b"hop"


def test_leaf_delivers_broadcast() -> None:
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False, group_key=cfg.group_key)
    got: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: got.append(t),
    )  # type: ignore[arg-type]
    fwd.handle("AA:BB:CC:DD:EE:02", fwd.build_data_packet(b"hi", BROADCAST_BD_ADDR))
    assert got == ["hi"]


def test_dedup_same_packet_twice() -> None:
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False, group_key=cfg.group_key)
    got: list[str] = []
    fails: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: got.append(t),
        on_decrypt_fail=lambda s: fails.append(s),
    )  # type: ignore[arg-type]
    pkt = fwd.build_data_packet(b"once", BROADCAST_BD_ADDR)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert got == ["once"]
    assert fails == []


def test_leaf_with_two_peers_relays_as_bridge() -> None:
    """Sparse BLE: leaf with ≥2 L2CAP links still bridges until CDS is elected."""
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=False, group_key=cfg.group_key)
    got: list[str] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,
        on_message=lambda _s, t: got.append(t),
    )  # type: ignore[arg-type]
    pkt = fwd.build_data_packet(b"bridge", BROADCAST_BD_ADDR)
    transport.sent.clear()
    fwd.handle("AA:BB:CC:DD:EE:02", pkt)
    assert got == ["bridge"]
    assert len(transport.sent) >= 1


def test_arq_cds_replays_cached_data() -> None:
    from config import PKT_ARQ
    from src.forwarding.arq import build_arq_body
    from src.security.packet import build_routing_header

    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"])
    hello = _FakeHelloMgr(relay=True, group_key=cfg.group_key)
    fwd = PacketForwarder(cfg, transport, hello, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    data_pkt = fwd.build_data_packet(b"miss", BROADCAST_BD_ADDR)
    hdr = __import__("src.security.packet", fromlist=["parse_routing_header"]).parse_routing_header(
        data_pkt
    )
    fwd._arq.store_packet(hdr["src"], int(hdr["seq"]), data_pkt)
    transport.sent.clear()

    arq_rh = build_routing_header(
        PKT_ARQ,
        "AA:BB:CC:DD:EE:02",
        BROADCAST_BD_ADDR,
        5,
        99,
        hdr["ts_ms"],
    )
    arq_pkt = arq_rh + build_arq_body(hdr["src"], int(hdr["seq"]))
    fwd.handle("AA:BB:CC:DD:EE:02", arq_pkt)
    assert any(wire == data_pkt for _peer, wire in transport.sent)


def test_private_message_unknown_peer() -> None:
    cfg = _cfg()
    transport = _FakeTransport(["AA:BB:CC:DD:EE:02"])
    hello = _FakeHelloMgr(relay=False, group_key=cfg.group_key)
    hello.key_store.get_pair_key = lambda _bd, epoch=0: None  # type: ignore[method-assign, assignment]
    fwd = PacketForwarder(cfg, transport, hello, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    try:
        fwd.build_data_packet(b"secret", "AA:BB:CC:DD:EE:02", private=True)
        raise AssertionError("expected RuntimeError for unknown pairwise key")
    except RuntimeError as e:
        assert "No pairwise key" in str(e)


if __name__ == "__main__":
    test_relay_decrypts_after_ttl_change()
    test_leaf_delivers_broadcast()
    test_dedup_same_packet_twice()
    test_private_message_unknown_peer()
    print("✅ forwarder tests passed")
