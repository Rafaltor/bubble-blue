from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from cryptography.exceptions import InvalidTag

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_DATA, load_config  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.crypto import decrypt_with_key, encrypt_with_key  # noqa: E402
from src.security.keys import BBKeyStore, derive_packet_key  # noqa: E402
from src.security.packet import (  # noqa: E402
    build_bb_packet,
    build_routing_header,
    parse_routing_header,
    routing_header_aad,
)

GROUP_KEY = b"\x01" * 32
ADDR_A = "AA:BB:CC:DD:EE:01"
ADDR_B = "AA:BB:CC:DD:EE:02"
ADDR_C = "AA:BB:CC:DD:EE:03"


def _register_pair(store_a: BBKeyStore, addr_a: str, store_b: BBKeyStore, addr_b: str) -> None:
    store_a.register_peer(addr_b, store_b.local_public_key)
    store_b.register_peer(addr_a, store_a.local_public_key)


class _FakeHelloMgr:
    def __init__(self, *, relay: bool, key_store: BBKeyStore) -> None:
        self.is_relay = relay
        self.key_store = key_store

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose


class _FakeTransport:
    def __init__(self, peers: list[str] | None = None) -> None:
        self._peers = [p.upper() for p in (peers or [])]

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:
        _ = (bd_addr, data)


def test_pairwise_encrypt_decrypt() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    _register_pair(store_a, ADDR_A, store_b, ADDR_B)

    k_pair_a = store_a.get_pair_key(ADDR_B)
    k_pair_b = store_b.get_pair_key(ADDR_A)
    assert k_pair_a is not None and k_pair_b is not None
    assert k_pair_a == k_pair_b

    src = ADDR_A
    seq = 1
    ts_ms = 1_000
    rh = build_routing_header(PKT_DATA, src, ADDR_B, ttl=10, seq=seq, ts_ms=ts_ms)
    aad = routing_header_aad(rh)

    packet_key_a = derive_packet_key(k_pair_a, src, seq, ts_ms)
    enc = encrypt_with_key(packet_key_a, b"secret msg", aad)

    packet_key_b = derive_packet_key(k_pair_b, src, seq, ts_ms)
    plain = decrypt_with_key(packet_key_b, enc["ciphertext"], aad)
    assert plain == b"secret msg"


def test_pairwise_wrong_key_raises() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_c = BBKeyStore.from_group_key(GROUP_KEY, ADDR_C)
    _register_pair(store_a, ADDR_A, store_b, ADDR_B)

    k_pair_a = store_a.get_pair_key(ADDR_B)
    assert k_pair_a is not None

    src = ADDR_A
    seq = 2
    ts_ms = 2_000
    rh = build_routing_header(PKT_DATA, src, ADDR_B, ttl=10, seq=seq, ts_ms=ts_ms)
    aad = routing_header_aad(rh)

    packet_key_a = derive_packet_key(k_pair_a, src, seq, ts_ms)
    enc = encrypt_with_key(packet_key_a, b"secret msg", aad)

    k_pair_c_wrong = store_c.get_pair_key(ADDR_A)
    assert k_pair_c_wrong is None
    store_c.register_peer(ADDR_A, store_a.local_public_key)
    k_pair_c_wrong = store_c.get_pair_key(ADDR_A)
    assert k_pair_c_wrong is not None
    assert k_pair_c_wrong != k_pair_a

    wrong_key = derive_packet_key(k_pair_c_wrong, src, seq, ts_ms)
    try:
        decrypt_with_key(wrong_key, enc["ciphertext"], aad)
    except InvalidTag:
        pass
    else:
        raise AssertionError("expected InvalidTag for wrong pairwise key")


def test_pairwise_replay_rejected() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    _register_pair(store_a, ADDR_A, store_b, ADDR_B)

    k_pair = store_a.get_pair_key(ADDR_B)
    assert k_pair is not None

    src = ADDR_A
    seq = 5
    ts_ms = time.time_ns() // 1_000_000
    rh = build_routing_header(PKT_DATA, src, ADDR_B, ttl=10, seq=seq, ts_ms=ts_ms)
    aad = routing_header_aad(rh)
    packet_key = derive_packet_key(k_pair, src, seq, ts_ms)
    enc = encrypt_with_key(packet_key, b"once", aad)
    data = build_bb_packet(rh, enc["ciphertext"])
    hdr = parse_routing_header(data)

    cfg = replace(
        load_config(),
        group_key=GROUP_KEY,
        local_bd_addr=ADDR_B,
        ttl_max=10,
    )
    hello = _FakeHelloMgr(relay=False, key_store=store_b)
    transport = _FakeTransport([])
    deliveries: list[tuple[str, str]] = []
    fwd = PacketForwarder(
        cfg,
        transport,
        hello,  # type: ignore[arg-type]
        on_message=lambda s, t: deliveries.append((s, t)),
    )

    fwd._try_deliver(ADDR_A, data, hdr)
    fwd._try_deliver(ADDR_A, data, hdr)
    assert deliveries == [(ADDR_A, "once")]


if __name__ == "__main__":
    test_pairwise_encrypt_decrypt()
    test_pairwise_wrong_key_raises()
    test_pairwise_replay_rejected()
    print("✅ private pairwise tests passed")
