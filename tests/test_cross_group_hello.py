from __future__ import annotations

"""
Cross-group Hello: anon_ids are learned from wire, never recomputed with a foreign key.

Two nodes with different bootstrap group keys exchange Hellos over L2CAP. Each must:
  - see the other in 1-hop
  - find its own anon_id in the other's advertised neighbor list (symmetry)
  - build a coherent 2-hop view
  - get parse_hello_private == None (not in the other's group)
"""

import os
import sys
import tempfile
from dataclasses import replace

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.control.hello import (  # noqa: E402
    build_hello,
    compute_anon_id,
    parse_hello_private,
    parse_hello_public,
)
from src.control.hello_manager import HelloManager  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402

_GK_A = b"\x01" * 32
_GK_B = b"\x02" * 32
_ADDR_A = "40:D9:5A:8B:69:3F"
_ADDR_B = "14:B5:CD:E2:49:ED"


class _FakeTransport:
    def __init__(self, peers: list[str]) -> None:
        self._peers = [p.upper() for p in peers]
        self.sent: list[tuple[str, bytes]] = []

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:
        self.sent.append((bd_addr.upper(), bytes(data)))


def _make_mgr(
    *,
    group_key: bytes,
    local_bd: str,
    peers: list[str],
) -> tuple[HelloManager, _FakeTransport]:
    cfg = replace(
        load_config(),
        group_key=group_key,
        local_bd_addr=local_bd.upper(),
        remote_bd_addr="00:00:00:00:00:00",
        hello_interval_s=1,
        neighbor_timeout_s=30,
    )
    transport = _FakeTransport(peers)
    key_store = BBKeyStore.from_group_key(group_key, local_bd.upper())
    fd, path = tempfile.mkstemp(prefix="bb-cross-epoch-")
    os.close(fd)
    epoch_store = EpochStore(group_key, persist_path=path, local_bd_addr=local_bd.upper())
    mgr = HelloManager(cfg, transport, key_store, epoch_store, quiet=True)
    return mgr, transport


def _build_pkt(
    mgr: HelloManager,
    *,
    group_key: bytes,
    seq: int,
) -> bytes:
    return build_hello(
        mgr.epoch_store.current_group_key(),
        mgr._cfg.local_bd_addr,
        seq,
        mgr._known_neighbor_pairs(),
        mgr.key_store.local_public_key,
        epoch=mgr.epoch_store.current_epoch(),
        anon_id_key=group_key,
        ts_ms=1_000 + seq,
    )


def test_cross_group_hello_learned_anon_ids() -> None:
    aid_a = compute_anon_id(_GK_A, _ADDR_A)
    aid_b = compute_anon_id(_GK_B, _ADDR_B)

    mgr_a, tx_a = _make_mgr(group_key=_GK_A, local_bd=_ADDR_A, peers=[_ADDR_B])
    mgr_b, tx_b = _make_mgr(group_key=_GK_B, local_bd=_ADDR_B, peers=[_ADDR_A])

    # Round 1: B sends first Hello (no learned peers yet → empty neighbor list).
    pkt_b1 = _build_pkt(mgr_b, group_key=_GK_B, seq=1)
    mgr_a.on_receive(_ADDR_B, pkt_b1)

    pub_b1 = parse_hello_public(pkt_b1)
    assert parse_hello_private(pkt_b1, _GK_A) is None
    assert mgr_a.anon_id_for(_ADDR_B) == aid_b

    # Round 2: A replies, advertising learned B with B's wire anon_id (not HMAC under GK_A).
    pkt_a1 = _build_pkt(mgr_a, group_key=_GK_A, seq=1)
    assert parse_hello_public(pkt_a1)["neighbor_anon_ids"] == [aid_b]
    mgr_b.on_receive(_ADDR_A, pkt_a1)

    assert parse_hello_private(pkt_a1, _GK_B) is None
    assert mgr_b.anon_id_for(_ADDR_A) == aid_a
    assert aid_b in parse_hello_public(pkt_a1)["neighbor_anon_ids"]

    # Round 3: B sends again, now advertising learned A.
    pkt_b2 = _build_pkt(mgr_b, group_key=_GK_B, seq=2)
    pub_b2 = parse_hello_public(pkt_b2)
    assert aid_a in pub_b2["neighbor_anon_ids"]
    mgr_a.on_receive(_ADDR_B, pkt_b2)

    # 1-hop: each sees the other.
    hop_a = {e["anon_id"] for e in mgr_a.table.get_1hop()}
    hop_b = {e["anon_id"] for e in mgr_b.table.get_1hop()}
    assert aid_b in hop_a
    assert aid_a in hop_b

    # Symmetry: own anon_id appears in the other's neighbor list.
    assert aid_a in pub_b2["neighbor_anon_ids"]
    assert aid_b in parse_hello_public(pkt_a1)["neighbor_anon_ids"]

    # 2-hop coherence: each relay advertises the other → self appears at 2-hop via peer.
    two_a = mgr_a.table.get_2hop()
    two_b = mgr_b.table.get_2hop()
    assert aid_a in two_a.get(aid_b, set())
    assert aid_b in two_b.get(aid_a, set())

    # Disconnect purges learned id; peer is no longer announcable.
    mgr_a.on_peer_disconnected(_ADDR_B)
    assert mgr_a._known_neighbor_pairs() == []
    tx_a.sent.clear()
    mgr_a._send_hellos()
    if tx_a.sent:
        assert parse_hello_public(tx_a.sent[0][1])["neighbor_anon_ids"] == []


if __name__ == "__main__":
    test_cross_group_hello_learned_anon_ids()
    print("✅ cross-group Hello tests passed")
