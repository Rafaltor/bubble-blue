from __future__ import annotations

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
from src.control.neighbors import NeighborTable  # noqa: E402
from src.forwarding.cds import CDSAlgorithm, am_i_cds  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402

_GK = b"\x42" * 32

# Distinct BD addresses for the scenario.
_X = "14:B5:CD:E2:49:ED"  # central node under test
_Y = "40:D9:5A:8B:69:3F"  # L2CAP peer of X, bridges to W (2-hop)
_Z = "00:11:22:33:44:55"  # L2CAP peer of X, no further reach
_W = "AA:BB:CC:DD:EE:FF"  # 2-hop neighbor of X, reachable only via Y


class _FakeTransport:
    def __init__(self, peers: list[str]) -> None:
        self._peers = [p.upper() for p in peers]
        self.sent: list[tuple[str, bytes]] = []

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:
        self.sent.append((bd_addr.upper(), bytes(data)))


def _make_manager(local_bd: str, peers: list[str]) -> tuple[HelloManager, _FakeTransport]:
    cfg = replace(
        load_config(),
        group_key=_GK,
        local_bd_addr=local_bd.upper(),
        remote_bd_addr="00:00:00:00:00:00",
        hello_interval_s=1,
        neighbor_timeout_s=30,
    )
    transport = _FakeTransport(peers)
    key_store = BBKeyStore.from_group_key(_GK, local_bd.upper())
    fd, path = tempfile.mkstemp(prefix="bb-mpr-epoch-")
    os.close(fd)
    epoch_store = EpochStore(_GK, persist_path=path, local_bd_addr=local_bd.upper())
    mgr = HelloManager(cfg, transport, key_store, epoch_store, quiet=True)
    return mgr, transport


def _hello_from(src_bd: str, neighbors: list[str], seq: int = 1) -> bytes:
    pubkey = BBKeyStore.from_group_key(_GK, src_bd.upper()).local_public_key
    return build_hello(
        _GK, src_bd.upper(), seq=seq, known_neighbors=[n.upper() for n in neighbors],
        local_public_key=pubkey, anon_id_key=_GK, ts_ms=1_000 + seq,
    )


def test_hello_manager_announces_local_mpr() -> None:
    """The central node must advertise a non-empty MPR set in its Hello."""
    mgr, transport = _make_manager(_X, peers=[_Y, _Z])

    # X only ever RECEIVES Hellos from its L2CAP peers. Y advertises X and W,
    # so W is a strict 2-hop neighbor reachable only via Y → Y is a mandatory MPR.
    mgr.on_receive(_Y, _hello_from(_Y, [_X, _W]))
    mgr.on_receive(_Z, _hello_from(_Z, [_X]))

    transport.sent.clear()
    mgr._send_hellos()
    assert transport.sent, "expected the manager to send a Hello"

    pub = parse_hello_public(transport.sent[0][1])
    mpr = set(pub["mpr_anon_ids"])
    assert mpr == {compute_anon_id(_GK, _Y)}, f"expected MPR={{Y}}, got {mpr}"
    # The advertised MPR must be a subset of the advertised neighbors.
    assert mpr <= set(pub["neighbor_anon_ids"])


def test_announced_mpr_activates_rule_b() -> None:
    """A peer in the smallest-id neighbor's announced MPR set relays (rule b)."""
    # Choose the central node to be the GLOBAL-MIN id so it is Y* for its peers.
    addrs = [_X, _Y, _Z]
    by_id = sorted(addrs, key=lambda a: int.from_bytes(compute_anon_id(_GK, a), "big"))
    center, p1, p2 = by_id[0], by_id[1], by_id[2]
    a_center, a_p1, a_p2 = (compute_anon_id(_GK, center), compute_anon_id(_GK, p1), compute_anon_id(_GK, p2))

    # Merged view (am_i_cds needs each node's own advertised list present): full
    # triangle so all three are mutually adjacent. center advertises p1 as its MPR.
    merged = NeighborTable()
    hellos = {
        center: ([p1, p2], [a_p1]),  # center elects p1 as MPR
        p1: ([center, p2], None),
        p2: ([center, p1], None),
    }
    for src_bd, (nbrs, mprs) in hellos.items():
        pubkey = BBKeyStore.from_group_key(_GK, src_bd.upper()).local_public_key
        pkt = build_hello(
            _GK, src_bd.upper(), seq=1, known_neighbors=[n.upper() for n in nbrs],
            local_public_key=pubkey, anon_id_key=_GK, mpr_anon_ids=mprs, ts_ms=2_000,
        )
        merged.update_from_hello(parse_hello_public(pkt), parse_hello_private(pkt, _GK))

    # p1 is in center's (smallest-id neighbor) announced MPR → RELAY via rule (b).
    assert am_i_cds(a_p1, merged, {a_center, a_p2}, CDSAlgorithm.MPR) is True
    # p2 is NOT in center's announced MPR → does not relay.
    assert am_i_cds(a_p2, merged, {a_center, a_p1}, CDSAlgorithm.MPR) is False


if __name__ == "__main__":
    test_hello_manager_announces_local_mpr()
    test_announced_mpr_activates_rule_b()
    print("✅ MPR Hello announcement tests passed")
