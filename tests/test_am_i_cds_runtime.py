from __future__ import annotations

# Runtime contract test for am_i_cds (REGRESSION / red-before-fix).
#
# On real hardware every node owns a single NeighborTable populated ONLY by the
# Hellos it RECEIVES from others — it never ingests its own Hello. am_i_cds builds
# its symmetric peer set via _mutually_adjacent(local, p, advertised), which tests
# `p in advertised[local]`. But advertised[local] never exists in a received-only
# table (a node does not receive its own Hello), so sym_peers is always empty and
# am_i_cds always returns False — no node ever becomes a relay.
#
# This test reproduces that scenario (line Alice — Bob — Charlie, Bob in the
# middle) and ASSERTS THE CORRECT behavior: Bob is the bridge and MUST relay
# (am_i_cds(...) is True). It is therefore expected to be RED until the bug is
# fixed, and GREEN afterwards.

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.control.hello import (  # noqa: E402
    build_hello,
    compute_anon_id,
    parse_hello_private,
    parse_hello_public,
)
from src.control.neighbors import NeighborTable  # noqa: E402
from src.forwarding.cds import am_i_cds  # noqa: E402

_GK = b"\x42" * 32

_ALICE = "40:D9:5A:8B:69:3F"
_BOB = "14:B5:CD:E2:49:ED"
_CHARLIE = "00:11:22:33:44:55"


def _hello_from(src_bd: str, neighbors: list[str], seq: int) -> bytes:
    pubkey = b"\x00" * 31 + bytes([seq])
    return build_hello(
        _GK, src_bd.upper(), seq=seq, known_neighbors=[n.upper() for n in neighbors],
        local_public_key=pubkey, anon_id_key=_GK, ts_ms=1_000 + seq,
    )


def _ingest(table: NeighborTable, pkt: bytes) -> None:
    """Exactly what HelloManager.on_receive does for a received Hello."""
    table.update_from_hello(parse_hello_public(pkt), parse_hello_private(pkt, _GK))


def test_bridge_node_relays_with_received_only_table() -> None:
    bob_id = compute_anon_id(_GK, _BOB)
    alice_id = compute_anon_id(_GK, _ALICE)
    charlie_id = compute_anon_id(_GK, _CHARLIE)

    # Bob's runtime table: he received Alice's Hello (Alice lists Bob) and
    # Charlie's Hello (Charlie lists Bob). Crucially, NO Hello emitted by Bob
    # himself is injected — at runtime a node never receives its own Hello.
    bob_table = NeighborTable()
    _ingest(bob_table, _hello_from(_ALICE, [_BOB], seq=1))
    _ingest(bob_table, _hello_from(_CHARLIE, [_BOB], seq=2))

    # Bob's active L2CAP peers, as transport.connections() would report them.
    l2cap_peers = {alice_id, charlie_id}

    # Alice and Charlie are not adjacent → Bob is the bridge and must relay.
    assert am_i_cds(bob_id, bob_table, l2cap_peers) is True, (
        "Bob is the line bridge and must be a RELAY; am_i_cds returned False, "
        "which means the received-only-table runtime bug is present."
    )


if __name__ == "__main__":
    test_bridge_node_relays_with_received_only_table()
    print("✅ am_i_cds runtime contract test passed")
