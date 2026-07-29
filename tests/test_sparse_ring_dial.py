"""Empty-CDS dial must stay sparse as N grows (no full-mesh O(N²) storm)."""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.api.bb_api import (  # noqa: E402
    BBNode,
    MAX_L2CAP_DEGREE,
    SPARSE_RING_SUCCESSORS,
)


def test_sparse_ring_successors_are_circular_and_bounded() -> None:
    a = bytes.fromhex("0100000000000000")
    b = bytes.fromhex("0200000000000000")
    c = bytes.fromhex("0300000000000000")
    d = bytes.fromhex("0400000000000000")
    heard = {b, c, d}

    assert BBNode._sparse_ring_successors(a, heard, count=1) == [b]
    assert BBNode._sparse_ring_successors(a, heard, count=2) == [b, c]
    # Highest id wraps to the lowest other node.
    assert BBNode._sparse_ring_successors(d, heard | {a}, count=2) == [a, b]


def test_sparse_ring_empty_when_alone() -> None:
    a = bytes.fromhex("0100000000000000")
    assert BBNode._sparse_ring_successors(a, set(), count=2) == []


def test_degree_and_successor_caps_are_small_constants() -> None:
    # Guard against accidental full-mesh regression: these must stay O(1).
    assert MAX_L2CAP_DEGREE <= 4
    assert SPARSE_RING_SUCCESSORS <= 3
    assert SPARSE_RING_SUCCESSORS >= 1
