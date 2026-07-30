"""Sparse dial must stay connected and one-sided as N grows (no dual-dial)."""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.api.bb_api import (  # noqa: E402
    BBNode,
)
from config import MAX_L2CAP_DEGREE, SPARSE_RING_SUCCESSORS  # noqa: E402


def test_sparse_ring_successors_are_higher_only_and_bounded() -> None:
    a = bytes.fromhex("0100000000000000")
    b = bytes.fromhex("0200000000000000")
    c = bytes.fromhex("0300000000000000")
    d = bytes.fromhex("0400000000000000")
    heard = {b, c, d}

    assert BBNode._sparse_ring_successors(a, heard, count=1) == [b]
    assert BBNode._sparse_ring_successors(a, heard, count=2) == [b, c]
    # Max id has no higher peers — does not wrap (avoids dual-dial with min).
    assert BBNode._sparse_ring_successors(d, heard | {a}, count=2) == []


def test_sparse_dag_is_connected_for_five_nodes() -> None:
    nodes = [bytes([i]) + bytes(7) for i in range(1, 6)]
    edges: set[tuple[bytes, bytes]] = set()
    catalog = set(nodes)
    for local in nodes:
        for peer in BBNode._sparse_ring_successors(local, catalog, count=2):
            edges.add((local, peer))
            assert local < peer  # single dialer per edge

    # Undirected reachability from the minimum.
    undirected: dict[bytes, set[bytes]] = {n: set() for n in nodes}
    for u, v in edges:
        undirected[u].add(v)
        undirected[v].add(u)
    seen = {nodes[0]}
    stack = [nodes[0]]
    while stack:
        cur = stack.pop()
        for nxt in undirected[cur]:
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    assert seen == set(nodes)


def test_sparse_ring_empty_when_alone() -> None:
    a = bytes.fromhex("0100000000000000")
    assert BBNode._sparse_ring_successors(a, set(), count=2) == []


def test_degree_and_successor_caps_are_small_constants() -> None:
    assert MAX_L2CAP_DEGREE <= 4
    assert SPARSE_RING_SUCCESSORS == 2
