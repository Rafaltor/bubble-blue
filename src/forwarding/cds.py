from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.control.neighbors import NeighborTable


@dataclass
class _Topology:
    """Anonymous topology from Hello neighbor advertisements (anon_ids only)."""

    nodes: set[bytes] = field(default_factory=set)
    # Each node's direct neighbors as advertised in its Hello (public list).
    advertised: dict[bytes, set[bytes]] = field(default_factory=dict)
    # Undirected edges where both nodes mutually list each other in Hello.
    adj: dict[bytes, set[bytes]] = field(default_factory=dict)


def _add_edge(topo: _Topology, a: bytes, b: bytes) -> None:
    if a == b:
        return
    topo.nodes.add(a)
    topo.nodes.add(b)
    topo.adj.setdefault(a, set()).add(b)
    topo.adj.setdefault(b, set()).add(a)


def _advertised_neighbors(neighbor_table: NeighborTable) -> dict[bytes, set[bytes]]:
    """
    Per-node 1-hop neighbor lists from Hello public fields.

    Stored in NeighborTable._2hop as relay -> advertised anon_ids (not used as 2-hop paths).
    """
    out: dict[bytes, set[bytes]] = {}
    for relay, targets in neighbor_table.get_2hop().items():
        relay_b = bytes(relay)
        out[relay_b] = {bytes(t) for t in targets}
    return out


def _extract_topology(neighbor_table: NeighborTable) -> _Topology:
    """Build mutual-adjacency graph from Hello advertisements only."""
    topo = _Topology()
    topo.advertised = _advertised_neighbors(neighbor_table)
    topo.nodes.update(topo.advertised.keys())
    for ads in topo.advertised.values():
        topo.nodes.update(ads)

    # Direct link u—v only if each lists the other in its Hello 1-hop set.
    seen: set[tuple[bytes, bytes]] = set()
    for u, nbrs in topo.advertised.items():
        for v in nbrs:
            if u == v:
                continue
            key = (min(u, v), max(u, v))
            if key in seen:
                continue
            if u in topo.advertised.get(v, set()) and v in topo.advertised.get(u, set()):
                seen.add(key)
                _add_edge(topo, u, v)

    for node in list(topo.nodes):
        topo.adj.setdefault(node, set())
    return topo


def _mutually_adjacent(u: bytes, v: bytes, advertised: dict[bytes, set[bytes]]) -> bool:
    """True iff u and v each list the other as a direct Hello neighbor."""
    return v in advertised.get(u, set()) and u in advertised.get(v, set())


def _one_hop_neighbors(node: bytes, topo: _Topology) -> set[bytes]:
    return set(topo.adj.get(node, set()))


def _bridged_by_cds(u: bytes, v: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """True if some CDS node is adjacent to both u and v."""
    for w in cds:
        adj = topo.adj.get(w, set())
        if u in adj and v in adj:
            return True
    return False


def _should_join_cds(node: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """
    Greedy CDS election rule for node X (global view, mutual Hello adjacency only).
    """
    if node in cds:
        return False

    if cds and not topo.adj.get(node, set()).intersection(cds):
        return False

    neighbors = _one_hop_neighbors(node, topo)
    if len(neighbors) < 2:
        return False

    for u, v in itertools.combinations(sorted(neighbors), 2):
        if _mutually_adjacent(u, v, topo.advertised):
            continue
        if _bridged_by_cds(u, v, cds, topo):
            continue
        return True
    return False


def compute_cds(neighbor_table: NeighborTable) -> set[bytes]:
    """
    Compute the Greedy CDS backbone (anon_ids only, global merged view).

    Uses mutual Hello adjacency only — not 2-hop reachability.
    """
    topo = _extract_topology(neighbor_table)
    if not topo.nodes:
        return set()

    cds: set[bytes] = set()
    ordered = sorted(
        topo.nodes,
        key=lambda n: (-len(_one_hop_neighbors(n, topo)), int.from_bytes(n, "big")),
    )

    while True:
        added = False
        for node in ordered:
            if _should_join_cds(node, cds, topo):
                cds.add(node)
                added = True
                break
        if not added:
            break

    return cds


def am_i_cds(
    local_anon_id: bytes,
    neighbor_table: NeighborTable,
    l2cap_peers: frozenset[bytes] | set[bytes],
) -> bool:
    """
    Return True if this node should relay packets (local CDS role).

    RELAY iff among DIRECT L2CAP peers, some pair (u, v) is not mutually listed
    in each other's Hello 1-hop neighbor advertisements.
    """
    local = bytes(local_anon_id)
    peers = {bytes(p) for p in l2cap_peers}
    peers.discard(local)

    if len(peers) < 2:
        return False

    advertised = _advertised_neighbors(neighbor_table)
    for u, v in itertools.combinations(sorted(peers), 2):
        if not _mutually_adjacent(u, v, advertised):
            return True
    return False


def _verify_cds_properties(cds: set[bytes], topo: _Topology) -> None:
    """Sanity-check dominating + connected backbone."""
    if not topo.nodes:
        return

    for node in topo.nodes:
        if node in cds:
            continue
        adj = topo.adj.get(node, set())
        if not adj.intersection(cds):
            raise AssertionError(f"node {node.hex()} not dominated by CDS")

    if len(cds) <= 1:
        return
    start = next(iter(cds))
    seen = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for nb in topo.adj.get(cur, set()):
            if nb in cds and nb not in seen:
                seen.add(nb)
                stack.append(nb)
    if seen != cds:
        raise AssertionError("CDS nodes do not form a connected subgraph")


def _build_linear_topology_table(group_key: bytes, addrs: list[str]) -> NeighborTable:
    """
    Build a merged NeighborTable for a line A-B-C-D-E from Hello exchanges.
    """
    from src.control.hello import build_hello, parse_hello_private, parse_hello_public
    from src.control.neighbors import NeighborTable

    merged = NeighborTable()

    for i, addr in enumerate(addrs):
        neighbors = []
        if i > 0:
            neighbors.append(addrs[i - 1])
        if i + 1 < len(addrs):
            neighbors.append(addrs[i + 1])

        pkt = build_hello(group_key, addr, seq=i + 1, known_neighbors=neighbors, ts_ms=1_000 + i)
        pub = parse_hello_public(pkt)
        priv = parse_hello_private(pkt, group_key)
        merged.update_from_hello(pub, priv)

    return merged


if __name__ == "__main__":
    from src.control.hello import compute_anon_id

    group_key = b"\x42" * 32
    names = ["A", "B", "C", "D", "E"]
    addrs = [
        "40:D9:5A:8B:69:3F",
        "14:B5:CD:E2:49:ED",
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
    ]
    labels = dict(zip(addrs, names, strict=True))

    table = _build_linear_topology_table(group_key, addrs)
    anon_by_addr = {a: compute_anon_id(group_key, a) for a in addrs}
    topo = _extract_topology(table)

    cds = compute_cds(table)
    _verify_cds_properties(cds, topo)

    print("Linear topology A — B — C — D — E")
    print(f"CDS size (global greedy): {len(cds)}")
    for addr in addrs:
        aid = anon_by_addr[addr]
        role = "CDS" if aid in cds else "not CDS"
        print(f"  {labels[addr]}  anon_id={aid.hex()}  → {role} (global)")

    print("\nLocal am_i_cds (L2CAP direct peers only):")
    for i, addr in enumerate(addrs):
        aid = anon_by_addr[addr]
        l2cap: set[bytes] = set()
        if i > 0:
            l2cap.add(anon_by_addr[addrs[i - 1]])
        if i + 1 < len(addrs):
            l2cap.add(anon_by_addr[addrs[i + 1]])
        relay = am_i_cds(aid, table, l2cap)
        l2cap_names = [labels[a] for a in addrs if anon_by_addr[a] in l2cap]
        print(f"  {labels[addr]}  l2cap={l2cap_names}  → {'RELAY' if relay else 'LEAF'}")

    assert am_i_cds(anon_by_addr[addrs[1]], table, {anon_by_addr[addrs[0]], anon_by_addr[addrs[2]]}) is True
    assert am_i_cds(anon_by_addr[addrs[0]], table, {anon_by_addr[addrs[1]]}) is False
    assert am_i_cds(anon_by_addr[addrs[4]], table, {anon_by_addr[addrs[3]]}) is False

    print("\n✅ All CDS self-tests passed")
