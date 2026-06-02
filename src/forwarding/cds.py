from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.control.neighbors import NeighborTable


@dataclass
class _Topology:
    """Anonymous topology extracted from a NeighborTable (anon_ids only)."""

    nodes: set[bytes] = field(default_factory=set)
    # Undirected adjacency (direct neighbors).
    adj: dict[bytes, set[bytes]] = field(default_factory=dict)
    # Neighbors advertised by each relay in its Hello (2-hop table rows).
    advertised: dict[bytes, set[bytes]] = field(default_factory=dict)


def _add_edge(topo: _Topology, a: bytes, b: bytes) -> None:
    if a == b:
        return
    topo.nodes.add(a)
    topo.nodes.add(b)
    topo.adj.setdefault(a, set()).add(b)
    topo.adj.setdefault(b, set()).add(a)


def _extract_topology(neighbor_table: NeighborTable) -> _Topology:
    """
    Build an anonymous graph from 1-hop / 2-hop Hello state.

    - 1-hop rows with a direct Hello (seq is not None) → confirmed edge to observer
    - 2-hop relay rows → relay advertises adjacency to its neighbors
    """
    topo = _Topology()

    one_hop = neighbor_table.get_1hop()
    two_hop = neighbor_table.get_2hop()

    direct: set[bytes] = set()
    for entry in one_hop:
        aid = bytes(entry["anon_id"])
        topo.nodes.add(aid)
        if entry.get("seq") is not None:
            direct.add(aid)

    for relay, targets in two_hop.items():
        relay_b = bytes(relay)
        topo.nodes.add(relay_b)
        ads = {bytes(t) for t in targets}
        topo.advertised[relay_b] = ads
        topo.nodes.update(ads)
        for target in ads:
            _add_edge(topo, relay_b, target)

    # Direct Hellos imply adjacency to the observing node when that node appears in table.
    # For a merged/global table used in tests, treat direct nodes as fully linked clique
    # only when both report each other via advertisements.
    for a in direct:
        for b in direct:
            if a != b:
                if b in topo.advertised.get(a, set()) or a in topo.advertised.get(b, set()):
                    _add_edge(topo, a, b)

    # Ensure adj dict exists for all nodes.
    for node in list(topo.nodes):
        topo.adj.setdefault(node, set())

    return topo


def _one_hop_neighbors(node: bytes, topo: _Topology) -> set[bytes]:
    return set(topo.adj.get(node, set()))


def _two_hop_connected(u: bytes, v: bytes, topo: _Topology) -> bool:
    """
    True if u and v are within 2 hops using advertised neighbor lists.

    "In each other's 2-hop" ⇔ v appears in u's advertised neighbors (or vice versa),
    or they are the same node, or directly adjacent.
    """
    if u == v:
        return True
    if v in topo.adj.get(u, set()) or u in topo.adj.get(v, set()):
        return True
    ads_u = topo.advertised.get(u, set())
    ads_v = topo.advertised.get(v, set())
    return v in ads_u or u in ads_v


def _dominated(node: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """True if node is in CDS or has a CDS node as a direct neighbor."""
    if node in cds:
        return True
    return bool(topo.adj.get(node, set()).intersection(cds))


def _bridged_by_cds(u: bytes, v: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """True if some CDS node is adjacent to both u and v."""
    for w in cds:
        adj = topo.adj.get(w, set())
        if u in adj and v in adj:
            return True
    return False


def _should_join_cds(node: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """
    Greedy CDS election rule for node X:

    X joins if there exist two 1-hop neighbors u, v such that:
      - u and v are NOT in each other's 2-hop (not connected via advertisements)
      - no existing CDS node is adjacent to both u and v
    If CDS is non-empty, X must be adjacent to an existing CDS node (connected backbone).
    """
    if node in cds:
        return False

    if cds and not topo.adj.get(node, set()).intersection(cds):
        return False

    neighbors = _one_hop_neighbors(node, topo)
    if len(neighbors) < 2:
        return False

    for u, v in itertools.combinations(sorted(neighbors), 2):
        if _two_hop_connected(u, v, topo):
            continue
        if _bridged_by_cds(u, v, cds, topo):
            continue
        return True
    return False


def compute_cds(neighbor_table: NeighborTable) -> set[bytes]:
    """
    Compute the Greedy CDS backbone (anon_ids only).

    Iterates nodes in deterministic order (degree desc, then anon_id) until stable.
    """
    topo = _extract_topology(neighbor_table)
    if not topo.nodes:
        return set()

    cds: set[bytes] = set()
    # Same-degree tie-break: lower anon_id first (picks center-ish nodes on paths).
    ordered = sorted(
        topo.nodes,
        key=lambda n: (-len(_one_hop_neighbors(n, topo)), int.from_bytes(n, "big")),
    )

    # Greedy rounds: at most one new CDS node per pass (deterministic priority).
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


def am_i_cds(local_anon_id: bytes, neighbor_table: NeighborTable) -> bool:
    """Return True if local_anon_id is in the CDS backbone for this topology view."""
    return bytes(local_anon_id) in compute_cds(neighbor_table)


def _verify_cds_properties(cds: set[bytes], topo: _Topology) -> None:
    """Sanity-check dominating + connected backbone."""
    if not topo.nodes:
        return

    # Every node is dominated (in CDS or adjacent to a CDS node).
    for node in topo.nodes:
        if node in cds:
            continue
        adj = topo.adj.get(node, set())
        if not adj.intersection(cds):
            raise AssertionError(f"node {node.hex()} not dominated by CDS")

    # CDS induces a connected subgraph (on the full graph).
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

    Simulates each node sending Hello; merges into one global view for CDS computation.
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

    cds = compute_cds(table)
    _verify_cds_properties(cds, _extract_topology(table))

    print("Linear topology A — B — C — D — E")
    print(f"CDS size: {len(cds)} (minimum connected CDS for a path of 5 is 3)")
    for addr in addrs:
        aid = anon_by_addr[addr]
        role = "CDS" if aid in cds else "not CDS"
        print(f"  {labels[addr]}  anon_id={aid.hex()}  → {role}")

    assert len(cds) == 3, f"expected 3 CDS relays for connected P5, got {len(cds)}"
    for name in ("B", "C", "D"):
        idx = names.index(name)
        assert anon_by_addr[addrs[idx]] in cds, f"{name} should be in CDS"

    # am_i_cds checks
    assert am_i_cds(anon_by_addr[addrs[1]], table) is True
    assert am_i_cds(anon_by_addr[addrs[0]], table) is False

    print("\n✅ All CDS self-tests passed")
