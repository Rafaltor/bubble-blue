# CDS election: Wu-Li 2001 algorithm
# Reference: Wu J, Li H (2001). A domination-based scheme for mobile ad-hoc
# networks. Telecommunication Systems 18(1-3):13-35.
# Selected for BUBBLE-BLUE per arXiv:2509.00967 (Achir, Jacquet 2025).

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


def _anon_id_int(node: bytes) -> int:
    return int.from_bytes(node, "big")


def _one_hop_neighbors(node: bytes, topo: _Topology) -> set[bytes]:
    return set(topo.adj.get(node, set()))


def _wu_li_rule1(sym_neighbors: set[bytes], advertised: dict[bytes, set[bytes]]) -> bool:
    """
    Gateway rule: some pair of symmetric neighbors is not directly linked.
    """
    if len(sym_neighbors) < 2:
        return False
    for u, v in itertools.combinations(sym_neighbors, 2):
        if not _mutually_adjacent(u, v, advertised):
            return True
    return False


def _wu_li_rule2_not_dominated(
    node: bytes,
    sym_neighbors: set[bytes],
    neighbor_closure: dict[bytes, set[bytes]],
) -> bool:
    """
    Pruning rule: node is not dominated by a higher-ID symmetric neighbor Y
    (sym_neighbors \\ {Y} ⊆ N(Y)).
    """
    node_id = _anon_id_int(node)
    for y in sym_neighbors:
        if _anon_id_int(y) <= node_id:
            continue
        if sym_neighbors - {y} <= neighbor_closure.get(y, set()):
            return False
    return True


def _wu_li_is_cds_member(
    node: bytes,
    sym_neighbors: set[bytes],
    *,
    advertised: dict[bytes, set[bytes]],
    neighbor_closure: dict[bytes, set[bytes]],
) -> bool:
    if not _wu_li_rule1(sym_neighbors, advertised):
        return False
    return _wu_li_rule2_not_dominated(node, sym_neighbors, neighbor_closure)


def compute_cds(neighbor_table: NeighborTable) -> set[bytes]:
    """
    Wu-Li 2001 CDS backbone (anon_ids only, global merged Hello view).

    For each node X, sym_N = mutual Hello neighbors of X. X ∈ CDS iff:
      Rule 1: ∃ u,v ∈ sym_N with no mutual Hello link u↔v
      Rule 2: no Y ∈ sym_N with ID(Y) > ID(X) such that sym_N \\ {Y} ⊆ N(Y)
    """
    topo = _extract_topology(neighbor_table)
    if not topo.nodes:
        return set()

    cds: set[bytes] = set()
    for node in topo.nodes:
        sym_n = _one_hop_neighbors(node, topo)
        if _wu_li_is_cds_member(
            node,
            sym_n,
            advertised=topo.advertised,
            neighbor_closure=topo.adj,
        ):
            cds.add(node)
    return cds


def _bridged_by_cds(u: bytes, v: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """True if some CDS node is adjacent to both u and v."""
    for w in cds:
        adj = topo.adj.get(w, set())
        if u in adj and v in adj:
            return True
    return False


def _should_join_greedy_cds(node: bytes, cds: set[bytes], topo: _Topology) -> bool:
    """Legacy Greedy CDS rule (reference for tests / comparison only)."""
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


def compute_greedy_cds(neighbor_table: NeighborTable) -> set[bytes]:
    """Greedy CDS (Wu-Li 1999-style reference). Used only in self-tests."""
    topo = _extract_topology(neighbor_table)
    if not topo.nodes:
        return set()

    cds: set[bytes] = set()
    ordered = sorted(
        topo.nodes,
        key=lambda n: (-len(_one_hop_neighbors(n, topo)), _anon_id_int(n)),
    )

    while True:
        added = False
        for node in ordered:
            if _should_join_greedy_cds(node, cds, topo):
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
    Return True if this node should relay packets (local Wu-Li 2001 CDS role).

    Direct L2CAP peers are exactly ``l2cap_peers`` (from transport.connections()).
    Hello is used only for mutual adjacency between those peers.

    RELAY iff Wu-Li Rule 1 (gateway) and Rule 2 (not pruned) both hold on the
    symmetric L2CAP peer set.
    """
    local = bytes(local_anon_id)
    peers = {bytes(p) for p in l2cap_peers}
    peers.discard(local)

    if len(peers) < 2:
        return False

    advertised = _advertised_neighbors(neighbor_table)
    sym_peers = {p for p in peers if _mutually_adjacent(local, p, advertised)}
    if len(sym_peers) < 2:
        return False

    neighbor_closure: dict[bytes, set[bytes]] = {}
    for p in sym_peers | {local}:
        neighbor_closure[p] = {bytes(n) for n in advertised.get(p, set())}

    return _wu_li_is_cds_member(
        local,
        sym_peers,
        advertised=advertised,
        neighbor_closure=neighbor_closure,
    )


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

        pkt = build_hello(
            group_key,
            addr,
            seq=i + 1,
            known_neighbors=neighbors,
            local_public_key=b"\x00" * 31 + bytes([i + 1]),
            ts_ms=1_000 + i,
        )
        pub = parse_hello_public(pkt)
        priv = parse_hello_private(pkt, group_key)
        merged.update_from_hello(pub, priv)

    return merged


def _build_mesh_topology_table(
    group_key: bytes,
    addrs: list[str],
    neighbor_map: dict[str, list[str]],
) -> NeighborTable:
    """Build NeighborTable from per-node neighbor lists (e.g. full triangle)."""
    from src.control.hello import build_hello, parse_hello_private, parse_hello_public
    from src.control.neighbors import NeighborTable

    merged = NeighborTable()
    for i, addr in enumerate(addrs):
        neighbors = neighbor_map.get(addr, [])
        pkt = build_hello(
            group_key,
            addr,
            seq=i + 1,
            known_neighbors=neighbors,
            local_public_key=b"\x00" * 31 + bytes([i + 1]),
            ts_ms=1_000 + i,
        )
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
    greedy = compute_greedy_cds(table)
    _verify_cds_properties(cds, topo)

    print("Linear topology A — B — C — D — E")
    print(f"CDS size (Wu-Li 2001): {len(cds)}  (Greedy reference: {len(greedy)})")
    assert len(cds) <= len(greedy)
    relay_addrs = [a for a in addrs if anon_by_addr[a] in cds]
    assert any(labels[a] in ("B", "D") for a in relay_addrs), f"expected B or D in CDS, got {relay_addrs}"

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

    # 4-node path A—B—C—D
    path4 = addrs[0:4]
    path_table = _build_linear_topology_table(group_key, path4)
    path_topo = _extract_topology(path_table)
    path_cds = compute_cds(path_table)
    _verify_cds_properties(path_cds, path_topo)
    path_labels = {labels[a] for a in path4 if anon_by_addr[a] in path_cds}
    assert path_labels.intersection({"B", "C"}), f"expected B or C in 4-node CDS, got {path_labels}"
    assert anon_by_addr[path4[0]] not in path_cds or path_topo.adj[path4[0]].intersection(path_cds)
    assert anon_by_addr[path4[3]] not in path_cds or path_topo.adj[path4[3]].intersection(path_cds)

    # Star: hub has L2CAP to two leaves; leaves do not list each other in Hello.
    star_addrs = addrs[0:3]
    h_addr, l1_addr, l2_addr = star_addrs
    star_table = _build_mesh_topology_table(
        group_key,
        star_addrs,
        {h_addr: [l1_addr, l2_addr], l1_addr: [h_addr], l2_addr: [h_addr]},
    )
    h, l1, l2 = anon_by_addr[h_addr], anon_by_addr[l1_addr], anon_by_addr[l2_addr]
    assert am_i_cds(l1, star_table, {h}) is False
    assert am_i_cds(h, star_table, {l1, l2}) is True
    assert am_i_cds(l2, star_table, {h}) is False

    # Full triangle X—Y—Z: each has L2CAP to both others, all mutually in Hello → all LEAF.
    tri_addrs = addrs[0:3]
    x, y, z = tri_addrs
    tri_map = {
        x: [y, z],
        y: [x, z],
        z: [x, y],
    }
    tri_table = _build_mesh_topology_table(group_key, tri_addrs, tri_map)
    ax, ay, az = anon_by_addr[x], anon_by_addr[y], anon_by_addr[z]
    for aid, peers in (
        (ax, {ay, az}),
        (ay, {ax, az}),
        (az, {ax, ay}),
    ):
        assert am_i_cds(aid, tri_table, peers) is False, "mesh node should be LEAF"

    print("\n✅ All CDS self-tests passed")
