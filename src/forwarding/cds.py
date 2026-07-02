# CDS election: Wu-Li 1999 algorithm
# Reference: Wu J, Li H (1999). "On calculating connected dominating set for
# efficient routing in ad hoc wireless networks". Proc. 3rd Int. Workshop on
# Discrete Algorithms and Methods for Mobile Computing and Communications
# (DIALM '99), pp. 7-14.
# Implemented per the formulation in arXiv:2509.00967 §2.4.2 (Achir, Jacquet 2025).

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.control.neighbors import NeighborTable


class CDSAlgorithm(Enum):
    """
    CDS election strategy selector.

    - ``WU_LI_1999`` (default): Wu-Li 1999 marking + §2.4.2 id pruning.
    - ``MPR``: MPR-CDS membership rule (Jacquet 2004, arXiv:2509.00967 §2.4.2)
      built on the Qayyum MPR sets.
    """

    WU_LI_1999 = "wu_li_1999"
    MPR = "mpr"


def _require_supported_algorithm(algorithm: CDSAlgorithm) -> None:
    """Validate the requested strategy. WU_LI_1999 and MPR are both wired."""
    if algorithm in (CDSAlgorithm.WU_LI_1999, CDSAlgorithm.MPR):
        return
    raise NotImplementedError(f"Unsupported CDS algorithm: {algorithm!r}")


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


def local_symmetric_peers(
    neighbor_table: NeighborTable,
    local_anon_id: bytes,
    l2cap_peers: frozenset[bytes] | set[bytes],
) -> set[bytes]:
    """
    Correct LOCAL view of a node's symmetric 1-hop neighbors (runtime-safe).

    A node's NeighborTable is populated ONLY by RECEIVED Hellos, so it never
    contains the node's own advertised list — ``advertised[local]`` does not
    exist. The symmetric-neighbor test must therefore be ASYMMETRIC:

      - "is p MY neighbor?"      → the node knows this DIRECTLY: p ∈ l2cap_peers
                                   (transport.connections()). We do NOT consult
                                   advertised[local] (which is always empty).
      - "does p list me back?"   → read from the RECEIVED table: local ∈
                                   advertised[p] (p's Hello confirms the link).

    So p is symmetric for ``local`` iff p ∈ l2cap_peers (minus local) AND
    local ∈ advertised[p]. This is the shared notion used by am_i_cds (Wu-Li and
    MPR). The adjacency BETWEEN peers is still read from ``advertised`` elsewhere,
    which is legitimate (local learns p's neighbors from p's received Hello).
    """
    local = bytes(local_anon_id)
    advertised = _advertised_neighbors(neighbor_table)
    peers = {bytes(p) for p in l2cap_peers}
    peers.discard(local)
    return {p for p in peers if local in advertised.get(p, set())}


def _anon_id_int(node: bytes) -> int:
    return int.from_bytes(node, "big")


def _one_hop_neighbors(node: bytes, topo: _Topology) -> set[bytes]:
    return set(topo.adj.get(node, set()))


# ---------------------------------------------------------------------------
# CDS election — Wu & Li 1999
# Reference: Wu J, Li H (1999). "On calculating connected dominating set for
# efficient routing in ad hoc wireless networks". DIALM '99.
# Formulation reprise de arXiv:2509.00967 §2.4.2 (Achir, Jacquet 2025).
#
# L'algorithme Wu-Li 1999 complet se compose de DEUX phases ; les deux
# ensemble constituent l'élection, _is_gateway n'est pas un ajout propre à BB :
#
#   Phase 1 — Marking process (canonique, Wu-Li 1999) : un nœud X se marque
#     (devient candidat « gateway ») ssi il possède deux voisins symétriques qui
#     ne sont PAS adjacents entre eux, autrement dit s'il relie une coupure du
#     graphe. C'est exactement la règle de marquage de l'article original.
#
#   Phase 2 — Pruning par identifiant (Cas 1 / Cas 2) : on élague les candidats
#     redondants. On suit la convention du préprint §2.4.2, qui élague à partir
#     des voisins d'ID PLUS PETIT (S_low). C'est l'INVERSE du tie-breaker de
#     l'article original de Wu-Li 1999 (qui conserve les ID plus grands) ; le
#     résultat reste un CDS valide, seul le critère de départage est inversé.
# ---------------------------------------------------------------------------


def _is_gateway(sym_neighbors: set[bytes], advertised: dict[bytes, set[bytes]]) -> bool:
    """
    Wu-Li 1999 phase 1 — canonical marking process (not a BB-specific addition):
    a node marks itself as a gateway iff it has ≥2 symmetric neighbors with at
    least one pair that is not mutually adjacent (i.e. X bridges a gap). Phase 2
    (Case 1 / Case 2 pruning) then prunes redundant gateways.
    """
    if len(sym_neighbors) < 2:
        return False
    for u, v in itertools.combinations(sym_neighbors, 2):
        if not _mutually_adjacent(u, v, advertised):
            return True
    return False


def _is_connected(nodes: set[bytes], adjacency: dict[bytes, set[bytes]]) -> bool:
    """
    True iff ``nodes`` form a connected subgraph under ``adjacency`` (mutual links
    restricted to ``nodes``). Empty set or singleton are connected by convention.
    """
    if len(nodes) <= 1:
        return True
    start = next(iter(nodes))
    seen = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for nb in adjacency.get(cur, set()):
            if nb in nodes and nb not in seen:
                seen.add(nb)
                stack.append(nb)
    return seen == nodes


def _s_low_forms_cds_of_neighborhood(
    node: bytes,
    sym_neighbors: set[bytes],
    advertised: dict[bytes, set[bytes]],
) -> bool:
    """
    True iff S_low = {Y ∈ sym_N | id(Y) < id(X)} is a Connected Dominating Set
    of N(X) on the mutual-adjacency subgraph induced on N(X) ∪ {X}.

    - Domination: every v ∈ N(X) is in S_low or mutually adjacent to some S_low member.
    - Connectivity: the subgraph induced by S_low (mutual links) is connected.
    Empty S_low cannot dominate a non-empty N(X), so it is never a CDS.
    """
    node_id = _anon_id_int(node)
    s_low = {y for y in sym_neighbors if _anon_id_int(y) < node_id}
    if not s_low:
        return False

    for v in sym_neighbors:
        if v in s_low:
            continue
        if not any(_mutually_adjacent(v, s, advertised) for s in s_low):
            return False

    adjacency = {
        s: {t for t in s_low if t != s and _mutually_adjacent(s, t, advertised)}
        for s in s_low
    }
    return _is_connected(s_low, adjacency)


def _wu_li_is_cds_member(
    node: bytes,
    sym_neighbors: set[bytes],
    *,
    advertised: dict[bytes, set[bytes]],
    neighbor_closure: dict[bytes, set[bytes]] | None = None,
) -> bool:
    """
    Wu-Li 1999 membership for node X (§2.4.2 formulation).

    ``neighbor_closure`` is accepted for backward-compatible call sites but is
    not used by this formulation (N(·) is derived from ``advertised``).
    """
    _ = neighbor_closure

    # Base marking (Wu-Li 1999): only gateway nodes can join the CDS.
    if not _is_gateway(sym_neighbors, advertised):
        return False

    node_id = _anon_id_int(node)

    # Case 1: lowest id among its symmetric neighbors → always kept.
    if node_id < min(_anon_id_int(y) for y in sym_neighbors):
        return True

    # Case 2: pruned iff its lower-id neighbors already form a CDS of N(X).
    return not _s_low_forms_cds_of_neighborhood(node, sym_neighbors, advertised)


def compute_cds(
    neighbor_table: NeighborTable,
    algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
) -> set[bytes]:
    """
    Wu-Li 1999 CDS backbone (anon_ids only, global merged Hello view).

    For each node X, sym_N = mutual Hello neighbors of X. X ∈ CDS iff X is a
    gateway (two non-adjacent symmetric neighbors) and survives the §2.4.2 pruning:
      Case 1: id(X) < min(id(Y) for Y in sym_N) → kept.
      Case 2: otherwise X is kept iff S_low = {Y in sym_N | id(Y) < id(X)} is NOT
              a CDS of N(X).

    "S_low is a CDS of N(X)" means S_low is both a dominating set of N(X) (every
    v in N(X) is in S_low or mutually adjacent to some member) and connected
    (the mutual-adjacency subgraph induced by S_low is connected). id(·) is the
    big-endian integer of the 8-byte anon_id.

    ``algorithm`` selects the election strategy:
      - ``WU_LI_1999`` (default): the rule described above.
      - ``MPR``: MPR-CDS membership (Jacquet 2004). For each node X, X joins iff
        it is the local min id, or it belongs to the MPR set of its smallest-id
        neighbor Y*. In this GLOBAL/test view the MPR sets are recomputed from
        the merged topology via ``compute_all_mpr`` (vs. am_i_cds at runtime,
        which reads the MPR set Y* actually advertised in its Hello).
    """
    _require_supported_algorithm(algorithm)
    topo = _extract_topology(neighbor_table)
    if not topo.nodes:
        return set()

    if algorithm is CDSAlgorithm.MPR:
        # Global view: recompute the MPR sets each node would advertise.
        mpr_by_node = compute_all_mpr(neighbor_table)
        cds: set[bytes] = set()
        for node in topo.nodes:
            sym_n = _one_hop_neighbors(node, topo)
            if _is_mpr_cds_member(node, sym_n, mpr_by_node=mpr_by_node):
                cds.add(node)
        return cds

    cds = set()
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


# ---------------------------------------------------------------------------
# MPR selection — Qayyum heuristic (RFC 3626 §8.3.1)
# Selects, for a node, a minimal subset of its 1-hop symmetric neighbors (MPRs)
# that covers every strict 2-hop neighbor. Independent of Wu-Li 1999; used to
# advertise the MPR set in the public Hello and to feed a future MPR-CDS.
# All tie-breaks use ascending _anon_id_int for strict determinism.
# ---------------------------------------------------------------------------


def _select_mpr(node: bytes, topo: _Topology) -> set[bytes]:
    """
    Qayyum MPR set of ``node`` over the mutual-adjacency graph ``topo.adj``.

    N1 = symmetric 1-hop neighbors of node.
    N2 = strict 2-hop neighbors: nodes reachable via N1 only (excluding node and N1).
    Step 1: every w in N2 covered by a single y in N1 forces that y into the MPR set.
    Step 2: greedily add the y in N1 covering the most still-uncovered N2 nodes,
            tie-broken by smallest anon_id, until all of N2 is covered.
    """
    n1 = set(topo.adj.get(node, set()))
    if not n1:
        return set()

    n2: set[bytes] = set()
    for y in n1:
        n2 |= topo.adj.get(y, set())
    n2.discard(node)
    n2 -= n1
    if not n2:
        return set()

    # Coverage of each candidate y restricted to N2.
    cover = {y: (topo.adj.get(y, set()) & n2) for y in n1}

    mpr: set[bytes] = set()

    # Step 1 — mandatory MPRs: w in N2 reachable through exactly one y in N1.
    for w in n2:
        covering = [y for y in n1 if w in cover[y]]
        if len(covering) == 1:
            mpr.add(covering[0])

    covered: set[bytes] = set()
    for y in mpr:
        covered |= cover[y]

    # Step 2 — greedy cover of the remaining N2 nodes (deterministic tie-break).
    while covered != n2:
        remaining = n2 - covered
        candidates = [y for y in n1 if y not in mpr]
        best = min(
            candidates,
            key=lambda y: (-len(cover[y] & remaining), _anon_id_int(y)),
        )
        if not (cover[best] & remaining):
            # No candidate can cover the rest (disconnected/asymmetric data); stop.
            break
        mpr.add(best)
        covered |= cover[best]

    return mpr


def compute_all_mpr(neighbor_table: NeighborTable) -> dict[bytes, set[bytes]]:
    """Return {node: MPR set} for every node in the merged Hello topology."""
    topo = _extract_topology(neighbor_table)
    return {node: _select_mpr(node, topo) for node in topo.nodes}


def compute_local_mpr(neighbor_table: NeighborTable, local_anon_id: bytes) -> set[bytes]:
    """
    MPR set this node would advertise in its own Hello (Qayyum, RFC 3626).

    A node's own NeighborTable holds only RECEIVED Hellos — it never contains the
    node's own advertised neighbor list — so ``_extract_topology`` yields an empty
    adjacency for ``local_anon_id`` and a naive ``_select_mpr`` would always return
    ∅. We therefore rebuild the local OLSR view directly:
      - N1 = symmetric 1-hop neighbors = peers that advertised us (the reverse
        edge confirms the link: they list us, and our own Hello lists them).
      - 2-hop discovery is directional, OLSR-style: each y in N1 exposes the
        neighbors it advertised, so a node w is a strict 2-hop neighbor when some
        y in N1 advertised it and w is neither us nor in N1.
    This view is fed to the same ``_select_mpr`` heuristic used elsewhere.
    """
    local = bytes(local_anon_id)
    advertised = _advertised_neighbors(neighbor_table)

    # N1 uses the same "p listed me back" predicate as local_symmetric_peers,
    # but WITHOUT the l2cap_peers filter (this helper has no transport handle).
    # At runtime the two coincide: a node appears in advertised[p] only because p
    # listed it, and p lists exactly its own direct (L2CAP) peers. We reuse
    # local_symmetric_peers by treating every advertiser of `local` as a peer,
    # so the symmetric-neighbor definition stays single-sourced.
    advertisers_of_local = {p for p, ads in advertised.items() if local in ads}
    n1 = local_symmetric_peers(neighbor_table, local, advertisers_of_local)
    if not n1:
        return set()

    view = _Topology()
    view.adj[local] = set(n1)
    for y in n1:
        view.adj[y] = set(advertised.get(y, set()))
    return _select_mpr(local, view)


def _is_mpr_cds_member(
    node: bytes,
    sym_neighbors: set[bytes],
    *,
    mpr_by_node: dict[bytes, set[bytes]],
) -> bool:
    """
    MPR-CDS membership for node X (Jacquet 2004, arXiv:2509.00967 §2.4.2).

    With N1(X) = ``sym_neighbors`` and id(·) = _anon_id_int:
      Rule 1 (a): id(X) < min(id(Y) for Y in N1)        → X ∈ MPR-CDS.
      Rule 2 (b): else let Y* = the smallest-id neighbor in N1; X ∈ MPR-CDS iff
                  X is in the MPR set advertised by Y* (``mpr_by_node[Y*]``).

    ``mpr_by_node`` maps a node to the MPR set it advertises. The lookup for Y*
    is what makes the two call sites differ semantically (see compute_cds /
    am_i_cds): in a global test view it is recomputed, at runtime it is the set
    Y* actually announced in its Hello.

    KNOWN DEFECT of unconditional Rule 1 (NOT an implementation artifact): a node
    can join the backbone purely because it owns the locally-minimal id, even if
    it relays nothing. The classic case is a degree-1 leaf with the global-min id
    that is pulled into the CDS uselessly (Wu calls such Rule-1 additions
    "unnecessary"). This is faithful to the canonical Rule 1 / Rule 2 formulation
    of the preprint §2.4.2. The literature fixes it with EMPR (Enhanced MPR),
    which gates Rule 1 with an extra "has ≥2 non-connected neighbors" condition —
    exactly the gateway test in ``_is_gateway`` used by Wu-Li 1999. EMPR is an
    improvement OUTSIDE the scope of the preprint and is intentionally not applied
    here so this rule matches §2.4.2 verbatim.
    """
    if not sym_neighbors:
        return False

    node_id = _anon_id_int(node)
    if node_id < min(_anon_id_int(y) for y in sym_neighbors):
        return True

    y_star = min(sym_neighbors, key=_anon_id_int)
    return node in mpr_by_node.get(y_star, set())


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
    algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
) -> bool:
    """
    Return True if this node should relay packets (local Wu-Li 1999 CDS role).

    Direct L2CAP peers are exactly ``l2cap_peers`` (from transport.connections()).
    Hello is used only for mutual adjacency between those peers.

    RELAY iff this node is a gateway (two non-adjacent symmetric peers) and is
    not pruned by the §2.4.2 id-based rule (Case 1 / Case 2) over its symmetric
    L2CAP peer set.

    ``algorithm`` selects the election strategy:
      - ``WU_LI_1999`` (default): the rule described above.
      - ``MPR``: MPR-CDS membership (Jacquet 2004). RELAY iff this node is the
        local min id among its symmetric peers, or it appears in the MPR set
        that its smallest-id peer Y* ADVERTISED in its Hello. Unlike compute_cds
        (which recomputes MPR sets from a global view for testing), the runtime
        rule here reads ``neighbor_table.get_mpr()[Y*]`` — i.e. what Y* actually
        announced. A node only knows Y*'s MPR set because Y* advertised it; if
        no MPR Hello has been received from Y* yet, we conservatively do NOT
        relay (return False) rather than guess.
    """
    _require_supported_algorithm(algorithm)
    local = bytes(local_anon_id)
    peers = {bytes(p) for p in l2cap_peers}
    peers.discard(local)

    if len(peers) < 2:
        return False

    advertised = _advertised_neighbors(neighbor_table)
    # Runtime-correct symmetric peers: "p is my neighbor" comes from l2cap_peers
    # (known directly), "p lists me back" from the received table. NOT from
    # advertised[local], which never exists in a received-only table (see
    # local_symmetric_peers).
    sym_peers = local_symmetric_peers(neighbor_table, local, peers)
    if len(sym_peers) < 2:
        return False

    if algorithm is CDSAlgorithm.MPR:
        # Runtime view: use the MPR sets peers actually advertised (received via
        # Hello), NOT a local recomputation — at runtime Y*'s announcement is
        # authoritative. Missing entry → conservative False.
        mpr_by_node = neighbor_table.get_mpr()
        return _is_mpr_cds_member(local, sym_peers, mpr_by_node=mpr_by_node)

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
    from src.control.hello import build_hello, known_neighbors_same_group, parse_hello_private, parse_hello_public
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
            known_neighbors=known_neighbors_same_group(group_key, neighbors),
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
    from src.control.hello import build_hello, known_neighbors_same_group, parse_hello_private, parse_hello_public
    from src.control.neighbors import NeighborTable

    merged = NeighborTable()
    for i, addr in enumerate(addrs):
        neighbors = neighbor_map.get(addr, [])
        pkt = build_hello(
            group_key,
            addr,
            seq=i + 1,
            known_neighbors=known_neighbors_same_group(group_key, neighbors),
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
    print(f"CDS size (Wu-Li 1999): {len(cds)}  (Greedy reference: {len(greedy)})")
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

    # -----------------------------------------------------------------------
    # Wu-Li 1999 §2.4.2 — Case 1 / Case 2 and STRICT connectivity of S_low.
    # ids are HMAC-derived, so we never assume order from labels A..E: we sort
    # the addresses by their real anon_id and assign roles by rank.
    #   p0 < p1 < x < p3 (< p4)   ascending anon_id order
    # -----------------------------------------------------------------------
    ordered = sorted(addrs, key=lambda a: _anon_id_int(anon_by_addr[a]))
    p0, p1, x_addr, p3, _p4 = ordered  # p0,p1 < x_addr < p3

    # Case A — S_low DOMINANT but NOT CONNECTED → X must REMAIN relay.
    # Tests that we enforce strict connectivity, not just domination.
    #   topology (mutual Hello links):
    #       p1
    #        |
    #       X(x_addr) —— p0 —— p3
    #        \___________________/        (X also linked to p3)
    #   X's symmetric peers: {p0, p1, p3}.  S_low = {p0, p1} (both id < X).
    #   N(X) = {p0, p1, p3}: p0,p1 ∈ S_low, p3 dominated by p0  → DOMINANT.
    #   S_low subgraph {p0, p1}: p0—p1 absent                   → NOT CONNECTED.
    #   ⇒ S_low is not a CDS of N(X)  ⇒  X stays RELAY.
    case_a_table = _build_mesh_topology_table(
        group_key,
        [p0, p1, x_addr, p3],
        {
            x_addr: [p0, p1, p3],
            p0: [x_addr, p3],
            p1: [x_addr],
            p3: [x_addr, p0],
        },
    )
    assert am_i_cds(
        anon_by_addr[x_addr],
        case_a_table,
        {anon_by_addr[p0], anon_by_addr[p1], anon_by_addr[p3]},
    ) is True, "S_low dominant but disconnected → X must stay RELAY"

    # Case B — S_low DOMINANT and CONNECTED → X RETIRES (LEAF).
    #   same nodes, but now p0—p1 linked (S_low connected) and p3 still
    #   dominated by p0; p1—p3 absent keeps X a gateway.
    #   N(X) = {p0, p1, p3}: p0,p1 ∈ S_low, p3 dominated by p0  → DOMINANT.
    #   S_low subgraph {p0, p1}: p0—p1 present                  → CONNECTED.
    #   ⇒ S_low IS a CDS of N(X)  ⇒  X retires → LEAF.
    case_b_table = _build_mesh_topology_table(
        group_key,
        [p0, p1, x_addr, p3],
        {
            x_addr: [p0, p1, p3],
            p0: [x_addr, p1, p3],
            p1: [x_addr, p0],
            p3: [x_addr, p0],
        },
    )
    assert am_i_cds(
        anon_by_addr[x_addr],
        case_b_table,
        {anon_by_addr[p0], anon_by_addr[p1], anon_by_addr[p3]},
    ) is False, "S_low dominant and connected → X must become LEAF"

    # Case C — pure Case 1: X has the minimal id of its neighborhood → always
    # RELAY, whatever the coverage. p0 is the global-min anon_id.
    #   topology:  p1 —— X(p0) —— p2   (p1—p2 absent → X is a gateway)
    #   id(X) < min(id(p1), id(p2))  ⇒  Case 1  ⇒  RELAY (S_low is empty here).
    c0, c1, c2 = ordered[0], ordered[1], ordered[2]
    case_c_table = _build_mesh_topology_table(
        group_key,
        [c0, c1, c2],
        {
            c0: [c1, c2],
            c1: [c0],
            c2: [c0],
        },
    )
    assert am_i_cds(
        anon_by_addr[c0],
        case_c_table,
        {anon_by_addr[c1], anon_by_addr[c2]},
    ) is True, "Case 1 (min id) → X must stay RELAY regardless of coverage"

    # -----------------------------------------------------------------------
    # MPR selection (Qayyum, RFC 3626) on known topologies.
    # -----------------------------------------------------------------------
    def _n1_n2(n: bytes, t: _Topology) -> tuple[set[bytes], set[bytes]]:
        n1 = set(t.adj.get(n, set()))
        n2: set[bytes] = set()
        for y in n1:
            n2 |= t.adj.get(y, set())
        n2.discard(n)
        n2 -= n1
        return n1, n2

    def _assert_mpr_covers(n: bytes, t: _Topology, mpr: set[bytes]) -> None:
        _, n2 = _n1_n2(n, t)
        covered: set[bytes] = set()
        for y in mpr:
            covered |= t.adj.get(y, set())
        assert n2 <= covered, "MPR set must cover all strict 2-hop neighbors"

    # Line A — B — C — D — E:  C reaches A only via B and E only via D.
    #   N1(C) = {B, D};  N2(C) = {A, E}
    #   A is covered solely by B, E solely by D  → both are mandatory MPRs.
    #   ⇒ MPR(C) = {B, D}.
    aid_b_l, aid_c_l, aid_d_l = (
        anon_by_addr[addrs[1]],
        anon_by_addr[addrs[2]],
        anon_by_addr[addrs[3]],
    )
    mpr_c = _select_mpr(aid_c_l, topo)
    assert mpr_c == {aid_b_l, aid_d_l}, f"MPR(C) expected {{B,D}}, got {mpr_c}"
    _assert_mpr_covers(aid_c_l, topo, mpr_c)
    # Endpoint A reaches C only via B → MPR(A) = {B} (B is a mandatory bridge).
    assert _select_mpr(anon_by_addr[addrs[0]], topo) == {aid_b_l}
    all_mpr_line = compute_all_mpr(table)
    for nd in topo.nodes:
        _assert_mpr_covers(nd, topo, all_mpr_line[nd])
    print("✅ MPR line A—B—C—D—E: MPR(C)={B,D}, coverage holds: OK")

    # Star: hub —— l1, hub —— l2 (leaves list only the hub).
    #        l1
    #         |
    #        hub —— l2
    #   MPR(leaf) = {hub} (its single bridge to the other leaf).
    #   MPR(hub)  = ∅      (hub has no strict 2-hop neighbor).
    star_topo = _extract_topology(star_table)
    mpr_l1 = _select_mpr(l1, star_topo)
    mpr_hub = _select_mpr(h, star_topo)
    assert mpr_l1 == {h}, f"MPR(leaf) expected {{hub}}, got {mpr_l1}"
    assert mpr_hub == set(), f"MPR(hub) expected ∅, got {mpr_hub}"
    _assert_mpr_covers(l1, star_topo, mpr_l1)
    _assert_mpr_covers(h, star_topo, mpr_hub)
    print("✅ MPR star: MPR(leaf)={hub}, MPR(hub)=∅, coverage holds: OK")

    # -----------------------------------------------------------------------
    # MPR-CDS election (Jacquet 2004) via compute_cds(..., algorithm=MPR).
    # Each backbone must still be a valid CDS (dominating + connected).
    # -----------------------------------------------------------------------
    mpr_cds_line = compute_cds(table, algorithm=CDSAlgorithm.MPR)
    _verify_cds_properties(mpr_cds_line, topo)

    mpr_cds_star = compute_cds(star_table, algorithm=CDSAlgorithm.MPR)
    _verify_cds_properties(mpr_cds_star, star_topo)
    # Star: the global-min id is the hub → MPR-CDS = {hub}, leaves are leaves.
    assert mpr_cds_star == {h}, f"MPR-CDS(star) expected {{hub}}, got {mpr_cds_star}"

    tri_topo = _extract_topology(tri_table)
    mpr_cds_tri = compute_cds(tri_table, algorithm=CDSAlgorithm.MPR)
    _verify_cds_properties(mpr_cds_tri, tri_topo)
    # Full triangle: only the local-min node joins (no 2-hop to cover).
    assert len(mpr_cds_tri) == 1, f"MPR-CDS(triangle) expected 1 node, got {mpr_cds_tri}"
    print("✅ MPR-CDS dominating+connected on line / star / triangle: OK")

    # Size comparison vs Wu-Li on the line. The preprint predicts MPR-CDS ≤ Wu-Li
    # IN GENERAL, but the bound is not guaranteed under adversarial id placement.
    # Here the GLOBAL-MIN anon_id (A) happens to sit at a LINE ENDPOINT, and Rule 1
    # unconditionally adds the local-min node to the backbone — so the leaf A is
    # pulled in, giving MPR-CDS = {A,B,C,D} (size 4) vs Wu-Li {B,C,D} (size 3).
    #
    # This is NOT an implementation artifact: it is a KNOWN DEFECT of the
    # unconditional Rule 1 in Jacquet 2004's MPR-CDS. Rule-1 additions are often
    # "unnecessary" (Wu) — here a degree-1 leaf joins the backbone without relaying
    # anything. The behavior is faithful to the canonical Rule 1 / Rule 2
    # formulation of preprint §2.4.2. The literature corrects it with EMPR, which
    # gates Rule 1 with the same "≥2 non-connected neighbors" gateway condition as
    # _is_gateway (Wu-Li 1999); EMPR is out of scope for §2.4.2, so we keep the
    # verbatim rule and document the exception rather than asserting the bound.
    wu_li_line = compute_cds(table, algorithm=CDSAlgorithm.WU_LI_1999)
    print(
        f"  line: |MPR-CDS|={len(mpr_cds_line)}  |Wu-Li|={len(wu_li_line)}"
    )
    if len(mpr_cds_line) <= len(wu_li_line):
        print("✅ MPR-CDS ≤ Wu-Li on the line (preprint bound holds): OK")
    else:
        print(
            "ℹ️  MPR-CDS > Wu-Li on this line: global-min id is a leaf endpoint, "
            "so rule (a) forces that leaf into the backbone (documented exception)."
        )

    # Runtime am_i_cds(MPR): Y*'s MPR set comes from what Y* ADVERTISED (get_mpr),
    # NOT a local recomputation. Triangle A,B,C where A (global-min) advertises
    # B as its only MPR. Then B relays (rule b via A's announce), C does not.
    from src.control.hello import build_hello as _bh
    from src.control.hello import known_neighbors_same_group as _kn
    from src.control.hello import parse_hello_private as _ppriv
    from src.control.hello import parse_hello_public as _ppub
    from src.control.neighbors import NeighborTable as _NT

    rt = _NT()
    pubkey = b"\x00" * 32
    a_addr, b_addr, c_addr = addrs[0], addrs[1], addrs[2]
    a_id, b_id = anon_by_addr[a_addr], anon_by_addr[b_addr]
    for src_addr, nbrs, mprs in (
        (a_addr, [b_addr, c_addr], [b_id]),  # A elects B as its MPR
        (b_addr, [a_addr, c_addr], None),
        (c_addr, [a_addr, b_addr], None),
    ):
        pkt = _bh(
            group_key, src_addr, seq=1, known_neighbors=_kn(group_key, nbrs),
            local_public_key=pubkey, mpr_anon_ids=mprs, ts_ms=5_000,
        )
        rt.update_from_hello(_ppub(pkt), _ppriv(pkt, group_key))

    # B is in A's advertised MPR set → B relays.
    assert am_i_cds(b_id, rt, {a_id, anon_by_addr[c_addr]}, CDSAlgorithm.MPR) is True
    # C is NOT in A's advertised MPR set → C does not relay.
    assert am_i_cds(anon_by_addr[c_addr], rt, {a_id, b_id}, CDSAlgorithm.MPR) is False
    # A is the global-min among its peers → rule (a) → relay.
    assert am_i_cds(a_id, rt, {b_id, anon_by_addr[c_addr]}, CDSAlgorithm.MPR) is True
    print("✅ runtime am_i_cds(MPR) uses advertised get_mpr() of Y*: OK")

    # Conservative behavior: if Y*'s MPR Hello hasn't been received, do not relay.
    rt_blind = _NT()
    pkt_b = _bh(
        group_key, b_addr, seq=1, known_neighbors=_kn(group_key, [a_addr, c_addr]),
        local_public_key=pubkey, ts_ms=6_000,
    )
    pkt_c = _bh(
        group_key, c_addr, seq=1, known_neighbors=_kn(group_key, [a_addr, b_addr]),
        local_public_key=pubkey, ts_ms=6_000,
    )
    # Note: no Hello from A → get_mpr() has no entry for Y*=A.
    rt_blind.update_from_hello(_ppub(pkt_b), _ppriv(pkt_b, group_key))
    rt_blind.update_from_hello(_ppub(pkt_c), _ppriv(pkt_c, group_key))
    assert am_i_cds(b_id, rt_blind, {a_id, anon_by_addr[c_addr]}, CDSAlgorithm.MPR) is False
    print("✅ runtime am_i_cds(MPR) conservative when Y* MPR unknown: OK")

    print("\n✅ All CDS self-tests passed")
