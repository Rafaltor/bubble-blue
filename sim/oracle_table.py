from __future__ import annotations

import math

from src.control.hello import build_hello, known_neighbors_same_group, parse_hello_private, parse_hello_public
from src.control.neighbors import NeighborTable
from src.forwarding.cds import CDSAlgorithm, compute_cds

from sim.sim_engine import _GK

Position = dict[str, tuple[float, float]]


def neighbor_map_from_positions(positions: Position, radius: float) -> dict[str, list[str]]:
    """Ground-truth 1-hop adjacency from unit-disk geometry (sorted neighbor lists)."""
    if radius <= 0:
        raise ValueError("radius must be > 0")
    bds = sorted(positions)
    coords = [positions[bd] for bd in bds]
    out: dict[str, list[str]] = {bd: [] for bd in bds}
    for i, bd in enumerate(bds):
        xi, yi = coords[i]
        for j, nb in enumerate(bds):
            if i == j:
                continue
            xj, yj = coords[j]
            if math.hypot(xi - xj, yi - yj) <= radius:
                out[bd].append(nb)
        out[bd] = sorted(out[bd])
    return out


def build_merged_table(
    neighbor_map: dict[str, list[str]],
    group_key: bytes = _GK,
) -> NeighborTable:
    """Merged NeighborTable from ground-truth adjacency (oracle for ``compute_cds``)."""
    merged = NeighborTable()
    addrs = sorted(neighbor_map)
    for i, addr in enumerate(addrs):
        pkt = build_hello(
            group_key,
            addr,
            seq=i + 1,
            known_neighbors=known_neighbors_same_group(group_key, neighbor_map[addr]),
            local_public_key=b"\x00" * 31 + bytes([i + 1]),
            anon_id_key=group_key,
            ts_ms=1_000 + i,
        )
        merged.update_from_hello(parse_hello_public(pkt), parse_hello_private(pkt, group_key))
    return merged


def global_cds_size(
    neighbor_map: dict[str, list[str]],
    algorithm: CDSAlgorithm,
    group_key: bytes = _GK,
) -> int:
    """``len(compute_cds(...))`` on a merged table built from ground-truth links."""
    merged = build_merged_table(neighbor_map, group_key=group_key)
    return len(compute_cds(merged, algorithm=algorithm))
