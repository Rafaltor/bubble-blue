from __future__ import annotations

import math
import random
from typing import Iterable

Position = tuple[float, float]


def _bd_addr_for_index(index: int) -> str:
    """Deterministic, distinct BD address for node ``index`` (upper-case MAC)."""
    if index < 0 or index > 0xFFFFFF:
        raise ValueError("index out of range for bd_addr encoding")
    return f"02:00:00:{(index >> 16) & 0xFF:02X}:{(index >> 8) & 0xFF:02X}:{index & 0xFF:02X}"


def generate_geometric(
    n_nodes: int,
    area: float,
    radius: float,
    seed: int,
) -> dict[str, Position]:
    """
    Place ``n_nodes`` uniformly in ``[0, area] × [0, area]`` (deterministic).

    Uses a local ``random.Random(seed)`` instance — never the global ``random``
    module — for strict reproducibility and isolation between calls.

    Returns ``bd_addr -> (x, y)`` with distinct upper-case BD addresses.
    """
    if n_nodes < 1:
        raise ValueError("n_nodes must be >= 1")
    if area <= 0:
        raise ValueError("area must be > 0")
    if radius <= 0:
        raise ValueError("radius must be > 0")

    rng = random.Random(seed)
    out: dict[str, Position] = {}
    for i in range(n_nodes):
        bd = _bd_addr_for_index(i)
        x = rng.uniform(0.0, area)
        y = rng.uniform(0.0, area)
        out[bd] = (x, y)
    return out


def expected_mean_degree(n_nodes: int, area: float, radius: float) -> float:
    """
    Theoretical mean degree in a uniform geometric graph (unit-disk model).

    Approximation: each node sees roughly a fraction ``π r² / area²`` of the
    square occupied by others → ``n_nodes * π r² / area²``.
    """
    if n_nodes < 1:
        return 0.0
    if area <= 0 or radius <= 0:
        raise ValueError("area and radius must be > 0")
    return n_nodes * math.pi * radius * radius / (area * area)


def _distance(a: Position, b: Position) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def _mean_degree(positions: dict[str, Position], radius: float) -> float:
    if not positions:
        return 0.0
    bds = list(positions)
    coords = [positions[bd] for bd in bds]
    n = len(bds)
    total = 0
    for i in range(n):
        deg = 0
        for j in range(n):
            if i == j:
                continue
            if _distance(coords[i], coords[j]) <= radius:
                deg += 1
        total += deg
    return total / n


def is_connected(positions: dict[str, Position], radius: float) -> bool:
    """
    True iff the unit-disk graph (edge iff Euclidean distance <= radius) is
    connected. A single node is connected by convention.
    """
    if len(positions) <= 1:
        return True
    if radius <= 0:
        raise ValueError("radius must be > 0")

    bds = list(positions)
    coords = [positions[bd] for bd in bds]
    n = len(bds)

    # Adjacency lists (undirected).
    adj: list[list[int]] = [[] for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            if _distance(coords[i], coords[j]) <= radius:
                adj[i].append(j)
                adj[j].append(i)

    start = 0
    seen = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for nb in adj[cur]:
            if nb not in seen:
                seen.add(nb)
                stack.append(nb)
    return len(seen) == n


def generate_connected_geometric(
    n_nodes: int,
    area: float,
    radius: float,
    seed: int,
    *,
    max_tries: int = 100,
) -> dict[str, Position]:
    """
    Like ``generate_geometric``, but retry with incremented seeds until connected.

    Methodological note: filtering for connectivity slightly biases toward
    denser realisations (more edges than a uniformly disconnected draw). Mention
    this when reporting comparative Wu-Li vs MPR results.

    Raises ``RuntimeError`` if no connected graph is found within ``max_tries``
    (typically the density ``(n_nodes, area, radius)`` is too low).
    """
    if max_tries < 1:
        raise ValueError("max_tries must be >= 1")

    for attempt in range(max_tries):
        trial_seed = seed + attempt
        positions = generate_geometric(n_nodes, area, radius, trial_seed)
        if is_connected(positions, radius):
            return positions

    raise RuntimeError(
        f"no connected geometric graph after {max_tries} tries "
        f"(n_nodes={n_nodes}, area={area}, radius={radius}, seed={seed}); "
        f"expected_mean_degree={expected_mean_degree(n_nodes, area, radius):.2f} "
        "— density may be too low for connectivity"
    )


def _summarize(
    label: str,
    positions: dict[str, Position],
    area: float,
    radius: float,
) -> None:
    n = len(positions)
    exp_deg = expected_mean_degree(n, area, radius)
    act_deg = _mean_degree(positions, radius)
    connected = is_connected(positions, radius)
    print(
        f"{label}: n={n}  E[deg]={exp_deg:.2f}  mean_deg={act_deg:.2f}  "
        f"connected={connected}"
    )


if __name__ == "__main__":
    # Sample densities via (n_nodes, area, radius). Geometry only — no sim engine.
    scenarios: Iterable[tuple[str, int, float, float, int]] = (
        ("sparse", 20, 100.0, 8.0, 1),
        ("medium", 40, 80.0, 12.0, 2),
        ("dense", 50, 60.0, 15.0, 3),
    )
    for label, n, area, r, seed in scenarios:
        pos = generate_geometric(n, area, r, seed)
        _summarize(label, pos, area, r)

    print("\nconnected retry (peloton-friendly):")
    peloton = generate_connected_geometric(30, 70.0, 14.0, seed=42)
    _summarize("peloton", peloton, 70.0, 14.0)
    print("\n✅ topology_gen self-check done")
