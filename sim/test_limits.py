"""
The topological limit study, and the claim it rests on.

The headline result is that the smallest TTL delivering to every node equals the
source's hop eccentricity — the relay backbone forwards along shortest paths and
adds no stretch. That is a statement about the shipped PacketForwarder, not
about the simulator, so it is worth an executable check rather than a line in a
table someone has to trust.

The other thing pinned here is the propagation order. Synchronous delivery walks
the graph depth-first, which no radio does, and the resulting coverage is both
pessimistic and non-monotonic in TTL. Every number in the study depends on that
being fixed, so the fix is tested too.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.forwarding_sim import ForwardingSimEngine  # noqa: E402
from sim.limits import (  # noqa: E402
    RADIUS,
    _sources,
    adjacency,
    hop_distances,
    measure_topology,
    min_ttl_for_full_delivery,
)
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402


def _geometric(n: int, seed: int, degree: float = 6.0):
    """A connected draw at a density that actually percolates."""
    area = _area_for_target_degree(n, radius=RADIUS, target_degree=degree)
    return generate_connected_geometric(n, area, RADIUS, seed=seed)


def _line(n: int) -> dict[str, tuple[float, float]]:
    """A chain: the harshest diameter for a given node count, and exactly known."""
    return {f"AA:AA:AA:AA:AA:{i:02X}": (float(i) * 0.9, 0.0) for i in range(n)}


def _converged(positions, ttl_max=40, algorithm=CDSAlgorithm.WU_LI_1999):
    engine = ForwardingSimEngine(positions, RADIUS, algorithm, ttl_max=ttl_max)
    engine.converge(max_steps=60)
    return engine


# ---- the graph helpers ---------------------------------------------------


def test_hop_distances_on_a_known_chain():
    pos = _line(6)
    adj = adjacency(pos)
    src = sorted(pos)[0]
    dist = hop_distances(adj, src)

    assert dist[sorted(pos)[-1]] == 5
    assert max(dist.values()) == 5


def test_sources_are_spread_not_clustered():
    pos = _line(12)
    picked = _sources(pos, 3)

    assert len(picked) == 3
    assert len(set(picked)) == 3
    # Spread across the address order rather than the first three.
    assert picked != sorted(pos)[:3]


def test_asking_for_more_sources_than_nodes_uses_them_all():
    pos = _line(4)
    assert len(_sources(pos, 99)) == 4


# ---- the claim: no path stretch -----------------------------------------


def test_required_ttl_equals_the_hop_distance_on_a_chain():
    # A chain leaves no alternative route, so any stretch would show immediately.
    pos = _line(8)
    src = sorted(pos)[0]
    engine = _converged(pos)
    ecc = max(hop_distances(adjacency(pos), src).values())

    assert min_ttl_for_full_delivery(engine, src, max_ttl=30, tag="chain") == ecc


def test_one_hop_short_of_the_far_end_leaves_it_out():
    # The boundary is exact: TTL = eccentricity - 1 must not reach everyone.
    pos = _line(8)
    src = sorted(pos)[0]
    engine = _converged(pos)
    ecc = max(hop_distances(adjacency(pos), src).values())

    short = engine.measure_broadcast(src, ttl=ecc - 1, text="short", breadth_first=True)
    exact = engine.measure_broadcast(src, ttl=ecc, text="exact", breadth_first=True)

    assert short.delivery_ratio < 1.0
    assert exact.delivery_ratio == 1.0


def test_no_stretch_on_geometric_topologies_either():
    # The chain is a special case; the study's claim is about random graphs.
    for n, seed in ((20, 1), (30, 2), (40, 3)):
        pos = _geometric(n, seed)
        row = measure_topology(pos, ttl_default=10, max_ttl=40, n_sources=3,
                               algorithm=CDSAlgorithm.WU_LI_1999)
        assert row["min_ttl_full"] == row["eccentricity"], (
            f"n={n}: TTL requis {row['min_ttl_full']} != diametre {row['eccentricity']}"
        )


# ---- the propagation order the study depends on --------------------------


def test_radio_order_never_covers_less_than_call_order():
    # Depth-first arrival locks duplicate suppression onto whichever copy came
    # the long way round, so it can only lose coverage, never gain it.
    pos = _geometric(40, seed=7)
    src = sorted(pos)[0]
    engine = _converged(pos)

    for ttl in (6, 8, 10, 12):
        dfs = engine.measure_broadcast(src, ttl=ttl, text=f"d{ttl}")
        bfs = engine.measure_broadcast(src, ttl=ttl, text=f"b{ttl}", breadth_first=True)
        assert bfs.delivery_ratio >= dfs.delivery_ratio


def test_coverage_only_grows_with_ttl_in_radio_order():
    # Non-monotonic coverage was the symptom that exposed the ordering problem;
    # if it comes back, every table in the study is wrong again.
    pos = _geometric(60, seed=11)
    src = sorted(pos)[0]
    engine = _converged(pos)

    seen = [
        engine.measure_broadcast(src, ttl=t, text=f"m{t}", breadth_first=True).delivery_ratio
        for t in range(2, 22, 2)
    ]
    assert seen == sorted(seen), seen


def test_breadth_first_refuses_to_nest():
    # Two overlapping drains would interleave two floods into one queue.
    pos = _line(4)
    engine = _converged(pos)
    with engine.bus.breadth_first():
        try:
            with engine.bus.breadth_first():
                pass
        except RuntimeError:
            return
    raise AssertionError("l'imbrication aurait du etre refusee")


if __name__ == "__main__":
    for fn in (
        test_hop_distances_on_a_known_chain,
        test_sources_are_spread_not_clustered,
        test_asking_for_more_sources_than_nodes_uses_them_all,
        test_required_ttl_equals_the_hop_distance_on_a_chain,
        test_one_hop_short_of_the_far_end_leaves_it_out,
        test_no_stretch_on_geometric_topologies_either,
        test_radio_order_never_covers_less_than_call_order,
        test_coverage_only_grows_with_ttl_in_radio_order,
        test_breadth_first_refuses_to_nest,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All topological limit tests passed")
