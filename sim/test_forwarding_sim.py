from __future__ import annotations

# Forwarding overhead validation: hand-countable unicasts (cases 1–3) and full
# delivery on connected geometric graphs (case 4). Protects data_unicast_count and
# measure_broadcast before sweep / rapport metrics.

import math
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.forwarding.cds import CDSAlgorithm  # noqa: E402

from sim.forwarding_sim import (  # noqa: E402
    ForwardingSimEngine,
    _line_positions,
    delivery_depth_from_waves,
)
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import _bd_addr_for_index, generate_connected_geometric  # noqa: E402

_RADIUS = 1.0
_MAX_STEPS = 50
_ALGORITHMS = (CDSAlgorithm.WU_LI_1999, CDSAlgorithm.MPR)


def _star_positions() -> tuple[dict[str, tuple[float, float]], str, list[str]]:
    """Hub at origin, three leaves on a circle at 0.9·R (pairwise out of range)."""
    hub = _bd_addr_for_index(0)
    leaves = [_bd_addr_for_index(i) for i in (1, 2, 3)]
    dist = 0.9 * _RADIUS
    positions: dict[str, tuple[float, float]] = {hub: (0.0, 0.0)}
    for i, leaf in enumerate(leaves):
        angle = i * 2.0 * math.pi / 3.0
        positions[leaf] = (dist * math.cos(angle), dist * math.sin(angle))
    return positions, hub, leaves


def _assert_exact_overhead(
    case: str,
    positions: dict[str, tuple[float, float]],
    source: str,
    ttl: int,
    expected_unicasts: int,
    *,
    algorithms: tuple[CDSAlgorithm, ...] = _ALGORITHMS,
) -> None:
    for algo in algorithms:
        engine = ForwardingSimEngine(positions, _RADIUS, algo, ttl_max=ttl)
        engine.converge(max_steps=_MAX_STEPS)
        metrics = engine.measure_broadcast(source, ttl, text=f"{case}-{algo.value}")

        if metrics.data_unicasts != expected_unicasts:
            raise AssertionError(
                f"[{case} {algo.value}] data_unicasts={metrics.data_unicasts}, "
                f"expected {expected_unicasts} (manual propagation count)\n"
                f"  source={source}, ttl={ttl}, backbone={metrics.backbone_size}, "
                f"roles={engine.roles()}"
            )
        if metrics.delivery_ratio != 1.0:
            n = len(positions)
            missed = sorted(
                bd for bd in positions if bd != source and bd not in metrics.receivers
            )
            raise AssertionError(
                f"[{case} {algo.value}] delivery_ratio={metrics.delivery_ratio}, "
                f"expected 1.0\n"
                f"  source={source}, missed={missed}, "
                f"receivers={len(metrics.receivers)}/{n - 1}"
            )

    print(f"✅ {case}: {expected_unicasts} unicasts, delivery 100% ({len(algorithms)} algos)")


def test_line5_endpoint() -> None:
    """
    Line A—B—C—D—E, source A, ttl=5.

    Manual path: A→B, B→C, C→D, D→E → 4 data unicasts, 100% delivery.
  Wu-Li and MPR share the same 3-relay backbone on a line.
    """
    n = 5
    positions = _line_positions(n)
    source = sorted(positions)[0]
    _assert_exact_overhead(
        "line5-endpoint",
        positions,
        source,
        ttl=n,
        expected_unicasts=4,
    )


def test_star_hub_source() -> None:
    """
    Star: hub is the sole relay; broadcast from hub → 3 leaf unicasts, no relay.
    """
    positions, hub, _leaves = _star_positions()
    _assert_exact_overhead(
        "star-hub",
        positions,
        hub,
        ttl=len(positions),
        expected_unicasts=3,
    )


def test_star_leaf_source() -> None:
    """
    Star: leaf → hub (1), hub relays to the other two leaves (2) → 3 unicasts total.
    """
    positions, _hub, leaves = _star_positions()
    _assert_exact_overhead(
        "star-leaf",
        positions,
        leaves[0],
        ttl=len(positions),
        expected_unicasts=3,
    )


def test_waves_journal_matches_counter() -> None:
    """Journal total_unicasts must equal measure_broadcast data_unicast_count."""
    positions = _line_positions(5)
    source = sorted(positions)[0]
    ttl = 5
    for algo in _ALGORITHMS:
        engine = ForwardingSimEngine(positions, _RADIUS, algo, ttl_max=ttl)
        engine.converge(max_steps=_MAX_STEPS)
        text = f"waves-{algo.value}"
        metrics = engine.measure_broadcast(source, ttl, text=text)
        engine2 = ForwardingSimEngine(positions, _RADIUS, algo, ttl_max=ttl)
        engine2.converge(max_steps=_MAX_STEPS)
        waves = engine2.measure_broadcast_with_waves(source, ttl, text=text)
        if waves["total_unicasts"] != metrics.data_unicasts:
            raise AssertionError(
                f"[waves {algo.value}] journal total {waves['total_unicasts']} "
                f"!= measure_broadcast {metrics.data_unicasts}"
            )
        wave_sum = sum(len(w["unicasts"]) for w in waves["waves"])
        if wave_sum != waves["total_unicasts"]:
            raise AssertionError(f"[waves {algo.value}] wave unicast sum mismatch")
    print("✅ waves journal cross-check: total_unicasts == measure_broadcast counter")


def _run_waves(
    positions: dict[str, tuple[float, float]],
    source: str,
    ttl: int,
    *,
    algo: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
) -> dict:
    engine = ForwardingSimEngine(positions, _RADIUS, algo, ttl_max=ttl)
    return engine.measure_broadcast_with_waves(
        source, ttl, text="wave-shape-test", max_steps=_MAX_STEPS
    )


def _square_positions() -> tuple[dict[str, tuple[float, float]], str]:
    """Cycle A—B—C—D—A (unit square, R=1)."""
    nodes = [_bd_addr_for_index(i) for i in range(4)]
    a, b, c, d = nodes
    positions = {a: (0.0, 0.0), b: (1.0, 0.0), c: (1.0, 1.0), d: (0.0, 1.0)}
    return positions, a


def _assert_cumulative_strict_growth(
    waves: list[dict],
    source: str,
    all_bds: set[str],
) -> None:
    """cumulative_reached grows by newly_reached each wave until all non-source nodes."""
    prev: set[str] = set()
    for w in waves:
        newly = set(w["newly_reached"])
        cum = set(w["cumulative_reached"])
        if not newly.issubset(cum):
            raise AssertionError(f"newly_reached not subset of cumulative: wave {w['wave']}")
        if len(cum) != len(prev) + len(newly):
            raise AssertionError(
                f"cumulative size mismatch wave {w['wave']}: "
                f"|prev|={len(prev)} + |newly|={len(newly)} != |cum|={len(cum)}"
            )
        if not prev.issubset(cum):
            raise AssertionError(f"cumulative not monotonic at wave {w['wave']}")
        if newly & prev:
            raise AssertionError(
                f"newly_reached overlaps prior cumulative at wave {w['wave']}: {newly & prev}"
            )
        prev = cum
    expected = all_bds - {source.upper()}
    if prev != expected:
        raise AssertionError(
            f"cumulative_reached final {sorted(prev)} != expected {sorted(expected)}"
        )


def test_waves_line5_sequential() -> None:
    """
    Line A—B—C—D—E from A: 4 waves, 1 unicast each, chain delivery B→C→D→E.
    """
    positions = _line_positions(5)
    chain = sorted(positions)
    source = chain[0]
    ttl = 5
    for algo in _ALGORITHMS:
        r = _run_waves(positions, source, ttl, algo=algo)
        if r["n_waves"] != 4:
            raise AssertionError(f"[line waves {algo.value}] n_waves={r['n_waves']}, expected 4")
        if r["delivery_depth"] != 4:
            raise AssertionError(
                f"[line waves {algo.value}] delivery_depth={r['delivery_depth']}, expected 4"
            )
        for i, w in enumerate(r["waves"]):
            if len(w["unicasts"]) != 1:
                raise AssertionError(
                    f"[line waves {algo.value}] wave {i}: "
                    f"{len(w['unicasts'])} unicasts, expected 1"
                )
            expected_node = chain[i + 1]
            if w["newly_reached"] != [expected_node]:
                raise AssertionError(
                    f"[line waves {algo.value}] wave {i}: "
                    f"newly_reached={w['newly_reached']}, expected [{expected_node}]"
                )
            if w["cumulative_reached"] != chain[1 : i + 2]:
                raise AssertionError(
                    f"[line waves {algo.value}] wave {i}: bad cumulative {w['cumulative_reached']}"
                )
    print("✅ waves line5: 4 sequential waves, 1 unicast each, chain delivery")


def test_waves_star_hub_single() -> None:
    """Star from hub: one wave, k unicasts to all leaves."""
    positions, hub, leaves = _star_positions()
    k = len(leaves)
    ttl = len(positions)
    for algo in _ALGORITHMS:
        r = _run_waves(positions, hub, ttl, algo=algo)
        if r["n_waves"] != 1:
            raise AssertionError(f"[star-hub waves {algo.value}] n_waves={r['n_waves']}")
        if r["delivery_depth"] != 1:
            raise AssertionError(
                f"[star-hub waves {algo.value}] delivery_depth={r['delivery_depth']}"
            )
        w0 = r["waves"][0]
        if len(w0["unicasts"]) != k:
            raise AssertionError(
                f"[star-hub waves {algo.value}] wave 0: {len(w0['unicasts'])} unicasts, expected {k}"
            )
        if set(w0["newly_reached"]) != set(leaves):
            raise AssertionError(
                f"[star-hub waves {algo.value}] newly_reached={w0['newly_reached']}"
            )
    print(f"✅ waves star-hub: 1 wave, {k} unicasts, all leaves newly_reached")


def test_waves_star_leaf_two_hops() -> None:
    """Star from leaf: wave 0 leaf→hub, wave 1 hub→other leaves."""
    positions, hub, leaves = _star_positions()
    leaf = leaves[0]
    others = leaves[1:]
    ttl = len(positions)
    for algo in _ALGORITHMS:
        r = _run_waves(positions, leaf, ttl, algo=algo)
        if r["n_waves"] != 2:
            raise AssertionError(f"[star-leaf waves {algo.value}] n_waves={r['n_waves']}")
        if r["delivery_depth"] != 2:
            raise AssertionError(
                f"[star-leaf waves {algo.value}] delivery_depth={r['delivery_depth']}"
            )
        w0, w1 = r["waves"]
        if len(w0["unicasts"]) != 1 or w0["unicasts"][0]["to"] != hub:
            raise AssertionError(f"[star-leaf waves {algo.value}] wave 0: {w0['unicasts']}")
        if w0["newly_reached"] != [hub]:
            raise AssertionError(
                f"[star-leaf waves {algo.value}] wave 0 newly={w0['newly_reached']}"
            )
        if len(w1["unicasts"]) != len(others):
            raise AssertionError(
                f"[star-leaf waves {algo.value}] wave 1: "
                f"{len(w1['unicasts'])} unicasts, expected {len(others)}"
            )
        if set(w1["newly_reached"]) != set(others):
            raise AssertionError(
                f"[star-leaf waves {algo.value}] wave 1 newly={w1['newly_reached']}"
            )
    print("✅ waves star-leaf: 2 waves (1→hub, then hub→others)")


def test_waves_ghost_after_full_coverage() -> None:
    """
    On cyclic/dense graphs, post-coverage waves may carry unicasts (dedup overhead)
    but must not add newly_reached. n_waves may exceed delivery_depth.
    """
    cases: list[tuple[str, dict, str, int]] = []
    sq, sq_src = _square_positions()
    cases.append(("square", sq, sq_src, 4))

    area = _area_for_target_degree(10, _RADIUS, 8.0)
    geo = generate_connected_geometric(10, area, _RADIUS, seed=3)
    cases.append(("geo-seed3", geo, sorted(geo)[0], 10))

    for label, positions, source, ttl in cases:
        r = _run_waves(positions, source, ttl)
        waves = r["waves"]
        _assert_cumulative_strict_growth(waves, source, set(positions))

        depth = delivery_depth_from_waves(waves)
        if r["delivery_depth"] != depth:
            raise AssertionError(f"[{label}] delivery_depth field != helper")

        full_at = None
        expected = set(positions) - {source.upper()}
        for w in waves:
            if set(w["cumulative_reached"]) == expected:
                full_at = int(w["wave"])
                break
        if full_at is None:
            raise AssertionError(f"[{label}] never reached full coverage in cumulative")

        for w in waves:
            if int(w["wave"]) > full_at and w["newly_reached"]:
                raise AssertionError(
                    f"[{label}] phantom newly_reached after full coverage "
                    f"at wave {w['wave']}: {w['newly_reached']}"
                )

        ghost_waves = [w for w in waves if not w["newly_reached"]]
        if ghost_waves:
            ghost_u = sum(len(w["unicasts"]) for w in ghost_waves)
            print(
                f"ℹ️  [{label}] {len(ghost_waves)} ghost wave(s) "
                f"({ghost_u} unicasts overhead), "
                f"n_waves={r['n_waves']} > delivery_depth={depth}"
            )
            if r["n_waves"] <= depth:
                raise AssertionError(f"[{label}] expected n_waves > delivery_depth")
        else:
            if r["n_waves"] != depth:
                raise AssertionError(
                    f"[{label}] no ghost waves but n_waves={r['n_waves']} != depth={depth}"
                )

    print("✅ waves ghost check: cumulative strict growth, no post-coverage newly_reached")


def test_geometric_full_delivery() -> None:
    """
    On several connected geometric graphs, every source must reach all other nodes
    with ttl = n_nodes (Wu-Li and MPR). Failure ⇒ TTL too short or incomplete CDS.
    """
    n_nodes = 10
    target_degree = 5.0
    seeds = (0, 20, 100, 9451, 42)

    for seed in seeds:
        area = _area_for_target_degree(n_nodes, _RADIUS, target_degree)
        positions = generate_connected_geometric(n_nodes, area, _RADIUS, seed)
        ttl = n_nodes
        sources = sorted(positions)

        for algo in _ALGORITHMS:
            engine = ForwardingSimEngine(positions, _RADIUS, algo, ttl_max=ttl)
            engine.converge(max_steps=_MAX_STEPS)
            if engine.convergence and engine.convergence.status != "fixed_point":
                print(
                    f"ℹ️  seed={seed} {algo.value}: convergence={engine.convergence.status} "
                    f"(still checking delivery)"
                )

            for source in sources:
                metrics = engine.measure_broadcast(
                    source, ttl, text=f"cov-{seed}-{algo.value}"
                )
                if metrics.delivery_ratio == 1.0:
                    continue

                expected = set(positions) - {source}
                missed = sorted(expected - set(metrics.receivers))
                raise AssertionError(
                    f"[coverage seed={seed} {algo.value}] delivery < 100%\n"
                    f"  topology: n={n_nodes}, area={area:.4f}, radius={_RADIUS}, "
                    f"target_degree={target_degree}\n"
                    f"  source={source}, delivery_ratio={metrics.delivery_ratio}\n"
                    f"  backbone_size={metrics.backbone_size}, "
                    f"convergence={metrics.convergence_status}\n"
                    f"  missed nodes ({len(missed)}): {missed}\n"
                    f"  roles={engine.roles()}"
                )

        print(f"✅ geometric coverage seed={seed}: {len(sources)} sources × 2 algos, delivery 100%")


if __name__ == "__main__":
    test_line5_endpoint()
    test_star_hub_source()
    test_star_leaf_source()
    test_waves_journal_matches_counter()
    test_waves_line5_sequential()
    test_waves_star_hub_single()
    test_waves_star_leaf_two_hops()
    test_waves_ghost_after_full_coverage()
    test_geometric_full_delivery()
    print("\n✅ forwarding_sim overhead tests passed (exact counts + full delivery)")
