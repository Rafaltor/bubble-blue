from __future__ import annotations

import math
import statistics
from typing import Any

from src.forwarding.cds import CDSAlgorithm

from sim.sim_engine import ConvergenceResult, SimEngine
from sim.topology_gen import expected_mean_degree, generate_connected_geometric

Position = dict[str, tuple[float, float]]


def _roles_snapshot(engine: SimEngine) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(engine.roles().items()))


def _relay_count(engine: SimEngine) -> int:
    return sum(1 for role in engine.roles().values() if role == "RELAY")


def _run_with_history(
    engine: SimEngine,
    max_steps: int,
) -> tuple[ConvergenceResult, list[int]]:
    """
    Mirror ``SimEngine.run_until_stable`` while recording relay counts per step.

    ``relay_counts[0]`` is the initial count; ``relay_counts[k]`` after step k.
    """
    if max_steps < 1:
        raise ValueError("max_steps must be >= 1")

    relay_counts = [_relay_count(engine)]
    history: list[tuple[tuple[str, str], ...]] = [_roles_snapshot(engine)]

    for step in range(1, max_steps + 1):
        engine.step()
        snapshot = _roles_snapshot(engine)
        relay_counts.append(_relay_count(engine))

        if snapshot == history[-1]:
            return (
                ConvergenceResult(steps=step, status="fixed_point", period=1),
                relay_counts,
            )

        for i, prior in enumerate(history):
            if snapshot == prior:
                period = len(history) - i
                if period > 1:
                    return (
                        ConvergenceResult(steps=step, status="cycle", period=period),
                        relay_counts,
                    )
                break

        history.append(snapshot)

    return (
        ConvergenceResult(steps=max_steps, status="max_steps", period=0),
        relay_counts,
    )


def run_one(
    positions: Position,
    radius: float,
    algorithm: CDSAlgorithm,
    max_steps: int = 50,
) -> dict[str, Any]:
    """
    Run one algorithm on one topology and return CDS size + convergence metrics.

    ``cds_size`` is only defined at a fixed point. Oscillating or non-convergent
    runs set ``cds_size`` to None and set ``oscillates`` / ``did_not_converge``.
    For cycles, ``cds_size_cycle_mean`` averages relay counts over one period
    (last ``period`` steps of the detected cycle) — documented as optional,
    not a substitute for a stable backbone size.
    """
    engine = SimEngine(positions, radius, algorithm=algorithm)
    result, relay_counts = _run_with_history(engine, max_steps)

    out: dict[str, Any] = {
        "n_nodes": len(positions),
        "algorithm": algorithm.value,
        "convergence_status": result.status,
        "convergence_steps": result.steps,
        "convergence_period": result.period,
        "cds_size": None,
        "oscillates": False,
        "did_not_converge": False,
        "cds_size_cycle_mean": None,
    }

    if result.status == "fixed_point":
        out["cds_size"] = _relay_count(engine)
    elif result.status == "cycle":
        out["oscillates"] = True
        # One period = relay counts for snapshots history[i..] that repeat;
        # align with last `period` post-step counts before closure.
        period = result.period
        if period >= 1 and len(relay_counts) >= period:
            window = relay_counts[-period:]
            out["cds_size_cycle_mean"] = sum(window) / len(window)
    else:
        out["did_not_converge"] = True

    return out


def compare_one(
    positions: Position,
    radius: float,
    max_steps: int = 50,
) -> dict[str, Any]:
    """Fair comparison: same positions, Wu-Li 1999 vs MPR."""
    wu_li = run_one(positions, radius, CDSAlgorithm.WU_LI_1999, max_steps=max_steps)
    mpr = run_one(positions, radius, CDSAlgorithm.MPR, max_steps=max_steps)

    delta: int | None = None
    if (
        wu_li["convergence_status"] == "fixed_point"
        and mpr["convergence_status"] == "fixed_point"
        and wu_li["cds_size"] is not None
        and mpr["cds_size"] is not None
    ):
        delta = int(mpr["cds_size"]) - int(wu_li["cds_size"])

    return {
        "wu_li": wu_li,
        "mpr": mpr,
        "delta_cds_size": delta,
        "both_fixed_point": delta is not None,
    }


def _fixed_point_stats(sizes: list[int]) -> dict[str, float | int | None]:
    if not sizes:
        return {"count": 0, "mean": None, "stdev": None, "min": None, "max": None}
    return {
        "count": len(sizes),
        "mean": statistics.mean(sizes),
        "stdev": statistics.stdev(sizes) if len(sizes) > 1 else 0.0,
        "min": min(sizes),
        "max": max(sizes),
    }


def sweep(
    n_nodes: int,
    area: float,
    radius: float,
    n_seeds: int,
    base_seed: int = 0,
    max_steps: int = 50,
) -> dict[str, Any]:
    """
    Aggregate metrics over ``n_seeds`` connected geometric topologies.

    CDS size means/std are computed ONLY on topologies where that algorithm
    reached a fixed point. Oscillating or max_steps runs are counted separately
    and excluded from size averages (no defined stable backbone size).
    """
    if n_seeds < 1:
        raise ValueError("n_seeds must be >= 1")

    comparisons: list[dict[str, Any]] = []
    wu_li_sizes: list[int] = []
    mpr_sizes: list[int] = []
    wu_li_steps: list[int] = []
    mpr_steps: list[int] = []
    deltas: list[int] = []

    status_counts = {
        "wu_li_fixed": 0,
        "wu_li_cycle": 0,
        "wu_li_max_steps": 0,
        "mpr_fixed": 0,
        "mpr_cycle": 0,
        "mpr_max_steps": 0,
        "both_fixed": 0,
    }

    for seed in range(base_seed, base_seed + n_seeds):
        positions = generate_connected_geometric(n_nodes, area, radius, seed)
        cmp = compare_one(positions, radius, max_steps=max_steps)
        comparisons.append({"seed": seed, **cmp})

        wu = cmp["wu_li"]
        mp = cmp["mpr"]

        if wu["convergence_status"] == "fixed_point":
            status_counts["wu_li_fixed"] += 1
            if wu["cds_size"] is not None:
                wu_li_sizes.append(int(wu["cds_size"]))
                wu_li_steps.append(int(wu["convergence_steps"]))
        elif wu["convergence_status"] == "cycle":
            status_counts["wu_li_cycle"] += 1
        else:
            status_counts["wu_li_max_steps"] += 1

        if mp["convergence_status"] == "fixed_point":
            status_counts["mpr_fixed"] += 1
            if mp["cds_size"] is not None:
                mpr_sizes.append(int(mp["cds_size"]))
                mpr_steps.append(int(mp["convergence_steps"]))
        elif mp["convergence_status"] == "cycle":
            status_counts["mpr_cycle"] += 1
        else:
            status_counts["mpr_max_steps"] += 1

        if cmp["both_fixed_point"] and cmp["delta_cds_size"] is not None:
            status_counts["both_fixed"] += 1
            deltas.append(int(cmp["delta_cds_size"]))

    exp_deg = expected_mean_degree(n_nodes, area, radius)
    delta_stats = _fixed_point_stats(deltas)

    return {
        "n_nodes": n_nodes,
        "area": area,
        "radius": radius,
        "n_seeds": n_seeds,
        "expected_mean_degree": exp_deg,
        "status_counts": status_counts,
        "wu_li": {
            **_fixed_point_stats(wu_li_sizes),
            "mean_convergence_steps": (
                statistics.mean(wu_li_steps) if wu_li_steps else None
            ),
            "pct_fixed": 100.0 * status_counts["wu_li_fixed"] / n_seeds,
            "pct_cycle": 100.0 * status_counts["wu_li_cycle"] / n_seeds,
            "pct_max_steps": 100.0 * status_counts["wu_li_max_steps"] / n_seeds,
        },
        "mpr": {
            **_fixed_point_stats(mpr_sizes),
            "mean_convergence_steps": (
                statistics.mean(mpr_steps) if mpr_steps else None
            ),
            "pct_fixed": 100.0 * status_counts["mpr_fixed"] / n_seeds,
            "pct_cycle": 100.0 * status_counts["mpr_cycle"] / n_seeds,
            "pct_max_steps": 100.0 * status_counts["mpr_max_steps"] / n_seeds,
        },
        "delta_cds_size_mpr_minus_wu_li": delta_stats,
        "comparisons": comparisons,
    }


def _area_for_target_degree(n_nodes: int, radius: float, target_degree: float) -> float:
    if target_degree <= 0:
        raise ValueError("target_degree must be > 0")
    return math.sqrt(n_nodes * math.pi * radius * radius / target_degree)


def _fmt_stats(label: str, block: dict[str, Any]) -> str:
    mean = block.get("mean")
    stdev = block.get("stdev")
    size_part = (
        f"{mean:.2f} ± {stdev:.2f}" if mean is not None and stdev is not None else "n/a"
    )
    steps = block.get("mean_convergence_steps")
    steps_part = f"{steps:.1f}" if steps is not None else "n/a"
    return (
        f"  {label:10s}  cds_size {size_part}  (n={block.get('count', 0)})  "
        f"fixed {block.get('pct_fixed', 0):.0f}%  "
        f"cycle {block.get('pct_cycle', 0):.0f}%  "
        f"max_steps {block.get('pct_max_steps', 0):.0f}%  "
        f"mean_steps {steps_part}"
    )


if __name__ == "__main__":
    # Peloton-like sweep: ~5 expected mean degree, reproducible seeds.
    # MPR cycles (when they occur) are election instability data for the rapport,
    # not simulator bugs — never fold them into stable CDS size averages.
    N_NODES = 15
    RADIUS = 1.0
    TARGET_DEG = 5.0
    AREA = _area_for_target_degree(N_NODES, RADIUS, TARGET_DEG)
    N_SEEDS = 20

    report = sweep(N_NODES, AREA, RADIUS, N_SEEDS, base_seed=0, max_steps=50)

    print(
        f"sweep: n={N_NODES}  area={AREA:.2f}  R={RADIUS}  "
        f"E[deg]={report['expected_mean_degree']:.2f}  seeds={N_SEEDS}"
    )
    print(_fmt_stats("Wu-Li", report["wu_li"]))
    print(_fmt_stats("MPR", report["mpr"]))

    delta = report["delta_cds_size_mpr_minus_wu_li"]
    if delta["count"]:
        print(
            f"  delta (MPR−Wu-Li) on both-fixed topologies: "
            f"{delta['mean']:.2f} ± {delta['stdev']:.2f}  (n={delta['count']})"
        )
    else:
        print("  delta (MPR−Wu-Li): n/a (no topology where both algorithms fixed)")

    print("\n✅ metrics_roles sweep done")
