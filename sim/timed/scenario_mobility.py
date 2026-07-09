"""
End-to-end mobility scenarios: TimedEngine + random waypoint + NetworkObserver.

``run_mobility_scenario`` wires protocol simulation, mobility, and periodic
observation into one reproducible run. ``compare_mobility`` runs the **same**
initial layout and mobility seed under Wu-Li 1999 and MPR — the scientific
comparison for *which CDS algorithm is more stable under mobility*.

``run_timed_timeline`` returns frame-by-frame positions, edges, and roles for
animation (same observer snapshots, JSON-serializable).

Metrics come from :meth:`sim.timed.observer.NetworkObserver.summary` (optionally
scoped with ``since_t`` to skip startup transients).
"""

from __future__ import annotations

import random
from typing import Any, Literal

from src.forwarding.cds import CDSAlgorithm

from sim.topology_gen import Position, generate_connected_geometric
from sim.timed.mobility import PelotonGroup, PelotonMobility, RandomWaypointMobility
from sim.timed.observer import NetworkObserver, Snapshot
from sim.timed.timed_engine import TimedEngine

Metrics = dict[str, Any]
MobilityModelName = Literal["waypoint", "peloton"]


def _attach_mobility(
    engine: TimedEngine,
    *,
    area: float,
    speed_min: float,
    speed_max: float,
    pause_min_s: float,
    pause_max_s: float,
    mobility_seed: int,
    update_interval_s: float,
    mobility_model: MobilityModelName = "waypoint",
) -> None:
    if speed_max <= 0.0:
        return

    if mobility_model == "peloton":
        group = PelotonGroup(
            engine.env,
            area=area,
            speed_min=speed_min,
            speed_max=speed_max,
            pause_min_s=pause_min_s,
            pause_max_s=pause_max_s,
            rng=random.Random(mobility_seed),
            update_interval_s=update_interval_s,
        )
        for index, bd in enumerate(sorted(engine.nodes)):
            mobile = PelotonMobility(
                engine.env,
                engine.bus,
                bd,
                area=area,
                speed_min=speed_min,
                speed_max=speed_max,
                pause_min_s=pause_min_s,
                pause_max_s=pause_max_s,
                group=group,
                rng=random.Random(mobility_seed * 10_007 + index),
                update_interval_s=update_interval_s,
            )
            engine.env.process(mobile.walk_process())
        return

    for index, bd in enumerate(sorted(engine.nodes)):
        mobile = RandomWaypointMobility(
            engine.env,
            engine.bus,
            bd,
            area=area,
            speed_min=speed_min,
            speed_max=speed_max,
            pause_min_s=pause_min_s,
            pause_max_s=pause_max_s,
            rng=random.Random(mobility_seed * 10_007 + index),
            update_interval_s=update_interval_s,
        )
        engine.env.process(mobile.walk_process())


def _snapshot_to_frame(snap: Snapshot) -> dict[str, Any]:
    return {
        "t": snap["t"],
        "positions": snap["positions"],
        "edges": snap["edges"],
        "roles": snap["roles"],
        "relay_count": snap["relay_count"],
        "cds_valid": snap["cds_valid"],
        "uncovered_nodes": snap["uncovered_nodes"],
    }


def _setup_timed_scenario(
    n_nodes: int,
    area: float,
    radius: float,
    algorithm: CDSAlgorithm,
    *,
    speed: float = 1.0,
    speed_max: float | None = None,
    hello_interval_s: float = 5.0,
    seed: int = 0,
    jitter_frac: float = 0.1,
    tx_latency_s: float = 0.003,
    loss_prob: float = 0.0,
    sample_interval_s: float = 1.0,
    pause_min_s: float = 1.0,
    pause_max_s: float = 3.0,
    mobility_update_interval_s: float = 0.5,
    mobility_seed: int | None = None,
    mobility_model: MobilityModelName = "waypoint",
    positions: dict[str, Position] | None = None,
) -> tuple[TimedEngine, NetworkObserver, dict[str, Any]]:
    """
    Build TimedEngine + mobility + observer (process started, not yet run).
    """
    if positions is None:
        positions = generate_connected_geometric(n_nodes, area, radius, seed)
    elif len(positions) != n_nodes:
        raise ValueError(f"positions has {len(positions)} nodes, expected {n_nodes}")

    mob_seed = seed if mobility_seed is None else mobility_seed
    speed_min = max(0.0, float(speed))
    speed_hi = speed_min if speed_max is None else max(speed_min, float(speed_max))
    mobility_on = speed_hi > 0.0

    engine = TimedEngine(
        positions,
        radius,
        algorithm=algorithm,
        hello_interval_s=hello_interval_s,
        jitter_frac=jitter_frac,
        tx_latency_s=tx_latency_s,
        loss_prob=loss_prob,
        seed=seed,
    )
    if mobility_on:
        _attach_mobility(
            engine,
            area=area,
            speed_min=speed_min,
            speed_max=speed_hi,
            pause_min_s=pause_min_s,
            pause_max_s=pause_max_s,
            mobility_seed=mob_seed,
            update_interval_s=mobility_update_interval_s,
            mobility_model=mobility_model,
        )

    observer = NetworkObserver(
        engine.env,
        engine,
        engine.bus,
        sample_interval_s=sample_interval_s,
    )
    engine.env.process(observer.sample_process())

    setup_meta = {
        "n_nodes": len(positions),
        "area": area,
        "radius": radius,
        "algorithm": algorithm.value,
        "mobility_model": mobility_model,
        "seed": seed,
        "mobility_seed": mob_seed,
        "mobility_on": mobility_on,
        "speed_min": speed_min,
        "speed_max": speed_hi,
        "hello_interval_s": hello_interval_s,
        "sample_interval_s": sample_interval_s,
    }
    return engine, observer, setup_meta


def run_mobility_scenario(
    n_nodes: int,
    area: float,
    radius: float,
    algorithm: CDSAlgorithm,
    *,
    duration_s: float = 120.0,
    speed: float = 1.0,
    speed_max: float | None = None,
    hello_interval_s: float = 5.0,
    seed: int = 0,
    jitter_frac: float = 0.1,
    tx_latency_s: float = 0.003,
    loss_prob: float = 0.0,
    sample_interval_s: float = 1.0,
    pause_min_s: float = 1.0,
    pause_max_s: float = 3.0,
    mobility_update_interval_s: float = 0.5,
    mobility_seed: int | None = None,
    mobility_model: MobilityModelName = "waypoint",
    since_t: float | None = None,
    positions: dict[str, Position] | None = None,
) -> Metrics:
    """
    Run one timed mobility experiment and return observer metrics.

    Parameters
    ----------
    speed:
        Constant waypoint speed when ``speed_max`` is omitted. ``speed=0``
        disables mobility (static nodes).
    mobility_model:
        ``"waypoint"`` (independent random waypoint) or ``"peloton"`` (shared
        group center via :class:`~sim.timed.mobility.PelotonGroup`).
    positions:
        Optional fixed initial layout; otherwise
        ``generate_connected_geometric(n_nodes, area, radius, seed)``.
    since_t:
        If set, adds ``summary_tail`` from :meth:`NetworkObserver.summary`
        with ``since_t`` (skip early convergence transients).
    mobility_seed:
        RNG seed for per-node waypoint RNGs (defaults to ``seed``).
    """
    engine, observer, setup = _setup_timed_scenario(
        n_nodes,
        area,
        radius,
        algorithm,
        speed=speed,
        speed_max=speed_max,
        hello_interval_s=hello_interval_s,
        seed=seed,
        jitter_frac=jitter_frac,
        tx_latency_s=tx_latency_s,
        loss_prob=loss_prob,
        sample_interval_s=sample_interval_s,
        pause_min_s=pause_min_s,
        pause_max_s=pause_max_s,
        mobility_update_interval_s=mobility_update_interval_s,
        mobility_seed=mobility_seed,
        mobility_model=mobility_model,
        positions=positions,
    )
    engine.run_for(duration_s)

    summary = observer.summary()
    out: Metrics = {
        **setup,
        "duration_s": duration_s,
        "simulated_time": engine.now,
        **summary,
    }
    if since_t is not None:
        out["summary_tail"] = observer.summary(since_t=since_t)
    return out


def run_timed_timeline(
    n_nodes: int,
    area: float,
    radius: float,
    algorithm: CDSAlgorithm,
    *,
    duration_s: float = 120.0,
    speed: float = 1.0,
    speed_max: float | None = None,
    hello_interval_s: float = 5.0,
    seed: int = 0,
    jitter_frac: float = 0.1,
    tx_latency_s: float = 0.003,
    loss_prob: float = 0.0,
    sample_interval_s: float = 1.0,
    pause_min_s: float = 1.0,
    pause_max_s: float = 3.0,
    mobility_update_interval_s: float = 0.5,
    mobility_seed: int | None = None,
    mobility_model: MobilityModelName = "waypoint",
    positions: dict[str, Position] | None = None,
) -> dict[str, Any]:
    """
    Run one timed scenario and return an animatable timeline (JSON-serializable).

    Same deterministic setup as :func:`run_mobility_scenario`; frames are observer
    snapshots with ``positions`` and ``edges`` included.
    """
    engine, observer, setup = _setup_timed_scenario(
        n_nodes,
        area,
        radius,
        algorithm,
        speed=speed,
        speed_max=speed_max,
        hello_interval_s=hello_interval_s,
        seed=seed,
        jitter_frac=jitter_frac,
        tx_latency_s=tx_latency_s,
        loss_prob=loss_prob,
        sample_interval_s=sample_interval_s,
        pause_min_s=pause_min_s,
        pause_max_s=pause_max_s,
        mobility_update_interval_s=mobility_update_interval_s,
        mobility_seed=mobility_seed,
        mobility_model=mobility_model,
        positions=positions,
    )
    engine.run_for(duration_s)

    meta = {
        "n_nodes": setup["n_nodes"],
        "area": setup["area"],
        "radius": setup["radius"],
        "algorithm": setup["algorithm"],
        "mobility_model": setup["mobility_model"],
        "seed": setup["seed"],
        "duration_s": duration_s,
        "sample_interval_s": setup["sample_interval_s"],
        "hello_interval_s": setup["hello_interval_s"],
        "speed_min": setup["speed_min"],
        "speed_max": setup["speed_max"],
    }
    frames = [_snapshot_to_frame(s) for s in observer.snapshots]
    return {
        "meta": meta,
        "frames": frames,
        "summary": observer.summary(),
    }


def compare_mobility(
    n_nodes: int,
    area: float,
    radius: float,
    *,
    duration_s: float = 120.0,
    speed: float = 1.0,
    speed_max: float | None = None,
    hello_interval_s: float = 5.0,
    seed: int = 0,
    since_t: float | None = None,
    **kwargs: Any,
) -> Metrics:
    """
    Same scenario under Wu-Li 1999 and MPR (shared positions + mobility seed).

    Returns a dict with ``wu_li``, ``mpr``, and ``comparison`` (deltas on
    ``role_flip_rate``, ``cds_valid_fraction``, ``mean_uncovered``).
    """
    positions = generate_connected_geometric(n_nodes, area, radius, seed)
    shared = {
        "duration_s": duration_s,
        "speed": speed,
        "speed_max": speed_max,
        "hello_interval_s": hello_interval_s,
        "seed": seed,
        "since_t": since_t,
        "positions": positions,
    }
    shared.update(kwargs)

    wu = run_mobility_scenario(
        n_nodes,
        area,
        radius,
        CDSAlgorithm.WU_LI_1999,
        **shared,
    )
    mpr = run_mobility_scenario(
        n_nodes,
        area,
        radius,
        CDSAlgorithm.MPR,
        **shared,
    )

    def _delta(key: str) -> float:
        return float(mpr.get(key, 0)) - float(wu.get(key, 0))

    tail_wu = wu.get("summary_tail", wu)
    tail_mpr = mpr.get("summary_tail", mpr)

    return {
        "wu_li": wu,
        "mpr": mpr,
        "comparison": {
            "role_flip_rate_delta": _delta("role_flip_rate"),
            "cds_valid_fraction_delta": _delta("cds_valid_fraction"),
            "mean_uncovered_delta": _delta("mean_uncovered"),
            "tail_role_flip_rate_delta": float(tail_mpr.get("role_flip_rate", 0))
            - float(tail_wu.get("role_flip_rate", 0)),
            "tail_cds_valid_fraction_delta": float(tail_mpr.get("cds_valid_fraction", 0))
            - float(tail_wu.get("cds_valid_fraction", 0)),
            "tail_mean_uncovered_delta": float(tail_mpr.get("mean_uncovered", 0))
            - float(tail_wu.get("mean_uncovered", 0)),
        },
    }


if __name__ == "__main__":
    result = compare_mobility(
        10,
        area=25.0,
        radius=12.0,
        duration_s=100.0,
        speed=0.15,
        hello_interval_s=3.0,
        seed=42,
        since_t=25.0,
    )
    cmp_ = result["comparison"]
    wu = result["wu_li"]
    mpr = result["mpr"]
    assert wu["cds_valid_fraction"] > 0.0
    assert mpr["cds_valid_fraction"] > 0.0
    assert "role_flip_rate_delta" in cmp_
    print("✅ scenario_mobility demo complete")
