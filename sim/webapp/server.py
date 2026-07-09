"""
FastAPI front-end for the BUBBLE-BLUE discrete simulator.

Install (example on RubikPi / dev host):
    pip install fastapi uvicorn --break-system-packages

Remote access via SSH tunnel (do NOT bind 0.0.0.0 in production):
    ssh -L 8000:localhost:8000 user@rubikpi
    # then open http://localhost:8000 in your local browser

All topology / CDS / metrics computation is delegated to existing ``sim.*``
modules — this server only orchestrates and serializes JSON.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, HTTPException, Query  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402

from sim.forwarding_sim import ForwardingSimEngine  # noqa: E402
from sim.metrics_roles import (  # noqa: E402
    _area_for_target_degree,
    compare_one,
)
from sim.oracle_table import neighbor_map_from_positions  # noqa: E402
from sim.sim_engine import SimEngine  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402
from sim.timed.scenario_mobility import run_timed_timeline  # noqa: E402
from sim.topology_gen import (  # noqa: E402
    expected_mean_degree,
    generate_connected_geometric,
)

# Timed timeline caps: at most MAX_TIMED_FRAMES samples per response.
# Effective sample_interval_s is raised so ceil(duration_s / interval) <= cap.
MAX_TIMED_FRAMES = 500
MAX_TIMED_DURATION_S = 300.0
MIN_TIMED_SAMPLE_INTERVAL_S = 0.25

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"

Position = dict[str, tuple[float, float]]

app = FastAPI(title="BUBBLE-BLUE Simulator", version="0.1.0")


class TopologyNotConnectedError(Exception):
    """Raised when geometric sampling fails to produce a connected graph."""

    def __init__(self, detail: dict[str, Any]) -> None:
        self.detail = detail
        super().__init__(detail.get("message", "topology not connected"))


def resolve_topology_inputs(
    n_nodes: int,
    radius: float,
    seed: int,
    target_degree: float,
) -> tuple[Position, float]:
    """
    Compute ``area`` with ``metrics_roles._area_for_target_degree`` then draw a
    connected geometric graph (``topology_gen.generate_connected_geometric``).
    """
    area = _area_for_target_degree(n_nodes, radius, target_degree)
    try:
        positions = generate_connected_geometric(n_nodes, area, radius, seed)
    except RuntimeError as exc:
        raise TopologyNotConnectedError(
            {
                "error": "topology_not_connected",
                "message": str(exc),
                "n_nodes": n_nodes,
                "area": area,
                "radius": radius,
                "seed": seed,
                "target_degree": target_degree,
                "expected_mean_degree": expected_mean_degree(n_nodes, area, radius),
            }
        ) from exc
    return positions, area


def topology_json(
    positions: Position,
    *,
    area: float,
    radius: float,
    seed: int,
    n_nodes: int,
) -> dict[str, Any]:
    nmap = neighbor_map_from_positions(positions, radius)
    edges: list[list[str]] = []
    for a in sorted(nmap):
        for b in nmap[a]:
            if a < b:
                edges.append([a, b])
    nodes = [
        {"bd": bd, "x": positions[bd][0], "y": positions[bd][1]}
        for bd in sorted(positions)
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "area": area,
        "radius": radius,
        "expected_mean_degree": expected_mean_degree(n_nodes, area, radius),
        "seed": seed,
        "n_nodes": n_nodes,
    }


def build_topology_response(
    n_nodes: int,
    radius: float,
    seed: int,
    target_degree: float,
) -> dict[str, Any]:
    """Pure JSON payload for ``/api/topology`` (no HTTP)."""
    positions, area = resolve_topology_inputs(n_nodes, radius, seed, target_degree)
    return topology_json(
        positions, area=area, radius=radius, seed=seed, n_nodes=n_nodes
    )


def roles_for_algorithm(
    positions: Position,
    radius: float,
    algorithm: CDSAlgorithm,
    max_steps: int,
) -> dict[str, str] | None:
    """Per-node RELAY/LEAF after convergence; None if cycle or max_steps."""
    engine = SimEngine(positions, radius, algorithm=algorithm)
    result = engine.run_until_stable(max_steps=max_steps)
    if result.status != "fixed_point":
        return None
    return engine.roles()


def algo_response(
    metrics: dict[str, Any],
    roles: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "cds_size": metrics.get("cds_size"),
        "convergence_status": metrics["convergence_status"],
        "convergence_steps": metrics["convergence_steps"],
        "convergence_period": metrics["convergence_period"],
        "oscillates": metrics.get("oscillates", False),
        "did_not_converge": metrics.get("did_not_converge", False),
        "roles": roles,
    }


def build_simulate_response(
    n_nodes: int,
    radius: float,
    seed: int,
    target_degree: float,
    max_steps: int,
) -> dict[str, Any]:
    """Pure JSON payload for ``/api/simulate`` (no HTTP)."""
    positions, area = resolve_topology_inputs(n_nodes, radius, seed, target_degree)
    topology = topology_json(
        positions, area=area, radius=radius, seed=seed, n_nodes=n_nodes
    )

    comparison = compare_one(positions, radius, max_steps=max_steps)
    wu_li_roles = roles_for_algorithm(
        positions, radius, CDSAlgorithm.WU_LI_1999, max_steps
    )
    mpr_roles = roles_for_algorithm(
        positions, radius, CDSAlgorithm.MPR, max_steps
    )

    return {
        "topology": topology,
        "wu_li": algo_response(comparison["wu_li"], wu_li_roles),
        "mpr": algo_response(comparison["mpr"], mpr_roles),
        "delta_cds_size": comparison["delta_cds_size"],
        "both_fixed_point": comparison["both_fixed_point"],
    }


def resolve_broadcast_source(
    positions: Position,
    source: str | None,
    seed: int,
) -> str:
    """Pick broadcast source BD; ``None`` / ``random`` → deterministic sub-seed."""
    nodes = sorted(positions)
    if not nodes:
        raise ValueError("empty topology")
    if source is None or source.strip().lower() == "random":
        rng = random.Random(seed ^ 0xBADC0FFE)
        return rng.choice(nodes)
    src = source.strip().upper()
    upper_positions = {bd.upper(): bd for bd in positions}
    if src not in upper_positions:
        raise ValueError(f"unknown source node: {source}")
    return src


def _run_broadcast_waves(
    positions: Position,
    radius: float,
    algorithm: CDSAlgorithm,
    source_bd: str,
    ttl: int,
    max_steps: int,
) -> dict[str, Any]:
    engine = ForwardingSimEngine(
        positions, radius, algorithm, ttl_max=ttl
    )
    return engine.measure_broadcast_with_waves(
        source_bd, ttl, text="probe", max_steps=max_steps
    )


def build_broadcast_response(
    n_nodes: int,
    radius: float,
    seed: int,
    target_degree: float,
    max_steps: int,
    source: str | None,
    ttl: int | None,
) -> dict[str, Any]:
    """Pure JSON payload for ``/api/broadcast`` (no HTTP)."""
    positions, area = resolve_topology_inputs(n_nodes, radius, seed, target_degree)
    topology = topology_json(
        positions, area=area, radius=radius, seed=seed, n_nodes=n_nodes
    )
    source_bd = resolve_broadcast_source(positions, source, seed)
    actual_ttl = ttl if ttl is not None else n_nodes

    wu_li = _run_broadcast_waves(
        positions,
        radius,
        CDSAlgorithm.WU_LI_1999,
        source_bd,
        actual_ttl,
        max_steps,
    )
    mpr = _run_broadcast_waves(
        positions,
        radius,
        CDSAlgorithm.MPR,
        source_bd,
        actual_ttl,
        max_steps,
    )

    return {
        "topology": topology,
        "source": source_bd,
        "ttl": actual_ttl,
        "wu_li": wu_li,
        "mpr": mpr,
    }


def _parse_timed_algorithm(algorithm: str) -> CDSAlgorithm:
    key = algorithm.strip().lower()
    if key == "wu_li":
        return CDSAlgorithm.WU_LI_1999
    if key == "mpr":
        return CDSAlgorithm.MPR
    raise ValueError(f"unknown algorithm: {algorithm!r} (expected 'wu_li' or 'mpr')")


def _parse_mobility_model(mobility_model: str) -> str:
    key = mobility_model.strip().lower()
    if key in ("waypoint", "peloton"):
        return key
    raise ValueError(
        f"unknown mobility_model: {mobility_model!r} (expected 'waypoint' or 'peloton')"
    )


def _cap_timed_sampling(
    duration_s: float,
    sample_interval_s: float,
) -> tuple[float, float]:
    """
    Bound duration and sample interval so ``len(frames) <= MAX_TIMED_FRAMES``.

    Raises ``sample_interval_s`` when needed; duration is capped at
    ``MAX_TIMED_DURATION_S``.
    """
    duration = min(max(0.1, float(duration_s)), MAX_TIMED_DURATION_S)
    interval = max(MIN_TIMED_SAMPLE_INTERVAL_S, float(sample_interval_s))
    min_interval = duration / MAX_TIMED_FRAMES
    if interval < min_interval:
        interval = min_interval
    return duration, interval


def build_timed_response(
    n_nodes: int,
    radius: float,
    seed: int,
    target_degree: float,
    duration_s: float,
    sample_interval_s: float,
    algorithm: str,
    mobility_model: str,
    *,
    hello_interval_s: float = 5.0,
    speed: float = 0.15,
    speed_max: float | None = None,
) -> dict[str, Any]:
    """Pure JSON payload for ``/api/timed`` (no HTTP)."""
    positions, area = resolve_topology_inputs(n_nodes, radius, seed, target_degree)
    capped_duration, capped_interval = _cap_timed_sampling(duration_s, sample_interval_s)
    algo = _parse_timed_algorithm(algorithm)
    mob = _parse_mobility_model(mobility_model)

    timeline = run_timed_timeline(
        n_nodes,
        area,
        radius,
        algo,
        duration_s=capped_duration,
        speed=speed,
        speed_max=speed_max,
        hello_interval_s=hello_interval_s,
        seed=seed,
        sample_interval_s=capped_interval,
        mobility_model=mob,  # type: ignore[arg-type]
        positions=positions,
    )
    timeline["meta"]["max_frames_cap"] = MAX_TIMED_FRAMES
    timeline["meta"]["capped_duration_s"] = capped_duration
    timeline["meta"]["capped_sample_interval_s"] = capped_interval
    return timeline


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_INDEX_HTML)


@app.get("/api/topology")
def api_topology(
    n_nodes: int = Query(15, ge=1, le=500),
    radius: float = Query(1.0, gt=0),
    seed: int = Query(0, ge=0),
    target_degree: float = Query(5.0, gt=0),
) -> dict[str, Any]:
    try:
        return build_topology_response(n_nodes, radius, seed, target_degree)
    except TopologyNotConnectedError as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc


@app.get("/api/simulate")
def api_simulate(
    n_nodes: int = Query(15, ge=1, le=500),
    radius: float = Query(1.0, gt=0),
    seed: int = Query(0, ge=0),
    target_degree: float = Query(5.0, gt=0),
    max_steps: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    try:
        return build_simulate_response(
            n_nodes, radius, seed, target_degree, max_steps
        )
    except TopologyNotConnectedError as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc


@app.get("/api/broadcast")
def api_broadcast(
    n_nodes: int = Query(15, ge=1, le=500),
    radius: float = Query(1.0, gt=0),
    seed: int = Query(0, ge=0),
    target_degree: float = Query(5.0, gt=0),
    max_steps: int = Query(50, ge=1, le=500),
    source: str | None = Query(None),
    ttl: int | None = Query(None, ge=1, le=500),
) -> dict[str, Any]:
    try:
        return build_broadcast_response(
            n_nodes,
            radius,
            seed,
            target_degree,
            max_steps,
            source,
            ttl,
        )
    except TopologyNotConnectedError as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/timed")
def api_timed(
    n_nodes: int = Query(15, ge=1, le=100),
    radius: float = Query(1.0, gt=0),
    seed: int = Query(0, ge=0),
    target_degree: float = Query(5.0, gt=0),
    duration_s: float = Query(60.0, ge=0.1, le=MAX_TIMED_DURATION_S),
    sample_interval_s: float = Query(1.0, ge=MIN_TIMED_SAMPLE_INTERVAL_S, le=60.0),
    algorithm: str = Query("wu_li"),
    mobility_model: str = Query("waypoint"),
    hello_interval_s: float = Query(5.0, ge=0.1, le=60.0),
    speed: float = Query(0.15, ge=0.0, le=10.0),
    speed_max: float | None = Query(None, ge=0.0, le=10.0),
) -> dict[str, Any]:
    try:
        return build_timed_response(
            n_nodes,
            radius,
            seed,
            target_degree,
            duration_s,
            sample_interval_s,
            algorithm,
            mobility_model,
            hello_interval_s=hello_interval_s,
            speed=speed,
            speed_max=speed_max,
        )
    except TopologyNotConnectedError as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "sim.webapp.server:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
