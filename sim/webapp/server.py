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

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, HTTPException, Query  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402

from sim.metrics_roles import (  # noqa: E402
    _area_for_target_degree,
    compare_one,
)
from sim.oracle_table import neighbor_map_from_positions  # noqa: E402
from sim.sim_engine import SimEngine  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402
from sim.topology_gen import (  # noqa: E402
    expected_mean_degree,
    generate_connected_geometric,
)

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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "sim.webapp.server:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
