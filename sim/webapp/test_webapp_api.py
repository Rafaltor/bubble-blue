from __future__ import annotations

# Webapp API contract tests — no uvicorn, no HTTP.
# Proves build_topology_response / build_simulate_response expose the exact
# numbers from sim.metrics_roles and sim.topology_gen without divergence.

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.forwarding.cds import CDSAlgorithm  # noqa: E402

from sim.metrics_roles import _area_for_target_degree, run_one  # noqa: E402
from sim.oracle_table import neighbor_map_from_positions  # noqa: E402
from sim.topology_gen import expected_mean_degree  # noqa: E402
from sim.webapp.server import (  # noqa: E402
    TopologyNotConnectedError,
    build_simulate_response,
    build_topology_response,
)

_TOPO_PARAMS = dict(n_nodes=15, radius=1.0, seed=20, target_degree=5.0)
_SIM_PARAMS = {**_TOPO_PARAMS, "max_steps": 50}


def _positions_from_topology(topo: dict) -> dict[str, tuple[float, float]]:
    return {n["bd"]: (n["x"], n["y"]) for n in topo["nodes"]}


def _adjacency_from_edges(edges: list[list[str]]) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    for a, b in edges:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    return adj


def test_build_topology_response() -> None:
    topo = build_topology_response(**_TOPO_PARAMS)
    n_nodes = _TOPO_PARAMS["n_nodes"]
    radius = _TOPO_PARAMS["radius"]
    target_degree = _TOPO_PARAMS["target_degree"]

    if len(topo["nodes"]) != n_nodes:
        raise AssertionError(
            f"expected {n_nodes} nodes, got {len(topo['nodes'])}"
        )
    if topo["n_nodes"] != n_nodes:
        raise AssertionError("n_nodes field mismatch")

    expected_area = _area_for_target_degree(n_nodes, radius, target_degree)
    if abs(topo["area"] - expected_area) > 1e-9:
        raise AssertionError(
            f"area {topo['area']} != _area_for_target_degree -> {expected_area}"
        )

    emd = expected_mean_degree(n_nodes, topo["area"], radius)
    if abs(topo["expected_mean_degree"] - emd) > 1e-9:
        raise AssertionError("expected_mean_degree inconsistent with formula")

    positions = _positions_from_topology(topo)
    nmap = neighbor_map_from_positions(positions, radius)
    adj = _adjacency_from_edges(topo["edges"])

    for bd in positions:
        if bd not in nmap:
            raise AssertionError(f"node {bd} missing from neighbor_map")
        if set(nmap[bd]) != adj.get(bd, set()):
            raise AssertionError(
                f"edges for {bd}: API {adj.get(bd, set())} != nmap {set(nmap[bd])}"
            )

    for a, b in topo["edges"]:
        if a >= b:
            raise AssertionError(f"edge not canonical (a<b): {[a, b]}")
        if b not in nmap.get(a, []):
            raise AssertionError(f"edge {[a, b]} not in unit-disk neighbor map")

    print(
        f"✅ build_topology_response: {n_nodes} nodes, "
        f"{len(topo['edges'])} edges, area={topo['area']:.4f}, E[deg]={emd:.2f}"
    )


def test_build_simulate_response_wu_li_parity() -> None:
    resp = build_simulate_response(**_SIM_PARAMS)
    positions = _positions_from_topology(resp["topology"])
    radius = _SIM_PARAMS["radius"]
    max_steps = _SIM_PARAMS["max_steps"]

    harness = run_one(
        positions, radius, CDSAlgorithm.WU_LI_1999, max_steps=max_steps
    )
    api_wu = resp["wu_li"]

    if api_wu["cds_size"] != harness["cds_size"]:
        raise AssertionError(
            "Wu-Li cds_size diverges from run_one — server alters metrics\n"
            f"  API:     {api_wu['cds_size']}\n"
            f"  run_one: {harness['cds_size']}"
        )

    for key in (
        "convergence_status",
        "convergence_steps",
        "convergence_period",
        "oscillates",
        "did_not_converge",
    ):
        if api_wu[key] != harness[key]:
            raise AssertionError(
                f"Wu-Li {key}: API {api_wu[key]!r} != run_one {harness[key]!r}"
            )

    if harness["convergence_status"] == "fixed_point":
        roles = api_wu["roles"]
        if roles is None:
            raise AssertionError("fixed_point but roles is None")
        relay_count = sum(1 for r in roles.values() if r == "RELAY")
        if relay_count != api_wu["cds_size"]:
            raise AssertionError(
                f"RELAY count {relay_count} != cds_size {api_wu['cds_size']}"
            )
        if relay_count != harness["cds_size"]:
            raise AssertionError("RELAY count != harness cds_size")

    if resp["delta_cds_size"] is not None:
        mpr_size = resp["mpr"]["cds_size"]
        wu_size = resp["wu_li"]["cds_size"]
        if resp["delta_cds_size"] != int(mpr_size) - int(wu_size):
            raise AssertionError("delta_cds_size inconsistent with algo sizes")

    print(
        f"✅ build_simulate_response: Wu-Li cds_size={api_wu['cds_size']} "
        f"== run_one ({harness['convergence_status']}, "
        f"{harness['convergence_steps']} steps)"
    )


def test_topology_not_connected() -> None:
    bad = dict(n_nodes=60, radius=0.01, seed=0, target_degree=1.0)
    try:
        build_topology_response(**bad)
    except TopologyNotConnectedError as exc:
        detail = exc.detail
        if detail.get("error") != "topology_not_connected":
            raise AssertionError(f"unexpected error code: {detail.get('error')}")
        if "message" not in detail:
            raise AssertionError("detail missing message")
        if detail["n_nodes"] != bad["n_nodes"]:
            raise AssertionError("detail n_nodes mismatch")
        print(f"✅ topology_not_connected: {detail['message'][:72]}…")
        return
    raise AssertionError("expected TopologyNotConnectedError, got success")


def test_simulate_not_connected() -> None:
    bad = dict(n_nodes=60, radius=0.01, seed=0, target_degree=1.0, max_steps=50)
    try:
        build_simulate_response(**bad)
    except TopologyNotConnectedError:
        print("✅ build_simulate_response propagates TopologyNotConnectedError")
        return
    raise AssertionError("expected TopologyNotConnectedError from simulate builder")


if __name__ == "__main__":
    test_build_topology_response()
    test_build_simulate_response_wu_li_parity()
    test_topology_not_connected()
    test_simulate_not_connected()
    print("\n✅ webapp API builders match engine metrics (no HTTP, no uvicorn)")
