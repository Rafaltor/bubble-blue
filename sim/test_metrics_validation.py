from __future__ import annotations

# Harness validation: metrics_roles.run_one (local per-node sim) vs compute_cds
# (global merged oracle). Wu-Li must match exactly at fixed_point; MPR gaps are
# reported as local/global view data, not hidden failures.

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.forwarding.cds import (  # noqa: E402
    CDSAlgorithm,
    _extract_topology,
    _verify_cds_properties,
)

from sim.metrics_roles import _relay_count, _run_with_history, run_one  # noqa: E402
from sim.oracle_table import (  # noqa: E402
    build_merged_table,
    global_cds_size,
    neighbor_map_from_positions,
)
from sim.sim_engine import SimEngine  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402

# Fixed peloton-like scenarios (connected, reproducible seeds).
_SCENARIOS: list[tuple[str, int, float, float, int]] = [
    ("small", 8, 2.5, 1.0, 10),
    ("medium", 15, 3.07, 1.0, 20),
    ("larger", 25, 4.0, 1.0, 30),
]


def _validate_wu_li(
    label: str,
    positions: dict[str, tuple[float, float]],
    radius: float,
) -> None:
    result = run_one(positions, radius, CDSAlgorithm.WU_LI_1999, max_steps=50)
    nmap = neighbor_map_from_positions(positions, radius)
    global_size = global_cds_size(nmap, CDSAlgorithm.WU_LI_1999)

    if result["convergence_status"] != "fixed_point":
        raise AssertionError(
            f"[{label} Wu-Li] expected fixed_point on static connected topology, "
            f"got {result['convergence_status']} "
            f"(steps={result['convergence_steps']}, period={result['convergence_period']})"
        )

    sim_size = result["cds_size"]
    if sim_size != global_size:
        raise AssertionError(
            f"[{label} Wu-Li] harness cds_size != global compute_cds — THIS IS A BUG\n"
            f"  sim cds_size:    {sim_size}\n"
            f"  global oracle:   {global_size}\n"
            f"  convergence:   {result['convergence_status']} "
            f"in {result['convergence_steps']} step(s)\n"
            f"  n_nodes:         {result['n_nodes']}"
        )

    print(
        f"✅ {label} Wu-Li: sim={sim_size} == global={global_size} "
        f"({result['convergence_steps']} steps)"
    )


def _run_mpr_sim(
    positions: dict[str, tuple[float, float]],
    radius: float,
    max_steps: int = 50,
) -> tuple[dict, set[bytes]]:
    """Single MPR sim run: metrics dict + runtime RELAY anon_id set."""
    engine = SimEngine(positions, radius, algorithm=CDSAlgorithm.MPR)
    result, relay_counts = _run_with_history(engine, max_steps)
    relay_aids = {
        node.hello_mgr.anon_id
        for node in engine.nodes.values()
        if node.hello_mgr.is_relay
    }
    out: dict = {
        "n_nodes": len(positions),
        "algorithm": CDSAlgorithm.MPR.value,
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
        period = result.period
        if period >= 1 and len(relay_counts) >= period:
            window = relay_counts[-period:]
            out["cds_size_cycle_mean"] = sum(window) / len(window)
    else:
        out["did_not_converge"] = True
    return out, relay_aids


def _verify_mpr_runtime_backbone(
    label: str,
    positions: dict[str, tuple[float, float]],
    radius: float,
    relay_aids: set[bytes],
    sim_size: int,
    global_size: int,
) -> None:
    """Check whether the runtime MPR relay set is a valid CDS on the ground-truth graph."""
    nmap = neighbor_map_from_positions(positions, radius)
    topo = _extract_topology(build_merged_table(nmap))
    try:
        _verify_cds_properties(relay_aids, topo)
    except AssertionError as exc:
        print(
            f"⚠️  MPR runtime backbone INCOMPLETE on {label}: {exc}\n"
            f"    runtime relays={sim_size}  global oracle={global_size}  "
            f"delta={sim_size - global_size}\n"
            f"    → coverage loss risk for delivery ratio (not a silent pass)"
        )
        return

    if sim_size < global_size:
        print(
            f"✅ MPR runtime backbone valid (dominating+connected) despite smaller size: "
            f"efficiency gain, not a coverage loss "
            f"(runtime={sim_size}, global={global_size})"
        )
    else:
        print(
            f"✅ MPR runtime backbone valid (dominating+connected) "
            f"(runtime={sim_size}, global={global_size})"
        )


def _characterize_mpr(
    label: str,
    positions: dict[str, tuple[float, float]],
    radius: float,
) -> None:
    """
    MPR local (announced MPR in Hellos) vs global (recomputed MPR) may differ.

    Documented in cds.py: compute_cds(MPR) uses compute_all_mpr on the merged
    view; runtime am_i_cds(MPR) reads get_mpr() from received Hellos. Oscillation
    is also possible. We report gaps; we do not assert strict equality.
    At fixed_point we additionally verify whether the runtime relay set is a
    valid CDS (dominating + connected) — turning size gaps into a clear verdict.
    """
    result, relay_aids = _run_mpr_sim(positions, radius, max_steps=50)
    nmap = neighbor_map_from_positions(positions, radius)
    global_size = global_cds_size(nmap, CDSAlgorithm.MPR)
    status = result["convergence_status"]

    if status == "cycle":
        print(
            f"ℹ️  {label} MPR: oscillates (period={result['convergence_period']}, "
            f"steps={result['convergence_steps']}) — expected possible instability; "
            f"global oracle size={global_size} (not compared to oscillating sim)"
        )
        if result.get("cds_size_cycle_mean") is not None:
            print(
                f"    cycle_mean relay count={result['cds_size_cycle_mean']:.2f} "
                f"(informational only)"
            )
        return

    if status == "max_steps":
        print(
            f"ℹ️  {label} MPR: did not converge within limit "
            f"(steps={result['convergence_steps']}); global oracle={global_size}"
        )
        return

    sim_size = result["cds_size"]
    assert sim_size is not None
    delta = int(sim_size) - global_size
    if delta == 0:
        print(
            f"✅ {label} MPR: sim={sim_size} == global={global_size} at fixed_point "
            f"({result['convergence_steps']} steps) — local/global agree here"
        )
    else:
        print(
            f"ℹ️  {label} MPR: local/global gap (NOT a test failure)\n"
            f"    sim cds_size (local Hellos):  {sim_size}\n"
            f"    global compute_cds (recomputed MPR): {global_size}\n"
            f"    delta local−global: {delta}\n"
            f"    steps: {result['convergence_steps']}\n"
            f"    → analyse as vue-locale/vue-globale (cds.py); not a sim bug per se"
        )
    _verify_mpr_runtime_backbone(
        label, positions, radius, relay_aids, int(sim_size), global_size
    )


def test_metrics_match_global_oracle() -> None:
    for label, n_nodes, area, radius, seed in _SCENARIOS:
        positions = generate_connected_geometric(n_nodes, area, radius, seed)
        _validate_wu_li(label, positions, radius)
        _characterize_mpr(label, positions, radius)


if __name__ == "__main__":
    test_metrics_match_global_oracle()
    print("\n✅ metrics harness validation passed (Wu-Li oracle locked; MPR characterized)")
