from __future__ import annotations

# Oracle validation: SimEngine roles must match the known Wu-Li 1999 outcomes from
# cds.py self-tests. Any divergence means the simulator (or local/global view gap)
# is wrong — do not silence failures here.

import math
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.control.hello import compute_anon_id  # noqa: E402
from src.forwarding.cds import (  # noqa: E402
    CDSAlgorithm,
    _extract_topology,
    _verify_cds_properties,
    compute_cds,
)
from sim.oracle_table import build_merged_table  # noqa: E402
from sim.sim_engine import ConvergenceResult, SimEngine, _GK  # noqa: E402

# Same BD addresses as cds.py __main__ (deterministic anon_ids under _GK).
_ADDR_A = "40:D9:5A:8B:69:3F"
_ADDR_B = "14:B5:CD:E2:49:ED"
_ADDR_C = "00:11:22:33:44:55"
_ADDR_D = "AA:BB:CC:DD:EE:FF"
_ADDR_E = "11:22:33:44:55:66"
_LINE5 = [_ADDR_A, _ADDR_B, _ADDR_C, _ADDR_D, _ADDR_E]

# Extra addresses for star (hub + 3 leaves) and triangle.
_ADDR_F = "22:33:44:55:66:77"
_ADDR_G = "33:44:55:66:77:88"


def _fail(
    topology: str,
    *,
    expected: str,
    got: str,
    steps: int,
    detail: str = "",
) -> None:
    msg = (
        f"[{topology}] roles mismatch after {steps} step(s)\n"
        f"  expected: {expected}\n"
        f"  got:      {got}"
    )
    if detail:
        msg += f"\n  detail:   {detail}"
    raise AssertionError(msg)


def _neighbor_map(engine: SimEngine) -> dict[str, list[str]]:
    return {bd: engine.bus.neighbors(bd) for bd in sorted(engine.nodes)}


def _relay_anon_ids(engine: SimEngine) -> set[bytes]:
    return {
        node.hello_mgr.anon_id
        for node in engine.nodes.values()
        if node.role() == "RELAY"
    }


def _compare_with_global_oracle(
    topology: str,
    engine: SimEngine,
    steps: int,
    *,
    neighbor_map: dict[str, list[str]] | None = None,
) -> None:
    """
    Sim local roles vs compute_cds on a merged table built from bus ground truth.

    At convergence these should coincide for Wu-Li 1999. If they differ, it is
    either incomplete Hello convergence in the sim or a local-view vs global-view
    gap — neither should happen on static symmetric topologies after stability.
    """
    nmap = neighbor_map if neighbor_map is not None else _neighbor_map(engine)
    merged = build_merged_table(nmap)
    topo = _extract_topology(merged)
    global_cds = compute_cds(merged, algorithm=CDSAlgorithm.WU_LI_1999)
    sim_relays = _relay_anon_ids(engine)

    if sim_relays != global_cds:
        sim_by_bd = {
            bd: ("RELAY" if node.hello_mgr.anon_id in sim_relays else "LEAF")
            for bd, node in engine.nodes.items()
        }
        global_by_bd = {
            bd: ("RELAY" if compute_anon_id(_GK, bd) in global_cds else "LEAF")
            for bd in engine.nodes
        }
        _fail(
            topology,
            expected=f"sim relays == compute_cds (global) {global_by_bd}",
            got=f"sim {sim_by_bd}",
            steps=steps,
            detail=(
                "sim uses per-node received-only tables + am_i_cds; "
                "compute_cds uses merged global view — divergence indicates "
                "convergence bug or local/global inconsistency"
            ),
        )


def _verify_relay_backbone(
    engine: SimEngine,
    relay_aids: set[bytes],
    neighbor_map: dict[str, list[str]],
) -> None:
    merged = build_merged_table(neighbor_map)
    topo = _extract_topology(merged)
    _verify_cds_properties(relay_aids, topo)


def _run_engine(
    positions: dict[str, tuple[float, float]],
    radius: float,
    *,
    max_steps: int = 30,
) -> tuple[SimEngine, ConvergenceResult]:
    engine = SimEngine(positions, radius, algorithm=CDSAlgorithm.WU_LI_1999, group_key=_GK)
    result = engine.run_until_stable(max_steps=max_steps)
    assert result.status == "fixed_point", (
        f"static Wu-Li topology must reach a fixed point, not {result.status} "
        f"(period={result.period}, steps={result.steps})"
    )
    return engine, result


def test_line5_wu_li() -> None:
    topology = "line-5 A—B—C—D—E"
    R = 1.0
    positions = {bd: (float(i), 0.0) for i, bd in enumerate(_LINE5)}

    engine, result = _run_engine(positions, R)
    steps = result.steps
    roles = engine.roles()
    nmap = _neighbor_map(engine)

    endpoints = {bd for bd in _LINE5 if len(nmap[bd]) == 1}
    degree2 = {bd for bd in _LINE5 if len(nmap[bd]) == 2}
    relays = {bd for bd, role in roles.items() if role == "RELAY"}

    if len(relays) != 3:
        _fail(
            topology,
            expected="exactly 3 RELAY nodes",
            got=f"{len(relays)} relays {roles}",
            steps=steps,
        )
    if relays != degree2:
        _fail(
            topology,
            expected=f"relays == degree-2 nodes {sorted(degree2)}",
            got=f"relays {sorted(relays)} endpoints {sorted(endpoints)} roles {roles}",
            steps=steps,
        )
    if any(roles[bd] != "LEAF" for bd in endpoints):
        _fail(
            topology,
            expected="endpoints LEAF",
            got=str(roles),
            steps=steps,
        )

    _verify_relay_backbone(engine, _relay_anon_ids(engine), nmap)
    _compare_with_global_oracle(topology, engine, steps, neighbor_map=nmap)
    print(f"✅ {topology}: 3 relays on degree-2 nodes, CDS valid, matches compute_cds ({steps} steps)")


def test_star_wu_li() -> None:
    topology = "star hub + 3 leaves"
    R = 1.0
    hub = _ADDR_A
    leaves = [_ADDR_B, _ADDR_C, _ADDR_D]
    dist = 0.9 * R
    positions: dict[str, tuple[float, float]] = {hub: (0.0, 0.0)}
    for i, leaf in enumerate(leaves):
        angle = i * 2.0 * math.pi / 3.0
        positions[leaf] = (dist * math.cos(angle), dist * math.sin(angle))

    engine, result = _run_engine(positions, R)
    steps = result.steps
    roles = engine.roles()
    nmap = _neighbor_map(engine)

    # Leaves must not see each other (geometry check).
    for i, a in enumerate(leaves):
        for b in leaves[i + 1 :]:
            if b in nmap[a]:
                _fail(
                    topology,
                    expected=f"leaves {a},{b} out of range",
                    got=f"neighbors {nmap}",
                    steps=steps,
                )

    if roles[hub] != "RELAY":
        _fail(topology, expected=f"hub {hub} RELAY", got=str(roles), steps=steps)
    for leaf in leaves:
        if roles[leaf] != "LEAF":
            _fail(topology, expected=f"leaf {leaf} LEAF", got=str(roles), steps=steps)

    _compare_with_global_oracle(topology, engine, steps, neighbor_map=nmap)
    print(f"✅ {topology}: hub RELAY, leaves LEAF, matches compute_cds ({steps} steps)")


def test_triangle_wu_li() -> None:
    topology = "triangle full mesh"
    R = 1.0
    side = 0.8 * R
    tri = [_ADDR_A, _ADDR_B, _ADDR_C]
    # Equilateral triangle: side < R so all pairs are in range.
    positions = {
        tri[0]: (0.0, 0.0),
        tri[1]: (side, 0.0),
        tri[2]: (side / 2.0, side * math.sqrt(3) / 2.0),
    }

    engine, result = _run_engine(positions, R)
    steps = result.steps
    roles = engine.roles()
    nmap = _neighbor_map(engine)

    for bd in tri:
        if len(nmap[bd]) != 2:
            _fail(
                topology,
                expected=f"{bd} degree 2",
                got=f"neighbors {nmap}",
                steps=steps,
            )

    if any(role != "LEAF" for role in roles.values()):
        _fail(topology, expected="all LEAF", got=str(roles), steps=steps)

    _compare_with_global_oracle(topology, engine, steps, neighbor_map=nmap)
    print(f"✅ {topology}: all LEAF, matches compute_cds ({steps} steps)")


if __name__ == "__main__":
    test_line5_wu_li()
    test_star_wu_li()
    test_triangle_wu_li()
    print("\n✅ All sim validation tests passed")
