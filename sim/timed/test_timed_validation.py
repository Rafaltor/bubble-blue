from __future__ import annotations

# TimedEngine oracle validation: static stabilized roles must match compute_cds
# (global merged table), same guard as sim/test_sim_validation.py for the
# round-based SimEngine. Any Wu-Li divergence reveals a SimPy integration bug
# (timing, ordering, incomplete convergence) — do not silence failures here.

import math
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.control.hello import compute_anon_id  # noqa: E402
from src.forwarding.cds import (  # noqa: E402
    CDSAlgorithm,
    _extract_topology,
    _verify_cds_properties,
    compute_cds,
)
from sim.oracle_table import build_merged_table, global_cds_size  # noqa: E402
from sim.sim_engine import _GK  # noqa: E402
from sim.timed.timed_engine import TimedEngine  # noqa: E402

# Same BD addresses as sim/test_sim_validation.py (deterministic anon_ids under _GK).
_ADDR_A = "40:D9:5A:8B:69:3F"
_ADDR_B = "14:B5:CD:E2:49:ED"
_ADDR_C = "00:11:22:33:44:55"
_ADDR_D = "AA:BB:CC:DD:EE:FF"
_ADDR_E = "11:22:33:44:55:66"
_LINE5 = [_ADDR_A, _ADDR_B, _ADDR_C, _ADDR_D, _ADDR_E]

HELLO_INTERVAL_S = 5.0
RUN_MULTIPLIER = 10


def _fail(
    topology: str,
    *,
    expected: str,
    got: str,
    sim_time: float,
    detail: str = "",
) -> None:
    msg = (
        f"[{topology}] roles mismatch after t={sim_time:.1f}s simulated\n"
        f"  expected: {expected}\n"
        f"  got:      {got}"
    )
    if detail:
        msg += f"\n  detail:   {detail}"
    raise AssertionError(msg)


def _neighbor_map(engine: TimedEngine) -> dict[str, list[str]]:
    return {bd: engine.bus.neighbors(bd) for bd in sorted(engine.nodes)}


def _relay_anon_ids(engine: TimedEngine) -> set[bytes]:
    return {
        node.hello_mgr.anon_id
        for node in engine.nodes.values()
        if node.role() == "RELAY"
    }


def _relay_count(engine: TimedEngine) -> int:
    return sum(1 for node in engine.nodes.values() if node.role() == "RELAY")


def _run_timed(
    positions: dict[str, tuple[float, float]],
    radius: float,
    *,
    algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
    hello_interval_s: float = HELLO_INTERVAL_S,
    run_multiplier: int = RUN_MULTIPLIER,
) -> tuple[TimedEngine, float]:
    engine = TimedEngine(
        positions,
        radius,
        algorithm=algorithm,
        hello_interval_s=hello_interval_s,
        jitter_frac=0.0,
        tx_latency_s=0.0,
        loss_prob=0.0,
        seed=0,
        group_key=_GK,
    )
    duration_s = run_multiplier * hello_interval_s
    engine.run_for(duration_s)
    return engine, duration_s


def _compare_with_global_oracle(
    topology: str,
    engine: TimedEngine,
    sim_time: float,
    *,
    neighbor_map: dict[str, list[str]] | None = None,
) -> None:
    """
    Timed local roles vs compute_cds on a merged table from bus ground truth.

    At convergence these must coincide for Wu-Li 1999 on static symmetric
    topologies — same contract as sim/test_sim_validation.py.
    """
    nmap = neighbor_map if neighbor_map is not None else _neighbor_map(engine)
    merged = build_merged_table(nmap)
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
            sim_time=sim_time,
            detail=(
                "TimedEngine uses per-node received-only tables + am_i_cds; "
                "compute_cds uses merged global view — divergence indicates "
                "SimPy timing bug or incomplete convergence"
            ),
        )


def _verify_relay_backbone(
    engine: TimedEngine,
    relay_aids: set[bytes],
    neighbor_map: dict[str, list[str]],
) -> None:
    merged = build_merged_table(neighbor_map)
    topo = _extract_topology(merged)
    _verify_cds_properties(relay_aids, topo)


def _characterize_mpr_timed(
    topology: str,
    positions: dict[str, tuple[float, float]],
    radius: float,
) -> None:
    """
    MPR local (runtime Hellos) vs global (recomputed MPR) may differ.

    Same reporting contract as sim/test_metrics_validation.py: document gaps,
    do not assert strict equality. Verify runtime backbone when fixed_point-like.
    """
    engine, sim_time = _run_timed(positions, radius, algorithm=CDSAlgorithm.MPR)
    nmap = _neighbor_map(engine)
    global_size = global_cds_size(nmap, CDSAlgorithm.MPR)
    relay_aids = _relay_anon_ids(engine)
    sim_size = _relay_count(engine)
    delta = sim_size - global_size

    if delta == 0:
        print(
            f"ℹ️  {topology} MPR (timed t={sim_time:.0f}s): "
            f"sim={sim_size} == global={global_size} — local/global agree here"
        )
    else:
        print(
            f"ℹ️  {topology} MPR (timed t={sim_time:.0f}s): "
            f"local/global gap (NOT a test failure)\n"
            f"    sim cds_size (local Hellos):  {sim_size}\n"
            f"    global compute_cds (recomputed MPR): {global_size}\n"
            f"    delta local−global: {delta}\n"
            f"    → analyse as vue-locale/vue-globale (cds.py); not a SimPy bug per se"
        )

    try:
        _verify_relay_backbone(engine, relay_aids, nmap)
        if sim_size < global_size:
            print(
                f"    MPR runtime backbone valid despite smaller size "
                f"(runtime={sim_size}, global={global_size})"
            )
        else:
            print(
                f"    MPR runtime backbone valid "
                f"(runtime={sim_size}, global={global_size})"
            )
    except AssertionError as exc:
        print(
            f"⚠️  {topology} MPR runtime backbone INCOMPLETE (timed): {exc}\n"
            f"    runtime relays={sim_size}  global oracle={global_size}  "
            f"delta={delta}"
        )


def test_line5_wu_li() -> None:
    topology = "line-5 A—B—C—D—E"
    R = 1.0
    positions = {bd: (float(i), 0.0) for i, bd in enumerate(_LINE5)}

    engine, sim_time = _run_timed(positions, R)
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
            sim_time=sim_time,
        )
    if relays != degree2:
        _fail(
            topology,
            expected=f"relays == degree-2 nodes {sorted(degree2)}",
            got=f"relays {sorted(relays)} endpoints {sorted(endpoints)} roles {roles}",
            sim_time=sim_time,
        )
    if any(roles[bd] != "LEAF" for bd in endpoints):
        _fail(topology, expected="endpoints LEAF", got=str(roles), sim_time=sim_time)

    _verify_relay_backbone(engine, _relay_anon_ids(engine), nmap)
    _compare_with_global_oracle(topology, engine, sim_time, neighbor_map=nmap)
    print(
        f"✅ {topology}: 3 relays on degree-2 nodes, CDS valid, "
        f"matches compute_cds (t={sim_time:.0f}s)"
    )
    _characterize_mpr_timed(topology, positions, R)


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

    engine, sim_time = _run_timed(positions, R)
    roles = engine.roles()
    nmap = _neighbor_map(engine)

    for i, a in enumerate(leaves):
        for b in leaves[i + 1 :]:
            if b in nmap[a]:
                _fail(
                    topology,
                    expected=f"leaves {a},{b} out of range",
                    got=f"neighbors {nmap}",
                    sim_time=sim_time,
                )

    if roles[hub] != "RELAY":
        _fail(topology, expected=f"hub {hub} RELAY", got=str(roles), sim_time=sim_time)
    for leaf in leaves:
        if roles[leaf] != "LEAF":
            _fail(topology, expected=f"leaf {leaf} LEAF", got=str(roles), sim_time=sim_time)

    _compare_with_global_oracle(topology, engine, sim_time, neighbor_map=nmap)
    print(f"✅ {topology}: hub RELAY, leaves LEAF, matches compute_cds (t={sim_time:.0f}s)")
    _characterize_mpr_timed(topology, positions, R)


def test_triangle_wu_li() -> None:
    topology = "triangle full mesh"
    R = 1.0
    side = 0.8 * R
    tri = [_ADDR_A, _ADDR_B, _ADDR_C]
    positions = {
        tri[0]: (0.0, 0.0),
        tri[1]: (side, 0.0),
        tri[2]: (side / 2.0, side * math.sqrt(3) / 2.0),
    }

    engine, sim_time = _run_timed(positions, R)
    roles = engine.roles()
    nmap = _neighbor_map(engine)

    for bd in tri:
        if len(nmap[bd]) != 2:
            _fail(
                topology,
                expected=f"{bd} degree 2",
                got=f"neighbors {nmap}",
                sim_time=sim_time,
            )

    if any(role != "LEAF" for role in roles.values()):
        _fail(topology, expected="all LEAF", got=str(roles), sim_time=sim_time)

    _compare_with_global_oracle(topology, engine, sim_time, neighbor_map=nmap)
    print(f"✅ {topology}: all LEAF, matches compute_cds (t={sim_time:.0f}s)")
    _characterize_mpr_timed(topology, positions, R)


if __name__ == "__main__":
    test_line5_wu_li()
    test_star_wu_li()
    test_triangle_wu_li()
    print("\n✅ All timed validation tests passed (Wu-Li oracle locked; MPR characterized)")
