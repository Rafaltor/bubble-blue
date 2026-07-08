"""
Periodic sampling of timed-simulation network state for mobility/CDS time series.

``NetworkObserver`` records relay/leaf roles, backbone validity, coverage holes,
and radio edge counts at a fixed SimPy interval. Aggregated metrics in
:meth:`NetworkObserver.summary` answer *how the CDS adapts under mobility*:

``role_flips_total`` / ``role_flip_rate``
    Count of RELAY↔LEAF transitions between consecutive samples (all nodes).
    High values indicate churn — the backbone is being torn down and rebuilt.

``cds_valid_fraction``
    Share of samples where the current RELAY set is dominating **and** connected
    on the **ground-truth** radio graph (``TimedBus.neighbors``). Drops when
    elected relays no longer form a valid CDS on the real topology.

``mean_uncovered``
    Average number of LEAF nodes with **no** RELAY radio neighbor per sample.
    Proxy for local coverage holes (nodes that cannot reach a relay in one hop).

``coverage_hole_time_fraction``
    Share of samples with at least one uncovered LEAF. Complements
    ``mean_uncovered`` when holes are intermittent rather than persistent.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import simpy

from sim.sim_engine import _GK
from src.forwarding.cds import _Topology, _add_edge, _verify_cds_properties

from sim.timed.timed_bus import TimedBus
from sim.timed.timed_engine import TimedEngine

Snapshot = dict[str, Any]


def _neighbor_map(bus: TimedBus, bds: list[str]) -> dict[str, list[str]]:
    return {bd: bus.neighbors(bd) for bd in bds}


def _n_edges(nmap: dict[str, list[str]]) -> int:
    edges: set[tuple[str, str]] = set()
    for a, neighbors in nmap.items():
        for b in neighbors:
            edges.add((min(a, b), max(a, b)))
    return len(edges)


def _topology_from_radio(
    engine: TimedEngine,
    nmap: dict[str, list[str]],
) -> _Topology:
    """Ground-truth unit-disk graph as anon_id ``_Topology`` (symmetric edges)."""
    topo = _Topology()
    bd_to_aid = {bd: node.hello_mgr.anon_id for bd, node in engine.nodes.items()}
    for bd in engine.nodes:
        aid = bd_to_aid[bd]
        topo.nodes.add(aid)
        topo.adj.setdefault(aid, set())
        for nb in nmap.get(bd, []):
            nb_aid = bd_to_aid[nb]
            _add_edge(topo, aid, nb_aid)
    return topo


def _relay_anon_ids(engine: TimedEngine, roles: dict[str, str]) -> set[bytes]:
    return {
        engine.nodes[bd].hello_mgr.anon_id
        for bd, role in roles.items()
        if role == "RELAY"
    }


def _cds_valid(engine: TimedEngine, roles: dict[str, str], nmap: dict[str, list[str]]) -> bool:
    relays = _relay_anon_ids(engine, roles)
    if not relays:
        return len(engine.nodes) <= 1
    topo = _topology_from_radio(engine, nmap)
    try:
        _verify_cds_properties(relays, topo)
    except AssertionError:
        return False
    return True


def _uncovered_nodes(roles: dict[str, str], nmap: dict[str, list[str]]) -> list[str]:
    relays = {bd for bd, role in roles.items() if role == "RELAY"}
    uncovered: list[str] = []
    for bd, role in roles.items():
        if role == "RELAY":
            continue
        if not any(nb in relays for nb in nmap.get(bd, [])):
            uncovered.append(bd)
    return sorted(uncovered)


class NetworkObserver:
    """
    SimPy process that samples ``TimedEngine`` / ``TimedBus`` state periodically.

    Start with ``env.process(observer.sample_process())`` before ``run_for``.
    """

    def __init__(
        self,
        env: simpy.Environment,
        engine: TimedEngine,
        bus: TimedBus,
        *,
        sample_interval_s: float = 1.0,
    ) -> None:
        self._env = env
        self._engine = engine
        self._bus = bus
        self._sample_interval_s = max(1e-6, float(sample_interval_s))
        self._snapshots: list[Snapshot] = []

    @property
    def snapshots(self) -> list[Snapshot]:
        return list(self._snapshots)

    def sample_process(self) -> Generator[simpy.events.Event, None, None]:
        while True:
            self._record_snapshot()
            yield self._env.timeout(self._sample_interval_s)

    def _record_snapshot(self) -> None:
        bds = sorted(self._engine.nodes)
        roles = self._engine.roles()
        nmap = _neighbor_map(self._bus, bds)
        relay_count = sum(1 for role in roles.values() if role == "RELAY")
        uncovered = _uncovered_nodes(roles, nmap)
        self._snapshots.append(
            {
                "t": self._env.now,
                "roles": dict(roles),
                "relay_count": relay_count,
                "cds_valid": _cds_valid(self._engine, roles, nmap),
                "uncovered_nodes": uncovered,
                "n_edges": _n_edges(nmap),
            }
        )

    def summary(self, *, since_t: float | None = None) -> dict[str, float | int]:
        """
        Aggregate mobility/CDS metrics over recorded snapshots.

        Parameters
        ----------
        since_t:
            If set, only snapshots with ``t >= since_t`` are included (useful to
            skip convergence transients on static runs).

        Returns a dict with:

        ``role_flips_total``
            Total RELAY↔LEAF transitions between consecutive samples (per node).

        ``role_flip_rate``
            ``role_flips_total / duration_s`` (0 if fewer than 2 samples).

        ``cds_valid_fraction``
            Fraction of samples where ``cds_valid`` is True.

        ``mean_uncovered``
            Mean count of uncovered LEAF nodes per sample.

        ``coverage_hole_time_fraction``
            Fraction of samples with at least one uncovered LEAF.
        """
        snaps = self._snapshots
        if since_t is not None:
            snaps = [s for s in snaps if s["t"] >= since_t]
        if not snaps:
            return {
                "role_flips_total": 0,
                "role_flip_rate": 0.0,
                "cds_valid_fraction": 0.0,
                "mean_uncovered": 0.0,
                "coverage_hole_time_fraction": 0.0,
                "duration_s": 0.0,
                "n_samples": 0,
            }

        role_flips = 0
        for prev, curr in zip(snaps, snaps[1:]):
            prev_roles = prev["roles"]
            curr_roles = curr["roles"]
            for bd in prev_roles:
                if curr_roles.get(bd) != prev_roles[bd]:
                    role_flips += 1

        duration_s = float(snaps[-1]["t"] - snaps[0]["t"])
        if duration_s <= 0.0:
            duration_s = self._sample_interval_s

        n = len(snaps)
        cds_ok = sum(1 for s in snaps if s["cds_valid"])
        holes = sum(1 for s in snaps if s["uncovered_nodes"])
        mean_uncovered = sum(len(s["uncovered_nodes"]) for s in snaps) / n

        return {
            "role_flips_total": role_flips,
            "role_flip_rate": role_flips / duration_s,
            "cds_valid_fraction": cds_ok / n,
            "mean_uncovered": mean_uncovered,
            "coverage_hole_time_fraction": holes / n,
            "duration_s": duration_s,
            "n_samples": n,
        }


if __name__ == "__main__":
    from src.forwarding.cds import CDSAlgorithm

    A, B, C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"
    positions = {A: (0.0, 0.0), B: (1.0, 0.0), C: (2.0, 0.0)}

    engine = TimedEngine(
        positions,
        radius=1.0,
        algorithm=CDSAlgorithm.WU_LI_1999,
        hello_interval_s=5.0,
        jitter_frac=0.0,
        tx_latency_s=0.0,
        loss_prob=0.0,
        seed=0,
        group_key=_GK,
    )
    observer = NetworkObserver(
        engine.env,
        engine,
        engine.bus,
        sample_interval_s=1.0,
    )
    engine.env.process(observer.sample_process())
    run_s = 50.0
    engine.run_for(run_s)

    summary = observer.summary()
    tail_summary = observer.summary(since_t=25.0)
    print(f"static line-3 observer (t=0..{run_s}s, no mobility)")
    print(f"  samples: {summary['n_samples']} (tail from t=25s: {tail_summary['n_samples']})")
    print(f"  cds_valid_fraction (tail): {tail_summary['cds_valid_fraction']:.3f}")
    print(f"  role_flips_total (tail): {tail_summary['role_flips_total']}")
    print(f"  mean_uncovered (tail): {tail_summary['mean_uncovered']:.3f}")

    assert tail_summary["cds_valid_fraction"] >= 0.99, tail_summary
    assert tail_summary["mean_uncovered"] == 0.0, tail_summary
    assert tail_summary["role_flips_total"] == 0, tail_summary

    tail = [s for s in observer.snapshots if s["t"] >= 25.0]
    assert tail, "expected samples in convergence tail"
    tail_roles = [s["roles"] for s in tail]
    assert all(r == tail_roles[0] for r in tail_roles), "roles must stabilize (no flips)"
    assert tail_roles[0][B] == "RELAY"
    print("\n✅ static sanity: tail cds_valid≈1, no flips, B stays RELAY")
