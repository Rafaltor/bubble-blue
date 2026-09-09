"""
One coordinator, agreed on by everyone.

Revocation authority rests on a single rule: the member with the smallest
anon_id speaks for the group. The rule is applied twice — once by a node
deciding whether it may revoke, once by every receiver deciding whether to
believe an incoming rekey — and it has to be the same rule both times.

It was not. Election counted only members resolved through Hello, which reaches
direct neighbours alone, while validation also counted peers learned through
PKT_ANNOUNCE, which reaches the whole mesh. On a dense mesh the two views
coincide and everything looks fine. On a sparse one the neighbourhood view is a
strict subset, so several nodes each find themselves smallest, and every
revocation they issue is refused mesh-wide as "not coordinator" — while the
initiator sees its own epoch advance and reports success.

A stringy 30-node mesh had four self-declared coordinators and left 28 of 29
legitimate members stranded on the old key.
"""

from __future__ import annotations

import os
import statistics
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.forwarding_sim import ForwardingSimEngine  # noqa: E402
from sim.limits import RADIUS, adjacency, measure_revocation  # noqa: E402
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402

# Degree 6 is the *target*; boundary effects and the connectivity filter bring
# 30 nodes out at roughly 3.3, which is exactly the sparse case that broke.
_SPARSE = (30, 6.0, 1)


def _mesh(n: int, degree: float, seed: int):
    pos = generate_connected_geometric(
        n, _area_for_target_degree(n, RADIUS, degree), RADIUS, seed=seed
    )
    engine = ForwardingSimEngine(pos, RADIUS, CDSAlgorithm.WU_LI_1999, ttl_max=40)
    engine.converge(max_steps=60, announce_rounds=2)
    return engine, pos


def _coordinators(engine) -> list[str]:
    return [b for b in sorted(engine.nodes) if engine.nodes[b].hello_mgr.is_coordinator()]


def test_a_sparse_mesh_elects_exactly_one_coordinator():
    n, degree, seed = _SPARSE
    engine, pos = _mesh(n, degree, seed)
    mean_degree = statistics.mean(len(v) for v in adjacency(pos).values())

    assert mean_degree < 5.0, f"topologie pas assez eparse pour le test ({mean_degree:.2f})"
    assert len(_coordinators(engine)) == 1, (
        f"{len(_coordinators(engine))} noeuds se croient coordinateur "
        f"a degre moyen {mean_degree:.2f}"
    )


def test_election_and_validation_share_one_membership_view():
    # The asymmetry itself, independent of any topology: whatever the receiver
    # counts when validating, the elector must count when electing.
    engine, _ = _mesh(*_SPARSE)
    for bd in sorted(engine.nodes):
        node = engine.nodes[bd]
        elector = set(node.hello_mgr.member_anon_ids().values())
        validator = set(node.forwarder._member_anon_ids_for_coordinator_check())
        assert elector == validator, f"{bd}: {len(elector)} vs {len(validator)} membres"


def test_announce_learned_members_count_towards_election():
    # Without the announce plane a node sees only its neighbours, which is the
    # subset that used to cause split brain; with it, the view is the mesh.
    n, degree, seed = _SPARSE
    pos = generate_connected_geometric(
        n, _area_for_target_degree(n, RADIUS, degree), RADIUS, seed=seed
    )
    engine = ForwardingSimEngine(pos, RADIUS, CDSAlgorithm.WU_LI_1999, ttl_max=40)
    engine.converge(max_steps=60, announce_rounds=0)
    narrow = len(engine.nodes[sorted(engine.nodes)[0]].hello_mgr.member_anon_ids())

    engine.run_announce_rounds(2)
    wide = len(engine.nodes[sorted(engine.nodes)[0]].hello_mgr.member_anon_ids())

    assert wide > narrow, f"announce n'a rien ajoute ({narrow} -> {wide})"
    assert wide == n


def test_revocation_lands_on_a_sparse_mesh():
    # The consequence, measured the way it matters: nobody legitimate is left
    # on the old key, and the revoked node goes dark.
    result = measure_revocation(
        generate_connected_geometric(
            _SPARSE[0], _area_for_target_degree(_SPARSE[0], RADIUS, _SPARSE[1]),
            RADIUS, seed=_SPARSE[2],
        ),
        announce_rounds=2,
        algorithm=CDSAlgorithm.WU_LI_1999,
    )

    assert result.get("stranded") == 0, f"{result.get('stranded')} membres egares"
    assert result.get("victim_still_reads") is False


def test_revocation_lands_across_densities():
    for n, degree in ((10, 6.0), (20, 6.0), (30, 8.0)):
        result = measure_revocation(
            generate_connected_geometric(
                n, _area_for_target_degree(n, RADIUS, degree), RADIUS, seed=1
            ),
            announce_rounds=2,
            algorithm=CDSAlgorithm.WU_LI_1999,
        )
        assert result.get("stranded") == 0, f"n={n}: {result.get('stranded')} egares"
        assert result.get("victim_still_reads") is False


if __name__ == "__main__":
    for fn in (
        test_a_sparse_mesh_elects_exactly_one_coordinator,
        test_election_and_validation_share_one_membership_view,
        test_announce_learned_members_count_towards_election,
        test_revocation_lands_on_a_sparse_mesh,
        test_revocation_lands_across_densities,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All coordinator agreement tests passed")
