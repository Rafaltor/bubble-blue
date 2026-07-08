"""
Qualitative mobility behaviour tests for the timed SimPy harness.

These tests validate **expected behaviour**, not precise numeric targets:

- Static (mobility off): CDS stays valid; roles stabilise after convergence.
- Mobility on: backbone reconfigures (role flips) while CDS remains mostly valid.
- Determinism: identical seeds → identical metrics.
- Faster mobility → higher role-flip rate.

Exact metric values are **scientific results** for the rapport — produced by
``scenario_mobility.compare_mobility`` and analysed there, not locked here.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.forwarding.cds import CDSAlgorithm  # noqa: E402

from sim.timed.scenario_mobility import compare_mobility, run_mobility_scenario  # noqa: E402

# Shared scenario geometry (connected, moderate density).
_N = 10
_AREA = 25.0
_RADIUS = 12.0
_SEED = 17
_DURATION_S = 100.0
_HELLO_S = 3.0
_TAIL_S = 25.0


def _tail(metrics: dict) -> dict:
    return metrics.get("summary_tail", metrics)


def test_static_mobility_off_converges() -> None:
    """Mobility OFF (speed=0): valid CDS and no role churn after convergence."""
    metrics = run_mobility_scenario(
        _N,
        _AREA,
        _RADIUS,
        CDSAlgorithm.WU_LI_1999,
        duration_s=50.0,
        speed=0.0,
        hello_interval_s=_HELLO_S,
        seed=_SEED,
        jitter_frac=0.0,
        tx_latency_s=0.0,
        since_t=_TAIL_S,
    )
    tail = _tail(metrics)
    assert not metrics["mobility_on"]
    assert tail["cds_valid_fraction"] >= 0.99, tail
    assert tail["role_flips_total"] == 0, tail
    assert tail["mean_uncovered"] == 0.0, tail
    print(
        f"✅ static: tail cds_valid={tail['cds_valid_fraction']:.3f}, "
        f"role_flips={tail['role_flips_total']}"
    )


def test_mobility_on_reconfigures_and_repairs() -> None:
    """Mobility ON: role churn > 0; CDS remains mostly valid (soft threshold)."""
    metrics = run_mobility_scenario(
        _N,
        _AREA,
        _RADIUS,
        CDSAlgorithm.WU_LI_1999,
        duration_s=_DURATION_S,
        speed=0.15,
        hello_interval_s=_HELLO_S,
        seed=_SEED,
        since_t=_TAIL_S,
    )
    assert metrics["mobility_on"]
    assert metrics["role_flip_rate"] > 0.0, metrics
    assert metrics["cds_valid_fraction"] > 0.7, metrics
    print(
        f"✅ mobility ON: flip_rate={metrics['role_flip_rate']:.4f}, "
        f"cds_valid={metrics['cds_valid_fraction']:.3f}"
    )


def test_deterministic_metrics_same_seed() -> None:
    """Same seed → identical metrics (reproducibility)."""
    kwargs = dict(
        duration_s=_DURATION_S,
        speed=1.0,
        hello_interval_s=_HELLO_S,
        seed=_SEED,
        since_t=_TAIL_S,
    )
    a = run_mobility_scenario(_N, _AREA, _RADIUS, CDSAlgorithm.WU_LI_1999, **kwargs)
    b = run_mobility_scenario(_N, _AREA, _RADIUS, CDSAlgorithm.WU_LI_1999, **kwargs)
    # Compare scalar metric fields (full reproducibility).
    keys = {
        k
        for k in a
        if k not in ("summary_tail",) and isinstance(a[k], (int, float, bool, str))
    }
    for k in keys:
        assert a[k] == b[k], f"metric {k} differs: {a[k]!r} vs {b[k]!r}"
    assert a["summary_tail"] == b["summary_tail"]
    print("✅ determinism: identical metrics for same seed")


def test_higher_speed_more_role_flips() -> None:
    """Faster waypoint speed → higher role_flip_rate (more reconfiguration)."""
    common = dict(
        duration_s=_DURATION_S,
        hello_interval_s=_HELLO_S,
        seed=_SEED + 100,
        since_t=_TAIL_S,
    )
    slow = run_mobility_scenario(
        _N, _AREA, _RADIUS, CDSAlgorithm.WU_LI_1999, speed=0.08, **common
    )
    fast = run_mobility_scenario(
        _N, _AREA, _RADIUS, CDSAlgorithm.WU_LI_1999, speed=1.8, **common
    )
    assert fast["role_flip_rate"] > slow["role_flip_rate"], (
        f"slow={slow['role_flip_rate']:.4f} fast={fast['role_flip_rate']:.4f}"
    )
    print(
        f"✅ speed effect: slow flip_rate={slow['role_flip_rate']:.4f} "
        f"< fast={fast['role_flip_rate']:.4f}"
    )


def test_compare_mobility_wu_li_vs_mpr() -> None:
    """Wu-Li vs MPR comparison runs and returns structured deltas (report data)."""
    result = compare_mobility(
        _N,
        _AREA,
        _RADIUS,
        duration_s=_DURATION_S,
        speed=0.15,
        hello_interval_s=_HELLO_S,
        seed=_SEED,
        since_t=_TAIL_S,
    )
    assert "wu_li" in result and "mpr" in result and "comparison" in result
    cmp_ = result["comparison"]
    assert "role_flip_rate_delta" in cmp_
    print(
        f"✅ compare_mobility: Δ flip_rate={cmp_['role_flip_rate_delta']:+.4f} "
        f"Δ cds_valid={cmp_['cds_valid_fraction_delta']:+.3f}"
    )


if __name__ == "__main__":
    test_static_mobility_off_converges()
    test_mobility_on_reconfigures_and_repairs()
    test_deterministic_metrics_same_seed()
    test_higher_speed_more_role_flips()
    test_compare_mobility_wu_li_vs_mpr()
    print("\n✅ All mobility behaviour tests passed")
