"""
Convergence and stability metrics, checked without boards.

These numbers are meant to end up in a paper, so the arithmetic behind them has
to be pinned down: what counts as converged, what the warm-up window excludes,
and — the one that is easy to get quietly wrong — that the campaign figure is
the worst board rather than the average of them. A mesh is only converged when
the last node joined.
"""

from __future__ import annotations

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from bb_bench import Board, aggregate  # noqa: E402
from bb_probe import WARMUP_S, Probe  # noqa: E402


class _FakeNode:
    def __init__(self, local="AA:AA:AA:AA:AA:AA", peers=(), relay=False):
        self.local_bd_addr = local
        self._peers = list(peers)
        self._relay = relay

    def peers(self):
        return list(self._peers)

    def is_relay(self):
        return self._relay


def _probe(expect_peers=5, elapsed=300.0):
    p = Probe("banc", expect_peers=expect_peers)
    p.started = time.monotonic() - elapsed
    return p


# ---- convergence ---------------------------------------------------------


def test_convergence_is_when_every_peer_is_present():
    p = _probe(expect_peers=5)
    # Ramps 0..5 peers, one per second from t=1.
    p.samples = [(float(t), min(t, 5), False) for t in range(0, 300)]

    c = p._convergence()
    assert c["time_to_first_peer_s"] == 1.0
    assert c["time_to_full_mesh_s"] == 5.0


def test_a_mesh_that_never_completes_reports_null_not_zero():
    p = _probe(expect_peers=5)
    p.samples = [(float(t), 3, False) for t in range(0, 300)]  # stuck at 3

    c = p._convergence()
    assert c["time_to_full_mesh_s"] is None
    assert c["time_to_first_peer_s"] == 0.0


def test_convergence_is_undefined_without_a_board_count():
    # Without --expect there is no way to know what "complete" means, and
    # guessing would produce a confident wrong number.
    p = _probe(expect_peers=None)
    p.samples = [(float(t), 4, False) for t in range(0, 300)]

    c = p._convergence()
    assert c["time_to_full_mesh_s"] is None
    assert c["full_mesh_frac_steady"] is None
    assert c["time_to_first_peer_s"] == 0.0  # still useful


def test_time_at_full_mesh_ignores_the_ramp_up():
    p = _probe(expect_peers=5)
    # Complete throughout steady state, incomplete only while converging.
    p.samples = [(float(t), 0 if t < WARMUP_S else 5, False) for t in range(0, 300)]

    assert p._convergence()["full_mesh_frac_steady"] == 1.0


def test_a_partition_shows_up_as_lost_time():
    p = _probe(expect_peers=5)
    # Steady state runs 25..299; drop to 4 peers for half of it.
    p.samples = [
        (float(t), 5 if t < 162 else 4, False) for t in range(0, 300)
    ]

    frac = p._convergence()["full_mesh_frac_steady"]
    assert 0.45 < frac < 0.55, frac


# ---- stability -----------------------------------------------------------


def test_links_dropped_while_converging_are_not_flaps():
    p = _probe()
    p.samples = [(float(t), 5, False) for t in range(0, 300)]
    p.events = [
        (5.0, "down", "BB:BB:BB:BB:BB:BB"),   # during warm-up: converging
        (200.0, "down", "CC:CC:CC:CC:CC:CC"),  # after: a real flap
    ]

    s = p._stability()
    assert s["flaps_after_warmup"] == 1
    assert s["flap_rate_per_h"] > 0


def test_a_stable_relay_role_is_not_counted_as_churn():
    p = _probe()
    # Relay for the whole run: many samples, zero transitions.
    p.samples = [(float(t), 5, True) for t in range(0, 300)]

    s = p._stability()
    assert s["relay_transitions"] == 0
    assert s["relay_frac_steady"] == 1.0


def test_relay_churn_counts_changes_of_mind():
    p = _probe()
    # Flips role every 50 s from t=0; steady state starts at 25.
    p.samples = [(float(t), 5, (t // 50) % 2 == 1) for t in range(0, 300)]

    assert p._stability()["relay_transitions"] == 5


def test_the_minimum_peer_count_survives_the_average():
    # A mean of 5 can hide a board that briefly saw nobody, so both are kept.
    p = _probe()
    p.samples = [(float(t), 0 if t == 150 else 5, False) for t in range(0, 300)]

    s = p._stability()
    assert s["min_peers_steady"] == 0
    assert s["mean_peers_steady"] > 4.9


# ---- the campaign view ---------------------------------------------------


def _board(tag, local, senders, conv, frac, flaps=0, transitions=0):
    b = Board(tag, f"user@{tag}")
    b.summary = {
        "local": local,
        "senders": senders,
        "time_to_full_mesh_s": conv,
        "full_mesh_frac_steady": frac,
        "flaps_after_warmup": flaps,
        "relay_transitions": transitions,
    }
    return b


_A, _B, _C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"


def test_the_campaign_converges_when_the_last_board_does():
    boards = [
        _board("a", _A, [_B, _C], 12.0, 1.0),
        _board("b", _B, [_A, _C], 40.0, 1.0),
        _board("c", _C, [_A, _B], 21.0, 1.0),
    ]
    agg = aggregate(boards, expect=3)

    assert agg["convergence_last_board_s"] == 40.0
    assert agg["convergence_first_board_s"] == 12.0
    assert agg["boards_fully_converged"] == 3
    assert agg["delivery_worst"] == 1.0


def test_the_worst_board_sets_the_campaign_figure():
    boards = [
        _board("a", _A, [_B, _C], 12.0, 1.0, flaps=0, transitions=1),
        _board("b", _B, [_A, _C], 15.0, 0.62, flaps=4, transitions=2),
    ]
    agg = aggregate(boards, expect=2)

    assert agg["full_mesh_frac_worst"] == 0.62  # not the 0.81 average
    assert agg["flaps_total"] == 4
    assert agg["relay_transitions_total"] == 3


def test_a_silent_link_shows_up_in_delivery_not_in_peer_counts():
    # b is connected and converged but never heard c: peer counts look perfect,
    # delivery is what catches it.
    boards = [
        _board("a", _A, [_B, _C], 10.0, 1.0),
        _board("b", _B, [_A], 10.0, 1.0),
        _board("c", _C, [_A, _B], 10.0, 1.0),
    ]
    agg = aggregate(boards, expect=3)

    assert agg["full_mesh_frac_worst"] == 1.0
    assert agg["delivery_worst"] == 0.5
    assert agg["delivery_mean"] < 1.0


def test_a_board_that_never_reported_is_not_silently_dropped():
    boards = [
        _board("a", _A, [_B], 10.0, 1.0),
        _board("b", _B, [_A], 10.0, 1.0),
        Board("dead", "user@dead"),  # no summary
    ]
    agg = aggregate(boards, expect=3)

    assert agg["boards_reporting"] == 2
    assert agg["boards_expected"] == 3


if __name__ == "__main__":
    for fn in (
        test_convergence_is_when_every_peer_is_present,
        test_a_mesh_that_never_completes_reports_null_not_zero,
        test_convergence_is_undefined_without_a_board_count,
        test_time_at_full_mesh_ignores_the_ramp_up,
        test_a_partition_shows_up_as_lost_time,
        test_links_dropped_while_converging_are_not_flaps,
        test_a_stable_relay_role_is_not_counted_as_churn,
        test_relay_churn_counts_changes_of_mind,
        test_the_minimum_peer_count_survives_the_average,
        test_the_campaign_converges_when_the_last_board_does,
        test_the_worst_board_sets_the_campaign_figure,
        test_a_silent_link_shows_up_in_delivery_not_in_peer_counts,
        test_a_board_that_never_reported_is_not_silently_dropped,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All benchmark metric tests passed")
