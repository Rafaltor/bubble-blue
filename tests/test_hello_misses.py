"""
Node departure: how many missed Hellos before a neighbour is dropped.

Dropping on the first silence churns the CDS for nothing — a lost advertisement
is routine on a shared 2.4 GHz band. So the delay is expressed as a count of
missed periods, configurable, and what is checked here is the boundary: the
neighbour must survive the last tolerated miss and disappear on the next one.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config as bbconfig  # noqa: E402
from src.control.neighbors import NeighborTable  # noqa: E402
from src.control.hello import compute_anon_id  # noqa: E402

_KEY = bytes(range(32))
_PEER = "BB:BB:BB:BB:BB:BB"


class _Env:
    """Set env vars for the duration of a block, restoring whatever was there."""

    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        for k, v in self.values.items():
            self.saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = str(v)
        return self

    def __exit__(self, *exc):
        for k, old in self.saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _timing(**env):
    """Load just the timing fields, without touching the Bluetooth adapter."""
    with _Env(**env):
        interval = bbconfig._env_int(
            "BUBBLE_BLUE_HELLO_INTERVAL_S", bbconfig.DEFAULT_HELLO_INTERVAL_S, minimum=1
        )
        misses = bbconfig._env_int(
            "BUBBLE_BLUE_HELLO_MISSES", bbconfig.DEFAULT_HELLO_MISSES, minimum=2
        )
    return interval, misses, interval * misses


# ---- the configured threshold -------------------------------------------


def test_defaults_are_unchanged():
    # 5 s x 3 was the previous hardcoded 15 s; retuning must not have moved it.
    interval, misses, timeout = _timing(
        BUBBLE_BLUE_HELLO_INTERVAL_S=None, BUBBLE_BLUE_HELLO_MISSES=None
    )
    assert (interval, misses, timeout) == (5, 3, 15)


def test_the_threshold_is_configurable():
    assert _timing(BUBBLE_BLUE_HELLO_MISSES=5) == (5, 5, 25)
    assert _timing(BUBBLE_BLUE_HELLO_INTERVAL_S=2, BUBBLE_BLUE_HELLO_MISSES=4) == (2, 4, 8)


def test_the_delay_follows_the_interval():
    # The point of counting periods: retuning the interval keeps the meaning.
    _, misses_fast, timeout_fast = _timing(BUBBLE_BLUE_HELLO_INTERVAL_S=1)
    _, misses_slow, timeout_slow = _timing(BUBBLE_BLUE_HELLO_INTERVAL_S=10)
    assert misses_fast == misses_slow == 3
    assert (timeout_fast, timeout_slow) == (3, 30)


def test_a_single_miss_cannot_be_configured():
    # Dropping on one lost packet is the instability this exists to prevent.
    assert _timing(BUBBLE_BLUE_HELLO_MISSES=1)[1] == 2
    assert _timing(BUBBLE_BLUE_HELLO_MISSES=0)[1] == 2


def test_a_typo_falls_back_instead_of_refusing_to_start():
    # A bad .env must not keep a board off the mesh.
    assert _timing(BUBBLE_BLUE_HELLO_MISSES="trois")[1] == 3
    assert _timing(BUBBLE_BLUE_HELLO_INTERVAL_S="")[0] == 5


# ---- what the table actually does with it --------------------------------


def _table_with_peer(last_seen_ms: int) -> tuple[NeighborTable, bytes]:
    table = NeighborTable()
    aid = compute_anon_id(_KEY, _PEER)
    table.resolve_member(aid, _PEER, last_seen_ms)
    table._upsert_1hop(aid, bd_addr=_PEER, last_seen_ms=last_seen_ms, seq=1)
    return table, aid


def _still_present(silent_for_s: float, timeout_s: int) -> bool:
    import time

    now_ms = time.time_ns() // 1_000_000
    table, aid = _table_with_peer(now_ms - int(silent_for_s * 1000))
    table.expire(timeout_s * 1000)
    return any(e["anon_id"] == aid for e in table.get_1hop())


def test_a_neighbour_survives_the_last_tolerated_miss():
    # 5 s interval, 3 misses: silent for two periods is not yet a departure.
    assert _still_present(silent_for_s=10.0, timeout_s=15) is True
    assert _still_present(silent_for_s=14.5, timeout_s=15) is True


def test_a_neighbour_is_dropped_past_the_threshold():
    assert _still_present(silent_for_s=16.0, timeout_s=15) is False


def test_raising_the_threshold_keeps_a_flapping_neighbour():
    # The same 20 s silence: dropped at 3 misses, tolerated at 5.
    assert _still_present(silent_for_s=20.0, timeout_s=15) is False
    assert _still_present(silent_for_s=20.0, timeout_s=25) is True


if __name__ == "__main__":
    for fn in (
        test_defaults_are_unchanged,
        test_the_threshold_is_configurable,
        test_the_delay_follows_the_interval,
        test_a_single_miss_cannot_be_configured,
        test_a_typo_falls_back_instead_of_refusing_to_start,
        test_a_neighbour_survives_the_last_tolerated_miss,
        test_a_neighbour_is_dropped_past_the_threshold,
        test_raising_the_threshold_keeps_a_flapping_neighbour,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All Hello-miss threshold tests passed")
