"""
Event-driven simulation layer (SimPy) alongside the round-based SimEngine.

``TimedBus`` mirrors ``SimBus`` geometry but schedules packet delivery on a
simulated clock with transmission latency and optional loss.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sim.timed.timed_bus import TimedBus
    from sim.timed.timed_engine import TimedEngine, TimedNode

__all__ = ["TimedBus", "TimedEngine", "TimedNode"]


def __getattr__(name: str) -> object:
    if name == "TimedBus":
        from sim.timed.timed_bus import TimedBus

        return TimedBus
    if name == "TimedEngine":
        from sim.timed.timed_engine import TimedEngine

        return TimedEngine
    if name == "TimedNode":
        from sim.timed.timed_engine import TimedNode

        return TimedNode
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
