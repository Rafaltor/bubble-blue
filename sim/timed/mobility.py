"""
Mobility models for the timed SimPy simulation layer.

Models update node positions on a ``TimedBus`` under the simulated clock. Each
new topology is reflected immediately in ``neighbors()`` / ``in_range()`` via
the unit-disk geometry.

Known bias — **random waypoint**: nodes spend disproportionately long near the
centre of the deployment area (speed–pause trade-off). Report this when
interpreting spatial density or link stability; prefer a peloton/group model
(see ``MobilityModel``) when nodes should stay clustered.

Future work: ``PelotonMobility`` (or similar) as a sister class implementing the
same ``MobilityModel`` interface for coordinated group motion.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import Protocol, runtime_checkable

import simpy

from sim.timed.timed_bus import Position, TimedBus

_ARRIVAL_EPS = 1e-6


@runtime_checkable
class MobilityModel(Protocol):
    """Common surface for timed mobility drivers (random waypoint, peloton, …)."""

    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        """SimPy process that updates ``TimedBus`` positions over simulated time."""
        ...


class RandomWaypointMobility:
    """
    Classic random-waypoint mobility on a square ``[0, area]²`` deployment.

    The node must already be registered on ``bus`` before ``walk_process`` runs.
    Movement uses ``TimedBus.set_position``; radio neighbors refresh on every
    update.

    **Central concentration bias**: with uniform destination sampling and
    uniform pause, the steady-state spatial distribution is not uniform — nodes
    tend to cluster toward the area centre. Document this in mobility studies.
    """

    def __init__(
        self,
        env: simpy.Environment,
        bus: TimedBus,
        bd_addr: str,
        *,
        area: float,
        speed_min: float,
        speed_max: float,
        pause_min_s: float,
        pause_max_s: float,
        rng: random.Random,
        update_interval_s: float = 0.5,
    ) -> None:
        self._env = env
        self._bus = bus
        self.bd = bd_addr.upper()
        self._area = max(0.0, float(area))
        self._speed_min = max(0.0, float(speed_min))
        self._speed_max = max(self._speed_min, float(speed_max))
        self._pause_min_s = max(0.0, float(pause_min_s))
        self._pause_max_s = max(self._pause_min_s, float(pause_max_s))
        self._rng = rng
        self._update_interval_s = max(1e-6, float(update_interval_s))

        if self.bd not in self._bus._positions:  # noqa: SLF001 — node must be on bus
            raise KeyError(f"node {self.bd} not registered on TimedBus")
        self._x, self._y = self._bus._positions[self.bd]  # noqa: SLF001

    @property
    def position(self) -> Position:
        return (self._x, self._y)

    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        while True:
            dest = (self._rng.uniform(0.0, self._area), self._rng.uniform(0.0, self._area))
            speed = self._rng.uniform(self._speed_min, self._speed_max)
            while not self._at_destination(dest):
                self._step_toward(dest, speed)
                yield self._env.timeout(self._update_interval_s)
            self._set_position(dest[0], dest[1])
            pause_s = self._rng.uniform(self._pause_min_s, self._pause_max_s)
            yield self._env.timeout(pause_s)

    def _at_destination(self, dest: Position) -> bool:
        return math.hypot(dest[0] - self._x, dest[1] - self._y) <= _ARRIVAL_EPS

    def _step_toward(self, dest: Position, speed: float) -> None:
        dx = dest[0] - self._x
        dy = dest[1] - self._y
        dist = math.hypot(dx, dy)
        if dist <= _ARRIVAL_EPS:
            return
        step = min(speed * self._update_interval_s, dist)
        nx = self._x + dx / dist * step
        ny = self._y + dy / dist * step
        self._set_position(nx, ny)

    def _set_position(self, x: float, y: float) -> None:
        self._x = float(x)
        self._y = float(y)
        self._bus.set_position(self.bd, (self._x, self._y))


class _MobilityModelABC(ABC):
    """Optional explicit base for future peloton / group models."""

    @abstractmethod
    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        raise NotImplementedError


def _sample_positions(bus: TimedBus, bds: list[str]) -> dict[str, Position]:
    return {bd: bus._positions[bd] for bd in bds}  # noqa: SLF001


def _run_mobility_demo(*, seed: int, duration_s: float) -> list[tuple[float, dict[str, Position]]]:
    area = 20.0
    env = simpy.Environment()
    bus = TimedBus(env, radius=2.5, rng=random.Random(seed))
    bds = [f"AA:BB:CC:DD:EE:{i:02X}" for i in range(5)]
    spawn_rng = random.Random(seed)

    for bd in bds:
        pos = (spawn_rng.uniform(0.0, area), spawn_rng.uniform(0.0, area))
        bus.register(bd, pos, lambda _p, _d: None)

    for index, bd in enumerate(bds):
        mobile = RandomWaypointMobility(
            env,
            bus,
            bd,
            area=area,
            speed_min=0.5,
            speed_max=2.0,
            pause_min_s=0.5,
            pause_max_s=2.0,
            rng=random.Random(seed * 10_007 + index),
            update_interval_s=0.5,
        )
        env.process(mobile.walk_process())

    snapshots: list[tuple[float, dict[str, Position]]] = []

    def _sampler() -> Generator[simpy.events.Event, None, None]:
        while True:
            snapshots.append((env.now, _sample_positions(bus, bds)))
            yield env.timeout(1.0)

    env.process(_sampler())
    env.run(until=duration_s)
    return snapshots


if __name__ == "__main__":
    duration = 6.0
    seed = 42
    traj = _run_mobility_demo(seed=seed, duration_s=duration)

    print(f"random waypoint demo (seed={seed}, t=0..{duration}s, 5 nodes)")
    for t, poses in traj:
        short = {bd[-8:]: f"({x:.2f},{y:.2f})" for bd, (x, y) in sorted(poses.items())}
        print(f"  t={t:4.1f}s  {short}")

    repeat = _run_mobility_demo(seed=seed, duration_s=duration)
    assert traj == repeat, "same seed must yield identical trajectories"
    print("\n✅ deterministic trajectories (seed=42 replay match)")
    print("✅ mobility self-test passed")
