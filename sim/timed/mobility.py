"""
Mobility models for the timed SimPy simulation layer.

Models update node positions on a ``TimedBus`` under the simulated clock. Each
new topology is reflected immediately in ``neighbors()`` / ``in_range()`` via
the unit-disk geometry.

Known biases:

- **Random waypoint**: nodes spend disproportionately long near the centre of
  the deployment area (speed–pause trade-off). Report this when interpreting
  spatial density or link stability.
- **Peloton**: the shared centre still follows random waypoint (same central
  concentration bias on the group centroid). Cohesion is enforced in offset
  space, not against wall effects — the centre clamp can compress offsets when
  the peloton grazes the area border.
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
_TWO_PI = 2.0 * math.pi


def _clamp_coord(value: float, area: float) -> float:
    return max(0.0, min(float(area), float(value)))


def _clamp_position(x: float, y: float, area: float) -> Position:
    return (_clamp_coord(x, area), _clamp_coord(y, area))


@runtime_checkable
class MobilityModel(Protocol):
    """Common surface for timed mobility drivers (random waypoint, peloton, …)."""

    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        """SimPy process that updates ``TimedBus`` positions over simulated time."""
        ...


class PelotonGroup:
    """
    Shared random-waypoint centre for a peloton.

    Instantiate **once** per scenario run with an ``rng`` derived from
    ``mobility_seed`` (not per-node). Pass the same instance to every
    ``PelotonMobility`` via ``group=``.

    Integration hook (``scenario_mobility`` not modified yet)::

        group = PelotonGroup(env, area=area, ..., rng=random.Random(mobility_seed))
        for index, bd in enumerate(nodes):
            PelotonMobility(env, bus, bd, ..., group=group,
                            rng=random.Random(mobility_seed * 10_007 + index))
    """

    def __init__(
        self,
        env: simpy.Environment,
        *,
        area: float,
        speed_min: float,
        speed_max: float,
        pause_min_s: float,
        pause_max_s: float,
        rng: random.Random,
        update_interval_s: float = 0.5,
        center: Position | None = None,
    ) -> None:
        self._env = env
        self._area = max(0.0, float(area))
        self._speed_min = max(0.0, float(speed_min))
        self._speed_max = max(self._speed_min, float(speed_max))
        self._pause_min_s = max(0.0, float(pause_min_s))
        self._pause_max_s = max(self._pause_min_s, float(pause_max_s))
        self._rng = rng
        self._update_interval_s = max(1e-6, float(update_interval_s))
        if center is None:
            cx = cy = self._area / 2.0
        else:
            cx, cy = center
        self._center_x, self._center_y = _clamp_position(cx, cy, self._area)
        self._center_driver_started = False

    @property
    def center(self) -> Position:
        return (self._center_x, self._center_y)

    def ensure_center_driver(self) -> None:
        """Start the shared centre waypoint process (idempotent)."""
        if self._center_driver_started:
            return
        self._center_driver_started = True
        self._env.process(self._center_walk_process())

    def _center_walk_process(self) -> Generator[simpy.events.Event, None, None]:
        while True:
            dest = (
                self._rng.uniform(0.0, self._area),
                self._rng.uniform(0.0, self._area),
            )
            speed = self._rng.uniform(self._speed_min, self._speed_max)
            while not self._center_at_destination(dest):
                self._step_center_toward(dest, speed)
                yield self._env.timeout(self._update_interval_s)
            self._center_x, self._center_y = _clamp_position(dest[0], dest[1], self._area)
            pause_s = self._rng.uniform(self._pause_min_s, self._pause_max_s)
            yield self._env.timeout(pause_s)

    def _center_at_destination(self, dest: Position) -> bool:
        return math.hypot(dest[0] - self._center_x, dest[1] - self._center_y) <= _ARRIVAL_EPS

    def _step_center_toward(self, dest: Position, speed: float) -> None:
        dx = dest[0] - self._center_x
        dy = dest[1] - self._center_y
        dist = math.hypot(dx, dy)
        if dist <= _ARRIVAL_EPS:
            return
        step = min(speed * self._update_interval_s, dist)
        nx = self._center_x + dx / dist * step
        ny = self._center_y + dy / dist * step
        self._center_x, self._center_y = _clamp_position(nx, ny, self._area)


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
        self._x, self._y = _clamp_position(x, y, self._area)
        self._bus.set_position(self.bd, (self._x, self._y))


class PelotonMobility:
    """
    Peloton mobility: nodes orbit a **shared** random-waypoint centre.

    Each member keeps a slowly drifting offset bounded by ``cohesion_radius``
    around ``PelotonGroup.center``. Per-node ``rng`` drives offset noise only;
    centre motion is entirely owned by the shared ``PelotonGroup`` RNG.

    Pass the **same** ``PelotonGroup`` to every member. If ``group`` is omitted,
    a private group is created (single-node peloton — not a coordinated flock).

    See ``PelotonGroup`` for the ``scenario_mobility`` injection hook.
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
        group: PelotonGroup | None = None,
        cohesion_radius: float | None = None,
    ) -> None:
        self._env = env
        self._bus = bus
        self.bd = bd_addr.upper()
        self._area = max(0.0, float(area))
        self._rng = rng
        self._update_interval_s = max(1e-6, float(update_interval_s))
        self._cohesion_radius = (
            max(0.0, float(cohesion_radius))
            if cohesion_radius is not None
            else self._area * 0.15
        )
        self._offset_drift = self._cohesion_radius * 0.08

        if self.bd not in self._bus._positions:  # noqa: SLF001
            raise KeyError(f"node {self.bd} not registered on TimedBus")
        self._x, self._y = self._bus._positions[self.bd]  # noqa: SLF001

        if group is None:
            self._group = PelotonGroup(
                env,
                area=self._area,
                speed_min=speed_min,
                speed_max=speed_max,
                pause_min_s=pause_min_s,
                pause_max_s=pause_max_s,
                rng=rng,
                update_interval_s=update_interval_s,
                center=(self._x, self._y),
            )
        else:
            self._group = group

        cx, cy = self._group.center
        self._offset_x = self._x - cx
        self._offset_y = self._y - cy
        self._clamp_offset()
        self._apply_position()

    @property
    def position(self) -> Position:
        return (self._x, self._y)

    @property
    def group(self) -> PelotonGroup:
        return self._group

    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        self._group.ensure_center_driver()
        while True:
            self._drift_offset()
            self._apply_position()
            yield self._env.timeout(self._update_interval_s)

    def _drift_offset(self) -> None:
        angle = self._rng.uniform(0.0, _TWO_PI)
        step = self._rng.uniform(0.0, self._offset_drift)
        self._offset_x += step * math.cos(angle)
        self._offset_y += step * math.sin(angle)
        self._clamp_offset()

    def _clamp_offset(self) -> None:
        dist = math.hypot(self._offset_x, self._offset_y)
        if dist > self._cohesion_radius and dist > 0.0:
            scale = self._cohesion_radius / dist
            self._offset_x *= scale
            self._offset_y *= scale

    def _apply_position(self) -> None:
        cx, cy = self._group.center
        self._x, self._y = _clamp_position(
            cx + self._offset_x,
            cy + self._offset_y,
            self._area,
        )
        self._bus.set_position(self.bd, (self._x, self._y))


class _MobilityModelABC(ABC):
    """Optional explicit base for peloton / group models."""

    @abstractmethod
    def walk_process(self) -> Generator[simpy.events.Event, None, None]:
        raise NotImplementedError


def _sample_positions(bus: TimedBus, bds: list[str]) -> dict[str, Position]:
    return {bd: bus._positions[bd] for bd in bds}  # noqa: SLF001


def _group_diameter(poses: dict[str, Position]) -> float:
    pts = list(poses.values())
    if len(pts) < 2:
        return 0.0
    max_d = 0.0
    for i, (x0, y0) in enumerate(pts):
        for x1, y1 in pts[i + 1 :]:
            max_d = max(max_d, math.hypot(x1 - x0, y1 - y0))
    return max_d


def _run_random_waypoint_demo(*, seed: int, duration_s: float) -> list[tuple[float, dict[str, Position]]]:
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


def _run_peloton_demo(
    *,
    seed: int,
    duration_s: float,
) -> tuple[list[tuple[float, dict[str, Position]]], float, PelotonMobility]:
    area = 20.0
    cohesion_radius = area * 0.15
    env = simpy.Environment()
    bus = TimedBus(env, radius=2.5, rng=random.Random(seed))
    bds = [f"BB:CC:DD:EE:FF:{i:02X}" for i in range(5)]
    group_rng = random.Random(seed * 97 + 3)
    group = PelotonGroup(
        env,
        area=area,
        speed_min=0.5,
        speed_max=1.5,
        pause_min_s=0.5,
        pause_max_s=1.5,
        rng=group_rng,
        update_interval_s=0.5,
        center=(area / 2.0, area / 2.0),
    )
    spawn_rng = random.Random(seed + 11)
    cx, cy = group.center
    for bd in bds:
        angle = spawn_rng.uniform(0.0, _TWO_PI)
        radius = spawn_rng.uniform(0.0, cohesion_radius * 0.6)
        pos = _clamp_position(
            cx + radius * math.cos(angle),
            cy + radius * math.sin(angle),
            area,
        )
        bus.register(bd, pos, lambda _p, _d: None)

    peloton_ref: PelotonMobility | None = None
    for index, bd in enumerate(bds):
        mobile = PelotonMobility(
            env,
            bus,
            bd,
            area=area,
            speed_min=0.5,
            speed_max=1.5,
            pause_min_s=0.5,
            pause_max_s=1.5,
            rng=random.Random(seed * 10_007 + index),
            update_interval_s=0.5,
            group=group,
            cohesion_radius=cohesion_radius,
        )
        if peloton_ref is None:
            peloton_ref = mobile
        env.process(mobile.walk_process())

    snapshots: list[tuple[float, dict[str, Position]]] = []

    def _sampler() -> Generator[simpy.events.Event, None, None]:
        while True:
            snapshots.append((env.now, _sample_positions(bus, bds)))
            yield env.timeout(0.5)

    env.process(_sampler())
    env.run(until=duration_s)
    assert peloton_ref is not None
    return snapshots, cohesion_radius, peloton_ref


if __name__ == "__main__":
    duration = 6.0
    seed = 42

    traj = _run_random_waypoint_demo(seed=seed, duration_s=duration)
    repeat = _run_random_waypoint_demo(seed=seed, duration_s=duration)
    assert traj == repeat, "same seed must yield identical trajectories"
    print("✅ random waypoint deterministic replay")

    peloton_traj, cohesion_r, peloton_instance = _run_peloton_demo(seed=seed, duration_s=duration)
    peloton_repeat, _, _ = _run_peloton_demo(seed=seed, duration_s=duration)
    assert peloton_traj == peloton_repeat, "peloton replay mismatch"
    print("✅ peloton deterministic replay")

    margin = 0.05
    for _t, poses in peloton_traj:
        diam = _group_diameter(poses)
        assert diam <= 2.0 * cohesion_r + margin, f"diameter {diam} exceeds cohesion"
    print("✅ peloton cohesion (diameter bound)")

    assert isinstance(peloton_instance, MobilityModel)
    print("✅ peloton satisfies MobilityModel protocol")

    print("✅ mobility self-tests passed")
