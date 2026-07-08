"""
TimedBus — event-driven counterpart to ``SimBus``.

Same validated unit-disk geometry (positions, neighbors, in_range) as
``sim.sim_transport.SimBus``, but delivery is scheduled on a SimPy clock:
after ``tx_latency_s`` the packet is delivered only if the pair is still in
range and a seeded loss draw succeeds. Positions may move during the latency
window, which models mobility more realistically than synchronous SimBus.
"""

from __future__ import annotations

import math
import random
from collections.abc import Generator
from typing import Any, Callable

import simpy

from config import PKT_DATA
from src.security.packet import parse_routing_header

OnReceive = Callable[[str, bytes], None]

Position = tuple[float, float]

DataLogEvent = dict[str, Any]


class TimedBus:
    """
    Shared medium with SimBus geometry; delivery deferred via SimPy.

    Connectivity — SYMMETRIC unit-disk links (identical to ``SimBus``).
    Delivery — asynchronous: ``deliver()`` schedules a process that waits
    ``tx_latency_s``, then checks range and optional packet loss before calling
    the destination ``on_receive``.
    """

    def __init__(
        self,
        env: simpy.Environment,
        radius: float,
        *,
        tx_latency_s: float = 0.003,
        loss_prob: float = 0.0,
        rng: random.Random | None = None,
    ) -> None:
        self._env = env
        self.radius = float(radius)
        self._tx_latency_s = max(0.0, float(tx_latency_s))
        self._loss_prob = min(1.0, max(0.0, float(loss_prob)))
        self._rng = rng if rng is not None else random.Random(0)
        self._positions: dict[str, Position] = {}
        self._on_receive: dict[str, OnReceive] = {}
        self.unicast_count = 0
        self.data_unicast_count = 0
        self._data_log_active = False
        self._data_log: list[DataLogEvent] = []

    def register(self, bd_addr: str, position: Position, on_receive: OnReceive) -> None:
        """Add a node at ``position`` with an inbound callback."""
        bd = bd_addr.upper()
        self._positions[bd] = (float(position[0]), float(position[1]))
        self._on_receive[bd] = on_receive

    def set_position(self, bd_addr: str, position: Position) -> None:
        """Move a node to an absolute position."""
        bd = bd_addr.upper()
        if bd not in self._positions:
            raise KeyError(f"unknown node: {bd}")
        self._positions[bd] = (float(position[0]), float(position[1]))

    def move(self, bd_addr: str, dx: float, dy: float) -> None:
        """Translate a node by (dx, dy)."""
        bd = bd_addr.upper()
        x, y = self._positions[bd]
        self._positions[bd] = (x + float(dx), y + float(dy))

    def _distance(self, a: str, b: str) -> float:
        ax, ay = self._positions[a]
        bx, by = self._positions[b]
        return math.hypot(ax - bx, ay - by)

    def in_range(self, src: str, dst: str) -> bool:
        """True iff ``dst`` is within radio range R of ``src`` (symmetric)."""
        s, d = src.upper(), dst.upper()
        if s == d or s not in self._positions or d not in self._positions:
            return False
        return self._distance(s, d) <= self.radius

    def neighbors(self, bd_addr: str) -> list[str]:
        """Ground-truth 1-hop neighbors: nodes at Euclidean distance <= R (not self)."""
        bd = bd_addr.upper()
        if bd not in self._positions:
            raise KeyError(f"unknown node: {bd}")
        return sorted(
            other
            for other in self._positions
            if other != bd and self._distance(bd, other) <= self.radius
        )

    def start_data_log(self) -> None:
        """Clear the journal and begin recording PKT_DATA deliver() events."""
        self._data_log = []
        self._data_log_active = True

    def stop_data_log(self) -> None:
        """Stop recording; existing journal remains readable via get_data_log()."""
        self._data_log_active = False

    def get_data_log(self) -> list[DataLogEvent]:
        """Copy of recorded PKT_DATA propagation events (passive trace only)."""
        return list(self._data_log)

    def reset_data_unicast_count(self) -> None:
        """Zero the PKT_DATA unicast counter (broadcast overhead measurement)."""
        self.data_unicast_count = 0

    def deliver(self, src: str, dst: str, data: bytes) -> None:
        """
        Schedule delivery of ``data`` from ``src`` to ``dst`` after ``tx_latency_s``.

        Counts the unicast attempt immediately (same as ``SimBus``). The
        destination callback runs only after the latency elapses, and only if
        the pair is still in range and the loss draw succeeds.
        """
        s, d = src.upper(), dst.upper()
        self.unicast_count += 1
        payload = bytes(data)
        is_data = bool(payload) and payload[0] == PKT_DATA
        if is_data:
            self.data_unicast_count += 1
        self._env.process(self._delayed_deliver(s, d, payload, is_data))

    def _delayed_deliver(
        self,
        src: str,
        dst: str,
        data: bytes,
        is_data: bool,
    ) -> Generator[simpy.events.Event, None, None]:
        yield self._env.timeout(self._tx_latency_s)
        in_range = self.in_range(src, dst)
        if self._data_log_active and is_data:
            try:
                hdr = parse_routing_header(data)
                self._data_log.append(
                    {
                        "from": src,
                        "to": dst,
                        "ttl": hdr["ttl"],
                        "seq": hdr["seq"],
                        "delivered_in_range": in_range,
                    }
                )
            except ValueError:
                pass
        if not in_range:
            return
        if self._rng.random() < self._loss_prob:
            return
        self._on_receive[dst](src, data)


if __name__ == "__main__":
    env = simpy.Environment()
    tx_latency_s = 0.05
    bus = TimedBus(env, radius=1.0, tx_latency_s=tx_latency_s, rng=random.Random(7))

    received: list[tuple[float, str, str, bytes]] = []

    def _mk(name: str) -> OnReceive:
        def _cb(peer: str, data: bytes) -> None:
            received.append((env.now, name, peer, data))

        return _cb

    a = "AA:AA:AA:AA:AA:AA"
    b = "BB:BB:BB:BB:BB:BB"
    c = "CC:CC:CC:CC:CC:CC"
    bus.register(a, (0.0, 0.0), _mk("A"))
    bus.register(b, (1.0, 0.0), _mk("B"))
    bus.register(c, (2.0, 0.0), _mk("C"))

    assert bus.neighbors(a) == [b]
    assert bus.neighbors(b) == [a, c]
    print("✅ line topology neighbors OK")

    def _run() -> Generator[simpy.events.Event, None, None]:
        assert env.now == 0.0
        bus.deliver(a, b, b"delayed")
        yield env.timeout(tx_latency_s * 0.5)
        assert received == [], f"packet arrived too early at t={env.now}"
        yield env.timeout(tx_latency_s * 0.5 + 1e-9)
        assert len(received) == 1, received
        t_recv, who, peer, payload = received[0]
        assert who == "B" and peer == a and payload == b"delayed"
        assert t_recv >= tx_latency_s, f"expected t>={tx_latency_s}, got {t_recv}"
        print(f"✅ packet delivered at t={t_recv:.4f}s (latency={tx_latency_s}s)")

    env.process(_run())
    env.run()
    print("\n✅ All timed_bus self-tests passed")
