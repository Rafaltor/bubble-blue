from __future__ import annotations

import math
from typing import Callable

# Callback invoked on a node when it receives a packet: on_receive(peer_bd, data).
OnReceive = Callable[[str, bytes], None]

Position = tuple[float, float]


class SimTransport:
    """
    Per-node façade injected in place of L2CAPTransport.

    Exposes exactly the surface the real HelloManager / PacketForwarder use:
      - connections() -> list[str]
      - send(bd_addr, data)
    plus an ``on_receive`` hook the bus calls to deliver inbound packets. The
    wiring of ``on_receive`` to HelloManager.on_receive / forwarder.handle is done
    by the simulation engine, not here.
    """

    def __init__(self, bus: SimBus, bd_addr: str, on_receive: OnReceive) -> None:
        self.bus = bus
        self.bd = bd_addr.upper()
        self.on_receive: OnReceive = on_receive
        self.sent_count = 0

    def connections(self) -> list[str]:
        """BD addresses currently in radio range — the simulated 'L2CAP peers'."""
        return [bd.upper() for bd in self.bus.neighbors(self.bd)]

    def send(self, bd_addr: str, data: bytes) -> None:
        """Unicast ``data`` to ``bd_addr`` if in range (else silently dropped)."""
        self.sent_count += 1
        self.bus.deliver(self.bd, bd_addr.upper(), bytes(data))


class SimBus:
    """
    Shared medium routing packets by 2D geometry (unit-disk radio model).

    Connectivity assumption — SYMMETRIC links: if A is within radius R of B then
    B is within R of A (true for the Euclidean unit-disk model used here). The
    set of nodes within R of a node is the ground-truth 1-hop topology.

    Delivery is synchronous, immediate and deterministic: no threads, no sleeps,
    no randomness. Positions and R are supplied entirely from the outside.
    """

    def __init__(self, radius: float = 1.0) -> None:
        self.radius = float(radius)
        self._positions: dict[str, Position] = {}
        self._transports: dict[str, SimTransport] = {}
        self._on_receive: dict[str, OnReceive] = {}
        # Metrics: total unicast deliveries attempted on the bus.
        self.unicast_count = 0

    def register(self, bd_addr: str, position: Position, on_receive: OnReceive) -> SimTransport:
        """Add a node at ``position`` and return its SimTransport façade."""
        bd = bd_addr.upper()
        transport = SimTransport(self, bd, on_receive)
        self._positions[bd] = (float(position[0]), float(position[1]))
        self._transports[bd] = transport
        self._on_receive[bd] = on_receive
        return transport

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

    def deliver(self, src: str, dst: str, data: bytes) -> None:
        """
        Deliver ``data`` from ``src`` to ``dst`` if in range, else drop it.

        Counts every attempted unicast. On success, invokes the destination's
        ``on_receive(src, data)`` synchronously.
        """
        s, d = src.upper(), dst.upper()
        self.unicast_count += 1
        if not self.in_range(s, d):
            return  # out of range → packet lost
        self._on_receive[d](s, data)


if __name__ == "__main__":
    # Line A — B — C: positions x=0,1,2 with R=1.0 → A↔B, B↔C, but NOT A↔C.
    bus = SimBus(radius=1.0)
    received: list[tuple[str, str, bytes]] = []

    def _mk(name: str):
        def _cb(peer: str, data: bytes) -> None:
            received.append((name, peer, data))
        return _cb

    A, B, C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"
    ta = bus.register(A, (0.0, 0.0), _mk("A"))
    tb = bus.register(B, (1.0, 0.0), _mk("B"))
    tc = bus.register(C, (2.0, 0.0), _mk("C"))

    assert bus.neighbors(A) == [B], bus.neighbors(A)
    assert bus.neighbors(B) == [A, C], bus.neighbors(B)
    assert bus.neighbors(C) == [B], bus.neighbors(C)
    print("✅ line topology neighbors: A→[B], B→[A,C], C→[B]")

    # connections() mirrors neighbors() in uppercase.
    assert ta.connections() == [B]
    assert tb.connections() == [A, C]
    print("✅ SimTransport.connections matches range")

    # In-range unicast is delivered; out-of-range is dropped.
    tb.send(C, b"hi")
    assert received == [("C", B, b"hi")], received
    received.clear()
    ta.send(C, b"nope")  # A cannot reach C directly
    assert received == [], received
    assert bus.unicast_count == 2  # both attempts counted, one delivered
    print("✅ in-range delivered, out-of-range dropped, unicasts counted")

    print("\n✅ All sim_transport self-tests passed")
