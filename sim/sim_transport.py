from __future__ import annotations

import contextlib
import math
import time
from collections import deque
from typing import Any, Callable

from config import PKT_DATA
from src.security.packet import build_routing_header, parse_routing_header

# Callback invoked on a node when it receives a packet: on_receive(peer_bd, data).
OnReceive = Callable[[str, bytes], None]

Position = tuple[float, float]

DataLogEvent = dict[str, Any]


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
        # PKT_DATA only — excludes Hello/control traffic (see forwarding_sim).
        self.data_unicast_count = 0
        # Passive PKT_DATA propagation trace (see start_data_log / get_data_log).
        self._data_log_active = False
        self._data_log: list[DataLogEvent] = []
        # When set, deliveries queue here instead of recursing (see
        # breadth_first). None means the default synchronous behaviour.
        self._pending: deque[tuple[str, str, bytes]] | None = None

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

    def deliver(self, src: str, dst: str, data: bytes) -> None:
        """
        Deliver ``data`` from ``src`` to ``dst`` if in range, else drop it.

        Counts every attempted unicast. On success, invokes the destination's
        ``on_receive(src, data)`` synchronously.
        """
        s, d = src.upper(), dst.upper()
        in_range = self.in_range(s, d)
        self.unicast_count += 1
        is_data = bool(data) and data[0] == PKT_DATA
        if is_data:
            self.data_unicast_count += 1
        if self._data_log_active and is_data:
            try:
                hdr = parse_routing_header(data)
                self._data_log.append(
                    {
                        "from": s,
                        "to": d,
                        "ttl": hdr["ttl"],
                        "seq": hdr["seq"],
                        "delivered_in_range": in_range,
                    }
                )
            except ValueError:
                pass
        if not in_range:
            return  # out of range → packet lost
        if self._pending is not None:
            self._pending.append((s, d, data))
            return
        self._on_receive[d](s, data)

    @contextlib.contextmanager
    def breadth_first(self, max_events: int = 5_000_000):
        """Propagate one flood level at a time instead of recursing.

        Delivering synchronously means a relay's handler re-emits from inside
        the sender's own call, so a flood explores the graph depth-first: one
        branch is walked to exhaustion before its siblings hear anything. A
        radio does the opposite — every neighbour hears the same transmission at
        once — and the difference is not cosmetic, because duplicate suppression
        locks in whichever copy arrives first. Under depth-first order that can
        be a copy which took a long way round and has little TTL left, so the
        subtree behind it is explored on a smaller budget than it deserves.

        Queueing deliveries and draining FIFO restores level-by-level order:
        everything one hop out is handled before anything two hops out.

        Counting and range checks stay at enqueue time, which is where the
        transmission conceptually happens; only the handler call is deferred.
        """
        if self._pending is not None:
            raise RuntimeError("breadth_first() is not reentrant")
        self._pending = deque()
        try:
            yield
            drained = 0
            while self._pending:
                s, d, data = self._pending.popleft()
                drained += 1
                if drained > max_events:
                    raise RuntimeError(
                        f"breadth-first drain exceeded {max_events} deliveries — "
                        "a forwarding loop would otherwise hang the run"
                    )
                self._on_receive[d](s, data)
        finally:
            self._pending = None

    def reset_data_unicast_count(self) -> None:
        """Zero the PKT_DATA unicast counter (broadcast overhead measurement)."""
        self.data_unicast_count = 0


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

    # PKT_DATA propagation journal (passive trace; wave = ttl_initial - ttl).
    bus.start_data_log()
    ts_ms = time.time_ns() // 1_000_000
    pkt = build_routing_header(PKT_DATA, A, B, ttl=3, seq=7, ts_ms=ts_ms) + bytes(16)
    bus.deliver(A, B, pkt)
    bus.deliver(A, C, pkt)  # out of range on line A—B—C
    log = bus.get_data_log()
    assert len(log) == 2, log
    assert log[0] == {
        "from": A,
        "to": B,
        "ttl": 3,
        "seq": 7,
        "delivered_in_range": True,
    }, log[0]
    assert log[1]["from"] == A and log[1]["to"] == C
    assert log[1]["ttl"] == 3 and log[1]["seq"] == 7
    assert log[1]["delivered_in_range"] is False
    bus.stop_data_log()
    bus.deliver(B, C, pkt)
    assert len(bus.get_data_log()) == 2, "log must not grow after stop_data_log()"
    print("✅ PKT_DATA propagation journal: fields and delivered_in_range OK")

    print("\n✅ All sim_transport self-tests passed")
