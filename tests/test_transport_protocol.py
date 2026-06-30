from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.base import ManagedTransport, Transport  # noqa: E402
from src.transport.factory import make_transport  # noqa: E402
from src.transport.l2cap import L2CAPTransport  # noqa: E402
from sim.sim_transport import SimBus, SimTransport  # noqa: E402


def test_l2cap_satisfies_transport_protocol() -> None:
    received: list[tuple[str, bytes]] = []

    def on_rx(peer: str, data: bytes) -> None:
        received.append((peer, data))

    transport = L2CAPTransport(on_receive=on_rx, quiet=True)
    assert isinstance(transport, Transport)
    assert isinstance(transport, ManagedTransport)
    assert transport.connections() == []
    assert callable(transport.start)
    assert callable(transport.connect)
    transport.on_receive("AA:BB:CC:DD:EE:02", b"\x01test")
    assert received == [("AA:BB:CC:DD:EE:02", b"\x01test")]
    print("✅ L2CAPTransport satisfies Transport + ManagedTransport")


def test_sim_transport_satisfies_transport_protocol() -> None:
    bus = SimBus(radius=1.0)
    a = "AA:AA:AA:AA:AA:AA"
    b = "BB:BB:BB:BB:BB:BB"
    ta: SimTransport = bus.register(a, (0.0, 0.0), lambda _p, _d: None)
    received_b: list[tuple[str, bytes]] = []
    bus.register(b, (1.0, 0.0), lambda peer, data: received_b.append((peer, data)))

    assert isinstance(ta, Transport)
    assert not isinstance(ta, ManagedTransport)
    assert ta.connections() == [b]
    ta.send(b, b"probe")
    assert received_b == [(a, b"probe")]
    print("✅ SimTransport satisfies Transport (not ManagedTransport)")


def test_make_transport_bt_classic() -> None:
    t = make_transport("bt_classic", quiet=True)
    assert isinstance(t, L2CAPTransport)
    assert isinstance(t, ManagedTransport)
    print("✅ make_transport(bt_classic) → L2CAPTransport")


def test_make_transport_ble_unavailable() -> None:
    try:
        make_transport("ble_l2cap", quiet=True)
        raise AssertionError("expected RuntimeError for missing ble_l2cap")
    except RuntimeError as exc:
        if "ble_l2cap" not in str(exc).lower():
            raise AssertionError(f"unexpected error: {exc}") from exc
    print("✅ make_transport(ble_l2cap) raises clearly when module missing")


if __name__ == "__main__":
    test_l2cap_satisfies_transport_protocol()
    test_sim_transport_satisfies_transport_protocol()
    test_make_transport_bt_classic()
    test_make_transport_ble_unavailable()
    print("\n✅ transport protocol tests passed")
