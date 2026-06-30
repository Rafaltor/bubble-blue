from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

# Inbound packet hook: (ingress_peer_bd, wire_bytes).
OnReceive = Callable[[str, bytes], None]
OnPeerEvent = Callable[[str], None]


@runtime_checkable
class Transport(Protocol):
    """
    Minimal transport surface used by HelloManager and PacketForwarder.

    SimTransport implements only this subset (no listen/dial lifecycle).
  Hardware transports implement ManagedTransport below.
    """

    on_receive: OnReceive

    def connections(self) -> list[str]:
        """Currently connected peer BD addresses (L2CAP links or sim neighbors)."""
        ...

    def send(self, bd_addr: str, data: bytes) -> None:
        """Unicast ``data`` to ``bd_addr`` on an established link."""
        ...


@runtime_checkable
class ManagedTransport(Transport, Protocol):
    """
    Full hardware transport: listen, dial, and peer up/down callbacks.

    L2CAPTransport (BT Classic) and future BLEL2CAPTransport implement this.
    """

    on_peer_connected: OnPeerEvent | None
    on_peer_disconnected: OnPeerEvent | None

    def start(self) -> None:
        """Begin accepting inbound connections (idempotent)."""
        ...

    def connect(self, bd_addr: str) -> None:
        """Initiate or ensure an outbound link to ``bd_addr`` (if applicable)."""
        ...
