from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from src.transport.base import ManagedTransport, OnReceive, OnPeerEvent

if TYPE_CHECKING:
    pass


def make_transport(
    kind: str,
    *,
    on_receive: OnReceive | None = None,
    interface: str = "hci0",
    quiet: bool = False,
    allowed_peers: frozenset[str] | None = None,
    on_peer_connected: OnPeerEvent | None = None,
    on_peer_disconnected: OnPeerEvent | None = None,
) -> ManagedTransport:
    """
    Construct a hardware transport by kind.

    ``bt_classic`` → L2CAPTransport (default, Linux/BlueZ BR/EDR).
    ``ble_l2cap``  → BLEL2CAPTransport (lazy import; LE stack not required otherwise).
    """
    k = kind.strip().lower()
    if k == "bt_classic":
        from src.transport.l2cap import L2CAPTransport

        return L2CAPTransport(
            on_receive=on_receive,
            interface=interface,
            quiet=quiet,
            allowed_peers=allowed_peers,
            on_peer_connected=on_peer_connected,
            on_peer_disconnected=on_peer_disconnected,
        )

    if k == "ble_l2cap":
        try:
            from src.transport.ble_l2cap import BLEL2CAPTransport
        except (ImportError, RuntimeError) as exc:
            raise RuntimeError(
                "BLE L2CAP transport (ble_l2cap) is not available on this Python "
                "build — set BUBBLE_BLUE_TRANSPORT=bt_classic or use Python 3.14+ "
                "with LE L2CAP socket support (socket.BDADDR_LE_PUBLIC)."
            ) from exc
        return BLEL2CAPTransport(
            on_receive=on_receive,
            interface=interface,
            quiet=quiet,
            allowed_peers=allowed_peers,
            on_peer_connected=on_peer_connected,
            on_peer_disconnected=on_peer_disconnected,
        )

    raise ValueError(
        f"unknown transport_kind {kind!r} (expected 'bt_classic' or 'ble_l2cap')"
    )
