"""
Shared BlueZ LE L2CAP CoC socket setup.

Used by ``coc_client.py``, ``coc_server.py``, and ``BLEL2CAPTransport`` so every
board (Rubik Pi, Arduino UNO Q, …) runs the **same** bring-up sequence:

  listen : bind(BDADDR_ANY, psm) → BT_MODE_LE_FLOWCTL → BT_SECURITY_LOW → listen
  outbound: bind(BDADDR_ANY, psm=0) → BT_MODE_LE_FLOWCTL → BT_SECURITY_LOW → connect

Security is LOW (no link-layer encryption): BB encrypts everything at the
application layer, so no SMP pairing/bonding is required to open the CoC.
See ``apply_le_flowctl`` for the full rationale and trade-off.
"""

from __future__ import annotations

import errno
import os
import select
import socket
import struct

from config import PSM_BLE, get_local_bd_addr

LE_ADDR_TYPE = int(socket.BDADDR_LE_PUBLIC)


def require_le_coc() -> None:
    if not hasattr(socket, "BDADDR_LE_PUBLIC"):
        raise RuntimeError(
            "LE L2CAP CoC requires socket.BDADDR_LE_PUBLIC (Python 3.14+ / LE L2CAP)"
        )


def addr_type_from_label(label: str) -> int:
    """Map bluetoothctl ``AddressType`` to ``socket.BDADDR_LE_*``."""
    require_le_coc()
    normalized = label.strip().lower()
    if normalized in ("random", "static-random", "rpa", "random-static"):
        return int(socket.BDADDR_LE_RANDOM)
    return int(socket.BDADDR_LE_PUBLIC)


def le_addr_types_to_try(preferred: int | str | None = None) -> list[int]:
    """Candidate addr types for outbound connect (preferred first)."""
    require_le_coc()
    public = int(socket.BDADDR_LE_PUBLIC)
    random = int(socket.BDADDR_LE_RANDOM)
    ordered: list[int] = []
    if preferred is not None:
        if isinstance(preferred, str):
            ordered.append(addr_type_from_label(preferred))
        else:
            ordered.append(int(preferred))
    for candidate in (public, random):
        if candidate not in ordered:
            ordered.append(candidate)
    return ordered


def le_addr(bd_addr: str, *, psm: int, addr_type: int = LE_ADDR_TYPE) -> tuple[str, int, int, int]:
    return (bd_addr.upper(), int(psm), 0, int(addr_type))


def new_socket() -> socket.socket:
    require_le_coc()
    return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)


def apply_le_flowctl(sock: socket.socket) -> None:
    """After LE bind: assert LE_FLOWCTL + LOW security.

    We deliberately use ``BT_SECURITY_LOW`` (no link-layer encryption) rather
    than ``MEDIUM``. Bubble-Blue provides its own confidentiality and integrity
    at the application layer (per-packet AES-256-GCM, X25519 pairwise keys,
    group key, Ed25519 attestations), so BlueZ link encryption is redundant.

    Requiring ``MEDIUM`` would force SMP pairing/bonding on every unicast peer,
    which (a) makes the group mesh depend on manual pre-bonding and (b) is the
    root cause of the connect/disconnect flapping: unbonded peers fail with
    ``EPERM`` and SMP re-pairing between many boards falls back to passkey and
    tears the link down (HCI reason 0x13). ``LOW`` lets the CoC open bare so the
    mesh self-completes as members appear.

    Trade-off: a co-located passive sniffer can observe the cleartext routing
    header (packet type, src/dst, seq, ts). Payloads and Hello private parts
    stay AES-GCM encrypted, and forged/tampered frames are rejected by the GCM
    tag — consistent with BB's "outsider" adversary rows.
    """
    bt_mode = getattr(socket, "BT_MODE", None)
    le_flowctl = getattr(socket, "BT_MODE_LE_FLOWCTL", None)
    if bt_mode is not None and le_flowctl is not None:
        sock.setsockopt(socket.SOL_BLUETOOTH, bt_mode, struct.pack("B", le_flowctl))

    bt_security = getattr(socket, "BT_SECURITY", None)
    sec_low = getattr(socket, "BT_SECURITY_LOW", None)
    if bt_security is not None and sec_low is not None:
        sock.setsockopt(
            socket.SOL_BLUETOOTH, bt_security, struct.pack("BB", sec_low, 0)
        )


def bind_listen(sock: socket.socket, *, psm: int = PSM_BLE, addr_type: int = LE_ADDR_TYPE) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((socket.BDADDR_ANY, int(psm), 0, int(addr_type)))
    apply_le_flowctl(sock)


def bind_outbound(sock: socket.socket, *, addr_type: int = LE_ADDR_TYPE) -> None:
    sock.bind((socket.BDADDR_ANY, 0, 0, int(addr_type)))
    apply_le_flowctl(sock)


def connect_coc(
    sock: socket.socket,
    bd_addr: str,
    *,
    psm: int = PSM_BLE,
    addr_type: int = LE_ADDR_TYPE,
    timeout: float = 30.0,
) -> None:
    """Non-blocking ``connect`` with a hard ``timeout``.

    The socket is switched to non-blocking so ``connect`` returns immediately
    with ``EINPROGRESS`` and the ``select`` below actually bounds the wait; a
    blocking socket would ignore ``timeout`` and could hang for a long time on
    an unreachable/non-connectable peer, stalling the whole dial loop. Blocking
    mode is restored before returning so the recv loop reads normally.
    """
    addr = le_addr(bd_addr, psm=psm, addr_type=addr_type)
    sock.setblocking(False)
    try:
        try:
            sock.connect(addr)
        except OSError as e:
            if e.errno not in (errno.EINPROGRESS, errno.EALREADY):
                raise
            _, writable, exceptional = select.select([], [sock], [sock], timeout)
            if exceptional:
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err:
                    raise OSError(err, os.strerror(err))
            if not writable:
                raise OSError(
                    errno.ETIMEDOUT,
                    f"BLE L2CAP connect to {bd_addr.upper()} timed out "
                    f"after {timeout:g}s",
                )
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err:
                raise OSError(err, os.strerror(err))
    finally:
        sock.setblocking(True)


def open_listener(*, psm: int = PSM_BLE, backlog: int = 10) -> socket.socket:
    """Listening CoC socket (``coc_server`` / ``BLEL2CAPTransport.start``)."""
    sock = new_socket()
    bind_listen(sock, psm=psm)
    sock.listen(backlog)
    return sock


def open_outbound(
    bd_addr: str,
    *,
    psm: int = PSM_BLE,
    addr_type: int = LE_ADDR_TYPE,
    timeout: float = 30.0,
) -> socket.socket:
    """Connected CoC socket (``coc_client`` / outbound dial).

    A failed dial closes its socket at once: left to the garbage collector (the
    raised exception keeps it alive), the kernel keeps the LE connection attempt
    pending, and a few of those fill the controller's connection slots — every
    later dial then fails with "Connection Limit Exceeded".
    """
    sock = new_socket()
    try:
        bind_outbound(sock, addr_type=addr_type)
        connect_coc(sock, bd_addr, psm=psm, addr_type=addr_type, timeout=timeout)
    except BaseException:
        sock.close()
        raise
    return sock


def print_board_info(role: str, *, server: str | None = None) -> None:
    local = get_local_bd_addr()
    msg = f"[{role}] local={local} psm=0x{PSM_BLE:04X} addr_type=LE_PUBLIC"
    if server:
        msg += f" → server={server.upper()}"
    print(msg, flush=True)
