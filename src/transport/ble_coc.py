"""
Shared BlueZ LE L2CAP CoC socket setup.

Used by ``coc_client.py``, ``coc_server.py``, and ``BLEL2CAPTransport`` so every
board (Rubik Pi, Arduino UNO Q, …) runs the **same** bring-up sequence:

  listen : bind(BDADDR_ANY, psm) → BT_MODE_LE_FLOWCTL → BT_SECURITY → listen
  outbound: bind(BDADDR_ANY, psm=0) → BT_MODE_LE_FLOWCTL → BT_SECURITY → connect
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


def le_addr(bd_addr: str, *, psm: int, addr_type: int = LE_ADDR_TYPE) -> tuple[str, int, int, int]:
    return (bd_addr.upper(), int(psm), 0, int(addr_type))


def new_socket() -> socket.socket:
    require_le_coc()
    return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)


def apply_le_flowctl(sock: socket.socket) -> None:
    """After LE bind: assert LE_FLOWCTL + MEDIUM security (matches coc_* scripts)."""
    bt_mode = getattr(socket, "BT_MODE", None)
    le_flowctl = getattr(socket, "BT_MODE_LE_FLOWCTL", None)
    if bt_mode is not None and le_flowctl is not None:
        sock.setsockopt(socket.SOL_BLUETOOTH, bt_mode, struct.pack("B", le_flowctl))

    bt_security = getattr(socket, "BT_SECURITY", None)
    sec_medium = getattr(socket, "BT_SECURITY_MEDIUM", None)
    if bt_security is not None and sec_medium is not None:
        sock.setsockopt(
            socket.SOL_BLUETOOTH, bt_security, struct.pack("BB", sec_medium, 0)
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
    """``connect`` with ``EINPROGRESS`` (115) handling — common on BlueZ LE."""
    addr = le_addr(bd_addr, psm=psm, addr_type=addr_type)
    try:
        sock.connect(addr)
        return
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
            f"BLE L2CAP connect to {bd_addr.upper()} timed out after {timeout:g}s",
        )
    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if err:
        raise OSError(err, os.strerror(err))


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
    """Connected CoC socket (``coc_client`` / outbound dial)."""
    sock = new_socket()
    bind_outbound(sock, addr_type=addr_type)
    connect_coc(sock, bd_addr, psm=psm, addr_type=addr_type, timeout=timeout)
    return sock


def print_board_info(role: str, *, server: str | None = None) -> None:
    local = get_local_bd_addr()
    msg = f"[{role}] local={local} psm=0x{PSM_BLE:04X} addr_type=LE_PUBLIC"
    if server:
        msg += f" → server={server.upper()}"
    print(msg, flush=True)
