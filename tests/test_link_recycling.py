"""
Link recycling against the kernel L2CAP ident leak (UNO Q, kernel 7.0).

Every received PDU makes the kernel send an LE Flow Control Credit whose ident is
never released; after 254 of them on one ACL the channel stalls. These tests pin
the pieces the workaround rests on without a radio: which kernels recycle, and
that the MGMT Disconnect used to get a fresh ACL is framed and awaited correctly.
"""

from __future__ import annotations

import os
import socket
import struct
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pytest  # noqa: E402

from config import DEFAULT_L2CAP_IDENT_BUDGET, l2cap_ident_budget  # noqa: E402
from src.transport.le_scan import (  # noqa: E402
    MGMT_EV_CMD_COMPLETE,
    MGMT_EV_CMD_STATUS,
    MGMT_OP_DISCONNECT,
    disconnect_params,
    mgmt_disconnect,
)

_ENV = "BUBBLE_BLUE_L2CAP_IDENT_BUDGET"


@pytest.fixture(autouse=True)
def _no_budget_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_ENV, raising=False)


def test_affected_kernel_recycles() -> None:
    assert l2cap_ident_budget("7.0.0-g122c2c22d838") == DEFAULT_L2CAP_IDENT_BUDGET


def test_rubik_kernel_does_not_recycle() -> None:
    assert l2cap_ident_budget("6.8.0-1055-qcom") == 0


def test_env_can_disable_on_a_fixed_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "0")
    assert l2cap_ident_budget("7.0.0") == 0


def test_budget_never_reaches_the_ident_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    # Connection requests draw from the same 254 idents, so a budget at the pool
    # size would stall the link before the recycle fires.
    monkeypatch.setenv(_ENV, "1000")
    assert l2cap_ident_budget("7.0.0") < 254


def test_disconnect_params_little_endian_then_type() -> None:
    assert disconnect_params("11:22:33:44:55:66", 1) == bytes(
        [0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x01]
    )


def _event(code: int, index: int, params: bytes) -> bytes:
    return struct.pack("<HHH", code, index, len(params)) + params


def _complete(index: int, status: int, addr_info: bytes) -> bytes:
    return _event(
        MGMT_EV_CMD_COMPLETE, index, struct.pack("<HB", MGMT_OP_DISCONNECT, status) + addr_info
    )


def test_mgmt_disconnect_sends_command_and_returns_status() -> None:
    ours, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ours.setblocking(False)
    addr = disconnect_params("AA:BB:CC:DD:EE:FF", 1)
    try:
        peer.send(_complete(0, 0x00, addr))
        status = mgmt_disconnect(0, "AA:BB:CC:DD:EE:FF", 1, timeout_s=0.5, sock=ours)
        sent = peer.recv(64)
    finally:
        ours.close()
        peer.close()
    assert status == 0
    assert sent == struct.pack("<HHH", MGMT_OP_DISCONNECT, 0, len(addr)) + addr


def test_mgmt_disconnect_ignores_other_peers_and_adapters() -> None:
    ours, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ours.setblocking(False)
    try:
        peer.send(_complete(1, 0x00, disconnect_params("AA:BB:CC:DD:EE:FF", 1)))
        peer.send(_complete(0, 0x00, disconnect_params("11:22:33:44:55:66", 1)))
        peer.send(_complete(0, 0x0E, disconnect_params("AA:BB:CC:DD:EE:FF", 1)))
        status = mgmt_disconnect(0, "AA:BB:CC:DD:EE:FF", 1, timeout_s=0.5, sock=ours)
    finally:
        ours.close()
        peer.close()
    assert status == 0x0E


def test_mgmt_disconnect_accepts_a_bare_status_event() -> None:
    ours, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ours.setblocking(False)
    try:
        peer.send(_event(MGMT_EV_CMD_STATUS, 0, struct.pack("<HB", MGMT_OP_DISCONNECT, 0x02)))
        status = mgmt_disconnect(0, "AA:BB:CC:DD:EE:FF", 1, timeout_s=0.5, sock=ours)
    finally:
        ours.close()
        peer.close()
    assert status == 0x02


def test_mgmt_disconnect_times_out_to_none() -> None:
    ours, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ours.setblocking(False)
    try:
        assert mgmt_disconnect(0, "AA:BB:CC:DD:EE:FF", 1, timeout_s=0.2, sock=ours) is None
    finally:
        ours.close()
        peer.close()
