"""
A board whose controller cannot dial while peripheral must never be dialled.

On the UNO Q (WCN3988) the kernel refuses to start an LE connection while any
link has it as peripheral. Once link recycling made links drop and come back,
the UNO Qs that happened to accept first could never redial the rest, and the
mesh fell apart ten minutes in. These pin the rule that keeps them central.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import (  # noqa: E402
    LINK_ROLE_ANY,
    LINK_ROLE_CENTRAL,
    LINK_ROLE_PERIPHERAL,
    link_role,
)
from src.api.bb_api import BBNode  # noqa: E402
from src.transport.advertising import LEAdvertiser  # noqa: E402
from src.transport.discovery import ScanDeviceRecord  # noqa: E402
from src.transport.le_scan import merge_device_found  # noqa: E402


def _sysfs(tmp_path, compatible: bytes) -> str:
    node = tmp_path / "hci0" / "device" / "of_node"
    node.mkdir(parents=True)
    (node / "compatible").write_bytes(compatible)
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _no_role_override(monkeypatch):
    monkeypatch.delenv("BUBBLE_BLUE_LINK_ROLE", raising=False)


def test_uno_q_controller_is_central_only(tmp_path) -> None:
    assert link_role("hci0", sysfs=_sysfs(tmp_path, b"qcom,wcn3988-bt\0")) == LINK_ROLE_CENTRAL


def test_other_controllers_take_both_roles(tmp_path) -> None:
    assert link_role("hci0", sysfs=_sysfs(tmp_path, b"brcm,bcm4345c5\0")) == LINK_ROLE_ANY
    assert link_role("hci0", sysfs=str(tmp_path / "missing")) == LINK_ROLE_ANY


def test_role_can_be_forced(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("BUBBLE_BLUE_LINK_ROLE", "peripheral")
    assert link_role("hci0", sysfs=_sysfs(tmp_path, b"qcom,wcn3988-bt\0")) == LINK_ROLE_PERIPHERAL


def _run_recorder(calls):
    def run(_idx, cmd):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    return run


def test_central_only_board_advertises_non_connectable() -> None:
    calls: list[str] = []
    adv = LEAdvertiser(interface=0, quiet=True, btmgmt_runner=_run_recorder(calls),
                       connectable=False)
    adv.start()
    adv.stop()
    adds = [c for c in calls if c.startswith("add-adv")]
    assert adds and all(" -c " not in f" {c} " for c in adds)


def _device_found(bd: str, flags: int) -> bytes:
    eir = bytes([0x06, 0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x01])
    addr = bytes(reversed([int(x, 16) for x in bd.split(":")]))
    return addr + bytes([1, 0xD0]) + struct.pack("<I", flags) + struct.pack("<H", len(eir)) + eir


def test_scanner_records_whether_an_advert_is_connectable() -> None:
    records: dict[str, ScanDeviceRecord] = {}
    merge_device_found(records, _device_found("AA:BB:CC:DD:EE:01", 0x00))
    merge_device_found(records, _device_found("AA:BB:CC:DD:EE:02", 0x04))
    assert records["AA:BB:CC:DD:EE:01"].connectable is True
    assert records["AA:BB:CC:DD:EE:02"].connectable is False


_LOCAL = bytes.fromhex("0100000000000000")
_SCREEN = bytes.fromhex("0200000000000000")
_UNO = bytes.fromhex("0300000000000000")
_SCREEN_BD = "AA:BB:CC:DD:EE:02"
_UNO_BD = "AA:BB:CC:DD:EE:03"


class _Hello:
    is_connectionless = True
    anon_id = _LOCAL

    def __init__(self, plan: dict) -> None:
        self._plan = plan

    def heard_anon_ids(self) -> frozenset[bytes]:
        return frozenset({_SCREEN, _UNO})

    def connectionless_link_plan(self) -> dict:
        return self._plan


def _node(role: str, plan: dict | None = None) -> BBNode:
    node = BBNode(quiet=True)
    node._hello_mgr = _Hello(plan or {"sym": set(), "relays": set(), "am_relay": False})
    node._link_role = role
    node._presence_addr = {_SCREEN.hex(): (_SCREEN_BD, "public"), _UNO.hex(): (_UNO_BD, "public")}
    node._presence_connectable = {_SCREEN.hex(): True, _UNO.hex(): False}
    return node


def test_nobody_dials_a_non_connectable_peer() -> None:
    assert _node(LINK_ROLE_ANY)._backbone_dial_targets() == {_SCREEN_BD}


def test_leaf_does_not_dial_a_central_only_dominator() -> None:
    # The UNO Q relay dials the screen instead; a dial here would only time out.
    plan = {"sym": {_UNO}, "relays": {_UNO}, "am_relay": False}
    assert _node(LINK_ROLE_ANY, plan)._backbone_dial_targets() == set()


def test_central_only_board_dials_everyone_it_can_reach() -> None:
    # Even as a relay whose plan would leave the edge to the other side.
    plan = {"sym": {_SCREEN}, "relays": {_LOCAL}, "am_relay": True}
    assert _node(LINK_ROLE_CENTRAL, plan)._backbone_dial_targets() == {_SCREEN_BD}


def test_peripheral_board_dials_nobody() -> None:
    assert _node(LINK_ROLE_PERIPHERAL)._backbone_dial_targets() == set()
