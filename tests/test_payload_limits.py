from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config, max_payload  # noqa: E402
from src.forwarding.forwarder import PacketForwarder, PayloadTooLarge  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.packet import BROADCAST_BD_ADDR  # noqa: E402


class _FakeHelloMgr:
    def __init__(self) -> None:
        self.is_relay = False
        self.key_store = MagicMock()
        self.key_store.get_pair_key.return_value = b"\x02" * 32
        _fd, path = tempfile.mkstemp(prefix="bb-payload-test-")
        os.close(_fd)
        self.epoch_store = EpochStore(
            b"\x01" * 32, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01"
        )

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose

    def get_peer_epoch(self, bd_addr: str) -> int:
        _ = bd_addr
        return 0

    def anon_id_for(self, bd_addr: str) -> bytes:
        _ = bd_addr
        return b"\xab" * 8


def _forwarder(transport_kind: str) -> PacketForwarder:
    cfg = replace(
        load_config(),
        group_key=b"\x01" * 32,
        local_bd_addr="AA:BB:CC:DD:EE:01",
        transport_kind=transport_kind,
    )
    return PacketForwarder(
        cfg,
        MagicMock(),
        _FakeHelloMgr(),
        on_message=lambda _s, _t: None,
    )


def test_ble_payload_limits() -> None:
    fwd = _forwarder("ble_l2cap")
    limit = max_payload("ble_l2cap")
    assert limit == 470, limit

    pkt_ok = fwd.build_data_packet(b"x" * 470, BROADCAST_BD_ADDR)
    assert len(pkt_ok) == 512

    try:
        fwd.build_data_packet(b"x" * 471, BROADCAST_BD_ADDR)
        raise AssertionError("expected PayloadTooLarge for 471 B on BLE")
    except PayloadTooLarge as exc:
        assert exc.limit == 470 and exc.actual == 471

    print("✅ BLE: 470 B OK, 471 B raises PayloadTooLarge")


def test_bt_classic_payload_limit() -> None:
    fwd = _forwarder("bt_classic")
    limit = max_payload("bt_classic")
    assert limit == 979, limit

    pkt = fwd.build_data_packet(b"y" * 979, BROADCAST_BD_ADDR)
    assert len(pkt) == 979 + 42

    try:
        fwd.build_data_packet(b"y" * 980, BROADCAST_BD_ADDR)
        raise AssertionError("expected PayloadTooLarge for 980 B on BT Classic")
    except PayloadTooLarge as exc:
        assert exc.limit == 979 and exc.actual == 980

    print("✅ BT Classic: 979 B OK, 980 B raises PayloadTooLarge")


if __name__ == "__main__":
    test_ble_payload_limits()
    test_bt_classic_payload_limit()
    print("\n✅ payload MTU limit tests passed")
