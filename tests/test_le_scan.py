from __future__ import annotations

import os
import socket
import struct
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.control.presence_scanner import PresenceScanner  # noqa: E402
from src.transport.discovery import ScanDeviceRecord  # noqa: E402
from src.transport.le_scan import (  # noqa: E402
    MGMT_EV_DEVICE_FOUND,
    hci_index_from_interface,
    merge_device_found,
    mgmt_scan_records,
    parse_device_found,
    parse_eir_manufacturer,
    parse_mgmt_event,
    records_from_events,
)

# BB beacon EIR forms.
_BB_MFG_ONLY = bytes([0x06, 0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x01])
_FLAGS_AD = bytes([0x02, 0x01, 0x06])
_BB_EIR_WITH_FLAGS = _FLAGS_AD + _BB_MFG_ONLY
# A non-BB manufacturer AD (Apple, company 0x004C).
_APPLE_EIR = _FLAGS_AD + bytes([0x05, 0xFF, 0x4C, 0x00, 0x02, 0x15])


def _addr_wire(bd: str) -> bytes:
    parts = [int(x, 16) for x in bd.split(":")]
    return bytes(reversed(parts))


def _device_found_params(bd: str, addr_type: int, rssi: int, eir: bytes) -> bytes:
    return (
        _addr_wire(bd)
        + bytes([addr_type & 0xFF, rssi & 0xFF])
        + struct.pack("<I", 0)
        + struct.pack("<H", len(eir))
        + eir
    )


def _device_found_packet(index: int, bd: str, addr_type: int, rssi: int, eir: bytes) -> bytes:
    params = _device_found_params(bd, addr_type, rssi, eir)
    return struct.pack("<HHH", MGMT_EV_DEVICE_FOUND, index, len(params)) + params


def test_hci_index_from_interface() -> None:
    assert hci_index_from_interface("hci0") == 0
    assert hci_index_from_interface("hci3") == 3
    assert hci_index_from_interface(2) == 2


def test_parse_eir_manufacturer_mfg_only() -> None:
    mfg = parse_eir_manufacturer(_BB_MFG_ONLY)
    assert mfg == {0xFFFF: b"BB\x01"}


def test_parse_eir_manufacturer_skips_flags() -> None:
    mfg = parse_eir_manufacturer(_BB_EIR_WITH_FLAGS)
    assert mfg == {0xFFFF: b"BB\x01"}


def test_parse_eir_manufacturer_truncated_is_safe() -> None:
    # Declares length 6 but only 3 bytes follow: must not raise.
    assert parse_eir_manufacturer(bytes([0x06, 0xFF, 0xFF])) == {}


def test_parse_device_found_reverses_address() -> None:
    params = _device_found_params("11:22:33:44:55:66", 1, -30, _BB_MFG_ONLY)
    df = parse_device_found(params)
    assert df is not None
    assert df.bd_addr == "11:22:33:44:55:66"
    assert df.addr_type == 1
    assert df.rssi == -30
    assert df.eir == _BB_MFG_ONLY


def test_parse_device_found_rejects_short() -> None:
    assert parse_device_found(b"\x00\x01") is None


def test_merge_device_found_bb_hit_sets_addr_type() -> None:
    records: dict[str, ScanDeviceRecord] = {}
    assert merge_device_found(records, _device_found_params("AA:BB:CC:DD:EE:FF", 2, -40, _BB_EIR_WITH_FLAGS))
    rec = records["AA:BB:CC:DD:EE:FF"]
    assert rec.manufacturer_data == {0xFFFF: b"BB\x01"}
    assert rec.addr_type == "random"


def test_merge_device_found_ignores_non_bb() -> None:
    records: dict[str, ScanDeviceRecord] = {}
    assert not merge_device_found(records, _device_found_params("11:22:33:44:55:66", 1, -50, _APPLE_EIR))
    assert records == {}


def test_parse_mgmt_event_roundtrip() -> None:
    pkt = _device_found_packet(0, "11:22:33:44:55:66", 1, -30, _BB_MFG_ONLY)
    ev = parse_mgmt_event(pkt)
    assert ev is not None
    assert ev.code == MGMT_EV_DEVICE_FOUND
    assert ev.index == 0


def test_records_from_events_filters_index_and_non_bb() -> None:
    packets = [
        _device_found_packet(0, "11:22:33:44:55:66", 1, -30, _BB_EIR_WITH_FLAGS),
        _device_found_packet(0, "AA:BB:CC:DD:EE:01", 1, -60, _APPLE_EIR),
        _device_found_packet(1, "99:99:99:99:99:99", 1, -30, _BB_EIR_WITH_FLAGS),  # other adapter
    ]
    records = records_from_events(packets, index=0)
    assert set(records) == {"11:22:33:44:55:66"}
    assert records["11:22:33:44:55:66"].addr_type == "public"


def test_mgmt_scan_records_over_socketpair() -> None:
    """Drive the socket loop with a DGRAM socketpair standing in for the MGMT socket."""
    ours, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ours.setblocking(False)
    try:
        peer.send(_device_found_packet(0, "11:22:33:44:55:66", 1, -30, _BB_EIR_WITH_FLAGS))
        peer.send(_device_found_packet(0, "AA:BB:CC:DD:EE:01", 1, -60, _APPLE_EIR))
        records = mgmt_scan_records(0, 0.3, sock=ours)
    finally:
        ours.close()
        peer.close()
    assert set(records) == {"11:22:33:44:55:66"}


def test_presence_scanner_records_provider_skips_info() -> None:
    """With a records_provider the scanner must not touch bluetoothctl info/paired."""
    info_calls: list[str] = []
    paired_calls: list[int] = []
    seen: list[tuple[str, str]] = []

    def provider(_window_s: float) -> dict[str, ScanDeviceRecord]:
        return {
            "11:22:33:44:55:66": ScanDeviceRecord(
                bd_addr="11:22:33:44:55:66",
                manufacturer_data={0xFFFF: b"BB\x01"},
                addr_type="public",
            )
        }

    scanner = PresenceScanner(
        scan_window_s=0.1,
        quiet=True,
        on_candidate=lambda bd, addr_type, _ts: seen.append((bd, addr_type)),
        info_runner=lambda bd: info_calls.append(bd) or "",
        paired_runner=lambda: paired_calls.append(1) or "",
        records_provider=provider,
    )
    found = scanner.scan_once(now=1000.0)
    assert [f.bd_addr for f in found] == ["11:22:33:44:55:66"]
    assert seen == [("11:22:33:44:55:66", "public")]
    assert info_calls == []
    assert paired_calls == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"✅ {name}")
