from __future__ import annotations

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.control.presence_scanner import PresenceScanner, is_bb_beacon_record  # noqa: E402
from src.transport.advertising import BB_BEACON_COMPANY_ID, BB_BEACON_MAGIC, match_bb_beacon_manufacturer_data  # noqa: E402
from src.transport.discovery import (  # noqa: E402
    _strip_ctl,
    new_devices_from_scan_output,
    parse_bluetoothctl_info,
    parse_bluetoothctl_scan_output,
    parse_manufacturer_data_hex,
)

SCAN_FIXTURE = """
[NEW] Device 11:22:33:44:55:66 ubuntu-le
[CHG] Device 11:22:33:44:55:66 RSSI: -55 TXPower: 0x0000 (0)
[CHG] Device 11:22:33:44:55:66 ManufacturerData Key: 0xffff (65535)
[CHG] Device 11:22:33:44:55:66 ManufacturerData Value: 424201
[NEW] Device AA:BB:CC:DD:EE:01 other-phone
[CHG] Device AA:BB:CC:DD:EE:01 ManufacturerData Key: 0x004c (76)
[CHG] Device AA:BB:CC:DD:EE:01 ManufacturerData Value: 0215ac04000c30
[CHG] Device 11:22:33:44:55:66 ManufacturerData: 0xffff 424201
[CHG] Device CC:CC:CC:CC:CC:03 bad-mfg
[CHG] Device CC:CC:CC:CC:CC:03 ManufacturerData Value: 42420
garbled line without device {{{{
[NEW] Device BB:BB:BB:BB:BB:02 bb-inline
[CHG] Device BB:BB:BB:BB:BB:02 ManufacturerData: 0xffff, ffff424201
"""

INFO_PUBLIC_FIXTURE = """
Device 11:22:33:44:55:66 (public)
    Name: ubuntu-le
    Alias: ubuntu-le
    Address: 11:22:33:44:55:66
    AddressType: public
    Paired: no
    Bonded: no
    Trusted: no
    Blocked: no
    Connected: no
    LegacyPairing: no
    ManufacturerData Key: 0xffff (65535)
    ManufacturerData Value: 424201
"""

INFO_RANDOM_FIXTURE = """
Device BB:BB:BB:BB:BB:02 (random)
    Name: bb-inline
    Address: BB:BB:BB:BB:BB:02
    AddressType: random
    ManufacturerData Key: 0xffff (65535)
    ManufacturerData Value: ffff424201
"""

# TODO: recaler sur capture board si le format bluetoothctl diffère.
INFO_MULTILINE_HEX_FIXTURE = """
Device 14:B5:CD:E2:12:4F (public)
    Name: rubik2
    Address: 14:B5:CD:E2:12:4F
    AddressType: public
    Paired: yes
    Bonded: yes
    ManufacturerData Key: 0xffff (65535)
    ManufacturerData Value:
      42 42 01                                         BB.
"""

CACHED_DEVICE_SCAN_FIXTURE = """
[CHG] Device 14:B5:CD:E2:12:4F RSSI: -60
"""

# Verbatim excerpt from ``bluetoothctl --timeout 6 scan le`` (ANSI escapes literal).
REAL_SCAN_CAPTURE_RAW = (
    "[\x1b[0;93mCHG\x1b[0m] Device 44:C8:3E:FD:9D:A1 RSSI: 0xffffffae (-82)\n"
    "[\x1b[0;93mCHG\x1b[0m] Device 44:C8:3E:FD:9D:A1 ManufacturerData.Key: 0x0075 (117)\n"
    "[\x1b[0;93mCHG\x1b[0m] Device 44:C8:3E:FD:9D:A1 ManufacturerData.Value:\n"
    "  0b a0 7f 69 b1 73 60 b5                          ...i.s`.        \n"
    "[\x1b[0;92mNEW\x1b[0m] \x1b[1;30mDevice 0F:DD:51:26:17:C8 0F-DD-51-26-17-C8\x1b[0m\n"
)

REAL_SCAN_CAPTURE_CLEAN = """
[CHG] Device 44:C8:3E:FD:9D:A1 RSSI: 0xffffffae (-82)
[CHG] Device 44:C8:3E:FD:9D:A1 ManufacturerData.Key: 0x0075 (117)
[CHG] Device 44:C8:3E:FD:9D:A1 ManufacturerData.Value:
  0b a0 7f 69 b1 73 60 b5                          ...i.s`.        
[NEW] Device 0F:DD:51:26:17:C8 0F-DD-51-26-17-C8
"""


def test_parse_manufacturer_data_hex() -> None:
    assert parse_manufacturer_data_hex("424201") == BB_BEACON_MAGIC + b"\x01"
    assert parse_manufacturer_data_hex("0x424201") == BB_BEACON_MAGIC + b"\x01"


def test_real_scan_capture_ansi_and_multiline_mfg() -> None:
    raw = parse_bluetoothctl_scan_output(REAL_SCAN_CAPTURE_RAW)
    clean = parse_bluetoothctl_scan_output(REAL_SCAN_CAPTURE_CLEAN)

    expected_mfg = bytes.fromhex("0ba07f69b17360b5")
    assert raw["44:C8:3E:FD:9D:A1"].manufacturer_data[0x0075] == expected_mfg
    assert clean["44:C8:3E:FD:9D:A1"].manufacturer_data[0x0075] == expected_mfg
    assert raw["0F:DD:51:26:17:C8"].name == "0F-DD-51-26-17-C8"
    assert clean["0F:DD:51:26:17:C8"].name == "0F-DD-51-26-17-C8"
    assert raw["44:C8:3E:FD:9D:A1"].manufacturer_data == clean["44:C8:3E:FD:9D:A1"].manufacturer_data
    assert raw["0F:DD:51:26:17:C8"].name == clean["0F:DD:51:26:17:C8"].name

    assert "0F:DD:51:26:17:C8" in new_devices_from_scan_output(REAL_SCAN_CAPTURE_RAW)
    assert "0F:DD:51:26:17:C8" in new_devices_from_scan_output(REAL_SCAN_CAPTURE_CLEAN)

    colored = "[\x1b[0;92mNEW\x1b[0m] \x1b[1;30mDevice AA:BB:CC:DD:EE:FF foo\x1b[0m"
    assert _strip_ctl(colored) == "[NEW] Device AA:BB:CC:DD:EE:FF foo"


def test_parse_bluetoothctl_scan_output_fixture() -> None:
    logs: list[str] = []
    records = parse_bluetoothctl_scan_output(SCAN_FIXTURE, log=logs.append)
    assert "11:22:33:44:55:66" in records
    assert records["11:22:33:44:55:66"].name == "ubuntu-le"
    assert BB_BEACON_COMPANY_ID in records["11:22:33:44:55:66"].manufacturer_data
    assert records["11:22:33:44:55:66"].manufacturer_data[BB_BEACON_COMPANY_ID].startswith(
        BB_BEACON_MAGIC
    )
    assert "AA:BB:CC:DD:EE:01" in records
    assert 0x004C in records["AA:BB:CC:DD:EE:01"].manufacturer_data
    assert "BB:BB:BB:BB:BB:02" in records
    assert match_bb_beacon_manufacturer_data(
        records["BB:BB:BB:BB:BB:02"].manufacturer_data[BB_BEACON_COMPANY_ID]
    )
    assert any("42420" in msg or "garbled" in msg for msg in logs)


def test_parse_bluetoothctl_info_multiline_hexdump() -> None:
    info = parse_bluetoothctl_info(INFO_MULTILINE_HEX_FIXTURE)
    assert info.bd_addr == "14:B5:CD:E2:12:4F"
    assert info.addr_type == "public"
    assert info.manufacturer_data[BB_BEACON_COMPANY_ID] == BB_BEACON_MAGIC + b"\x01"


def test_parse_bluetoothctl_info_fixture() -> None:
    pub = parse_bluetoothctl_info(INFO_PUBLIC_FIXTURE)
    assert pub.bd_addr == "11:22:33:44:55:66"
    assert pub.addr_type == "public"
    assert pub.name == "ubuntu-le"
    assert match_bb_beacon_manufacturer_data(pub.manufacturer_data[BB_BEACON_COMPANY_ID])

    rnd = parse_bluetoothctl_info(INFO_RANDOM_FIXTURE)
    assert rnd.addr_type == "random"
    assert match_bb_beacon_manufacturer_data(rnd.manufacturer_data[BB_BEACON_COMPANY_ID])


def test_is_bb_beacon_record() -> None:
    records = parse_bluetoothctl_scan_output(SCAN_FIXTURE)
    assert is_bb_beacon_record(records["11:22:33:44:55:66"])
    assert is_bb_beacon_record(records["BB:BB:BB:BB:BB:02"])
    assert not is_bb_beacon_record(records["AA:BB:CC:DD:EE:01"])


def test_presence_scanner_cached_device_via_info() -> None:
    info_calls: list[str] = []

    def info_runner(bd: str) -> str:
        info_calls.append(bd)
        if bd == "14:B5:CD:E2:12:4F":
            return INFO_MULTILINE_HEX_FIXTURE
        return ""

    seen: list[tuple[str, str]] = []
    scanner = PresenceScanner(
        scan_window_s=0.1,
        scan_period_s=0.2,
        quiet=True,
        on_candidate=lambda bd, addr_type, _ts: seen.append((bd, addr_type)),
        scan_runner=lambda _t: CACHED_DEVICE_SCAN_FIXTURE,
        info_runner=info_runner,
    )

    found = scanner.scan_once(now=1000.0)
    assert len(found) == 1
    assert found[0].bd_addr == "14:B5:CD:E2:12:4F"
    assert found[0].addr_type == "public"
    assert seen == [("14:B5:CD:E2:12:4F", "public")]
    assert info_calls == ["14:B5:CD:E2:12:4F"]
    scanner.stop()


def test_presence_scanner_scan_once_and_ttl() -> None:
    info_map = {
        "11:22:33:44:55:66": INFO_PUBLIC_FIXTURE,
        "BB:BB:BB:BB:BB:02": INFO_RANDOM_FIXTURE,
    }
    seen: list[tuple[str, str, float]] = []

    scanner = PresenceScanner(
        scan_window_s=0.1,
        scan_period_s=0.2,
        candidate_ttl_s=0.15,
        quiet=True,
        on_candidate=lambda bd, addr_type, ts: seen.append((bd, addr_type, ts)),
        scan_runner=lambda _t: SCAN_FIXTURE,
        info_runner=lambda bd: info_map.get(bd, ""),
    )

    t0 = time.monotonic()
    found = scanner.scan_once(now=t0)
    assert len(found) == 2
    assert seen == [
        ("11:22:33:44:55:66", "public", t0),
        ("BB:BB:BB:BB:BB:02", "random", t0),
    ]
    cands = scanner.candidates()
    assert set(cands) == {"11:22:33:44:55:66", "BB:BB:BB:BB:BB:02"}

    # Evict after TTL without re-detection.
    with scanner._lock:
        scanner._evict_stale_locked(t0 + 0.2)
    assert scanner.candidates() == {}

    scanner.stop()


def test_presence_scanner_thread_loop() -> None:
    seen: list[str] = []

    scanner = PresenceScanner(
        scan_window_s=0.05,
        scan_period_s=0.12,
        quiet=True,
        on_candidate=lambda bd, _t, _ts: seen.append(bd),
        scan_runner=lambda _t: SCAN_FIXTURE,
        info_runner=lambda bd: INFO_PUBLIC_FIXTURE if bd == "11:22:33:44:55:66" else INFO_RANDOM_FIXTURE,
    )
    scanner.start()
    time.sleep(0.25)
    scanner.stop()
    assert "11:22:33:44:55:66" in seen


if __name__ == "__main__":
    test_parse_manufacturer_data_hex()
    print("✅ parse_manufacturer_data_hex")
    test_real_scan_capture_ansi_and_multiline_mfg()
    print("✅ real scan capture ANSI + multiline mfg")
    test_parse_bluetoothctl_scan_output_fixture()
    print("✅ parse_bluetoothctl_scan_output")
    test_parse_bluetoothctl_info_multiline_hexdump()
    print("✅ parse_bluetoothctl_info multiline hexdump")
    test_parse_bluetoothctl_info_fixture()
    print("✅ parse_bluetoothctl_info")
    test_is_bb_beacon_record()
    print("✅ is_bb_beacon_record")
    test_presence_scanner_cached_device_via_info()
    print("✅ cached device via info fallback")
    test_presence_scanner_scan_once_and_ttl()
    print("✅ PresenceScanner scan_once + TTL")
    test_presence_scanner_thread_loop()
    print("✅ PresenceScanner thread loop")
