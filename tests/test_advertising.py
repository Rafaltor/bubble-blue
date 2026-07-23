from __future__ import annotations

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.advertising import (  # noqa: E402
    BB_BEACON_AD,
    BB_BEACON_ADV_DATA,
    BB_BEACON_COMPANY_ID,
    BB_BEACON_MAGIC,
    BB_BEACON_PROTOCOL_VERSION,
    LEAdvertiser,
    bb_beacon_ad_hex,
    build_bb_beacon_ad,
    build_bb_beacon_adv_data,
    build_presence_manufacturer_value,
    match_bb_beacon_in_ad,
    match_bb_beacon_manufacturer_data,
    parse_presence_manufacturer_value,
)

# TODO: recaler ces fixtures sur la sortie capturée des boards (btmgmt advinfo / info).
# Format btmgmt réel — pas btmon/HCI decode.
BTMGMT_ADVINFO_ACTIVE = """
Supported flags: connectable general-discoverable limited-discoverable managed-flags tx-power appearance local-name
Max advertising data len: 31
Max scan response data len: 31
Max instances: 10
Instances list with 1 item
Instance: 1
"""

BTMGMT_ADVINFO_EMPTY = """
Supported flags: connectable general-discoverable limited-discoverable managed-flags tx-power appearance local-name
Max advertising data len: 31
Max scan response data len: 31
Max instances: 10
Instances list with 0 items
"""

BTMGMT_INFO_ADVERTISING = """
Index list with 1 item
hci0:	Primary controller
	addr 40:D9:5A:8B:69:3F version 9 manufacturer 15 class 0x6c0000
	supported settings: powered connectable discoverable bondable le advertising secure-conn
	current settings: powered connectable le advertising secure-conn
	name ubuntu
"""

BTMGMT_INFO_IDLE = """
Index list with 1 item
hci0:	Primary controller
	addr 40:D9:5A:8B:69:3F version 9 manufacturer 15 class 0x6c0000
	supported settings: powered connectable discoverable bondable le advertising secure-conn
	current settings: powered connectable le secure-conn
	name ubuntu
"""


def test_bb_beacon_static_payload() -> None:
    ad = build_bb_beacon_ad()
    mfg = build_bb_beacon_adv_data()
    # On-air: 02 01 06 | 06 FF FF FF 42 42 01
    assert ad == bytes([0x02, 0x01, 0x06, 0x06, 0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x01])
    assert ad == BB_BEACON_AD
    assert mfg == bytes([0x06, 0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x01])
    assert mfg == BB_BEACON_ADV_DATA
    assert bb_beacon_ad_hex() == "06ffffff424201"
    assert BB_BEACON_MAGIC == b"BB"
    assert BB_BEACON_PROTOCOL_VERSION == 0x01


def test_match_bb_beacon_manufacturer_data() -> None:
    assert match_bb_beacon_manufacturer_data(BB_BEACON_MAGIC + b"\x01")
    assert match_bb_beacon_manufacturer_data(b"\xff\xff" + BB_BEACON_MAGIC + b"\x01")
    assert not match_bb_beacon_manufacturer_data(b"\x00\x01")


def test_match_bb_beacon_in_ad() -> None:
    assert match_bb_beacon_in_ad(BB_BEACON_AD)
    prefixed = bytes([0x02, 0x01, 0x04]) + BB_BEACON_AD
    assert match_bb_beacon_in_ad(prefixed)
    assert not match_bb_beacon_in_ad(b"\x02\x01\x06")
    assert not match_bb_beacon_in_ad(bytes.fromhex("0606FFFF424201"))


def _mfg_ad_structure(value: bytes) -> bytes:
    """Wrap a manufacturer VALUE into a full AD structure (len, type 0xFF, company, value)."""
    payload = BB_BEACON_COMPANY_ID.to_bytes(2, "little") + value
    return bytes([1 + len(payload), 0xFF]) + payload


def test_presence_value_roundtrip() -> None:
    anon = bytes(range(8))
    nbrs = [bytes([i]) * 8 for i in range(1, 4)]
    mpr = [bytes([9]) * 8]
    value = build_presence_manufacturer_value(
        anon, 42, nbrs, mpr, is_relay=True, bd_addr="14:B5:CD:E8:75:33"
    )
    # The presence value keeps the plain-beacon prefix so discovery still matches.
    assert value[:3] == BB_BEACON_MAGIC + bytes([BB_BEACON_PROTOCOL_VERSION])
    assert match_bb_beacon_manufacturer_data(value)
    assert match_bb_beacon_in_ad(_mfg_ad_structure(value))

    parsed = parse_presence_manufacturer_value(value)
    assert parsed is not None
    assert parsed["anon_id"] == anon
    assert parsed["seq"] == 42
    assert parsed["is_relay"] is True
    assert parsed["bd_addr"] == "14:B5:CD:E8:75:33"
    assert parsed["neighbors"] == nbrs
    assert parsed["mpr"] == mpr

    # Default role is non-relay and no reachable address advertised.
    default = parse_presence_manufacturer_value(build_presence_manufacturer_value(anon, 1, nbrs))
    assert default["is_relay"] is False
    assert default["bd_addr"] is None


def test_presence_value_truncates_to_budget() -> None:
    anon = bytes(range(8))
    nbrs = [bytes([i % 256]) * 8 for i in range(60)]  # 60 * 8 = 480 bytes > budget
    mpr = [bytes([7]) * 8 for _ in range(5)]
    value = build_presence_manufacturer_value(anon, 1, nbrs, mpr)
    assert len(value) <= 247
    parsed = parse_presence_manufacturer_value(value)
    assert parsed is not None
    assert parsed["anon_id"] == anon
    # Neighbors are kept (prefix), MPRs dropped first under pressure.
    assert 0 < len(parsed["neighbors"]) <= len(nbrs)
    assert parsed["neighbors"] == nbrs[: len(parsed["neighbors"])]


def test_presence_parse_rejects_plain_beacon_and_garbage() -> None:
    assert parse_presence_manufacturer_value(BB_BEACON_MAGIC + b"\x01") is None
    assert parse_presence_manufacturer_value(b"\x00\x01\x02") is None
    assert parse_presence_manufacturer_value(b"") is None
    # Truncated presence (claims neighbors it does not carry) → None, never raises.
    # prefix(4) + anon(8) + seq(4) + flags(1) + bd(6) + n_neighbors=5 but no neighbor bytes.
    truncated = (
        BB_BEACON_MAGIC
        + bytes([0x01, 0x02])  # protocol 0x01, presence format 0x02
        + bytes(8)
        + b"\x00\x00\x00\x01"
        + bytes([0x00])
        + bytes(6)
        + bytes([5])
    )
    assert parse_presence_manufacturer_value(truncated) is None


def test_instance_present_advinfo_and_info_fallback() -> None:
    adv = LEAdvertiser(quiet=True)
    assert adv._instance_present_in_advinfo(BTMGMT_ADVINFO_ACTIVE)
    assert not adv._instance_present_in_advinfo(BTMGMT_ADVINFO_EMPTY)
    assert adv._instance_present_in_info(BTMGMT_INFO_ADVERTISING)
    assert not adv._instance_present_in_info(BTMGMT_INFO_IDLE)


def test_le_advertiser_watchdog_rearms() -> None:
    calls: list[str] = []
    present = {"ok": True}

    def fake_run(_idx: int, cmd: str) -> object:
        calls.append(cmd)
        if cmd == "advinfo":
            stdout = BTMGMT_ADVINFO_ACTIVE if present["ok"] else BTMGMT_ADVINFO_EMPTY
            return type("R", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
        if cmd == "info":
            stdout = BTMGMT_INFO_ADVERTISING if present["ok"] else BTMGMT_INFO_IDLE
            return type("R", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    adv = LEAdvertiser(
        interface=0,
        watchdog_interval_s=0.05,
        quiet=True,
        btmgmt_runner=fake_run,
    )
    adv.start()
    assert any(cmd == f"add-adv -c -d {bb_beacon_ad_hex()} 1" for cmd in calls)

    present["ok"] = False
    time.sleep(0.12)
    assert any(cmd.startswith("add-adv -c -d") for cmd in calls[1:])

    adv.stop()
    assert any(cmd == "rm-adv 1" for cmd in calls)
    assert not adv.running


def test_mute_is_stop() -> None:
    ok = type("R", (), {"returncode": 0, "stdout": BTMGMT_ADVINFO_ACTIVE, "stderr": ""})()

    def fake_run(_idx: int, cmd: str) -> object:
        if cmd == "advinfo":
            return ok
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    adv = LEAdvertiser(quiet=True, btmgmt_runner=fake_run)
    adv.start()
    adv.mute()
    assert not adv.running


if __name__ == "__main__":
    test_bb_beacon_static_payload()
    print("✅ bb beacon static payload")
    test_match_bb_beacon_manufacturer_data()
    print("✅ match_bb_beacon_manufacturer_data")
    test_match_bb_beacon_in_ad()
    print("✅ match_bb_beacon_in_ad")
    test_instance_present_advinfo_and_info_fallback()
    print("✅ instance present advinfo + info fallback")
    test_le_advertiser_watchdog_rearms()
    print("✅ LEAdvertiser watchdog re-arms")
    test_mute_is_stop()
    print("✅ mute is stop")
