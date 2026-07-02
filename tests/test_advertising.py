from __future__ import annotations

import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.advertising import (  # noqa: E402
    BB_BEACON_AD,
    BB_BEACON_MAGIC,
    BB_BEACON_PROTOCOL_VERSION,
    LEAdvertiser,
    bb_beacon_ad_hex,
    build_bb_beacon_ad,
    match_bb_beacon_in_ad,
    match_bb_beacon_manufacturer_data,
)


def test_bb_beacon_static_payload() -> None:
    ad = build_bb_beacon_ad()
    # 02 01 06 | 06 FF FF FF 42 42 01  (Flags + Manufacturer Specific Data)
    assert ad == bytes([0x02, 0x01, 0x06, 0x06, 0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x01])
    assert ad == BB_BEACON_AD
    assert bb_beacon_ad_hex() == "02010606ffffff424201"
    assert BB_BEACON_MAGIC == b"BB"
    assert BB_BEACON_PROTOCOL_VERSION == 0x01


def test_match_bb_beacon_manufacturer_data() -> None:
    assert match_bb_beacon_manufacturer_data(BB_BEACON_MAGIC + b"\x01")
    assert match_bb_beacon_manufacturer_data(b"\xff\xff" + BB_BEACON_MAGIC + b"\x01")
    assert not match_bb_beacon_manufacturer_data(b"\x00\x01")


def test_match_bb_beacon_in_ad() -> None:
    assert match_bb_beacon_in_ad(BB_BEACON_AD)
    # Extra unrelated AD element before the BB beacon.
    prefixed = bytes([0x02, 0x01, 0x04]) + BB_BEACON_AD
    assert match_bb_beacon_in_ad(prefixed)
    assert not match_bb_beacon_in_ad(b"\x02\x01\x06")
    assert not match_bb_beacon_in_ad(bytes.fromhex("0606FFFF424201"))


def test_le_advertiser_watchdog_rearms() -> None:
    calls: list[str] = []
    present = {"ok": False}

    def fake_run(_idx: int, cmd: str) -> object:
        calls.append(cmd)
        if cmd == "info":
            if present["ok"]:

                class _Result:
                    returncode = 0
                    stdout = (
                        f"Advertising (0x0048) plen 13\n"
                        f"        Instance: 1 (0x01)\n"
                        f"        Data len: 10\n"
                        f"        {LEAdvertiser.ad_hex()}\n"
                    )
                    stderr = ""

                return _Result()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    adv = LEAdvertiser(
        interface=0,
        watchdog_interval_s=0.05,
        quiet=True,
        btmgmt_runner=fake_run,
    )
    adv.start()
    assert any(cmd.startswith("add-adv") for cmd in calls)

    present["ok"] = False
    time.sleep(0.12)
    assert any(cmd.startswith("add-adv") for cmd in calls[1:])

    adv.stop()
    assert any(cmd.startswith("rm-adv") for cmd in calls)
    assert not adv.running


def test_mute_is_stop() -> None:
    adv = LEAdvertiser(quiet=True, btmgmt_runner=lambda _i, _c: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
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
    test_le_advertiser_watchdog_rearms()
    print("✅ LEAdvertiser watchdog re-arms")
    test_mute_is_stop()
    print("✅ mute is stop")
