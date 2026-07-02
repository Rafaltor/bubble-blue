"""
LE advertising for BUBBLE-BLUE presence beacons.

Design choice (intentional): every BB node advertises a **universal, group-independent**
presence marker. Any observer (scanner, sniffer, foreign mesh node) can recognize a
Bubble-Blue participant from raw AD alone. The mesh is **open by design** at the
discovery layer; a future stealth mode with keyed beacons may be added later.

``mute()`` / ``stop()`` tear down the btmgmt advertising instance and stop the
watchdog — there is no separate "silent but running" state.
"""

from __future__ import annotations

import re
import subprocess
import threading
from typing import Callable

# ASCII magic in Manufacturer Specific Data — reusable by scanners.
BB_BEACON_MAGIC = b"BB"
BB_BEACON_PROTOCOL_VERSION = 0x01
BB_BEACON_COMPANY_ID = 0xFFFF

# Flags AD: length 2, type 0x01, value 0x06 (LE General Discoverable + BR/EDR Not Supported).
_FLAGS_AD = bytes([0x02, 0x01, 0x06])

# Manufacturer Specific Data AD: company ID 0xFFFF (LE) + magic + protocol version.
_MFG_PAYLOAD = (
    bytes([0x06, 0xFF])
    + BB_BEACON_COMPANY_ID.to_bytes(2, "little")
    + BB_BEACON_MAGIC
    + bytes([BB_BEACON_PROTOCOL_VERSION])
)

BB_BEACON_AD: bytes = _FLAGS_AD + _MFG_PAYLOAD


def build_bb_beacon_ad() -> bytes:
    """Return the static BLE advertising data payload for BB presence."""
    return BB_BEACON_AD


def bb_beacon_ad_hex() -> str:
    """Hex string for ``btmgmt add-adv -d <hex>``."""
    return BB_BEACON_AD.hex()


def match_bb_beacon_manufacturer_data(data: bytes) -> bool:
    """
    Return True if manufacturer payload begins with :data:`BB_BEACON_MAGIC`.

    Accepts either the value-only form (``424201``) or company-prefixed form
    (``ffff424201``) as reported by bluetoothctl.
    """
    if len(data) >= len(BB_BEACON_MAGIC) and data[: len(BB_BEACON_MAGIC)] == BB_BEACON_MAGIC:
        return True
    if len(data) >= 2 + len(BB_BEACON_MAGIC):
        company_id = data[0] | (data[1] << 8)
        if company_id == BB_BEACON_COMPANY_ID:
            return data[2 : 2 + len(BB_BEACON_MAGIC)] == BB_BEACON_MAGIC
    return False


def match_bb_beacon_in_ad(ad: bytes) -> bool:
    """
    Return True if *ad* contains a valid BB universal presence marker.

    Scanners pass raw AD bytes (e.g. from ``MANUFACTURERDATA`` / HCI) through here.
    """
    offset = 0
    while offset < len(ad):
        if offset + 1 >= len(ad):
            break
        length = ad[offset]
        if length == 0:
            break
        end = offset + 1 + length
        if end > len(ad):
            break
        ad_type = ad[offset + 1]
        ad_data = ad[offset + 2 : end]
        if ad_type == 0xFF and len(ad_data) >= 5:
            company_id = ad_data[0] | (ad_data[1] << 8)
            if (
                company_id == BB_BEACON_COMPANY_ID
                and ad_data[2:4] == BB_BEACON_MAGIC
                and ad_data[4] == BB_BEACON_PROTOCOL_VERSION
            ):
                return True
        offset = end
    return False


def _hci_index(interface: str | int) -> int:
    if isinstance(interface, int):
        return interface
    iface = interface.strip().lower()
    if iface.startswith("hci"):
        return int(iface[3:])
    return int(iface)


def _run_btmgmt(hci_index: int, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["btmgmt", "--index", str(hci_index), *args],
        check=False,
        capture_output=True,
        text=True,
    )


class LEAdvertiser:
    """
    Manage a static LE advertising instance via ``btmgmt add-adv``.

    A background watchdog periodically verifies the instance is still active and
    re-arms it when BlueZ drops it. ``mute()`` is an alias for ``stop()``.
    """

    _INSTANCE_RE = re.compile(r"^\s*Instance:\s*(\d+)", re.MULTILINE)

    def __init__(
        self,
        *,
        interface: str | int = 0,
        instance_id: int = 1,
        watchdog_interval_s: float = 30.0,
        quiet: bool = False,
        log: Callable[[str], None] | None = None,
        btmgmt_runner: Callable[[int, str], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._hci_index = _hci_index(interface)
        self._instance_id = int(instance_id)
        self._watchdog_interval_s = max(1.0, float(watchdog_interval_s))
        self._quiet = quiet
        self._log = log or (lambda msg: None if quiet else print(f"[ADV] {msg}", flush=True))
        self._run = btmgmt_runner or (lambda idx, cmd: _run_btmgmt(idx, *cmd.split()))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    @staticmethod
    def ad_hex() -> str:
        return bb_beacon_ad_hex()

    def start(self) -> None:
        """Bring up LE advertising and start the watchdog thread."""
        if self._started:
            return
        self._prepare_controller()
        if not self._ensure_instance(force=True):
            raise RuntimeError(
                f"btmgmt add-adv failed on hci{self._hci_index} "
                f"(instance {self._instance_id}); is btmgmt available and is the adapter up?"
            )
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._watchdog_loop,
            name=f"bb-adv-watchdog-hci{self._hci_index}",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        self._log(f"advertising on hci{self._hci_index} instance {self._instance_id}")

    def stop(self) -> None:
        """Stop advertising and the watchdog (``mute``)."""
        if not self._started:
            self._remove_instance()
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._watchdog_interval_s + 2.0)
            self._thread = None
        self._remove_instance()
        self._started = False
        self._log(f"muted hci{self._hci_index} instance {self._instance_id}")

    def mute(self) -> None:
        """Alias for :meth:`stop` — no separate silent mode."""
        self.stop()

    @property
    def running(self) -> bool:
        return self._started

    def _prepare_controller(self) -> None:
        self._run(self._hci_index, "power on")
        self._run(self._hci_index, "le on")

    def _remove_instance(self) -> None:
        self._run(self._hci_index, f"rm-adv {self._instance_id}")

    def _add_instance(self) -> bool:
        result = self._run(
            self._hci_index,
            f"add-adv -d {self.ad_hex()} {self._instance_id}",
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            if err and not self._quiet:
                self._log(f"add-adv failed: {err}")
            return False
        return True

    def _instance_present(self) -> bool:
        result = self._run(self._hci_index, "info")
        text = result.stdout or ""
        if result.returncode != 0:
            return False
        for match in self._INSTANCE_RE.finditer(text):
            if int(match.group(1)) != self._instance_id:
                continue
            chunk = text[match.start() : match.start() + 512]
            normalized = chunk.replace(" ", "").lower()
            if self.ad_hex().lower() in normalized:
                return True
        return False

    def _ensure_instance(self, *, force: bool = False) -> bool:
        if not force and self._instance_present():
            return True
        self._remove_instance()
        return self._add_instance()

    def _watchdog_loop(self) -> None:
        while not self._stop.wait(self._watchdog_interval_s):
            try:
                if not self._ensure_instance():
                    self._log(
                        f"watchdog: failed to re-arm instance {self._instance_id} "
                        f"on hci{self._hci_index}"
                    )
            except Exception as exc:
                self._log(f"watchdog error: {exc}")
