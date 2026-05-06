from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass


_BD_ADDR_RE = re.compile(r"(?P<bd>([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")


@dataclass(frozen=True)
class DiscoveredDevice:
    bd_addr: str
    name: str | None = None
    last_seen_ms: int | None = None


def _parse_device_line(line: str) -> tuple[str, str | None] | None:
    """
    Parses bluetoothctl output lines such as:
      [NEW] Device AA:BB:CC:DD:EE:FF Foo Bar
      Device AA:BB:CC:DD:EE:FF Foo Bar
    Returns (bd_addr, name?) or None.
    """
    m = _BD_ADDR_RE.search(line)
    if not m:
        return None
    bd = m.group("bd").upper()

    # Best-effort name extraction: everything after the BD addr
    after = line[m.end() :].strip()
    name = after if after else None
    return bd, name


def discover_devices(*, timeout_s: float = 5.0) -> list[DiscoveredDevice]:
    """
    Discovers nearby Bluetooth devices using BlueZ's bluetoothctl.

    Notes:
    - Requires a working BlueZ installation.
    - Permissions depend on system policy; on some systems, scanning may require root
      or user membership in the `bluetooth` group.
    """
    start = time.monotonic()
    last_seen: dict[str, int] = {}
    names: dict[str, str] = {}

    # `bluetoothctl --timeout <sec> scan on` is available on many BlueZ versions.
    # We also run `bluetoothctl devices` afterwards as a fallback to capture devices
    # even if scan output is sparse.
    try:
        scan = subprocess.run(
            ["bluetoothctl", "--timeout", str(int(max(1, timeout_s))), "scan", "on"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`bluetoothctl` not found. Install BlueZ tools and ensure it is in PATH.") from e

    now_ms = int((time.monotonic() - start) * 1000)
    for raw in (scan.stdout or "").splitlines():
        parsed = _parse_device_line(raw)
        if not parsed:
            continue
        bd, name = parsed
        last_seen[bd] = now_ms
        if name:
            names[bd] = name

    # Fallback: query the device cache list.
    devs = subprocess.run(
        ["bluetoothctl", "devices"],
        check=False,
        capture_output=True,
        text=True,
    )
    for raw in (devs.stdout or "").splitlines():
        parsed = _parse_device_line(raw)
        if not parsed:
            continue
        bd, name = parsed
        last_seen.setdefault(bd, now_ms)
        if name:
            names.setdefault(bd, name)

    out: list[DiscoveredDevice] = []
    for bd in sorted(last_seen.keys()):
        out.append(DiscoveredDevice(bd_addr=bd, name=names.get(bd), last_seen_ms=last_seen.get(bd)))
    return out

