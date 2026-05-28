from __future__ import annotations

import math
import re
import subprocess
import time
from dataclasses import dataclass


_BD_ADDR_RE = re.compile(r"(?P<bd>([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
_SCAN_PREFIX_RE = re.compile(r"^\s*(?:\[(?:NEW|CHG|DEL)\]\s+)?Device\s+", re.IGNORECASE)
_LIKELY_KV_PREFIXES = (
    "RSSI:",
    "TXPOWER:",
    "UUID:",
    "CLASS:",
    "ICON:",
    "APPEARANCE:",
    "MANUFACTURERDATA:",
    "SERVICEDATA:",
)


@dataclass(frozen=True)
class DiscoveredDevice:
    bd_addr: str
    name: str | None = None
    last_seen_ms: int | None = None
    source: str | None = None  # "le" | "bredr" | "cache"


def _parse_device_line(line: str) -> tuple[str, str | None] | None:
    """
    Parses bluetoothctl output lines such as:
      [NEW] Device AA:BB:CC:DD:EE:FF Foo Bar
      Device AA:BB:CC:DD:EE:FF Foo Bar
    Returns (bd_addr, name?) or None.
    """
    # Avoid treating scan status lines as device lines.
    if not _SCAN_PREFIX_RE.search(line):
        return None

    m = _BD_ADDR_RE.search(line)
    if not m:
        return None
    bd = m.group("bd").upper()

    # Best-effort name extraction: everything after the BD addr
    after = line[m.end() :].strip()
    if after and after.upper().startswith(_LIKELY_KV_PREFIXES):
        # e.g. "[CHG] Device <bd> TxPower: 0x0000 (0)" is not a name
        after = ""
    name = after if after else None
    return bd, name


def _run_scan(mode: str, timeout_s: float) -> subprocess.CompletedProcess[str]:
    secs = int(max(1, math.ceil(timeout_s)))
    return subprocess.run(
        ["bluetoothctl", "--timeout", str(secs), "scan", mode],
        check=False,
        capture_output=True,
        text=True,
    )


def _bluetoothctl_info(bd_addr: str) -> str:
    info = subprocess.run(
        ["bluetoothctl", "info", bd_addr],
        check=False,
        capture_output=True,
        text=True,
    )
    return info.stdout or ""


def _parse_info_name(info_text: str) -> str | None:
    # Typical lines:
    #   Name: ubuntu
    #   Alias: ubuntu
    name = None
    alias = None
    for raw in info_text.splitlines():
        line = raw.strip()
        if line.startswith("Name:"):
            val = line.split(":", 1)[1].strip()
            if val:
                name = val
        elif line.startswith("Alias:"):
            val = line.split(":", 1)[1].strip()
            if val:
                alias = val
    return name or alias


def discover_devices(*, timeout_s: float = 5.0, modes: tuple[str, ...] = ("le", "bredr")) -> list[DiscoveredDevice]:
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
    sources: dict[str, str] = {}

    # Important for your setup: some devices only show up in BR/EDR, others only in LE.
    # We scan both modes by default, then read the cached device list as fallback.
    try:
        scans = [_run_scan(m, timeout_s) for m in modes]
    except FileNotFoundError as e:
        raise RuntimeError("`bluetoothctl` not found. Install BlueZ tools and ensure it is in PATH.") from e

    for mode, scan in zip(modes, scans, strict=False):
        now_ms = int((time.monotonic() - start) * 1000)
        for raw in (scan.stdout or "").splitlines():
            parsed = _parse_device_line(raw)
            if not parsed:
                continue
            bd, name = parsed
            last_seen[bd] = now_ms
            sources.setdefault(bd, mode)
            if name:
                names[bd] = name

    # Fallback: query the device cache list.
    now_ms = int((time.monotonic() - start) * 1000)
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
        sources.setdefault(bd, "cache")

    # Resolve missing/garbled names using `bluetoothctl info <BD_ADDR>`.
    for bd in list(last_seen.keys()):
        cur = names.get(bd)
        if cur:
            continue
        resolved = _parse_info_name(_bluetoothctl_info(bd))
        if resolved:
            names[bd] = resolved

    out: list[DiscoveredDevice] = []
    for bd in sorted(last_seen.keys()):
        out.append(
            DiscoveredDevice(
                bd_addr=bd,
                name=names.get(bd),
                last_seen_ms=last_seen.get(bd),
                source=sources.get(bd),
            )
        )
    return out

