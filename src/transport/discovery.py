from __future__ import annotations

import math
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field


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
_MFG_KEY_RE = re.compile(
    r"ManufacturerData(?:\s+Key|\s*\.Key)?\s*:\s*0x([0-9A-Fa-f]+)(?:\s*\(\d+\))?",
    re.IGNORECASE,
)
_MFG_VALUE_RE = re.compile(
    r"ManufacturerData(?:\s+Value|\s*\.Value)?\s*:\s*(?:0x)?([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_MFG_VALUE_EMPTY_RE = re.compile(
    r"ManufacturerData(?:\s+Value|\s*\.Value)?\s*:\s*$",
    re.IGNORECASE,
)
_MFG_INLINE_RE = re.compile(
    r"ManufacturerData\s*:\s*0x([0-9A-Fa-f]+)(?:\s*\(\d+\))?\s*(?:[, ]\s*(?:0x)?([0-9A-Fa-f]+))?",
    re.IGNORECASE,
)
_ADDR_TYPE_RE = re.compile(r"AddressType\s*:\s*(\S+)", re.IGNORECASE)
_DEVICE_HEADER_ADDR_TYPE_RE = re.compile(
    r"^\s*Device\s+(?P<bd>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*\((?P<addr_type>[a-zA-Z-]+)\)",
    re.IGNORECASE,
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_READLINE_CTL_RE = re.compile(r"[\x01\x02]")


@dataclass(frozen=True)
class DiscoveredDevice:
    bd_addr: str
    name: str | None = None
    last_seen_ms: int | None = None
    source: str | None = None  # "le" | "bredr" | "cache"


@dataclass
class ScanDeviceRecord:
    """Aggregated bluetoothctl scan output for one BD_ADDR."""

    bd_addr: str
    name: str | None = None
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    last_seen_ms: int = 0


@dataclass
class BluetoothctlInfo:
    bd_addr: str | None = None
    name: str | None = None
    addr_type: str | None = None
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)


def _strip_ctl(line: str) -> str:
    """Remove ANSI escapes, readline control chars, and carriage returns."""
    cleaned = line.replace("\r", "")
    cleaned = _ANSI_ESCAPE_RE.sub("", cleaned)
    cleaned = _READLINE_CTL_RE.sub("", cleaned)
    return cleaned


def parse_manufacturer_data_hex(hex_text: str) -> bytes:
    """Decode ``424201`` / ``0x424201`` style manufacturer payloads."""
    cleaned = hex_text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "")
    if len(cleaned) % 2:
        raise ValueError(f"odd-length manufacturer hex: {hex_text!r}")
    return bytes.fromhex(cleaned)


def _hexdump_line_bytes(line: str) -> bytes | None:
    """
    Parse one hexdump continuation line (``42 42 01                    BB.``).

    Tokenizes on whitespace; keeps only tokens of exactly two hex digits,
    stopping at the first non-conforming token (ASCII column).
    """
    tokens = line.split()
    hex_parts: list[str] = []
    for tok in tokens:
        if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
            hex_parts.append(tok)
        else:
            break
    if not hex_parts:
        return None
    return bytes.fromhex("".join(hex_parts))


def _flush_pending_mfg_hex(
    *,
    pending_key: int | None,
    accum: bytearray,
    target: dict[int, bytes],
) -> None:
    if pending_key is not None and accum:
        target[pending_key] = bytes(accum)


class _MfgHexdumpConsumer:
    """Shared multiline hexdump state for scan stdout and ``bluetoothctl info``."""

    __slots__ = ("_accum", "_pending_key")

    def __init__(self) -> None:
        self._pending_key: int | None = None
        self._accum = bytearray()

    @property
    def active(self) -> bool:
        return self._pending_key is not None

    def start(self, company_id: int) -> None:
        self._pending_key = company_id
        self._accum = bytearray()

    def reset(self) -> None:
        self._pending_key = None
        self._accum = bytearray()

    def feed(self, line: str) -> bool:
        """Consume one hexdump continuation line; return True if bytes were appended."""
        chunk = _hexdump_line_bytes(line)
        if chunk is None:
            return False
        self._accum.extend(chunk)
        return True

    def flush_into(self, target: dict[int, bytes]) -> None:
        _flush_pending_mfg_hex(
            pending_key=self._pending_key,
            accum=self._accum,
            target=target,
        )
        self.reset()


def new_devices_from_scan_output(text: str) -> set[str]:
    """BD addresses announced with ``[NEW] Device …`` during a scan window."""
    seen: set[str] = set()
    for raw in text.splitlines():
        line = _strip_ctl(raw)
        if "[NEW]" not in line.upper():
            continue
        bd = _device_bd_from_line(line)
        if bd:
            seen.add(bd)
    return seen


def _device_bd_from_line(line: str) -> str | None:
    if not _SCAN_PREFIX_RE.search(line):
        return None
    m = _BD_ADDR_RE.search(line)
    if not m:
        return None
    return m.group("bd").upper()


def _record_for(records: dict[str, ScanDeviceRecord], bd_addr: str) -> ScanDeviceRecord:
    rec = records.get(bd_addr)
    if rec is None:
        rec = ScanDeviceRecord(bd_addr=bd_addr)
        records[bd_addr] = rec
    return rec


def parse_bluetoothctl_scan_output(
    text: str,
    *,
    now_ms: int = 0,
    log: Callable[[str], None] | None = None,
) -> dict[str, ScanDeviceRecord]:
    """
    Parse ``bluetoothctl scan le`` stdout into per-device records.

    Captures device names and ManufacturerData (company id + hex value) from
    ``[NEW]`` / ``[CHG]`` lines. Unexpected lines are logged (if *log* is set)
    and skipped.
    """
    records: dict[str, ScanDeviceRecord] = {}
    pending_mfg_key: dict[str, int] = {}
    pending_mfg_value = _MfgHexdumpConsumer()
    pending_value_bd: str | None = None

    def _flush_scan_mfg_value() -> None:
        nonlocal pending_value_bd
        if pending_value_bd is not None and pending_mfg_value.active:
            rec = _record_for(records, pending_value_bd)
            pending_mfg_value.flush_into(rec.manufacturer_data)
        pending_value_bd = None
        pending_mfg_value.reset()

    for raw in text.splitlines():
        line = _strip_ctl(raw.rstrip("\n"))
        if not line.strip():
            if pending_value_bd is not None:
                _flush_scan_mfg_value()
            continue
        try:
            bd = _device_bd_from_line(line)

            if pending_value_bd is not None:
                if bd is not None:
                    _flush_scan_mfg_value()
                elif pending_mfg_value.feed(line):
                    continue
                else:
                    _flush_scan_mfg_value()

            if bd is None:
                continue

            rec = _record_for(records, bd)
            rec.last_seen_ms = max(rec.last_seen_ms, now_ms)

            parsed = _parse_device_line(line)
            if parsed is not None:
                _, name = parsed
                if name:
                    rec.name = name

            inline = _MFG_INLINE_RE.search(line)
            if inline:
                company_id = int(inline.group(1), 16)
                value_hex = inline.group(2)
                if value_hex:
                    rec.manufacturer_data[company_id] = parse_manufacturer_data_hex(value_hex)
                else:
                    pending_mfg_key[bd] = company_id
                continue

            key_match = _MFG_KEY_RE.search(line)
            if key_match:
                pending_mfg_key[bd] = int(key_match.group(1), 16)
                continue

            if _MFG_VALUE_EMPTY_RE.search(line):
                company_id = pending_mfg_key.pop(bd, None)
                if company_id is not None:
                    pending_value_bd = bd
                    pending_mfg_value.start(company_id)
                continue

            val_match = _MFG_VALUE_RE.search(line)
            if val_match:
                company_id = pending_mfg_key.pop(bd, None)
                payload = parse_manufacturer_data_hex(val_match.group(1))
                if company_id is None and len(payload) >= 2:
                    company_id = payload[0] | (payload[1] << 8)
                    payload = payload[2:]
                if company_id is not None:
                    rec.manufacturer_data[company_id] = payload
                continue
        except Exception as exc:
            if log is not None:
                log(f"scan parse skip ({exc}): {line!r}")
            continue

    if pending_value_bd is not None:
        _flush_scan_mfg_value()

    return records


def parse_bluetoothctl_info(
    text: str,
    *,
    log: Callable[[str], None] | None = None,
) -> BluetoothctlInfo:
    """Parse ``bluetoothctl info <bd>`` for address type and manufacturer data."""
    info = BluetoothctlInfo()
    pending_mfg_key: int | None = None
    mfg_consumer = _MfgHexdumpConsumer()

    for raw in text.splitlines():
        line = _strip_ctl(raw.rstrip("\n"))
        stripped = line.strip()
        if not stripped:
            if mfg_consumer.active:
                mfg_consumer.flush_into(info.manufacturer_data)
            continue
        try:
            if mfg_consumer.active:
                if mfg_consumer.feed(line):
                    continue
                mfg_consumer.flush_into(info.manufacturer_data)

            header = _DEVICE_HEADER_ADDR_TYPE_RE.match(stripped)
            if header:
                info.bd_addr = header.group("bd").upper()
                info.addr_type = header.group("addr_type").lower()
                continue

            m = _BD_ADDR_RE.search(stripped)
            if info.bd_addr is None and m and stripped.lower().startswith("device"):
                info.bd_addr = m.group("bd").upper()

            addr_type = _ADDR_TYPE_RE.search(stripped)
            if addr_type:
                info.addr_type = addr_type.group(1).lower()

            if stripped.startswith("Name:"):
                val = stripped.split(":", 1)[1].strip()
                if val:
                    info.name = val
            elif stripped.startswith("Alias:"):
                val = stripped.split(":", 1)[1].strip()
                if val and info.name is None:
                    info.name = val

            inline = _MFG_INLINE_RE.search(stripped)
            if inline:
                company_id = int(inline.group(1), 16)
                value_hex = inline.group(2)
                if value_hex:
                    info.manufacturer_data[company_id] = parse_manufacturer_data_hex(value_hex)
                else:
                    pending_mfg_key = company_id
                continue

            key_match = _MFG_KEY_RE.search(stripped)
            if key_match:
                pending_mfg_key = int(key_match.group(1), 16)
                continue

            if _MFG_VALUE_EMPTY_RE.search(stripped):
                if pending_mfg_key is not None:
                    mfg_consumer.start(pending_mfg_key)
                    pending_mfg_key = None
                continue

            val_match = _MFG_VALUE_RE.search(stripped)
            if val_match:
                payload = parse_manufacturer_data_hex(val_match.group(1))
                company_id = pending_mfg_key
                pending_mfg_key = None
                if company_id is None and len(payload) >= 2:
                    company_id = payload[0] | (payload[1] << 8)
                    payload = payload[2:]
                if company_id is not None:
                    info.manufacturer_data[company_id] = payload
                continue
        except Exception as exc:
            if log is not None:
                log(f"info parse skip ({exc}): {stripped!r}")
            continue

    if mfg_consumer.active:
        mfg_consumer.flush_into(info.manufacturer_data)

    return info


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
    if after:
        upper = after.upper()
        if upper.startswith(_LIKELY_KV_PREFIXES) or upper.startswith("MANUFACTURERDATA"):
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

