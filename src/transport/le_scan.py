"""
Robust LE scanning via the Linux Bluetooth Management (MGMT) API.

Why not ``bluetoothctl scan le``?
--------------------------------
``bluetoothctl`` only prints ``ManufacturerData`` on *change*. A stable BB
beacon that bluetoothd has already cached never re-emits a ``[CHG]`` line, so
its manufacturer payload is invisible to a stdout parser after the first sight.
The fallback of ``bluetoothctl info <bd>`` per device does not scale: in a noisy
RF environment (a building full of BLE devices + rotating RPAs) the round-robin
starves and BB nodes are never resolved — which is exactly why auto-discovery
failed and ``--topology`` had to be supplied by hand.

The MGMT ``Device Found`` event, by contrast, carries the *full EIR* on **every**
detection, independent of bluetoothd's change tracking. This is what
``btmgmt find`` uses. We open a MGMT control socket, drive a short discovery
window, and parse the EIR ourselves — no ``bluetoothctl`` text scraping, no
per-device ``info`` lookups.

The socket plumbing is intentionally thin; all the byte parsing lives in pure
functions (:func:`parse_mgmt_event`, :func:`parse_device_found`,
:func:`parse_eir_manufacturer`, :func:`merge_device_found`) that are unit tested
without any Bluetooth hardware.
"""

from __future__ import annotations

import select
import socket
import struct
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from src.transport.advertising import match_bb_beacon_in_ad
from src.transport.discovery import ScanDeviceRecord

# --- MGMT control socket addressing -----------------------------------------
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_CONTROL = 3

# --- MGMT opcodes / event codes (subset we need) ----------------------------
MGMT_OP_START_DISCOVERY = 0x0023
MGMT_OP_STOP_DISCOVERY = 0x0024

MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002
MGMT_EV_DEVICE_FOUND = 0x0012
MGMT_EV_DISCOVERING = 0x0013

# Address-type bitmask for START/STOP_DISCOVERY: LE Public (bit1) + LE Random (bit2).
LE_DISCOVERY_ADDR_MASK = 0x06

# MGMT LE address types inside Device Found.
_ADDR_TYPE_LE_PUBLIC = 1
_ADDR_TYPE_LE_RANDOM = 2

_MGMT_HEADER = struct.Struct("<HHH")


def hci_index_from_interface(interface: str | int) -> int:
    """Map ``"hci0"`` / ``0`` → adapter index ``0``."""
    if isinstance(interface, int):
        return interface
    iface = interface.strip().lower()
    if iface.startswith("hci"):
        return int(iface[3:])
    return int(iface)


def _addr_type_label(addr_type: int) -> str:
    if addr_type == _ADDR_TYPE_LE_PUBLIC:
        return "public"
    if addr_type == _ADDR_TYPE_LE_RANDOM:
        return "random"
    return "unknown"


@dataclass(frozen=True)
class MgmtEvent:
    code: int
    index: int
    params: bytes


@dataclass(frozen=True)
class DeviceFound:
    bd_addr: str
    addr_type: int
    rssi: int
    eir: bytes


def parse_mgmt_event(pkt: bytes) -> MgmtEvent | None:
    """Split a raw MGMT packet into (event code, adapter index, params)."""
    if len(pkt) < _MGMT_HEADER.size:
        return None
    code, index, plen = _MGMT_HEADER.unpack_from(pkt, 0)
    params = pkt[_MGMT_HEADER.size : _MGMT_HEADER.size + plen]
    if len(params) < plen:
        return None
    return MgmtEvent(code=code, index=index, params=params)


def parse_device_found(params: bytes) -> DeviceFound | None:
    """
    Parse ``Device Found`` params:
    ``address(6) address_type(1) rssi(1, signed) flags(4, LE) eir_len(2, LE) eir[]``.
    """
    if len(params) < 14:
        return None
    addr = params[0:6]
    addr_type = params[6]
    (rssi,) = struct.unpack_from("b", params, 7)
    (eir_len,) = struct.unpack_from("<H", params, 12)
    eir = params[14 : 14 + eir_len]
    bd_addr = ":".join(f"{b:02X}" for b in reversed(addr))
    return DeviceFound(bd_addr=bd_addr, addr_type=addr_type, rssi=rssi, eir=eir)


def parse_eir_manufacturer(eir: bytes) -> dict[int, bytes]:
    """
    Walk EIR/AD structures and return ``{company_id: payload}`` for every
    Manufacturer Specific Data (AD type 0xFF) entry.

    Handles both flags-prefixed EIR (``02 01 06 06 ff ff ff 42 42 01``) and
    manufacturer-only EIR (``06 ff ff ff 42 42 01``).
    """
    out: dict[int, bytes] = {}
    offset = 0
    n = len(eir)
    while offset < n:
        length = eir[offset]
        if length == 0:
            break
        if offset + 1 + length > n:
            break
        ad_type = eir[offset + 1]
        ad_data = eir[offset + 2 : offset + 1 + length]
        if ad_type == 0xFF and len(ad_data) >= 2:
            company_id = ad_data[0] | (ad_data[1] << 8)
            out[company_id] = bytes(ad_data[2:])
        offset += 1 + length
    return out


def merge_device_found(records: dict[str, ScanDeviceRecord], params: bytes) -> bool:
    """
    Parse one ``Device Found`` params blob and, if it carries a BB beacon,
    upsert a :class:`ScanDeviceRecord` into *records*. Returns True on a BB hit.
    """
    df = parse_device_found(params)
    if df is None:
        return False
    if not match_bb_beacon_in_ad(df.eir):
        return False
    mfg = parse_eir_manufacturer(df.eir)
    existing = records.get(df.bd_addr)
    if existing is None:
        records[df.bd_addr] = ScanDeviceRecord(
            bd_addr=df.bd_addr,
            manufacturer_data=mfg,
            addr_type=_addr_type_label(df.addr_type),
        )
    else:
        existing.manufacturer_data.update(mfg)
        if not existing.addr_type:
            existing.addr_type = _addr_type_label(df.addr_type)
    return True


def records_from_events(packets: Iterable[bytes], *, index: int | None = None) -> dict[str, ScanDeviceRecord]:
    """Aggregate BB :class:`ScanDeviceRecord`s from raw MGMT event packets (test-friendly)."""
    records: dict[str, ScanDeviceRecord] = {}
    for pkt in packets:
        ev = parse_mgmt_event(pkt)
        if ev is None:
            continue
        if index is not None and ev.index != index:
            continue
        if ev.code == MGMT_EV_DEVICE_FOUND:
            merge_device_found(records, ev.params)
    return records


def _open_mgmt_socket() -> socket.socket:
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.setblocking(False)
    sock.bind((HCI_DEV_NONE, HCI_CHANNEL_CONTROL))
    return sock


def _send_cmd(sock: socket.socket, opcode: int, index: int, params: bytes) -> None:
    sock.send(_MGMT_HEADER.pack(opcode, index, len(params)) + params)


def mgmt_scan_records(
    index: int,
    window_s: float,
    *,
    log: Callable[[str], None] | None = None,
    sock: socket.socket | None = None,
) -> dict[str, ScanDeviceRecord]:
    """
    Run one MGMT LE discovery window and return BB beacon records keyed by BD_ADDR.

    Only devices whose EIR contains a valid BB universal presence marker are
    returned, with ``manufacturer_data`` and ``addr_type`` populated straight
    from the on-air EIR — no ``bluetoothctl`` involvement. On any socket error
    the window degrades to an empty result (logged), so the caller keeps polling.
    """
    records: dict[str, ScanDeviceRecord] = {}
    own_sock = sock is None
    try:
        s = _open_mgmt_socket() if own_sock else sock
    except OSError as exc:
        if log is not None:
            log(f"MGMT socket open failed: {exc!r} (need root / CAP_NET_ADMIN?)")
        return records

    try:
        try:
            _send_cmd(s, MGMT_OP_START_DISCOVERY, index, bytes([LE_DISCOVERY_ADDR_MASK]))
        except OSError as exc:
            if log is not None:
                log(f"MGMT start-discovery failed on hci{index}: {exc!r}")
            return records

        deadline = time.monotonic() + max(0.1, float(window_s))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select([s], [], [], remaining)
            except OSError:
                break
            if not ready:
                break
            try:
                pkt = s.recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not pkt:
                break
            ev = parse_mgmt_event(pkt)
            if ev is None or ev.index != index:
                continue
            if ev.code == MGMT_EV_DEVICE_FOUND:
                merge_device_found(records, ev.params)
            elif ev.code == MGMT_EV_CMD_STATUS and len(ev.params) >= 3:
                status, opcode = ev.params[0], (ev.params[1] | (ev.params[2] << 8))
                if opcode == MGMT_OP_START_DISCOVERY and status != 0 and log is not None:
                    log(f"MGMT start-discovery status=0x{status:02x} on hci{index}")

        try:
            _send_cmd(s, MGMT_OP_STOP_DISCOVERY, index, bytes([LE_DISCOVERY_ADDR_MASK]))
        except OSError:
            pass
    finally:
        if own_sock:
            try:
                s.close()
            except OSError:
                pass

    return records
