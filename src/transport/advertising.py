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
import struct
import subprocess
import threading
from collections.abc import Iterable
from typing import Callable

# ASCII magic in Manufacturer Specific Data — reusable by scanners.
BB_BEACON_MAGIC = b"BB"
BB_BEACON_PROTOCOL_VERSION = 0x01
BB_BEACON_COMPANY_ID = 0xFFFF

# Flags AD: length 2, type 0x01, value 0x06 (LE General Discoverable + BR/EDR Not Supported).
_FLAGS_AD = bytes([0x02, 0x01, 0x06])

# Manufacturer Specific Data AD: company ID 0xFFFF (LE) + magic + protocol version.
_MFG_AD_STRUCTURE = (
    bytes([0x06, 0xFF])
    + BB_BEACON_COMPANY_ID.to_bytes(2, "little")
    + BB_BEACON_MAGIC
    + bytes([BB_BEACON_PROTOCOL_VERSION])
)

# On-air AD (Flags + Manufacturer) — scanners / match_bb_beacon_in_ad.
BB_BEACON_AD: bytes = _FLAGS_AD + _MFG_AD_STRUCTURE

# btmgmt add-adv -d payload only: kernel mgmt sets Flags itself (type 0x01 rejected).
BB_BEACON_ADV_DATA: bytes = _MFG_AD_STRUCTURE


def build_bb_beacon_ad() -> bytes:
    """Return the full on-air AD bytes (Flags + Manufacturer Specific Data)."""
    return BB_BEACON_AD


def build_bb_beacon_adv_data() -> bytes:
    """Return Manufacturer Specific Data for ``btmgmt add-adv -d``."""
    return BB_BEACON_ADV_DATA


def bb_beacon_ad_hex() -> str:
    """Hex string for ``btmgmt add-adv -d <hex>`` (Manufacturer data only)."""
    return BB_BEACON_ADV_DATA.hex()


# Largest company VALUE that fits a legacy connectable advertisement: the 31-byte
# AD budget minus the manufacturer AD header (length + type 0xFF + 2-byte company).
LEGACY_PRESENCE_MAX_VALUE_LEN = 31 - 4


def manufacturer_adv_data_hex(value: bytes) -> str:
    """
    Build the ``btmgmt add-adv -d`` hex for a Manufacturer Specific Data VALUE.

    ``value`` is the company payload (bytes after the 2-byte company id). Wraps it
    in one AD structure: ``[len][0xFF][company-id LE][value]``.
    """
    ad = (
        bytes([1 + 2 + len(value), 0xFF])
        + BB_BEACON_COMPANY_ID.to_bytes(2, "little")
        + bytes(value)
    )
    return ad.hex()


# ---------------------------------------------------------------------------
# Connectionless public Hello carried in Manufacturer Specific Data.
#
# Broadcasting the public Hello (anon_id + advertised 1-hop neighbors + MPR set)
# lets every node build the mesh topology and run the CDS election WITHOUT any
# L2CAP connection — presence is learned from the air, exactly like the beacon.
# The full payload (with neighbor/MPR lists) exceeds the 31-byte legacy AD limit.
# Production therefore uses the *compact* form (anon_id + flags + reachable
# bd_addr, empty lists) that fits ``LEGACY_PRESENCE_MAX_VALUE_LEN``: every
# scanner — legacy or extended — can hear presence and dial. Neighbor/MPR lists
# are empty in compact AD; empty-CDS dial uses a sparse anon_id ring (not full mesh).
#
# Layout of the manufacturer VALUE (the bytes AFTER the 2-byte company id, i.e.
# what ``parse_eir_manufacturer`` returns for company 0xFFFF):
#   BB_BEACON_MAGIC            (2)  b"BB"   ] identical to the plain beacon, so
#   BB_BEACON_PROTOCOL_VERSION (1)  0x01    ] match_bb_beacon_in_ad still matches
#   PRESENCE_FORMAT_VERSION    (1)  0x02    -> presence extension marker
#   anon_id                    (8)
#   seq                        (4, big-endian)
#   flags                      (1)  bit0 = CDS relay (RELAY role), other bits reserved
#   bd_addr                    (6)  reachable L2CAP address (big-endian, 00..00 = none)
#   n_neighbors                (1)
#   neighbor_anon_ids          (8 * n_neighbors)
#   n_mpr                      (1)
#   mpr_anon_ids               (8 * n_mpr)
#
# The bd_addr field is what makes the presence beacon self-contained: a
# non-connectable ("broadcast") advert rotates its transport-layer source
# address (RPA), so a scanner cannot derive a peer's connectable L2CAP address
# from the packet. The Hello therefore states it explicitly.
# ---------------------------------------------------------------------------
ANON_ID_SIZE = 8
BD_ADDR_SIZE = 6
PRESENCE_FORMAT_VERSION = 0x02
PRESENCE_FLAG_RELAY = 0x01
_PRESENCE_PREFIX = BB_BEACON_MAGIC + bytes([BB_BEACON_PROTOCOL_VERSION, PRESENCE_FORMAT_VERSION])
# Max manufacturer VALUE the controller accepts, leaving room for the company id
# (2) + the AD length/type (2) inside the 251-byte extended AD budget.
_MAX_PRESENCE_VALUE_LEN = 247


def _coerce_anon_id(anon_id: bytes) -> bytes:
    b = bytes(anon_id)
    if len(b) != ANON_ID_SIZE:
        raise ValueError(f"anon_id must be {ANON_ID_SIZE} bytes, got {len(b)}")
    return b


def _bd_addr_to_bytes(bd_addr: str | None) -> bytes:
    """Pack ``AA:BB:CC:DD:EE:FF`` into 6 big-endian bytes; None/blank -> zeros."""
    if not bd_addr:
        return bytes(BD_ADDR_SIZE)
    parts = bd_addr.strip().split(":")
    if len(parts) != BD_ADDR_SIZE:
        return bytes(BD_ADDR_SIZE)
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        return bytes(BD_ADDR_SIZE)


def _bytes_to_bd_addr(raw: bytes) -> str | None:
    """Unpack 6 bytes into ``AA:BB:CC:DD:EE:FF``; all-zero -> None (unset)."""
    if len(raw) != BD_ADDR_SIZE or not any(raw):
        return None
    return ":".join(f"{b:02X}" for b in raw)


def build_presence_manufacturer_value(
    anon_id: bytes,
    seq: int,
    neighbor_anon_ids: Iterable[bytes],
    mpr_anon_ids: Iterable[bytes] = (),
    *,
    is_relay: bool = False,
    bd_addr: str | None = None,
    max_value_len: int = _MAX_PRESENCE_VALUE_LEN,
) -> bytes:
    """
    Encode a public Hello into the Manufacturer Specific Data VALUE (company 0xFFFF).

    Neighbor and MPR lists are truncated (MPRs then neighbors) so the value stays
    within ``max_value_len``; callers should pass the most relevant neighbors first.
    Pass ``max_value_len=LEGACY_PRESENCE_MAX_VALUE_LEN`` for a compact Hello that
    fits a legacy 31-byte advertisement (readable by legacy-only scanners); the
    fixed header alone (anon_id + seq + flags + bd_addr) already fits, so the lists
    simply drop to empty. anon_ids must be 8 bytes each. ``is_relay`` advertises
    this node's CDS role. ``bd_addr`` is this node's reachable L2CAP address so
    peers can dial it even when the beacon rides a rotating source address.
    """
    local = _coerce_anon_id(anon_id)
    if not (0 <= int(seq) <= 0xFFFFFFFF):
        raise ValueError("seq must fit in uint32")
    neighbors = [_coerce_anon_id(a) for a in neighbor_anon_ids]
    mprs = [_coerce_anon_id(a) for a in mpr_anon_ids]

    flags = PRESENCE_FLAG_RELAY if is_relay else 0x00
    head = _PRESENCE_PREFIX + local + struct.pack("!LB", int(seq), flags) + _bd_addr_to_bytes(bd_addr)

    def _assemble(nbrs: list[bytes], mp: list[bytes]) -> bytes:
        out = head + bytes([len(nbrs)])
        for a in nbrs:
            out += a
        out += bytes([len(mp)])
        for a in mp:
            out += a
        return out

    budget = int(max_value_len)
    value = _assemble(neighbors, mprs)
    # Drop MPRs first, then neighbors, until the value fits the controller budget.
    while len(value) > budget and mprs:
        mprs.pop()
        value = _assemble(neighbors, mprs)
    while len(value) > budget and neighbors:
        neighbors.pop()
        value = _assemble(neighbors, mprs)
    return value


def parse_presence_manufacturer_value(value: bytes) -> dict | None:
    """
    Decode a presence Hello from a Manufacturer VALUE (company 0xFFFF payload).

    Returns ``{"anon_id", "seq", "is_relay", "bd_addr", "neighbors": [8b...],
    "mpr": [8b...]}`` or ``None`` if the value is a plain beacon / not a
    well-formed presence Hello. Never raises on malformed input — unknown or
    truncated payloads simply yield ``None`` so the scanner can keep polling
    untrusted air data.
    """
    if len(value) < len(_PRESENCE_PREFIX):
        return None
    if value[: len(_PRESENCE_PREFIX)] != _PRESENCE_PREFIX:
        return None
    off = len(_PRESENCE_PREFIX)
    if len(value) < off + ANON_ID_SIZE + 4 + 1 + BD_ADDR_SIZE + 1:
        return None
    anon_id = value[off : off + ANON_ID_SIZE]
    off += ANON_ID_SIZE
    (seq, flags) = struct.unpack_from("!LB", value, off)
    off += 5
    bd_addr = _bytes_to_bd_addr(value[off : off + BD_ADDR_SIZE])
    off += BD_ADDR_SIZE
    n = value[off]
    off += 1
    if len(value) < off + n * ANON_ID_SIZE + 1:
        return None
    neighbors = [value[off + i * ANON_ID_SIZE : off + (i + 1) * ANON_ID_SIZE] for i in range(n)]
    off += n * ANON_ID_SIZE
    m = value[off]
    off += 1
    if len(value) < off + m * ANON_ID_SIZE:
        return None
    mprs = [value[off + i * ANON_ID_SIZE : off + (i + 1) * ANON_ID_SIZE] for i in range(m)]
    return {
        "anon_id": bytes(anon_id),
        "seq": int(seq),
        "is_relay": bool(flags & PRESENCE_FLAG_RELAY),
        "bd_addr": bd_addr,
        "neighbors": neighbors,
        "mpr": mprs,
    }


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

    _ADVINFO_INSTANCE_RE = re.compile(r"^\s*Instance:\s*(\d+)\s*$", re.MULTILINE | re.IGNORECASE)
    _ADVINFO_COUNT_RE = re.compile(
        r"Instances list with (\d+) item",
        re.IGNORECASE,
    )

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
        # Company payload currently advertised (after the 2-byte company id).
        # Defaults to the plain beacon; set_value() swaps in the presence Hello.
        self._value = BB_BEACON_MAGIC + bytes([BB_BEACON_PROTOCOL_VERSION])

    def ad_hex(self) -> str:
        """``btmgmt add-adv -d`` hex for the current manufacturer VALUE."""
        return manufacturer_adv_data_hex(self._value)

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

    def ensure(self) -> None:
        """Re-arm the advertising instance if the controller dropped it."""
        if not self._started:
            return
        try:
            self._ensure_instance(force=False)
        except Exception as exc:
            self._log(f"ensure error: {exc}")

    def set_value(self, value: bytes) -> None:
        """
        Replace the advertised Manufacturer Specific Data VALUE and re-arm.

        ``value`` is the company payload (the bytes after the 2-byte company id),
        e.g. the compact connectionless presence Hello. It must start with the BB
        beacon magic so ``match_bb_beacon_in_ad`` still recognises us. Re-arming
        via ``rm-adv``+``add-adv`` is how bluetoothd/btmgmt swaps a legacy payload.
        """
        value = bytes(value)
        if value == self._value:
            return
        self._value = value
        if self._started:
            try:
                self._ensure_instance(force=True)
            except Exception as exc:  # noqa: BLE001
                self._log(f"set_value error: {exc}")

    def _prepare_controller(self) -> None:
        self._run(self._hci_index, "power on")
        self._run(self._hci_index, "le on")

    def _remove_instance(self) -> None:
        self._run(self._hci_index, f"rm-adv {self._instance_id}")

    def _add_instance(self) -> bool:
        result = self._run(
            self._hci_index,
            f"add-adv -c -d {self.ad_hex()} {self._instance_id}",
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            if err and not self._quiet:
                self._log(f"add-adv failed: {err}")
            return False
        return True

    def _instance_present(self) -> bool:
        advinfo = self._run(self._hci_index, "advinfo")
        if advinfo.returncode == 0 and self._instance_present_in_advinfo(advinfo.stdout or ""):
            return True
        info = self._run(self._hci_index, "info")
        if info.returncode == 0 and self._instance_present_in_info(info.stdout or ""):
            return True
        return False

    def _instance_present_in_advinfo(self, text: str) -> bool:
        """True when ``btmgmt advinfo`` reports our advertising instance."""
        instances = [int(m.group(1)) for m in self._ADVINFO_INSTANCE_RE.finditer(text)]
        if instances:
            return self._instance_id in instances
        count_match = self._ADVINFO_COUNT_RE.search(text)
        if count_match and int(count_match.group(1)) >= 1:
            # Single-instance deployments: count-only advinfo (stock BlueZ) implies id 1.
            return self._instance_id == 1
        return False

    @staticmethod
    def _instance_present_in_info(text: str) -> bool:
        """Fallback: ``current settings`` includes ``advertising``."""
        for line in text.splitlines():
            if "current settings:" in line.casefold():
                return "advertising" in line.casefold()
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
