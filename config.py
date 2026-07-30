from __future__ import annotations

import os
import re
import socket
import subprocess
from dataclasses import dataclass


# Packet types
PKT_HELLO = 0x01
PKT_DATA  = 0x02
PKT_ACK   = 0x03
PKT_SUBGROUP = 0x04
PKT_REKEY   = 0x05
PKT_ANNOUNCE = 0x06
PKT_REKEY_FLOOD = 0x07
# Preprint §2.3.2 / §2.4.3: request retransmission of (originator, seq).
PKT_ARQ = 0x08

# ARQ / CDS replay cache (Blue_Bubble_specs.pdf)
ARQ_CACHE_MAX = 256
ARQ_CACHE_TTL_S = 300.0
ARQ_MAX_RETRIES = 3
ARQ_RETRY_INTERVAL_S = 1.5

# BLE cannot sustain a full mesh: soft cap on live L2CAP links.
MAX_L2CAP_DEGREE = 3
# Each node dials the next N *higher* anon_ids (no wrap). That yields a
# connected DAG toward the max id — one dialer per edge, no dual-dial flaps.
# count=1 partitions when presence catalogs differ slightly across boards.
SPARSE_RING_SUCCESSORS = 2

# Network-wide pubkey announce (complement to Hello private, 2-hop limited)
ANNOUNCE_INTERVAL_S = 30
ANNOUNCE_BURST_COUNT = 3
ANNOUNCE_BURST_GAP_S = 2.0

# L2CAP protocol service multiplexors
PSM_BT_CLASSIC = 0x1001
PSM_BLE = 0x0081  # LE CoC PSM (dynamic range 0x80–0xFF; validated on hardware)

# Prudent L2CAP/CoC MTU per transport (full BB wire frame including header + tag).
MTU_BT_CLASSIC = 1021
MTU_BLE = 512

# Security
AES_KEY_SIZE = 32      # bytes
AES_NONCE_SIZE = 12    # bytes  
AES_TAG_SIZE = 16      # bytes
SESSION_KEY_SIZE = 32  # bytes
ENC_SESSION_KEY_SIZE = 60  # nonce(12) + ciphertext(32) + tag(16)


def _load_dotenv(path: str = ".env") -> None:
    """
    Minimal .env loader (no external dependency).
    - Ignores empty lines and comments
    - Supports KEY=VALUE with optional single/double quotes
    - Does not override already-defined environment variables
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        return


_load_dotenv()

DEFAULT_REMOTE_BD_ADDR = os.environ.get("BUBBLE_BLUE_REMOTE_BD_ADDR", "00:00:00:00:00:00")
_DEFAULT_INTERFACE = os.environ.get("BUBBLE_BLUE_INTERFACE", "hci0")
_BD_ADDR_ENV_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


_VALID_TRANSPORT_KINDS = frozenset({"bt_classic", "ble_l2cap"})


@dataclass(frozen=True)
class BubbleBlueConfig:
    # L2CAP
    psm: int  # L2CAP PSM (PSM_BT_CLASSIC or PSM_BLE depending on transport_kind)
    local_bd_addr: str
    remote_bd_addr: str
    transport_kind: str  # "bt_classic" | "ble_l2cap"

    # Node identity / control plane timers
    node_name: str
    hello_interval_s: int
    neighbor_timeout_s: int

    # Forwarding
    ttl_max: int

    # Security
    group_key: bytes          # 32-byte AES-256 key
    group_members: list[str]  # list of BD addresses in group
    replay_window: int        # anti-replay window size


_BD_ADDR_RE = re.compile(r"BD Address:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _load_group_key() -> bytes:
    """Load group key from BUBBLE_BLUE_GROUP_KEY env var.
    Falls back to a random key if not set (dev mode only).
    Prints a warning if using random key."""
    hex_key = os.environ.get("BUBBLE_BLUE_GROUP_KEY", "")
    if not hex_key or hex_key == "0" * 64:
        import secrets as _secrets
        key = _secrets.token_bytes(32)
        print("[BB] WARNING: No group key set. Using random key (dev mode only!)", flush=True)
        print("[BB] Set BUBBLE_BLUE_GROUP_KEY in .env to fix this.", flush=True)
        return key
    try:
        key = bytes.fromhex(hex_key)
        if len(key) != 32:
            raise ValueError("Group key must be 32 bytes (64 hex chars)")
        return key
    except ValueError as e:
        raise RuntimeError(f"Invalid BUBBLE_BLUE_GROUP_KEY: {e}") from e


def _normalize_bd_addr(addr: str, *, label: str) -> str | None:
    a = addr.strip().upper()
    if not a or a == "00:00:00:00:00:00":
        return None
    if not _BD_ADDR_ENV_RE.match(a):
        print(f"[BB] WARNING: ignoring invalid {label}: {addr!r}", flush=True)
        return None
    return a


def _load_group_members(*, local_bd_addr: str | None = None) -> list[str]:
    """Peers to dial / allowlist from BUBBLE_BLUE_GROUP_MEMBERS (excludes local)."""
    return _parse_group_members_env(exclude_local=local_bd_addr)


def _parse_group_members_env(*, exclude_local: str | None = None) -> list[str]:
    """Parse BUBBLE_BLUE_GROUP_MEMBERS; optionally skip the local BD_ADDR (for outbound dial)."""
    raw = os.environ.get("BUBBLE_BLUE_GROUP_MEMBERS", "")
    if not raw:
        return []
    local = (exclude_local or "").upper()
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        bd = _normalize_bd_addr(part, label="BUBBLE_BLUE_GROUP_MEMBERS entry")
        if bd is None or bd == local or bd in seen:
            continue
        seen.add(bd)
        out.append(bd)
    return out


def _load_transport_kind() -> str:
    raw = os.environ.get("BUBBLE_BLUE_TRANSPORT", "bt_classic").strip().lower()
    if raw in _VALID_TRANSPORT_KINDS:
        return raw
    print(
        f"[BB] WARNING: unknown BUBBLE_BLUE_TRANSPORT={raw!r}, using bt_classic",
        flush=True,
    )
    return "bt_classic"


def mtu_for_transport(transport_kind: str) -> int:
    """L2CAP/CoC MTU for a full on-wire BB frame (routing header + ciphertext + tag)."""
    k = transport_kind.strip().lower()
    if k == "ble_l2cap":
        return MTU_BLE
    return MTU_BT_CLASSIC


def max_payload(transport_kind: str) -> int:
    """
    Maximum plaintext bytes per PKT_DATA message for ``transport_kind``.

    Wire size = routing header (26) + plaintext + GCM tag (16) = plaintext + 42.
    BLE (512 MTU) → 470 B (~470 ASCII chat characters). BT Classic unchanged at 979 B.
    """
    from src.security.packet import packet_overhead

    return mtu_for_transport(transport_kind) - packet_overhead()


def get_hciconfig_bd_addr(interface: str | None = None) -> str:
    """BD_ADDR from the controller only (ignores BUBBLE_BLUE_LOCAL_BD_ADDR override)."""
    iface = interface or _DEFAULT_INTERFACE
    try:
        proc = subprocess.run(
            ["hciconfig", iface],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`hciconfig` not found. Install BlueZ tools and ensure it is in PATH.") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        raise RuntimeError(f"`hciconfig {iface}` failed{': ' + stderr if stderr else ''}.") from e

    m = _BD_ADDR_RE.search(proc.stdout or "")
    if not m:
        out = (proc.stdout or "").strip()
        raise RuntimeError(f"Could not parse BD Address from `hciconfig {iface}` output.\n{out}")
    return m.group(1).upper()


def config_warnings(*, interface: str | None = None) -> list[str]:
    """Human-readable warnings about common .env mistakes (copy-paste across boards)."""
    warnings: list[str] = []
    override = os.environ.get("BUBBLE_BLUE_LOCAL_BD_ADDR", "").strip()
    if override:
        try:
            hci = get_hciconfig_bd_addr(interface)
            norm = _normalize_bd_addr(override, label="BUBBLE_BLUE_LOCAL_BD_ADDR")
            if norm and norm != hci:
                warnings.append(
                    f"BUBBLE_BLUE_LOCAL_BD_ADDR={norm} but hciconfig reports {hci} — "
                    "remove the override or set it to this board's real address"
                )
        except RuntimeError:
            pass

    try:
        local = get_local_bd_addr(interface=interface)
    except RuntimeError:
        local = ""

    raw_members = os.environ.get("BUBBLE_BLUE_GROUP_MEMBERS", "")
    for part in raw_members.split(","):
        bd = _normalize_bd_addr(part, label="BUBBLE_BLUE_GROUP_MEMBERS entry")
        if bd and local and bd == local:
            warnings.append(
                f"GROUP_MEMBERS lists this board's own address ({bd}) — "
                "list only the *other* boards (run python3 config.py on each)"
            )
            break

    return warnings


def get_local_bd_addr(interface: str | None = None) -> str:
    """
    Local controller BD_ADDR: BUBBLE_BLUE_LOCAL_BD_ADDR, else `hciconfig <interface>`.
    """
    override = os.environ.get("BUBBLE_BLUE_LOCAL_BD_ADDR", "").strip()
    if override:
        bd = _normalize_bd_addr(override, label="BUBBLE_BLUE_LOCAL_BD_ADDR")
        if bd is not None:
            return bd

    iface = interface or _DEFAULT_INTERFACE
    try:
        proc = subprocess.run(
            ["hciconfig", iface],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`hciconfig` not found. Install BlueZ tools and ensure it is in PATH.") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        raise RuntimeError(f"`hciconfig {iface}` failed{': ' + stderr if stderr else ''}.") from e

    m = _BD_ADDR_RE.search(proc.stdout or "")
    if not m:
        out = (proc.stdout or "").strip()
        raise RuntimeError(f"Could not parse BD Address from `hciconfig {iface}` output.\n{out}")
    return m.group(1).upper()


def load_config(
    *,
    remote_bd_addr: str | None = None,
    interface: str | None = None,
) -> BubbleBlueConfig:
    iface = interface or _DEFAULT_INTERFACE
    local = get_local_bd_addr(interface=iface)
    remote = remote_bd_addr or DEFAULT_REMOTE_BD_ADDR
    remote_n = _normalize_bd_addr(remote, label="remote BD_ADDR") or "00:00:00:00:00:00"
    transport_kind = _load_transport_kind()
    psm = PSM_BLE if transport_kind == "ble_l2cap" else PSM_BT_CLASSIC
    return BubbleBlueConfig(
        psm=psm,
        local_bd_addr=local,
        remote_bd_addr=remote_n,
        transport_kind=transport_kind,
        node_name=socket.gethostname(),
        hello_interval_s=5,
        neighbor_timeout_s=15,
        ttl_max=10,
        group_key=_load_group_key(),
        group_members=_load_group_members(local_bd_addr=local),
        replay_window=256,
    )


def format_config(cfg: BubbleBlueConfig) -> str:
    return "\n".join(
        [
            "=== BUBBLE-BLUE configuration ===",
            f"- Node name            : {cfg.node_name}",
            f"- Transport            : {cfg.transport_kind}",
            f"- L2CAP PSM            : 0x{cfg.psm:04X} ({cfg.psm})",
            f"- Local BD address     : {cfg.local_bd_addr}",
            f"- Remote BD address    : {cfg.remote_bd_addr}",
            f"- Hello interval (s)   : {cfg.hello_interval_s}",
            f"- Neighbor timeout (s) : {cfg.neighbor_timeout_s}",
            f"- TTL max              : {cfg.ttl_max}",
            f"- Group key            : {'SET' if cfg.group_key else 'NOT SET'}",
            f"- Group members        : {', '.join(cfg.group_members) or '(none — use --topology or .env)'}",
            f"- Replay window        : {cfg.replay_window}",
        ]
    )


def print_config(cfg: BubbleBlueConfig | None = None) -> BubbleBlueConfig:
    cfg = cfg or load_config()
    print(format_config(cfg), flush=True)
    return cfg


if __name__ == "__main__":
    print_config()
