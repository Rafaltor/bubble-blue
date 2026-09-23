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

# Control plane timing.
#
# A node is dropped only after several *consecutive* missed Hellos, never on the
# first one: losing a single advertisement is routine on a shared 2.4 GHz band,
# and reacting to it would churn the CDS — re-electing relays and tearing down
# links for a neighbour that never actually left.
#
# The departure delay is therefore expressed as a count of missed periods rather
# than a bare number of seconds, so it keeps its meaning when the Hello interval
# is retuned. Defaults give 5 s x 3 = 15 s.
DEFAULT_HELLO_INTERVAL_S = 5
DEFAULT_HELLO_MISSES = 3

# Kernels carrying 6c3ea155e5ee ("L2CAP: Fix not tracking outstanding TX ident")
# but not its fix 6e1930ece855 never release the ident of an LE Flow Control
# Credit, which is sent for every received PDU. After 254 of them on one ACL the
# channel stalls ("Unable to allocate ident: -28"). The only userspace cure is to
# drop the ACL before that, so links are recycled after this many credits.
# Observed on the UNO Q (7.0.0); the Rubik (6.8) is unaffected.
L2CAP_IDENT_LEAK_SINCE = (6, 12)
DEFAULT_L2CAP_IDENT_BUDGET = 200

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
    hello_misses: int          # consecutive missed Hellos before dropping a node
    neighbor_timeout_s: int    # derived: hello_interval_s * hello_misses

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


def _env_int(name: str, default: int, *, minimum: int) -> int:
    """Read a positive integer from the environment, warning instead of failing.

    A typo in .env must not stop a board from joining the mesh — it is far more
    useful to run with the default and say so.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"[BB] WARNING: {name}={raw!r} is not an integer, using {default}", flush=True)
        return default
    if value < minimum:
        print(f"[BB] WARNING: {name}={value} is below {minimum}, using {minimum}", flush=True)
        return minimum
    return value


def _kernel_version(release: str) -> tuple[int, int]:
    m = re.match(r"(\d+)\.(\d+)", release)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def l2cap_ident_budget(release: str | None = None) -> int:
    """Credits a BLE link may receive before it is recycled; 0 disables recycling.

    ``BUBBLE_BLUE_L2CAP_IDENT_BUDGET`` overrides the kernel-version guess — set it
    to 0 once a board runs a kernel with 6e1930ece855, whose version alone cannot
    tell (the fix is being backported to stable series).
    """
    if release is None:
        release = os.uname().release
    affected = _kernel_version(release) >= L2CAP_IDENT_LEAK_SINCE
    default = DEFAULT_L2CAP_IDENT_BUDGET if affected else 0
    return min(_env_int("BUBBLE_BLUE_L2CAP_IDENT_BUDGET", default, minimum=0), 240)


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

    hello_interval_s = _env_int(
        "BUBBLE_BLUE_HELLO_INTERVAL_S", DEFAULT_HELLO_INTERVAL_S, minimum=1
    )
    # 1 would mean dropping a node on a single lost packet, which is the
    # instability this threshold exists to avoid.
    hello_misses = _env_int("BUBBLE_BLUE_HELLO_MISSES", DEFAULT_HELLO_MISSES, minimum=2)

    return BubbleBlueConfig(
        psm=psm,
        local_bd_addr=local,
        remote_bd_addr=remote_n,
        transport_kind=transport_kind,
        node_name=socket.gethostname(),
        hello_interval_s=hello_interval_s,
        hello_misses=hello_misses,
        neighbor_timeout_s=hello_interval_s * hello_misses,
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
            f"- Missed Hellos allowed: {cfg.hello_misses}",
            f"- Neighbor timeout (s) : {cfg.neighbor_timeout_s} "
            f"({cfg.hello_interval_s} x {cfg.hello_misses})",
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
