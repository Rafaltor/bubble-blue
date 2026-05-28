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


@dataclass(frozen=True)
class BubbleBlueConfig:
    # L2CAP
    psm: int  # L2CAP PSM
    local_bd_addr: str
    remote_bd_addr: str

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


def _load_group_members() -> list[str]:
    """Load group member BD addresses from env."""
    raw = os.environ.get("BUBBLE_BLUE_GROUP_MEMBERS", "")
    if not raw:
        return []
    return [addr.strip().upper() for addr in raw.split(",") if addr.strip()]


def get_local_bd_addr(interface: str = "hci0") -> str:
    """
    Reads the local controller BD address dynamically via `hciconfig hci0`.
    """
    try:
        proc = subprocess.run(
            ["hciconfig", interface],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`hciconfig` not found. Install BlueZ tools and ensure it is in PATH.") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        raise RuntimeError(f"`hciconfig {interface}` failed{': ' + stderr if stderr else ''}.") from e

    m = _BD_ADDR_RE.search(proc.stdout or "")
    if not m:
        out = (proc.stdout or "").strip()
        raise RuntimeError(f"Could not parse BD Address from `hciconfig {interface}` output.\n{out}")
    return m.group(1).upper()


def load_config(
    *,
    remote_bd_addr: str | None = None,
    interface: str = "hci0",
) -> BubbleBlueConfig:
    return BubbleBlueConfig(
        psm=0x1001,
        local_bd_addr=get_local_bd_addr(interface=interface),
        remote_bd_addr=(remote_bd_addr or DEFAULT_REMOTE_BD_ADDR).upper(),
        node_name=socket.gethostname(),
        hello_interval_s=5,
        neighbor_timeout_s=15,
        ttl_max=10,
        group_key=_load_group_key(),
        group_members=_load_group_members(),
        replay_window=256,
    )


def format_config(cfg: BubbleBlueConfig) -> str:
    return "\n".join(
        [
            "=== BUBBLE-BLUE configuration ===",
            f"- Node name            : {cfg.node_name}",
            f"- L2CAP PSM            : 0x{cfg.psm:04X} ({cfg.psm})",
            f"- Local BD address     : {cfg.local_bd_addr}",
            f"- Remote BD address    : {cfg.remote_bd_addr}",
            f"- Hello interval (s)   : {cfg.hello_interval_s}",
            f"- Neighbor timeout (s) : {cfg.neighbor_timeout_s}",
            f"- TTL max              : {cfg.ttl_max}",
            f"- Group key            : {'SET' if cfg.group_key else 'NOT SET'}",
            f"- Group members        : {len(cfg.group_members)} nodes",
            f"- Replay window        : {cfg.replay_window}",
        ]
    )


def print_config(cfg: BubbleBlueConfig | None = None) -> BubbleBlueConfig:
    cfg = cfg or load_config()
    print(format_config(cfg), flush=True)
    return cfg


if __name__ == "__main__":
    print_config()
