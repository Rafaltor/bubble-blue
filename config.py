from __future__ import annotations

import os
import re
import socket
import subprocess
from dataclasses import dataclass


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


_BD_ADDR_RE = re.compile(r"BD Address:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


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
        ]
    )


def print_config(cfg: BubbleBlueConfig | None = None) -> BubbleBlueConfig:
    cfg = cfg or load_config()
    print(format_config(cfg), flush=True)
    return cfg


if __name__ == "__main__":
    print_config()
