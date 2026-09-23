"""
Daemon-to-daemon control messages, carried inside the group chat plane.

They ride ordinary encrypted broadcasts, so they get the mesh's flooding,
dedup, replay protection and group authentication for free — and anyone who
could forge one could already post to the group. A reserved prefix that no
on-screen button or keyboard can produce keeps them out of the chat:

    topo     a node's own L2CAP links, so every screen can draw the whole mesh
             (Hellos only ever reach direct neighbours)
    restart  every daemon restarts BlueZ and itself — the demo stand's
             "turn it off and on again", reachable from a single board
"""

from __future__ import annotations

import json
import os

CONTROL_PREFIX = "\x1ebb/"

KIND_SCREEN = "screen"
KIND_RELAY = "relay"

_NAMES_FILE = os.path.join(os.path.dirname(__file__), "node_names.txt")


def encode_control(msg_type: str, /, **fields) -> str:
    body = dict(fields, t=msg_type)
    return CONTROL_PREFIX + json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def decode_control(text: str) -> dict | None:
    """The control body, or None for an ordinary chat message."""
    if not text.startswith(CONTROL_PREFIX):
        return None
    try:
        body = json.loads(text[len(CONTROL_PREFIX):])
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def load_node_names(path: str | None = None) -> dict[str, tuple[str, str]]:
    """BD address -> (kind, display name), from ``apps/node_names.txt``."""
    path = path or os.environ.get("BUBBLE_BLUE_NODE_NAMES", _NAMES_FILE)
    names: dict[str, tuple[str, str]] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                parts = line.split(None, 2)
                if len(parts) == 3:
                    names[parts[0].upper()] = (parts[1], parts[2].strip())
    except OSError:
        pass
    return names
