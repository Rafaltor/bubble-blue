"""
Wire format between the mesh daemon and the screen UI.

The two processes cannot share an interpreter: the mesh needs Python 3.14 for
LE L2CAP sockets, while PyGObject only exists for the distribution Python. So
they talk newline-delimited JSON over an AF_UNIX stream instead, which keeps
this module the only thing both interpreters import — plain stdlib, no syntax
newer than the older of the two.

Events flow daemon -> UI, commands flow UI -> daemon:

    {"ev": "hello",   "local": str, "relay": bool, "epoch": int,
                      "peers": [str], "history": [message, ...]}
    {"ev": "message", "from": str, "text": str, "ts": float, "mine": bool}
    {"ev": "peers",   "peers": [str], "relay": bool}
    {"ev": "log",     "text": str, "error": bool}

    {"cmd": "send", "text": str, "id": int}
    {"ev": "ack",   "id": int, "ok": bool, "error": str}
"""

from __future__ import annotations

import json
import os
import socket

DEFAULT_SOCKET = "/run/bubble-blue/meshd.sock"

# Long enough that a UI restart still shows a useful conversation, short enough
# that the daemon never grows without bound on a board left running for weeks.
HISTORY_LIMIT = 200

_READ_CHUNK = 65536

# A UI that stops reading must not be able to stall the mesh callbacks, so the
# daemon drops a client once this many frames are queued for it.
CLIENT_QUEUE_LIMIT = 256


def encode(obj: dict) -> bytes:
    """Serialise one frame. Never emits a bare newline inside the payload."""
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def read_frames(sock: socket.socket):
    """
    Yield decoded frames from ``sock`` until the peer closes.

    Malformed lines are skipped rather than fatal: a desynchronised client
    should not be able to take the daemon down.
    """
    buf = b""
    while True:
        try:
            chunk = sock.recv(_READ_CHUNK)
        except (ConnectionResetError, OSError):
            return
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue


def socket_path() -> str:
    return os.environ.get("BUBBLE_BLUE_SOCKET", DEFAULT_SOCKET)
