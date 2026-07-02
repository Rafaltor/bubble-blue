#!/usr/bin/env python3.14
"""BLE L2CAP CoC echo server — same stack as ``BLEL2CAPTransport`` / all boards."""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.ble_coc import open_listener, print_board_info  # noqa: E402

print_board_info("server")
s = open_listener(backlog=1)
print("[server] BT_MODE = LE_FLOWCTL OK", flush=True)
print("[server] listening...", flush=True)

conn, addr = s.accept()
print(f"[server] connected by {addr}", flush=True)
while True:
    data = conn.recv(1024)
    if not data:
        print("[server] peer closed", flush=True)
        break
    print(f"[server] GOT {len(data)} bytes: {data!r}", flush=True)
    conn.send(b"ACK " + data)
conn.close()
s.close()
