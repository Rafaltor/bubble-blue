#!/usr/bin/env python3.14
"""BLE L2CAP CoC echo client — same stack as ``BLEL2CAPTransport`` / all boards."""
from __future__ import annotations

import os
import sys
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.ble_coc import open_outbound, print_board_info  # noqa: E402

SERVER_ADDR = os.environ.get("COC_SERVER_ADDR", "9C:B8:B4:9F:2D:75")

print_board_info("client", server=SERVER_ADDR)
s = open_outbound(SERVER_ADDR)
print("[client] BT_MODE = LE_FLOWCTL OK", flush=True)
print("[client] connected", flush=True)

for i in range(3):
    payload = f"MSG-{i} from client".encode()
    n = s.send(payload)
    print(f"[client] sent #{i}: {n} bytes", flush=True)
    resp = s.recv(1024)
    print(f"[client] echo: {resp!r}", flush=True)
    time.sleep(1)

s.close()
print("[client] closed", flush=True)
