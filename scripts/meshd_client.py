#!/usr/bin/env python3
"""
Terminal client for meshd — the screen app's protocol, without a screen.

Useful for bringing a board up before its panel arrives, and for scripted
checks across several boards at once:

    python3 scripts/meshd_client.py                          # interactive
    python3 scripts/meshd_client.py --send "hello" --duration 60
    python3 scripts/meshd_client.py --restart   # restart the whole mesh

Runs on the distribution Python: it only speaks to the socket, never to the
adapter, so it needs no root and no 3.14.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.protocol import encode, read_frames, socket_path  # noqa: E402


def _stamp(started: float) -> str:
    return f"[{time.monotonic() - started:7.1f}]"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket", default=socket_path())
    ap.add_argument("--send", default="", help="message to send, then keep listening")
    ap.add_argument("--send-every", type=float, default=0.0, help="repeat period (s)")
    ap.add_argument("--duration", type=float, default=0.0, help="exit after N seconds")
    ap.add_argument("--json-out", default="", help="write a summary here on exit")
    ap.add_argument(
        "--restart",
        action="store_true",
        help="restart BlueZ and meshd on every board reachable through the mesh",
    )
    args = ap.parse_args()

    started = time.monotonic()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(args.socket)
    except OSError as e:
        print(f"cannot reach meshd on {args.socket}: {e}", file=sys.stderr)
        return 1

    if args.restart:
        sock.sendall(encode({"cmd": "restart_mesh", "id": 1}))
        sock.settimeout(5.0)
        for frame in read_frames(sock):
            if frame.get("ev") == "ack":
                ok = frame.get("ok")
                print("redémarrage du mesh lancé" if ok else f"refusé: {frame.get('error')}")
                return 0 if ok else 1
        print("pas de réponse du démon", file=sys.stderr)
        return 1

    received: list[dict] = []
    sent = 0
    local = ""

    def reader() -> None:
        nonlocal local
        for frame in read_frames(sock):
            ev = frame.get("ev")
            if ev == "hello":
                local = frame.get("local", "")
                peers = frame.get("peers", [])
                print(
                    f"{_stamp(started)} connecté local={local} "
                    f"voisins={len(peers)} relay={frame.get('relay')}",
                    flush=True,
                )
            elif ev == "message":
                received.append(frame)
                who = "moi" if frame.get("mine") else frame.get("from", "?")
                print(f"{_stamp(started)} {who}: {frame.get('text','')}", flush=True)
            elif ev == "peers":
                print(
                    f"{_stamp(started)} voisins={len(frame.get('peers', []))} "
                    f"relay={frame.get('relay')}",
                    flush=True,
                )
            elif ev == "ack" and not frame.get("ok", True):
                print(f"{_stamp(started)} envoi refusé: {frame.get('error')}", flush=True)

    threading.Thread(target=reader, daemon=True).start()

    def emit(text: str) -> None:
        nonlocal sent
        sock.sendall(encode({"cmd": "send", "text": text, "id": sent}))
        sent += 1

    deadline = started + args.duration if args.duration else None
    try:
        if args.send:
            emit(args.send)
            while deadline is None or time.monotonic() < deadline:
                if args.send_every:
                    time.sleep(args.send_every)
                    emit(f"{args.send}#{sent}")
                else:
                    time.sleep(0.5)
        else:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    emit(line)
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        summary = {
            "local": local,
            "sent": sent,
            "received": len(received),
            "senders": sorted({f.get("from", "") for f in received if not f.get("mine")}),
        }
        print("\n=== RESUME ===", flush=True)
        print(json.dumps(summary, indent=2), flush=True)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2)
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
