from __future__ import annotations

import argparse
import sys
import threading
import time

from config import load_config, print_config
from src.transport.l2cap import L2CAPTransport


def main() -> int:
    parser = argparse.ArgumentParser(description="BUBBLE-BLUE node (simple L2CAP ping/echo test)")
    parser.add_argument(
        "--peer",
        help="Remote peer BD_ADDR (e.g. 40:D9:5A:8B:69:3F). If omitted, only listens.",
        default=None,
    )
    parser.add_argument(
        "--message",
        help="Message to send (utf-8). If omitted and --peer is set, reads from stdin.",
        default=None,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.0,
        help="If > 0, sends message every N seconds (requires --peer and --message).",
    )
    parser.add_argument(
        "--interface",
        default="hci0",
        help="Bluetooth interface for local BD address lookup (default: hci0).",
    )
    args = parser.parse_args()

    cfg = load_config(interface=args.interface, remote_bd_addr=args.peer)
    print_config(cfg)

    def on_receive(bd_addr: str, data: bytes) -> None:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)
        print(f"[APP] rx from={bd_addr} bytes={len(data)} text={text}", flush=True)

    # Listen-only mode: suppress L2CAP transport logs so stdout only shows `[APP]` lines.
    t = L2CAPTransport(on_receive=on_receive, interface=args.interface, quiet=(args.peer is None))
    t.start()

    if not args.peer:
        print("[APP] listening only (no --peer). Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            t.stop()
            return 0

    peer = args.peer.upper()

    if args.interval > 0:
        if not args.message:
            print("[APP] --interval requires --message", file=sys.stderr)
            return 2

        msg = args.message.encode("utf-8")
        print(f"[APP] sending to={peer} every {args.interval}s. Ctrl+C to stop.", flush=True)
        try:
            while True:
                t.send(peer, msg)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            t.stop()
            return 0

    if args.message is not None:
        t.send(peer, args.message.encode("utf-8"))
        print("[APP] sent once. Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            t.stop()
            return 0

    # Interactive mode: read stdin lines and send
    stop = threading.Event()

    def stdin_loop() -> None:
        print("[APP] interactive mode: type a line then Enter to send. Ctrl+D to exit.", flush=True)
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            t.send(peer, line.encode("utf-8"))
        stop.set()

    th = threading.Thread(target=stdin_loop, name="stdin-loop", daemon=True)
    th.start()

    try:
        while not stop.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        t.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

