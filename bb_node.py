from __future__ import annotations

import argparse
import sys
import threading
import time

from config import load_config, print_config
from src.transport.discovery import discover_devices
from src.transport.l2cap import L2CAPTransport


def main() -> int:
    parser = argparse.ArgumentParser(description="BUBBLE-BLUE node (simple L2CAP ping/echo test)")
    parser.add_argument(
        "--scan",
        type=float,
        default=0.0,
        help="Scan for nearby Bluetooth devices for N seconds, print results, then exit (unless --auto-peer is set).",
    )
    parser.add_argument(
        "--auto-peer",
        default=None,
        help="If set, scans then selects a peer automatically (substring match against name or BD_ADDR).",
    )
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

    # Optional pre-step: discovery
    selected_peer = args.peer
    if args.scan and args.scan > 0:
        print(f"[APP] scanning for devices for {args.scan:.1f}s ...", flush=True)
        try:
            devices = discover_devices(timeout_s=args.scan)
        except Exception as e:  # noqa: BLE001
            print(f"[APP] scan failed: {e}", file=sys.stderr, flush=True)
            return 2

        if not devices:
            print("[APP] scan done: no devices found.", flush=True)
        else:
            print("[APP] scan done:", flush=True)
            for d in devices:
                label = d.name or "<?>"
                src = d.source or "?"
                print(f"[APP] - {d.bd_addr} name={label} src={src}", flush=True)

        if args.auto_peer:
            key = str(args.auto_peer).strip().upper()
            chosen = None
            for d in devices:
                hay = f"{d.bd_addr} {(d.name or '')}".upper()
                if key in hay:
                    chosen = d
                    break
            if not chosen:
                print(f"[APP] --auto-peer={args.auto_peer!r}: no match in scan results", file=sys.stderr, flush=True)
                return 2
            selected_peer = chosen.bd_addr
            print(f"[APP] auto-selected peer={selected_peer} name={chosen.name or '<?>'}", flush=True)
        else:
            # Scan-only mode
            return 0

    cfg = load_config(interface=args.interface, remote_bd_addr=selected_peer)
    print_config(cfg)

    def on_receive(bd_addr: str, data: bytes) -> None:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)
        print(f"[APP] rx from={bd_addr} bytes={len(data)} text={text}", flush=True)

    # Listen-only mode: suppress L2CAP transport logs so stdout only shows `[APP]` lines.
    t = L2CAPTransport(on_receive=on_receive, interface=args.interface, quiet=(selected_peer is None))
    t.start()

    if not selected_peer:
        print("[APP] listening only (no --peer). Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            t.stop()
            return 0

    peer = selected_peer.upper()

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

