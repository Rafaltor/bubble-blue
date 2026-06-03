from __future__ import annotations

import argparse
import subprocess
import sys
import time

from config import load_config, print_config
from src.api.bb_api import BBNode, parse_topology
from src.api.chat_input import read_chat_line
from src.api.chat_log import ChatLog
from src.transport.discovery import discover_devices


def setup_ble_pairing_agent(*, quiet: bool = False) -> None:
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        if not quiet:
            print("[APP] bluetoothctl not found", flush=True)
        return
    assert proc.stdin is not None
    proc.stdin.write(
        "agent NoInputNoOutput\n"
        "default-agent\n"
        "discoverable on\n"
        "pairable on\n"
    )
    proc.stdin.flush()


def run_chat(
    topology: frozenset[str] | None,
    interface: str,
    peer: str | None = None,
) -> int:
    node = BBNode(
        interface=interface,
        remote_bd_addr=peer,
        quiet=True,
        setup_pairing_agent=False,
    )
    node.on_message = lambda s, t: ChatLog.emit(f"[{s}] {t}", force=True)
    node.on_log = lambda m, err: ChatLog.emit(m, err=err)

    setup_ble_pairing_agent(quiet=True)
    try:
        node.start(topology)
        time.sleep(1.0)
        targets = node.connect_targets()
        for _ in range(12):
            if node.peers() or not targets:
                break
            time.sleep(1.0)
        role = "RELAY" if node.is_relay() else "LEAF"
        n = len(node.peers())
        ChatLog.emit(f"local {node.local_bd_addr} · {role} · {n} peer(s)", force=True)
        if targets:
            ChatLog.emit(f"dial: {', '.join(targets)}", force=True)
        elif n == 0:
            ChatLog.emit(
                "no peer — use --topology ADDR or set BUBBLE_BLUE_GROUP_MEMBERS in .env",
                force=True,
            )

        while True:
            try:
                line = read_chat_line("> ")
            except KeyboardInterrupt:
                break
            if line:
                if not node.peers():
                    ChatLog.emit("no peer connected — message not sent", force=True, err=True)
                    continue
                try:
                    node.send(line)
                except (OSError, RuntimeError) as e:
                    ChatLog.emit(str(e), force=True, err=True)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
    return 0


def run_listen(args: argparse.Namespace, topology: frozenset[str] | None) -> int:
    verbose = not (topology or args.peer or args.send)
    setup_ble_pairing_agent(quiet=not verbose)

    node = BBNode(
        interface=args.interface,
        remote_bd_addr=args.peer,
        quiet=not verbose,
        setup_pairing_agent=False,
    )
    node.on_message = lambda s, t: print(f"[{s}] {t}", flush=True)
    if verbose:
        print_config(load_config(interface=args.interface, remote_bd_addr=args.peer))

    node.start(topology)

    if args.send:
        dst = (args.dst or args.peer or "").upper()
        if not dst or dst == "00:00:00:00:00:00":
            print("[APP] --send needs --dst or --peer", file=sys.stderr)
            return 2
        node.send_unicast(args.send, dst, via_peer=args.peer)
        print("[APP] sent, Ctrl+C to stop", flush=True)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BUBBLE-BLUE node")
    parser.add_argument("--scan", type=float, default=0.0)
    parser.add_argument("--auto-peer", default=None)
    parser.add_argument("--peer", default=None)
    parser.add_argument("--interface", default="hci0")
    parser.add_argument(
        "--topology",
        default=None,
        help="Comma-separated BD_ADDR: L2CAP allowlist + connect on start",
    )
    parser.add_argument("--send", default=None)
    parser.add_argument("--dst", default=None)
    parser.add_argument("--chat", action="store_true")
    args = parser.parse_args()

    topology = parse_topology(args.topology)
    peer = args.peer

    if args.chat:
        if args.scan:
            print("[APP] --chat incompatible with --scan", file=sys.stderr)
            return 2
        return run_chat(topology, args.interface, args.peer)

    if args.scan and args.scan > 0:
        devices = discover_devices(timeout_s=args.scan)
        for d in devices:
            print(f"{d.bd_addr}  {d.name or '?'}", flush=True)
        if not args.auto_peer:
            return 0
        key = args.auto_peer.strip().upper()
        peer = next(
            (d.bd_addr for d in devices if key in f"{d.bd_addr} {d.name or ''}".upper()),
            None,
        )
        if not peer:
            print(f"[APP] no match for --auto-peer={args.auto_peer!r}", file=sys.stderr)
            return 2
        args.peer = peer

    if peer and topology and peer.upper() not in topology:
        print("[APP] --peer not in --topology", file=sys.stderr)
        return 2

    return run_listen(args, topology)


if __name__ == "__main__":
    raise SystemExit(main())
