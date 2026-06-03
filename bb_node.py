from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time

from config import PKT_DATA, PKT_HELLO, load_config, print_config
from src.api.bb_api import BBNode
from src.control.hello_manager import HelloManager
from src.forwarding.forwarder import PacketForwarder
from src.transport.discovery import discover_devices
from src.transport.l2cap import L2CAPTransport


def parse_topology(raw: str | None) -> frozenset[str] | None:
    """Parse comma-separated BD addresses from --topology."""
    if not raw:
        return None
    addrs = {part.strip().upper() for part in raw.split(",") if part.strip()}
    if not addrs:
        return None
    return frozenset(addrs)


def setup_ble_pairing_agent() -> subprocess.Popen[str] | None:
    """
    Register a BlueZ pairing agent via bluetoothctl at node startup.

    Security note: pairing is transport-level (link/key exchange only).
    Group membership and payload protection are enforced by the AES group key
    (BUBBLE_BLUE_GROUP_KEY) — pairing does not grant access to BB traffic.
    """
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print("[APP] WARNING: bluetoothctl not found; skipping pairing agent setup", flush=True)
        return None

    # NoInputNoOutput: auto-accept pairing without user prompts.
    # Keep this bluetoothctl session alive so the agent stays registered.
    cmds = (
        "agent NoInputNoOutput\n"
        "default-agent\n"
        "discoverable on\n"
        "pairable on\n"
    )
    assert proc.stdin is not None
    proc.stdin.write(cmds)
    proc.stdin.flush()

    print(
        "[APP] BLE pairing agent: NoInputNoOutput (auto-accept), discoverable+pairable",
        flush=True,
    )
    return proc


def _run_with_transport(
    transport: L2CAPTransport,
    hello_mgr: HelloManager,
    forwarder: PacketForwarder,
    cfg,
    *,
    peer: str | None,
    topology: frozenset[str] | None,
    message: str | None,
    send: str | None,
    dst: str | None,
    interval: float,
) -> int:
    hello_mgr.start()

    connect_targets: list[str] = []
    if topology:
        connect_targets = sorted(topology)
    elif peer:
        connect_targets = [peer.upper()]

    for bd_addr in connect_targets:
        try:
            transport.connect(bd_addr)
        except OSError as e:
            print(f"[APP] connect to {bd_addr} failed: {e}", file=sys.stderr, flush=True)

    if send is not None:
        route_dst = (dst or peer or "").upper()
        if not route_dst or route_dst == "00:00:00:00:00:00":
            print(
                "[APP] --send requires --dst (routing destination) or --peer",
                file=sys.stderr,
                flush=True,
            )
            return 2
        l2cap_peer = peer.upper() if peer else None
        if not l2cap_peer and transport.connections():
            l2cap_peer = transport.connections()[0]
        try:
            forwarder.send_data(send, route_dst, l2cap_peer=l2cap_peer)
        except (OSError, RuntimeError) as e:
            print(f"[APP] --send failed: {e}", file=sys.stderr, flush=True)
            return 2
        print("[APP] --send done. Listening for replies. Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            hello_mgr.stop()
            transport.stop()
            return 0

    if not peer:
        print("[APP] listening (Hello + DATA). Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            hello_mgr.stop()
            transport.stop()
            return 0

    peer_u = peer.upper()

    if interval > 0:
        if not message:
            print("[APP] --interval requires --message", file=sys.stderr)
            return 2
        msg = message.encode("utf-8")
        print(f"[APP] sending DATA to={peer_u} every {interval}s. Ctrl+C to stop.", flush=True)
        try:
            while True:
                transport.send(peer_u, msg)
                time.sleep(interval)
        except KeyboardInterrupt:
            hello_mgr.stop()
            transport.stop()
            return 0

    if message is not None:
        transport.send(peer_u, message.encode("utf-8"))
        print("[APP] sent once. Ctrl+C to stop.", flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            hello_mgr.stop()
            transport.stop()
            return 0

    stop = threading.Event()

    def stdin_loop() -> None:
        print("[APP] interactive mode: type a line then Enter to send. Ctrl+D to exit.", flush=True)
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            transport.send(peer_u, line.encode("utf-8"))
        stop.set()

    th = threading.Thread(target=stdin_loop, name="stdin-loop", daemon=True)
    th.start()

    try:
        while not stop.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        hello_mgr.stop()
        transport.stop()
    return 0


def run_chat_mode(*, topology: frozenset[str] | None, interface: str) -> int:
    """Interactive chat using BBNode API."""
    node = BBNode(interface=interface, quiet=False, setup_pairing_agent=False)

    def on_message(sender_bd_addr: str, text: str) -> None:
        print(f"[{sender_bd_addr}] {text}", flush=True)

    node.on_message = on_message

    try:
        node.start(topology)
        for _ in range(6):
            time.sleep(1.0)
            if len(node.peers()) >= 1:
                break
        role = "RELAY" if node.is_relay() else "LEAF"
        print(f"[chat] local={node.local_bd_addr} CDS role={role}", flush=True)
        if role == "LEAF" and topology and len(topology) >= 2:
            print(
                "[chat] WARN: 2+ peers in topology but LEAF — need L2CAP to 2 neighbors "
                "and Hello before relay works",
                flush=True,
            )
        if topology:
            print(f"[chat] topology: {', '.join(sorted(topology))}", flush=True)
        print(f"[chat] peers: {', '.join(node.peers()) or '(none yet)'}", flush=True)
        print("[chat] type a message and press Enter. Ctrl+C to quit.", flush=True)

        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                node.send(line)
            except (OSError, RuntimeError) as e:
                print(f"[chat] send failed: {e}", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("\n[chat] exiting.", flush=True)
    finally:
        node.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BUBBLE-BLUE node (L2CAP + Hello + DATA)")
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
    parser.add_argument(
        "--topology",
        default=None,
        help=(
            "Comma-separated allowlist of peer BD_ADDR for L2CAP "
            "(incoming and outbound). Example: 40:D9:5A:8B:69:3F,14:B5:CD:E2:49:ED"
        ),
    )
    parser.add_argument(
        "--send",
        default=None,
        help='Send one test PKT_DATA (utf-8), then listen. Requires --dst or --peer for routing.',
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Routing destination BD_ADDR for --send (final hop, may differ from --peer).",
    )
    parser.add_argument(
        "--chat",
        action="store_true",
        help="Interactive chat (stdin → send, incoming as [BD_ADDR] message).",
    )
    args = parser.parse_args()

    topology = parse_topology(args.topology)
    if args.chat:
        if args.scan and args.scan > 0:
            print("[APP] --chat cannot be combined with --scan", file=sys.stderr, flush=True)
            return 2
        _pairing_agent = setup_ble_pairing_agent()
        return run_chat_mode(topology=topology, interface=args.interface)

    _pairing_agent = setup_ble_pairing_agent()

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
            return 0

    if topology:
        print(f"[APP] topology allowlist: {', '.join(sorted(topology))}", flush=True)
    if selected_peer and topology and selected_peer.upper() not in topology:
        print(
            f"[APP] --peer {selected_peer} is not in --topology allowlist",
            file=sys.stderr,
            flush=True,
        )
        return 2

    cfg = load_config(interface=args.interface, remote_bd_addr=selected_peer)
    print_config(cfg)

    hello_mgr: HelloManager | None = None
    forwarder: PacketForwarder | None = None

    def on_receive(peer_bd_addr: str, data: bytes) -> None:
        if not data:
            return
        pkt_type = data[0]
        if pkt_type == PKT_HELLO:
            if hello_mgr is None:
                return
            try:
                hello_mgr.on_receive(peer_bd_addr, data)
            except Exception as e:  # noqa: BLE001
                print(f"[APP] Hello rx error from={peer_bd_addr}: {e}", flush=True)
            return

        if pkt_type == PKT_DATA:
            if forwarder is None:
                return
            forwarder.handle(peer_bd_addr, data)
            return

        # Legacy cleartext / unknown framing
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)
        print(f"[APP] rx from={peer_bd_addr} bytes={len(data)} text={text}", flush=True)

    transport = L2CAPTransport(
        on_receive=on_receive,
        interface=args.interface,
        quiet=(selected_peer is None and topology is None),
        allowed_peers=topology,
    )
    hello_mgr = HelloManager(cfg, transport)
    forwarder = PacketForwarder(cfg, transport, hello_mgr, topology=topology)
    transport.start()

    return _run_with_transport(
        transport,
        hello_mgr,
        forwarder,
        cfg,
        peer=selected_peer,
        topology=topology,
        message=args.message,
        send=args.send,
        dst=args.dst,
        interval=args.interval,
    )


if __name__ == "__main__":
    raise SystemExit(main())
