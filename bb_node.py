from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from config import BubbleBlueConfig, load_config, print_config
from src.api.bb_api import BBNode, merge_topology
from src.api.chat_input import read_chat_line
from src.api.chat_log import ChatLog
from src.security.keys import BBKeyStore
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


def _identity_key_store(cfg: BubbleBlueConfig) -> BBKeyStore:
    return BBKeyStore.from_group_key(cfg.group_key, cfg.local_bd_addr)


def _log_x25519_identity(cfg: BubbleBlueConfig) -> None:
    pub_hex = _identity_key_store(cfg).local_public_key.hex()
    print(f"[APP] X25519 identity: {pub_hex[:16]}… (full: {pub_hex})", flush=True)


def show_identity(*, interface: str, peer: str | None) -> int:
    cfg = load_config(interface=interface, remote_bd_addr=peer)
    pub_hex = _identity_key_store(cfg).local_public_key.hex()
    print(f"BD_ADDR: {cfg.local_bd_addr.upper()}", flush=True)
    print(f"X25519 public key: {pub_hex}", flush=True)
    return 0


def run_chat(
    topology: frozenset[str] | None,
    interface: str,
    peer: str | None = None,
    *,
    private: bool = False,
    dst: str | None = None,
) -> int:
    cfg = load_config(interface=interface, remote_bd_addr=peer)
    _log_x25519_identity(cfg)

    node = BBNode(
        interface=interface,
        remote_bd_addr=peer,
        quiet=True,
        setup_pairing_agent=False,
    )
    node.on_message = lambda s, t: ChatLog.interrupt(f"[{s}] {t}")
    node.on_peer_connected = lambda bd: ChatLog.interrupt(f"peer connecté: {bd}")
    node.on_peer_disconnected = lambda bd: ChatLog.interrupt(f"peer déconnecté: {bd}")
    node.on_decrypt_fail = lambda src: ChatLog.interrupt(
        f"paquet non déchiffrable (mauvaise clé ?) de {src}"
    )
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
        ChatLog.interrupt(f"local {node.local_bd_addr} · {role} · {n} peer(s)")
        if targets:
            ChatLog.interrupt(f"dial: {', '.join(targets)}")
        elif n == 0:
            ChatLog.interrupt(
                "aucun peer — --topology ADDR ou BUBBLE_BLUE_GROUP_MEMBERS dans .env"
            )
        while True:
            try:
                line = read_chat_line("> ")
            except KeyboardInterrupt:
                break
            if line:
                if not node.peers():
                    ChatLog.interrupt("aucun peer connecté — message non envoyé", err=True)
                    continue
                try:
                    if private:
                        target = (dst or peer or "").upper()
                        if not target or target == "00:00:00:00:00:00":
                            ChatLog.interrupt(
                                "message privé — préciser --peer ou --dst",
                                err=True,
                            )
                            continue
                        l2cap_peer = (peer or node.peers()[0]).upper()
                        node.send_data(line, target, via_peer=l2cap_peer, private=True)
                    else:
                        node.send(line)
                except (OSError, RuntimeError) as e:
                    ChatLog.interrupt(str(e), err=True)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
    return 0


def _run_with_transport(args: argparse.Namespace, topology: frozenset[str] | None) -> int:
    verbose = not (topology or args.peer or args.send)
    setup_ble_pairing_agent(quiet=not verbose)

    cfg = load_config(interface=args.interface, remote_bd_addr=args.peer)
    _log_x25519_identity(cfg)

    node = BBNode(
        interface=args.interface,
        remote_bd_addr=args.peer,
        quiet=not verbose,
        setup_pairing_agent=False,
    )
    node.on_message = lambda s, t: print(f"[{s}] {t}", flush=True)
    if verbose:
        print_config(cfg)

    node.start(topology)

    if args.send:
        dst = (args.dst or args.peer or "").upper()
        if not dst or dst == "00:00:00:00:00:00":
            print("[APP] --send needs --dst or --peer", file=sys.stderr)
            return 2
        if not args.peer:
            print("[APP] --send needs --peer (L2CAP link)", file=sys.stderr)
            return 2
        node.send_data(
            args.send,
            dst,
            via_peer=args.peer,
            private=args.private,
        )
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
    parser.add_argument(
        "--interface",
        default=os.environ.get("BUBBLE_BLUE_INTERFACE", "hci0"),
    )
    parser.add_argument(
        "--topology",
        default=None,
        help="Comma-separated peer BD_ADDR (allowlist + outbound connect). "
        "Default: BUBBLE_BLUE_TOPOLOGY or BUBBLE_BLUE_GROUP_MEMBERS in .env",
    )
    parser.add_argument("--send", default=None)
    parser.add_argument("--dst", default=None)
    parser.add_argument(
        "--private",
        action="store_true",
        default=False,
        help=(
            "Encrypt as private pairwise message (requires X25519 key exchange "
            "via Hello). Destination must have been seen in a Hello before sending."
        ),
    )
    parser.add_argument(
        "--show-identity",
        action="store_true",
        help="Print full X25519 public key hex + BD address, then exit",
    )
    parser.add_argument("--chat", action="store_true")
    args = parser.parse_args()

    if args.show_identity:
        return show_identity(interface=args.interface, peer=args.peer)

    topology = merge_topology(args.topology)
    peer = args.peer

    if args.chat:
        if args.scan:
            print("[APP] --chat incompatible with --scan", file=sys.stderr)
            return 2
        return run_chat(
            topology,
            args.interface,
            args.peer,
            private=args.private,
            dst=args.dst,
        )

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

    return _run_with_transport(args, topology)


if __name__ == "__main__":
    raise SystemExit(main())
