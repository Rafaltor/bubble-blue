from __future__ import annotations

import argparse
import os
import sys
import time


def _require_crypto_deps() -> None:
    """Fail fast with a clear message when cryptography/cffi are missing for this interpreter."""
    try:
        import _cffi_backend  # noqa: F401
        from cryptography.exceptions import InvalidTag  # noqa: F401
    except Exception:
        print(
            f"\nBUBBLE-BLUE: cryptography/cffi not available for {sys.executable}\n\n"
            "bb_node.py is usually run with sudo for L2CAP; packages installed via\n"
            "  python3.14 -m pip install --user ...\n"
            "live in ~/.local and are NOT visible to root.\n\n"
            "Fix (from repo root):\n"
            "  ./scripts/install_py314_deps.sh\n"
            "  # or:\n"
            "  sudo python3.14 -m pip install --break-system-packages --ignore-installed -r requirements.txt\n\n"
            "Without sudo (local tests only):\n"
            "  python3.14 -m pip install --user -r requirements.txt\n"
            "  python3.14 bb_node.py --chat\n",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


_require_crypto_deps()

from config import BubbleBlueConfig, config_warnings, load_config, print_config
from src.api.bb_api import BBNode, merge_topology
from src.api.chat_commands import (
    CHAT_HELP,
    format_members_display,
    load_chat_aliases,
    parse_chat_command,
    resolve_chat_target,
)
from src.api.chat_input import read_chat_line
from src.api.chat_log import ChatLog
from src.security.keys import BBKeyStore
from src.transport.discovery import discover_devices
from src.transport.pairing_agent import PairingAgentSupervisor


def setup_ble_pairing_agent(*, quiet: bool = False) -> PairingAgentSupervisor:
    """Start supervised NoInputNoOutput agent; caller must :meth:`PairingAgentSupervisor.stop`."""
    supervisor = PairingAgentSupervisor(quiet=quiet)
    supervisor.start()
    return supervisor


def _identity_key_store(cfg: BubbleBlueConfig) -> BBKeyStore:
    """Persistent random identity (not derived from group key)."""
    return BBKeyStore.for_node(cfg.local_bd_addr)


def _log_x25519_identity(cfg: BubbleBlueConfig) -> None:
    store = _identity_key_store(cfg)
    pub_hex = store.local_public_key.hex()
    sig_hex = store.local_signing_public_key.hex()
    print(f"[APP] X25519 identity: {pub_hex[:16]}… (full: {pub_hex})", flush=True)
    print(f"[APP] Ed25519 signing: {sig_hex[:16]}… (full: {sig_hex})", flush=True)


def show_identity(*, interface: str, peer: str | None) -> int:
    cfg = load_config(interface=interface, remote_bd_addr=peer)
    store = _identity_key_store(cfg)
    print(f"BD_ADDR: {cfg.local_bd_addr.upper()}", flush=True)
    print(f"X25519 public key: {store.local_public_key.hex()}", flush=True)
    print(f"Ed25519 public key: {store.local_signing_public_key.hex()}", flush=True)
    return 0


def _print_mesh_hints(cfg: BubbleBlueConfig, *, interface: str) -> None:
    print(f"[APP] local BD_ADDR: {cfg.local_bd_addr}", flush=True)
    if cfg.group_members:
        print(f"[APP] outbound dial list: {', '.join(cfg.group_members)}", flush=True)
    else:
        print(
            "[APP] open mesh: no GROUP_MEMBERS — discovery via presence beacon + auto-dial",
            flush=True,
        )
    for msg in config_warnings(interface=interface):
        print(f"[APP] WARNING: {msg}", flush=True)
    print(
        "[APP] chat: accepting any incoming L2CAP peer "
        "(crypto still requires the shared GROUP_KEY)",
        flush=True,
    )


def run_chat(
    topology: frozenset[str] | None,
    interface: str,
    peer: str | None = None,
    *,
    private: bool = False,
    dst: str | None = None,
) -> int:
    cfg = load_config(interface=interface, remote_bd_addr=peer)
    _print_mesh_hints(cfg, interface=interface)
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

    pairing = setup_ble_pairing_agent(quiet=True)
    try:
        node.start(topology, l2cap_accept_all=True)
        time.sleep(1.0)
        targets = node.connect_targets()
        for _ in range(12):
            if node.peers() or not targets:
                break
            time.sleep(1.0)
        role = "RELAY" if node.is_relay() else "LEAF"
        n = len(node.peers())
        ChatLog.interrupt(
            f"transport {cfg.transport_kind} · PSM 0x{cfg.psm:04X} · "
            f"local {node.local_bd_addr} · {role} · {n} peer(s)"
        )
        if targets:
            ChatLog.interrupt(f"dial: {', '.join(targets)}")
        elif n == 0:
            ChatLog.interrupt(
                "aucun peer encore — attente discovery (presence) ou "
                "--topology / GROUP_MEMBERS en labo"
            )
        ChatLog.interrupt("tape /help pour les commandes (/private …)")
        aliases = load_chat_aliases()
        while True:
            try:
                line = read_chat_line("> ")
            except KeyboardInterrupt:
                break
            if not line:
                continue

            cmd = parse_chat_command(line)
            if cmd is not None:
                if cmd.kind == "help":
                    ChatLog.interrupt(CHAT_HELP)
                    continue
                if cmd.kind == "members":
                    ChatLog.interrupt(
                        format_members_display(
                            alias_config=aliases,
                            resolved_members=node.resolved_member_addresses(),
                            group_members=cfg.group_members,
                            local_bd_addr=node.local_bd_addr,
                        )
                    )
                    continue
                if cmd.kind == "epoch":
                    coord = "oui" if node.is_coordinator() else "non"
                    ChatLog.interrupt(
                        f"epoch={node.current_epoch()} · coordinateur={coord}"
                    )
                    continue
                if cmd.kind == "revoke":
                    if not cmd.target:
                        ChatLog.interrupt("usage: /revoke <cible>", err=True)
                        continue
                    dst = resolve_chat_target(
                        cmd.target,
                        aliases=aliases.lookup,
                        group_members=cfg.group_members,
                        resolved_members=node.resolved_member_addresses(),
                        local_bd_addr=node.local_bd_addr,
                    )
                    if dst is None:
                        ChatLog.interrupt(f"cible inconnue: {cmd.target!r}", err=True)
                        continue
                    try:
                        node.revoke_member(dst)
                        ChatLog.interrupt(f"révocation initiée pour {dst} (epoch={node.current_epoch()})")
                    except RuntimeError as e:
                        ChatLog.interrupt(str(e), err=True)
                    continue
                if cmd.kind == "subgroup":
                    if not cmd.recipients or not cmd.message:
                        ChatLog.interrupt(
                            'usage: /subgroup <cible>… <message>  ex: /subgroup rubikQ arduino "hi"',
                            err=True,
                        )
                        continue
                    resolved: list[str] = []
                    for name in cmd.recipients:
                        dst = resolve_chat_target(
                            name,
                            aliases=aliases.lookup,
                            group_members=cfg.group_members,
                            resolved_members=node.resolved_member_addresses(),
                            local_bd_addr=node.local_bd_addr,
                        )
                        if dst is None:
                            ChatLog.interrupt(f"cible inconnue: {name!r}", err=True)
                            resolved = []
                            break
                        resolved.append(dst)
                    if not resolved:
                        continue
                    if not node.peers():
                        ChatLog.interrupt("aucun peer connecté", err=True)
                        continue
                    try:
                        node.send_subgroup(cmd.message, resolved)
                        ChatLog.interrupt(f"→ subgroup {resolved}: {cmd.message}")
                    except (OSError, RuntimeError) as e:
                        ChatLog.interrupt(str(e), err=True)
                    continue
                if cmd.kind == "private":
                    if not cmd.target or not cmd.message:
                        ChatLog.interrupt(
                            'usage: /private <cible> <message>  ex: /private rubikQ "salut"',
                            err=True,
                        )
                        continue
                    dst = resolve_chat_target(
                        cmd.target,
                        aliases=aliases.lookup,
                        group_members=cfg.group_members,
                        resolved_members=node.resolved_member_addresses(),
                        local_bd_addr=node.local_bd_addr,
                    )
                    if dst is None:
                        ChatLog.interrupt(
                            f"cible inconnue: {cmd.target!r} — /members ou BUBBLE_BLUE_CHAT_ALIASES",
                            err=True,
                        )
                        continue
                    if not node.peers():
                        ChatLog.interrupt("aucun peer connecté — message non envoyé", err=True)
                        continue
                    if not node.has_pairwise_key(dst):
                        ChatLog.interrupt(
                            f"pas de clé pairwise pour {dst} — attendre Hello privé (~5 s)",
                            err=True,
                        )
                        continue
                    try:
                        via = node.route_l2cap_peer(dst)
                        node.send_data(cmd.message, dst, via_peer=via, private=True)
                        ChatLog.interrupt(f"→ privé [{dst}] {cmd.message}")
                    except (OSError, RuntimeError) as e:
                        ChatLog.interrupt(str(e), err=True)
                    continue

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
        pairing.stop()
    return 0


def _run_with_transport(args: argparse.Namespace, topology: frozenset[str] | None) -> int:
    verbose = not (topology or args.peer or args.send)
    pairing = setup_ble_pairing_agent(quiet=not verbose)

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
        pairing.stop()
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
