from __future__ import annotations

import errno
import os
import subprocess
import threading
import time
from collections.abc import Callable

from config import PKT_DATA, PKT_HELLO, PKT_REKEY, PKT_SUBGROUP, BubbleBlueConfig, load_config
from src.control.hello_manager import HelloManager
from src.forwarding.forwarder import LogCallback, OnMessageCallback, PacketForwarder
from src.security.epoch import EpochStore
from src.security.keys import BBKeyStore
from src.transport.base import ManagedTransport
from src.transport.factory import make_transport

LogFn = Callable[[str, bool], None]


def topology_from_env() -> frozenset[str] | None:
    """Optional allowlist/dial list from BUBBLE_BLUE_TOPOLOGY."""
    return parse_topology(os.environ.get("BUBBLE_BLUE_TOPOLOGY"))


def merge_topology(
    cli: str | frozenset[str] | set[str] | None,
    *,
    use_env: bool = True,
) -> frozenset[str] | None:
    """CLI --topology wins; else BUBBLE_BLUE_TOPOLOGY from .env."""
    topo = parse_topology(cli)
    if topo:
        return topo
    if use_env:
        return topology_from_env()
    return None


def parse_topology(raw: str | frozenset[str] | set[str] | None) -> frozenset[str] | None:
    if raw is None:
        return None
    if isinstance(raw, frozenset):
        return raw if raw else None
    if isinstance(raw, set):
        return frozenset(raw) if raw else None
    addrs = {part.strip().upper() for part in str(raw).split(",") if part.strip()}
    return frozenset(addrs) if addrs else None


class BBNode:
    """
    BUBBLE-BLUE node: L2CAP + Hello (control) + PKT_DATA (forward).

    Configure ``on_message`` and optionally ``on_log`` (stderr-style diagnostics).
    ``start(topology=...)`` sets the L2CAP allowlist and opens connections to those peers.
    """

    on_message: OnMessageCallback | None = None
    on_log: LogFn | None = None
    on_peer_connected: Callable[[str], None] | None = None
    on_peer_disconnected: Callable[[str], None] | None = None
    on_decrypt_fail: Callable[[str], None] | None = None

    def __init__(
        self,
        *,
        interface: str = "hci0",
        remote_bd_addr: str | None = None,
        key_store: BBKeyStore | None = None,
        quiet: bool = False,
        setup_pairing_agent: bool = True,
    ) -> None:
        self._interface = interface
        self._remote_bd_addr = remote_bd_addr
        self._key_store = key_store
        self._quiet = quiet
        self._topology: frozenset[str] | None = None
        self._pairing_proc: subprocess.Popen[str] | None = None

        self._cfg: BubbleBlueConfig | None = None
        self._transport: ManagedTransport | None = None
        self._hello_mgr: HelloManager | None = None
        self._forwarder: PacketForwarder | None = None
        self._started = False
        self._lock = threading.RLock()
        self._connect_stop = threading.Event()
        self._connect_thread: threading.Thread | None = None
        self._connect_last_err: dict[str, str] = {}
        self._connect_last_log: dict[str, float] = {}
        self._connect_backoff_until: dict[str, float] = {}
        self._connect_streak: dict[str, int] = {}
        self._active_peers: set[str] = set()

        if setup_pairing_agent:
            self._pairing_proc = self._setup_ble_pairing_agent()

    def start(
        self,
        topology: str | frozenset[str] | set[str] | None = None,
        *,
        l2cap_accept_all: bool = False,
    ) -> None:
        if self.on_message is None:
            raise RuntimeError("set BBNode.on_message before start()")

        with self._lock:
            if self._started:
                return

            self._topology = parse_topology(topology)
            self._cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )
            allowlist = self._connect_targets()
            if l2cap_accept_all:
                allowed_peers = None
            elif allowlist:
                allowed_peers = frozenset(allowlist)
            else:
                allowed_peers = None

            holder: dict[str, HelloManager | PacketForwarder | None] = {
                "hello": None,
                "fwd": None,
            }

            def on_receive(peer: str, data: bytes) -> None:
                if not data:
                    return
                if data[0] == PKT_HELLO:
                    hm = holder["hello"]
                    if hm is not None:
                        hm.on_receive(peer, data)
                    return
                if data[0] in (PKT_DATA, PKT_SUBGROUP, PKT_REKEY):
                    fwd = holder["fwd"]
                    if fwd is not None:
                        fwd.handle(peer, data)

            transport = make_transport(
                self._cfg.transport_kind,
                on_receive=on_receive,
                interface=self._interface,
                quiet=self._quiet,
                allowed_peers=allowed_peers,
                on_peer_connected=self._dispatch_peer_connected,
                on_peer_disconnected=self._dispatch_peer_disconnected,
            )
            key_store = self._key_store or BBKeyStore.from_group_key(
                self._cfg.group_key,
                self._cfg.local_bd_addr,
            )
            epoch_store = EpochStore(
                self._cfg.group_key,
                local_bd_addr=self._cfg.local_bd_addr,
            )
            hello = HelloManager(self._cfg, transport, key_store, epoch_store, quiet=self._quiet)
            fwd = PacketForwarder(
                self._cfg,
                transport,
                hello,
                on_message=self._dispatch_message,
                on_log=self._dispatch_log if self.on_log else None,
                on_decrypt_fail=(
                    self._dispatch_decrypt_fail if self.on_decrypt_fail else None
                ),
            )
            hello.set_rekey_catchup(fwd.send_rekey_catchup)
            holder["hello"] = hello
            holder["fwd"] = fwd

            transport.start()
            hello.start()

            self._transport = transport
            self._hello_mgr = hello
            self._forwarder = fwd
            self._started = True

            self._active_peers = {p.upper() for p in transport.connections()}
            self._connect_peers()
            if allowlist:
                self._connect_stop.clear()
                self._connect_thread = threading.Thread(
                    target=self._connect_loop,
                    name="bb-connect",
                    daemon=True,
                )
                self._connect_thread.start()

    def stop(self) -> None:
        self._connect_stop.set()
        with self._lock:
            if self._hello_mgr is not None:
                self._hello_mgr.stop()
            if self._transport is not None:
                self._transport.stop()
            self._hello_mgr = None
            self._transport = None
            self._forwarder = None
            self._started = False
            self._active_peers.clear()

        if self._pairing_proc is not None:
            try:
                self._pairing_proc.terminate()
            except OSError:
                pass
            self._pairing_proc = None

    def send(self, text: str) -> None:
        """Broadcast chat message (dst = FF:FF:FF:FF:FF:FF) on all L2CAP links."""
        self._require_forwarder().send_broadcast(text)

    def send_subgroup(self, text: str, recipients: list[str]) -> None:
        """À la carte multicast (PKT_SUBGROUP) to subset ``recipients``."""
        self._require_forwarder().send_subgroup(text, recipients)

    def revoke_member(self, bd_addr: str) -> None:
        """Revoke a member (epoch bump + PKT_REKEY flood). Coordinator only."""
        self._require_forwarder().revoke_member(bd_addr)

    def current_epoch(self) -> int:
        if self._hello_mgr is None:
            return 0
        return self._hello_mgr.epoch_store.current_epoch()

    def is_coordinator(self) -> bool:
        if self._hello_mgr is None:
            return False
        return self._hello_mgr.is_coordinator()

    def send_unicast(
        self,
        text: str,
        dst_bd_addr: str,
        *,
        via_peer: str | None = None,
        private: bool = False,
    ) -> None:
        """Send PKT_DATA toward ``dst_bd_addr`` on L2CAP link ``via_peer`` (or first peer)."""
        peer = (via_peer or self._pick_l2cap_peer()).upper()
        self.send_data(text, dst_bd_addr, via_peer=peer, private=private)

    def send_data(
        self,
        text: str | bytes,
        dst_bd_addr: str,
        *,
        via_peer: str,
        private: bool = False,
    ) -> None:
        """Send PKT_DATA to ``dst_bd_addr`` on the given L2CAP peer."""
        self._require_forwarder().send_data(
            text,
            dst_bd_addr,
            private=private,
            l2cap_peer=via_peer.upper(),
        )

    def peers(self) -> list[str]:
        if self._transport is None:
            return []
        return self._transport.connections()

    def connect_targets(self) -> list[str]:
        """BD addresses this node will try to reach (topology + env + --peer)."""
        return sorted(self._connect_targets())

    def is_relay(self) -> bool:
        if self._hello_mgr is None:
            return False
        self._hello_mgr.refresh_cds_role()
        return self._hello_mgr.is_relay

    @property
    def local_bd_addr(self) -> str:
        return self._require_cfg().local_bd_addr

    def resolved_member_addresses(self) -> list[str]:
        if self._hello_mgr is None:
            return []
        return [str(m["bd_addr"]).upper() for m in self._hello_mgr.get_resolved_members()]

    def has_pairwise_key(self, bd_addr: str) -> bool:
        if self._hello_mgr is None:
            return False
        return self._hello_mgr.key_store.get_pair_key(bd_addr.upper()) is not None

    def route_l2cap_peer(self, dst_bd_addr: str) -> str:
        """Pick an L2CAP link to reach ``dst_bd_addr`` (direct neighbor or multihop relay)."""
        dst = dst_bd_addr.upper()
        local = self.local_bd_addr.upper()
        if dst == local:
            raise RuntimeError("cannot send to yourself")
        peers = self.peers()
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        if dst in peers:
            return dst
        return peers[0].upper()

    def _require_cfg(self) -> BubbleBlueConfig:
        if self._cfg is None:
            raise RuntimeError("call start() first")
        return self._cfg

    def _require_forwarder(self) -> PacketForwarder:
        if self._forwarder is None:
            raise RuntimeError("call start() first")
        return self._forwarder

    def _pick_l2cap_peer(self) -> str:
        peers = self.peers()
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        return peers[0]

    def _connect_targets(self) -> set[str]:
        """Peers to dial: --topology, then .env group members, then --peer."""
        if self._cfg is None:
            cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )
        else:
            cfg = self._cfg
        local = cfg.local_bd_addr.upper()
        targets: set[str] = set()
        if self._topology:
            targets.update(self._topology)
        for bd in cfg.group_members:
            targets.add(bd.upper())
        remote = (self._remote_bd_addr or cfg.remote_bd_addr).upper()
        if remote not in ("00:00:00:00:00:00", local):
            targets.add(remote)
        targets.discard(local)
        return targets

    def _connect_peers(self) -> None:
        if self._transport is None:
            return
        now = time.monotonic()
        local = self._require_cfg().local_bd_addr.upper()
        for bd in sorted(self._connect_targets()):
            if bd == local:
                continue
            if bd in self._transport.connections():
                self._connect_last_err.pop(bd, None)
                self._connect_backoff_until.pop(bd, None)
                self._connect_streak.pop(bd, None)
                continue
            if now < self._connect_backoff_until.get(bd, 0.0):
                continue
            if local >= bd:
                continue
            try:
                self._transport.connect(bd)
                self._connect_last_err.pop(bd, None)
                self._connect_backoff_until.pop(bd, None)
                self._connect_streak.pop(bd, None)
            except OSError as e:
                self._backoff_after_connect_fail(bd, e)
                self._log_connect_failure(bd, e)

    def _backoff_after_connect_fail(self, bd: str, e: OSError) -> None:
        if e.errno not in (
            errno.EHOSTDOWN,
            errno.ECONNREFUSED,
            errno.ENETUNREACH,
            errno.ETIMEDOUT,
            errno.ECONNABORTED,
            errno.ECONNRESET,
        ):
            return
        key = f"{e.errno}"
        streak = self._connect_streak.get(bd, 0) + 1 if self._connect_last_err.get(bd) == key else 1
        self._connect_streak[bd] = streak
        self._connect_backoff_until[bd] = time.monotonic() + min(60.0, 4.0 * streak)

    def _log_connect_failure(self, bd: str, e: OSError) -> None:
        key = f"{e.errno}"
        now = time.monotonic()
        prev = self._connect_last_err.get(bd)
        last = self._connect_last_log.get(bd, 0.0)
        self._connect_last_err[bd] = key
        if prev == key and now - last < 45.0:
            return
        self._connect_last_log[bd] = now
        self._dispatch_log(f"connect {bd} failed: {e}")

    def _connect_loop(self) -> None:
        while not self._connect_stop.wait(4.0):
            try:
                self._connect_peers()
            except Exception as e:  # noqa: BLE001
                self._dispatch_log(f"connect loop: {e}")

    def _dispatch_message(self, sender: str, text: str) -> None:
        assert self.on_message is not None
        self.on_message(sender, text)

    def _dispatch_peer_connected(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        if bd in self._active_peers:
            return
        self._active_peers.add(bd)
        if self.on_peer_connected:
            self.on_peer_connected(bd)

    def _dispatch_peer_disconnected(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        if bd not in self._active_peers:
            return
        self._active_peers.discard(bd)
        if self.on_peer_disconnected:
            self.on_peer_disconnected(bd)

    def _dispatch_decrypt_fail(self, src: str) -> None:
        if self.on_decrypt_fail:
            self.on_decrypt_fail(src.upper())

    def _dispatch_log(self, msg: str, *, err: bool | None = None) -> None:
        if self.on_log:
            # Chat mode: network retries are not errors (buffer while typing).
            is_err = err if err is not None else not self._quiet
            self.on_log(msg, is_err)

    @staticmethod
    def _setup_ble_pairing_agent() -> subprocess.Popen[str] | None:
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return None
        assert proc.stdin is not None
        proc.stdin.write(
            "agent NoInputNoOutput\n"
            "default-agent\n"
            "discoverable on\n"
            "pairable on\n"
        )
        proc.stdin.flush()
        return proc
