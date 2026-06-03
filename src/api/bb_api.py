from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable

from config import PKT_DATA, PKT_HELLO, BubbleBlueConfig, load_config
from src.control.hello_manager import HelloManager
from src.forwarding.forwarder import LogCallback, OnMessageCallback, PacketForwarder
from src.transport.l2cap import L2CAPTransport

LogFn = Callable[[str, bool], None]


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

    def __init__(
        self,
        *,
        interface: str = "hci0",
        remote_bd_addr: str | None = None,
        quiet: bool = False,
        setup_pairing_agent: bool = True,
    ) -> None:
        self._interface = interface
        self._remote_bd_addr = remote_bd_addr
        self._quiet = quiet
        self._topology: frozenset[str] | None = None
        self._pairing_proc: subprocess.Popen[str] | None = None

        self._cfg: BubbleBlueConfig | None = None
        self._transport: L2CAPTransport | None = None
        self._hello_mgr: HelloManager | None = None
        self._forwarder: PacketForwarder | None = None
        self._started = False
        self._lock = threading.RLock()
        self._connect_stop = threading.Event()
        self._connect_thread: threading.Thread | None = None

        if setup_pairing_agent:
            self._pairing_proc = self._setup_ble_pairing_agent()

    def start(self, topology: str | frozenset[str] | set[str] | None = None) -> None:
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
            allowed_peers = frozenset(allowlist) if allowlist else None

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
                if data[0] == PKT_DATA:
                    fwd = holder["fwd"]
                    if fwd is not None:
                        fwd.handle(peer, data)

            transport = L2CAPTransport(
                on_receive=on_receive,
                interface=self._interface,
                quiet=self._quiet,
                allowed_peers=allowed_peers,
            )
            hello = HelloManager(self._cfg, transport, quiet=self._quiet)
            fwd = PacketForwarder(
                self._cfg,
                transport,
                hello,
                on_message=self._dispatch_message,
                on_log=self._dispatch_log if self.on_log else None,
            )
            holder["hello"] = hello
            holder["fwd"] = fwd

            transport.start()
            hello.start()

            self._transport = transport
            self._hello_mgr = hello
            self._forwarder = fwd
            self._started = True

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

        if self._pairing_proc is not None:
            try:
                self._pairing_proc.terminate()
            except OSError:
                pass
            self._pairing_proc = None

    def send(self, text: str) -> None:
        """Broadcast chat message (dst = FF:FF:FF:FF:FF:FF) on all L2CAP links."""
        self._require_forwarder().send_broadcast(text)

    def send_unicast(self, text: str, dst_bd_addr: str, *, via_peer: str | None = None) -> None:
        """Send PKT_DATA toward ``dst_bd_addr`` on L2CAP link ``via_peer`` (or first peer)."""
        fwd = self._require_forwarder()
        peer = (via_peer or self._pick_l2cap_peer()).upper()
        fwd.send_unicast(text, dst_bd_addr, l2cap_peer=peer)

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
        for bd in sorted(self._connect_targets()):
            try:
                self._transport.connect(bd)
            except OSError as e:
                self._dispatch_log(f"connect {bd} failed: {e}", True)

    def _connect_loop(self) -> None:
        while not self._connect_stop.wait(4.0):
            try:
                self._connect_peers()
            except Exception as e:  # noqa: BLE001
                self._dispatch_log(f"connect loop: {e}", True)

    def _dispatch_message(self, sender: str, text: str) -> None:
        assert self.on_message is not None
        self.on_message(sender, text)

    def _dispatch_log(self, msg: str) -> None:
        if self.on_log:
            self.on_log(msg, True)

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
