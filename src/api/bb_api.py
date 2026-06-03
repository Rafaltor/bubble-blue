from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable
from config import PKT_DATA, PKT_HELLO, BubbleBlueConfig, load_config
from src.control.hello_manager import HelloManager
from src.forwarding.forwarder import BROADCAST_BD_ADDR, PacketForwarder
from src.transport.l2cap import L2CAPTransport

OnMessageCallback = Callable[[str, str], None]


def _parse_topology(raw: str | frozenset[str] | set[str] | None) -> frozenset[str] | None:
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
    High-level BUBBLE-BLUE node API (L2CAP + Hello + PKT_DATA forwarding).

    ``on_message(sender_bd_addr, text)`` is invoked for locally delivered chat payloads
    (routing header ``src``, not the L2CAP ingress hop).
    """

    on_message: OnMessageCallback | None = None

    def __init__(
        self,
        *,
        interface: str = "hci0",
        remote_bd_addr: str | None = None,
        quiet: bool = True,
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

        if setup_pairing_agent:
            self._pairing_proc = self._setup_ble_pairing_agent()

    def start(self, topology: str | frozenset[str] | set[str] | None = None) -> None:
        """Start transport, Hello manager, and connect to topology peers."""
        with self._lock:
            if self._started:
                return

            self._topology = _parse_topology(topology)
            self._cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )

            hello_holder: list[HelloManager | None] = [None]
            forwarder_holder: list[PacketForwarder | None] = [None]

            def on_receive(peer_bd_addr: str, data: bytes) -> None:
                if not data:
                    return
                pkt_type = data[0]
                hm = hello_holder[0]
                fwd = forwarder_holder[0]
                if pkt_type == PKT_HELLO:
                    if hm is not None:
                        try:
                            hm.on_receive(peer_bd_addr, data)
                        except Exception as e:  # noqa: BLE001
                            print(f"[BB] Hello rx error from={peer_bd_addr}: {e}", flush=True)
                    return
                if pkt_type == PKT_DATA and fwd is not None:
                    fwd.handle(peer_bd_addr, data)

            transport = L2CAPTransport(
                on_receive=on_receive,
                interface=self._interface,
                quiet=self._quiet,
                allowed_peers=self._topology,
            )
            hello_mgr = HelloManager(self._cfg, transport)
            forwarder = PacketForwarder(
                self._cfg,
                transport,
                hello_mgr,
                on_message=self._on_chat_message,
            )
            hello_holder[0] = hello_mgr
            forwarder_holder[0] = forwarder

            transport.start()
            hello_mgr.start()

            if self._topology:
                for bd_addr in sorted(self._topology):
                    try:
                        transport.connect(bd_addr)
                    except OSError as e:
                        print(f"[BB] connect to {bd_addr} failed: {e}", flush=True)

            self._transport = transport
            self._hello_mgr = hello_mgr
            self._forwarder = forwarder
            self._started = True

    def stop(self) -> None:
        """Stop Hello manager, L2CAP transport, and pairing agent."""
        with self._lock:
            if self._hello_mgr is not None:
                self._hello_mgr.stop()
                self._hello_mgr = None
            if self._transport is not None:
                self._transport.stop()
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
        """Send a broadcast PKT_DATA (dst=FF:FF:FF:FF:FF:FF) to the next L2CAP hop."""
        fwd = self._require_forwarder()
        hop = self._l2cap_hop_for(BROADCAST_BD_ADDR)
        if hop is None:
            raise RuntimeError("No L2CAP peers connected; cannot send PKT_DATA")
        fwd.send_data(text, BROADCAST_BD_ADDR, l2cap_peer=hop)

    def peers(self) -> list[str]:
        """Active L2CAP peer BD addresses."""
        if self._transport is None:
            return []
        return self._transport.connections()

    def is_relay(self) -> bool:
        """True if this node is a CDS relay (RELAY role)."""
        if self._hello_mgr is None:
            return False
        return self._hello_mgr.is_relay

    @property
    def local_bd_addr(self) -> str:
        return self._require_cfg().local_bd_addr

    @property
    def config(self) -> BubbleBlueConfig:
        return self._require_cfg()

    def _require_cfg(self) -> BubbleBlueConfig:
        if self._cfg is None:
            raise RuntimeError("BBNode not started; call start() first")
        return self._cfg

    def _require_forwarder(self) -> PacketForwarder:
        if self._forwarder is None:
            raise RuntimeError("BBNode not started; call start() first")
        return self._forwarder

    def _l2cap_hop_for(self, dst_bd_addr: str) -> str | None:
        """Pick L2CAP next hop toward ``dst_bd_addr`` (direct peer or first link)."""
        dst = dst_bd_addr.upper()
        connected = self.peers()
        if dst in connected:
            return dst
        if connected:
            return connected[0]
        return None

    def _on_chat_message(self, sender_bd_addr: str, text: str) -> None:
        cb = self.on_message
        if cb is not None:
            cb(sender_bd_addr, text)
            return
        print(f"[{sender_bd_addr}] {text}", flush=True)

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
