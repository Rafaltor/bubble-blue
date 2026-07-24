"""
BLE L2CAP Connection-oriented Channels (CoC) transport for BUBBLE-BLUE.

Requires **Python 3.14+** with LE L2CAP socket support (``BDADDR_LE_PUBLIC``).
Interchangeable with ``L2CAPTransport`` via ``make_transport("ble_l2cap")``.

Differences from BT Classic ``l2cap.py``:
  1. ``SOCK_SEQPACKET`` + 4-tuple LE address ``(bd, psm, cid, bdaddr_type)``
  2. ``PSM_BLE`` (0x0081) from config — LE CoC listen PSM
  3. BlueZ LE CoC bring-up (``coc_server`` / ``coc_client``): bind LE first,
     then ``BT_MODE_LE_FLOWCTL`` + ``BT_SECURITY_LOW`` (no link encryption —
     BB secures the payload at the app layer, so no SMP bonding is needed);
     outbound uses ``bind(BDADDR_ANY, psm=0)`` before ``connect``
  4. Negotiated MTU (target ``MTU_BLE`` = 512), exposed as ``self.mtu``
  5. Optional fragmentation (``fragmentation.py``) only when wire size > MTU

Normal chat (≤ max_payload) is sent **without** fragment headers. On receive,
packets with ``FRAG_MARKER`` (0xFB) at byte 0 are reassembled per peer; all
other wires are delivered directly to ``on_receive``.

Functional two-board testing is out of scope for ``__main__`` (environment check only).
"""

from __future__ import annotations

import errno
import socket
import sys
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable

if sys.version_info < (3, 14):
    raise RuntimeError(
        "BLE L2CAP CoC transport requires Python 3.14+ (LE L2CAP socket API)"
    )

if not hasattr(socket, "BDADDR_LE_PUBLIC"):
    raise RuntimeError(
        "BLE L2CAP CoC transport requires socket.BDADDR_LE_PUBLIC "
        "(Python 3.14+ build with LE L2CAP support)"
    )

from config import MTU_BLE, PSM_BLE, load_config  # noqa: E402
from src.transport.advertising import LEAdvertiser  # noqa: E402
from src.transport.ble_coc import (  # noqa: E402
    LE_ADDR_TYPE,
    le_addr_types_to_try,
    open_listener,
    open_outbound,
)
from src.transport.fragmentation import (  # noqa: E402
    HEADER_SIZE,
    Reassembler,
    fragment,
    is_fragment_packet,
)


# Per-attempt outbound dial timeout. Kept short so a dial to a momentarily
# unreachable/non-connectable peer fails fast instead of stalling the one-dial-
# per-pass connect loop (a reachable peer connects well under a second).
_DIAL_TIMEOUT_S = 8.0


def _ts() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S.%f%z")


def _tlog_always(node: str, msg: str) -> None:
    print(f"[{_ts()}] [{node}] {msg}", flush=True)


def _tlog(node: str, msg: str, *, quiet: bool) -> None:
    if quiet:
        return
    _tlog_always(node, msg)


def _expected_socket_close(err: OSError, *, stopping: bool, replaced: bool) -> bool:
    if stopping or replaced:
        return True
    return err.errno in (
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.EPIPE,
        errno.ENOTCONN,
        errno.EBADF,
    )


def _should_initiate_connect(local_bd_addr: str, remote_bd_addr: str) -> bool:
    return local_bd_addr.upper() < remote_bd_addr.upper()


def _probe_negotiated_mtu(sock: socket.socket, *, default: int) -> int:
    """Read BT_SNDMTU/BT_RCVMTU when the platform exposes them."""
    for name in ("BT_SNDMTU", "BT_RCVMTU", "BT_MTU"):
        opt = getattr(socket, name, None)
        if opt is None:
            continue
        try:
            value = sock.getsockopt(socket.SOL_BLUETOOTH, opt)
            if isinstance(value, int) and value > HEADER_SIZE:
                return value
        except OSError:
            continue
    return default


@dataclass(frozen=True)
class PeerConn:
    bd_addr: str
    sock: socket.socket
    thread: threading.Thread


class BLEL2CAPTransport:
    """
    Linux/BlueZ BLE L2CAP CoC (``SOCK_SEQPACKET``) — ``ManagedTransport`` twin of
    ``L2CAPTransport`` with LE addressing and optional fragmentation.
    """

    def __init__(
        self,
        *,
        on_receive: Callable[[str, bytes], None] | None = None,
        backlog: int = 10,
        interface: str = "hci0",
        quiet: bool = False,
        allowed_peers: frozenset[str] | None = None,
        on_peer_connected: Callable[[str], None] | None = None,
        on_peer_disconnected: Callable[[str], None] | None = None,
        bdaddr_type: int | None = None,
    ) -> None:
        self._cfg = replace(
            load_config(interface=interface),
            transport_kind="ble_l2cap",
            psm=PSM_BLE,
        )
        self._node = self._cfg.node_name
        self._psm = int(self._cfg.psm)
        self._backlog = backlog
        self._quiet = quiet
        self._allowed_peers = (
            frozenset(a.upper() for a in allowed_peers) if allowed_peers is not None else None
        )
        self._bdaddr_type = (
            int(bdaddr_type) if bdaddr_type is not None else LE_ADDR_TYPE
        )

        self.on_receive: Callable[[str, bytes], None] = on_receive or (lambda _a, _d: None)
        self.on_peer_connected = on_peer_connected
        self.on_peer_disconnected = on_peer_disconnected

        self.mtu: int = MTU_BLE

        self._lock = threading.RLock()
        self._conns: dict[str, PeerConn] = {}
        self._reassemblers: dict[str, Reassembler] = {}
        self._frag_id = 0
        self._frag_lock = threading.Lock()

        self._server_sock: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._advertiser = LEAdvertiser(interface=interface, quiet=quiet)

    def update_presence(self, value: bytes) -> None:
        """
        Set the connectable advertisement's manufacturer payload.

        Carries the compact connectionless presence Hello (anon_id + reachable
        L2CAP address + CDS relay flag) in the legacy 31-byte advertisement so
        controllers that can only do legacy scanning still hear presence — extended
        advertising is invisible to a legacy scanner.
        """
        self._advertiser.set_value(value)

    def _rearm_advertising(self) -> None:
        """Non-blocking advertising re-arm after connect/disconnect (legacy LE)."""
        if not self._advertiser.running:
            return
        threading.Thread(
            target=self._advertiser.ensure,
            name="bb-adv-ensure",
            daemon=True,
        ).start()

    def _le_addr(self, bd_addr: str) -> tuple[str, int, int, int]:
        return (bd_addr.upper(), self._psm, 0, self._bdaddr_type)

    def _peer_allowed(self, bd_addr: str) -> bool:
        if self._allowed_peers is None:
            return True
        return bd_addr.upper() in self._allowed_peers

    def _next_frag_msg_id(self) -> int:
        with self._frag_lock:
            self._frag_id = (self._frag_id + 1) & 0xFFFF
            return self._frag_id

    def start(self) -> None:
        with self._lock:
            if self._server_thread and self._server_thread.is_alive():
                return

            self._stop_evt.clear()
            self._advertiser.start()

            s = open_listener(psm=self._psm, backlog=self._backlog)
            self.mtu = _probe_negotiated_mtu(s, default=MTU_BLE)

            self._server_sock = s
            self._server_thread = threading.Thread(
                target=self._server_loop,
                name="bb-ble-l2cap-server",
                daemon=True,
            )
            self._server_thread.start()

        _tlog(
            self._node,
            f"BLE L2CAP listen src={self._cfg.local_bd_addr} psm=0x{self._psm:04X} "
            f"mtu={self.mtu} bdaddr_type={self._bdaddr_type}",
            quiet=self._quiet,
        )
        if self._allowed_peers is not None:
            peers = ", ".join(sorted(self._allowed_peers))
            _tlog_always(
                self._node,
                f"BLE L2CAP topology allowlist ({len(self._allowed_peers)}): {peers}",
            )

    def stop(self) -> None:
        self._stop_evt.set()
        self._advertiser.stop()

        with self._lock:
            if self._server_sock:
                try:
                    self._server_sock.close()
                except OSError:
                    pass
                self._server_sock = None

            for bd_addr, peer in list(self._conns.items()):
                try:
                    peer.sock.close()
                except OSError:
                    pass
                self._conns.pop(bd_addr, None)
            self._reassemblers.clear()

        _tlog(self._node, "BLE L2CAP stopped", quiet=self._quiet)

    def mute(self) -> None:
        """Stop LE advertising only (scanner muted separately via BBNode)."""
        self._advertiser.mute()

    def disconnect(self, bd_addr: str) -> None:
        """Close an established peer link (does not block the caller)."""
        bd_addr = bd_addr.upper()
        with self._lock:
            peer = self._conns.get(bd_addr)
        if peer is None:
            return
        try:
            peer.sock.close()
        except OSError:
            pass

    def connect(
        self, bd_addr: str, *, addr_type: int | str | None = None, force: bool = False
    ) -> None:
        bd_addr = bd_addr.upper()
        local = self._cfg.local_bd_addr.upper()
        if bd_addr == local:
            _tlog_always(
                self._node,
                f"BLE L2CAP connect to self ignored (local={local})",
            )
            return

        if not self._peer_allowed(bd_addr):
            _tlog_always(
                self._node,
                f"BLE L2CAP connect rejected (not in topology) peer={bd_addr}",
            )
            return

        # The lower-BD tie-break avoids both sides dialing in legacy full-mesh.
        # ``force`` bypasses it so a caller that already decided the dial direction
        # (e.g. the connectionless CDS backbone plan) is honoured instead of being
        # silently vetoed here.
        if not force and not _should_initiate_connect(self._cfg.local_bd_addr, bd_addr):
            return

        is_new = False
        with self._lock:
            existing = self._conns.get(bd_addr)
            if existing and existing.sock.fileno() != -1:
                return

        last_err: OSError | None = None
        sock: socket.socket | None = None
        for try_type in le_addr_types_to_try(addr_type):
            try:
                sock = open_outbound(
                    bd_addr,
                    psm=self._psm,
                    addr_type=try_type,
                    timeout=_DIAL_TIMEOUT_S,
                )
                break
            except OSError as e:
                last_err = e
        if sock is None:
            assert last_err is not None
            raise last_err

        mtu = _probe_negotiated_mtu(sock, default=self.mtu)

        with self._lock:
            existing = self._conns.get(bd_addr)
            if existing and existing.sock.fileno() != -1:
                try:
                    sock.close()
                except OSError:
                    pass
                return

            self.mtu = min(self.mtu, mtu) if self.mtu else mtu

            t = threading.Thread(
                target=self._recv_loop,
                args=(bd_addr, sock),
                name=f"bb-ble-l2cap-rx-{bd_addr}",
                daemon=True,
            )
            self._conns[bd_addr] = PeerConn(bd_addr=bd_addr, sock=sock, thread=t)
            t.start()
            is_new = True

        if is_new and self.on_peer_connected:
            self.on_peer_connected(bd_addr)

        if is_new:
            self._rearm_advertising()

        _tlog(
            self._node,
            f"BLE L2CAP connect src={self._cfg.local_bd_addr} dst={bd_addr} "
            f"psm=0x{self._psm:04X} mtu={self.mtu}",
            quiet=self._quiet,
        )

    def send(self, bd_addr: str, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        bd_addr = bd_addr.upper()

        with self._lock:
            peer = self._conns.get(bd_addr)
            ok = bool(peer and peer.sock.fileno() != -1)

        if not ok:
            if _should_initiate_connect(self._cfg.local_bd_addr, bd_addr):
                self.connect(bd_addr)
            with self._lock:
                peer = self._conns.get(bd_addr)

        if not peer or peer.sock.fileno() == -1:
            raise RuntimeError(f"Could not establish BLE L2CAP connection to {bd_addr}")

        payload = bytes(data)
        if len(payload) <= self.mtu:
            wires = [payload]
        else:
            wires = fragment(payload, self.mtu, self._next_frag_msg_id())

        try:
            for wire in wires:
                peer.sock.send(wire)
        except OSError:
            with self._lock:
                cur = self._conns.get(bd_addr)
                if cur is peer:
                    self._conns.pop(bd_addr, None)
                    self._reassemblers.pop(bd_addr, None)
            raise

        _tlog(
            self._node,
            f"BLE L2CAP tx src={self._cfg.local_bd_addr} dst={bd_addr} "
            f"bytes={len(payload)} wire_pkts={len(wires)}",
            quiet=self._quiet,
        )

    def connections(self) -> list[str]:
        with self._lock:
            return sorted(self._conns.keys())

    def _server_loop(self) -> None:
        assert self._server_sock is not None
        server_sock = self._server_sock

        while not self._stop_evt.is_set():
            try:
                client_sock, client_info = server_sock.accept()
            except OSError:
                break

            peer_bd_addr = str(client_info[0]).upper() if client_info else "UNKNOWN"

            if not self._peer_allowed(peer_bd_addr):
                _tlog_always(
                    self._node,
                    f"BLE L2CAP accept rejected (not in topology) peer={peer_bd_addr}",
                )
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            with self._lock:
                old = self._conns.get(peer_bd_addr)
                if old and old.sock.fileno() != -1:
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    _tlog(
                        self._node,
                        f"BLE L2CAP duplicate accept ignored peer={peer_bd_addr}",
                        quiet=self._quiet,
                    )
                    continue

                mtu = _probe_negotiated_mtu(client_sock, default=self.mtu)
                self.mtu = min(self.mtu, mtu) if self.mtu else mtu

                t = threading.Thread(
                    target=self._recv_loop,
                    args=(peer_bd_addr, client_sock),
                    name=f"bb-ble-l2cap-rx-{peer_bd_addr}",
                    daemon=True,
                )
                self._conns[peer_bd_addr] = PeerConn(
                    bd_addr=peer_bd_addr, sock=client_sock, thread=t
                )
                t.start()

            if self.on_peer_connected:
                self.on_peer_connected(peer_bd_addr)

            self._rearm_advertising()

            _tlog(
                self._node,
                f"BLE L2CAP accept src={peer_bd_addr} dst={self._cfg.local_bd_addr} "
                f"psm=0x{self._psm:04X}",
                quiet=self._quiet,
            )

    def _deliver_rx(self, peer_bd_addr: str, data: bytes) -> None:
        if is_fragment_packet(data):
            with self._lock:
                reasm = self._reassemblers.setdefault(peer_bd_addr, Reassembler())
            complete = reasm.push(data)
            if complete is None:
                return
            data = complete
            with self._lock:
                if reasm.pending_count() == 0:
                    self._reassemblers.pop(peer_bd_addr, None)

        try:
            self.on_receive(peer_bd_addr, data)
        except Exception as e:  # noqa: BLE001
            _tlog_always(self._node, f"on_receive error src={peer_bd_addr}: {e}")

    def _recv_loop(self, peer_bd_addr: str, sock: socket.socket) -> None:
        try:
            while not self._stop_evt.is_set():
                try:
                    data = sock.recv(self.mtu)
                except OSError as e:
                    with self._lock:
                        cur = self._conns.get(peer_bd_addr)
                        replaced = cur is None or cur.sock is not sock
                    if _expected_socket_close(
                        e, stopping=self._stop_evt.is_set(), replaced=replaced
                    ):
                        break
                    raise
                if not data:
                    break

                _tlog(
                    self._node,
                    f"BLE L2CAP rx src={peer_bd_addr} dst={self._cfg.local_bd_addr} "
                    f"bytes={len(data)}",
                    quiet=self._quiet,
                )
                self._deliver_rx(peer_bd_addr, data)
        except OSError as e:
            with self._lock:
                cur = self._conns.get(peer_bd_addr)
                replaced = cur is None or cur.sock is not sock
            if not _expected_socket_close(
                e, stopping=self._stop_evt.is_set(), replaced=replaced
            ):
                _tlog_always(self._node, f"BLE L2CAP socket error peer={peer_bd_addr}: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass
            removed = False
            with self._lock:
                cur = self._conns.get(peer_bd_addr)
                if cur and cur.sock is sock:
                    self._conns.pop(peer_bd_addr, None)
                    self._reassemblers.pop(peer_bd_addr, None)
                    removed = True
            if removed and self.on_peer_disconnected:
                self.on_peer_disconnected(peer_bd_addr)
            if removed:
                self._rearm_advertising()
                _tlog(self._node, f"BLE L2CAP disconnect peer={peer_bd_addr}", quiet=self._quiet)


if __name__ == "__main__":
    from src.transport.ble_coc import bind_outbound, new_socket

    print(f"Python {sys.version_info.major}.{sys.version_info.minor} OK (>= 3.14)")
    print(f"socket.BDADDR_LE_PUBLIC = {socket.BDADDR_LE_PUBLIC}")
    print(f"socket.BDADDR_LE_RANDOM = {getattr(socket, 'BDADDR_LE_RANDOM', 'n/a')}")

    print(f"LE listen PSM=0x{PSM_BLE:04X} bdaddr_type=BDADDR_LE_PUBLIC")

    s = open_listener(psm=PSM_BLE, backlog=1)
    try:
        mtu = _probe_negotiated_mtu(s, default=MTU_BLE)
        print(f"LE listen bind OK — BT_MODE=LE_FLOWCTL, mtu={mtu}")
    finally:
        s.close()

    c = new_socket()
    try:
        bind_outbound(c)
        print("LE outbound bind OK — BT_MODE=LE_FLOWCTL (psm=0 auto)")
    finally:
        c.close()

    print(
        "\n✅ BLE L2CAP environment self-check passed "
        "(no peer connection — use two boards for functional test)"
    )
