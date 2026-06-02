from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from config import load_config


def _ts() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S.%f%z")


def _tlog_always(node: str, msg: str) -> None:
    """Logs that should remain visible even in quiet experiments (failures)."""
    print(f"[{_ts()}] [{node}] {msg}", flush=True)


def _tlog(node: str, msg: str, *, quiet: bool) -> None:
    if quiet:
        return
    _tlog_always(node, msg)


@dataclass(frozen=True)
class PeerConn:
    bd_addr: str
    sock: socket.socket
    thread: threading.Thread


class L2CAPTransport:
    """
    Linux/BlueZ L2CAP (AF_BLUETOOTH, BTPROTO_L2CAP) transport.

    Design goals for BUBBLE-BLUE:
    - symmetric node: every node can accept and initiate connections
    - multi-connection: keep a per-peer socket + rx thread
    - clear logs: timestamp + node name + src/dst
    """

    def __init__(
        self,
        *,
        on_receive: Callable[[str, bytes], None] | None = None,
        backlog: int = 10,
        interface: str = "hci0",
        quiet: bool = False,
        allowed_peers: frozenset[str] | None = None,
    ) -> None:
        self._cfg = load_config(interface=interface)
        self._node = self._cfg.node_name
        self._psm = int(self._cfg.psm)
        self._backlog = backlog
        self._quiet = quiet
        self._allowed_peers = (
            frozenset(a.upper() for a in allowed_peers) if allowed_peers is not None else None
        )

        self.on_receive: Callable[[str, bytes], None] = on_receive or (lambda _a, _d: None)

        self._lock = threading.RLock()
        self._conns: dict[str, PeerConn] = {}

        self._server_sock: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._stop_evt = threading.Event()

    def _peer_allowed(self, bd_addr: str) -> bool:
        if self._allowed_peers is None:
            return True
        return bd_addr.upper() in self._allowed_peers

    def start(self) -> None:
        with self._lock:
            if self._server_thread and self._server_thread.is_alive():
                return

            self._stop_evt.clear()

            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self._cfg.local_bd_addr, self._psm))
            s.listen(self._backlog)

            self._server_sock = s
            self._server_thread = threading.Thread(target=self._server_loop, name="bb-l2cap-server", daemon=True)
            self._server_thread.start()

        _tlog(
            self._node,
            f"L2CAP listen src={self._cfg.local_bd_addr} psm=0x{self._psm:04X} backlog={self._backlog}",
            quiet=self._quiet,
        )
        if self._allowed_peers is not None:
            peers = ", ".join(sorted(self._allowed_peers))
            _tlog_always(self._node, f"L2CAP topology allowlist ({len(self._allowed_peers)}): {peers}")

    def stop(self) -> None:
        self._stop_evt.set()

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

        _tlog(self._node, "L2CAP stopped", quiet=self._quiet)

    def connect(self, bd_addr: str) -> None:
        bd_addr = bd_addr.upper()
        if not self._peer_allowed(bd_addr):
            _tlog_always(
                self._node,
                f"L2CAP connect rejected (not in topology) peer={bd_addr}",
            )
            return

        with self._lock:
            existing = self._conns.get(bd_addr)
            if existing and existing.sock.fileno() != -1:
                return

            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
            sock.connect((bd_addr, self._psm))

            t = threading.Thread(
                target=self._recv_loop,
                args=(bd_addr, sock),
                name=f"bb-l2cap-rx-{bd_addr}",
                daemon=True,
            )
            self._conns[bd_addr] = PeerConn(bd_addr=bd_addr, sock=sock, thread=t)
            t.start()

        _tlog(
            self._node,
            f"L2CAP connect src={self._cfg.local_bd_addr} dst={bd_addr} psm=0x{self._psm:04X}",
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
            self.connect(bd_addr)
            with self._lock:
                peer = self._conns.get(bd_addr)

        if not peer:
            raise RuntimeError(f"Could not establish L2CAP connection to {bd_addr}")

        payload = bytes(data)
        peer.sock.sendall(payload)
        _tlog(
            self._node,
            f"L2CAP tx src={self._cfg.local_bd_addr} dst={bd_addr} bytes={len(payload)}",
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

            # BlueZ returns (bdaddr, psm) for L2CAP stream accept()
            peer_bd_addr = str(client_info[0]).upper() if client_info else "UNKNOWN"

            if not self._peer_allowed(peer_bd_addr):
                _tlog_always(
                    self._node,
                    f"L2CAP accept rejected (not in topology) peer={peer_bd_addr}",
                )
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            with self._lock:
                old = self._conns.get(peer_bd_addr)
                if old:
                    try:
                        old.sock.close()
                    except OSError:
                        pass

                t = threading.Thread(
                    target=self._recv_loop,
                    args=(peer_bd_addr, client_sock),
                    name=f"bb-l2cap-rx-{peer_bd_addr}",
                    daemon=True,
                )
                self._conns[peer_bd_addr] = PeerConn(bd_addr=peer_bd_addr, sock=client_sock, thread=t)
                t.start()

            _tlog(
                self._node,
                f"L2CAP accept src={peer_bd_addr} dst={self._cfg.local_bd_addr} psm=0x{self._psm:04X}",
                quiet=self._quiet,
            )

    def _recv_loop(self, peer_bd_addr: str, sock: socket.socket) -> None:
        try:
            while not self._stop_evt.is_set():
                data = sock.recv(4096)
                if not data:
                    break

                _tlog(
                    self._node,
                    f"L2CAP rx src={peer_bd_addr} dst={self._cfg.local_bd_addr} bytes={len(data)}",
                    quiet=self._quiet,
                )
                try:
                    self.on_receive(peer_bd_addr, data)
                except Exception as e:  # noqa: BLE001
                    _tlog_always(self._node, f"on_receive error src={peer_bd_addr}: {e}")
        except OSError as e:
            _tlog_always(self._node, f"L2CAP socket error peer={peer_bd_addr}: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                cur = self._conns.get(peer_bd_addr)
                if cur and cur.sock is sock:
                    self._conns.pop(peer_bd_addr, None)
            _tlog(self._node, f"L2CAP disconnect peer={peer_bd_addr}", quiet=self._quiet)

