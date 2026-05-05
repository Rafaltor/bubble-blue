from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from config import load_config


def _ts() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S.%f%z")


def _log(msg: str) -> None:
    print(f"[{_ts()}] {msg}", flush=True)


@dataclass(frozen=True)
class PeerConn:
    bd_addr: str
    sock: socket.socket
    thread: threading.Thread


class L2CAPTransport:
    """
    Simple L2CAP transport for Linux/BlueZ (AF_BLUETOOTH, BTPROTO_L2CAP).
    - Starts a server thread listening on config PSM
    - Supports multiple simultaneous peer connections
    - Invokes `on_receive(bd_addr, data)` for each received frame
    """

    def __init__(
        self,
        *,
        on_receive: Callable[[str, bytes], None] | None = None,
        backlog: int = 5,
    ) -> None:
        self._cfg = load_config()
        self._psm = int(self._cfg.psm)
        self._backlog = backlog

        self.on_receive: Callable[[str, bytes], None] = on_receive or (lambda _a, _d: None)

        self._lock = threading.RLock()
        self._conns: dict[str, PeerConn] = {}

        self._server_sock: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._stop_evt = threading.Event()

    def start(self) -> None:
        with self._lock:
            if self._server_thread and self._server_thread.is_alive():
                return

            self._stop_evt.clear()
            self._server_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self._cfg.local_bd_addr, self._psm))
            self._server_sock.listen(self._backlog)

            self._server_thread = threading.Thread(target=self._server_loop, name="l2cap-server", daemon=True)
            self._server_thread.start()

        _log(f"L2CAP server listening src={self._cfg.local_bd_addr} psm=0x{self._psm:04X}")

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

        _log("L2CAP transport stopped")

    def connect(self, bd_addr: str) -> None:
        bd_addr = bd_addr.upper()

        with self._lock:
            existing = self._conns.get(bd_addr)
            if existing and existing.sock.fileno() != -1:
                return

            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
            sock.connect((bd_addr, self._psm))

            t = threading.Thread(target=self._recv_loop, args=(bd_addr, sock), name=f"l2cap-rx-{bd_addr}", daemon=True)
            self._conns[bd_addr] = PeerConn(bd_addr=bd_addr, sock=sock, thread=t)
            t.start()

        _log(f"L2CAP connected src={self._cfg.local_bd_addr} dst={bd_addr} psm=0x{self._psm:04X}")

    def send(self, bd_addr: str, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        bd_addr = bd_addr.upper()
        with self._lock:
            peer = self._conns.get(bd_addr)
        if not peer or peer.sock.fileno() == -1:
            self.connect(bd_addr)
            with self._lock:
                peer = self._conns.get(bd_addr)
        if not peer:
            raise RuntimeError(f"Could not establish connection to {bd_addr}")

        payload = bytes(data)
        peer.sock.sendall(payload)
        _log(f"L2CAP tx src={self._cfg.local_bd_addr} dst={bd_addr} bytes={len(payload)}")

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
                    name=f"l2cap-rx-{peer_bd_addr}",
                    daemon=True,
                )
                self._conns[peer_bd_addr] = PeerConn(bd_addr=peer_bd_addr, sock=client_sock, thread=t)
                t.start()

            _log(f"L2CAP accepted src={self._cfg.local_bd_addr} dst={peer_bd_addr} psm=0x{self._psm:04X}")

    def _recv_loop(self, bd_addr: str, sock: socket.socket) -> None:
        try:
            while not self._stop_evt.is_set():
                data = sock.recv(4096)
                if not data:
                    break
                _log(f"L2CAP rx src={bd_addr} dst={self._cfg.local_bd_addr} bytes={len(data)}")
                try:
                    self.on_receive(bd_addr, data)
                except Exception as e:  # noqa: BLE001
                    _log(f"on_receive error src={bd_addr}: {e}")
        except OSError as e:
            _log(f"L2CAP socket error peer={bd_addr}: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                cur = self._conns.get(bd_addr)
                if cur and cur.sock is sock:
                    self._conns.pop(bd_addr, None)
            _log(f"L2CAP disconnected peer={bd_addr}")

