#!/usr/bin/env python3.14
"""
Mesh daemon: owns the BBNode and serves it to local UI clients.

Run as root (L2CAP and MGMT both need it), one instance per board:

    sudo python3.14 apps/meshd.py

The UI connects to the AF_UNIX socket and never touches Bluetooth itself. That
split is not decoration: the mesh takes ~40 s to converge, so a UI that crashes
or gets restarted during development must not take the links down with it. It
also keeps the graphical stack — by far the largest attack surface here — out
of the root process.
"""

from __future__ import annotations

import argparse
import grp
import os
import signal
import socket
import sys
import threading
import time
from collections import deque
from queue import Empty, Full, Queue

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.protocol import (  # noqa: E402
    CLIENT_QUEUE_LIMIT,
    HISTORY_LIMIT,
    encode,
    read_frames,
    socket_path,
)
from src.api.bb_api import BBNode  # noqa: E402

# Peers and relay status have no callback of their own, so poll them and emit
# an event only when the picture actually changes.
_POLL_INTERVAL_S = 1.0


class _Client:
    """One connected UI. Writes go through a queue so a stalled UI cannot block
    the mesh callbacks that feed it."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.queue: Queue = Queue(maxsize=CLIENT_QUEUE_LIMIT)
        self.alive = True

    def send(self, frame: dict) -> None:
        if not self.alive:
            return
        try:
            self.queue.put_nowait(frame)
        except Full:
            # Client is not draining; disconnect it rather than grow forever.
            self.alive = False

    def writer_loop(self) -> None:
        while self.alive:
            try:
                frame = self.queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                self.sock.sendall(encode(frame))
            except OSError:
                self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class MeshDaemon:
    def __init__(self, interface: str, path: str, node=None) -> None:
        self.path = path
        # ``node`` is injected by the tests so the protocol can be exercised
        # without an adapter; production always builds a real BBNode.
        self.node = node if node is not None else BBNode(interface=interface, quiet=True)
        self.node.on_message = self._on_message
        self.node.on_peer_connected = lambda bd: self._on_log(f"peer up {bd}", False)
        self.node.on_peer_disconnected = lambda bd: self._on_log(f"peer down {bd}", False)
        self.node.on_log = self._on_log

        self._clients: list[_Client] = []
        self._clients_lock = threading.Lock()
        self._history: deque = deque(maxlen=HISTORY_LIMIT)
        self._history_lock = threading.Lock()
        self._last_view: tuple | None = None
        self._stopping = threading.Event()
        self._srv: socket.socket | None = None

    # ---- BBNode callbacks (runtime threads) ----------------------------

    def _on_message(self, sender_bd: str, text: str) -> None:
        self._record_and_broadcast(sender_bd, text, mine=False)

    def _on_log(self, text: str, is_err: bool) -> None:
        self._broadcast({"ev": "log", "text": str(text), "error": bool(is_err)})

    def _record_and_broadcast(self, sender: str, text: str, mine: bool) -> None:
        frame = {
            "ev": "message",
            "from": sender,
            "text": text,
            "ts": time.time(),
            "mine": mine,
        }
        with self._history_lock:
            self._history.append(frame)
        self._broadcast(frame)

    # ---- fan-out --------------------------------------------------------

    def _broadcast(self, frame: dict) -> None:
        with self._clients_lock:
            clients = list(self._clients)
        for c in clients:
            c.send(frame)

    def _poll_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                view = (
                    tuple(sorted(self.node.peers())),
                    bool(self.node.is_relay()),
                    str(self.node.local_bd_addr or ""),
                    int(self.node.current_epoch()),
                )
            except Exception:  # noqa: BLE001 — node still starting up
                self._stopping.wait(_POLL_INTERVAL_S)
                continue
            if view != self._last_view:
                self._last_view = view
                peers, relay, local, epoch = view
                # local and epoch ride along because the socket is bound before
                # the node has finished starting: a client that connects during
                # those seconds gets a hello with no address, and this is what
                # corrects it.
                self._broadcast({
                    "ev": "peers",
                    "peers": list(peers),
                    "relay": relay,
                    "local": local,
                    "epoch": epoch,
                })
            self._stopping.wait(_POLL_INTERVAL_S)

    # ---- client handling ------------------------------------------------

    def _hello_frame(self) -> dict:
        try:
            peers = sorted(self.node.peers())
            relay = bool(self.node.is_relay())
            epoch = int(self.node.current_epoch())
        except Exception:  # noqa: BLE001
            peers, relay, epoch = [], False, 0
        with self._history_lock:
            history = list(self._history)
        return {
            "ev": "hello",
            "local": str(self.node.local_bd_addr or ""),
            "relay": relay,
            "epoch": epoch,
            "peers": peers,
            "history": history,
        }

    def _serve_client(self, client: _Client) -> None:
        threading.Thread(target=client.writer_loop, daemon=True).start()
        client.send(self._hello_frame())
        for frame in read_frames(client.sock):
            if not client.alive:
                break
            self._handle_command(client, frame)
        client.alive = False
        with self._clients_lock:
            if client in self._clients:
                self._clients.remove(client)

    def _handle_command(self, client: _Client, frame: dict) -> None:
        cmd = frame.get("cmd")
        req_id = frame.get("id")
        if cmd == "send":
            text = str(frame.get("text", "")).strip()
            if not text:
                client.send({"ev": "ack", "id": req_id, "ok": False, "error": "empty"})
                return
            try:
                self.node.send(text)
            except Exception as e:  # noqa: BLE001 — no peer yet is the common case
                client.send({"ev": "ack", "id": req_id, "ok": False, "error": str(e)})
                return
            client.send({"ev": "ack", "id": req_id, "ok": True, "error": ""})
            # Locally sent messages never come back through on_message, so echo
            # them here — that way every connected UI shows the same thread.
            self._record_and_broadcast(self.node.local_bd_addr, text, mine=True)
        elif cmd == "status":
            client.send(self._hello_frame())
        else:
            client.send({"ev": "ack", "id": req_id, "ok": False, "error": "unknown command"})

    # ---- lifecycle ------------------------------------------------------

    def _bind(self, group: str | None) -> socket.socket:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(self.path):
            os.unlink(self.path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        srv.listen(8)

        # The UI runs unprivileged, so hand it group access rather than making
        # the socket world-writable — anyone who can write here can post to the
        # group chat as this board. Only root may chown, so the fake daemon used
        # for UI development just keeps the socket owned by its own user.
        if os.geteuid() == 0:
            gid = -1
            if group:
                gid = grp.getgrnam(group).gr_gid
            elif os.environ.get("SUDO_GID"):
                gid = int(os.environ["SUDO_GID"])
            if gid != -1:
                os.chown(self.path, 0, gid)
        os.chmod(self.path, 0o660)
        return srv

    def run(self, group: str | None, accept_all: bool) -> int:
        self._srv = self._bind(group)
        self.node.start(l2cap_accept_all=accept_all)
        threading.Thread(target=self._poll_loop, daemon=True).start()

        print(f"meshd local={self.node.local_bd_addr} socket={self.path}", flush=True)

        try:
            while not self._stopping.is_set():
                try:
                    conn, _ = self._srv.accept()
                except OSError:
                    break
                client = _Client(conn)
                with self._clients_lock:
                    self._clients.append(client)
                threading.Thread(target=self._serve_client, args=(client,), daemon=True).start()
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        with self._clients_lock:
            for c in self._clients:
                c.alive = False
            self._clients.clear()
        try:
            self.node.stop()
        except Exception:  # noqa: BLE001
            pass
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interface", default="hci0")
    ap.add_argument("--socket", default=socket_path(), help="AF_UNIX path")
    ap.add_argument("--group", default=None, help="group granted access to the socket")
    ap.add_argument(
        "--no-accept-all",
        action="store_true",
        help="refuse inbound L2CAP (dial-only node)",
    )
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("meshd needs root for L2CAP and MGMT", file=sys.stderr)
        return 1

    daemon = MeshDaemon(args.interface, args.socket)

    def _bye(_signum, _frame):
        daemon.shutdown()

    signal.signal(signal.SIGINT, _bye)
    signal.signal(signal.SIGTERM, _bye)
    return daemon.run(args.group, accept_all=not args.no_accept_all)


if __name__ == "__main__":
    raise SystemExit(main())
