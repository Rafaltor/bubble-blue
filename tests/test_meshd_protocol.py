"""
The daemon<->UI contract, exercised without a Bluetooth adapter.

The screen app talks to the mesh only through this socket, so these are the
guarantees it is allowed to rely on: a snapshot on connect, an echo of what it
sent (BBNode deliberately does not loop local messages back), a failure that
stays a failure instead of a silent drop, and a daemon that survives a client
speaking nonsense.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.meshd import MeshDaemon  # noqa: E402
from apps.protocol import encode  # noqa: E402

_LOCAL = "AA:BB:CC:DD:EE:01"


class _FakeNode:
    """Stands in for BBNode: same surface, no radio."""

    def __init__(self, peers=(), relay=False, send_error=None):
        self.local_bd_addr = _LOCAL
        self.on_message = None
        self.on_log = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self._peers = list(peers)
        self._relay = relay
        self._send_error = send_error
        self.sent = []
        self.started = False

    def start(self, l2cap_accept_all=True):
        self.started = True

    def stop(self):
        self.started = False

    def send(self, text):
        if self._send_error:
            raise RuntimeError(self._send_error)
        self.sent.append(text)

    def peers(self):
        return list(self._peers)

    def is_relay(self):
        return self._relay

    def current_epoch(self):
        return 3


class _Harness:
    """Runs a daemon on a throwaway socket for the duration of a test."""

    def __init__(self, node):
        self.dir = tempfile.mkdtemp(prefix="meshd-test-")
        self.path = os.path.join(self.dir, "meshd.sock")
        self.daemon = MeshDaemon("hci0", self.path, node=node)
        self.node = node

    def __enter__(self):
        # _bind() chowns the socket, which needs root; the tests only need the
        # socket to exist, so bind it plainly here.
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        srv.listen(8)
        self.daemon._srv = srv
        self.node.start()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def _accept_loop(self):
        while not self.daemon._stopping.is_set():
            try:
                conn, _ = self.daemon._srv.accept()
            except OSError:
                return
            from apps.meshd import _Client

            client = _Client(conn)
            with self.daemon._clients_lock:
                self.daemon._clients.append(client)
            threading.Thread(
                target=self.daemon._serve_client, args=(client,), daemon=True
            ).start()

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        return _Conn(sock)

    def __exit__(self, *exc):
        self.daemon.shutdown()


class _Conn:
    def __init__(self, sock):
        self.sock = sock
        self.sock.settimeout(3.0)
        self._buf = b""

    def next_frame(self, ev=None, timeout=3.0):
        """Read frames until one matches ``ev`` (or the next one if ev is None)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                if not line.strip():
                    continue
                import json

                frame = json.loads(line)
                if ev is None or frame.get("ev") == ev:
                    return frame
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self._buf += chunk
        raise AssertionError(f"no frame {ev!r} within {timeout}s")

    def send(self, obj):
        self.sock.sendall(encode(obj))

    def send_raw(self, data: bytes):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def test_hello_carries_the_current_snapshot():
    node = _FakeNode(peers=["AA:BB:CC:DD:EE:02"], relay=True)
    with _Harness(node) as h:
        conn = h.connect()
        hello = conn.next_frame("hello")
        assert hello["local"] == _LOCAL
        assert hello["peers"] == ["AA:BB:CC:DD:EE:02"]
        assert hello["relay"] is True
        assert hello["epoch"] == 3
        assert hello["history"] == []
        conn.close()


def test_sent_message_is_acked_and_echoed_back():
    # BBNode never loops local messages back, so without this echo the sender's
    # own screen would stay empty.
    node = _FakeNode()
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "send", "text": "bonjour", "id": 7})

        ack = conn.next_frame("ack")
        assert ack["id"] == 7 and ack["ok"] is True

        msg = conn.next_frame("message")
        assert msg["text"] == "bonjour"
        assert msg["mine"] is True
        assert msg["from"] == _LOCAL
        assert node.sent == ["bonjour"]
        conn.close()


def test_send_failure_is_reported_not_swallowed():
    node = _FakeNode(send_error="no peer")
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "send", "text": "personne", "id": 1})
        ack = conn.next_frame("ack")
        assert ack["ok"] is False
        assert "no peer" in ack["error"]
        conn.close()


def test_incoming_message_reaches_every_client():
    node = _FakeNode()
    with _Harness(node) as h:
        a, b = h.connect(), h.connect()
        a.next_frame("hello")
        b.next_frame("hello")

        node.on_message("AA:BB:CC:DD:EE:09", "salut")

        for conn in (a, b):
            msg = conn.next_frame("message")
            assert msg["from"] == "AA:BB:CC:DD:EE:09"
            assert msg["text"] == "salut"
            assert msg["mine"] is False
        a.close()
        b.close()


def test_reconnecting_ui_gets_the_conversation_back():
    node = _FakeNode()
    with _Harness(node) as h:
        first = h.connect()
        first.next_frame("hello")
        node.on_message("AA:BB:CC:DD:EE:09", "avant")
        first.next_frame("message")
        first.close()

        second = h.connect()
        hello = second.next_frame("hello")
        assert [m["text"] for m in hello["history"]] == ["avant"]
        second.close()


def test_an_address_learned_after_connect_is_broadcast():
    # The socket is bound before the node has started, so a client can connect
    # in time to get a hello with no address. The periodic event is what makes
    # that recoverable rather than permanent.
    node = _FakeNode()
    node.local_bd_addr = ""
    with _Harness(node) as h:
        conn = h.connect()
        assert conn.next_frame("hello")["local"] == ""

        threading.Thread(target=h.daemon._poll_loop, daemon=True).start()
        node.local_bd_addr = _LOCAL

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            peers = conn.next_frame("peers", timeout=4.0)
            if peers["local"]:
                break
        assert peers["local"] == _LOCAL
        assert peers["epoch"] == 3
        conn.close()


def test_garbage_does_not_kill_the_daemon():
    node = _FakeNode()
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send_raw(b"not json at all\n{\n")
        conn.send({"cmd": "send", "text": "toujours la", "id": 2})
        ack = conn.next_frame("ack")
        assert ack["ok"] is True
        conn.close()


def test_unknown_command_is_rejected():
    node = _FakeNode()
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "autodestruction", "id": 4})
        ack = conn.next_frame("ack")
        assert ack["ok"] is False
        conn.close()


if __name__ == "__main__":
    for fn in (
        test_hello_carries_the_current_snapshot,
        test_sent_message_is_acked_and_echoed_back,
        test_send_failure_is_reported_not_swallowed,
        test_incoming_message_reaches_every_client,
        test_reconnecting_ui_gets_the_conversation_back,
        test_an_address_learned_after_connect_is_broadcast,
        test_garbage_does_not_kill_the_daemon,
        test_unknown_command_is_rejected,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All meshd protocol tests passed")
