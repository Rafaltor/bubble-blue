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

from apps.mesh_control import decode_control, encode_control  # noqa: E402
from apps.meshd import MeshDaemon  # noqa: E402
from apps.protocol import encode  # noqa: E402

_LOCAL = "AA:BB:CC:DD:EE:01"


class _FakeNode:
    """Stands in for BBNode: same surface, no radio."""

    def __init__(self, peers=(), relay=False, send_error=None, coordinator=False):
        self.local_bd_addr = _LOCAL
        self.on_message = None
        self.on_log = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self._peers = list(peers)
        self._relay = relay
        self._send_error = send_error
        self._coordinator = coordinator
        self._epoch = 3
        self.sent = []
        self.private = []
        self.revoked = []
        self.resets = 0
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
        return self._epoch

    def is_coordinator(self):
        return self._coordinator

    def revoke_member(self, bd_addr):
        self.revoked.append(bd_addr)
        self._epoch += 1

    def reset_group(self):
        self.resets += 1
        self._epoch = 0

    def send_private_at_epoch(self, text, dst, epoch):
        self.private.append((dst, epoch, text))


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


_REMOTE = "AA:BB:CC:DD:EE:09"
_RELAY = "AA:BB:CC:DD:EE:02"


def test_routed_message_says_how_it_travelled():
    node = _FakeNode()
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        node.on_message_route(_REMOTE, "salut", _RELAY, 2)
        msg = conn.next_frame("message")
        assert msg["text"] == "salut"
        assert msg["via"] == _RELAY and msg["hops"] == 2
        conn.close()


def test_topology_reports_build_the_map_and_stay_out_of_the_chat():
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.next_frame("topology")
        report = encode_control("topo", peers=[_RELAY], relay=False, name="Rubik B", kind="screen")
        node.on_message_route(_REMOTE, report, _RELAY, 2)

        topo = conn.next_frame("topology")
        remote = next(n for n in topo["nodes"] if n["bd"] == _REMOTE)
        assert remote["name"] == "Rubik B" and remote["peers"] == [_RELAY]
        # Named by the report from now on, including in the chat.
        node.on_message_route(_REMOTE, "coucou", _RELAY, 2)
        msg = conn.next_frame("message")
        assert msg["text"] == "coucou" and msg["name"] == "Rubik B"

        second = h.connect()
        assert second.next_frame("hello")["history"] == [msg]
        conn.close()
        second.close()


def test_links_are_announced_to_the_mesh():
    node = _FakeNode(peers=[_RELAY], relay=True)
    with _Harness(node) as h:
        threading.Thread(target=h.daemon._poll_loop, daemon=True).start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not node.sent:
            time.sleep(0.05)
        body = decode_control(node.sent[0])
        assert body["t"] == "topo" and body["peers"] == [_RELAY] and body["relay"] is True


def test_ui_cannot_forge_a_control_message():
    node = _FakeNode()
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "send", "text": encode_control("restart", id="x"), "id": 5})
        conn.next_frame("ack")
        assert all(decode_control(t) is None for t in node.sent)
        conn.close()


def test_restart_floods_an_order_then_stops_the_daemon(monkeypatch):
    monkeypatch.setattr("apps.meshd._RESTART_GRACE_S", 0.1)
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "restart_mesh", "id": 9})
        assert conn.next_frame("ack")["ok"] is True
        assert conn.next_frame("restarting")
        assert h.daemon._stopped.wait(5.0)
        assert h.daemon.restart_requested is True
        orders = [decode_control(t) for t in node.sent]
        assert [o["t"] for o in orders] == ["restart", "restart"]
        assert orders[0]["id"] == orders[1]["id"]
        conn.close()


def test_restart_order_from_the_mesh(monkeypatch):
    monkeypatch.setattr("apps.meshd._RESTART_GRACE_S", 0.1)
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        h.daemon._started_at -= 3600
        node.on_message_route(_REMOTE, encode_control("restart", id="abcd"), _RELAY, 2)
        assert h.daemon._stopped.wait(5.0)
        assert h.daemon.restart_requested is True
        # Already relayed by the forwarder: re-sending it would only add load.
        assert node.sent == []


def test_fresh_daemon_ignores_a_late_restart_order(monkeypatch):
    # The order is still flooding when the first boards come back up.
    monkeypatch.setattr("apps.meshd._RESTART_GRACE_S", 0.1)
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        node.on_message_route(_REMOTE, encode_control("restart", id="abcd"), _RELAY, 2)
        assert not h.daemon._stopped.wait(0.5)
        assert h.daemon.restart_requested is False


class _FakeHealth:
    def __init__(self, *answers):
        self._answers = list(answers)

    def problem(self):
        return self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]


def test_dead_controller_restarts_this_board_only(monkeypatch):
    monkeypatch.setattr("apps.meshd._HEALTH_INTERVAL_S", 0.01)
    monkeypatch.setattr("apps.meshd._RESTART_GRACE_S", 0.1)
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        h.daemon._health = _FakeHealth("hci0 missing or not powered")
        threading.Thread(target=h.daemon._health_loop, daemon=True).start()
        assert h.daemon._stopped.wait(5.0)
        assert h.daemon.restart_requested is True
        assert h.daemon.rebind_requested is True
        # The rest of the mesh is healthy: no restart order goes out.
        assert node.sent == []


def test_a_single_failed_check_is_not_a_dead_controller(monkeypatch):
    monkeypatch.setattr("apps.meshd._HEALTH_INTERVAL_S", 0.01)
    node = _FakeNode(peers=[_RELAY])
    with _Harness(node) as h:
        h.daemon._health = _FakeHealth("hci0 missing or not powered", None, None, "x", None)
        threading.Thread(target=h.daemon._health_loop, daemon=True).start()
        assert not h.daemon._stopped.wait(0.5)
        assert h.daemon.rebind_requested is False


def test_kernel_tx_timeouts_are_recognised():
    from apps.meshd import is_tx_timeout

    assert is_tx_timeout("3,4406,67615698,-;Bluetooth: hci0: command 0x2039 tx timeout\n", "hci0")
    assert not is_tx_timeout("3,4406,67615698,-;Bluetooth: hci1: command 0x2039 tx timeout\n", "hci0")
    assert not is_tx_timeout("3,4407,67615699,-;Bluetooth: hci0: Opcode 0x2039 failed: -110\n", "hci0")


def test_revoke_asks_the_coordinator_to_rotate_the_key():
    from apps.mesh_control import decode_control

    node = _FakeNode(peers=[_RELAY], coordinator=True)
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        conn.send({"cmd": "revoke", "bd": _RELAY, "id": 3})
        assert conn.next_frame("ack")["ok"] is True
        assert conn.next_frame("revoked")["bd"] == _RELAY
        assert node.revoked == [_RELAY]
        assert node._epoch == 4
        kinds = [decode_control(t)["t"] for t in node.sent]
        assert kinds == ["revoke"]
        assert node.private[0][0] == _RELAY
        conn.close()


def test_revoke_received_rotates_only_on_the_coordinator():
    follower = _FakeNode(peers=[_RELAY], coordinator=False)
    with _Harness(follower) as h:
        h.daemon._on_control(_REMOTE, {"t": "revoke", "id": "abcd", "bd": _RELAY})
        assert follower.revoked == []
        assert _RELAY in h.daemon._revoked

    leader = _FakeNode(peers=[_RELAY], coordinator=True)
    with _Harness(leader) as h:
        h.daemon._on_control(_REMOTE, {"t": "revoke", "id": "abcd", "bd": _RELAY})
        assert leader.revoked == [_RELAY]


def test_reset_reaches_a_revoked_member_then_wipes_the_group():
    from apps.mesh_control import decode_control

    node = _FakeNode(peers=[_RELAY], coordinator=True)
    with _Harness(node) as h:
        conn = h.connect()
        conn.next_frame("hello")
        h.daemon._revoked[_RELAY] = 2
        conn.send({"cmd": "reset_demo", "id": 4})
        assert conn.next_frame("ack")["ok"] is True
        reset = conn.next_frame("demo_reset")
        assert reset["epoch"] == 0
        assert node.resets == 1
        assert h.daemon._revoked == {}
        assert node.private[0][0] == _RELAY and node.private[0][1] == 2
        assert decode_control(node.sent[-1])["t"] == "reset"
        conn.close()


def test_epoch_reset_returns_to_the_bootstrap_key():
    import tempfile

    from src.security.epoch import EpochStore

    bootstrap = b"\x11" * 32
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "epoch.bin")
        store = EpochStore(bootstrap, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01")
        store.prepare_revocation(b"\xaa" * 32)
        store.reset_to_bootstrap()
        assert store.current_epoch() == 0
        assert store.current_group_key() == bootstrap
        assert store.revoked_pubkeys() == frozenset()
        again = EpochStore(bootstrap, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01")
        assert again.current_epoch() == 0
        assert again.revoked_pubkeys() == frozenset()


def test_forwarder_counts_hops_from_the_ttl():
    from types import SimpleNamespace

    from src.forwarding.forwarder import PacketForwarder

    got = []
    fwd = object.__new__(PacketForwarder)
    fwd._cfg = SimpleNamespace(ttl_max=7)
    fwd._on_routed_message = lambda *a: got.append(a)
    fwd._on_deliver("aa:bb:cc:dd:ee:02", b"hi", {"src": "aa:bb:cc:dd:ee:09", "ttl": 7})
    fwd._on_deliver("aa:bb:cc:dd:ee:02", b"hi", {"src": "aa:bb:cc:dd:ee:09", "ttl": 5})
    assert got == [
        ("AA:BB:CC:DD:EE:09", "hi", "AA:BB:CC:DD:EE:02", 1),
        ("AA:BB:CC:DD:EE:09", "hi", "AA:BB:CC:DD:EE:02", 3),
    ]


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
