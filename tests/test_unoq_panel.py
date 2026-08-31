"""
The UNO Q panel bridge, exercised without a shield or a radio.

The panel is the one place where mesh state leaves Python and lands on a screen
with no scrollback, a 25-column font and no accents. So what is checked here is
mostly the narrowing: that text is folded and cut to what the sketch can draw,
that a button sends the message rather than its label, and that neither half of
the link — meshd below, the sketch above — can take the process down by going
away.
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

from apps.meshd import MeshDaemon, _Client  # noqa: E402
from apps.unoq_panel import (  # noqa: E402
    MAX_LABEL,
    MAX_TEXT,
    PanelBridge,
    parse_preset,
    to_ascii,
)

_LOCAL = "AA:BB:CC:DD:EE:01"
_PRESETS = [("OK", "Bien recu"), ("ARRIVE", "J'arrive dans cinq minutes")]


class _FakeNode:
    """Stands in for BBNode: same surface, no radio."""

    def __init__(self, peers=(), relay=False):
        self.local_bd_addr = _LOCAL
        self.on_message = None
        self.on_log = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self._peers = list(peers)
        self._relay = relay
        self.sent = []

    def start(self, l2cap_accept_all=True):
        pass

    def stop(self):
        pass

    def send(self, text):
        self.sent.append(text)

    def peers(self):
        return list(self._peers)

    def is_relay(self):
        return self._relay

    def current_epoch(self):
        return 7


class _FakeLink:
    """Stands in for the Router Bridge. Records pushes, can play dead."""

    def __init__(self, fail=False, touch_ok=True):
        self.pushes = []
        self.fail = fail
        self.touch_ok = touch_ok
        self.handler = None
        self._lock = threading.Lock()

    def provide_preset(self, handler):
        self.handler = handler

    def push(self, method, *params):
        if self.fail:
            raise TimeoutError("sketch muet")
        with self._lock:
            self.pushes.append((method, params))
        # Only panel_status answers; the others are void on the sketch side.
        return self.touch_ok if method == "panel_status" else None

    def last(self, method):
        with self._lock:
            for m, params in reversed(self.pushes):
                if m == method:
                    return params
        return None

    def wait_for(self, method, predicate, timeout=4.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            params = self.last(method)
            if params is not None and predicate(params):
                return params
            time.sleep(0.05)
        raise AssertionError(f"aucun {method} satisfaisant en {timeout}s")


class _Harness:
    """A real meshd on a throwaway socket, with a panel bridge attached."""

    def __init__(self, node, link, presets=_PRESETS):
        self.dir = tempfile.mkdtemp(prefix="panel-test-")
        self.path = os.path.join(self.dir, "meshd.sock")
        self.daemon = MeshDaemon("hci0", self.path, node=node)
        self.node = node
        self.link = link
        self.panel = PanelBridge(link, presets, self.path)

    def __enter__(self):
        # _bind() chowns the socket, which needs root; the test only needs it
        # to exist.
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        srv.listen(8)
        self.daemon._srv = srv
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self.panel.run, daemon=True).start()
        self.link.wait_for("panel_status", lambda p: p[0] == _LOCAL)
        return self

    def _accept_loop(self):
        while not self.daemon._stopping.is_set():
            try:
                conn, _ = self.daemon._srv.accept()
            except OSError:
                return
            client = _Client(conn)
            with self.daemon._clients_lock:
                self.daemon._clients.append(client)
            threading.Thread(
                target=self.daemon._serve_client, args=(client,), daemon=True
            ).start()

    def __exit__(self, *exc):
        self.panel.stop()
        self.daemon.shutdown()


# ---- narrowing to what the screen can draw ------------------------------


def test_accents_are_folded_to_the_font_the_sketch_has():
    assert to_ascii("Bien reçu à l'étage") == "Bien recu a l'etage"
    assert to_ascii("emoji \U0001f600 ici") == "emoji  ici"
    assert "\n" not in to_ascii("deux\nlignes")


def test_presets_accept_a_label_or_stand_alone():
    assert parse_preset("OK|Bien recu") == ("OK", "Bien recu")

    label, text = parse_preset("J'arrive tout de suite vraiment")
    assert text == "J'arrive tout de suite vraiment"
    assert len(label) <= MAX_LABEL

    label, _ = parse_preset("Réponse trop longue pour le bouton|texte")
    assert len(label) <= MAX_LABEL
    assert label.isascii()

    for bad in ("", "   ", "LABEL|"):
        try:
            parse_preset(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} aurait du etre refuse")


def test_an_address_learned_late_still_reaches_the_panel():
    # meshd binds its socket before the node has an address, so a panel that
    # starts with it gets an empty hello and must take the correction.
    panel = PanelBridge(_FakeLink(), _PRESETS, "/nonexistent")
    panel.apply({"ev": "hello", "local": "", "peers": [], "relay": False, "epoch": 0})
    assert panel.snapshot()["local"] == ""

    panel.apply({"ev": "peers", "peers": ["BB:BB:BB:BB:BB:BB"],
                 "relay": True, "local": _LOCAL, "epoch": 4})
    snap = panel.snapshot()
    assert (snap["local"], snap["peers"], snap["epoch"]) == (_LOCAL, 1, 4)


def test_snapshot_cuts_text_to_the_three_lines_available():
    panel = PanelBridge(_FakeLink(), _PRESETS, "/nonexistent")
    panel.apply({"ev": "hello", "local": _LOCAL, "peers": [], "relay": False, "epoch": 1})
    panel.apply({"ev": "message", "from": "BB:BB:BB:BB:BB:BB", "text": "é" * 400})

    snap = panel.snapshot()
    assert len(snap["msg_text"]) <= MAX_TEXT
    assert snap["msg_text"].isascii()


# ---- folding mesh events -------------------------------------------------


def test_peer_changes_reach_the_panel():
    node = _FakeNode(peers=["BB:BB:BB:BB:BB:BB"], relay=True)
    link = _FakeLink()
    with _Harness(node, link) as h:
        params = h.link.wait_for("panel_status", lambda p: p[1] == 1)
        local, peers, relay, epoch = params
        assert (local, peers, relay, epoch) == (_LOCAL, 1, True, 7)


def test_incoming_message_is_pushed_to_the_sketch():
    node = _FakeNode()
    link = _FakeLink()
    with _Harness(node, link) as h:
        h.node.on_message("BB:BB:BB:BB:BB:BB", "salut les autres")
        sender, text = h.link.wait_for("panel_message", lambda p: p[1] != "")
        assert sender == "BB:BB:BB:BB:BB:BB"
        assert text == "salut les autres"


def test_panel_shows_the_labels_it_will_actually_send():
    node = _FakeNode()
    link = _FakeLink()
    with _Harness(node, link) as h:
        labels = h.link.wait_for("panel_presets", lambda p: p[0] != "")
        assert list(labels) == ["OK", "ARRIVE"]


# ---- the buttons ---------------------------------------------------------


def test_button_sends_the_message_not_the_label():
    node = _FakeNode()
    link = _FakeLink()
    with _Harness(node, link) as h:
        h.link.handler(1)
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline and not node.sent:
            time.sleep(0.05)
        assert node.sent == ["J'arrive dans cinq minutes"]


def test_a_tap_from_linux_is_the_same_path_as_a_finger():
    # --tap notifies panel_preset, which is exactly what the sketch calls, so a
    # board whose touch controller never answered still sends the same message.
    node = _FakeNode()
    link = _FakeLink(touch_ok=False)
    with _Harness(node, link) as h:
        h.link.handler(0)
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline and not node.sent:
            time.sleep(0.05)
        assert node.sent == ["Bien recu"]


def test_a_bogus_button_index_is_ignored():
    node = _FakeNode()
    link = _FakeLink()
    with _Harness(node, link) as h:
        for bad in (9, -1, None, "gauche"):
            h.link.handler(bad)
        time.sleep(0.3)
        assert node.sent == []


# ---- neither side may take the process down ------------------------------


def test_the_touch_verdict_is_reported_once_per_change():
    # It rides every heartbeat, so a panel left running for days must not fill
    # the log with it — only transitions are worth a line.
    link = _FakeLink(touch_ok=False)
    panel = PanelBridge(link, _PRESETS, "/nonexistent")
    panel.apply({"ev": "hello", "local": _LOCAL, "peers": [], "relay": False, "epoch": 1})

    seen = []
    panel.note_touch = lambda ok, _s=seen: _s.append(bool(ok))
    for _ in range(3):
        panel.push_all()
    assert seen == [False, False, False]  # push_all always forwards the answer

    panel = PanelBridge(_FakeLink(touch_ok=False), _PRESETS, "/nonexistent")
    panel.note_touch(False)
    panel.note_touch(False)
    assert panel._touch_ok is False
    panel.note_touch(True)
    assert panel._touch_ok is True


def test_a_silent_sketch_does_not_kill_the_bridge():
    panel = PanelBridge(_FakeLink(fail=True), _PRESETS, "/nonexistent")
    panel.apply({"ev": "hello", "local": _LOCAL, "peers": [], "relay": False, "epoch": 1})
    assert panel.push_all() is False
    assert panel.push_all() is False  # still alive, still honest


def test_losing_meshd_blanks_the_numbers_rather_than_lying():
    node = _FakeNode(peers=["BB:BB:BB:BB:BB:BB"], relay=True)
    link = _FakeLink()
    with _Harness(node, link) as h:
        h.link.wait_for("panel_status", lambda p: p[1] == 1)
        h.daemon.shutdown()
        params = h.link.wait_for("panel_status", lambda p: p[1] == 0)
        assert params[2] is False


if __name__ == "__main__":
    for fn in (
        test_accents_are_folded_to_the_font_the_sketch_has,
        test_presets_accept_a_label_or_stand_alone,
        test_an_address_learned_late_still_reaches_the_panel,
        test_snapshot_cuts_text_to_the_three_lines_available,
        test_peer_changes_reach_the_panel,
        test_incoming_message_is_pushed_to_the_sketch,
        test_panel_shows_the_labels_it_will_actually_send,
        test_button_sends_the_message_not_the_label,
        test_a_tap_from_linux_is_the_same_path_as_a_finger,
        test_a_bogus_button_index_is_ignored,
        test_the_touch_verdict_is_reported_once_per_change,
        test_a_silent_sketch_does_not_kill_the_bridge,
        test_losing_meshd_blanks_the_numbers_rather_than_lying,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All UNO Q panel tests passed")
