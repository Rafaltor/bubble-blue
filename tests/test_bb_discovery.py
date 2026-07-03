from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from unittest.mock import MagicMock, patch

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.api.bb_api import (  # noqa: E402
    BBNode,
    PROTOCOL_HELLO_GRACE_MULT,
    PROTOCOL_QUARANTINE_BASE_S,
)

_ADDR_PEER = "BB:BB:BB:BB:BB:02"
_ADDR_LOCAL = "AA:BB:CC:DD:EE:01"


def _ble_cfg():
    return replace(
        load_config(),
        group_key=b"\x02" * 32,
        local_bd_addr=_ADDR_LOCAL,
        remote_bd_addr="00:00:00:00:00:00",
        transport_kind="ble_l2cap",
        hello_interval_s=5,
        group_members=[],
    )


def test_decrypt_fail_does_not_quarantine() -> None:
    cfg = _ble_cfg()
    fake_transport = MagicMock()
    fake_transport.connections.return_value = [_ADDR_PEER]
    fake_transport.disconnect = MagicMock()
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()
    fake_hello.has_learned_public_hello.return_value = True

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.make_transport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
        patch("src.api.bb_api.PresenceScanner") as mock_scanner_cls,
    ):
        mock_fwd = MagicMock()
        mock_fwd_cls.return_value = mock_fwd
        mock_scanner_cls.return_value = MagicMock()

        node = BBNode(setup_pairing_agent=False)
        logs: list[str] = []
        node.on_message = lambda _s, _t: None
        node.on_log = lambda m, _e: logs.append(m)
        node.on_decrypt_fail = lambda _s: logs.append("decrypt_fail")
        node.start()
        node._dispatch_decrypt_fail(_ADDR_PEER)

        assert fake_transport.disconnect.call_count == 0
        assert node._protocol_quarantine_until.get(_ADDR_PEER.upper()) is None
        assert "decrypt_fail" in logs
        node.stop()


def test_protocol_silence_expels_and_quarantines() -> None:
    cfg = _ble_cfg()
    fake_transport = MagicMock()
    fake_transport.connections.return_value = []
    fake_transport.disconnect = MagicMock()
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()
    fake_hello.has_learned_public_hello.return_value = False

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.make_transport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
        patch("src.api.bb_api.PresenceScanner") as mock_scanner_cls,
    ):
        mock_fwd_cls.return_value = MagicMock()
        mock_scanner_cls.return_value = MagicMock()

        node = BBNode(setup_pairing_agent=False)
        logs: list[str] = []
        node.on_message = lambda _s, _t: None
        node.on_log = lambda m, _e: logs.append(m)
        node.start()
        node._connect_stop.set()
        if node._connect_thread is not None:
            node._connect_thread.join(timeout=1.0)

        node._dispatch_peer_connected(_ADDR_PEER)
        assert _ADDR_PEER in node._peer_admission_deadline
        node._peer_admission_deadline[_ADDR_PEER] = time.monotonic() - 1.0
        node._check_protocol_admission()

        assert fake_transport.disconnect.called
        assert _ADDR_PEER in node._protocol_quarantine_until
        quarantine = node._protocol_quarantine_until[_ADDR_PEER] - time.monotonic()
        assert 0 < quarantine <= PROTOCOL_QUARANTINE_BASE_S + 1
        assert any("silence protocolaire" in m for m in logs)
        assert any("quarantaine" in m for m in logs)
        node.stop()


def test_presence_candidate_feeds_connect_targets() -> None:
    cfg = _ble_cfg()
    fake_transport = MagicMock()
    fake_transport.connections.return_value = []
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.make_transport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
        patch("src.api.bb_api.PresenceScanner") as mock_scanner_cls,
    ):
        mock_fwd_cls.return_value = MagicMock()
        mock_scanner_cls.return_value = MagicMock()

        node = BBNode(setup_pairing_agent=False)
        node.on_message = lambda _s, _t: None
        node.start()
        node._on_presence_candidate(_ADDR_PEER, "random", time.monotonic())
        assert _ADDR_PEER in node.connect_targets()
        assert node._peer_addr_types[_ADDR_PEER] == "random"
        node.stop()


def test_mute_stops_scanner_and_transport() -> None:
    cfg = _ble_cfg()
    fake_transport = MagicMock()
    fake_transport.connections.return_value = []
    fake_transport.mute = MagicMock()
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()

    scanner = MagicMock()

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.make_transport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
        patch("src.api.bb_api.PresenceScanner", return_value=scanner),
    ):
        mock_fwd_cls.return_value = MagicMock()

        node = BBNode(setup_pairing_agent=False)
        node.on_message = lambda _s, _t: None
        node.start()
        node.mute()
        scanner.stop.assert_called_once()
        fake_transport.mute.assert_called_once()
        assert node._presence_scanner is None


if __name__ == "__main__":
    test_decrypt_fail_does_not_quarantine()
    print("✅ decrypt_fail does not quarantine")
    test_protocol_silence_expels_and_quarantines()
    print("✅ protocol silence expels + quarantine")
    test_presence_candidate_feeds_connect_targets()
    print("✅ presence candidate feeds connect targets")
    test_mute_stops_scanner_and_transport()
    print("✅ mute stops scanner and transport advertising")
