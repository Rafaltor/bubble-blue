from __future__ import annotations

import os
import sys
from dataclasses import replace
from unittest.mock import MagicMock, patch

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.api.bb_api import BBNode, _parse_topology  # noqa: E402


def test_parse_topology() -> None:
    assert _parse_topology("aa:bb:cc:dd:ee:01, AA:BB:CC:DD:EE:02") == frozenset(
        {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
    )
    assert _parse_topology(None) is None
    assert _parse_topology("") is None


def test_bbnode_lifecycle_and_callback() -> None:
    cfg = replace(
        load_config(),
        group_key=b"\x02" * 32,
        local_bd_addr="AA:BB:CC:DD:EE:01",
        group_members=[],
        remote_bd_addr="AA:BB:CC:DD:EE:02",
    )

    fake_transport = MagicMock()
    fake_transport.connections.return_value = ["AA:BB:CC:DD:EE:02"]
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.anon_id = b"\xcd" * 8
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()

    messages: list[tuple[str, str]] = []

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.L2CAPTransport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
    ):
        mock_fwd = MagicMock()
        mock_fwd_cls.return_value = mock_fwd

        node = BBNode(setup_pairing_agent=False)
        node.on_message = lambda s, t: messages.append((s, t))
        node.start("AA:BB:CC:DD:EE:02")

        assert node.peers() == ["AA:BB:CC:DD:EE:02"]
        assert node.is_relay() is False
        assert node.local_bd_addr == "AA:BB:CC:DD:EE:01"

        node.send("hi")
        mock_fwd.broadcast.assert_called_once_with("hi")

        on_msg = mock_fwd_cls.call_args.kwargs["on_message"]
        on_msg("AA:BB:CC:DD:EE:02", "hello")
        assert messages == [("AA:BB:CC:DD:EE:02", "hello")]

        node.stop()
        fake_hello.stop.assert_called_once()
        fake_transport.stop.assert_called_once()


if __name__ == "__main__":
    test_parse_topology()
    test_bbnode_lifecycle_and_callback()
    print("✅ All bb_api tests passed")
