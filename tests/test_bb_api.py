from __future__ import annotations

import os
import sys
from dataclasses import replace
from unittest.mock import MagicMock, patch

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.api.bb_api import BBNode, parse_topology  # noqa: E402


def test_parse_topology() -> None:
    assert parse_topology("aa:bb:cc:dd:ee:01, AA:BB:CC:DD:EE:02") == frozenset(
        {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
    )


def test_bbnode_send_broadcast() -> None:
    cfg = replace(
        load_config(),
        group_key=b"\x02" * 32,
        local_bd_addr="AA:BB:CC:DD:EE:01",
        remote_bd_addr="AA:BB:CC:DD:EE:02",
    )
    fake_transport = MagicMock()
    fake_transport.connections.return_value = ["AA:BB:CC:DD:EE:02"]
    fake_hello = MagicMock()
    fake_hello.is_relay = False
    fake_hello.l2cap_peer_anon_ids.return_value = frozenset()

    with (
        patch("src.api.bb_api.load_config", return_value=cfg),
        patch("src.api.bb_api.L2CAPTransport", return_value=fake_transport),
        patch("src.api.bb_api.HelloManager", return_value=fake_hello),
        patch("src.api.bb_api.PacketForwarder") as mock_fwd_cls,
    ):
        mock_fwd = MagicMock()
        mock_fwd_cls.return_value = mock_fwd

        node = BBNode(setup_pairing_agent=False)
        node.on_message = lambda s, t: None
        node.start("AA:BB:CC:DD:EE:02")
        node.send("hi")
        mock_fwd.send_broadcast.assert_called_once_with("hi")
        node.stop()
