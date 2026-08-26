"""
A node must still know who to dial after the OTA presence cache goes cold.

Regression guard for a silent mesh death observed on the lab boards: the
presence scanner idles once every candidate is a connected peer, so the
TTL-bounded ``heard`` set empties out while links are up. When a supervision
timeout later dropped a link, the dial list was empty and the node never
rejoined — boards sat at zero peers for the rest of the run.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.api.bb_api import BBNode  # noqa: E402

_LOCAL_AID = bytes.fromhex("0100000000000000")
_PEER_A_AID = bytes.fromhex("0200000000000000")
_PEER_B_AID = bytes.fromhex("0300000000000000")
_PEER_A_BD = "AA:BB:CC:DD:EE:02"
_PEER_B_BD = "AA:BB:CC:DD:EE:03"


class _FakeHello:
    """Connectionless manager with an empty CDS, as seen on the boards."""

    is_connectionless = True

    def __init__(self, heard: set[bytes]) -> None:
        self.anon_id = _LOCAL_AID
        self._heard = heard

    def heard_anon_ids(self) -> frozenset[bytes]:
        return frozenset(self._heard)

    def connectionless_link_plan(self) -> dict:
        return {"sym": set(), "relays": set(), "am_relay": False}


def _node(heard: set[bytes]) -> BBNode:
    node = BBNode(quiet=True)
    node._hello_mgr = _FakeHello(heard)  # type: ignore[assignment]
    node._presence_addr = {
        _PEER_A_AID.hex(): (_PEER_A_BD, "public"),
        _PEER_B_AID.hex(): (_PEER_B_BD, "public"),
    }
    return node


def test_dials_every_known_peer_while_presence_is_fresh() -> None:
    node = _node({_PEER_A_AID, _PEER_B_AID})
    assert node._backbone_dial_targets() == {_PEER_A_BD, _PEER_B_BD}


def test_dial_targets_survive_expired_heard_set() -> None:
    # Scanner went idle, every heard entry aged out — the catalog must carry on.
    node = _node(set())
    assert node._backbone_dial_targets() == {_PEER_A_BD, _PEER_B_BD}


def test_heard_peer_without_catalog_entry_is_still_dialable() -> None:
    node = _node({_PEER_A_AID})
    node._presence_addr = {_PEER_A_AID.hex(): (_PEER_A_BD, "public")}
    assert node._backbone_dial_targets() == {_PEER_A_BD}


def test_never_dials_itself() -> None:
    node = _node({_PEER_A_AID})
    node._presence_addr[_LOCAL_AID.hex()] = ("AA:BB:CC:DD:EE:01", "public")
    assert "AA:BB:CC:DD:EE:01" not in node._backbone_dial_targets()


if __name__ == "__main__":
    test_dials_every_known_peer_while_presence_is_fresh()
    print("✅ dials every known peer while presence is fresh")
    test_dial_targets_survive_expired_heard_set()
    print("✅ dial targets survive an expired heard set")
    test_heard_peer_without_catalog_entry_is_still_dialable()
    print("✅ heard peer stays dialable")
    test_never_dials_itself()
    print("✅ never dials itself")
    print("\n✅ All dial recovery tests passed")
