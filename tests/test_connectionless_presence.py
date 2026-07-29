"""Connectionless presence is discovery-only; CDS stays L2CAP-driven."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import load_config  # noqa: E402
from src.control.hello import compute_anon_id  # noqa: E402
from src.control.hello_manager import HelloManager  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402
from src.transport.advertising import parse_presence_manufacturer_value  # noqa: E402

_GK = b"\x42" * 32
_X = "14:B5:CD:E2:49:ED"
_Y = "40:D9:5A:8B:69:3F"
_Z = "00:11:22:33:44:55"


class _FakeTransport:
    def __init__(self, peers: list[str] | None = None) -> None:
        self._peers = [p.upper() for p in (peers or [])]

    def connections(self) -> list[str]:
        return list(self._peers)

    def send(self, bd_addr: str, data: bytes) -> None:  # pragma: no cover
        pass


def _make_manager(local_bd: str, *, peers: list[str] | None = None) -> HelloManager:
    cfg = replace(
        load_config(),
        group_key=_GK,
        local_bd_addr=local_bd.upper(),
        remote_bd_addr="00:00:00:00:00:00",
        hello_interval_s=1,
        neighbor_timeout_s=30,
    )
    key_store = BBKeyStore.from_group_key(_GK, local_bd.upper())
    fd, path = tempfile.mkstemp(prefix="bb-connless-epoch-")
    os.close(fd)
    epoch_store = EpochStore(_GK, persist_path=path, local_bd_addr=local_bd.upper())
    mgr = HelloManager(cfg, _FakeTransport(peers), key_store, epoch_store, quiet=True)
    mgr.enable_connectionless_topology()
    return mgr


def test_ota_presence_does_not_elect_cds_without_l2cap() -> None:
    mgr = _make_manager(_X)
    x, y, z = mgr.anon_id, compute_anon_id(_GK, _Y), compute_anon_id(_GK, _Z)
    mgr.ingest_public_hello(y, 1, [x], [])
    mgr.ingest_public_hello(z, 1, [x], [])
    assert mgr.heard_anon_ids() == frozenset({y, z})
    # Compact OTA must not make us a relay (no L2CAP neighbors).
    assert mgr.is_relay is False


def test_heard_tracks_discovery() -> None:
    mgr = _make_manager(_X)
    y = compute_anon_id(_GK, _Y)
    mgr.ingest_public_hello(y, 1, [], [])
    assert mgr.heard_anon_ids() == frozenset({y})
    assert mgr.is_relay is False


def test_local_presence_value_roundtrips_anon() -> None:
    mgr = _make_manager(_X)
    x, y = mgr.anon_id, compute_anon_id(_GK, _Y)
    mgr.ingest_public_hello(y, 1, [], [])
    parsed = parse_presence_manufacturer_value(mgr.build_local_presence_value())
    assert parsed is not None
    assert parsed["anon_id"] == x


def test_ignores_our_own_broadcast() -> None:
    mgr = _make_manager(_X)
    mgr.ingest_public_hello(mgr.anon_id, 7, [], [])
    assert mgr.heard_anon_ids() == frozenset()


def test_link_plan_is_discovery_snapshot() -> None:
    mgr = _make_manager(_X)
    y = compute_anon_id(_GK, _Y)
    mgr.ingest_public_hello(y, 1, [], [], is_relay=True)
    plan = mgr.connectionless_link_plan()
    assert plan["am_relay"] is False
    assert plan["heard"] == {y}
    assert plan["sym"] == set()
    assert plan["relays"] == set()
