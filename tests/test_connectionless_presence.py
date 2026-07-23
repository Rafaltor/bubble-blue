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
    """A transport with no L2CAP peers — the connectionless plane must not need it."""

    def connections(self) -> list[str]:
        return []

    def send(self, bd_addr: str, data: bytes) -> None:  # pragma: no cover - unused
        pass


def _make_manager(local_bd: str) -> HelloManager:
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
    mgr = HelloManager(cfg, _FakeTransport(), key_store, epoch_store, quiet=True)
    mgr.enable_connectionless_topology()
    return mgr


def test_relay_elected_without_any_l2cap_link() -> None:
    mgr = _make_manager(_X)
    x, y, z = mgr.anon_id, compute_anon_id(_GK, _Y), compute_anon_id(_GK, _Z)
    # Hear Y and Z over the air; each lists X back (symmetric), Y and Z do NOT
    # list each other → X bridges them → X must be a relay, with zero connections.
    mgr.ingest_public_hello(y, 1, [x], [])
    mgr.ingest_public_hello(z, 1, [x], [])
    assert mgr.heard_anon_ids() == frozenset({y, z})
    assert mgr.is_relay is True


def test_single_neighbor_is_leaf() -> None:
    mgr = _make_manager(_X)
    x, y = mgr.anon_id, compute_anon_id(_GK, _Y)
    mgr.ingest_public_hello(y, 1, [x], [])
    assert mgr.heard_anon_ids() == frozenset({y})
    assert mgr.is_relay is False


def test_local_presence_value_roundtrips_heard_neighbors() -> None:
    mgr = _make_manager(_X)
    x, y, z = mgr.anon_id, compute_anon_id(_GK, _Y), compute_anon_id(_GK, _Z)
    mgr.ingest_public_hello(y, 1, [x], [])
    mgr.ingest_public_hello(z, 1, [x], [])
    parsed = parse_presence_manufacturer_value(mgr.build_local_presence_value())
    assert parsed is not None
    assert parsed["anon_id"] == x
    assert set(parsed["neighbors"]) == {y, z}


def test_ignores_our_own_broadcast() -> None:
    mgr = _make_manager(_X)
    mgr.ingest_public_hello(mgr.anon_id, 7, [], [])
    assert mgr.heard_anon_ids() == frozenset()


if __name__ == "__main__":
    test_relay_elected_without_any_l2cap_link()
    print("✅ relay elected with zero L2CAP links")
    test_single_neighbor_is_leaf()
    print("✅ single neighbor → leaf")
    test_local_presence_value_roundtrips_heard_neighbors()
    print("✅ local presence value round-trips heard neighbors")
    test_ignores_our_own_broadcast()
    print("✅ ignores our own broadcast")
    print("\n✅ All connectionless presence tests passed")
