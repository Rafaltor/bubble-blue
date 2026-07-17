"""PKT_ANNOUNCE: signed network-wide pubkey binding under group key."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_ANNOUNCE, load_config  # noqa: E402
from src.control.announce import (  # noqa: E402
    announce_signed_message,
    build_announce,
    pack_announce_plaintext,
    parse_announce,
    unpack_announce_plaintext,
)
from src.control.hello import X25519_PUBLIC_KEY_SIZE  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402
from src.security.packet import BROADCAST_BD_ADDR, parse_routing_header  # noqa: E402

GROUP_KEY = b"\x11" * 32
ADDR_A = "AA:BB:CC:DD:EE:01"
ADDR_R = "AA:BB:CC:DD:EE:02"
ADDR_B = "AA:BB:CC:DD:EE:03"


def _epoch_store(bd: str, group_key: bytes = GROUP_KEY) -> EpochStore:
    fd, path = tempfile.mkstemp(prefix="bb-announce-epoch-")
    os.close(fd)
    return EpochStore(group_key, persist_path=path, local_bd_addr=bd)


def _mk_announce(
    store: BBKeyStore,
    bd: str,
    *,
    seq: int,
    ts_ms: int,
    epoch: int = 0,
    ttl: int = 10,
    group_key: bytes = GROUP_KEY,
) -> bytes:
    msg = announce_signed_message(
        bd, epoch, store.local_public_key, store.local_signing_public_key
    )
    return build_announce(
        group_key,
        bd,
        seq=seq,
        ts_ms=ts_ms,
        epoch=epoch,
        public_key=store.local_public_key,
        ttl=ttl,
        signing_public_key=store.local_signing_public_key,
        signature=store.sign(msg),
    )


def _apply(store: BBKeyStore, peer: BBKeyStore, bd: str, *, epoch: int = 0) -> str:
    msg = announce_signed_message(
        bd, epoch, peer.local_public_key, peer.local_signing_public_key
    )
    return store.apply_announce_binding(
        bd,
        peer.local_public_key,
        signing_public_key=peer.local_signing_public_key,
        signature=peer.sign(msg),
        signed_message=msg,
    )


class _MeshTransport:
    """Shared L2CAP mesh: send delivers immediately to peer on_receive."""

    def __init__(self) -> None:
        self._peers: dict[str, list[str]] = {}
        self._handlers: dict[str, object] = {}
        self.sent: list[tuple[str, str, bytes]] = []

    def register(self, bd: str, neighbors: list[str], handler: object) -> _NodeTransport:
        self._peers[bd.upper()] = [n.upper() for n in neighbors]
        self._handlers[bd.upper()] = handler
        return _NodeTransport(self, bd.upper())

    def deliver(self, src: str, dst: str, data: bytes) -> None:
        self.sent.append((src.upper(), dst.upper(), bytes(data)))
        h = self._handlers.get(dst.upper())
        if h is not None:
            h.handle(src.upper(), data)  # type: ignore[attr-defined]


class _NodeTransport:
    def __init__(self, mesh: _MeshTransport, bd: str) -> None:
        self._mesh = mesh
        self._bd = bd

    def connections(self) -> list[str]:
        return list(self._mesh._peers.get(self._bd, []))

    def send(self, bd_addr: str, data: bytes) -> None:
        self._mesh.deliver(self._bd, bd_addr.upper(), data)


class _AnnounceHelloMgr:
    def __init__(
        self,
        *,
        local: str,
        relay: bool,
        key_store: BBKeyStore,
        epoch_store: EpochStore,
        resolved: list[str] | None = None,
    ) -> None:
        self.is_relay = relay
        self.key_store = key_store
        self.epoch_store = epoch_store
        self.anon_id = b"\xab" * 8
        self.table = MagicMock()
        self._peer_epochs: dict[str, int] = {}
        self._resolved = [r.upper() for r in (resolved or [])]
        self._local = local.upper()
        self.announces_emitted = 0

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose

    def local_anon_id(self) -> bytes:
        return self.anon_id

    def anon_id_for(self, bd: str) -> bytes:
        _ = bd
        return b"\xab" * 8

    def get_peer_epoch(self, bd: str) -> int:
        return int(self._peer_epochs.get(bd.upper(), 0))

    def get_resolved_members(self) -> list[dict[str, str | bytes]]:
        return [{"bd_addr": bd, "anon_id": b"\x00" * 8} for bd in self._resolved]

    def is_coordinator(self) -> bool:
        return True

    def emit_announce(self) -> None:
        self.announces_emitted += 1


def test_announce_roundtrip() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    pkt = _mk_announce(store, ADDR_A, seq=7, ts_ms=1_700_000_000_000, epoch=2)
    hdr = parse_routing_header(pkt)
    assert hdr["type"] == PKT_ANNOUNCE
    assert hdr["src"] == ADDR_A
    assert hdr["dst"] == BROADCAST_BD_ADDR

    out = parse_announce(pkt, [GROUP_KEY])
    assert out is not None
    assert out["bd_addr"] == ADDR_A
    assert out["epoch"] == 2
    assert out["public_key"] == store.local_public_key
    assert out["signing_public_key"] == store.local_signing_public_key
    assert out["seq"] == 7


def test_announce_wrong_group_key() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    pkt = _mk_announce(store, ADDR_A, seq=1, ts_ms=1_700_000_000_000, epoch=0, ttl=5)
    assert parse_announce(pkt, [b"\x22" * 32]) is None


def test_announce_tamper_header_or_ciphertext() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    pkt = _mk_announce(store, ADDR_A, seq=3, ts_ms=1_700_000_000_000, epoch=1, ttl=5)
    bad_hdr = bytearray(pkt)
    bad_hdr[2] ^= 0xFF  # within src BD
    assert parse_announce(bytes(bad_hdr), [GROUP_KEY]) is None

    bad_ct = bytearray(pkt)
    bad_ct[-1] ^= 0xFF
    assert parse_announce(bytes(bad_ct), [GROUP_KEY]) is None


def test_announce_plaintext_validation() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    msg = announce_signed_message(
        ADDR_A, 9, store.local_public_key, store.local_signing_public_key
    )
    plain = pack_announce_plaintext(
        ADDR_A,
        9,
        store.local_public_key,
        store.local_signing_public_key,
        store.sign(msg),
    )
    body = unpack_announce_plaintext(plain)
    assert body["bd_addr"] == ADDR_A
    assert body["epoch"] == 9
    assert body["public_key"] == store.local_public_key
    try:
        unpack_announce_plaintext(plain[:-1])
        raise AssertionError("expected ValueError for truncated plaintext")
    except ValueError:
        pass
    try:
        unpack_announce_plaintext(b"\x99" + plain[1:])
        raise AssertionError("expected ValueError for unknown version")
    except ValueError:
        pass


def test_announce_bad_signature_rejected() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    peer = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    msg = announce_signed_message(
        ADDR_B, 0, peer.local_public_key, peer.local_signing_public_key
    )
    bad_sig = bytes(64)  # invalid
    assert (
        store.apply_announce_binding(
            ADDR_B,
            peer.local_public_key,
            signing_public_key=peer.local_signing_public_key,
            signature=bad_sig,
            signed_message=msg,
        )
        == "rejected_sig"
    )
    assert store.get_peer_public_key(ADDR_B) is None


def test_conflict_policy_hello_learned_wins(caplog_compat: None = None) -> None:
    _ = caplog_compat
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    peer = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    other = BBKeyStore()  # ephemeral attacker identity

    store.register_peer_from_hello(
        ADDR_B,
        peer.local_public_key,
        signing_public_key=peer.local_signing_public_key,
    )
    assert store.is_hello_learned(ADDR_B)

    with _CaptureWarnings() as caps:
        result = _apply(store, other, ADDR_B)
    assert result == "ignored_hello"
    assert store.get_peer_public_key(ADDR_B) == peer.local_public_key
    assert any("conflit de binding" in m and ADDR_B in m for m in caps)

    assert _apply(store, peer, ADDR_B) == "noop"


def test_conflict_policy_first_seen_otherwise() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    first = BBKeyStore()
    second = BBKeyStore()

    assert _apply(store, first, ADDR_B) == "registered"
    assert not store.is_hello_learned(ADDR_B)
    with _CaptureWarnings() as caps:
        assert _apply(store, second, ADDR_B) == "ignored_first"
    assert store.get_peer_public_key(ADDR_B) == first.local_public_key
    assert any("premier vu" in m for m in caps)


def test_register_peer_invalidates_pair_cache() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_a.register_peer(ADDR_B, store_b.local_public_key)
    k1 = store_a.get_pair_key(ADDR_B)
    assert k1 is not None
    new_b = BBKeyStore()  # ephemeral new identity
    store_a.register_peer(ADDR_B, new_b.local_public_key)
    k2 = store_a.get_pair_key(ADDR_B)
    assert k2 is not None
    assert k2 != k1


class _CaptureWarnings:
    def __enter__(self) -> list[str]:
        self._msgs: list[str] = []
        self._logger = logging.getLogger("src.security.keys")
        self._handler = _ListHandler(self._msgs)
        self._logger.addHandler(self._handler)
        self._old = self._logger.level
        self._logger.setLevel(logging.WARNING)
        return self._msgs

    def __exit__(self, *exc: object) -> None:
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._old)


class _ListHandler(logging.Handler):
    def __init__(self, msgs: list[str]) -> None:
        super().__init__()
        self._msgs = msgs

    def emit(self, record: logging.LogRecord) -> None:
        self._msgs.append(record.getMessage())


def test_line_topology_announce_enables_pair_and_rekey() -> None:
    """
    A—R—B: B is not a Hello neighbor of A; ANNOUNCE of A reaches B via R;
    B's ANNOUNCE reaches A; flood_rekey at A no longer skips B (pubkey known).
    """
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_r = BBKeyStore.from_group_key(GROUP_KEY, ADDR_R)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    ep_a = _epoch_store(ADDR_A)
    ep_r = _epoch_store(ADDR_R)
    ep_b = _epoch_store(ADDR_B)

    mesh = _MeshTransport()
    cfg_a = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    cfg_r = replace(cfg_a, local_bd_addr=ADDR_R)
    cfg_b = replace(cfg_a, local_bd_addr=ADDR_B)

    hm_a = _AnnounceHelloMgr(
        local=ADDR_A, relay=False, key_store=store_a, epoch_store=ep_a, resolved=[ADDR_B]
    )
    hm_r = _AnnounceHelloMgr(local=ADDR_R, relay=True, key_store=store_r, epoch_store=ep_r)
    hm_b = _AnnounceHelloMgr(local=ADDR_B, relay=False, key_store=store_b, epoch_store=ep_b)

    holders: dict[str, PacketForwarder] = {}

    class _H:
        def __init__(self, name: str) -> None:
            self.name = name

        def handle(self, peer: str, data: bytes) -> None:
            holders[self.name].handle(peer, data)

    t_a = mesh.register(ADDR_A, [ADDR_R], _H(ADDR_A))
    t_r = mesh.register(ADDR_R, [ADDR_A, ADDR_B], _H(ADDR_R))
    t_b = mesh.register(ADDR_B, [ADDR_R], _H(ADDR_B))

    fwd_a = PacketForwarder(cfg_a, t_a, hm_a, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_r = PacketForwarder(cfg_r, t_r, hm_r, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_b = PacketForwarder(cfg_b, t_b, hm_b, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    holders[ADDR_A] = fwd_a
    holders[ADDR_R] = fwd_r
    holders[ADDR_B] = fwd_b

    assert store_b.get_pair_key(ADDR_A) is None
    assert store_a.get_peer_public_key(ADDR_B) is None

    ts = time.time_ns() // 1_000_000
    t_a.send(ADDR_R, _mk_announce(store_a, ADDR_A, seq=100, ts_ms=ts))

    assert store_b.get_pair_key(ADDR_A) is not None
    assert store_b.get_peer_public_key(ADDR_A) == store_a.local_public_key
    assert store_b.get_peer_signing_public_key(ADDR_A) == store_a.local_signing_public_key

    t_b.send(ADDR_R, _mk_announce(store_b, ADDR_B, seq=200, ts_ms=ts + 1))
    assert store_a.get_peer_public_key(ADDR_B) == store_b.local_public_key
    assert store_a.get_pair_key(ADDR_B) is not None

    mesh.sent.clear()
    fwd_a.flood_rekey_state()
    rekey_dsts = [dst for _src, dst, data in mesh.sent if data and data[0] == 0x05]
    assert store_a.get_peer_public_key(ADDR_B) is not None
    assert any(dst == ADDR_R for dst in rekey_dsts) or any(
        dst == ADDR_B for dst in rekey_dsts
    )


def test_announce_replay_rejected() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    ep = _epoch_store(ADDR_B)
    cfg = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_B, ttl_max=10)
    hm = _AnnounceHelloMgr(local=ADDR_B, relay=False, key_store=store, epoch_store=ep)
    transport = MagicMock()
    transport.connections.return_value = [ADDR_R]
    fwd = PacketForwarder(cfg, transport, hm, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    ts = time.time_ns() // 1_000_000
    pkt = _mk_announce(store_a, ADDR_A, seq=55, ts_ms=ts)
    fwd.handle(ADDR_R, pkt)
    assert store.get_peer_public_key(ADDR_A) == store_a.local_public_key

    fwd.handle(ADDR_R, pkt)
    assert store.get_peer_public_key(ADDR_A) == store_a.local_public_key
    other = BBKeyStore()
    assert _apply(store, other, ADDR_A) == "ignored_first"


def test_file_identity_not_group_derived() -> None:
    """Runtime identity (for_node) must not be re-derivable from the group key."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "id.bin")
        file_store = BBKeyStore.for_node(ADDR_A, persist_path=path)
        derived = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
        assert file_store.local_public_key != derived.local_public_key
        again = BBKeyStore.for_node(ADDR_A, persist_path=path)
        assert again.local_public_key == file_store.local_public_key


if __name__ == "__main__":
    test_announce_roundtrip()
    test_announce_wrong_group_key()
    test_announce_tamper_header_or_ciphertext()
    test_announce_plaintext_validation()
    test_announce_bad_signature_rejected()
    test_conflict_policy_hello_learned_wins()
    test_conflict_policy_first_seen_otherwise()
    test_register_peer_invalidates_pair_cache()
    test_line_topology_announce_enables_pair_and_rekey()
    test_announce_replay_rejected()
    test_file_identity_not_group_derived()
    print("✅ announce tests passed")
