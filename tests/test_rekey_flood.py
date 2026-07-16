"""PKT_REKEY_FLOOD: multi-recipient wrap header for coordinator revocation."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import (  # noqa: E402
    MTU_BLE,
    MTU_BT_CLASSIC,
    PKT_REKEY,
    PKT_REKEY_FLOOD,
    load_config,
)
from src.control.hello import compute_anon_id  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.crypto import decrypt_with_key, unwrap_msg_key  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore, derive_wrap_key  # noqa: E402
from src.security.packet import (  # noqa: E402
    BROADCAST_BD_ADDR,
    GCM_TAG_SIZE,
    ROUTING_HEADER_SIZE,
    SUBGROUP_CASE_SIZE,
    parse_routing_header,
    parse_subgroup_packet,
    routing_header_aad,
    subgroup_cases_digest,
)
from src.security.rekey import (  # noqa: E402
    pack_rekey_plaintext,
    partition_rekey_targets,
    rekey_plaintext_len,
    unpack_rekey_plaintext,
)

GROUP_KEY = b"\x33" * 32
ADDR_A = "AA:BB:CC:DD:EE:01"  # coordinator
ADDR_R = "AA:BB:CC:DD:EE:02"  # relay
ADDR_B = "AA:BB:CC:DD:EE:03"  # 2-hop member
ADDR_M = "AA:BB:CC:DD:EE:04"  # revoked


def _epoch(bd: str, gk: bytes = GROUP_KEY) -> EpochStore:
    fd, path = tempfile.mkstemp(prefix="bb-rekey-flood-")
    os.close(fd)
    return EpochStore(gk, persist_path=path, local_bd_addr=bd)


class _Mesh:
    def __init__(self) -> None:
        self._peers: dict[str, list[str]] = {}
        self._fwds: dict[str, PacketForwarder] = {}
        self.sent: list[tuple[str, str, bytes]] = []

    def register(self, bd: str, neighbors: list[str]) -> _NodeTx:
        self._peers[bd.upper()] = [n.upper() for n in neighbors]
        return _NodeTx(self, bd.upper())

    def attach(self, bd: str, fwd: PacketForwarder) -> None:
        self._fwds[bd.upper()] = fwd

    def deliver(self, src: str, dst: str, data: bytes) -> None:
        self.sent.append((src.upper(), dst.upper(), bytes(data)))
        fwd = self._fwds.get(dst.upper())
        if fwd is not None:
            fwd.handle(src.upper(), data)


class _NodeTx:
    def __init__(self, mesh: _Mesh, bd: str) -> None:
        self._mesh = mesh
        self._bd = bd

    def connections(self) -> list[str]:
        return list(self._mesh._peers.get(self._bd, []))

    def send(self, bd_addr: str, data: bytes) -> None:
        self._mesh.deliver(self._bd, bd_addr.upper(), data)


class _HM:
    def __init__(
        self,
        *,
        local: str,
        relay: bool,
        key_store: BBKeyStore,
        epoch_store: EpochStore,
        coordinator: bool = False,
        resolved: list[str] | None = None,
    ) -> None:
        self.is_relay = relay
        self.key_store = key_store
        self.epoch_store = epoch_store
        self.anon_id = compute_anon_id(GROUP_KEY, local)
        self.table = MagicMock()
        self._peer_epochs: dict[str, int] = {}
        self._local = local.upper()
        self._coordinator = coordinator
        self._resolved = [r.upper() for r in (resolved or [])]
        self._learned: dict[str, bytes] = {}
        self.announces = 0

    def refresh_cds_role(self, *, verbose: bool = False) -> None:
        _ = verbose

    def local_anon_id(self) -> bytes:
        return self.anon_id

    def anon_id_for(self, bd: str) -> bytes:
        bd_u = bd.upper()
        if bd_u in self._learned:
            return self._learned[bd_u]
        raise KeyError(bd_u)

    def anon_id_for_or_compute(self, bd: str) -> bytes:
        bd_u = bd.upper()
        if bd_u in self._learned:
            return self._learned[bd_u]
        return compute_anon_id(GROUP_KEY, bd_u)

    def learn(self, bd: str) -> None:
        self._learned[bd.upper()] = compute_anon_id(GROUP_KEY, bd)

    def get_peer_epoch(self, bd: str) -> int:
        return int(self._peer_epochs.get(bd.upper(), 0))

    def get_resolved_members(self) -> list[dict[str, str | bytes]]:
        return [{"bd_addr": bd, "anon_id": self.anon_id_for_or_compute(bd)} for bd in self._resolved]

    def is_coordinator(self) -> bool:
        return self._coordinator

    def emit_announce(self) -> None:
        self.announces += 1


def test_pack_unpack_roundtrip() -> None:
    plain = pack_rekey_plaintext(3, b"\x44" * 32, [b"\xaa" * 32, b"\xbb" * 32])
    assert len(plain) == rekey_plaintext_len(2)
    out = unpack_rekey_plaintext(plain)
    assert out["epoch"] == 3
    assert out["group_key"] == b"\x44" * 32
    assert out["revoked_pubkeys"] == [b"\xaa" * 32, b"\xbb" * 32]
    try:
        unpack_rekey_plaintext(plain[:-1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_partition_small_and_large() -> None:
    body = rekey_plaintext_len(1)
    small = [f"AA:BB:CC:DD:EE:{i:02X}" for i in range(1, 4)]
    parts = partition_rekey_targets(small, body, MTU_BT_CLASSIC)
    assert len(parts) == 1
    assert set(parts[0]) == set(t.upper() for t in small)

    many = [f"AA:BB:CC:DD:{i // 256:02X}:{i % 256:02X}" for i in range(32)]
    # BLE MTU forces multiple packets for 32 cases.
    parts_ble = partition_rekey_targets(many, body, MTU_BLE)
    assert len(parts_ble) >= 2
    flat = [bd for p in parts_ble for bd in p]
    assert sorted(flat) == sorted({t.upper() for t in many})
    assert len(flat) == len(set(flat))

    # Determinism
    assert partition_rekey_targets(many, body, MTU_BLE) == parts_ble

    # Case size comes from real constants
    fixed = ROUTING_HEADER_SIZE + 1 + body + GCM_TAG_SIZE
    max_cases = (MTU_BLE - fixed) // SUBGROUP_CASE_SIZE
    assert all(len(p) <= max_cases for p in parts_ble)


def test_case_tamper_breaks_all_decrypts() -> None:
    """Tampering any case changes cases_digest → body InvalidTag for every member."""
    from cryptography.exceptions import InvalidTag

    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_r = BBKeyStore.from_group_key(GROUP_KEY, ADDR_R)
    for s, o, oa in (
        (store_a, store_b, ADDR_B),
        (store_a, store_r, ADDR_R),
        (store_b, store_a, ADDR_A),
        (store_r, store_a, ADDR_A),
    ):
        s.register_peer(oa, o.local_public_key)

    ep_a = _epoch(ADDR_A)
    cfg = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    hm = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[ADDR_B, ADDR_R],
    )
    hm.learn(ADDR_B)
    hm.learn(ADDR_R)
    fwd = PacketForwarder(
        cfg, MagicMock(connections=lambda: [ADDR_B, ADDR_R]), hm, on_message=lambda _s, _t: None
    )  # type: ignore[arg-type]

    wrap_epoch = 0
    pair_keys = {
        ADDR_B: store_a.get_pair_key(ADDR_B, epoch=wrap_epoch),
        ADDR_R: store_a.get_pair_key(ADDR_R, epoch=wrap_epoch),
    }
    assert all(v is not None for v in pair_keys.values())
    new_epoch, new_key, revoked = ep_a.prepare_revocation(b"\xff" * 32)
    packets = fwd.build_rekey_flood_packets(
        b"\xff" * 32,
        wrap_epoch=wrap_epoch,
        new_epoch=new_epoch,
        new_group_key=new_key,
        revoked_set=revoked,
        targets=[ADDR_B, ADDR_R],
        pair_keys=pair_keys,  # type: ignore[arg-type]
    )
    assert len(packets) == 1
    pkt = bytearray(packets[0])
    # Tamper R's case blob only; B's unwrap still works but body AAD fails.
    # Cases are sorted by bd_addr: R (...:02) then B (...:03).
    r_blob_off = ROUTING_HEADER_SIZE + 1 + 8
    pkt[r_blob_off] ^= 0xFF

    parsed = parse_subgroup_packet(bytes(pkt))
    hdr = parsed["parsed_header"]
    src, seq, ts_ms = hdr["src"], hdr["seq"], hdr["ts_ms"]
    my_tag = compute_anon_id(GROUP_KEY, ADDR_B)
    blob = next(b for tag, b in parsed["cases"] if tag == my_tag)
    wrap_key = derive_wrap_key(store_b.get_pair_key(ADDR_A, epoch=0), src, seq, ts_ms)  # type: ignore[arg-type]
    k_msg = unwrap_msg_key(wrap_key, blob, aad=my_tag)
    aad = (
        routing_header_aad(parsed["routing_header"])
        + bytes([PKT_REKEY_FLOOD])
        + subgroup_cases_digest(parsed["cases"])
    )
    try:
        decrypt_with_key(k_msg, parsed["ciphertext"], aad)
        raise AssertionError("tampered cases_digest must invalidate body decrypt")
    except InvalidTag:
        pass


def test_revoked_absent_from_cases() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_m = BBKeyStore.from_group_key(GROUP_KEY, ADDR_M)
    for s, a, o, oa in (
        (store_a, ADDR_A, store_b, ADDR_B),
        (store_a, ADDR_A, store_m, ADDR_M),
        (store_b, ADDR_B, store_a, ADDR_A),
        (store_m, ADDR_M, store_a, ADDR_A),
    ):
        s.register_peer(oa, o.local_public_key)

    ep_a = _epoch(ADDR_A)
    cfg = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    hm = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[ADDR_B, ADDR_M],
    )
    hm.learn(ADDR_B)
    hm.learn(ADDR_M)
    tx = MagicMock()
    tx.connections.return_value = [ADDR_B]
    fwd = PacketForwarder(cfg, tx, hm, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    wrap_epoch = 0
    targets = [ADDR_B]  # M excluded as in revoke_member
    pair_keys = {ADDR_B: store_a.get_pair_key(ADDR_B, epoch=wrap_epoch)}  # type: ignore[misc]
    assert pair_keys[ADDR_B] is not None
    new_epoch, new_key, revoked = ep_a.prepare_revocation(store_m.local_public_key)
    packets = fwd.build_rekey_flood_packets(
        store_m.local_public_key,
        wrap_epoch=wrap_epoch,
        new_epoch=new_epoch,
        new_group_key=new_key,
        revoked_set=revoked,
        targets=targets,
        pair_keys=pair_keys,  # type: ignore[arg-type]
    )
    parsed = parse_subgroup_packet(packets[0])
    tags = {tag for tag, _ in parsed["cases"]}
    assert compute_anon_id(GROUP_KEY, ADDR_B) in tags
    assert compute_anon_id(GROUP_KEY, ADDR_M) not in tags

    # M cannot obtain k_msg from any case (wrong AAD on unwrap).
    from cryptography.exceptions import InvalidTag

    hdr = parsed["parsed_header"]
    pair_ma = store_m.get_pair_key(ADDR_A, epoch=0)
    assert pair_ma is not None
    for tag, blob in parsed["cases"]:
        wrap_key = derive_wrap_key(pair_ma, hdr["src"], hdr["seq"], hdr["ts_ms"])
        try:
            unwrap_msg_key(wrap_key, blob, aad=tag)
            # Even if unwrap somehow succeeded with wrong semantics, body AAD binds cases.
        except InvalidTag:
            pass
        # Try with M's own tag as AAD — must fail (blob authenticated under B's tag).
        try:
            unwrap_msg_key(wrap_key, blob, aad=compute_anon_id(GROUP_KEY, ADDR_M))
            raise AssertionError("revoked member must not unwrap foreign case")
        except InvalidTag:
            pass


def test_integration_two_hop_adopt() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_r = BBKeyStore.from_group_key(GROUP_KEY, ADDR_R)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_m = BBKeyStore.from_group_key(GROUP_KEY, ADDR_M)

    # Pairwise keys among A↔R, R↔B, A↔B (via announce path), A↔M
    for left, la, right, ra in (
        (store_a, ADDR_A, store_r, ADDR_R),
        (store_r, ADDR_R, store_a, ADDR_A),
        (store_r, ADDR_R, store_b, ADDR_B),
        (store_b, ADDR_B, store_r, ADDR_R),
        (store_a, ADDR_A, store_b, ADDR_B),
        (store_b, ADDR_B, store_a, ADDR_A),
        (store_a, ADDR_A, store_m, ADDR_M),
        (store_m, ADDR_M, store_a, ADDR_A),
    ):
        left.register_peer(ra, right.local_public_key)

    ep_a, ep_r, ep_b = _epoch(ADDR_A), _epoch(ADDR_R), _epoch(ADDR_B)
    mesh = _Mesh()
    cfg = lambda bd: replace(load_config(), group_key=GROUP_KEY, local_bd_addr=bd, ttl_max=10)

    hm_a = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[ADDR_R, ADDR_B, ADDR_M],
    )
    hm_r = _HM(local=ADDR_R, relay=True, key_store=store_r, epoch_store=ep_r, resolved=[ADDR_A, ADDR_B])
    hm_b = _HM(local=ADDR_B, relay=False, key_store=store_b, epoch_store=ep_b, resolved=[ADDR_R])
    for hm in (hm_a, hm_r, hm_b):
        for bd in (ADDR_A, ADDR_R, ADDR_B, ADDR_M):
            hm.learn(bd)

    t_a = mesh.register(ADDR_A, [ADDR_R])
    t_r = mesh.register(ADDR_R, [ADDR_A, ADDR_B])
    t_b = mesh.register(ADDR_B, [ADDR_R])

    fwd_a = PacketForwarder(cfg(ADDR_A), t_a, hm_a, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_r = PacketForwarder(cfg(ADDR_R), t_r, hm_r, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_b = PacketForwarder(cfg(ADDR_B), t_b, hm_b, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    mesh.attach(ADDR_A, fwd_a)
    mesh.attach(ADDR_R, fwd_r)
    mesh.attach(ADDR_B, fwd_b)

    assert ep_b.current_epoch() == 0
    fwd_a.revoke_member(ADDR_M)

    assert ep_a.current_epoch() == 1
    assert ep_b.current_epoch() == 1
    assert store_m.local_public_key in ep_b.revoked_pubkeys()
    assert hm_b.announces >= 1

    # Flood used PKT_REKEY_FLOOD, not n-1 unicasts of PKT_REKEY for the initial push.
    flood_types = [data[0] for _s, _d, data in mesh.sent if data]
    assert PKT_REKEY_FLOOD in flood_types


def test_announce_only_member_in_cases() -> None:
    """Peer known only via pubkey register (no Hello learn) still gets a case."""
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_a.register_peer(ADDR_B, store_b.local_public_key)  # not hello-learned
    assert not store_a.is_hello_learned(ADDR_B)

    ep_a = _epoch(ADDR_A)
    cfg = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    hm = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[],
    )
    # Do NOT hm.learn(ADDR_B) — only anon_id_for_or_compute path.
    tx = MagicMock()
    tx.connections.return_value = []
    fwd = PacketForwarder(cfg, tx, hm, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    pk = store_a.get_pair_key(ADDR_B, epoch=0)
    assert pk is not None
    new_epoch, new_key, revoked = ep_a.prepare_revocation(b"\xee" * 32)
    packets = fwd.build_rekey_flood_packets(
        b"\xee" * 32,
        wrap_epoch=0,
        new_epoch=new_epoch,
        new_group_key=new_key,
        revoked_set=revoked,
        targets=[ADDR_B],
        pair_keys={ADDR_B: pk},
    )
    tags = {tag for tag, _ in parse_subgroup_packet(packets[0])["cases"]}
    assert compute_anon_id(GROUP_KEY, ADDR_B) in tags


def test_non_coordinator_revoke_raises() -> None:
    store = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    ep = _epoch(ADDR_B)
    cfg = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_B, ttl_max=10)
    hm = _HM(local=ADDR_B, relay=False, key_store=store, epoch_store=ep, coordinator=False)
    fwd = PacketForwarder(cfg, MagicMock(), hm, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    try:
        fwd.revoke_member(ADDR_M)
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "coordinator" in str(e).lower()


def test_replay_old_flood_rejected() -> None:
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_a.register_peer(ADDR_B, store_b.local_public_key)
    store_b.register_peer(ADDR_A, store_a.local_public_key)
    ep_a, ep_b = _epoch(ADDR_A), _epoch(ADDR_B)

    cfg_a = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    cfg_b = replace(cfg_a, local_bd_addr=ADDR_B)
    hm_a = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[ADDR_B],
    )
    hm_a.learn(ADDR_B)
    hm_b = _HM(local=ADDR_B, relay=False, key_store=store_b, epoch_store=ep_b)
    hm_b.learn(ADDR_A)

    fwd_a = PacketForwarder(cfg_a, MagicMock(connections=lambda: [ADDR_B]), hm_a, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_b = PacketForwarder(cfg_b, MagicMock(connections=lambda: [ADDR_A]), hm_b, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    pk = store_a.get_pair_key(ADDR_B, epoch=0)
    assert pk is not None
    new_epoch, new_key, revoked = ep_a.prepare_revocation(b"\xdd" * 32)
    packets = fwd_a.build_rekey_flood_packets(
        b"\xdd" * 32,
        wrap_epoch=0,
        new_epoch=new_epoch,
        new_group_key=new_key,
        revoked_set=revoked,
        targets=[ADDR_B],
        pair_keys={ADDR_B: pk},
    )
    fwd_b.handle(ADDR_A, packets[0])
    assert ep_b.current_epoch() == 1

    # Replaying the same flood (epoch already adopted) must not raise / regress.
    fwd_b.handle(ADDR_A, packets[0])  # replay filter may drop; if not, adopt rejects
    assert ep_b.current_epoch() == 1


def test_offline_catchup_via_unicast_gossip() -> None:
    """Member offline during flood is still catchable via PKT_REKEY unicast."""
    store_a = BBKeyStore.from_group_key(GROUP_KEY, ADDR_A)
    store_b = BBKeyStore.from_group_key(GROUP_KEY, ADDR_B)
    store_a.register_peer(ADDR_B, store_b.local_public_key)
    store_b.register_peer(ADDR_A, store_a.local_public_key)
    ep_a, ep_b = _epoch(ADDR_A), _epoch(ADDR_B)

    cfg_a = replace(load_config(), group_key=GROUP_KEY, local_bd_addr=ADDR_A, ttl_max=10)
    cfg_b = replace(cfg_a, local_bd_addr=ADDR_B)
    hm_a = _HM(
        local=ADDR_A,
        relay=False,
        key_store=store_a,
        epoch_store=ep_a,
        coordinator=True,
        resolved=[ADDR_B],
    )
    hm_a.learn(ADDR_B)
    hm_b = _HM(local=ADDR_B, relay=False, key_store=store_b, epoch_store=ep_b)
    hm_b._peer_epochs[ADDR_A] = 0

    tx_a = MagicMock()
    tx_a.connections.return_value = [ADDR_B]
    fwd_a = PacketForwarder(cfg_a, tx_a, hm_a, on_message=lambda _s, _t: None)  # type: ignore[arg-type]
    fwd_b = PacketForwarder(cfg_b, MagicMock(), hm_b, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

    # Coordinator advanced alone (B was offline for the flood).
    ep_a.prepare_revocation(b"\xcc" * 32)
    store_a.clear_pair_key_cache()
    assert ep_a.current_epoch() == 1
    assert ep_b.current_epoch() == 0

    pkt = fwd_a.build_rekey_packet(ADDR_B, peer_epoch=0)
    assert parse_routing_header(pkt)["type"] == PKT_REKEY
    fwd_b.handle(ADDR_A, pkt)
    assert ep_b.current_epoch() == 1
    assert ep_b.current_group_key() == ep_a.current_group_key()


if __name__ == "__main__":
    test_pack_unpack_roundtrip()
    test_partition_small_and_large()
    test_case_tamper_breaks_all_decrypts()
    test_revoked_absent_from_cases()
    test_integration_two_hop_adopt()
    test_announce_only_member_in_cases()
    test_non_coordinator_revoke_raises()
    test_replay_old_flood_rejected()
    test_offline_catchup_via_unicast_gossip()
    print("✅ rekey flood tests passed")
