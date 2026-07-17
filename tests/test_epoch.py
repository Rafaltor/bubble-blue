from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace
from unittest.mock import MagicMock

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_REKEY, load_config  # noqa: E402
from src.control.hello import build_hello, parse_hello_private  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.epoch import EpochStore, is_coordinator  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402
from src.security.rekey import pack_rekey_plaintext, unpack_rekey_plaintext  # noqa: E402


def test_epoch_store_persist_roundtrip() -> None:
    bootstrap = b"\x01" * 32
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "epoch.bin")
        store = EpochStore(bootstrap, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01")
        new_epoch, new_key, revoked = store.prepare_revocation(b"\xaa" * 32)
        assert new_epoch == 1
        assert len(new_key) == 32
        assert store.adopt_rekey(0, bootstrap, []) is False

        store2 = EpochStore(bootstrap, persist_path=path, local_bd_addr="AA:BB:CC:DD:EE:01")
        assert store2.current_epoch() == 1
        assert store2.current_group_key() == new_key
        assert store2.is_revoked_pubkey(b"\xaa" * 32)


def test_rekey_plaintext_roundtrip() -> None:
    plain = pack_rekey_plaintext(3, b"\x02" * 32, [b"\x03" * 32])
    body = unpack_rekey_plaintext(plain)
    assert body["epoch"] == 3
    assert body["group_key"] == b"\x02" * 32
    assert body["revoked_pubkeys"] == [b"\x03" * 32]


def test_hello_private_carries_epoch() -> None:
    bootstrap = b"\x04" * 32
    current = b"\x05" * 32
    pub = os.urandom(32)
    pkt = build_hello(
        current,
        "AA:BB:CC:DD:EE:01",
        seq=1,
        known_neighbors=[],
        local_public_key=pub,
        epoch=7,
        anon_id_key=bootstrap,
    )
    priv = parse_hello_private(pkt, current)
    assert priv is not None
    assert priv["epoch"] == 7
    assert priv["public_key"] == pub


def test_rekey_adoption_via_forwarder() -> None:
    # Group key where ADDR_A is the true min-anon_id coordinator vs ADDR_B.
    cfg = replace(load_config(), group_key=b"\x08" * 32, local_bd_addr="AA:BB:CC:DD:EE:01", ttl_max=10)
    addr_a, addr_b = "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"

    store_a = BBKeyStore.from_group_key(cfg.group_key, addr_a)
    store_b = BBKeyStore.from_group_key(cfg.group_key, addr_b)
    store_a.register_peer(
        addr_b, store_b.local_public_key, signing_public_key=store_b.local_signing_public_key
    )
    store_b.register_peer(
        addr_a, store_a.local_public_key, signing_public_key=store_a.local_signing_public_key
    )

    with tempfile.TemporaryDirectory() as tmp:
        epoch_a = EpochStore(
            cfg.group_key, persist_path=os.path.join(tmp, "a.bin"), local_bd_addr=addr_a
        )
        epoch_b = EpochStore(
            cfg.group_key, persist_path=os.path.join(tmp, "b.bin"), local_bd_addr=addr_b
        )

        class T:
            def __init__(self) -> None:
                self.sent: list[tuple[str, bytes]] = []

            def connections(self) -> list[str]:
                return [addr_b]

            def send(self, p: str, d: bytes) -> None:
                self.sent.append((p.upper(), bytes(d)))

        class HM:
            def __init__(self, relay: bool, local: str, store: BBKeyStore, epoch: EpochStore) -> None:
                self.is_relay = relay
                from src.control.hello import compute_anon_id

                self.anon_id = compute_anon_id(cfg.group_key, local)
                self.table = MagicMock()
                self.key_store = store
                self.epoch_store = epoch
                self._epochs: dict[str, int] = {}
                self._local = local.upper()

            def refresh_cds_role(self, *, verbose: bool = False) -> None:
                _ = verbose

            def local_anon_id(self) -> bytes:
                return self.anon_id

            def anon_id_for(self, bd: str) -> bytes:
                from src.control.hello import compute_anon_id

                return compute_anon_id(cfg.group_key, bd)

            def anon_id_for_or_compute(self, bd: str) -> bytes:
                return self.anon_id_for(bd)

            def get_peer_epoch(self, bd: str) -> int:
                return self._epochs.get(bd.upper(), 0)

            def get_resolved_members(self) -> list[dict[str, str | bytes]]:
                other = addr_b if self._local == addr_a else addr_a
                return [{"bd_addr": other, "anon_id": self.anon_id_for(other)}]

            def is_coordinator(self) -> bool:
                return self._local == addr_a

            def set_rekey_catchup(self, _h) -> None:
                pass

        transport = T()
        hm_a = HM(False, addr_a, store_a, epoch_a)
        hm_b = HM(False, addr_b, store_b, epoch_b)
        fwd_a = PacketForwarder(cfg, transport, hm_a, on_message=lambda _s, _t: None)  # type: ignore[arg-type]

        revoked_pk = b"\xff" * 32
        new_epoch, new_key, _revoked = epoch_a.prepare_revocation(revoked_pk)
        store_a.clear_pair_key_cache()
        pkt = fwd_a.build_rekey_packet(addr_b, peer_epoch=0)

        fwd_b = PacketForwarder(
            replace(cfg, local_bd_addr=addr_b),
            MagicMock(),
            hm_b,
            on_message=lambda _s, _t: None,
        )  # type: ignore[arg-type]
        fwd_b.handle(addr_a, pkt)
        assert epoch_b.current_epoch() == new_epoch
        assert epoch_b.current_group_key() == new_key


def test_coordinator_convention() -> None:
    a, b, c = b"\x01" * 8, b"\x02" * 8, b"\x03" * 8
    assert is_coordinator(a, [b, c])
    assert not is_coordinator(c, [a, b])


if __name__ == "__main__":
    test_epoch_store_persist_roundtrip()
    test_rekey_plaintext_roundtrip()
    test_hello_private_carries_epoch()
    test_rekey_adoption_via_forwarder()
    test_coordinator_convention()
    print("✅ epoch tests passed")
