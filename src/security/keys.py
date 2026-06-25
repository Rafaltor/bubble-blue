from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from .packet import bd_addr_to_bytes
except ImportError:  # pragma: no cover — direct script execution
    import sys

    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from src.security.packet import bd_addr_to_bytes

_X25519_KEY_SIZE: Final = 32
_PAIRWISE_HKDF_SALT: Final = b"bubble-blue-v1"
_SUBGROUP_WRAP_HKDF_SALT: Final = b"bb-subgroup-wrap-v1"
_IDENTITY_HKDF_SALT: Final = b"bb-identity-v1"
_IDENTITY_HKDF_INFO_PREFIX: Final = b"bubble-blue-x25519-identity:"
_DERIVED_KEY_SIZE: Final = 32


def _hkdf_sha256(
    ikm: bytes,
    *,
    length: int,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """Derive ``length`` bytes with HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def _load_or_create_file_private_key(path: Path) -> X25519PrivateKey:
    """Load 32-byte raw X25519 private key from ``path``, or create and persist it."""
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != _X25519_KEY_SIZE:
            raise ValueError(
                f"identity file {path} must be {_X25519_KEY_SIZE} bytes (got {len(raw)})"
            )
        return X25519PrivateKey.from_private_bytes(raw)

    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = X25519PrivateKey.generate()
    raw = private_key.private_bytes_raw()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return private_key


def _derive_identity_private_key(group_key: bytes, local_bd_addr: str) -> bytes:
    if len(group_key) != _DERIVED_KEY_SIZE:
        raise ValueError(f"group_key must be {_DERIVED_KEY_SIZE} bytes (got {len(group_key)})")
    addr = local_bd_addr.strip().upper()
    return _hkdf_sha256(
        group_key,
        salt=_IDENTITY_HKDF_SALT,
        info=_IDENTITY_HKDF_INFO_PREFIX + addr.encode("ascii"),
        length=_X25519_KEY_SIZE,
    )


def _derive_pairwise_key(
    private_key: X25519PrivateKey,
    peer_public_key: bytes,
    *,
    epoch: int = 0,
) -> bytes:
    """ECDH + HKDF to a 32-byte pairwise secret (epoch-domain-separated)."""
    if len(peer_public_key) != _X25519_KEY_SIZE:
        raise ValueError(f"peer public key must be {_X25519_KEY_SIZE} bytes (got {len(peer_public_key)})")
    peer = X25519PublicKey.from_public_bytes(peer_public_key)
    shared = private_key.exchange(peer)
    info = b"" if int(epoch) == 0 else struct.pack("!L", int(epoch) & 0xFFFFFFFF)
    return _hkdf_sha256(shared, length=_DERIVED_KEY_SIZE, salt=_PAIRWISE_HKDF_SALT, info=info)


def derive_packet_key(base_key: bytes, src: str, seq: int, ts_ms: int) -> bytes:
    """
    Per-packet AES key from a long-term base (``group_key`` or pairwise key).

    ``info`` = ``src`` BD address (6 B) || ``seq`` (uint32 BE) || ``ts_ms`` (uint64 BE).
    """
    if len(base_key) != _DERIVED_KEY_SIZE:
        raise ValueError(f"base_key must be {_DERIVED_KEY_SIZE} bytes (got {len(base_key)})")
    if not (0 <= seq <= 0xFFFFFFFF):
        raise ValueError("seq must fit in uint32")
    if not (0 <= ts_ms <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("ts_ms must fit in uint64")

    src_b = bd_addr_to_bytes(src)
    info = src_b + struct.pack("!LQ", int(seq), int(ts_ms))
    return _hkdf_sha256(base_key, length=_DERIVED_KEY_SIZE, info=info)


def derive_wrap_key(pair_key: bytes, src: str, seq: int, ts_ms: int) -> bytes:
    """
    Per-message, per-recipient wrap key for PKT_SUBGROUP case blobs.

    ``info`` = ``src`` BD address (6 B) || ``seq`` (uint32 BE) || ``ts_ms`` (uint64 BE).
    Domain-separated from ``derive_packet_key`` via a distinct HKDF salt so wrap keys
    and payload keys cannot be cross-used (nonce reuse under the same AES key).
    """
    if len(pair_key) != _DERIVED_KEY_SIZE:
        raise ValueError(f"pair_key must be {_DERIVED_KEY_SIZE} bytes (got {len(pair_key)})")
    if not (0 <= seq <= 0xFFFFFFFF):
        raise ValueError("seq must fit in uint32")
    if not (0 <= ts_ms <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("ts_ms must fit in uint64")

    src_b = bd_addr_to_bytes(src)
    info = src_b + struct.pack("!LQ", int(seq), int(ts_ms))
    return _hkdf_sha256(
        pair_key,
        length=_DERIVED_KEY_SIZE,
        salt=_SUBGROUP_WRAP_HKDF_SALT,
        info=info,
    )


class BBKeyStore:
    """
    X25519 identity and per-peer pairwise keys for private messaging.

    Static ECDH secrets are derived locally; no key material is placed in data packets.

    Two ways to obtain a **stable** identity across reboots:

    **Strategy A — file persistence** (``persist_path=...``):
        Load a 32-byte raw X25519 private key from disk, or generate and write it
        (mode ``0o600``). Useful when you want identity independent of group key rotation.

    **Strategy B — deterministic from group key** (``from_group_key(...)``, recommended):
        ``HKDF-SHA256(group_key, salt=bb-identity-v1,
        info=b"bubble-blue-x25519-identity:" + local_bd_addr)``.
        Same ``group_key`` + BD address always yields the same key pair.
        No file I/O — ideal for embedded nodes. If ``group_key`` rotates, the identity
        rotates too (peers must re-learn the new public key via Hello).

    **Ephemeral** (``BBKeyStore()`` with no ``persist_path``):
        Fresh random key each process start — private messages break after restart.
    """

    def __init__(self, *, persist_path: str | Path | None = None) -> None:
        if persist_path is not None:
            self._private_key = _load_or_create_file_private_key(Path(persist_path))
        else:
            self._private_key = X25519PrivateKey.generate()
        self._init_peer_state()

    @classmethod
    def from_group_key(
        cls,
        group_key: bytes,
        local_bd_addr: str,
        **kwargs: object,
    ) -> BBKeyStore:
        """
        Deterministic identity derived from the group pre-shared key and local BD address.

        ``kwargs`` is reserved for forward compatibility (ignored today).

        Caveat: rotating ``group_key`` changes this node's X25519 identity; peers must
        receive a fresh Hello to learn the new ``public_key``.
        """
        _ = kwargs
        inst = cls.__new__(cls)
        priv_bytes = _derive_identity_private_key(group_key, local_bd_addr)
        inst._private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        inst._init_peer_state()
        return inst

    def _init_peer_state(self) -> None:
        self._local_public_key = self._private_key.public_key().public_bytes_raw()
        self._peer_public_keys: dict[str, bytes] = {}
        self._pair_key_cache: dict[tuple[str, int], bytes] = {}

    def clear_pair_key_cache(self) -> None:
        """Invalidate cached pairwise keys (e.g. after epoch adoption)."""
        self._pair_key_cache.clear()

    @property
    def local_public_key(self) -> bytes:
        """32-byte X25519 public key for this node (advertised in Hello, not in PKT_DATA)."""
        return self._local_public_key

    def register_peer(self, bd_addr: str, public_key: bytes) -> None:
        """
        Record a peer's static X25519 public key (e.g. from a received Hello).

        Re-registering the same address with a different key invalidates any cached pairwise key.
        """
        addr = bd_addr.strip().upper()
        if len(public_key) != _X25519_KEY_SIZE:
            raise ValueError(f"public_key must be {_X25519_KEY_SIZE} bytes (got {len(public_key)})")
        X25519PublicKey.from_public_bytes(public_key)

        prev = self._peer_public_keys.get(addr)
        self._peer_public_keys[addr] = bytes(public_key)
        if prev != public_key:
            self._pair_key_cache = {k: v for k, v in self._pair_key_cache.items() if k[0] != addr}

    def get_pair_key(self, bd_addr: str, *, epoch: int = 0) -> bytes | None:
        """
        Return the cached 32-byte pairwise key for ``bd_addr`` at ``epoch``.

        ``K_pair = HKDF(ECDH, info=epoch)`` (empty info at epoch 0 for wire compat).
        """
        addr = bd_addr.strip().upper()
        pub = self._peer_public_keys.get(addr)
        if pub is None:
            return None

        ep = int(epoch)
        cache_key = (addr, ep)
        cached = self._pair_key_cache.get(cache_key)
        if cached is not None:
            return cached

        pair_key = _derive_pairwise_key(self._private_key, pub, epoch=ep)
        self._pair_key_cache[cache_key] = pair_key
        return pair_key

    def get_peer_public_key(self, bd_addr: str) -> bytes | None:
        """Return the registered X25519 public key for ``bd_addr``, if known."""
        pub = self._peer_public_keys.get(bd_addr.strip().upper())
        return bytes(pub) if pub is not None else None

    def known_peers(self) -> list[str]:
        """BD addresses for which a peer public key has been registered."""
        return sorted(self._peer_public_keys.keys())


if __name__ == "__main__":
    import tempfile

    group_key = b"\x01" * 32
    addr_a = "AA:BB:CC:DD:EE:01"
    addr_b = "AA:BB:CC:DD:EE:02"

    store_a = BBKeyStore.from_group_key(group_key, addr_a)
    store_b = BBKeyStore.from_group_key(group_key, addr_b)
    assert BBKeyStore.from_group_key(group_key, addr_a).local_public_key == store_a.local_public_key

    store_a.register_peer(addr_b, store_b.local_public_key)
    store_b.register_peer(addr_a, store_a.local_public_key)

    key_ab = store_a.get_pair_key(addr_b)
    key_ba = store_b.get_pair_key(addr_a)
    assert key_ab is not None and key_ba is not None
    assert key_ab == key_ba, "ECDH pairwise key must be symmetric"

    pkt_key = derive_packet_key(key_ab, addr_a, seq=1, ts_ms=1_700_000_000_000)
    assert len(pkt_key) == 32
    assert pkt_key != key_ab

    wrap_key = derive_wrap_key(key_ab, addr_a, seq=1, ts_ms=1_700_000_000_000)
    assert len(wrap_key) == 32
    assert wrap_key != key_ab
    assert wrap_key != pkt_key

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "identity.key"
        s1 = BBKeyStore(persist_path=path)
        pub1 = s1.local_public_key
        s2 = BBKeyStore(persist_path=path)
        assert s2.local_public_key == pub1
        assert path.stat().st_mode & 0o777 == 0o600

    print("✅ keys.py self-test passed")
