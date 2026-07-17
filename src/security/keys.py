from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Final

_log = logging.getLogger(__name__)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from .packet import bd_addr_to_bytes
    from .signing import (
        ed25519_private_from_identity_seed,
        ed25519_public_bytes,
        sign as ed25519_sign,
        verify as ed25519_verify,
    )
except ImportError:  # pragma: no cover — direct script execution
    import sys

    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from src.security.packet import bd_addr_to_bytes
    from src.security.signing import (
        ed25519_private_from_identity_seed,
        ed25519_public_bytes,
        sign as ed25519_sign,
        verify as ed25519_verify,
    )

_X25519_KEY_SIZE: Final = 32
_PAIRWISE_HKDF_SALT: Final = b"bubble-blue-v1"
_SUBGROUP_WRAP_HKDF_SALT: Final = b"bb-subgroup-wrap-v1"
_IDENTITY_HKDF_SALT: Final = b"bb-identity-v1"
_IDENTITY_HKDF_INFO_PREFIX: Final = b"bubble-blue-x25519-identity:"
_X25519_FROM_SEED_SALT: Final = b"bb-x25519-v1"
_X25519_FROM_SEED_INFO: Final = b"bubble-blue-ecdh"
_DERIVED_KEY_SIZE: Final = 32
_IDENTITY_MAGIC: Final = b"BBID"
_IDENTITY_FILE_VERSION: Final = 1


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


def default_identity_path(local_bd_addr: str) -> Path:
    """Default on-disk identity seed path (independent of group key)."""
    safe = local_bd_addr.replace(":", "").lower() or "node"
    env = os.environ.get("BUBBLE_BLUE_IDENTITY_PATH", "").strip()
    if env:
        return Path(env)
    return Path(f".bb-identity-{safe}.bin")


def _x25519_private_from_seed(seed: bytes) -> X25519PrivateKey:
    raw = _hkdf_sha256(
        seed,
        length=_X25519_KEY_SIZE,
        salt=_X25519_FROM_SEED_SALT,
        info=_X25519_FROM_SEED_INFO,
    )
    return X25519PrivateKey.from_private_bytes(raw)


def _derive_identity_private_key(group_key: bytes, local_bd_addr: str) -> bytes:
    """Deprecated: X25519 private bytes from group key (any member can re-derive)."""
    if len(group_key) != _DERIVED_KEY_SIZE:
        raise ValueError(f"group_key must be {_DERIVED_KEY_SIZE} bytes (got {len(group_key)})")
    addr = local_bd_addr.strip().upper()
    return _hkdf_sha256(
        group_key,
        salt=_IDENTITY_HKDF_SALT,
        info=_IDENTITY_HKDF_INFO_PREFIX + addr.encode("ascii"),
        length=_X25519_KEY_SIZE,
    )


def _load_or_create_identity(path: Path) -> tuple[X25519PrivateKey, bytes]:
    """
    Load identity from ``path``.

    Returns ``(x25519_private, signing_seed)``.

    File formats:
      - BBID v1: magic(4) | version(1) | seed(32) — X25519 and Ed25519 from seed
      - Legacy: raw 32-byte X25519 private — keep ECDH identity; Ed25519 from those bytes
    """
    if path.exists():
        raw = path.read_bytes()
        if len(raw) == 4 + 1 + _X25519_KEY_SIZE and raw[:4] == _IDENTITY_MAGIC:
            version = raw[4]
            if version != _IDENTITY_FILE_VERSION:
                raise ValueError(f"unsupported identity file version {version}")
            seed = bytes(raw[5 : 5 + _X25519_KEY_SIZE])
            return _x25519_private_from_seed(seed), seed
        if len(raw) == _X25519_KEY_SIZE:
            return X25519PrivateKey.from_private_bytes(raw), bytes(raw)
        raise ValueError(
            f"identity file {path} has unexpected length {len(raw)} "
            f"(expected {_X25519_KEY_SIZE} or {4 + 1 + _X25519_KEY_SIZE})"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(_X25519_KEY_SIZE)
    blob = _IDENTITY_MAGIC + bytes([_IDENTITY_FILE_VERSION]) + seed
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return _x25519_private_from_seed(seed), seed


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
    X25519 ECDH identity + Ed25519 signing identity for control-plane attestations.

    **Recommended — file persistence** (``persist_path=...`` / ``for_node(bd)``):
        Random seed on disk (mode ``0o600``). Independent of ``group_key`` — other
        members cannot re-derive private keys (traitor-resistant for pairwise secrecy).

    **Deprecated — from group key** (``from_group_key``):
        X25519 private = HKDF(group_key, bd). Any holder of the PSK can re-derive
        every member's ECDH keys. Kept for tests/sim only.

    **Ephemeral** (``BBKeyStore()`` with no path):
        Fresh random key each process start.
    """

    def __init__(self, *, persist_path: str | Path | None = None) -> None:
        if persist_path is not None:
            self._private_key, signing_seed = _load_or_create_identity(Path(persist_path))
        else:
            self._private_key = X25519PrivateKey.generate()
            signing_seed = self._private_key.private_bytes_raw()
        self._signing_key = ed25519_private_from_identity_seed(signing_seed)
        self._init_peer_state()

    @classmethod
    def for_node(cls, local_bd_addr: str, *, persist_path: str | Path | None = None) -> BBKeyStore:
        """Recommended constructor: persistent random identity for ``local_bd_addr``."""
        path = Path(persist_path) if persist_path is not None else default_identity_path(local_bd_addr)
        return cls(persist_path=path)

    @classmethod
    def from_group_key(
        cls,
        group_key: bytes,
        local_bd_addr: str,
        **kwargs: object,
    ) -> BBKeyStore:
        """
        Deprecated: X25519 identity derived from the group PSK.

        Unsafe when members may be traitors — any member can re-derive all ECDH keys.
        Prefer :meth:`for_node`. Ed25519 signing key is HKDF-derived from the same
        32-byte material (domain-separated).
        """
        _ = kwargs
        inst = cls.__new__(cls)
        priv_bytes = _derive_identity_private_key(group_key, local_bd_addr)
        inst._private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        inst._signing_key = ed25519_private_from_identity_seed(priv_bytes)
        inst._init_peer_state()
        return inst

    def _init_peer_state(self) -> None:
        self._local_public_key = self._private_key.public_key().public_bytes_raw()
        self._local_signing_public_key = ed25519_public_bytes(self._signing_key)
        self._peer_public_keys: dict[str, bytes] = {}
        self._peer_signing_keys: dict[str, bytes] = {}
        self._pair_key_cache: dict[tuple[str, int], bytes] = {}
        self._hello_learned: set[str] = set()

    def clear_pair_key_cache(self) -> None:
        """Invalidate cached pairwise keys (e.g. after epoch adoption)."""
        self._pair_key_cache.clear()

    @property
    def local_public_key(self) -> bytes:
        """32-byte X25519 public key for this node."""
        return self._local_public_key

    @property
    def local_signing_public_key(self) -> bytes:
        """32-byte Ed25519 public key for this node (ANNOUNCE / rekey attestations)."""
        return self._local_signing_public_key

    def sign(self, message: bytes) -> bytes:
        """Ed25519-sign ``message`` with the local signing key (64-byte signature)."""
        return ed25519_sign(self._signing_key, message)

    def verify_peer_signature(self, bd_addr: str, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` under the registered Ed25519 key for ``bd_addr``."""
        pub = self._peer_signing_keys.get(bd_addr.strip().upper())
        if pub is None:
            return False
        return ed25519_verify(pub, message, signature)

    def mark_hello_learned(self, bd_addr: str) -> None:
        """Mark ``bd_addr`` as having a pubkey from a direct Hello private part."""
        self._hello_learned.add(bd_addr.strip().upper())

    def is_hello_learned(self, bd_addr: str) -> bool:
        """True if the peer pubkey was registered from Hello (not only ANNOUNCE)."""
        return bd_addr.strip().upper() in self._hello_learned

    def register_peer(
        self,
        bd_addr: str,
        public_key: bytes,
        *,
        signing_public_key: bytes | None = None,
    ) -> None:
        """
        Record a peer's X25519 public key (and optional Ed25519 signing key).

        Re-registering the same address with a different ECDH key invalidates
        any cached pairwise key.
        """
        addr = bd_addr.strip().upper()
        if len(public_key) != _X25519_KEY_SIZE:
            raise ValueError(f"public_key must be {_X25519_KEY_SIZE} bytes (got {len(public_key)})")
        X25519PublicKey.from_public_bytes(public_key)

        prev = self._peer_public_keys.get(addr)
        self._peer_public_keys[addr] = bytes(public_key)
        if prev != public_key:
            self._pair_key_cache = {k: v for k, v in self._pair_key_cache.items() if k[0] != addr}

        if signing_public_key is not None:
            if len(signing_public_key) != 32:
                raise ValueError("signing_public_key must be 32 bytes")
            self._peer_signing_keys[addr] = bytes(signing_public_key)

    def register_peer_from_hello(
        self,
        bd_addr: str,
        public_key: bytes,
        *,
        signing_public_key: bytes | None = None,
    ) -> None:
        """Register pubkey from Hello private and mark hello-learned provenance."""
        self.register_peer(bd_addr, public_key, signing_public_key=signing_public_key)
        self.mark_hello_learned(bd_addr)

    def apply_announce_binding(
        self,
        bd_addr: str,
        public_key: bytes,
        *,
        signing_public_key: bytes,
        signature: bytes,
        signed_message: bytes,
    ) -> str:
        """
        Apply a signed PKT_ANNOUNCE binding.

        Requires a valid Ed25519 signature under ``signing_public_key`` (PoP).
        Conflict policy: Hello-learned wins; else first-seen.

        Returns ``registered`` | ``noop`` | ``ignored_hello`` | ``ignored_first``
        | ``rejected_sig``.
        """
        addr = bd_addr.strip().upper()
        if len(public_key) != _X25519_KEY_SIZE:
            raise ValueError(f"public_key must be {_X25519_KEY_SIZE} bytes (got {len(public_key)})")
        if not ed25519_verify(signing_public_key, signed_message, signature):
            _log.warning("[SEC] ANNOUNCE signature invalide pour %s", addr)
            return "rejected_sig"

        X25519PublicKey.from_public_bytes(public_key)
        pub = bytes(public_key)
        sig_pub = bytes(signing_public_key)

        prev = self._peer_public_keys.get(addr)
        if prev is None:
            self.register_peer(addr, pub, signing_public_key=sig_pub)
            return "registered"
        if prev == pub:
            self._peer_signing_keys.setdefault(addr, sig_pub)
            return "noop"
        if addr in self._hello_learned:
            _log.warning(
                "[SEC] conflit de binding pubkey pour %s (announce ignoré)",
                addr,
            )
            return "ignored_hello"
        _log.warning(
            "[SEC] conflit de binding pubkey pour %s (premier vu conservé, announce ignoré)",
            addr,
        )
        return "ignored_first"

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

    def get_peer_signing_public_key(self, bd_addr: str) -> bytes | None:
        """Return the registered Ed25519 public key for ``bd_addr``, if known."""
        pub = self._peer_signing_keys.get(bd_addr.strip().upper())
        return bytes(pub) if pub is not None else None

    def known_peers(self) -> list[str]:
        """BD addresses for which a peer public key has been registered."""
        return sorted(self._peer_public_keys.keys())


if __name__ == "__main__":
    import tempfile

    group_key = b"\x01" * 32
    addr_a = "AA:BB:CC:DD:EE:01"
    addr_b = "AA:BB:CC:DD:EE:02"

    # Group-derived X25519 identity must remain stable (wire/test compat).
    d1 = BBKeyStore.from_group_key(group_key, addr_a)
    d2 = BBKeyStore.from_group_key(group_key, addr_a)
    assert d1.local_public_key == d2.local_public_key
    assert d1.local_signing_public_key == d2.local_signing_public_key

    with tempfile.TemporaryDirectory() as tmp:
        path_a = Path(tmp) / "a.bin"
        path_b = Path(tmp) / "b.bin"
        store_a = BBKeyStore(persist_path=path_a)
        store_b = BBKeyStore(persist_path=path_b)
        assert BBKeyStore(persist_path=path_a).local_public_key == store_a.local_public_key
        assert store_a.local_public_key != store_b.local_public_key
        assert store_a.local_public_key != d1.local_public_key

        store_a.register_peer(
            addr_b,
            store_b.local_public_key,
            signing_public_key=store_b.local_signing_public_key,
        )
        store_b.register_peer(
            addr_a,
            store_a.local_public_key,
            signing_public_key=store_a.local_signing_public_key,
        )

        key_ab = store_a.get_pair_key(addr_b)
        key_ba = store_b.get_pair_key(addr_a)
        assert key_ab is not None and key_ba is not None
        assert key_ab == key_ba

        msg = b"attest"
        sig = store_a.sign(msg)
        assert store_b.verify_peer_signature(addr_a, msg, sig)
        assert path_a.stat().st_mode & 0o777 == 0o600

        # Legacy raw X25519 file still loads.
        legacy = Path(tmp) / "legacy.bin"
        raw_priv = X25519PrivateKey.generate().private_bytes_raw()
        legacy.write_bytes(raw_priv)
        leg = BBKeyStore(persist_path=legacy)
        assert leg.local_public_key == X25519PrivateKey.from_private_bytes(raw_priv).public_key().public_bytes_raw()

    print("✅ keys.py self-test passed")
