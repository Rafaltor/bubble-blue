from __future__ import annotations

import os
import secrets
import struct
import threading
from pathlib import Path
from typing import Final

_EPOCH_MAGIC: Final = b"BBEP"
_EPOCH_FILE_VERSION: Final = 1
_X25519_PUBLIC_KEY_SIZE: Final = 32
_GROUP_KEY_SIZE: Final = 32
_EPOCH_HEADER = struct.Struct("!4sBL32sH")  # magic, version, epoch, group_key, n_revoked


class EpochStore:
    """
    Group epoch state: current group key, monotonic epoch, revoked X25519 pubkeys.

    Persisted locally (~100 B + 32 B per revoked member) so reboots keep revocation.
    Bootstrap ``group_key`` from ``.env`` is epoch 0 initial material.
    """

    def __init__(
        self,
        bootstrap_group_key: bytes,
        *,
        persist_path: str | Path | None = None,
        local_bd_addr: str = "",
    ) -> None:
        if len(bootstrap_group_key) != _GROUP_KEY_SIZE:
            raise ValueError(f"bootstrap_group_key must be {_GROUP_KEY_SIZE} bytes")
        self._bootstrap_group_key = bytes(bootstrap_group_key)
        self._local_bd = local_bd_addr.strip().upper()
        self._path = Path(persist_path) if persist_path else _default_epoch_path(self._local_bd)
        self._lock = threading.RLock()
        self._epoch = 0
        self._group_key = bytes(bootstrap_group_key)
        self._revoked: set[bytes] = set()
        self._load()

    @property
    def bootstrap_group_key(self) -> bytes:
        """Initial PSK from ``.env`` — stable input for ``compute_anon_id``."""
        return self._bootstrap_group_key

    def current_epoch(self) -> int:
        with self._lock:
            return self._epoch

    def current_group_key(self) -> bytes:
        with self._lock:
            return bytes(self._group_key)

    def revoked_pubkeys(self) -> frozenset[bytes]:
        with self._lock:
            return frozenset(self._revoked)

    def is_revoked_pubkey(self, public_key: bytes) -> bool:
        if len(public_key) != _X25519_PUBLIC_KEY_SIZE:
            return False
        with self._lock:
            return bytes(public_key) in self._revoked

    def adopt_rekey(
        self,
        epoch: int,
        group_key: bytes,
        revoked_pubkeys: list[bytes] | frozenset[bytes],
    ) -> bool:
        """
        Adopt a newer epoch state. Returns True if adopted (strictly greater epoch).
        """
        if len(group_key) != _GROUP_KEY_SIZE:
            raise ValueError(f"group_key must be {_GROUP_KEY_SIZE} bytes")
        for pk in revoked_pubkeys:
            if len(pk) != _X25519_PUBLIC_KEY_SIZE:
                raise ValueError("revoked pubkey must be 32 bytes")

        with self._lock:
            if int(epoch) <= self._epoch:
                return False
            self._epoch = int(epoch)
            self._group_key = bytes(group_key)
            self._revoked.update(bytes(pk) for pk in revoked_pubkeys)
            self._save()
            return True

    def prepare_revocation(self, revoked_pubkey: bytes) -> tuple[int, bytes, frozenset[bytes]]:
        """
        Bump epoch and rotate group key; add ``revoked_pubkey`` to the list.

        Returns ``(new_epoch, new_group_key, full_revoked_set)`` for a REKEY payload.
        Caller must flood REKEY before relying on peers having adopted.
        """
        if len(revoked_pubkey) != _X25519_PUBLIC_KEY_SIZE:
            raise ValueError("revoked_pubkey must be 32 bytes")

        with self._lock:
            if bytes(revoked_pubkey) in self._revoked:
                raise RuntimeError("member already revoked")
            new_epoch = self._epoch + 1
            new_key = secrets.token_bytes(_GROUP_KEY_SIZE)
            self._revoked.add(bytes(revoked_pubkey))
            self._epoch = new_epoch
            self._group_key = new_key
            self._save()
            return new_epoch, new_key, frozenset(self._revoked)

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = self._path.read_bytes()
        if len(raw) < _EPOCH_HEADER.size:
            return
        magic, version, epoch, group_key, n_revoked = _EPOCH_HEADER.unpack_from(raw, 0)
        if magic != _EPOCH_MAGIC or version != _EPOCH_FILE_VERSION:
            return
        off = _EPOCH_HEADER.size
        need = off + int(n_revoked) * _X25519_PUBLIC_KEY_SIZE
        if len(raw) < need:
            return
        revoked: set[bytes] = set()
        for _ in range(int(n_revoked)):
            revoked.add(raw[off : off + _X25519_PUBLIC_KEY_SIZE])
            off += _X25519_PUBLIC_KEY_SIZE
        self._epoch = int(epoch)
        self._group_key = bytes(group_key)
        self._revoked = revoked

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        revoked = sorted(self._revoked)
        buf = bytearray(
            _EPOCH_HEADER.pack(
                _EPOCH_MAGIC,
                _EPOCH_FILE_VERSION,
                self._epoch,
                self._group_key,
                len(revoked),
            )
        )
        for pk in revoked:
            buf += pk
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(buf)
        tmp.replace(self._path)


def _default_epoch_path(local_bd_addr: str) -> Path:
    safe = local_bd_addr.replace(":", "").lower() or "node"
    env = os.environ.get("BUBBLE_BLUE_EPOCH_STATE", "").strip()
    if env:
        return Path(env)
    return Path(f".bb-epoch-{safe}.bin")


def is_coordinator(local_anon_id: bytes, member_anon_ids: list[bytes]) -> bool:
    """Coordinator convention: smallest anon_id among live members (including self)."""
    all_ids = list(member_anon_ids) + [local_anon_id]
    return local_anon_id == min(all_ids)
