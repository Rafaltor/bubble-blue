from __future__ import annotations

import struct
from typing import Final

_X25519_PUBLIC_KEY_SIZE: Final = 32
_GROUP_KEY_SIZE: Final = 32
_REKEY_PREFIX = struct.Struct("!L32sH")  # epoch, group_key, n_revoked


def pack_rekey_plaintext(
    epoch: int,
    group_key: bytes,
    revoked_pubkeys: list[bytes] | frozenset[bytes],
) -> bytes:
    """Wire plaintext for PKT_REKEY: epoch ‖ group_key ‖ revoked pubkeys."""
    if not (0 <= epoch <= 0xFFFFFFFF):
        raise ValueError("epoch must fit in uint32")
    if len(group_key) != _GROUP_KEY_SIZE:
        raise ValueError(f"group_key must be {_GROUP_KEY_SIZE} bytes")
    revoked = list(revoked_pubkeys)
    if len(revoked) > 0xFFFF:
        raise ValueError("too many revoked pubkeys")
    for pk in revoked:
        if len(pk) != _X25519_PUBLIC_KEY_SIZE:
            raise ValueError("revoked pubkey must be 32 bytes")
    out = bytearray(_REKEY_PREFIX.pack(int(epoch), group_key, len(revoked)))
    for pk in revoked:
        out += pk
    return bytes(out)


def unpack_rekey_plaintext(data: bytes) -> dict[str, object]:
    """Parse REKEY plaintext; raises ValueError on truncation."""
    if len(data) < _REKEY_PREFIX.size:
        raise ValueError("rekey plaintext too short")
    epoch, group_key, n_revoked = _REKEY_PREFIX.unpack_from(data, 0)
    off = _REKEY_PREFIX.size
    need = off + int(n_revoked) * _X25519_PUBLIC_KEY_SIZE
    if len(data) < need:
        raise ValueError("truncated rekey revoked list")
    revoked: list[bytes] = []
    for _ in range(int(n_revoked)):
        revoked.append(data[off : off + _X25519_PUBLIC_KEY_SIZE])
        off += _X25519_PUBLIC_KEY_SIZE
    return {
        "epoch": int(epoch),
        "group_key": bytes(group_key),
        "revoked_pubkeys": revoked,
    }
