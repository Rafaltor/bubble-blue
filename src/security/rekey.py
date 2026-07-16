"""
PKT_REKEY plaintext and PKT_REKEY_FLOOD multi-recipient helpers.

PKT_REKEY (0x05) unicast gossip is unchanged: pairwise-encrypted
``pack_rekey_plaintext`` body under ``derive_packet_key``.

PKT_REKEY_FLOOD (0x07) is the coordinator's initial revocation broadcast.
Wire layout reuses the PKT_SUBGROUP case header (n_cases × (tag‖wrap blob))
so each non-revoked member can unwrap a fresh ``k_msg`` and decrypt the
rekey plaintext. See arXiv:2509.00967 (multi-destination wrap header).

**Metadata leakage (assumed):** ``n_cases`` and each recipient_tag are
cleartext on the wire — observers learn the cardinality (and opaque tags)
of the wrap set. No padding or decoy cases are added.
"""

from __future__ import annotations

import struct
from typing import Final

from src.security.packet import (
    GCM_TAG_SIZE,
    ROUTING_HEADER_SIZE,
    SUBGROUP_CASE_SIZE,
    SUBGROUP_N_CASES_MAX,
)

_X25519_PUBLIC_KEY_SIZE: Final = 32
_GROUP_KEY_SIZE: Final = 32
_REKEY_PREFIX = struct.Struct("!L32sH")  # epoch, group_key, n_revoked


def pack_rekey_plaintext(
    epoch: int,
    group_key: bytes,
    revoked_pubkeys: list[bytes] | frozenset[bytes],
) -> bytes:
    """Wire plaintext for PKT_REKEY / PKT_REKEY_FLOOD body: epoch ‖ group_key ‖ revoked."""
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


def rekey_plaintext_len(n_revoked: int) -> int:
    """Byte length of ``pack_rekey_plaintext`` for ``n_revoked`` pubkeys."""
    n = int(n_revoked)
    if n < 0:
        raise ValueError("n_revoked must be >= 0")
    return _REKEY_PREFIX.size + n * _X25519_PUBLIC_KEY_SIZE


def partition_rekey_targets(
    targets: list[str],
    body_len: int,
    mtu: int,
) -> list[list[str]]:
    """
    Split recipient BD addresses into MTU-safe subsets for PKT_REKEY_FLOOD.

    Each partition becomes an independent, self-contained flood packet
    (own seq/ts/k_msg/body). No wire-level reassembly.

    Budget per packet::

        mtu - routing_header - 1 (n_cases) - body_len - GCM_tag
        // SUBGROUP_CASE_SIZE
    """
    ordered = sorted({t.strip().upper() for t in targets if t and t.strip()})
    if not ordered:
        return []

    body = int(body_len)
    if body < 0:
        raise ValueError("body_len must be >= 0")
    mtu_i = int(mtu)
    fixed = ROUTING_HEADER_SIZE + 1 + body + GCM_TAG_SIZE
    budget = mtu_i - fixed
    case_size = SUBGROUP_CASE_SIZE  # tag (8) + wrap blob (48) — from packet.py
    if budget < case_size:
        raise ValueError(
            f"MTU {mtu_i} too small for one rekey-flood case "
            f"(need >= {fixed + case_size} B)"
        )
    max_cases = min(SUBGROUP_N_CASES_MAX, budget // case_size)
    if max_cases < 1:
        raise ValueError("max_cases < 1 after MTU budget")

    partitions: list[list[str]] = []
    for i in range(0, len(ordered), max_cases):
        partitions.append(ordered[i : i + max_cases])
    return partitions
