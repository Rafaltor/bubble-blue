"""
PKT_ANNOUNCE — network-wide (bd_addr → X25519 pubkey) binding under group key.

Complements Hello private parts (2-hop limited): silent or multi-hop members
learn peer pubkeys so pairwise keys and rekey floods can reach them.
"""

from __future__ import annotations

import struct
import time
from typing import Any

from cryptography.exceptions import InvalidTag

from config import PKT_ANNOUNCE
from src.control.hello import X25519_PUBLIC_KEY_SIZE
from src.security.crypto import decrypt_with_key, encrypt_with_key
from src.security.keys import derive_packet_key
from src.security.packet import (
    BROADCAST_BD_ADDR,
    bd_addr_to_bytes,
    build_bb_packet,
    build_routing_header,
    bytes_to_bd_addr,
    parse_bb_packet,
    routing_header_aad,
)

_ANNOUNCE_VERSION = 0x01
# version(1) | bd_addr(6) | epoch(u32) | x25519_pub(32)
_ANNOUNCE_PLAINTEXT_SIZE = 1 + 6 + 4 + X25519_PUBLIC_KEY_SIZE
_ANNOUNCE_PLAINTEXT = struct.Struct("!B6sL32s")


def pack_announce_plaintext(
    local_bd_addr: str,
    epoch: int,
    public_key: bytes,
) -> bytes:
    """
    Pack announce plaintext.

    Layout: version(0x01, 1B) | bd_addr(6B) | epoch(uint32 BE) | x25519_pub(32B).
    """
    if len(public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"public_key must be {X25519_PUBLIC_KEY_SIZE} bytes "
            f"(got {len(public_key)})"
        )
    if not (0 <= int(epoch) <= 0xFFFFFFFF):
        raise ValueError("epoch must fit in uint32")
    return _ANNOUNCE_PLAINTEXT.pack(
        _ANNOUNCE_VERSION,
        bd_addr_to_bytes(local_bd_addr),
        int(epoch),
        bytes(public_key),
    )


def unpack_announce_plaintext(data: bytes) -> dict[str, Any]:
    """Parse announce plaintext; raises ValueError if truncated or unknown version."""
    if len(data) < _ANNOUNCE_PLAINTEXT_SIZE:
        raise ValueError("announce plaintext too short")
    if len(data) != _ANNOUNCE_PLAINTEXT_SIZE:
        raise ValueError("announce plaintext unexpected length")

    version, bd_b, epoch, public_key = _ANNOUNCE_PLAINTEXT.unpack(data)
    if version != _ANNOUNCE_VERSION:
        raise ValueError(f"unsupported announce version: 0x{version:02X}")
    if len(public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError("truncated X25519 public key in announce")

    return {
        "bd_addr": bytes_to_bd_addr(bd_b),
        "epoch": int(epoch),
        "public_key": bytes(public_key),
    }


def build_announce(
    group_key: bytes,
    local_bd_addr: str,
    seq: int,
    ts_ms: int | None,
    epoch: int,
    public_key: bytes,
    ttl: int,
) -> bytes:
    """
    Build a PKT_ANNOUNCE wire packet (group-encrypted, broadcast).

    Encryption path matches PKT_DATA group traffic:
    ``derive_packet_key`` + ``encrypt_with_key`` + ``routing_header_aad``.
    """
    if ts_ms is None:
        ts_ms = time.time_ns() // 1_000_000
    src = local_bd_addr.strip().upper()
    rh = build_routing_header(
        PKT_ANNOUNCE, src, BROADCAST_BD_ADDR, ttl, seq, int(ts_ms)
    )
    plaintext = pack_announce_plaintext(src, epoch, public_key)
    packet_key = derive_packet_key(group_key, src, seq, int(ts_ms))
    enc = encrypt_with_key(packet_key, plaintext, routing_header_aad(rh))
    return build_bb_packet(rh, enc["ciphertext"])


def parse_announce(packet: bytes, group_keys: list[bytes]) -> dict[str, Any] | None:
    """
    Decrypt and parse PKT_ANNOUNCE trying each group key in order.

    Returns dict with bd_addr, epoch, public_key (plus src/seq/ts_ms from header),
    or None if every key fails (InvalidTag) / malformed.
    """
    try:
        parsed = parse_bb_packet(packet)
        hdr = parsed["parsed_header"]
        if int(hdr["type"]) != PKT_ANNOUNCE:
            return None
        src = str(hdr["src"]).upper()
        seq = int(hdr["seq"])
        ts_ms = int(hdr["ts_ms"])
        aad = routing_header_aad(parsed["routing_header"])
        ciphertext = parsed["ciphertext"]
    except (ValueError, KeyError, TypeError):
        return None

    for key in group_keys:
        try:
            packet_key = derive_packet_key(key, src, seq, ts_ms)
            plain = decrypt_with_key(packet_key, ciphertext, aad)
            body = unpack_announce_plaintext(plain)
            if str(body["bd_addr"]).upper() != src:
                return None
            return {
                **body,
                "src": src,
                "seq": seq,
                "ts_ms": ts_ms,
            }
        except InvalidTag:
            continue
        except ValueError:
            return None
    return None


if __name__ == "__main__":
    import os

    gk = os.urandom(32)
    wrong = os.urandom(32)
    bd = "40:D9:5A:8B:69:3F"
    pub = os.urandom(X25519_PUBLIC_KEY_SIZE)
    pkt = build_announce(gk, bd, seq=1, ts_ms=1_700_000_000_000, epoch=3, public_key=pub, ttl=10)
    out = parse_announce(pkt, [gk])
    assert out is not None
    assert out["bd_addr"] == bd.upper()
    assert out["epoch"] == 3
    assert out["public_key"] == pub
    assert parse_announce(pkt, [wrong]) is None
    print("✅ announce.py self-test passed")
