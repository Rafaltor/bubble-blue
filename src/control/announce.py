"""
PKT_ANNOUNCE — network-wide (bd_addr → X25519 + Ed25519) binding under group key.

Complements Hello private parts (2-hop limited): silent or multi-hop members
learn peer pubkeys so pairwise keys and rekey floods can reach them.

v0x02 plaintext is Ed25519-signed (PoP of the announced signing key).
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
from src.security.signing import ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE

_ANNOUNCE_VERSION = 0x02
# version(1) | bd_addr(6) | epoch(u32) | x25519(32) | ed25519(32) | sig(64)
_ANNOUNCE_BODY = struct.Struct("!B6sL32s32s")
_ANNOUNCE_SIGNED_SIZE = _ANNOUNCE_BODY.size  # without signature
_ANNOUNCE_PLAINTEXT_SIZE = _ANNOUNCE_SIGNED_SIZE + ED25519_SIGNATURE_SIZE


def announce_signed_message(
    local_bd_addr: str,
    epoch: int,
    public_key: bytes,
    signing_public_key: bytes,
) -> bytes:
    """Bytes covered by the Ed25519 signature (everything except the signature)."""
    if len(public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"public_key must be {X25519_PUBLIC_KEY_SIZE} bytes (got {len(public_key)})"
        )
    if len(signing_public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"signing_public_key must be {ED25519_PUBLIC_KEY_SIZE} bytes "
            f"(got {len(signing_public_key)})"
        )
    if not (0 <= int(epoch) <= 0xFFFFFFFF):
        raise ValueError("epoch must fit in uint32")
    return _ANNOUNCE_BODY.pack(
        _ANNOUNCE_VERSION,
        bd_addr_to_bytes(local_bd_addr),
        int(epoch),
        bytes(public_key),
        bytes(signing_public_key),
    )


def pack_announce_plaintext(
    local_bd_addr: str,
    epoch: int,
    public_key: bytes,
    signing_public_key: bytes,
    signature: bytes,
) -> bytes:
    """
    Pack signed announce plaintext (v0x02).

    Layout: version | bd_addr | epoch | x25519_pub | ed25519_pub | signature.
    """
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise ValueError(f"signature must be {ED25519_SIGNATURE_SIZE} bytes")
    return announce_signed_message(
        local_bd_addr, epoch, public_key, signing_public_key
    ) + bytes(signature)


def unpack_announce_plaintext(data: bytes) -> dict[str, Any]:
    """Parse announce plaintext; raises ValueError if truncated or unknown version."""
    if len(data) != _ANNOUNCE_PLAINTEXT_SIZE:
        raise ValueError(
            f"announce plaintext unexpected length {len(data)} "
            f"(expected {_ANNOUNCE_PLAINTEXT_SIZE})"
        )

    version, bd_b, epoch, public_key, signing_public_key = _ANNOUNCE_BODY.unpack_from(data, 0)
    if version != _ANNOUNCE_VERSION:
        raise ValueError(f"unsupported announce version: 0x{version:02X}")
    signature = data[_ANNOUNCE_SIGNED_SIZE:]
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise ValueError("truncated announce signature")

    return {
        "bd_addr": bytes_to_bd_addr(bd_b),
        "epoch": int(epoch),
        "public_key": bytes(public_key),
        "signing_public_key": bytes(signing_public_key),
        "signature": bytes(signature),
        "signed_message": bytes(data[:_ANNOUNCE_SIGNED_SIZE]),
    }


def build_announce(
    group_key: bytes,
    local_bd_addr: str,
    seq: int,
    ts_ms: int | None,
    epoch: int,
    public_key: bytes,
    ttl: int,
    *,
    signing_public_key: bytes,
    signature: bytes,
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
    plaintext = pack_announce_plaintext(
        src, epoch, public_key, signing_public_key, signature
    )
    packet_key = derive_packet_key(group_key, src, seq, int(ts_ms))
    enc = encrypt_with_key(packet_key, plaintext, routing_header_aad(rh))
    return build_bb_packet(rh, enc["ciphertext"])


def parse_announce(packet: bytes, group_keys: list[bytes]) -> dict[str, Any] | None:
    """
    Decrypt and parse PKT_ANNOUNCE trying each group key in order.

    Returns dict with bd_addr, epoch, public_key, signing_public_key, signature,
    signed_message (plus src/seq/ts_ms from header), or None on failure.
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

    from src.security.keys import BBKeyStore

    gk = os.urandom(32)
    wrong = os.urandom(32)
    bd = "40:D9:5A:8B:69:3F"
    store = BBKeyStore.from_group_key(gk, bd)
    msg = announce_signed_message(
        bd, 3, store.local_public_key, store.local_signing_public_key
    )
    sig = store.sign(msg)
    pkt = build_announce(
        gk,
        bd,
        seq=1,
        ts_ms=1_700_000_000_000,
        epoch=3,
        public_key=store.local_public_key,
        ttl=10,
        signing_public_key=store.local_signing_public_key,
        signature=sig,
    )
    out = parse_announce(pkt, [gk])
    assert out is not None
    assert out["bd_addr"] == bd.upper()
    assert out["epoch"] == 3
    assert out["public_key"] == store.local_public_key
    assert out["signing_public_key"] == store.local_signing_public_key
    assert parse_announce(pkt, [wrong]) is None
    print("✅ announce.py self-test passed")
