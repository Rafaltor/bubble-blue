from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import PKT_HELLO
from src.security.crypto import AES_KEY_SIZE, AES_NONCE_SIZE
from src.security.packet import bd_addr_to_bytes, bytes_to_bd_addr

ANON_ID_SIZE = 8
X25519_PUBLIC_KEY_SIZE = 32
_PRIVATE_HELLO_VERSION = 0x01
_PRIVATE_HELLO_VERSION_EPOCH = 0x02

# Public Hello prefix: type | anon_id | seq | ts_ms | n_neighbors
_HELLO_PUBLIC_PREFIX = struct.Struct("!B8sLQB")


def compute_anon_id(group_key: bytes, bd_addr: str) -> bytes:
    """Return 8-byte anonymous ID: HMAC-SHA256(group_key, bd_addr)[:8]."""
    if len(group_key) != AES_KEY_SIZE:
        raise ValueError(f"group_key must be {AES_KEY_SIZE} bytes (got {len(group_key)})")
    addr_b = bd_addr_to_bytes(bd_addr)
    digest = hmac.new(group_key, addr_b, hashlib.sha256).digest()
    return digest[:ANON_ID_SIZE]


def _pack_private_plaintext(
    local_bd_addr: str,
    neighbor_bd_addrs: list[str],
    local_public_key: bytes,
    *,
    epoch: int = 0,
) -> bytes:
    """
    Private Hello plaintext v0x02 (encrypted under current group_key).

    Layout: version | local_bd | n_neighbors | neighbors | epoch (uint32) | x25519_pub.
    """
    if len(local_public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"local_public_key must be {X25519_PUBLIC_KEY_SIZE} bytes "
            f"(got {len(local_public_key)})"
        )
    if not (0 <= int(epoch) <= 0xFFFFFFFF):
        raise ValueError("epoch must fit in uint32")
    neighbors = list(neighbor_bd_addrs)
    if len(neighbors) > 255:
        raise ValueError("too many private neighbors (max 255)")
    out = struct.pack(
        "!B6sB",
        _PRIVATE_HELLO_VERSION_EPOCH,
        bd_addr_to_bytes(local_bd_addr),
        len(neighbors),
    )
    for addr in neighbors:
        out += bd_addr_to_bytes(addr)
    out += struct.pack("!L", int(epoch))
    out += bytes(local_public_key)
    return out


def _unpack_private_plaintext(data: bytes) -> dict[str, Any]:
    """
    Parse private Hello plaintext (version 0x01 or 0x02).

    Returns bd_addr, neighbor_bd_addrs, public_key, and epoch (0 for v0x01).
    """
    min_len = 1 + 6 + 1 + X25519_PUBLIC_KEY_SIZE
    if len(data) < min_len:
        raise ValueError("private hello plaintext too short")

    version, local_b, n = struct.unpack_from("!B6sB", data, 0)
    if version not in (_PRIVATE_HELLO_VERSION, _PRIVATE_HELLO_VERSION_EPOCH):
        raise ValueError(f"unsupported private hello version: 0x{version:02X}")

    off = 1 + 6 + 1
    need_neighbors = off + int(n) * 6
    if version == _PRIVATE_HELLO_VERSION_EPOCH:
        need = need_neighbors + 4 + X25519_PUBLIC_KEY_SIZE
    else:
        need = need_neighbors + X25519_PUBLIC_KEY_SIZE
    if len(data) < need:
        raise ValueError("truncated private hello plaintext")

    neighbors: list[str] = []
    for _ in range(int(n)):
        neighbors.append(bytes_to_bd_addr(data[off : off + 6]))
        off += 6

    epoch = 0
    if version == _PRIVATE_HELLO_VERSION_EPOCH:
        epoch, = struct.unpack_from("!L", data, off)
        off += 4

    public_key = data[off : off + X25519_PUBLIC_KEY_SIZE]
    if len(public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError("truncated X25519 public key in private hello")

    return {
        "bd_addr": bytes_to_bd_addr(local_b),
        "neighbor_bd_addrs": neighbors,
        "public_key": bytes(public_key),
        "epoch": int(epoch),
    }


def _encrypt_private(group_key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM with nonce prepended: nonce(12) + ciphertext + tag(16)."""
    aesgcm = AESGCM(group_key)
    nonce = os.urandom(AES_NONCE_SIZE)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext_with_tag


def _decrypt_private(group_key: bytes, encrypted: bytes, aad: bytes) -> bytes:
    if len(encrypted) < AES_NONCE_SIZE + 16:
        raise ValueError("encrypted private part too short")
    nonce = encrypted[:AES_NONCE_SIZE]
    ciphertext_with_tag = encrypted[AES_NONCE_SIZE:]
    aesgcm = AESGCM(group_key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


def build_hello(
    group_key: bytes,
    local_bd_addr: str,
    seq: int,
    known_neighbors: list[str],
    local_public_key: bytes,
    *,
    ts_ms: int | None = None,
    epoch: int = 0,
    anon_id_key: bytes | None = None,
) -> bytes:
    """
    Build a BB Hello packet (public cleartext + group-encrypted private part).

    ``group_key``: current epoch group key (encrypts the private part).
    ``anon_id_key``: bootstrap PSK for stable ``anon_id`` (defaults to ``group_key``).
    ``epoch``: monotonic group epoch advertised in the private part (gossip trigger).
    """
    if not (0 <= int(seq) <= 0xFFFFFFFF):
        raise ValueError("seq must fit in uint32")

    if ts_ms is None:
        ts_ms = time.time_ns() // 1_000_000

    aid_key = anon_id_key if anon_id_key is not None else group_key
    anon_id = compute_anon_id(aid_key, local_bd_addr)
    neighbor_anon_ids = [compute_anon_id(aid_key, n) for n in known_neighbors]
    n_pub = len(neighbor_anon_ids)
    if n_pub > 255:
        raise ValueError("too many public neighbors (max 255)")

    # Public (cleartext) part — usable by any node for CDS construction.
    public = _HELLO_PUBLIC_PREFIX.pack(PKT_HELLO, anon_id, int(seq), int(ts_ms), n_pub)
    for aid in neighbor_anon_ids:
        public += aid

    # Private part — BD addresses + X25519 pubkey; visible only to group members.
    priv_plain = _pack_private_plaintext(
        local_bd_addr, known_neighbors, local_public_key, epoch=int(epoch)
    )
    private_enc = _encrypt_private(group_key, priv_plain, aad=public)
    if len(private_enc) > 0xFFFF:
        raise ValueError("private hello part too large")

    return public + struct.pack("!H", len(private_enc)) + private_enc


def parse_hello_public(data: bytes) -> dict[str, Any]:
    """
    Parse Hello public fields (no group key required).

    Returns dict with:
      type, anon_id, seq, ts_ms, neighbor_anon_ids,
      private_part_len, private_part, public_aad
    """
    min_prefix = _HELLO_PUBLIC_PREFIX.size  # 22 bytes
    if len(data) < min_prefix + 2:
        raise ValueError("hello packet too short")

    pkt_type, anon_id, seq, ts_ms, n_pub = _HELLO_PUBLIC_PREFIX.unpack_from(data, 0)
    if pkt_type != PKT_HELLO:
        raise ValueError(f"not a HELLO packet (type=0x{pkt_type:02X})")

    off = min_prefix
    need_neighbors = off + int(n_pub) * ANON_ID_SIZE
    if len(data) < need_neighbors + 2:
        raise ValueError("truncated hello public neighbor list")

    neighbor_anon_ids: list[bytes] = []
    for _ in range(int(n_pub)):
        neighbor_anon_ids.append(data[off : off + ANON_ID_SIZE])
        off += ANON_ID_SIZE

    public_aad = data[:off]
    private_part_len, = struct.unpack_from("!H", data, off)
    off += 2
    if len(data) < off + private_part_len:
        raise ValueError("truncated hello private part")

    private_part = data[off : off + private_part_len]

    return {
        "type": pkt_type,
        "anon_id": anon_id,
        "seq": seq,
        "ts_ms": ts_ms,
        "neighbor_anon_ids": neighbor_anon_ids,
        "private_part_len": private_part_len,
        "private_part": private_part,
        "public_aad": public_aad,
    }


def parse_hello_private(data: bytes, group_key: bytes) -> dict[str, Any] | None:
    """
    Decrypt Hello private part for group members.

    Returns None if ``group_key`` is wrong (not a group member).
    On success, includes ``public_key`` (32-byte X25519) from the private plaintext.
    """
    try:
        pub = parse_hello_public(data)
        plaintext = _decrypt_private(group_key, pub["private_part"], pub["public_aad"])
        priv = _unpack_private_plaintext(plaintext)
        return {
            "anon_id": pub["anon_id"],
            "seq": pub["seq"],
            "ts_ms": pub["ts_ms"],
            "neighbor_anon_ids": pub["neighbor_anon_ids"],
            "epoch": priv.get("epoch", 0),
            **priv,
        }
    except InvalidTag:
        return None


if __name__ == "__main__":
    group_key = os.urandom(32)
    wrong_key = os.urandom(32)
    local = "40:D9:5A:8B:69:3F"
    n1 = "14:B5:CD:E2:49:ED"
    n2 = "00:11:22:33:44:55"

    aid_local = compute_anon_id(group_key, local)
    assert len(aid_local) == 8
    assert compute_anon_id(group_key, local) == aid_local
    print("✅ compute_anon_id: OK")

    local_pubkey = os.urandom(X25519_PUBLIC_KEY_SIZE)
    pkt = build_hello(group_key, local, seq=7, known_neighbors=[n1, n2], local_public_key=local_pubkey)
    pub = parse_hello_public(pkt)
    assert pub["seq"] == 7
    assert len(pub["neighbor_anon_ids"]) == 2
    assert pub["neighbor_anon_ids"][0] == compute_anon_id(group_key, n1)
    print("✅ parse_hello_public: OK")

    priv = parse_hello_private(pkt, group_key)
    assert priv is not None
    assert priv["bd_addr"] == local.upper()
    assert priv["neighbor_bd_addrs"] == [n1.upper(), n2.upper()]
    assert priv["public_key"] == local_pubkey
    print("✅ parse_hello_private (member): OK")

    assert parse_hello_private(pkt, wrong_key) is None
    print("✅ parse_hello_private (non-member): OK")

    print("\n✅ All Hello self-tests passed")
