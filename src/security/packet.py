from __future__ import annotations

import re
import struct
import time
from typing import Any

# =============================================================================
# BUBBLE-BLUE wire packet (PKT_DATA payload body)
# =============================================================================
#
#   [ routing_header (26 B) | ciphertext (+ 16 B GCM tag) ]
#
# routing_header (cleartext, relays may decrement TTL on the wire):
#   type (1) | src (6) | dst (6) | ttl (1) | seq (4 BE) | ts_ms (8 BE)  = 26 B
#
# ciphertext:
#   AES-256-GCM output from encrypt_with_key() — plaintext + 16-byte tag.
#   No session_key_enc or nonce on the wire; the per-packet AES key is derived
#   locally via derive_packet_key() (keys.py) from group_key or a pairwise key.
#
# Fixed overhead (excluding plaintext): 26 + 16 = 42 bytes
# =============================================================================

GCM_TAG_SIZE = 16

# ROUTING HEADER (26 bytes, cleartext)
# Layout:
#   [1B]  pkt_type : uint8
#   [6B]  src      : BD addr bytes
#   [6B]  dst      : BD addr bytes
#   [1B]  ttl      : uint8
#   [4B]  seq      : uint32 big-endian
#   [8B]  ts_ms    : uint64 big-endian (Unix timestamp milliseconds)
ROUTING_HEADER_FORMAT = "!B6s6sBLQ"  # big-endian
ROUTING_HEADER_SIZE = 26
# TTL is mutable when relays forward; it must not be part of the AES-GCM AAD.
_ROUTING_HEADER_TTL_OFFSET = 13

BROADCAST_BD_ADDR = "FF:FF:FF:FF:FF:FF"

_ROUTING_HEADER_STRUCT = struct.Struct(ROUTING_HEADER_FORMAT)

_BD_ADDR_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


def bd_addr_to_bytes(addr: str) -> bytes:
    """Convert "40:D9:5A:8B:69:3F" to 6 bytes."""
    a = addr.strip()
    if not _BD_ADDR_RE.match(a):
        raise ValueError(f"Invalid BD address: {addr!r}")
    return bytes.fromhex(a.replace(":", ""))


def bytes_to_bd_addr(b: bytes) -> str:
    """Convert 6 bytes to "40:D9:5A:8B:69:3F"."""
    if len(b) != 6:
        raise ValueError(f"BD address bytes must be 6 bytes (got {len(b)})")
    return ":".join(f"{x:02X}" for x in b)


def validate_timestamp(ts_ms: int, tolerance_s: int = 120) -> bool:
    """
    Returns False if abs(now - ts_ms) > tolerance_s * 1000.
    """
    try:
        ts = int(ts_ms)
        tol = int(tolerance_s)
    except (TypeError, ValueError):
        return False
    if tol < 0:
        return False

    now_ms = time.time_ns() // 1_000_000
    return abs(now_ms - ts) <= (tol * 1000)


def build_routing_header(
    pkt_type: int,
    src: str,
    dst: str,
    ttl: int,
    seq: int,
    ts_ms: int | None = None,
) -> bytes:
    """Pack 26-byte routing header."""
    if not (0 <= pkt_type <= 0xFF):
        raise ValueError("pkt_type must fit in uint8")
    if not (0 <= ttl <= 0xFF):
        raise ValueError("ttl must fit in uint8")
    if not (0 <= seq <= 0xFFFFFFFF):
        raise ValueError("seq must fit in uint32")

    src_b = bd_addr_to_bytes(src)
    dst_b = bd_addr_to_bytes(dst)

    if ts_ms is None:
        ts_ms = time.time_ns() // 1_000_000
    if not (0 <= int(ts_ms) <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("ts_ms must fit in uint64 (milliseconds since Unix epoch)")

    # Pack in network order: type | src(6) | dst(6) | ttl | seq (u32) | ts_ms (u64)
    return _ROUTING_HEADER_STRUCT.pack(pkt_type, src_b, dst_b, ttl, seq, int(ts_ms))


def routing_header_aad(routing_header: bytes) -> bytes:
    """
    AAD for payload AES-GCM: full routing header with TTL zeroed.

    Relays decrement TTL on the wire without breaking decryption at the next hop.
    """
    if len(routing_header) < ROUTING_HEADER_SIZE:
        raise ValueError(
            f"routing header requires {ROUTING_HEADER_SIZE} bytes (got {len(routing_header)})"
        )
    aad = bytearray(routing_header[:ROUTING_HEADER_SIZE])
    aad[_ROUTING_HEADER_TTL_OFFSET] = 0
    return bytes(aad)


def parse_routing_header(data: bytes) -> dict[str, Any]:
    """
    Unpack routing header.
    Returns dict: {type, src, dst, ttl, seq, ts_ms}
    Raises ValueError if data < 26 bytes.
    """
    if len(data) < ROUTING_HEADER_SIZE:
        raise ValueError(f"routing header requires {ROUTING_HEADER_SIZE} bytes (got {len(data)})")

    pkt_type, src_b, dst_b, ttl, seq, ts_ms = _ROUTING_HEADER_STRUCT.unpack_from(data, 0)
    return {
        "type": pkt_type,
        "src": bytes_to_bd_addr(src_b),
        "dst": bytes_to_bd_addr(dst_b),
        "ttl": ttl,
        "seq": seq,
        "ts_ms": ts_ms,
    }


def build_bb_packet(routing_header: bytes, ciphertext: bytes) -> bytes:
    """
    Assemble a complete BB packet on the wire.

    Layout: ``routing_header`` (26 B) || ``ciphertext`` (payload + 16 B GCM tag).
    """
    if len(routing_header) != ROUTING_HEADER_SIZE:
        raise ValueError(f"routing_header must be {ROUTING_HEADER_SIZE} bytes (got {len(routing_header)})")
    if len(ciphertext) < GCM_TAG_SIZE:
        raise ValueError(f"ciphertext must include a {GCM_TAG_SIZE}-byte GCM tag (len >= {GCM_TAG_SIZE})")

    return routing_header + ciphertext


def parse_bb_packet(data: bytes) -> dict[str, Any]:
    """
    Parse a complete BB packet.

    Returns:
        routing_header: 26-byte cleartext header
        parsed_header:  dict from ``parse_routing_header``
        ciphertext:     AES-GCM ciphertext + tag (variable length, tag included)

    Raises ValueError if the packet is too short or malformed.
    """
    min_len = ROUTING_HEADER_SIZE + GCM_TAG_SIZE
    if len(data) < min_len:
        raise ValueError(f"packet too short: {len(data)} bytes (min {min_len})")

    routing_header = data[:ROUTING_HEADER_SIZE]
    parsed_header = parse_routing_header(routing_header)
    ciphertext = data[ROUTING_HEADER_SIZE:]

    if len(ciphertext) < GCM_TAG_SIZE:
        raise ValueError("malformed packet (missing GCM tag)")

    return {
        "routing_header": routing_header,
        "parsed_header": parsed_header,
        "ciphertext": ciphertext,
    }


def packet_overhead() -> int:
    """Fixed per-packet overhead: routing header (26 B) + GCM tag (16 B) = 42 B."""
    return ROUTING_HEADER_SIZE + GCM_TAG_SIZE


if __name__ == "__main__":
    src = "40:D9:5A:8B:69:3F"
    dst = "14:B5:CD:E2:49:ED"

    rh = build_routing_header(0x02, src, dst, ttl=10, seq=42)
    assert len(rh) == ROUTING_HEADER_SIZE
    assert routing_header_aad(rh)[13] == 0
    parsed: dict[str, Any] = parse_routing_header(rh)
    assert parsed["src"] == src.upper()
    assert parsed["dst"] == dst.upper()
    assert parsed["ttl"] == 10
    assert parsed["seq"] == 42
    assert validate_timestamp(parsed["ts_ms"], tolerance_s=120) is True
    print("✅ routing header: OK")

    now_ms = time.time_ns() // 1_000_000
    assert validate_timestamp(now_ms, tolerance_s=120) is True
    assert validate_timestamp(now_ms - 121_000, tolerance_s=120) is False
    assert validate_timestamp(now_ms + 121_000, tolerance_s=120) is False
    print("✅ timestamp validation: OK")

    ciphertext = bytes(16)  # minimal: empty plaintext + tag placeholder
    packet = build_bb_packet(rh, ciphertext)
    assert len(packet) == ROUTING_HEADER_SIZE + len(ciphertext)
    result: dict[str, Any] = parse_bb_packet(packet)
    assert result["parsed_header"]["seq"] == 42
    assert result["ciphertext"] == ciphertext
    assert "session_key_enc" not in result
    print("✅ full packet serialization: OK")

    assert packet_overhead() == 42
    print(f"\n📦 Packet structure:")
    print(f"   Routing header  : {ROUTING_HEADER_SIZE} bytes (cleartext)")
    print(f"   Ciphertext+tag  : payload + {GCM_TAG_SIZE} bytes")
    print(f"   Fixed overhead  : {packet_overhead()} bytes")
    print(f"   Payload space   : {1021 - packet_overhead()} bytes (BT Classic MTU)")
    print("\n✅ All packet self-tests passed")
