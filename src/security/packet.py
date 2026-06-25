from __future__ import annotations

import hashlib
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


# =============================================================================
# PKT_SUBGROUP — à la carte multicast (subset S of group members)
# =============================================================================
#
# One message to an arbitrary subset S with O(|S|) wire overhead on that message
# only (vs permanent 16·n multi-key header). Relays flood like PKT_DATA when
# dst = BROADCAST_BD_ADDR and type = PKT_SUBGROUP (0x04).
#
# Wire layout:
#   [ routing_header (26 B) | n_cases (1 B) | cases[n_cases] | ciphertext ]
#
# routing_header: same 26-byte cleartext header as PKT_DATA; type = PKT_SUBGROUP,
#   dst typically FF:FF:FF:FF:FF:FF so CDS relays forward opaque.
#
# n_cases: uint8 count of recipients in S (1..255).
#
# Each case (56 B fixed):
#   recipient_tag (8 B)  — first 8 bytes of recipient anon_id (locate own case)
#   wrapped_key   (32 B) — per-recipient key material (e.g. encrypted session key)
#   wrap_tag      (16 B) — GCM tag authenticating wrapped_key under group/wrap key
#
# ciphertext: AES-256-GCM of plaintext (includes 16 B GCM tag at end).
#   AAD should bind routing header (TTL zeroed) + subgroup_cases_digest(cases).
#
# Fixed overhead (excluding plaintext): 26 + 1 + 56·n_cases + 16 bytes
# =============================================================================

SUBGROUP_CASE_TAG_SIZE = 8
SUBGROUP_WRAPPED_KEY_SIZE = 32
SUBGROUP_WRAP_TAG_SIZE = 16
SUBGROUP_CASE_BLOB_SIZE = SUBGROUP_WRAPPED_KEY_SIZE + SUBGROUP_WRAP_TAG_SIZE  # 48
SUBGROUP_CASE_SIZE = SUBGROUP_CASE_TAG_SIZE + SUBGROUP_CASE_BLOB_SIZE  # 56
SUBGROUP_N_CASES_MAX = 255
SUBGROUP_N_CASES_MIN = 1


def subgroup_overhead(n_cases: int) -> int:
    """Fixed wire overhead for PKT_SUBGROUP: 26 + 1 + 56·n_cases + 16."""
    n = int(n_cases)
    if not (SUBGROUP_N_CASES_MIN <= n <= SUBGROUP_N_CASES_MAX):
        raise ValueError(f"n_cases must be in [{SUBGROUP_N_CASES_MIN}, {SUBGROUP_N_CASES_MAX}] (got {n})")
    return ROUTING_HEADER_SIZE + 1 + (SUBGROUP_CASE_SIZE * n) + GCM_TAG_SIZE


def subgroup_cases_digest(cases: list[tuple[bytes, bytes]]) -> bytes:
    """
    SHA-256 over concatenated cases (recipient_tag ‖ wrapped_blob) in order.

    Used as part of AES-GCM AAD to bind the case header to the payload ciphertext.
    """
    h = hashlib.sha256()
    for tag, blob in cases:
        if len(tag) != SUBGROUP_CASE_TAG_SIZE:
            raise ValueError(f"recipient_tag must be {SUBGROUP_CASE_TAG_SIZE} bytes (got {len(tag)})")
        if len(blob) != SUBGROUP_CASE_BLOB_SIZE:
            raise ValueError(f"wrapped_blob must be {SUBGROUP_CASE_BLOB_SIZE} bytes (got {len(blob)})")
        h.update(tag)
        h.update(blob)
    return h.digest()


def _validate_subgroup_cases(cases: list[tuple[bytes, bytes]]) -> int:
    n_cases = len(cases)
    if not (SUBGROUP_N_CASES_MIN <= n_cases <= SUBGROUP_N_CASES_MAX):
        raise ValueError(
            f"n_cases must be in [{SUBGROUP_N_CASES_MIN}, {SUBGROUP_N_CASES_MAX}] (got {n_cases})"
        )
    for i, (tag, blob) in enumerate(cases):
        if len(tag) != SUBGROUP_CASE_TAG_SIZE:
            raise ValueError(
                f"cases[{i}].recipient_tag must be {SUBGROUP_CASE_TAG_SIZE} bytes (got {len(tag)})"
            )
        if len(blob) != SUBGROUP_CASE_BLOB_SIZE:
            raise ValueError(
                f"cases[{i}].wrapped_blob must be {SUBGROUP_CASE_BLOB_SIZE} bytes (got {len(blob)})"
            )
    return n_cases


def build_subgroup_packet(
    routing_header: bytes,
    cases: list[tuple[bytes, bytes]],
    ciphertext: bytes,
) -> bytes:
    """
    Assemble a PKT_SUBGROUP wire packet.

    ``cases``: list of (recipient_tag_8B, wrapped_blob_48B) where wrapped_blob is
    32-byte wrapped key + 16-byte GCM wrap tag.
    """
    if len(routing_header) != ROUTING_HEADER_SIZE:
        raise ValueError(f"routing_header must be {ROUTING_HEADER_SIZE} bytes (got {len(routing_header)})")
    if len(ciphertext) < GCM_TAG_SIZE:
        raise ValueError(f"ciphertext must include a {GCM_TAG_SIZE}-byte GCM tag (len >= {GCM_TAG_SIZE})")

    n_cases = _validate_subgroup_cases(cases)

    out = bytearray(routing_header)
    out.append(n_cases)
    for tag, blob in cases:
        out += tag
        out += blob
    out += ciphertext
    return bytes(out)


def parse_subgroup_packet(data: bytes) -> dict[str, Any]:
    """
    Parse a PKT_SUBGROUP wire packet.

    Returns routing_header, parsed_header, n_cases, cases (tag, blob pairs), ciphertext.
    """
    min_len = ROUTING_HEADER_SIZE + 1 + SUBGROUP_CASE_SIZE + GCM_TAG_SIZE
    if len(data) < min_len:
        raise ValueError(f"subgroup packet too short: {len(data)} bytes (min {min_len})")

    routing_header = data[:ROUTING_HEADER_SIZE]
    parsed_header = parse_routing_header(routing_header)
    n_cases = data[ROUTING_HEADER_SIZE]
    if not (SUBGROUP_N_CASES_MIN <= n_cases <= SUBGROUP_N_CASES_MAX):
        raise ValueError(f"invalid n_cases: {n_cases}")

    cases_start = ROUTING_HEADER_SIZE + 1
    cases_end = cases_start + (n_cases * SUBGROUP_CASE_SIZE)
    expected_min = cases_end + GCM_TAG_SIZE
    if len(data) < expected_min:
        raise ValueError(
            f"subgroup packet length inconsistent: {len(data)} bytes "
            f"(expected >= {expected_min} for n_cases={n_cases})"
        )

    cases: list[tuple[bytes, bytes]] = []
    off = cases_start
    for _ in range(n_cases):
        tag = data[off : off + SUBGROUP_CASE_TAG_SIZE]
        off += SUBGROUP_CASE_TAG_SIZE
        blob = data[off : off + SUBGROUP_CASE_BLOB_SIZE]
        off += SUBGROUP_CASE_BLOB_SIZE
        cases.append((tag, blob))

    ciphertext = data[cases_end:]
    if len(ciphertext) < GCM_TAG_SIZE:
        raise ValueError("malformed subgroup packet (missing payload GCM tag)")

    return {
        "routing_header": routing_header,
        "parsed_header": parsed_header,
        "n_cases": n_cases,
        "cases": cases,
        "ciphertext": ciphertext,
    }


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

    # PKT_SUBGROUP
    from config import PKT_SUBGROUP

    tag_a = b"\xaa" * SUBGROUP_CASE_TAG_SIZE
    tag_b = b"\xbb" * SUBGROUP_CASE_TAG_SIZE
    blob_a = bytes(SUBGROUP_CASE_BLOB_SIZE)
    blob_b = bytes([1] * SUBGROUP_CASE_BLOB_SIZE)
    cases = [(tag_a, blob_a), (tag_b, blob_b)]
    digest = subgroup_cases_digest(cases)
    assert len(digest) == 32

    rh_sg = build_routing_header(
        PKT_SUBGROUP, src, BROADCAST_BD_ADDR, ttl=10, seq=99, ts_ms=now_ms
    )
    ct_sg = b"hello" + bytes(GCM_TAG_SIZE)
    sg_pkt = build_subgroup_packet(rh_sg, cases, ct_sg)
    assert len(sg_pkt) == subgroup_overhead(2) + (len(ct_sg) - GCM_TAG_SIZE)
    assert subgroup_overhead(2) == 26 + 1 + 56 * 2 + 16

    sg_parsed = parse_subgroup_packet(sg_pkt)
    assert sg_parsed["n_cases"] == 2
    assert sg_parsed["cases"] == cases
    assert sg_parsed["ciphertext"] == ct_sg
    assert sg_parsed["parsed_header"]["type"] == PKT_SUBGROUP
    assert sg_parsed["parsed_header"]["dst"] == BROADCAST_BD_ADDR

    cases_end = ROUTING_HEADER_SIZE + 1 + SUBGROUP_CASE_SIZE * 2
    try:
        parse_subgroup_packet(sg_pkt[: cases_end + GCM_TAG_SIZE - 1])
        raise AssertionError("expected ValueError for truncated subgroup packet")
    except ValueError:
        pass

    print("✅ PKT_SUBGROUP serialization: OK")
    print(f"   Subgroup overhead (|S|=2): {subgroup_overhead(2)} bytes")
    print(f"   Subgroup overhead (|S|=10): {subgroup_overhead(10)} bytes")
    print("\n✅ All packet self-tests passed (incl. PKT_SUBGROUP)")
