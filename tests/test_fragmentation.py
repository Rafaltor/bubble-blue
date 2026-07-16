from __future__ import annotations

import os
import random
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import (  # noqa: E402
    PKT_ACK,
    PKT_ANNOUNCE,
    PKT_DATA,
    PKT_HELLO,
    PKT_REKEY,
    PKT_REKEY_FLOOD,
    PKT_SUBGROUP,
)
from src.transport.fragmentation import (  # noqa: E402
    FRAG_MARKER,
    HEADER_SIZE,
    Reassembler,
    fragment,
    is_fragment_packet,
)


def _reassemble_all(frags: list[bytes], *, reassembler: Reassembler | None = None) -> bytes:
    r = reassembler or Reassembler()
    out: bytes | None = None
    for frag in frags:
        hit = r.push(frag)
        if hit is not None:
            if out is not None:
                raise AssertionError("unexpected second complete message")
            out = hit
    if out is None:
        raise AssertionError("message never completed")
    return out


def test_round_trip_1000_bytes() -> None:
    data = bytes((i * 7 + 13) % 256 for i in range(1000))
    max_size = 244
    frags = fragment(data, max_size, msg_id=42)
    chunk_cap = max_size - HEADER_SIZE
    expected_n = (len(data) + chunk_cap - 1) // chunk_cap
    assert len(frags) == expected_n
    assert all(f[0] == FRAG_MARKER for f in frags)
    assert _reassemble_all(frags) == data
    print(f"✅ round-trip 1000 B @ max={max_size} → {len(frags)} fragments (7 B header)")


def test_single_fragment_small_message() -> None:
    data = b"chat fits in one frame"
    frags = fragment(data, 244, msg_id=1)
    assert len(frags) == 1
    mid, idx, total = _decode(frags[0])
    assert (mid, idx, total) == (1, 0, 1)
    assert _reassemble_all(frags) == data
    print("✅ small message → single fragment (frag_total=1)")


def test_out_of_order() -> None:
    data = b"x" * 500
    frags = fragment(data, 244, msg_id=7)
    shuffled = frags[:]
    random.Random(0).shuffle(shuffled)
    assert _reassemble_all(shuffled) == data
    print("✅ out-of-order fragments reassemble correctly")


def test_duplicate_ignored() -> None:
    data = b"y" * 300
    frags = fragment(data, 244, msg_id=9)
    assert len(frags) >= 2
    r = Reassembler()
    assert r.push(frags[0]) is None
    assert r.push(frags[0]) is None
    assert r.push(frags[1]) == data
    print("✅ duplicate fragment index ignored")


def test_two_interleaved_messages() -> None:
    a = b"A" * 400
    b = b"B" * 350
    fa = fragment(a, 244, msg_id=100)
    fb = fragment(b, 244, msg_id=200)
    interleaved: list[bytes] = []
    for pair in zip(fa, fb):
        interleaved.extend(pair)
    interleaved.extend(fa[len(fb) :])
    interleaved.extend(fb[len(fa) :])
    r = Reassembler()
    got: list[bytes] = []
    for frag_wire in interleaved:
        hit = r.push(frag_wire)
        if hit is not None:
            got.append(hit)
    assert sorted(got) == sorted([a, b])
    print("✅ two interleaved msg_id streams both complete")


def test_missing_fragment_expires() -> None:
    data = b"z" * 400
    frags = fragment(data, 244, msg_id=50)
    t = [0.0]

    def clock() -> float:
        return t[0]

    r = Reassembler(timeout_s=1.0, max_pending=8, clock=clock)
    for f in frags[:-1]:
        assert r.push(f) is None
    assert r.pending_count() == 1

    t[0] = 2.0
    assert r.purge_expired() == 1
    assert r.pending_count() == 0
    assert r.push(frags[-1]) is None
    print("✅ missing fragment never completes; stale entry expires")


def test_inconsistent_frag_total_rejected() -> None:
    data = b"m" * 300
    frags = fragment(data, 244, msg_id=3)
    r = Reassembler()
    assert r.push(frags[0]) is None
    bad = bytearray(frags[1])
    bad[6] = 99  # frag_total low byte (offset 5–6)
    assert r.push(bytes(bad)) is None
    assert r.push(frags[1]) == data
    print("✅ inconsistent frag_total does not assemble")


def _decode(fragment_wire: bytes) -> tuple[int, int, int]:
    from src.transport.fragmentation import _decode_header

    return _decode_header(fragment_wire)


def test_anti_collision_fragment_marker() -> None:
    """BB direct wires (PKT_* at byte 0) must never be mistaken for fragments."""
    for pkt_type in (
        PKT_HELLO,
        PKT_DATA,
        PKT_ACK,
        PKT_SUBGROUP,
        PKT_REKEY,
        PKT_ANNOUNCE,
        PKT_REKEY_FLOOD,
    ):
        wire = bytes([pkt_type]) + b"\x00" * 30
        assert not is_fragment_packet(wire), f"PKT 0x{pkt_type:02X} wire misclassified"

    # msg_id high byte 0x02 would have looked like PKT_DATA (0x02) under old heuristic.
    colliding_msg_id = 0x0200
    frags = fragment(b"x" * 300, 244, msg_id=colliding_msg_id)
    assert frags[0][0] == FRAG_MARKER
    assert frags[0][1] == 0x02  # msg_id BE high byte
    assert is_fragment_packet(frags[0])
    assert _reassemble_all(frags) == b"x" * 300

    assert not is_fragment_packet(frags[0][:6])
    print("✅ FRAG_MARKER anti-collision: PKT_* never fragments; msg_id 0x0200 OK")


if __name__ == "__main__":
    test_round_trip_1000_bytes()
    test_single_fragment_small_message()
    test_out_of_order()
    test_duplicate_ignored()
    test_two_interleaved_messages()
    test_missing_fragment_expires()
    test_inconsistent_frag_total_rejected()
    test_anti_collision_fragment_marker()
    print("\n✅ fragmentation tests passed (no hardware)")
