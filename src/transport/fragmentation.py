"""
Optional BB wire fragmentation / reassembly (transport-agnostic).

Used only when a payload exceeds ``max_payload(transport_kind)`` (multimedia) or
when the negotiated L2CAP/CoC MTU is smaller than expected. **Normal chat and
control traffic (≤ max_payload, e.g. 470 B on BLE) is never fragmented.**

Wire layout per fragment (7-byte header + chunk):

    FRAG_MARKER (1 B) | msg_id (uint16 BE) | frag_index (uint16 BE) |
    frag_total (uint16 BE) | chunk

``FRAG_MARKER`` (0xFB) is distinct from all ``PKT_*`` types in ``config.py``.
``fragment()`` prepends this header; ``Reassembler.push()`` strips it and
reassembles in-order by ``frag_index`` regardless of arrival order.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Callable

from config import PKT_ACK, PKT_DATA, PKT_HELLO, PKT_REKEY, PKT_SUBGROUP

FRAG_MARKER = 0xFB
_FRAGMENT_FIELDS = struct.Struct("!HHH")
HEADER_SIZE = 1 + _FRAGMENT_FIELDS.size  # 7

_PKT_TYPES = (PKT_HELLO, PKT_DATA, PKT_ACK, PKT_SUBGROUP, PKT_REKEY)
if FRAG_MARKER in _PKT_TYPES:
    raise RuntimeError(f"FRAG_MARKER 0x{FRAG_MARKER:02X} collides with a PKT_* type")

_MAX_FRAG_TOTAL = 4096


def _encode_header(msg_id: int, frag_index: int, frag_total: int) -> bytes:
    return bytes([FRAG_MARKER]) + _FRAGMENT_FIELDS.pack(
        msg_id & 0xFFFF, frag_index & 0xFFFF, frag_total & 0xFFFF
    )


def _decode_header(fragment: bytes) -> tuple[int, int, int]:
    if len(fragment) < HEADER_SIZE:
        raise ValueError(f"fragment too short: {len(fragment)} < {HEADER_SIZE}")
    if fragment[0] != FRAG_MARKER:
        raise ValueError(f"missing FRAG_MARKER (got 0x{fragment[0]:02X})")
    msg_id, frag_index, frag_total = _FRAGMENT_FIELDS.unpack_from(fragment, 1)
    return int(msg_id), int(frag_index), int(frag_total)


def _header_valid(msg_id: int, frag_index: int, frag_total: int) -> bool:
    _ = msg_id
    if frag_total < 1 or frag_total > _MAX_FRAG_TOTAL:
        return False
    return frag_index < frag_total


def is_fragment_packet(data: bytes) -> bool:
    """True iff ``data`` starts with ``FRAG_MARKER`` and carries a valid header."""
    if len(data) < HEADER_SIZE or data[0] != FRAG_MARKER:
        return False
    try:
        msg_id, frag_index, frag_total = _decode_header(data)
    except ValueError:
        return False
    return _header_valid(msg_id, frag_index, frag_total)


def fragment(data: bytes, max_fragment_size: int, msg_id: int) -> list[bytes]:
    """
    Split ``data`` into fragments that each fit in ``max_fragment_size`` bytes.

    Chunk capacity per fragment is ``max_fragment_size - HEADER_SIZE``. If
    ``data`` already fits, returns a single fragment with ``frag_total=1``.
    """
    if max_fragment_size <= HEADER_SIZE:
        raise ValueError(f"max_fragment_size must be > {HEADER_SIZE}")
    payload = bytes(data)
    chunk_cap = max_fragment_size - HEADER_SIZE
    mid = msg_id & 0xFFFF

    if len(payload) <= chunk_cap:
        return [_encode_header(mid, 0, 1) + payload]

    chunks: list[bytes] = []
    off = 0
    while off < len(payload):
        chunks.append(payload[off : off + chunk_cap])
        off += chunk_cap

    total = len(chunks)
    if total > 0xFFFF:
        raise ValueError(f"too many fragments: {total} (frag_total is uint16)")

    return [
        _encode_header(mid, idx, total) + chunk
        for idx, chunk in enumerate(chunks)
    ]


@dataclass
class _PendingMessage:
    frag_total: int
    parts: dict[int, bytes] = field(default_factory=dict)
    last_seen: float = 0.0


class Reassembler:
    """
    Incremental fragment collector keyed by ``msg_id`` (uint16, wraps naturally).

    - Out-of-order delivery: OK.
    - Duplicate ``frag_index`` for the same ``msg_id``: ignored.
    - Conflicting ``frag_total`` for the same ``msg_id``: fragment rejected.
    - ``timeout_s`` / ``max_pending`` bound memory; stale partial messages are dropped.
    """

    def __init__(
        self,
        *,
        timeout_s: float = 30.0,
        max_pending: int = 32,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if max_pending < 1:
            raise ValueError("max_pending must be >= 1")
        self._timeout_s = float(timeout_s)
        self._max_pending = int(max_pending)
        self._clock = clock or time.monotonic
        self._pending: dict[int, _PendingMessage] = {}

    def push(self, fragment: bytes) -> bytes | None:
        """
        Ingest one fragment. Returns the full message when complete, else ``None``.
        """
        now = self._clock()
        self._purge_expired(now)

        try:
            msg_id, frag_index, frag_total = _decode_header(fragment)
        except ValueError:
            return None
        if not _header_valid(msg_id, frag_index, frag_total):
            return None

        chunk = fragment[HEADER_SIZE:]
        pending = self._pending.get(msg_id)

        if pending is None:
            if len(self._pending) >= self._max_pending:
                self._evict_oldest(now)
            pending = _PendingMessage(frag_total=frag_total, last_seen=now)
            self._pending[msg_id] = pending
        elif pending.frag_total != frag_total:
            return None
        else:
            pending.last_seen = now

        if frag_index in pending.parts:
            return None

        pending.parts[frag_index] = chunk
        if len(pending.parts) != frag_total:
            return None

        message = b"".join(pending.parts[i] for i in range(frag_total))
        del self._pending[msg_id]
        return message

    def pending_count(self) -> int:
        """Number of incomplete messages currently buffered."""
        return len(self._pending)

    def purge_expired(self) -> int:
        """Drop partial messages older than ``timeout_s``. Returns count removed."""
        now = self._clock()
        before = len(self._pending)
        self._purge_expired(now)
        return before - len(self._pending)

    def _purge_expired(self, now: float) -> None:
        stale = [
            mid
            for mid, p in self._pending.items()
            if (now - p.last_seen) > self._timeout_s
        ]
        for mid in stale:
            del self._pending[mid]

    def _evict_oldest(self, now: float) -> None:
        if not self._pending:
            return
        oldest_id = min(self._pending, key=lambda mid: self._pending[mid].last_seen)
        del self._pending[oldest_id]
        _ = now
