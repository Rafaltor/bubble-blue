"""
ARQ (Automatic Repeat reQuest) per Blue_Bubble_specs.pdf §2.3.2 / §2.4.3.

Detect sequence gaps per originator, flood ARQ(originator, seq), and let the
originator or a CDS node that cached the DATA retransmit it.
"""

from __future__ import annotations

import struct
import threading
import time

from config import ARQ_CACHE_MAX, ARQ_CACHE_TTL_S
from src.security.packet import bd_addr_to_bytes, bytes_to_bd_addr

# Cleartext ARQ body after routing header: requested_src(6) | requested_seq(4)
ARQ_BODY_STRUCT = struct.Struct("!6sL")
ARQ_BODY_SIZE = ARQ_BODY_STRUCT.size


def build_arq_body(requested_src: str, requested_seq: int) -> bytes:
    return ARQ_BODY_STRUCT.pack(bd_addr_to_bytes(requested_src), int(requested_seq) & 0xFFFFFFFF)


def parse_arq_body(body: bytes) -> tuple[str, int]:
    if len(body) < ARQ_BODY_SIZE:
        raise ValueError("ARQ body too short")
    src_b, seq = ARQ_BODY_STRUCT.unpack_from(body, 0)
    return bytes_to_bd_addr(src_b), int(seq)


class ArqEngine:
    """
    Per-originator seq tracking + bounded DATA wire cache for CDS replay.
    """

    def __init__(
        self,
        *,
        cache_ttl_s: float = ARQ_CACHE_TTL_S,
        cache_max: int = ARQ_CACHE_MAX,
    ) -> None:
        self._ttl_s = float(cache_ttl_s)
        self._max = int(cache_max)
        self._lock = threading.RLock()
        # originator -> set of received seqs (recent window)
        self._seen: dict[str, set[int]] = {}
        # originator -> highest contiguous seq observed from 1..high
        self._contig: dict[str, int] = {}
        # (originator, seq) -> (wire_bytes, monotonic_ts)
        self._cache: dict[tuple[str, int], tuple[bytes, float]] = {}
        # (originator, seq) -> last ARQ send monotonic (dedupe)
        self._arq_sent_at: dict[tuple[str, int], float] = {}

    def store_packet(self, originator: str, seq: int, wire: bytes) -> None:
        """Cache a DATA wire frame for possible ARQ replay (CDS / originator)."""
        key = (originator.upper(), int(seq))
        with self._lock:
            self._evict_cache_locked()
            self._cache[key] = (bytes(wire), time.monotonic())

    def get_packet(self, originator: str, seq: int) -> bytes | None:
        key = (originator.upper(), int(seq))
        with self._lock:
            self._evict_cache_locked()
            hit = self._cache.get(key)
            return None if hit is None else hit[0]

    def note_received(self, originator: str, seq: int) -> list[int]:
        """
        Record ``seq`` from ``originator``.

        Returns missing sequence numbers strictly between the contiguous high-water
        mark and ``seq`` (preprint §2.3.2). The first packet from an originator
        sets the baseline (no ARQ for unseen history before join).
        """
        src = originator.upper()
        s = int(seq)
        if s <= 0:
            return []
        with self._lock:
            seen = self._seen.setdefault(src, set())
            if src not in self._contig:
                # First observation from this originator: adopt seq as baseline.
                seen.add(s)
                self._contig[src] = s
                return []
            seen.add(s)
            max_seen = max(seen)
            if len(seen) > 512:
                seen = {x for x in seen if x > max_seen - 256}
                self._seen[src] = seen
            contig = self._contig.get(src, 0)
            while (contig + 1) in seen:
                contig += 1
            self._contig[src] = contig
            if s <= contig + 1:
                return []
            missing = [m for m in range(contig + 1, s) if m not in seen]
            return missing

    def should_emit_arq(self, originator: str, seq: int, *, min_interval_s: float = 1.0) -> bool:
        """True if we should flood an ARQ for this gap (rate-limited)."""
        key = (originator.upper(), int(seq))
        now = time.monotonic()
        with self._lock:
            last = self._arq_sent_at.get(key, 0.0)
            if now - last < min_interval_s:
                return False
            self._arq_sent_at[key] = now
            return True

    def _evict_cache_locked(self) -> None:
        now = time.monotonic()
        stale = [k for k, (_w, ts) in self._cache.items() if now - ts > self._ttl_s]
        for k in stale:
            del self._cache[k]
        if len(self._cache) > self._max:
            oldest = sorted(self._cache.items(), key=lambda item: item[1][1])
            for k, _ in oldest[: max(1, len(self._cache) - self._max)]:
                del self._cache[k]
