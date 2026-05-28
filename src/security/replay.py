from __future__ import annotations

import threading
from dataclasses import dataclass


WINDOW_SIZE = 256
_WINDOW_MASK = (1 << WINDOW_SIZE) - 1  # 256-bit bitmap mask


@dataclass
class _SenderWindow:
    """
    Sliding window state for one sender.

    - max_seq: highest accepted sequence number so far
    - seen: bitset of size WINDOW_SIZE
        bit 0 corresponds to max_seq (seen or not)
        bit d corresponds to (max_seq - d)
    """

    max_seq: int
    seen: int


class ReplayFilter:
    """
    Sliding-window anti-replay filter.

    Core rules (per sender):
    - Reject if seq already seen
    - Reject if seq is too old (outside the last WINDOW_SIZE accepted seq numbers)
    - Accept out-of-order packets if they fall within the window and not seen yet

    Thread-safe: intended to be called from multiple receiver threads.
    """

    def __init__(self, *, window_size: int = WINDOW_SIZE) -> None:
        if window_size != WINDOW_SIZE:
            # Keep implementation simple/fast: bitmap logic is fixed at 256.
            raise ValueError("Only window_size=256 is supported in this MVP")
        self._lock = threading.RLock()
        self._per_sender: dict[str, _SenderWindow] = {}

    def check_and_update(self, src_addr: str, seq: int) -> bool:
        """
        True = accept, False = reject (replay or too old).
        """
        if seq < 0:
            return False

        src = str(src_addr).upper()

        with self._lock:
            st = self._per_sender.get(src)
            if st is None:
                # First packet from this sender: accept and initialize window.
                self._per_sender[src] = _SenderWindow(max_seq=int(seq), seen=1)
                return True

            max_seq = st.max_seq

            if seq > max_seq:
                # New highest sequence number; slide the window forward.
                shift = int(seq - max_seq)
                if shift >= WINDOW_SIZE:
                    # Jumped ahead beyond the entire window; forget old history.
                    st.seen = 1
                else:
                    st.seen = ((st.seen << shift) & _WINDOW_MASK) | 1
                st.max_seq = int(seq)
                return True

            # seq <= max_seq: check within window
            diff = int(max_seq - seq)
            if diff >= WINDOW_SIZE:
                # Too old (outside sliding window).
                return False

            bit = 1 << diff
            if st.seen & bit:
                # Replay (already accepted).
                return False

            # Mark as seen and accept.
            st.seen |= bit
            return True


if __name__ == "__main__":
    rf = ReplayFilter()
    src = "40:D9:5A:8B:69:3F"

    # Normal increasing sequence
    for s in range(1, 11):
        assert rf.check_and_update(src, s) is True
    print("✅ normal sequence: OK")

    # Replay attack (same seq twice)
    assert rf.check_and_update(src, 5) is False
    print("✅ replay rejected: OK")

    # Out-of-order but within window (not seen)
    assert rf.check_and_update(src, 12) is True
    assert rf.check_and_update(src, 11) is True
    print("✅ out-of-order accepted: OK")

    # Too old (outside 256 window)
    # Advance to seq=300, then try seq=40 (diff=260)
    assert rf.check_and_update(src, 300) is True
    assert rf.check_and_update(src, 40) is False
    print("✅ too old rejected: OK")

    # Per-sender isolation
    other = "14:B5:CD:E2:49:ED"
    assert rf.check_and_update(other, 1) is True
    assert rf.check_and_update(other, 1) is False
    assert rf.check_and_update(other, 2) is True
    print("✅ per-sender windows: OK")

    print("\n✅ All replay filter self-tests passed")

