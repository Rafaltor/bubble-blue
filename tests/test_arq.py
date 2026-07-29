"""ARQ gap detection + CDS/origin replay (Blue_Bubble_specs.pdf §2.4.3)."""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.forwarding.arq import ArqEngine, build_arq_body, parse_arq_body  # noqa: E402


def test_arq_body_roundtrip() -> None:
    body = build_arq_body("14:B5:CD:E2:12:4F", 42)
    src, seq = parse_arq_body(body)
    assert src == "14:B5:CD:E2:12:4F"
    assert seq == 42


def test_gap_detection_reports_missing() -> None:
    eng = ArqEngine()
    assert eng.note_received("AA:BB:CC:DD:EE:01", 1) == []
    assert eng.note_received("AA:BB:CC:DD:EE:01", 2) == []
    assert eng.note_received("AA:BB:CC:DD:EE:01", 5) == [3, 4]


def test_first_packet_sets_baseline_without_historical_arq() -> None:
    eng = ArqEngine()
    # Joined late: first seen seq is 10 — do not ARQ 1..9.
    assert eng.note_received("AA:BB:CC:DD:EE:01", 10) == []
    assert eng.note_received("AA:BB:CC:DD:EE:01", 12) == [11]


def test_cache_store_and_get() -> None:
    eng = ArqEngine()
    wire = b"\x02" + b"\x00" * 40
    eng.store_packet("AA:BB:CC:DD:EE:01", 7, wire)
    assert eng.get_packet("aa:bb:cc:dd:ee:01", 7) == wire
    assert eng.get_packet("AA:BB:CC:DD:EE:01", 8) is None


def test_arq_emit_rate_limit() -> None:
    eng = ArqEngine()
    assert eng.should_emit_arq("AA:BB:CC:DD:EE:01", 3, min_interval_s=10.0) is True
    assert eng.should_emit_arq("AA:BB:CC:DD:EE:01", 3, min_interval_s=10.0) is False
