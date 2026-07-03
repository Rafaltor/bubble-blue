"""
Periodic LE discovery of Bubble-Blue nodes via universal presence beacons.

Uses extended ``bluetoothctl`` parsing from ``src.transport.discovery`` and
recognizes candidates whose Manufacturer Specific Data starts with
``BB_BEACON_MAGIC``.
"""

from __future__ import annotations

import math
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from src.transport.advertising import match_bb_beacon_manufacturer_data
from src.transport.discovery import (
    ScanDeviceRecord,
    new_devices_from_scan_output,
    parse_bluetoothctl_info,
    parse_bluetoothctl_scan_output,
)

INFO_LOOKUP_LIMIT = 20


@dataclass(frozen=True)
class PresenceCandidate:
    bd_addr: str
    addr_type: str
    last_seen: float


def _is_bb_candidate(record: ScanDeviceRecord) -> bool:
    return any(match_bb_beacon_manufacturer_data(payload) for payload in record.manufacturer_data.values())


def _is_bb_info(info: object) -> bool:
    mfg = getattr(info, "manufacturer_data", None)
    if not isinstance(mfg, dict):
        return False
    return any(match_bb_beacon_manufacturer_data(payload) for payload in mfg.values())


class PresenceScanner:
    """
    Background LE scanner that reports BB beacon candidates to *on_candidate*.

    Each scan period runs an LE scan for *scan_window_s*, then sleeps until the
    next period. Stale entries are evicted from :meth:`candidates` after
    *candidate_ttl_s* without re-detection (default 60 s).
    """

    def __init__(
        self,
        *,
        scan_window_s: float = 6.0,
        scan_period_s: float = 15.0,
        candidate_ttl_s: float = 60.0,
        on_candidate: Callable[[str, str, float], None] | None = None,
        quiet: bool = False,
        log: Callable[[str], None] | None = None,
        scan_runner: Callable[[float], str] | None = None,
        info_runner: Callable[[str], str] | None = None,
    ) -> None:
        self._scan_window_s = max(0.1, float(scan_window_s))
        self._scan_period_s = max(self._scan_window_s, float(scan_period_s))
        self._candidate_ttl_s = max(0.01, float(candidate_ttl_s))
        self._on_candidate = on_candidate
        self._quiet = quiet
        self._log = log or (lambda msg: None if quiet else print(f"[PRESENCE] {msg}", flush=True))
        self._scan_runner = scan_runner or self._default_scan_runner
        self._info_runner = info_runner or self._default_info_runner
        self._lock = threading.Lock()
        self._candidates: dict[str, PresenceCandidate] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    @staticmethod
    def _default_scan_runner(timeout_s: float) -> str:
        secs = int(max(1, math.ceil(timeout_s)))
        result = subprocess.run(
            ["bluetoothctl", "--timeout", str(secs), "scan", "le"],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.stdout or ""

    @staticmethod
    def _default_info_runner(bd_addr: str) -> str:
        result = subprocess.run(
            ["bluetoothctl", "info", bd_addr],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.stdout or ""

    def start(self) -> None:
        if self._started:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="bb-presence-scanner",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        self._log(
            f"started (window={self._scan_window_s}s period={self._scan_period_s}s "
            f"ttl={self._candidate_ttl_s}s)"
        )

    def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._scan_period_s + self._scan_window_s + 2.0)
            self._thread = None
        self._started = False
        self._log("stopped")

    @property
    def running(self) -> bool:
        return self._started

    def candidates(self) -> dict[str, PresenceCandidate]:
        """Snapshot of known BB candidates (evicted after TTL without re-scan)."""
        with self._lock:
            self._evict_stale_locked(time.monotonic())
            return dict(self._candidates)

    def scan_once(self, *, now: float | None = None) -> list[PresenceCandidate]:
        """Run one LE scan window; useful for tests and manual invocation."""
        now_mono = time.monotonic() if now is None else now
        found = self._scan_pass(now_mono)
        with self._lock:
            self._evict_stale_locked(now_mono)
        return found

    def _loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._scan_pass(started)
            except Exception as exc:
                self._log(f"scan pass error: {exc}")
            with self._lock:
                self._evict_stale_locked(time.monotonic())
            elapsed = time.monotonic() - started
            wait_s = max(0.0, self._scan_period_s - elapsed)
            if self._stop.wait(wait_s):
                break

    def _scan_pass(self, now_mono: float) -> list[PresenceCandidate]:
        text = self._scan_runner(self._scan_window_s)
        records = parse_bluetoothctl_scan_output(
            text,
            now_ms=int(now_mono * 1000),
            log=self._log,
        )
        new_devices = new_devices_from_scan_output(text)
        found: list[PresenceCandidate] = []
        matched: set[str] = set()

        with self._lock:
            prior_candidates = set(self._candidates)

        # (a) Fast path: BB beacon visible in scan stdout.
        for bd, record in records.items():
            if not _is_bb_candidate(record):
                continue
            matched.add(bd)
            found.append(self._register_candidate(bd, self._resolve_addr_type(bd, record), now_mono))

        # Refresh known candidates seen again without re-querying info.
        for bd in records:
            if bd in prior_candidates and bd not in matched:
                with self._lock:
                    old = self._candidates.get(bd)
                    if old is not None:
                        self._candidates[bd] = PresenceCandidate(
                            bd_addr=bd,
                            addr_type=old.addr_type,
                            last_seen=now_mono,
                        )

        # (b) Cached / RSSI-only devices: bluetoothctl info fallback (cap per pass).
        info_queue: list[str] = []
        for bd in records:
            if bd in matched or bd in prior_candidates:
                continue
            if bd in new_devices:
                info_queue.insert(0, bd)
            else:
                info_queue.append(bd)

        info_calls = 0
        for bd in info_queue:
            if info_calls >= INFO_LOOKUP_LIMIT:
                break
            info_calls += 1
            try:
                info = parse_bluetoothctl_info(self._info_runner(bd), log=self._log)
            except Exception as exc:
                self._log(f"info parse failed for {bd}: {exc}")
                continue
            if not _is_bb_info(info):
                continue
            addr_type = (info.addr_type or "unknown").lower()
            matched.add(bd)
            found.append(self._register_candidate(bd, addr_type, now_mono))

        return found

    def _register_candidate(self, bd: str, addr_type: str, now_mono: float) -> PresenceCandidate:
        candidate = PresenceCandidate(bd_addr=bd, addr_type=addr_type, last_seen=now_mono)
        with self._lock:
            self._candidates[bd] = candidate
        if self._on_candidate is not None:
            try:
                self._on_candidate(bd, addr_type, now_mono)
            except Exception as exc:
                self._log(f"on_candidate error for {bd}: {exc}")
        return candidate

    def _resolve_addr_type(self, bd_addr: str, record: ScanDeviceRecord) -> str:
        try:
            info = parse_bluetoothctl_info(self._info_runner(bd_addr), log=self._log)
        except Exception as exc:
            self._log(f"info parse failed for {bd_addr}: {exc}")
            return "unknown"
        if info.addr_type:
            return info.addr_type.lower()
        return "unknown"

    def _evict_stale_locked(self, now_mono: float) -> None:
        stale = [
            bd
            for bd, cand in self._candidates.items()
            if now_mono - cand.last_seen > self._candidate_ttl_s
        ]
        for bd in stale:
            del self._candidates[bd]


def is_bb_beacon_record(record: ScanDeviceRecord) -> bool:
    """Return True when scan record manufacturer data matches a BB beacon."""
    return _is_bb_candidate(record)
