"""
Supervised ``bluetoothctl`` pairing agent for LE Just Works (NoInputNoOutput).

``bluetoothctl`` auto-registers a KeyboardDisplay agent at startup; a later
``agent NoInputNoOutput`` is silently rejected unless the default agent is
cleared first (``agent off``).  Without a working agent, SMP re-pairing falls
back to numeric-comparison MITM and links drop (~20 s, Reason 0x13).
"""

from __future__ import annotations

import collections
import subprocess
import threading
import time
from collections.abc import Callable

SETUP_COMMANDS: tuple[str, ...] = (
    "agent off",
    "agent NoInputNoOutput",
    "default-agent",
    "pairable on",
)

AGENT_REGISTERED_MARKER = "Agent registered"
DEFAULT_AGENT_OK_MARKER = "Default agent request successful"

WATCHDOG_INTERVAL_S = 10.0
SETUP_RETRY_COUNT = 3
SETUP_VERIFY_TIMEOUT_S = 2.0
SETUP_COMMAND_DELAY_S = 0.15
STDOUT_BUFFER_MAX_LINES = 512
STOP_JOIN_TIMEOUT_S = 3.0

PopenFactory = Callable[..., subprocess.Popen[str]]


class PairingAgentSupervisor:
    """
    Keeps an interactive ``bluetoothctl`` session with a verified
    NoInputNoOutput default agent.
    """

    def __init__(
        self,
        *,
        quiet: bool = False,
        log: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        popen_factory: PopenFactory | None = None,
        watchdog_interval_s: float = WATCHDOG_INTERVAL_S,
        setup_retry_count: int = SETUP_RETRY_COUNT,
        setup_command_delay_s: float = SETUP_COMMAND_DELAY_S,
        setup_verify_timeout_s: float = SETUP_VERIFY_TIMEOUT_S,
    ) -> None:
        self._quiet = quiet
        self._log = log or self._default_log
        self._log_error = log_error or self._default_log_error
        self._popen_factory = popen_factory or subprocess.Popen
        self._watchdog_interval_s = max(1.0, float(watchdog_interval_s))
        self._setup_retry_count = max(1, int(setup_retry_count))
        self._setup_command_delay_s = max(0.0, float(setup_command_delay_s))
        self._setup_verify_timeout_s = max(0.1, float(setup_verify_timeout_s))
        self._proc: subprocess.Popen[str] | None = None
        self._stdout_buffer: collections.deque[str] = collections.deque(maxlen=STDOUT_BUFFER_MAX_LINES)
        self._stdout_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._started = False
        self._setup_failed_persistent = False

    @staticmethod
    def _default_log(msg: str) -> None:
        print(f"[PAIRING] {msg}", flush=True)

    def _default_log_error(self, msg: str) -> None:
        if not self._quiet:
            print(f"[PAIRING] ERROR: {msg}", flush=True)

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._stop.clear()
            self._setup_failed_persistent = False

        if not self._spawn_process():
            self._log_error("bluetoothctl not found")
            self._setup_failed_persistent = True
        else:
            self._stdout_thread = threading.Thread(
                target=self._drain_stdout_loop,
                name="bb-pairing-stdout",
                daemon=True,
            )
            self._stdout_thread.start()
            if not self._run_setup_sequence(self._proc):
                self._log_error(
                    "pairing agent setup failed after "
                    f"{self._setup_retry_count} attempts — links may drop on re-pairing"
                )
                self._terminate_process(self._proc)
                self._proc = None
                self._setup_failed_persistent = True

        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="bb-pairing-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()
        with self._lock:
            self._started = True
        self._log("supervisor started")

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
            self._started = False
            self._stop.set()
            proc = self._proc
            self._proc = None
        if proc is not None:
            self._terminate_process(proc)
        for thread in (self._stdout_thread, self._watchdog_thread):
            if thread is not None:
                thread.join(timeout=STOP_JOIN_TIMEOUT_S)
        self._stdout_thread = None
        self._watchdog_thread = None
        self._log("supervisor stopped")

    @property
    def running(self) -> bool:
        return self._started

    @property
    def setup_ok(self) -> bool:
        return self._started and not self._setup_failed_persistent

    def recent_stdout(self) -> list[str]:
        with self._lock:
            return list(self._stdout_buffer)

    def _spawn_process(self) -> bool:
        self._terminate_process(self._proc)
        self._proc = None
        with self._lock:
            self._stdout_buffer.clear()
        try:
            proc = self._popen_factory(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            return False
        self._proc = proc
        return True

    def _launch_and_configure(self) -> bool:
        if not self._spawn_process():
            self._log_error("bluetoothctl not found")
            return False
        if not self._run_setup_sequence(self._proc):
            self._terminate_process(self._proc)
            self._proc = None
            return False
        return True

    def _run_setup_sequence(self, proc: subprocess.Popen[str]) -> bool:
        for attempt in range(1, self._setup_retry_count + 1):
            if proc.stdin is None:
                return False
            marker_before = len(self._stdout_buffer)
            for cmd in SETUP_COMMANDS:
                proc.stdin.write(f"{cmd}\n")
                proc.stdin.flush()
                if self._setup_command_delay_s:
                    time.sleep(self._setup_command_delay_s)
            if self._wait_for_setup_ok(marker_before):
                self._log(
                    f"agent configured ({AGENT_REGISTERED_MARKER!r}, "
                    f"{DEFAULT_AGENT_OK_MARKER!r})"
                )
                return True
            self._log_error(
                f"agent setup attempt {attempt}/{self._setup_retry_count} failed "
                f"(missing {AGENT_REGISTERED_MARKER!r} or {DEFAULT_AGENT_OK_MARKER!r})"
            )
            if attempt < self._setup_retry_count:
                time.sleep(0.05)
        return False

    def _wait_for_setup_ok(self, marker_before: int) -> bool:
        deadline = time.monotonic() + self._setup_verify_timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                tail = list(self._stdout_buffer)[marker_before:]
            joined = "\n".join(tail)
            if AGENT_REGISTERED_MARKER in joined and DEFAULT_AGENT_OK_MARKER in joined:
                return True
            time.sleep(0.02)
        return False

    def _drain_stdout_loop(self) -> None:
        while not self._stop.is_set():
            proc = self._proc
            if proc is None or proc.stdout is None:
                if self._stop.wait(0.1):
                    break
                continue
            try:
                line = proc.stdout.readline()
            except ValueError:
                line = ""
            if line:
                with self._lock:
                    self._stdout_buffer.append(line.rstrip("\n"))
                continue
            if proc.poll() is not None:
                if self._stop.wait(0.1):
                    break
                continue
            if self._stop.wait(0.05):
                break

    def _watchdog_loop(self) -> None:
        while not self._stop.wait(self._watchdog_interval_s):
            proc = self._proc
            if proc is None:
                continue
            if proc.poll() is None:
                continue
            self._log("bluetoothctl exited — relaunching pairing agent")
            with self._lock:
                self._proc = None
            if not self._launch_and_configure():
                self._log_error(
                    "pairing agent relaunch failed — links may drop on re-pairing"
                )
                with self._lock:
                    self._setup_failed_persistent = True

    @staticmethod
    def _terminate_process(proc: subprocess.Popen[str] | None) -> None:
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
