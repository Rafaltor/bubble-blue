"""
Supervised ``bluetoothctl`` pairing agent for LE Just Works (NoInputNoOutput).

``bluetoothctl`` auto-registers a KeyboardDisplay agent at startup; a later
``agent NoInputNoOutput`` is silently rejected unless the default agent is
cleared first (``agent off``).  Without a working agent, SMP re-pairing falls
back to numeric-comparison MITM and links drop (~20 s, Reason 0x13).

The supervisor both *accepts* inbound bonds (via the default agent) and can
*initiate* outbound bonds through :meth:`PairingAgentSupervisor.ensure_bonded`.
Outbound Just Works requires **both** boards to run this supervisor
(NoInputNoOutput on each side). If the peer advertises a different IO
capability, bluetoothd may request a passkey (``device_confirm_passkey`` /
``Failed requesting authentication``) and bonding fails — there is no
interactive confirm path in this agent.

A residual interactive ``bluetoothctl`` (or any other AgentManager client) that
keeps KeyboardDisplay as default will also force passkey negotiation — see
:meth:`PairingAgentSupervisor.verify_just_works_capability` and the concurrent-
process warning logged at start.
"""

from __future__ import annotations

import collections
import re
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

BOND_INFO_TIMEOUT_S = 2.0
BOND_PAIR_TIMEOUT_S = 25.0

CONCURRENT_AGENT_WARN = (
    "AVERTISSEMENT: agent concurrent détecté — le Just Works pourrait échouer"
)

_PAIR_SUCCESS_RE = re.compile(r"Pairing successful", re.IGNORECASE)
_PAIR_FAIL_RE = re.compile(
    r"Failed to pair|Authentication Failed|Failed requesting authentication|"
    r"org\.bluez\.Error\.(AuthenticationFailed|Failed)",
    re.IGNORECASE,
)
_BONDED_LINE_RE = re.compile(r"^\s*Bonded:\s*(yes|no)\s*$", re.IGNORECASE)
_PAIRED_LINE_RE = re.compile(r"^\s*Paired:\s*(yes|no)\s*$", re.IGNORECASE)
_PID_RE = re.compile(r"\b(\d+)\b")

PopenFactory = Callable[..., subprocess.Popen[str]]
PsRunner = Callable[[], str]
DbusRunner = Callable[[], str]


def parse_bonded_from_info(text: str) -> bool | None:
    """
    Parse ``Bonded:`` from ``bluetoothctl info`` output.

    Returns True/False when the field is present; None if absent.
    Prefer Bonded over Paired for LE.
    """
    bonded: bool | None = None
    paired: bool | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = _BONDED_LINE_RE.match(line)
        if m:
            bonded = m.group(1).lower() == "yes"
            continue
        m = _PAIRED_LINE_RE.match(line)
        if m:
            paired = m.group(1).lower() == "yes"
    if bonded is not None:
        return bonded
    return paired


def list_bluetoothctl_pids(
    *,
    exclude_pids: set[int] | frozenset[int] | None = None,
    ps_runner: PsRunner | None = None,
) -> list[int]:
    """
    Return PIDs of running ``bluetoothctl`` processes (excluding ``exclude_pids``).

    Uses ``ps -C bluetoothctl`` (fallback ``pgrep -x``). Empty list if none /
    tools missing.
    """
    exclude = {int(p) for p in (exclude_pids or ())}
    runner = ps_runner or _default_ps_bluetoothctl
    try:
        text = runner()
    except OSError:
        return []
    pids: list[int] = []
    for m in _PID_RE.finditer(text or ""):
        pid = int(m.group(1))
        if pid in exclude:
            continue
        if pid not in pids:
            pids.append(pid)
    return pids


def _default_ps_bluetoothctl() -> str:
    try:
        proc = subprocess.run(
            ["ps", "-C", "bluetoothctl", "-o", "pid="],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 or proc.stdout.strip():
            return proc.stdout
    except FileNotFoundError:
        pass
    try:
        proc = subprocess.run(
            ["pgrep", "-x", "bluetoothctl"],
            check=False,
            capture_output=True,
            text=True,
        )
        return proc.stdout
    except FileNotFoundError:
        return ""


def _default_dbus_agent_manager_probe() -> str:
    """
    Probe BlueZ AgentManager1 on the system bus (best-effort, no dbus-python).

    Returns combined stdout+stderr from ``busctl``; empty if unavailable.
    """
    try:
        proc = subprocess.run(
            [
                "busctl",
                "introspect",
                "org.bluez",
                "/org/bluez",
                "org.bluez.AgentManager1",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


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
        ps_runner: PsRunner | None = None,
        dbus_runner: DbusRunner | None = None,
        watchdog_interval_s: float = WATCHDOG_INTERVAL_S,
        setup_retry_count: int = SETUP_RETRY_COUNT,
        setup_command_delay_s: float = SETUP_COMMAND_DELAY_S,
        setup_verify_timeout_s: float = SETUP_VERIFY_TIMEOUT_S,
        bond_info_timeout_s: float = BOND_INFO_TIMEOUT_S,
        bond_pair_timeout_s: float = BOND_PAIR_TIMEOUT_S,
    ) -> None:
        self._quiet = quiet
        self._log = log or self._default_log
        self._log_error = log_error or self._default_log_error
        self._popen_factory = popen_factory or subprocess.Popen
        self._ps_runner = ps_runner
        self._dbus_runner = dbus_runner
        self._watchdog_interval_s = max(1.0, float(watchdog_interval_s))
        self._setup_retry_count = max(1, int(setup_retry_count))
        self._setup_command_delay_s = max(0.0, float(setup_command_delay_s))
        self._setup_verify_timeout_s = max(0.1, float(setup_verify_timeout_s))
        self._bond_info_timeout_s = max(0.1, float(bond_info_timeout_s))
        self._bond_pair_timeout_s = max(0.5, float(bond_pair_timeout_s))
        self._proc: subprocess.Popen[str] | None = None
        self._stdout_buffer: collections.deque[str] = collections.deque(
            maxlen=STDOUT_BUFFER_MAX_LINES
        )
        self._stdout_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._cmd_lock = threading.Lock()
        self._started = False
        self._setup_failed_persistent = False
        self._just_works_ok: bool | None = None

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
            self._just_works_ok = None

        # Before we spawn: any existing bluetoothctl is a concurrent agent risk.
        self._warn_concurrent_bluetoothctl(exclude_pids=None)

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

        own_pid = self._proc.pid if self._proc is not None else None
        self._warn_concurrent_bluetoothctl(
            exclude_pids={own_pid} if own_pid is not None else None
        )

        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="bb-pairing-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()
        with self._lock:
            self._started = True
        self._log("supervisor started")
        if not self._setup_failed_persistent:
            self.verify_just_works_capability()

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

    @property
    def just_works_ok(self) -> bool | None:
        """Result of the last :meth:`verify_just_works_capability` call (or None)."""
        return self._just_works_ok

    def recent_stdout(self) -> list[str]:
        with self._lock:
            return list(self._stdout_buffer)

    def _warn_concurrent_bluetoothctl(
        self,
        *,
        exclude_pids: set[int] | frozenset[int] | None,
    ) -> list[int]:
        """Log a clear warning if other ``bluetoothctl`` processes are running."""
        others = list_bluetoothctl_pids(
            exclude_pids=exclude_pids,
            ps_runner=self._ps_runner,
        )
        if others:
            pids = ", ".join(str(p) for p in others)
            self._log(f"{CONCURRENT_AGENT_WARN} (bluetoothctl pid(s): {pids})")
        return others

    def verify_just_works_capability(self) -> bool:
        """
        Confirm, after setup, that the active agent is NoInputNoOutput.

        Checks:
          1. Setup markers (``Agent registered`` + ``Default agent request successful``)
             from our ``agent NoInputNoOutput`` / ``default-agent`` sequence.
          2. No concurrent ``bluetoothctl`` (would re-register KeyboardDisplay).
          3. Best-effort D-Bus presence of ``org.bluez.AgentManager1``.

        Logs the result. Returns True only when markers are present and no
        concurrent bluetoothctl is detected.
        """
        if not self.setup_ok:
            self._log(
                "Just Works capability: FAILED "
                "(pairing agent setup not OK — NoInputNoOutput not confirmed)"
            )
            self._just_works_ok = False
            return False

        joined = "\n".join(self.recent_stdout())
        markers_ok = (
            AGENT_REGISTERED_MARKER in joined and DEFAULT_AGENT_OK_MARKER in joined
        )

        own_pid = self._proc.pid if self._proc is not None else None
        others = list_bluetoothctl_pids(
            exclude_pids={own_pid} if own_pid is not None else None,
            ps_runner=self._ps_runner,
        )
        if others:
            pids = ", ".join(str(p) for p in others)
            self._log(f"{CONCURRENT_AGENT_WARN} (bluetoothctl pid(s): {pids})")

        dbus_txt = ""
        try:
            runner = self._dbus_runner or _default_dbus_agent_manager_probe
            dbus_txt = runner() or ""
        except OSError:
            dbus_txt = ""
        dbus_reachable = (
            "AgentManager1" in dbus_txt
            or "RegisterAgent" in dbus_txt
            or "RequestDefaultAgent" in dbus_txt
        )
        if dbus_txt and not dbus_reachable:
            first = dbus_txt.strip().splitlines()[:1]
            self._log(
                "Just Works capability: D-Bus AgentManager1 probe inconclusive "
                f"({first})"
            )
        elif dbus_reachable:
            self._log("Just Works capability: D-Bus org.bluez.AgentManager1 reachable")

        ok = bool(markers_ok) and not others
        if ok:
            self._log(
                "Just Works capability: CONFIRMED "
                "(NoInputNoOutput is default-agent; no concurrent bluetoothctl)"
            )
        elif markers_ok and others:
            self._log(
                "Just Works capability: FRAGILE "
                "(NoInputNoOutput registered here, but concurrent bluetoothctl "
                "may force passkey / device_confirm_passkey)"
            )
        else:
            self._log(
                "Just Works capability: FAILED "
                "(NoInputNoOutput / default-agent markers missing from session)"
            )
        self._just_works_ok = ok
        return ok

    def ensure_bonded(
        self,
        bd_addr: str,
        addr_type: str | None = None,
        *,
        timeout_s: float | None = None,
    ) -> bool:
        """
        Ensure ``bd_addr`` is bonded, initiating Just Works pairing if needed.

        Sequence (interactive ``bluetoothctl`` session that already holds the
        NoInputNoOutput default agent)::

            info <bd>   → Bonded: yes ? return True
            pair <bd>   → wait for success / re-check info

        Returns True if already bonded or pairing succeeds; False otherwise.

        **Prerequisite:** both boards must run :class:`PairingAgentSupervisor`
        (NoInputNoOutput). Otherwise SMP may fall back to numeric comparison /
        passkey and this call fails (see module docstring).

        ``addr_type`` is accepted for symmetry with BLE ``connect`` (the device
        must already be known to BlueZ from LE scan); it is not passed on the
        ``pair`` wire command.
        """
        bd = bd_addr.strip().upper()
        _ = addr_type
        if not self.setup_ok:
            return False
        pair_timeout = (
            self._bond_pair_timeout_s if timeout_s is None else max(0.5, float(timeout_s))
        )

        with self._cmd_lock:
            if self._query_bonded(bd):
                return True
            marker = self._write_command(f"pair {bd}")
            if marker is None:
                return False
            deadline = time.monotonic() + pair_timeout
            while time.monotonic() < deadline:
                tail = self._stdout_since(marker)
                if _PAIR_FAIL_RE.search(tail):
                    return False
                if _PAIR_SUCCESS_RE.search(tail):
                    break
                if self._stop.wait(0.05):
                    return False
            # Confirm via info (Pairing successful can race with Bonded flip).
            return self._query_bonded(bd)

    def _query_bonded(self, bd: str) -> bool:
        """Run ``info <bd>`` and return True iff Bonded/Paired is yes."""
        marker = self._write_command(f"info {bd}")
        if marker is None:
            return False
        deadline = time.monotonic() + self._bond_info_timeout_s
        while time.monotonic() < deadline:
            tail = self._stdout_since(marker)
            parsed = parse_bonded_from_info(tail)
            if parsed is not None:
                return parsed
            if self._stop.wait(0.05):
                return False
        return parse_bonded_from_info(self._stdout_since(marker)) is True

    def _write_command(self, cmd: str) -> int | None:
        """Write one bluetoothctl command; return stdout index after the write."""
        with self._lock:
            proc = self._proc
            if proc is None or proc.stdin is None or self._setup_failed_persistent:
                return None
            marker = len(self._stdout_buffer)
            try:
                proc.stdin.write(f"{cmd}\n")
                proc.stdin.flush()
            except OSError:
                return None
            return marker

    def _stdout_since(self, marker: int) -> str:
        with self._lock:
            return "\n".join(list(self._stdout_buffer)[marker:])

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
            elif not self._setup_failed_persistent:
                own_pid = self._proc.pid if self._proc is not None else None
                self._warn_concurrent_bluetoothctl(
                    exclude_pids={own_pid} if own_pid is not None else None
                )
                self.verify_just_works_capability()

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
