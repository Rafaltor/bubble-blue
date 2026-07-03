from __future__ import annotations

import io
import os
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.transport.pairing_agent import (  # noqa: E402
    AGENT_REGISTERED_MARKER,
    DEFAULT_AGENT_OK_MARKER,
    SETUP_COMMANDS,
    PairingAgentSupervisor,
    STDOUT_BUFFER_MAX_LINES,
)


class MockStdin:
    def __init__(self, proc: MockBluetoothctl) -> None:
        self._proc = proc
        self.lines: list[str] = []

    def write(self, data: str) -> None:
        for raw in data.splitlines():
            line = raw.strip()
            if not line:
                continue
            self.lines.append(line)
            self._proc._emit_for_command(line)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class MockBluetoothctl:
    """Minimal ``bluetoothctl`` process double for pairing agent tests."""

    created: list[MockBluetoothctl] = []

    def __init__(self, cmd: list[str], **kwargs: object) -> None:
        assert cmd == ["bluetoothctl"]
        self._reject_agent = False
        self._agent_attempt = 0
        self._returncode: int | None = None
        stdout_r, stdout_w = os.pipe()
        self._stdout_writer = os.fdopen(stdout_w, "w", buffering=1)
        self.stdout = os.fdopen(stdout_r, "r", buffering=1)
        self.stdin = MockStdin(self)
        self.stderr = io.StringIO()
        MockBluetoothctl.created.append(self)

    def _emit_for_command(self, cmd: str) -> None:
        if cmd == "agent NoInputNoOutput":
            self._agent_attempt += 1
            if not self._reject_agent:
                self._stdout_writer.write(f"{AGENT_REGISTERED_MARKER}\n")
        elif cmd == "default-agent":
            self._stdout_writer.write(f"{DEFAULT_AGENT_OK_MARKER}\n")
        elif cmd == "agent off":
            self._stdout_writer.write("Agent unregistered\n")
        self._stdout_writer.flush()

    def poll(self) -> int | None:
        return self._returncode

    def terminate(self) -> None:
        self._returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        return self._returncode or 0

    def kill(self) -> None:
        self._returncode = -9

    def mark_dead(self) -> None:
        self._returncode = 1
        try:
            self._stdout_writer.close()
        except OSError:
            pass
        try:
            self.stdout.close()
        except OSError:
            pass


def _supervisor(**kwargs: object) -> PairingAgentSupervisor:
    return PairingAgentSupervisor(
        quiet=True,
        popen_factory=MockBluetoothctl,
        setup_command_delay_s=0.0,
        setup_verify_timeout_s=0.5,
        watchdog_interval_s=0.05,
        **kwargs,
    )


def test_setup_commands_emitted_in_order() -> None:
    MockBluetoothctl.created.clear()
    sup = _supervisor()
    sup.start()
    try:
        assert len(MockBluetoothctl.created) == 1
        proc = MockBluetoothctl.created[0]
        assert proc.stdin.lines == list(SETUP_COMMANDS)
        assert sup.setup_ok
    finally:
        sup.stop()


def test_agent_rejected_then_retry_succeeds() -> None:
    MockBluetoothctl.created.clear()
    rejections = iter([True, True, False])

    class RetryMock(MockBluetoothctl):
        def _emit_for_command(self, cmd: str) -> None:
            if cmd == "agent NoInputNoOutput":
                self._reject_agent = next(rejections, False)
            super()._emit_for_command(cmd)

    sup = PairingAgentSupervisor(
        quiet=True,
        popen_factory=RetryMock,
        setup_command_delay_s=0.0,
        setup_verify_timeout_s=0.3,
        setup_retry_count=3,
        watchdog_interval_s=1.0,
    )
    errors: list[str] = []
    sup._log_error = errors.append  # noqa: SLF001
    sup.start()
    try:
        assert sup.setup_ok
        assert any("attempt 1/3 failed" in e for e in errors)
        assert any("attempt 2/3 failed" in e for e in errors)
        assert RetryMock.created[0].stdin.lines.count("agent NoInputNoOutput") >= 3
    finally:
        sup.stop()


def test_watchdog_relaunches_after_process_death() -> None:
    MockBluetoothctl.created.clear()
    sup = _supervisor()
    sup.start()
    try:
        assert len(MockBluetoothctl.created) == 1
        MockBluetoothctl.created[0].mark_dead()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if len(MockBluetoothctl.created) >= 2:
                break
            time.sleep(0.02)
        assert len(MockBluetoothctl.created) >= 2
        assert MockBluetoothctl.created[-1].stdin.lines[:4] == list(SETUP_COMMANDS)
    finally:
        sup.stop()


def test_stdout_drained_into_buffer() -> None:
    MockBluetoothctl.created.clear()

    class VerboseMock(MockBluetoothctl):
        def _emit_for_command(self, cmd: str) -> None:
            for i in range(3):
                self._stdout_writer.write(f"{cmd}-line-{i}\n")
            super()._emit_for_command(cmd)

    sup = PairingAgentSupervisor(
        quiet=True,
        popen_factory=VerboseMock,
        setup_command_delay_s=0.0,
        setup_verify_timeout_s=0.5,
        watchdog_interval_s=1.0,
    )
    sup.start()
    try:
        time.sleep(0.1)
        lines = sup.recent_stdout()
        assert AGENT_REGISTERED_MARKER in "\n".join(lines)
        assert DEFAULT_AGENT_OK_MARKER in "\n".join(lines)
        assert len(lines) <= STDOUT_BUFFER_MAX_LINES
    finally:
        sup.stop()


if __name__ == "__main__":
    test_setup_commands_emitted_in_order()
    print("✅ setup command order")
    test_agent_rejected_then_retry_succeeds()
    print("✅ agent rejected retry")
    test_watchdog_relaunches_after_process_death()
    print("✅ watchdog relaunch")
    test_stdout_drained_into_buffer()
    print("✅ stdout drain")
