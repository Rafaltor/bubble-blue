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
    CONCURRENT_AGENT_WARN,
    DEFAULT_AGENT_OK_MARKER,
    SETUP_COMMANDS,
    PairingAgentSupervisor,
    STDOUT_BUFFER_MAX_LINES,
    list_bluetoothctl_pids,
    parse_bonded_from_info,
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
    _next_pid = 9000

    def __init__(self, cmd: list[str], **kwargs: object) -> None:
        assert cmd == ["bluetoothctl"]
        self._reject_agent = False
        self._agent_attempt = 0
        self._returncode: int | None = None
        self.bonded: set[str] = set()
        self.pair_fail = False
        MockBluetoothctl._next_pid += 1
        self.pid = MockBluetoothctl._next_pid
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
        elif cmd.startswith("info "):
            bd = cmd.split(None, 1)[1].strip().upper()
            bonded = "yes" if bd in self.bonded else "no"
            self._stdout_writer.write(f"Device {bd} (public)\n")
            self._stdout_writer.write(f"\tPaired: {bonded}\n")
            self._stdout_writer.write(f"\tBonded: {bonded}\n")
        elif cmd.startswith("pair "):
            bd = cmd.split(None, 1)[1].strip().upper()
            if self.pair_fail:
                self._stdout_writer.write(
                    f"Failed to pair: org.bluez.Error.AuthenticationFailed\n"
                )
            else:
                self.bonded.add(bd)
                self._stdout_writer.write("Pairing successful\n")
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
    kwargs.setdefault("ps_runner", lambda: "")
    kwargs.setdefault(
        "dbus_runner",
        lambda: "NAME=org.bluez.AgentManager1  RegisterAgent  RequestDefaultAgent\n",
    )
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
        ps_runner=lambda: "",
        dbus_runner=lambda: "RegisterAgent\n",
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
        ps_runner=lambda: "",
        dbus_runner=lambda: "RegisterAgent\n",
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


def test_parse_bonded_from_info() -> None:
    assert parse_bonded_from_info("Bonded: yes\n") is True
    assert parse_bonded_from_info("\tBonded: no\n") is False
    assert parse_bonded_from_info("Paired: yes\n") is True
    assert parse_bonded_from_info("Name: foo\n") is None


def test_ensure_bonded_already_bonded_skips_pair() -> None:
    MockBluetoothctl.created.clear()
    peer = "AA:BB:CC:DD:EE:99"
    sup = _supervisor(bond_info_timeout_s=0.4, bond_pair_timeout_s=0.5)
    sup.start()
    try:
        MockBluetoothctl.created[0].bonded.add(peer)
        assert sup.ensure_bonded(peer, "random") is True
        lines = MockBluetoothctl.created[0].stdin.lines
        assert any(l == f"info {peer}" for l in lines)
        assert not any(l.startswith("pair ") for l in lines)
    finally:
        sup.stop()


def test_ensure_bonded_pairs_when_unbonded() -> None:
    MockBluetoothctl.created.clear()
    peer = "AA:BB:CC:DD:EE:98"
    sup = _supervisor(bond_info_timeout_s=0.4, bond_pair_timeout_s=0.8)
    sup.start()
    try:
        assert peer not in MockBluetoothctl.created[0].bonded
        assert sup.ensure_bonded(peer) is True
        assert peer in MockBluetoothctl.created[0].bonded
        lines = MockBluetoothctl.created[0].stdin.lines
        assert any(l == f"pair {peer}" for l in lines)
    finally:
        sup.stop()


def test_ensure_bonded_returns_false_on_pair_fail() -> None:
    MockBluetoothctl.created.clear()
    peer = "AA:BB:CC:DD:EE:97"
    class FailPair(MockBluetoothctl):
        def __init__(self, cmd: list[str], **kwargs: object) -> None:
            super().__init__(cmd, **kwargs)
            self.pair_fail = True

    sup = PairingAgentSupervisor(
        quiet=True,
        popen_factory=FailPair,
        ps_runner=lambda: "",
        dbus_runner=lambda: "RegisterAgent\n",
        setup_command_delay_s=0.0,
        setup_verify_timeout_s=0.5,
        watchdog_interval_s=1.0,
        bond_info_timeout_s=0.3,
        bond_pair_timeout_s=0.5,
    )
    sup.start()
    try:
        assert sup.ensure_bonded(peer) is False
    finally:
        sup.stop()


def test_list_bluetoothctl_pids_excludes() -> None:
    assert list_bluetoothctl_pids(ps_runner=lambda: " 111\n 222\n", exclude_pids={111}) == [
        222
    ]
    assert list_bluetoothctl_pids(ps_runner=lambda: "", exclude_pids=None) == []


def test_concurrent_bluetoothctl_warns_at_start() -> None:
    MockBluetoothctl.created.clear()
    logs: list[str] = []
    # Pretend PID 4242 is another bluetoothctl (not our mock's pid).
    sup = _supervisor(ps_runner=lambda: "4242\n")
    sup._log = logs.append  # noqa: SLF001
    sup.start()
    try:
        assert any(CONCURRENT_AGENT_WARN in m for m in logs)
        assert sup.just_works_ok is False
        assert any("FRAGILE" in m or CONCURRENT_AGENT_WARN in m for m in logs)
    finally:
        sup.stop()


def test_verify_just_works_capability_confirmed() -> None:
    MockBluetoothctl.created.clear()
    logs: list[str] = []
    sup = _supervisor()
    # Capture after construction; start() calls verify which uses _log.
    sup._log = logs.append  # noqa: SLF001
    # Re-bind default log was already set; start uses self._log
    sup.start()
    try:
        assert SETUP_COMMANDS == (
            "agent off",
            "agent NoInputNoOutput",
            "default-agent",
            "pairable on",
        )
        assert sup.verify_just_works_capability() is True
        assert any("CONFIRMED" in m for m in logs)
        assert any("AgentManager1" in m or "D-Bus" in m for m in logs)
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
    test_parse_bonded_from_info()
    print("✅ parse bonded from info")
    test_ensure_bonded_already_bonded_skips_pair()
    print("✅ ensure_bonded already bonded")
    test_ensure_bonded_pairs_when_unbonded()
    print("✅ ensure_bonded pairs when unbonded")
    test_ensure_bonded_returns_false_on_pair_fail()
    print("✅ ensure_bonded pair fail")
    test_list_bluetoothctl_pids_excludes()
    print("✅ list bluetoothctl pids")
    test_concurrent_bluetoothctl_warns_at_start()
    print("✅ concurrent bluetoothctl warns")
    test_verify_just_works_capability_confirmed()
    print("✅ verify just works confirmed")
