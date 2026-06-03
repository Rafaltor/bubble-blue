from __future__ import annotations

import sys
import threading


class ChatLog:
    """
    Serialize chat stdout: buffer background logs while the user is typing.
    """

    _lock = threading.Lock()
    _typing = False
    _pending: list[tuple[str, bool]] = []

    @classmethod
    def emit(cls, msg: str, *, err: bool = False, force: bool = False) -> None:
        line = msg if msg.endswith("\n") else f"{msg}\n"
        with cls._lock:
            if cls._typing and not force:
                cls._pending.append((line, err))
                return
            cls._write(line, err)

    @classmethod
    def _write(cls, line: str, err: bool) -> None:
        stream = sys.stderr if err else sys.stdout
        stream.write(line)
        stream.flush()

    @classmethod
    def set_typing(cls, active: bool) -> None:
        with cls._lock:
            cls._typing = active
            if active:
                return
            pending = cls._pending
            cls._pending = []
        for line, err in pending:
            cls._write(line, err)

    @classmethod
    def flush_pending(cls) -> None:
        cls.set_typing(False)
