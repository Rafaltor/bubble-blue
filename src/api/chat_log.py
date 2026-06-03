from __future__ import annotations

import sys
import threading


class ChatLog:
    """
    Serialize chat stdout: buffer background logs while the user is typing.
    """

    _lock = threading.Lock()
    _typing = False
    _pending: list[str] = []

    @classmethod
    def emit(cls, msg: str, *, err: bool = False, force: bool = False) -> None:
        stream = sys.stderr if err else sys.stdout
        line = msg if msg.endswith("\n") else f"{msg}\n"
        with cls._lock:
            if cls._typing and not force:
                cls._pending.append(line)
                return
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
        for line in pending:
            sys.stdout.write(line)
        if pending:
            sys.stdout.flush()

    @classmethod
    def flush_pending(cls) -> None:
        cls.set_typing(False)
