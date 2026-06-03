from __future__ import annotations

import sys
import threading


class ChatLog:
    """
    Chat UI: buffer background logs while typing; interrupt redraws prompt + partial line.
    """

    _lock = threading.Lock()
    _typing = False
    _prompt = "> "
    _buffer: list[str] = []
    _pending: list[tuple[str, bool]] = []

    @classmethod
    def set_prompt(cls, prompt: str) -> None:
        cls._prompt = prompt

    @classmethod
    def begin_input(cls) -> None:
        with cls._lock:
            cls._typing = True
            cls._buffer.clear()
        sys.stdout.write(cls._prompt)
        sys.stdout.flush()

    @classmethod
    def append_char(cls, ch: str) -> None:
        cls._buffer.append(ch)
        sys.stdout.write(ch)
        sys.stdout.flush()

    @classmethod
    def backspace(cls) -> None:
        if not cls._buffer:
            return
        cls._buffer.pop()
        sys.stdout.write("\b \b")
        sys.stdout.flush()

    @classmethod
    def end_input(cls) -> str:
        with cls._lock:
            text = "".join(cls._buffer)
            cls._typing = False
            cls._buffer.clear()
            pending = cls._pending
            cls._pending = []
        sys.stdout.write("\n")
        sys.stdout.flush()
        for line, err in pending:
            cls._write(line, err)
        return text

    @classmethod
    def interrupt(cls, msg: str, *, err: bool = False) -> None:
        """Print on a new line; if typing, redraw prompt and partial input after."""
        line = msg if msg.endswith("\n") else f"{msg}\n"
        with cls._lock:
            if cls._typing:
                cls._print_interrupt(line)
                return
            cls._write(line, err)

    @classmethod
    def emit(cls, msg: str, *, err: bool = False, force: bool = False) -> None:
        """Background log: buffer while typing unless force (maps to interrupt)."""
        if force:
            cls.interrupt(msg, err=err)
            return
        line = msg if msg.endswith("\n") else f"{msg}\n"
        with cls._lock:
            if cls._typing:
                cls._pending.append((line, err))
                return
            cls._write(line, err)

    @classmethod
    def _print_interrupt(cls, line: str) -> None:
        partial = "".join(cls._buffer)
        sys.stdout.write("\r\033[K")
        sys.stdout.write(line)
        sys.stdout.write(cls._prompt + partial)
        sys.stdout.flush()

    @classmethod
    def _write(cls, line: str, err: bool) -> None:
        stream = sys.stderr if err else sys.stdout
        stream.write(line)
        stream.flush()
