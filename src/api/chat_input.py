from __future__ import annotations

import select
import sys
import termios
import tty

from src.api.chat_log import ChatLog


def read_chat_line(prompt: str = "> ") -> str:
    """
    Read one line with echo; pause background log output while typing.
    """
    if not sys.stdin.isatty():
        sys.stdout.write(prompt)
        sys.stdout.flush()
        return sys.stdin.readline().rstrip("\n")

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    chars: list[str] = []

    ChatLog.set_typing(True)
    try:
        tty.setcbreak(fd)
        sys.stdout.write(prompt)
        sys.stdout.flush()

        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not ready:
                continue
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                break
            if ch in ("\x03", "\x04"):  # Ctrl+C / Ctrl+D
                raise KeyboardInterrupt
            if ch in ("\x7f", "\b"):
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if ch == "\x1b":  # ignore escape sequences
                continue
            chars.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        ChatLog.set_typing(False)
        sys.stdout.write("\n")
        sys.stdout.flush()

    return "".join(chars)
