from __future__ import annotations

import select
import sys
import termios
import tty

from src.api.chat_log import ChatLog


def read_chat_line(prompt: str = "> ") -> str:
    """
    Read one line with echo; chat notifications redraw the prompt while typing.
    """
    ChatLog.set_prompt(prompt)

    if not sys.stdin.isatty():
        sys.stdout.write(prompt)
        sys.stdout.flush()
        return sys.stdin.readline().rstrip("\n")

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)

    ChatLog.begin_input()
    try:
        tty.setcbreak(fd)
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not ready:
                continue
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                break
            if ch in ("\x03", "\x04"):
                raise KeyboardInterrupt
            if ch in ("\x7f", "\b"):
                ChatLog.backspace()
                continue
            if ch == "\x1b":
                continue
            ChatLog.append_char(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    return ChatLog.end_input()
