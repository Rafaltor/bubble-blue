#!/usr/bin/env python3
"""
Stands in for the UNO Q panel sketch, on the Linux side.

Registers the same three RPC methods as apps/unoq/panel/panel.ino and redraws
the panel as text every time one of them fires, using the same 25-column,
three-row wrapping the sketch uses. So this previews the real layout — and,
more usefully, it exercises the whole chain (meshd -> unoq_panel.py -> Router
Bridge) before a shield exists to plug in.

    python3 scripts/panel_fake_sketch.py

Type 1 or 2 then Enter to simulate a tap on either preset button.
"""

from __future__ import annotations

import os
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_PYLIB = os.environ.get("BB_PYLIB") or os.path.expanduser("~/.local/lib/bubble-blue")
if os.path.isdir(_PYLIB) and _PYLIB not in sys.path:
    sys.path.append(_PYLIB)

from apps.unoq_panel import MSG_COLS, MSG_ROWS  # noqa: E402

# The sketch blanks its numbers after this long without a push; mirror it so the
# preview shows the same failure the screen would.
LINK_TIMEOUT_S = 10.0

_state = {
    "local": "",
    "peers": 0,
    "relay": False,
    "epoch": 0,
    "from": "",
    "text": "",
    "labels": ["", ""],
    "last_push": 0.0,
}
_lock = threading.Lock()


def wrap(text: str) -> list[str]:
    """Same wrapping as draw_message(): break on spaces, hard-cut a long word."""
    lines, pos = [], 0
    while pos < len(text) and len(lines) < MSG_ROWS:
        take = min(MSG_COLS, len(text) - pos)
        if pos + take < len(text) and take == MSG_COLS:
            brk = take
            while brk > 0 and text[pos + brk] != " ":
                brk -= 1
            if brk > 0:
                take = brk
        lines.append(text[pos : pos + take])
        pos += take
        while pos < len(text) and text[pos] == " ":
            pos += 1
    return lines


def render() -> str:
    with _lock:
        s = dict(_state)
    linked = time.time() - s["last_push"] < LINK_TIMEOUT_S

    w = 54
    bar = "+" + "-" * w + "+"
    badge = ("RELAI" if s["relay"] else "FEUILLE") if linked else "----"
    out = [
        bar,
        "|" + f" BUBBLE-BLUE{badge:>{w - 13}}" + "|",
        bar,
    ]
    if not linked:
        out.append("|" + " LIEN LINUX PERDU".ljust(w) + "|")
    else:
        out.append("|" + f" {s['local']}".ljust(w) + "|")
        out.append("|" + f" PAIRS {s['peers']}        EPOQUE {s['epoch']}".ljust(w) + "|")
    out.append(bar)

    head = f" DERNIER MESSAGE - {s['from']}" if s["text"] else " DERNIER MESSAGE"
    out.append("|" + head[:w].ljust(w) + "|")
    body = wrap(s["text"]) if s["text"] else ["(aucun)"]
    for i in range(MSG_ROWS):
        line = body[i] if i < len(body) else ""
        out.append("|" + f"  {line}".ljust(w) + "|")
    out.append(bar)

    l0, l1 = (s["labels"] + ["", ""])[:2]
    cell = (w - 3) // 2
    out.append("|" + f"[{(l0 or '...').center(cell - 2)}]".center(cell) + " "
               + f"[{(l1 or '...').center(cell - 2)}]".center(cell) + " |")
    out.append(bar)
    return "\n".join(out)


def redraw() -> None:
    print("\033[2J\033[H" + render(), flush=True)
    print("\n  1/2 + Entree = appui bouton, Ctrl-C = quitter", flush=True)


def on_status(local, peers, relay, epoch):
    with _lock:
        _state.update(local=local, peers=peers, relay=relay, epoch=epoch,
                      last_push=time.time())
    redraw()


def on_message(sender, text):
    with _lock:
        _state.update({"from": sender, "text": text, "last_push": time.time()})
    redraw()


def on_presets(label0, label1):
    with _lock:
        _state.update(labels=[label0, label1], last_push=time.time())
    redraw()


def main() -> int:
    try:
        from arduino.app_utils import Bridge
    except ImportError:
        print("bibliotheque arduino absente — lancer scripts/install_unoq_bridge.sh",
              file=sys.stderr)
        return 1

    Bridge.provide("panel_status", on_status)
    Bridge.provide("panel_message", on_message)
    Bridge.provide("panel_presets", on_presets)
    redraw()

    # The sketch redraws itself when the link goes quiet; do the same so the
    # preview does not sit there showing a mesh that stopped reporting.
    def _watchdog():
        while True:
            time.sleep(1.0)
            with _lock:
                stale = time.time() - _state["last_push"]
            if LINK_TIMEOUT_S < stale < LINK_TIMEOUT_S + 1.5:
                redraw()

    threading.Thread(target=_watchdog, daemon=True).start()

    try:
        for line in sys.stdin:
            key = line.strip()
            if key in ("1", "2"):
                Bridge.notify("panel_preset", int(key) - 1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
