from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal

_BD_ADDR_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


@dataclass(frozen=True)
class ChatCommand:
    kind: Literal["private", "help", "members"]
    target: str = ""
    message: str = ""


def _normalize_bd(addr: str) -> str | None:
    a = addr.strip().upper()
    if not _BD_ADDR_RE.match(a):
        return None
    return a


def load_chat_aliases() -> dict[str, str]:
    """
    Parse BUBBLE_BLUE_CHAT_ALIASES=name=BD_ADDR,name2=BD_ADDR2 (case-insensitive names).
    """
    raw = os.environ.get("BUBBLE_BLUE_CHAT_ALIASES", "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for part in raw.split(","):
        piece = part.strip()
        if not piece or "=" not in piece:
            continue
        name, bd = piece.split("=", 1)
        name_key = name.strip().lower()
        norm = _normalize_bd(bd)
        if name_key and norm:
            out[name_key] = norm
    return out


def parse_chat_command(line: str) -> ChatCommand | None:
    """
    Parse slash-commands in chat input.

    Returns None for normal broadcast lines.
    Supports:
      /private rubikQ message text
      /private rubikQ "quoted message"
      /help
      /members
    """
    stripped = line.strip()
    if not stripped.startswith("/"):
        return None

    lower = stripped.lower()
    if lower in ("/help", "/?"):
        return ChatCommand(kind="help")
    if lower == "/members":
        return ChatCommand(kind="members")

    if not lower.startswith("/private"):
        return None

    rest = stripped[len("/private") :].strip()
    if not rest:
        return ChatCommand(kind="private", target="", message="")

    if rest[0] in "\"'":
        q = rest[0]
        end = rest.find(q, 1)
        if end <= 0:
            return ChatCommand(kind="private", target="", message="")
        target = rest[1:end]
        message = rest[end + 1 :].strip()
    else:
        parts = rest.split(maxsplit=1)
        if len(parts) == 1:
            return ChatCommand(kind="private", target=parts[0], message="")
        target, message = parts[0], parts[1]
        if len(message) >= 2 and message[0] == message[-1] and message[0] in "\"'":
            message = message[1:-1]

    return ChatCommand(kind="private", target=target, message=message)


def resolve_chat_target(
    name: str,
    *,
    aliases: dict[str, str],
    group_members: list[str],
    resolved_members: list[str],
    local_bd_addr: str,
) -> str | None:
    """
    Resolve a chat target (alias, BD_ADDR, or known member) to an uppercase BD_ADDR.
    """
    key = name.strip()
    if not key:
        return None

    direct = _normalize_bd(key)
    if direct:
        return direct

    alias_hit = aliases.get(key.lower())
    if alias_hit:
        return alias_hit

    local = local_bd_addr.upper()
    key_upper = key.upper()

    for bd in resolved_members:
        if bd.upper() == key_upper:
            return bd.upper()

    for bd in group_members:
        if bd.upper() == key_upper:
            return bd.upper()

    # Partial BD match if unique (e.g. last octets)
    partial = [bd for bd in set(resolved_members + group_members) if key_upper in bd.upper()]
    if len(partial) == 1:
        return partial[0].upper()

    # Alias substring (rubik → rubikQ alias key)
    alias_sub = [bd for alias, bd in aliases.items() if key.lower() in alias]
    if len(alias_sub) == 1:
        return alias_sub[0]

    return None


CHAT_HELP = """Commandes chat:
  /private <cible> <message>   message privé chiffré (X25519)
  /members                     membres connus (Hello)
  /help                        cette aide

<cible>: alias (.env BUBBLE_BLUE_CHAT_ALIASES), BD_ADDR, ou membre du groupe
Exemples:
  /private rubikQ salut
  /private arduino "ping privé"
  /private 40:D9:5A:8B:69:3F test"""
