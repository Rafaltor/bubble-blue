from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal

_BD_ADDR_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


@dataclass(frozen=True)
class ChatAliasConfig:
    """Alias labels from BUBBLE_BLUE_CHAT_ALIASES (display name + lookup table)."""

    lookup: dict[str, str]
    entries: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ChatCommand:
    kind: Literal["private", "help", "members", "subgroup", "revoke", "epoch"]
    target: str = ""
    message: str = ""
    recipients: tuple[str, ...] = ()


def _normalize_bd(addr: str) -> str | None:
    a = addr.strip().upper()
    if not _BD_ADDR_RE.match(a):
        return None
    return a


def load_chat_aliases() -> ChatAliasConfig:
    """
    Parse BUBBLE_BLUE_CHAT_ALIASES=name=BD_ADDR,name2=BD_ADDR2 (case-insensitive lookup).
    """
    raw = os.environ.get("BUBBLE_BLUE_CHAT_ALIASES", "").strip()
    if not raw:
        return ChatAliasConfig(lookup={}, entries=())
    lookup: dict[str, str] = {}
    labels: list[tuple[str, str]] = []
    for part in raw.split(","):
        piece = part.strip()
        if not piece or "=" not in piece:
            continue
        name, bd = piece.split("=", 1)
        display = name.strip()
        name_key = display.lower()
        norm = _normalize_bd(bd)
        if name_key and norm:
            lookup[name_key] = norm
            labels.append((display, norm))
    return ChatAliasConfig(lookup=lookup, entries=tuple(labels))


def format_members_display(
    *,
    alias_config: ChatAliasConfig,
    resolved_members: list[str],
    group_members: list[str],
    local_bd_addr: str,
) -> str:
    """One-line-per-entry listing for /members (aliases + Hello + .env)."""
    local = local_bd_addr.upper()
    lines: list[str] = []

    for name, bd in alias_config.entries:
        if bd == local:
            continue
        tag = "Hello ✓" if bd in resolved_members else "alias"
        lines.append(f"  {name} → {bd} ({tag})")

    alias_bds = {bd for _, bd in alias_config.entries}
    for bd in sorted(set(resolved_members)):
        if bd == local or bd in alias_bds:
            continue
        lines.append(f"  {bd} (Hello)")

    for bd in sorted(set(group_members)):
        bd_u = bd.upper()
        if bd_u == local or bd_u in alias_bds or bd_u in resolved_members:
            continue
        lines.append(f"  {bd_u} (.env)")

    if not lines:
        return "aucun membre — configurer BUBBLE_BLUE_CHAT_ALIASES ou attendre Hello (~5 s)"
    return "membres:\n" + "\n".join(lines)


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
    if lower == "/epoch":
        return ChatCommand(kind="epoch")

    if lower.startswith("/revoke"):
        rest = stripped[len("/revoke") :].strip()
        if not rest:
            return ChatCommand(kind="revoke", target="")
        return ChatCommand(kind="revoke", target=rest.split()[0])

    if lower.startswith("/subgroup"):
        rest = stripped[len("/subgroup") :].strip()
        if not rest:
            return ChatCommand(kind="subgroup", recipients=())
        parts = rest.split()
        if len(parts) < 2:
            return ChatCommand(kind="subgroup", target=parts[0], recipients=())
        targets, message = parts[:-1], parts[-1]
        if message[0] in "\"'" and message[-1] == message[0]:
            message = message[1:-1]
        return ChatCommand(kind="subgroup", recipients=tuple(targets), message=message)

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
  /subgroup <cible>… <message>  multicast à la carte (PKT_SUBGROUP)
  /revoke <cible>            révoquer un membre (coordinateur → PKT_REKEY_FLOOD + gossip)
  /epoch                     epoch courant + rôle coordinateur
  /members                     alias + membres connus (Hello)
  /help                        cette aide

<cible>: alias (.env BUBBLE_BLUE_CHAT_ALIASES), BD_ADDR, ou membre du groupe
Exemples:
  /private rubikQ salut
  /subgroup rubikQ arduino "réunion à 14h"
  /revoke arduino
  /private 40:D9:5A:8B:69:3F test"""
