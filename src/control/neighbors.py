from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from src.control.hello import (
    ANON_ID_SIZE,
    build_hello,
    compute_anon_id,
    known_neighbors_same_group,
    parse_hello_private,
    parse_hello_public,
)


@dataclass
class _Hop1Entry:
    bd_addr: str | None
    last_seen_ms: int
    seq: int | None


@dataclass
class _ResolvedMember:
    bd_addr: str
    last_seen_ms: int


class NeighborTable:
    """
    Per-node neighbor tables for the BB control plane (topology awareness).

    - 1-hop / 2-hop / resolved: learned from Hello (CDS graph, member resolution)
    - NOT the source of truth for active L2CAP peers — use transport.connections()
      for CDS role (am_i_cds) and for what this node advertises in its own Hello.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._1hop: dict[bytes, _Hop1Entry] = {}
        self._2hop: dict[bytes, set[bytes]] = {}
        # sender anon_id -> set of anon_ids it advertised as its elected MPRs.
        self._mpr: dict[bytes, set[bytes]] = {}
        self._resolved: dict[bytes, _ResolvedMember] = {}

    def update_from_hello(
        self,
        parsed_public: dict[str, Any],
        parsed_private: dict[str, Any] | None,
    ) -> None:
        """
        Update topology tables from a received Hello (awareness only).

        Does not create L2CAP connections. Private neighbor BD addresses are
        stored for resolution/CDS graph only.

        parsed_public: output of parse_hello_public()
        parsed_private: output of parse_hello_private() or None if not a group member
        """
        sender_aid = bytes(parsed_public["anon_id"])
        if len(sender_aid) != ANON_ID_SIZE:
            raise ValueError("invalid sender anon_id length")

        ts_ms = int(parsed_public["ts_ms"])
        seq = int(parsed_public["seq"])
        neighbor_aids = [bytes(a) for a in parsed_public["neighbor_anon_ids"]]
        # Backward-compatible: tolerate a public dict without the MPR key / None.
        mpr_aids = {bytes(a) for a in (parsed_public.get("mpr_anon_ids") or [])}

        bd_sender: str | None = None
        neighbor_bd: dict[bytes, str] = {}
        if parsed_private is not None:
            bd_sender = str(parsed_private["bd_addr"]).upper()
            priv_neighbors = list(parsed_private["neighbor_bd_addrs"])
            if len(priv_neighbors) != len(neighbor_aids):
                raise ValueError("public/private neighbor count mismatch")
            for aid, addr in zip(neighbor_aids, priv_neighbors, strict=True):
                neighbor_bd[aid] = str(addr).upper()

        with self._lock:
            if parsed_private is not None:
                assert bd_sender is not None
                self._resolve_member(sender_aid, bd_sender, ts_ms)
                for n_aid, n_bd in neighbor_bd.items():
                    self._resolve_member(n_aid, n_bd, ts_ms)

            # Sender is 1-hop (we received their Hello directly).
            self._upsert_1hop(sender_aid, bd_addr=bd_sender, last_seen_ms=ts_ms, seq=seq)

            # Store the MPR set this sender advertised (for MPR-CDS election).
            self._mpr[sender_aid] = set(mpr_aids)

            # Sender's advertised neighbors are 2-hop via this relay.
            relay_set = self._2hop.setdefault(sender_aid, set())
            for n_aid in neighbor_aids:
                relay_set.add(n_aid)
                resolved_bd = neighbor_bd.get(n_aid)
                if resolved_bd is None:
                    resolved = self._resolved.get(n_aid)
                    resolved_bd = resolved.bd_addr if resolved else None
                self._upsert_1hop(
                    n_aid,
                    bd_addr=resolved_bd,
                    last_seen_ms=ts_ms,
                    seq=None,
                )

    def get_1hop(self) -> list[dict[str, Any]]:
        """Return 1-hop entries as list of dicts (includes anon_id)."""
        with self._lock:
            out: list[dict[str, Any]] = []
            for aid, ent in self._1hop.items():
                out.append(
                    {
                        "anon_id": aid,
                        "bd_addr": ent.bd_addr,
                        "last_seen_ms": ent.last_seen_ms,
                        "seq": ent.seq,
                    }
                )
            out.sort(key=lambda e: e["anon_id"])
            return out

    def get_2hop(self) -> dict[bytes, set[bytes]]:
        """Return 2-hop map: relay anon_id -> set of reachable anon_ids."""
        with self._lock:
            return {relay: set(targets) for relay, targets in self._2hop.items()}

    def get_mpr(self) -> dict[bytes, set[bytes]]:
        """Return MPR map: sender anon_id -> set of anon_ids it elected as MPRs."""
        with self._lock:
            return {sender: set(mprs) for sender, mprs in self._mpr.items()}

    def get_resolved_members(self) -> list[dict[str, Any]]:
        """Return group members whose anon_id has been resolved to a real BD address."""
        with self._lock:
            out: list[dict[str, Any]] = []
            for aid, ent in sorted(self._resolved.items(), key=lambda kv: kv[0]):
                out.append(
                    {
                        "anon_id": aid,
                        "bd_addr": ent.bd_addr,
                        "last_seen_ms": ent.last_seen_ms,
                    }
                )
            return out

    def resolve_member(self, anon_id: bytes, bd_addr: str, last_seen_ms: int) -> None:
        """Register or refresh anon_id → BD address resolution (thread-safe)."""
        with self._lock:
            self._resolve_member(anon_id, bd_addr, last_seen_ms)

    def expire(self, timeout_ms: int) -> None:
        """Remove stale 1-hop entries and their 2-hop relay rows."""
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be >= 0")

        now_ms = time.time_ns() // 1_000_000
        with self._lock:
            stale = [
                aid
                for aid, ent in self._1hop.items()
                if (now_ms - ent.last_seen_ms) > timeout_ms
            ]
            for aid in stale:
                self._1hop.pop(aid, None)
                self._2hop.pop(aid, None)
                self._mpr.pop(aid, None)

            stale_resolved = [
                aid
                for aid, ent in self._resolved.items()
                if (now_ms - ent.last_seen_ms) > timeout_ms
            ]
            for aid in stale_resolved:
                self._resolved.pop(aid, None)

    def _resolve_member(self, anon_id: bytes, bd_addr: str, last_seen_ms: int) -> None:
        """Store anon_id → BD mapping from a successfully decrypted Hello private part."""
        if len(anon_id) != ANON_ID_SIZE:
            raise ValueError("invalid anon_id length")
        self._resolved[anon_id] = _ResolvedMember(
            bd_addr=str(bd_addr).upper(),
            last_seen_ms=int(last_seen_ms),
        )

    def _upsert_1hop(
        self,
        anon_id: bytes,
        *,
        bd_addr: str | None,
        last_seen_ms: int,
        seq: int | None,
    ) -> None:
        ent = self._1hop.get(anon_id)
        if ent is None:
            self._1hop[anon_id] = _Hop1Entry(
                bd_addr=bd_addr,
                last_seen_ms=last_seen_ms,
                seq=seq,
            )
            return

        ent.last_seen_ms = max(ent.last_seen_ms, last_seen_ms)
        if bd_addr is not None:
            ent.bd_addr = bd_addr
        if seq is not None:
            ent.seq = seq


if __name__ == "__main__":
    group_key = b"\x42" * 32  # fixed key for deterministic anon IDs in test

    addr_a = "40:D9:5A:8B:69:3F"
    addr_b = "14:B5:CD:E2:49:ED"
    addr_c = "00:11:22:33:44:55"

    aid_a = compute_anon_id(group_key, addr_a)
    aid_b = compute_anon_id(group_key, addr_b)
    aid_c = compute_anon_id(group_key, addr_c)

    local_pubkey = b"\x00" * 32  # dummy X25519 key for deterministic self-test

    table_a = NeighborTable()
    table_b = NeighborTable()
    table_c = NeighborTable()

    # A receives Hello from B (B sees neighbors A, C)
    pkt_b = build_hello(
        group_key, addr_b, seq=1, known_neighbors=known_neighbors_same_group(group_key, [addr_a, addr_c]),
        local_public_key=local_pubkey, ts_ms=1_000,
    )
    pub_b = parse_hello_public(pkt_b)
    priv_b = parse_hello_private(pkt_b, group_key)
    assert priv_b is not None
    table_a.update_from_hello(pub_b, priv_b)

    hop_a = {e["anon_id"]: e for e in table_a.get_1hop()}
    assert aid_b in hop_a
    assert hop_a[aid_b]["bd_addr"] == addr_b.upper()
    assert hop_a[aid_b]["seq"] == 1
    resolved_a = {r["anon_id"]: r for r in table_a.get_resolved_members()}
    assert resolved_a[aid_b]["bd_addr"] == addr_b.upper()
    assert resolved_a[aid_c]["bd_addr"] == addr_c.upper()
    print("✅ anon_id resolution from private Hello: OK")
    two_a = table_a.get_2hop()
    assert aid_c in two_a[aid_b]
    assert aid_a in two_a[aid_b]
    print("✅ node A learned B + 2-hop via B: OK")

    # B receives Hello from A (A sees neighbor B)
    pkt_a = build_hello(
        group_key, addr_a, seq=2, known_neighbors=known_neighbors_same_group(group_key, [addr_b]),
        local_public_key=local_pubkey, ts_ms=2_000,
    )
    pub_a = parse_hello_public(pkt_a)
    priv_a = parse_hello_private(pkt_a, group_key)
    assert priv_a is not None
    table_b.update_from_hello(pub_a, priv_a)

    hop_b = {e["anon_id"]: e for e in table_b.get_1hop()}
    assert aid_a in hop_b
    assert hop_b[aid_a]["seq"] == 2
    assert aid_b in table_b.get_2hop()[aid_a]
    print("✅ node B learned A + 2-hop via A: OK")

    # C receives Hello from B
    pkt_b2 = build_hello(
        group_key, addr_b, seq=3, known_neighbors=known_neighbors_same_group(group_key, [addr_a, addr_c]),
        local_public_key=local_pubkey, ts_ms=3_000,
    )
    pub_b2 = parse_hello_public(pkt_b2)
    priv_b2 = parse_hello_private(pkt_b2, group_key)
    assert priv_b2 is not None
    table_c.update_from_hello(pub_b2, priv_b2)

    hop_c = {e["anon_id"]: e for e in table_c.get_1hop()}
    assert aid_b in hop_c
    two_c = table_c.get_2hop()
    assert aid_a in two_c[aid_b]
    assert aid_c in two_c[aid_b]
    print("✅ node C learned B + 2-hop via B: OK")

    # Public-only update still works (non-member observer)
    observer = NeighborTable()
    observer.update_from_hello(pub_b, None)
    obs_hop = {e["anon_id"]: e for e in observer.get_1hop()}
    assert aid_b in obs_hop
    assert obs_hop[aid_b]["bd_addr"] is None
    assert observer.get_resolved_members() == []
    print("✅ public-only hello update: OK")

    # MPR advertised in a Hello is stored per sender and readable via get_mpr().
    table_mpr = NeighborTable()
    pkt_mpr = build_hello(
        group_key, addr_b, seq=4, known_neighbors=known_neighbors_same_group(group_key, [addr_a, addr_c]),
        local_public_key=local_pubkey, mpr_anon_ids=[aid_a], ts_ms=4_000,
    )
    pub_mpr = parse_hello_public(pkt_mpr)
    priv_mpr = parse_hello_private(pkt_mpr, group_key)
    assert priv_mpr is not None
    table_mpr.update_from_hello(pub_mpr, priv_mpr)
    assert table_mpr.get_mpr()[aid_b] == {aid_a}
    print("✅ get_mpr stores advertised MPR set: OK")

    # Backward-compat: a public dict without the mpr_anon_ids key → empty set.
    legacy_pub = dict(pub_mpr)
    legacy_pub.pop("mpr_anon_ids")
    table_legacy = NeighborTable()
    table_legacy.update_from_hello(legacy_pub, None)
    assert table_legacy.get_mpr()[aid_b] == set()
    print("✅ get_mpr backward-compat (no mpr key): OK")

    # expire() removes the MPR entry along with 1-hop / 2-hop.
    table_mpr.expire(timeout_ms=500)
    assert table_mpr.get_mpr() == {}
    print("✅ expire removes MPR entries: OK")

    # Expire stale entries on A (timeout 500ms, ts was 1000, now >> 1500)
    table_a.expire(timeout_ms=500)
    assert table_a.get_1hop() == []
    assert table_a.get_2hop() == {}
    assert table_a.get_resolved_members() == []
    print("✅ expire removes stale entries: OK")

    print("\n✅ All neighbor table self-tests passed")
