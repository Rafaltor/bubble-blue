from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

from config import BubbleBlueConfig
from src.control.hello import build_hello, compute_anon_id, parse_hello_private, parse_hello_public
from src.control.neighbors import NeighborTable

if TYPE_CHECKING:
    from src.transport.l2cap import L2CAPTransport


def _fmt_anon_id(aid: bytes) -> str:
    return aid.hex()


class HelloManager:
    """
    Background Hello control-plane manager.

    - Sends periodic Hello packets to all connected L2CAP peers
    - Updates NeighborTable on received Hellos
    - Prints 1-hop / 2-hop tables every hello_interval_s
    """

    def __init__(self, cfg: BubbleBlueConfig, transport: L2CAPTransport) -> None:
        self._cfg = cfg
        self._transport = transport
        self._group_key = cfg.group_key
        self._local_bd = cfg.local_bd_addr.upper()
        self._interval_s = max(1, int(cfg.hello_interval_s))
        self._timeout_ms = int(cfg.neighbor_timeout_s) * 1000
        self._group_members = {a.upper() for a in cfg.group_members}

        self.anon_id = compute_anon_id(self._group_key, self._local_bd)
        self.table = NeighborTable()

        self._seq = 0
        self._seq_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="bb-hello-mgr", daemon=True)
        self._thread.start()
        print(
            f"[APP] HelloManager started (anon_id={self.anon_id.hex()}, interval={self._interval_s}s)",
            flush=True,
        )

    def stop(self) -> None:
        self._stop.set()

    def on_receive(self, peer_bd_addr: str, data: bytes) -> None:
        """Parse and ingest a received Hello packet."""
        _ = peer_bd_addr  # sender BD available for future link-local validation
        pub = parse_hello_public(data)
        priv = parse_hello_private(data, self._group_key)
        self.table.update_from_hello(pub, priv)

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def _known_neighbor_bd_addrs(self) -> list[str]:
        """BD addresses to advertise in our Hello private/public neighbor lists."""
        addrs: set[str] = set(self._transport.connections())
        if self._cfg.remote_bd_addr not in ("00:00:00:00:00:00", self._local_bd):
            addrs.add(self._cfg.remote_bd_addr.upper())

        for entry in self.table.get_1hop():
            bd = entry.get("bd_addr")
            if bd:
                addrs.add(str(bd).upper())

        addrs.discard(self._local_bd)
        return sorted(addrs)

    def _send_hellos(self) -> None:
        peers = list(self._transport.connections())
        if not peers and self._cfg.remote_bd_addr not in ("00:00:00:00:00:00",):
            peers = [self._cfg.remote_bd_addr.upper()]

        if not peers:
            return

        neighbors = self._known_neighbor_bd_addrs()
        seq = self._next_seq()
        pkt = build_hello(self._group_key, self._local_bd, seq, neighbors)

        for peer in peers:
            try:
                self._transport.send(peer, pkt)
            except OSError as e:
                print(f"[APP] Hello send failed peer={peer}: {e}", flush=True)

    def print_neighbor_tables(self) -> None:
        """Print 1-hop / 2-hop / known member BD addresses."""
        one_hop = self.table.get_1hop()
        two_hop = self.table.get_2hop()

        anon_ids = [_fmt_anon_id(e["anon_id"]) for e in one_hop]
        two_fmt: dict[str, list[str]] = {
            _fmt_anon_id(relay): [_fmt_anon_id(t) for t in sorted(targets)]
            for relay, targets in sorted(two_hop.items(), key=lambda kv: kv[0])
        }

        known_members: set[str] = set(self._group_members)
        for entry in one_hop:
            bd = entry.get("bd_addr")
            if bd:
                known_members.add(str(bd).upper())
        known_members.discard(self._local_bd)

        print(f"1-hop: [{', '.join(anon_ids)}]", flush=True)
        print(f"2-hop: {two_fmt}", flush=True)
        print(f"known members: [{', '.join(sorted(known_members))}]", flush=True)

    def _loop(self) -> None:
        # Send one Hello immediately, then on every interval.
        while not self._stop.is_set():
            self.table.expire(self._timeout_ms)
            self._send_hellos()
            self.print_neighbor_tables()
            if self._stop.wait(self._interval_s):
                break


def handle_pkt_data(peer_bd_addr: str, data: bytes, cfg: BubbleBlueConfig) -> None:
    """Decrypt and print a PKT_DATA BB packet (routing header + crypto payload)."""
    from src.security.crypto import decrypt_from_group
    from src.security.packet import parse_bb_packet, validate_timestamp
    from src.security.replay import ReplayFilter

    # Module-level replay filter per process (simple MVP).
    if not hasattr(handle_pkt_data, "_replay"):
        handle_pkt_data._replay = ReplayFilter()  # type: ignore[attr-defined]
    replay: ReplayFilter = handle_pkt_data._replay  # type: ignore[attr-defined]

    try:
        parsed = parse_bb_packet(data)
        rh = parsed["routing_header"]
        hdr = parsed["parsed_header"]

        if not validate_timestamp(hdr["ts_ms"]):
            print(f"[APP] DATA rejected from={peer_bd_addr}: timestamp out of window", flush=True)
            return

        if not replay.check_and_update(hdr["src"], hdr["seq"]):
            print(f"[APP] DATA rejected from={peer_bd_addr}: replay detected", flush=True)
            return

        plaintext = decrypt_from_group(
            cfg.group_key,
            parsed["session_key_enc"],
            parsed["nonce"],
            parsed["ciphertext"],
            rh,
        )
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(plaintext)
        print(
            f"[APP] DATA from={peer_bd_addr} src={hdr['src']} dst={hdr['dst']} "
            f"ttl={hdr['ttl']} seq={hdr['seq']} text={text}",
            flush=True,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[APP] DATA rx from={peer_bd_addr} bytes={len(data)} error={e}", flush=True)
