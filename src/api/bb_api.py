from __future__ import annotations

import errno
import os
import random
import threading
import time
from collections.abc import Callable

from config import (
    PKT_ANNOUNCE,
    PKT_DATA,
    PKT_HELLO,
    PKT_REKEY,
    PKT_REKEY_FLOOD,
    PKT_SUBGROUP,
    BubbleBlueConfig,
    load_config,
)
from src.control.hello_manager import HelloManager
from src.control.presence_scanner import PresenceScanner
from src.forwarding.forwarder import LogCallback, OnMessageCallback, PacketForwarder
from src.security.epoch import EpochStore
from src.security.keys import BBKeyStore
from src.transport.advertising import (
    BB_BEACON_COMPANY_ID,
    parse_presence_manufacturer_value,
)
from src.transport.base import ManagedTransport
from src.transport.dbus_advertiser import DBusLEAdvertiser
from src.transport.factory import make_transport
from src.transport.le_scan import MgmtLEScanner, hci_index_from_interface
from src.transport.pairing_agent import PairingAgentSupervisor

LogFn = Callable[[str, bool], None]

PROTOCOL_HELLO_GRACE_MULT = 3
PROTOCOL_QUARANTINE_BASE_S = 30.0
PROTOCOL_QUARANTINE_CAP_S = 600.0


def topology_from_env() -> frozenset[str] | None:
    """Optional allowlist/dial list from BUBBLE_BLUE_TOPOLOGY."""
    return parse_topology(os.environ.get("BUBBLE_BLUE_TOPOLOGY"))


def merge_topology(
    cli: str | frozenset[str] | set[str] | None,
    *,
    use_env: bool = True,
) -> frozenset[str] | None:
    """CLI --topology wins; else BUBBLE_BLUE_TOPOLOGY from .env."""
    topo = parse_topology(cli)
    if topo:
        return topo
    if use_env:
        return topology_from_env()
    return None


def parse_topology(raw: str | frozenset[str] | set[str] | None) -> frozenset[str] | None:
    if raw is None:
        return None
    if isinstance(raw, frozenset):
        return raw if raw else None
    if isinstance(raw, set):
        return frozenset(raw) if raw else None
    addrs = {part.strip().upper() for part in str(raw).split(",") if part.strip()}
    return frozenset(addrs) if addrs else None


class BBNode:
    """
    BUBBLE-BLUE node: L2CAP + Hello (control) + PKT_DATA (forward).

    Configure ``on_message`` and optionally ``on_log`` (stderr-style diagnostics).
    ``start(topology=...)`` sets the L2CAP allowlist and opens connections to those peers.
    """

    on_message: OnMessageCallback | None = None
    on_log: LogFn | None = None
    on_peer_connected: Callable[[str], None] | None = None
    on_peer_disconnected: Callable[[str], None] | None = None
    on_decrypt_fail: Callable[[str], None] | None = None

    def __init__(
        self,
        *,
        interface: str = "hci0",
        remote_bd_addr: str | None = None,
        key_store: BBKeyStore | None = None,
        quiet: bool = False,
        setup_pairing_agent: bool = True,
    ) -> None:
        self._interface = interface
        self._remote_bd_addr = remote_bd_addr
        self._key_store = key_store
        self._quiet = quiet
        self._topology: frozenset[str] | None = None
        self._pairing_supervisor: PairingAgentSupervisor | None = None

        self._cfg: BubbleBlueConfig | None = None
        self._transport: ManagedTransport | None = None
        self._hello_mgr: HelloManager | None = None
        self._forwarder: PacketForwarder | None = None
        self._started = False
        self._lock = threading.RLock()
        self._connect_stop = threading.Event()
        self._connect_thread: threading.Thread | None = None
        self._connect_last_err: dict[str, str] = {}
        self._connect_last_log: dict[str, float] = {}
        self._connect_backoff_until: dict[str, float] = {}
        self._connect_streak: dict[str, int] = {}
        # One outbound bond attempt per backoff cycle (BLE EPERM / unbonded peer).
        self._bond_attempted: set[str] = set()
        self._active_peers: set[str] = set()
        self._presence_scanner: PresenceScanner | None = None
        self._le_scanner: MgmtLEScanner | None = None
        # Connectionless presence plane (public Hello broadcast + ingest).
        self._dbus_advertiser: DBusLEAdvertiser | None = None
        self._presence_stop = threading.Event()
        self._presence_thread: threading.Thread | None = None
        # anon_id (hex) -> (bd_addr, addr_type) learned from heard presence Hellos.
        self._presence_addr: dict[str, tuple[str, str]] = {}
        self._discovered_candidates: dict[str, str] = {}
        self._peer_addr_types: dict[str, str] = {}
        self._peer_admission_deadline: dict[str, float] = {}
        self._admitted_peers: set[str] = set()
        self._protocol_quarantine_until: dict[str, float] = {}
        self._protocol_quarantine_streak: dict[str, int] = {}

        if setup_pairing_agent:
            self._pairing_supervisor = PairingAgentSupervisor(quiet=quiet)
            self._pairing_supervisor.start()

    def start(
        self,
        topology: str | frozenset[str] | set[str] | None = None,
        *,
        l2cap_accept_all: bool = False,
    ) -> None:
        if self.on_message is None:
            raise RuntimeError("set BBNode.on_message before start()")

        with self._lock:
            if self._started:
                return

            self._topology = parse_topology(topology)
            self._cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )
            allowlist = self._restrictive_allowlist()
            if allowlist is not None:
                allowed_peers = allowlist
            elif l2cap_accept_all:
                allowed_peers = None
            else:
                allowed_peers = None

            node_self = self

            holder: dict[str, HelloManager | PacketForwarder | None] = {
                "hello": None,
                "fwd": None,
            }

            def on_receive(peer: str, data: bytes) -> None:
                if not data:
                    return
                if data[0] == PKT_HELLO:
                    hm = holder["hello"]
                    if hm is not None:
                        had = hm.has_learned_public_hello(peer)
                        hm.on_receive(peer, data)
                        if not had and hm.has_learned_public_hello(peer):
                            node_self._mark_peer_admitted(peer)
                    return
                if data[0] in (
                    PKT_DATA,
                    PKT_SUBGROUP,
                    PKT_REKEY,
                    PKT_ANNOUNCE,
                    PKT_REKEY_FLOOD,
                ):
                    fwd = holder["fwd"]
                    if fwd is not None:
                        fwd.handle(peer, data)

            transport = make_transport(
                self._cfg.transport_kind,
                on_receive=on_receive,
                interface=self._interface,
                quiet=self._quiet,
                allowed_peers=allowed_peers,
                on_peer_connected=self._dispatch_peer_connected,
                on_peer_disconnected=self._dispatch_peer_disconnected,
            )
            key_store = self._key_store or BBKeyStore.for_node(self._cfg.local_bd_addr)
            epoch_store = EpochStore(
                self._cfg.group_key,
                local_bd_addr=self._cfg.local_bd_addr,
            )
            hello = HelloManager(self._cfg, transport, key_store, epoch_store, quiet=self._quiet)
            fwd = PacketForwarder(
                self._cfg,
                transport,
                hello,
                on_message=self._dispatch_message,
                on_log=self._dispatch_log if self.on_log else None,
                on_decrypt_fail=(
                    self._dispatch_decrypt_fail if self.on_decrypt_fail else None
                ),
            )
            hello.set_rekey_catchup(fwd.send_rekey_catchup)
            holder["hello"] = hello
            holder["fwd"] = fwd

            transport.start()
            hello.start()

            self._transport = transport
            self._hello_mgr = hello
            self._forwarder = fwd
            self._started = True

            if self._cfg.transport_kind == "ble_l2cap":
                hci_index = hci_index_from_interface(self._interface)
                scan_log = None if self._quiet else self._dispatch_log
                self._le_scanner = MgmtLEScanner(hci_index, log=scan_log)
                self._le_scanner.start()
                # Radio duty-cycling lives in MgmtLEScanner; the PresenceScanner
                # just polls its in-memory snapshot, so poll often (cheap) for
                # low discovery latency.
                self._presence_scanner = PresenceScanner(
                    quiet=self._quiet,
                    on_candidate=self._on_presence_candidate,
                    idle_check=self._presence_scanner_idle,
                    records_provider=self._le_scanner.snapshot,
                    scan_period_s=2.0,
                    steady_period_s=4.0,
                )
                self._presence_scanner.start()
                self._start_presence_plane(hello)

            self._active_peers = {p.upper() for p in transport.connections()}
            self._connect_peers()
            self._connect_stop.clear()
            self._connect_thread = threading.Thread(
                target=self._connect_loop,
                name="bb-connect",
                daemon=True,
            )
            self._connect_thread.start()

    def stop(self) -> None:
        self._connect_stop.set()
        self._stop_presence_plane()
        with self._lock:
            if self._presence_scanner is not None:
                self._presence_scanner.stop()
                self._presence_scanner = None
            if self._le_scanner is not None:
                self._le_scanner.stop()
                self._le_scanner = None
            if self._hello_mgr is not None:
                self._hello_mgr.stop()
            if self._transport is not None:
                self._transport.stop()
            self._hello_mgr = None
            self._transport = None
            self._forwarder = None
            self._started = False
            self._active_peers.clear()
            self._discovered_candidates.clear()
            self._peer_addr_types.clear()
            self._peer_admission_deadline.clear()
            self._admitted_peers.clear()
            self._protocol_quarantine_until.clear()
            self._protocol_quarantine_streak.clear()

        if self._pairing_supervisor is not None:
            self._pairing_supervisor.stop()
            self._pairing_supervisor = None

    def _start_presence_plane(self, hello: HelloManager) -> None:
        """
        Bring up the connectionless presence plane for BLE L2CAP.

        Elects the CDS backbone from over-the-air public Hellos (no link needed),
        broadcasts our own public Hello via Extended Advertising (bluetoothd
        D-Bus), and ingests peers' Hellos from the MGMT scan snapshot. If the
        D-Bus advertiser is unavailable we still ingest (read-only awareness).
        """
        hello.enable_connectionless_topology()
        hci_index = hci_index_from_interface(self._interface)
        if DBusLEAdvertiser.available():
            try:
                adv = DBusLEAdvertiser(
                    interface=hci_index,
                    company_id=BB_BEACON_COMPANY_ID,
                    value=hello.build_local_presence_value(),
                    log=(lambda m: None) if self._quiet else self._dispatch_log,
                )
                adv.start()
                self._dbus_advertiser = adv
            except Exception as e:  # noqa: BLE001
                self._dispatch_log(f"presence advertiser unavailable: {e!r}")
                self._dbus_advertiser = None
        else:
            self._dispatch_log(
                "dbus-fast missing: presence broadcast off (ingest still active)"
            )
        self._presence_stop.clear()
        self._presence_thread = threading.Thread(
            target=self._presence_loop, name="bb-presence", daemon=True
        )
        self._presence_thread.start()

    def _stop_presence_plane(self) -> None:
        self._presence_stop.set()
        thread = self._presence_thread
        if thread is not None:
            thread.join(timeout=3.0)
            self._presence_thread = None
        if self._dbus_advertiser is not None:
            self._dbus_advertiser.stop()
            self._dbus_advertiser = None
        self._presence_addr.clear()

    def _presence_loop(self) -> None:
        # Jittered so independently-booted nodes don't refresh in lockstep.
        while not self._presence_stop.wait(2.0 + random.uniform(0.0, 1.0)):
            try:
                self._ingest_presence_from_scan()
                adv = self._dbus_advertiser
                hello = self._hello_mgr
                if adv is not None and hello is not None:
                    adv.update(hello.build_local_presence_value())
            except Exception as e:  # noqa: BLE001
                self._dispatch_log(f"presence loop: {e}")

    def _ingest_presence_from_scan(self) -> None:
        """Parse public Hellos from the scan snapshot into the connectionless table."""
        scanner = self._le_scanner
        hello = self._hello_mgr
        if scanner is None or hello is None:
            return
        for bd, rec in scanner.snapshot().items():
            value = rec.manufacturer_data.get(BB_BEACON_COMPANY_ID)
            if value is None:
                continue
            parsed = parse_presence_manufacturer_value(value)
            if parsed is None:
                continue
            hello.ingest_public_hello(
                parsed["anon_id"], parsed["seq"], parsed["neighbors"], parsed["mpr"]
            )
            self._presence_addr[parsed["anon_id"].hex()] = (
                bd.upper(),
                rec.addr_type or "",
            )

    def _presence_scanner_idle(self) -> bool:
        """True when every non-quarantined discovered candidate is an admitted active peer."""
        with self._lock:
            now = time.monotonic()
            candidates = {
                bd
                for bd in self._discovered_candidates
                if now >= self._protocol_quarantine_until.get(bd, 0.0)
            }
            if not candidates:
                return False
            admitted_active = {bd for bd in self._admitted_peers if bd in self._active_peers}
            return candidates <= admitted_active

    def mute(self) -> None:
        """Stop presence scan and LE advertising (beacon); L2CAP links stay up."""
        self._stop_presence_plane()
        with self._lock:
            if self._presence_scanner is not None:
                self._presence_scanner.stop()
                self._presence_scanner = None
            if self._le_scanner is not None:
                self._le_scanner.stop()
                self._le_scanner = None
            transport = self._transport
        if transport is not None and hasattr(transport, "mute"):
            transport.mute()

    def send(self, text: str) -> None:
        """Broadcast chat message (dst = FF:FF:FF:FF:FF:FF) on all L2CAP links."""
        self._require_forwarder().send_broadcast(text)

    def send_subgroup(self, text: str, recipients: list[str]) -> None:
        """À la carte multicast (PKT_SUBGROUP) to subset ``recipients``."""
        self._require_forwarder().send_subgroup(text, recipients)

    def revoke_member(self, bd_addr: str) -> None:
        """
        Revoke a member (coordinator only).

        Bumps the group epoch, rotates the group key, and floods one or more
        ``PKT_REKEY_FLOOD`` packets (multi-recipient wrap header under the
        pre-bump pairwise keys). Late nodes are caught up by existing
        ``PKT_REKEY`` unicast gossip when they next Hello with a stale epoch.
        """
        self._require_forwarder().revoke_member(bd_addr)

    def current_epoch(self) -> int:
        if self._hello_mgr is None:
            return 0
        return self._hello_mgr.epoch_store.current_epoch()

    def is_coordinator(self) -> bool:
        if self._hello_mgr is None:
            return False
        return self._hello_mgr.is_coordinator()

    def send_unicast(
        self,
        text: str,
        dst_bd_addr: str,
        *,
        via_peer: str | None = None,
        private: bool = False,
    ) -> None:
        """Send PKT_DATA toward ``dst_bd_addr`` on L2CAP link ``via_peer`` (or first peer)."""
        peer = (via_peer or self._pick_l2cap_peer()).upper()
        self.send_data(text, dst_bd_addr, via_peer=peer, private=private)

    def send_data(
        self,
        text: str | bytes,
        dst_bd_addr: str,
        *,
        via_peer: str,
        private: bool = False,
    ) -> None:
        """Send PKT_DATA to ``dst_bd_addr`` on the given L2CAP peer."""
        self._require_forwarder().send_data(
            text,
            dst_bd_addr,
            private=private,
            l2cap_peer=via_peer.upper(),
        )

    def peers(self) -> list[str]:
        if self._transport is None:
            return []
        return self._transport.connections()

    def connect_targets(self) -> list[str]:
        """BD addresses this node will try to reach (topology + env + --peer)."""
        return sorted(self._connect_targets())

    def is_relay(self) -> bool:
        if self._hello_mgr is None:
            return False
        self._hello_mgr.refresh_cds_role()
        return self._hello_mgr.is_relay

    @property
    def local_bd_addr(self) -> str:
        return self._require_cfg().local_bd_addr

    def resolved_member_addresses(self) -> list[str]:
        if self._hello_mgr is None:
            return []
        return [str(m["bd_addr"]).upper() for m in self._hello_mgr.get_resolved_members()]

    def has_pairwise_key(self, bd_addr: str) -> bool:
        if self._hello_mgr is None:
            return False
        return self._hello_mgr.key_store.get_pair_key(bd_addr.upper()) is not None

    def route_l2cap_peer(self, dst_bd_addr: str) -> str:
        """Pick an L2CAP link to reach ``dst_bd_addr`` (direct neighbor or multihop relay)."""
        dst = dst_bd_addr.upper()
        local = self.local_bd_addr.upper()
        if dst == local:
            raise RuntimeError("cannot send to yourself")
        peers = self.peers()
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        if dst in peers:
            return dst
        return peers[0].upper()

    def _require_cfg(self) -> BubbleBlueConfig:
        if self._cfg is None:
            raise RuntimeError("call start() first")
        return self._cfg

    def _require_forwarder(self) -> PacketForwarder:
        if self._forwarder is None:
            raise RuntimeError("call start() first")
        return self._forwarder

    def _pick_l2cap_peer(self) -> str:
        peers = self.peers()
        if not peers:
            raise RuntimeError("no L2CAP peers connected")
        return peers[0]

    def _restrictive_allowlist(self) -> frozenset[str] | None:
        """Lab override: topology ∪ GROUP_MEMBERS (None = open discovery)."""
        if self._cfg is None:
            cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )
        else:
            cfg = self._cfg
        local = cfg.local_bd_addr.upper()
        addrs: set[str] = set()
        if self._topology:
            addrs.update(self._topology)
        for bd in cfg.group_members:
            addrs.add(bd.upper())
        remote = (self._remote_bd_addr or cfg.remote_bd_addr).upper()
        if remote not in ("00:00:00:00:00:00", local):
            addrs.add(remote)
        addrs.discard(local)
        return frozenset(addrs) if addrs else None

    def _connect_targets(self) -> set[str]:
        """Peers to dial: allowlist ∪ discovered BB candidates (filtered if lab)."""
        if self._cfg is None:
            cfg = load_config(
                interface=self._interface,
                remote_bd_addr=self._remote_bd_addr,
            )
        else:
            cfg = self._cfg
        local = cfg.local_bd_addr.upper()
        allow = self._restrictive_allowlist()
        targets: set[str] = set()
        if allow is not None:
            targets.update(allow)
        with self._lock:
            for bd, _addr_type in self._discovered_candidates.items():
                if allow is None or bd in allow:
                    targets.add(bd)
        targets.discard(local)
        return targets

    def _on_presence_candidate(self, bd_addr: str, addr_type: str, _seen: float) -> None:
        bd = bd_addr.upper()
        with self._lock:
            if time.monotonic() < self._protocol_quarantine_until.get(bd, 0.0):
                return
            allow = self._restrictive_allowlist()
            if allow is not None and bd not in allow:
                return
            first = bd not in self._discovered_candidates
            self._discovered_candidates[bd] = addr_type
            self._peer_addr_types[bd] = addr_type
        if first:
            self._dispatch_log(f"candidat découvert: {bd} ({addr_type})")

    def _mark_peer_admitted(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        with self._lock:
            if bd in self._admitted_peers:
                return
            self._admitted_peers.add(bd)
            self._peer_admission_deadline.pop(bd, None)
            self._protocol_quarantine_streak.pop(bd, None)
            self._protocol_quarantine_until.pop(bd, None)
        self._dispatch_log(f"peer admis: {bd}")

    def _check_protocol_admission(self) -> None:
        if self._hello_mgr is None or self._cfg is None:
            return
        if self._cfg.transport_kind != "ble_l2cap":
            return
        now = time.monotonic()
        with self._lock:
            pending = list(self._peer_admission_deadline.items())
        for bd, deadline in pending:
            if bd not in self._active_peers:
                with self._lock:
                    self._peer_admission_deadline.pop(bd, None)
                continue
            if self._hello_mgr.has_learned_public_hello(bd):
                self._mark_peer_admitted(bd)
                continue
            if now >= deadline:
                self._expel_peer_protocol_silence(bd)

    def _expel_peer_protocol_silence(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        with self._lock:
            self._peer_admission_deadline.pop(bd, None)
            streak = self._protocol_quarantine_streak.get(bd, 0) + 1
            self._protocol_quarantine_streak[bd] = streak
            quarantine_s = min(
                PROTOCOL_QUARANTINE_CAP_S,
                PROTOCOL_QUARANTINE_BASE_S * (2 ** (streak - 1)),
            )
            self._protocol_quarantine_until[bd] = time.monotonic() + quarantine_s
            self._discovered_candidates.pop(bd, None)
            self._peer_addr_types.pop(bd, None)
        self._dispatch_log(f"peer expulsé (silence protocolaire): {bd}")
        self._dispatch_log(f"quarantaine {bd}: {quarantine_s:.0f}s")
        transport = self._transport
        if transport is not None and hasattr(transport, "disconnect"):
            transport.disconnect(bd)

    def _connect_peers(self) -> None:
        if self._transport is None:
            return
        now = time.monotonic()
        local = self._require_cfg().local_bd_addr.upper()
        connections = self._transport.connections()
        # Reconcile state for peers already connected (any pass).
        for bd in list(connections):
            self._connect_last_err.pop(bd, None)
            self._connect_backoff_until.pop(bd, None)
            self._connect_streak.pop(bd, None)
            self._bond_attempted.discard(bd)
        # Attempt at most ONE new connection per pass. Firing every pending link
        # at once creates a connection storm (each L2CAP connect is radio-heavy
        # while also advertising + scanning): peers see EPERM/refused/timeouts and
        # already-established links drop. Staggering one dial per pass spreads
        # establishment out so live links stay up while the mesh fills in.
        for bd in sorted(self._connect_targets()):
            if bd == local or bd in connections:
                continue
            if now < self._connect_backoff_until.get(bd, 0.0):
                continue
            if now < self._protocol_quarantine_until.get(bd, 0.0):
                continue
            if local >= bd:
                continue
            # New attempt window after backoff (or first try): allow one bond.
            self._bond_attempted.discard(bd)
            addr_type = self._peer_addr_types.get(bd)
            try:
                if self._cfg and self._cfg.transport_kind == "ble_l2cap":
                    self._transport.connect(bd, addr_type=addr_type)
                else:
                    self._transport.connect(bd)
                self._connect_last_err.pop(bd, None)
                self._connect_backoff_until.pop(bd, None)
                self._connect_streak.pop(bd, None)
                self._bond_attempted.discard(bd)
            except OSError as e:
                if (
                    e.errno == errno.EPERM
                    and self._cfg is not None
                    and self._cfg.transport_kind == "ble_l2cap"
                    and bd not in self._bond_attempted
                ):
                    self._bond_attempted.add(bd)
                    if self._try_auto_bond(bd, addr_type):
                        try:
                            self._transport.connect(bd, addr_type=addr_type)
                            self._connect_last_err.pop(bd, None)
                            self._connect_backoff_until.pop(bd, None)
                            self._connect_streak.pop(bd, None)
                            self._bond_attempted.discard(bd)
                            return
                        except OSError as e2:
                            e = e2
                self._backoff_after_connect_fail(bd, e)
                self._log_connect_failure(bd, e)
            return

    def _try_auto_bond(self, bd: str, addr_type: str | None) -> bool:
        """
        Initiate Just Works bond once (BLE EPERM / no encrypted link).

        Requires PairingAgentSupervisor on *both* boards (NoInputNoOutput).
        """
        sup = self._pairing_supervisor
        self._dispatch_log(f"bond auto tenté avec {bd}")
        if sup is None or not sup.setup_ok:
            self._dispatch_log(f"bond auto échoué {bd}")
            return False
        try:
            ok = bool(sup.ensure_bonded(bd, addr_type))
        except Exception as exc:  # noqa: BLE001 — never break connect loop
            self._dispatch_log(f"bond auto échoué {bd}")
            self._dispatch_log(f"bond auto error {bd}: {exc}")
            return False
        if ok:
            self._dispatch_log(f"bond auto réussi {bd}")
            return True
        self._dispatch_log(f"bond auto échoué {bd}")
        return False

    def _backoff_after_connect_fail(self, bd: str, e: OSError) -> None:
        if e.errno not in (
            errno.EHOSTDOWN,
            errno.ECONNREFUSED,
            errno.ENETUNREACH,
            errno.ETIMEDOUT,
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.EINPROGRESS,
            errno.EALREADY,
            errno.EPERM,  # BLE L2CAP CoC to an unbonded peer (no encrypted link)
        ):
            return
        key = f"{e.errno}"
        streak = self._connect_streak.get(bd, 0) + 1 if self._connect_last_err.get(bd) == key else 1
        self._connect_streak[bd] = streak
        # Unbonded peer (EPERM) will not become connectable until bonded — back off harder.
        base_s = 10.0 if e.errno == errno.EPERM else 4.0
        self._connect_backoff_until[bd] = time.monotonic() + min(60.0, base_s * streak)

    def _log_connect_failure(self, bd: str, e: OSError) -> None:
        key = f"{e.errno}"
        now = time.monotonic()
        prev = self._connect_last_err.get(bd)
        last = self._connect_last_log.get(bd, 0.0)
        self._connect_last_err[bd] = key
        if prev == key and now - last < 45.0:
            return
        self._connect_last_log[bd] = now
        self._dispatch_log(f"connect {bd} failed: {e}")

    def _connect_loop(self) -> None:
        # Jittered interval so independently-booted nodes don't dial in lockstep
        # (lockstep dialing re-creates the very connection storm we stagger to avoid).
        while not self._connect_stop.wait(2.5 + random.uniform(0.0, 1.5)):
            try:
                self._check_protocol_admission()
                self._connect_peers()
            except Exception as e:  # noqa: BLE001
                self._dispatch_log(f"connect loop: {e}")

    def _dispatch_message(self, sender: str, text: str) -> None:
        assert self.on_message is not None
        self.on_message(sender, text)

    def _dispatch_peer_connected(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        if bd in self._active_peers:
            return
        if self._cfg and self._cfg.transport_kind == "ble_l2cap":
            now = time.monotonic()
            with self._lock:
                quarantine_until = self._protocol_quarantine_until.get(bd, 0.0)
            if now < quarantine_until:
                remaining_s = quarantine_until - now
                self._dispatch_log(
                    f"connexion entrante refusée (quarantaine {remaining_s:.0f}s restants): {bd}"
                )
                transport = self._transport
                if transport is not None and hasattr(transport, "disconnect"):
                    transport.disconnect(bd)
                return
            with self._lock:
                self._peer_admission_deadline[bd] = (
                    time.monotonic() + PROTOCOL_HELLO_GRACE_MULT * self._cfg.hello_interval_s
                )
        self._active_peers.add(bd)
        scanner = self._presence_scanner
        if scanner is not None:
            scanner.defer_next_pass()
        if self.on_peer_connected:
            self.on_peer_connected(bd)

    def _dispatch_peer_disconnected(self, bd_addr: str) -> None:
        bd = bd_addr.upper()
        if bd not in self._active_peers:
            return
        self._active_peers.discard(bd)
        with self._lock:
            self._peer_admission_deadline.pop(bd, None)
            self._admitted_peers.discard(bd)
        if self._hello_mgr is not None:
            self._hello_mgr.on_peer_disconnected(bd)
        if self.on_peer_disconnected:
            self.on_peer_disconnected(bd)

    def _dispatch_decrypt_fail(self, src: str) -> None:
        # Foreign-group relay: decrypt failure must never expel or quarantine.
        if self.on_decrypt_fail:
            self.on_decrypt_fail(src.upper())

    def _dispatch_log(self, msg: str, *, err: bool | None = None) -> None:
        if self.on_log:
            # Chat mode: network retries are not errors (buffer while typing).
            is_err = err if err is not None else not self._quiet
            self.on_log(msg, is_err)
