#!/usr/bin/env python3.14
"""
Mesh daemon: owns the BBNode and serves it to local UI clients.

Run as root (L2CAP and MGMT both need it), one instance per board:

    sudo python3.14 apps/meshd.py

The UI connects to the AF_UNIX socket and never touches Bluetooth itself. That
split is not decoration: the mesh takes ~40 s to converge, so a UI that crashes
or gets restarted during development must not take the links down with it. It
also keeps the graphical stack — by far the largest attack surface here — out
of the root process.
"""

from __future__ import annotations

import argparse
import grp
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from queue import Empty, Full, Queue

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apps.mesh_control import (  # noqa: E402
    KIND_RELAY,
    decode_control,
    encode_control,
    load_node_names,
)
from apps.protocol import (  # noqa: E402
    CLIENT_QUEUE_LIMIT,
    HISTORY_LIMIT,
    encode,
    read_frames,
    socket_path,
)
from src.api.bb_api import BBNode  # noqa: E402
from src.transport.le_scan import hci_index_from_interface  # noqa: E402

# Peers and relay status have no callback of their own, so poll them and emit
# an event only when the picture actually changes.
_POLL_INTERVAL_S = 1.0

# Topology reports flood every link, and on the UNO Q each received PDU spends
# one of the idents the kernel leaks (see config.l2cap_ident_budget), so they go
# out on change plus a slow heartbeat for boards that joined late — not on a
# fast timer.
_TOPO_HEARTBEAT_S = 60.0
_TOPO_MIN_GAP_S = 3.0
_TOPO_EXPIRY_S = 100.0
_TOPO_MAX_PEERS = 16

# A restart order keeps flooding through boards that are themselves going
# down, and a daemon that just came back has no memory of it: a late copy must
# not send it round again.
_RESTART_GUARD_S = 60.0
# Long enough for the order to be relayed before this board drops its links.
_RESTART_GRACE_S = 3.0

# The UNO Q's controller dies after minutes to hours: its UART stops receiving,
# every HCI command times out, and the kernel's own recovery never brings it
# back — only reloading the driver does. A restart order cannot reach a board
# whose radio is dead, so each board has to notice by itself.
_HEALTH_INTERVAL_S = 10.0
_HEALTH_FAILURES = 3
_TX_TIMEOUTS = 3
_TX_TIMEOUT_WINDOW_S = 60.0


class _Client:
    """One connected UI. Writes go through a queue so a stalled UI cannot block
    the mesh callbacks that feed it."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.queue: Queue = Queue(maxsize=CLIENT_QUEUE_LIMIT)
        self.alive = True

    def send(self, frame: dict) -> None:
        if not self.alive:
            return
        try:
            self.queue.put_nowait(frame)
        except Full:
            # Client is not draining; disconnect it rather than grow forever.
            self.alive = False

    def writer_loop(self) -> None:
        while self.alive:
            try:
                frame = self.queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                self.sock.sendall(encode(frame))
            except OSError:
                self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class ControllerHealth:
    """Is the local controller still answering? Checked from MGMT and the kernel log."""

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._index = hci_index_from_interface(interface)
        self._timeouts: deque = deque()
        self._kmsg: int | None = None
        try:
            self._kmsg = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
            os.lseek(self._kmsg, 0, os.SEEK_END)
        except OSError:
            self._kmsg = None

    def _drain_kmsg(self, now: float) -> None:
        if self._kmsg is None:
            return
        while True:
            try:
                record = os.read(self._kmsg, 8192)
            except BlockingIOError:
                break
            except BrokenPipeError:
                continue  # ring buffer overwrote unread records
            except OSError:
                break
            if is_tx_timeout(record.decode("utf-8", "replace"), self._interface):
                self._timeouts.append(now)
        while self._timeouts and now - self._timeouts[0] > _TX_TIMEOUT_WINDOW_S:
            self._timeouts.popleft()

    def problem(self) -> str | None:
        """None while healthy, else why not."""
        self._drain_kmsg(time.monotonic())
        if len(self._timeouts) >= _TX_TIMEOUTS:
            return f"{len(self._timeouts)} HCI command timeouts in {_TX_TIMEOUT_WINDOW_S:.0f} s"
        if not _adapter_powered(self._index):
            return f"{self._interface} missing or not powered"
        return None


def is_tx_timeout(kmsg_line: str, interface: str) -> bool:
    """``Bluetooth: hci0: command 0x2039 tx timeout`` from /dev/kmsg."""
    return f"{interface}: command 0x" in kmsg_line and "tx timeout" in kmsg_line


class MeshDaemon:
    def __init__(self, interface: str, path: str, node=None, health=None) -> None:
        self.path = path
        # ``node`` is injected by the tests so the protocol can be exercised
        # without an adapter; production always builds a real BBNode.
        self.node = node if node is not None else BBNode(interface=interface, quiet=True)
        # Same for ``health``: without it (tests), no controller watchdog runs.
        self._health = health if health is not None or node is not None else ControllerHealth(interface)
        self.node.on_message = self._on_message
        self.node.on_message_route = self._on_message_route
        self.node.on_peer_connected = lambda bd: self._on_log(f"peer up {bd}", False)
        self.node.on_peer_disconnected = lambda bd: self._on_log(f"peer down {bd}", False)
        self.node.on_log = self._on_log

        self._clients: list[_Client] = []
        self._clients_lock = threading.Lock()
        self._history: deque = deque(maxlen=HISTORY_LIMIT)
        self._history_lock = threading.Lock()
        self._last_view: tuple | None = None
        self._stopping = threading.Event()
        self._stopped = threading.Event()
        self._srv: socket.socket | None = None

        self._names = load_node_names()
        self._started_at = time.monotonic()
        # remote BD -> its last topology report, stamped with time.monotonic()
        self._topo: dict[str, dict] = {}
        # Last L2CAP neighbour set. A board that leaves it is off the map now,
        # not when its last report expires.
        self._linked: set[str] | None = None
        self._topo_lock = threading.Lock()
        self._topo_due = True
        self._topo_sent_at = float("-inf")
        self._last_topology: list | None = None
        self._restart_lock = threading.Lock()
        self._restarting = False
        self._restart_orders: set[str] = set()
        # bd -> epoch that member is still on (they never adopted the rekey).
        self._revoked: dict[str, int] = {}
        self._revoke_ids: set[str] = set()
        self._reset_ids: set[str] = set()
        self._excluded = False
        # Read by main() once run() returns: the process is replaced rather
        # than restarted in place, so nothing from the old mesh state survives.
        self.restart_requested = False
        # The controller looks cached-powered to MGMT for minutes after it
        # dies, so a watchdog restart reloads the driver unconditionally.
        self.rebind_requested = False

    # ---- BBNode callbacks (runtime threads) ----------------------------

    def _on_message(self, sender_bd: str, text: str) -> None:
        self._on_message_route(sender_bd, text, "", 0)

    def _on_message_route(self, sender_bd: str, text: str, via: str, hops: int) -> None:
        control = decode_control(text)
        if control is not None:
            self._on_control(sender_bd.upper(), control)
            return
        self._record_and_broadcast(sender_bd, text, mine=False, via=via, hops=hops)

    def _on_log(self, text: str, is_err: bool) -> None:
        self._broadcast({"ev": "log", "text": str(text), "error": bool(is_err)})

    def _record_and_broadcast(
        self,
        sender: str,
        text: str,
        mine: bool,
        via: str = "",
        hops: int = 0,
        to: str = "",
        private: bool = False,
    ) -> None:
        dest = str(to or "").upper()
        frame = {
            "ev": "message",
            "from": sender,
            "name": self._name_of(sender),
            "text": text,
            "ts": time.time(),
            "mine": mine,
            "via": via,
            "via_name": self._name_of(via) if via else "",
            "hops": hops,
            "to": dest,
            "to_name": self._name_of(dest) if dest else "",
            "private": bool(private or dest),
        }
        with self._history_lock:
            self._history.append(frame)
        self._broadcast(frame)

    # ---- mesh control (topology, restart) -------------------------------

    def _local_identity(self) -> tuple[str, str]:
        local = str(self.node.local_bd_addr or "").upper()
        if local in self._names:
            return self._names[local]
        return KIND_RELAY, socket.gethostname()

    def _name_of(self, bd: str) -> str:
        bd = str(bd or "").upper()
        if bd and bd == str(self.node.local_bd_addr or "").upper():
            return self._local_identity()[1]
        with self._topo_lock:
            report = self._topo.get(bd)
        if report and report["name"]:
            return report["name"]
        return self._names.get(bd, ("", bd))[1]

    def _on_control(self, src: str, body: dict) -> None:
        kind = body.get("t")
        if kind == "topo":
            peers = body.get("peers")
            if not isinstance(peers, list):
                return
            known = self._names.get(src, (KIND_RELAY, ""))
            report = {
                "peers": sorted({str(p).upper() for p in peers[:_TOPO_MAX_PEERS]}),
                "relay": bool(body.get("relay")),
                "name": str(body.get("name") or known[1])[:32],
                "kind": str(body.get("kind") or known[0])[:16],
                "seen": time.monotonic(),
            }
            with self._topo_lock:
                self._topo[src] = report
            pub = body.get("pub")
            if isinstance(pub, str) and pub:
                learn = getattr(self.node, "learn_peer_public_key", None)
                if callable(learn):
                    learn(src, pub)
            self._publish_topology()
        elif kind == "restart":
            self._on_restart_order(src, str(body.get("id", "")))
        elif kind == "revoke":
            self._on_revoke_order(str(body.get("id", "")), str(body.get("bd", "")))
        elif kind == "reset":
            self._on_reset_order(str(body.get("id", "")))

    def _forget_unplugged(self, peers: list[str]) -> None:
        """Drop a neighbour the moment our link to it is gone.

        Its own last report, and every cached peer list that still names it,
        would otherwise keep it drawn until ``_TOPO_EXPIRY_S``.
        """
        current = set(peers)
        if self._linked is None:
            self._linked = current
            return
        lost = self._linked - current
        self._linked = current
        if not lost:
            return
        with self._topo_lock:
            for bd in lost:
                self._topo.pop(bd, None)
            for report in self._topo.values():
                report["peers"] = [p for p in report["peers"] if p not in lost]

    def _topology_nodes(self) -> list[dict]:
        now = time.monotonic()
        local = str(self.node.local_bd_addr or "").upper()
        peers, relay = ([], False) if self._last_view is None else (
            [p.upper() for p in self._last_view[0]], self._last_view[1])
        try:
            peers = [p.upper() for p in self.node.peers()]
        except Exception:  # noqa: BLE001 — node still starting
            pass
        self._forget_unplugged(peers)
        with self._topo_lock:
            for bd in [bd for bd, r in self._topo.items() if now - r["seen"] > _TOPO_EXPIRY_S]:
                del self._topo[bd]
            remote = {bd: dict(r) for bd, r in self._topo.items()}

        nodes = []
        if local:
            kind, name = self._local_identity()
            nodes.append({"bd": local, "name": name, "kind": kind,
                          "relay": relay, "peers": peers})
        for bd, r in sorted(remote.items()):
            if bd != local:
                nodes.append({"bd": bd, "name": r["name"], "kind": r["kind"],
                              "relay": r["relay"], "peers": r["peers"]})
        # A neighbour whose first report has not arrived yet is still on the map.
        known = {n["bd"] for n in nodes}
        mentioned = set(peers).union(*(r["peers"] for r in remote.values()))
        for bd in sorted(mentioned - known):
            kind, name = self._names.get(bd, (KIND_RELAY, bd))
            nodes.append({"bd": bd, "name": name, "kind": kind, "relay": False, "peers": []})
        return nodes

    def _publish_topology(self) -> None:
        nodes = self._topology_nodes()
        if nodes == self._last_topology:
            return
        self._last_topology = nodes
        self._broadcast(self._topology_frame(nodes))

    def _topology_frame(self, nodes: list | None = None) -> dict:
        return {
            "ev": "topology",
            "local": str(self.node.local_bd_addr or "").upper(),
            "nodes": self._topology_nodes() if nodes is None else nodes,
        }

    def _maybe_announce_topology(self) -> None:
        now = time.monotonic()
        if not self._topo_due and now - self._topo_sent_at < _TOPO_HEARTBEAT_S:
            return
        if now - self._topo_sent_at < _TOPO_MIN_GAP_S or self._last_view is None:
            return
        peers, relay = self._last_view[0], self._last_view[1]
        if not peers:
            return
        kind, name = self._local_identity()
        fields = {"peers": list(peers), "relay": relay, "name": name, "kind": kind}
        getter = getattr(self.node, "local_public_key_hex", None)
        pub = getter() if callable(getter) else ""
        if pub:
            fields["pub"] = pub
        try:
            self.node.send(encode_control("topo", **fields))
        except Exception:  # noqa: BLE001 — links dropping as we send
            return
        self._topo_sent_at = now
        self._topo_due = False

    def request_mesh_restart(self) -> None:
        """Restart every daemon in the mesh, this one included."""
        order = os.urandom(4).hex()
        with self._restart_lock:
            self._restart_orders.add(order)
        self._start_restart(order)

    def _on_restart_order(self, src: str, order: str) -> None:
        with self._restart_lock:
            if not order or order in self._restart_orders:
                return
            self._restart_orders.add(order)
        if time.monotonic() - self._started_at < _RESTART_GUARD_S:
            self._on_log(f"restart order from {src} ignored: just restarted", False)
            return
        # No need to pass it on: the forwarder has already relayed it.
        self._start_restart(None)

    def _start_restart(self, order: str | None) -> None:
        with self._restart_lock:
            if self._restarting:
                return
            self._restarting = True
        threading.Thread(target=self._restart_sequence, args=(order,), daemon=True).start()

    def _restart_sequence(self, order: str | None) -> None:
        self._broadcast({"ev": "restarting", "grace_s": _RESTART_GRACE_S})
        if order is not None:
            # Twice: a board recycling a link at that instant would miss a
            # single copy, and duplicates are dropped by id.
            for _ in range(2):
                try:
                    self.node.send(encode_control("restart", id=order))
                except Exception:  # noqa: BLE001 — alone: restart ourselves anyway
                    pass
                if self._stopping.wait(1.0):
                    return
        if self._stopping.wait(_RESTART_GRACE_S):
            return
        self.restart_requested = True
        self.shutdown()

    def request_revoke(self, bd_addr: str) -> None:
        """Exclude one member from the group. The coordinator rotates the key."""
        target = bd_addr.strip().upper()
        local = str(self.node.local_bd_addr or "").upper()
        if not target or target == local:
            raise RuntimeError("choose another board")
        if target in self._revoked:
            raise RuntimeError(f"{self._name_of(target)} is already revoked")
        order = os.urandom(4).hex()
        self._revoke_ids.add(order)
        epoch = int(self.node.current_epoch())
        self._mark_revoked(target, epoch)
        # On the current key, so the target still hears it, then the coordinator
        # rotates. A non-coordinator only asks; the coordinator rotates on receipt.
        notice = encode_control("revoke", id=order, bd=target)
        try:
            self.node.send_private_at_epoch(notice, target, epoch)
        except Exception as exc:  # noqa: BLE001
            self._on_log(f"revoke notice to {target}: {exc}", True)
        try:
            self.node.send(notice)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"revoke not sent: {exc}") from exc
        if self.node.is_coordinator():
            self.node.revoke_member(target)

    def _on_revoke_order(self, order: str, bd_addr: str) -> None:
        target = bd_addr.strip().upper()
        if not order or not target:
            return
        with self._restart_lock:
            if order in self._revoke_ids:
                return
            self._revoke_ids.add(order)
        self._mark_revoked(target, int(self.node.current_epoch()))
        if self.node.is_coordinator():
            self.node.revoke_member(target)

    def _mark_revoked(self, target: str, epoch: int) -> None:
        self._revoked[target] = epoch
        local = str(self.node.local_bd_addr or "").upper()
        if target == local:
            self._excluded = True
        self._broadcast({
            "ev": "revoked",
            "bd": target,
            "name": self._name_of(target),
            "self": target == local,
        })

    def request_demo_reset(self) -> None:
        """Everyone, including revoked members, back on the shared epoch-0 key."""
        order = os.urandom(4).hex()
        with self._restart_lock:
            self._reset_ids.add(order)
        self._perform_reset(order, tell_mesh=True)

    def _on_reset_order(self, order: str) -> None:
        if not order:
            return
        with self._restart_lock:
            if order in self._reset_ids:
                return
            self._reset_ids.add(order)
        self._perform_reset(order, tell_mesh=False)

    def _perform_reset(self, order: str, *, tell_mesh: bool) -> None:
        notice = encode_control("reset", id=order)
        # Revoked members cannot read the group anymore. Reach them on the
        # pairwise key of the epoch they are still on, before we wipe it.
        for bd, epoch in list(self._revoked.items()):
            if bd == str(self.node.local_bd_addr or "").upper():
                continue
            try:
                self.node.send_private_at_epoch(notice, bd, epoch)
            except Exception as exc:  # noqa: BLE001
                self._on_log(f"reset to {bd}: {exc}", True)
        if tell_mesh:
            try:
                self.node.send(notice)
            except Exception as exc:  # noqa: BLE001
                self._on_log(f"reset broadcast: {exc}", True)
        try:
            self.node.reset_group()
        except Exception as exc:  # noqa: BLE001
            self._on_log(f"reset group: {exc}", True)
        self._revoked.clear()
        self._excluded = False
        with self._history_lock:
            self._history.clear()
        self._broadcast({"ev": "demo_reset", "epoch": int(self.node.current_epoch())})

    def _health_loop(self) -> None:
        failures = 0
        while not self._stopping.wait(_HEALTH_INTERVAL_S):
            try:
                reason = self._health.problem()
            except Exception as exc:  # noqa: BLE001
                reason = f"health check error: {exc}"
            if reason is None:
                failures = 0
                continue
            failures += 1
            self._on_log(f"controller check failed ({failures}/{_HEALTH_FAILURES}): {reason}", True)
            if failures >= _HEALTH_FAILURES:
                self._on_log("controller unresponsive: reloading its driver", True)
                self.rebind_requested = True
                # Local only: the rest of the mesh is fine.
                self._start_restart(None)
                return

    # ---- fan-out --------------------------------------------------------

    def _broadcast(self, frame: dict) -> None:
        with self._clients_lock:
            clients = list(self._clients)
        for c in clients:
            c.send(frame)

    def _poll_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                view = (
                    tuple(sorted(self.node.peers())),
                    bool(self.node.is_relay()),
                    str(self.node.local_bd_addr or ""),
                    int(self.node.current_epoch()),
                )
            except Exception:  # noqa: BLE001 — node still starting up
                self._stopping.wait(_POLL_INTERVAL_S)
                continue
            if view[:2] != (self._last_view or (None, None))[:2]:
                self._topo_due = True
            if view != self._last_view:
                self._last_view = view
                peers, relay, local, epoch = view
                # local and epoch ride along because the socket is bound before
                # the node has finished starting: a client that connects during
                # those seconds gets a hello with no address, and this is what
                # corrects it.
                self._broadcast({
                    "ev": "peers",
                    "peers": list(peers),
                    "relay": relay,
                    "local": local,
                    "epoch": epoch,
                })
            self._maybe_announce_topology()
            self._publish_topology()
            self._stopping.wait(_POLL_INTERVAL_S)

    # ---- client handling ------------------------------------------------

    def _hello_frame(self) -> dict:
        try:
            peers = sorted(self.node.peers())
            relay = bool(self.node.is_relay())
            epoch = int(self.node.current_epoch())
        except Exception:  # noqa: BLE001
            peers, relay, epoch = [], False, 0
        with self._history_lock:
            history = list(self._history)
        return {
            "ev": "hello",
            "local": str(self.node.local_bd_addr or ""),
            "relay": relay,
            "epoch": epoch,
            "peers": peers,
            "history": history,
            "revoked": sorted(self._revoked),
            "excluded": self._excluded,
        }

    def _serve_client(self, client: _Client) -> None:
        threading.Thread(target=client.writer_loop, daemon=True).start()
        client.send(self._hello_frame())
        client.send(self._topology_frame())
        for frame in read_frames(client.sock):
            if not client.alive:
                break
            self._handle_command(client, frame)
        client.alive = False
        with self._clients_lock:
            if client in self._clients:
                self._clients.remove(client)

    def _handle_command(self, client: _Client, frame: dict) -> None:
        cmd = frame.get("cmd")
        req_id = frame.get("id")
        if cmd == "send":
            # strip() also eats the \x1e that opens CONTROL_PREFIX, which is
            # what keeps a client from posting a control message as chat.
            text = str(frame.get("text", "")).strip()
            if not text:
                client.send({"ev": "ack", "id": req_id, "ok": False, "error": "empty"})
                return
            dest = str(frame.get("to") or "").strip().upper()
            try:
                if dest:
                    epoch = int(self.node.current_epoch())
                    self.node.send_private_at_epoch(text, dest, epoch)
                else:
                    self.node.send(text)
            except Exception as e:  # noqa: BLE001 — no peer yet is the common case
                client.send({"ev": "ack", "id": req_id, "ok": False, "error": str(e)})
                return
            client.send({"ev": "ack", "id": req_id, "ok": True, "error": ""})
            # Locally sent messages never come back through on_message, so echo
            # them here — that way every connected UI shows the same thread.
            self._record_and_broadcast(
                self.node.local_bd_addr, text, mine=True, to=dest, private=bool(dest)
            )
        elif cmd == "status":
            client.send(self._hello_frame())
        elif cmd == "restart_mesh":
            client.send({"ev": "ack", "id": req_id, "ok": True, "error": ""})
            self._on_log("mesh restart requested from the UI", False)
            self.request_mesh_restart()
        elif cmd == "revoke":
            client.send({"ev": "ack", "id": req_id, "ok": True, "error": ""})
            try:
                self.request_revoke(str(frame.get("bd", "")))
            except Exception as e:  # noqa: BLE001
                self._broadcast({"ev": "ack", "id": req_id, "ok": False, "error": str(e)})
        elif cmd == "reset_demo":
            client.send({"ev": "ack", "id": req_id, "ok": True, "error": ""})
            try:
                self.request_demo_reset()
            except Exception as e:  # noqa: BLE001
                self._broadcast({"ev": "ack", "id": req_id, "ok": False, "error": str(e)})
        else:
            client.send({"ev": "ack", "id": req_id, "ok": False, "error": "unknown command"})

    # ---- lifecycle ------------------------------------------------------

    def _bind(self, group: str | None) -> socket.socket:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(self.path):
            os.unlink(self.path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        srv.listen(8)

        # The UI runs unprivileged, so hand it group access rather than making
        # the socket world-writable — anyone who can write here can post to the
        # group chat as this board. Only root may chown, so the fake daemon used
        # for UI development just keeps the socket owned by its own user.
        if os.geteuid() == 0:
            gid = -1
            if group:
                gid = grp.getgrnam(group).gr_gid
            elif os.environ.get("SUDO_GID"):
                gid = int(os.environ["SUDO_GID"])
            if gid != -1:
                os.chown(self.path, 0, gid)
        os.chmod(self.path, 0o660)
        return srv

    def run(self, group: str | None, accept_all: bool) -> int:
        self._srv = self._bind(group)
        self.node.start(l2cap_accept_all=accept_all)
        threading.Thread(target=self._poll_loop, daemon=True).start()
        if self._health is not None:
            threading.Thread(target=self._health_loop, daemon=True).start()

        print(f"meshd local={self.node.local_bd_addr} socket={self.path}", flush=True)

        try:
            while not self._stopping.is_set():
                try:
                    conn, _ = self._srv.accept()
                except OSError:
                    break
                client = _Client(conn)
                with self._clients_lock:
                    self._clients.append(client)
                threading.Thread(target=self._serve_client, args=(client,), daemon=True).start()
        finally:
            self.shutdown()
            # A restart shuts down from its own thread; the node must be fully
            # stopped before main() replaces the process.
            self._stopped.wait(15.0)
        return 0

    def shutdown(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._srv is not None:
            # close() alone does not wake an accept() blocked in another thread.
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._srv.close()
            except OSError:
                pass
        with self._clients_lock:
            for c in self._clients:
                c.alive = False
            self._clients.clear()
        try:
            self.node.stop()
        except Exception:  # noqa: BLE001
            pass
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass
        self._stopped.set()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interface", default="hci0")
    ap.add_argument("--socket", default=socket_path(), help="AF_UNIX path")
    ap.add_argument("--group", default=None, help="group granted access to the socket")
    ap.add_argument(
        "--no-accept-all",
        action="store_true",
        help="refuse inbound L2CAP (dial-only node)",
    )
    ap.add_argument(
        "--link-role",
        choices=("auto", "any", "central", "peripheral"),
        default=None,
        help="which side of BLE links this board takes (default: detect from the "
        "controller; 'peripheral' on the stand screens keeps traffic on the relays)",
    )
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("meshd needs root for L2CAP and MGMT", file=sys.stderr)
        return 1
    if args.link_role:
        os.environ["BUBBLE_BLUE_LINK_ROLE"] = args.link_role
    _remember_controller(args.interface)

    daemon = MeshDaemon(args.interface, args.socket)

    def _bye(_signum, _frame):
        daemon.shutdown()

    signal.signal(signal.SIGINT, _bye)
    signal.signal(signal.SIGTERM, _bye)
    try:
        rc = daemon.run(args.group, accept_all=not args.no_accept_all)
    except Exception:  # noqa: BLE001
        # Typically "add-adv failed": a dead controller that MGMT still lists.
        # Exit afterwards and let systemd space out the retries.
        traceback.print_exc()
        print("meshd: startup failed, reloading the controller", flush=True)
        recover_controller(args.interface)
        return 1
    if daemon.restart_requested:
        reexec(restart_bluez=True, interface=args.interface, rebind=daemon.rebind_requested)
    return rc


def _adapter_powered(index: int) -> bool:
    try:
        out = subprocess.run(
            ["btmgmt", "--index", str(index), "info"],
            capture_output=True, text=True, input="", timeout=5, check=False,
        ).stdout
    except subprocess.TimeoutExpired:
        return False
    return any("current settings:" in ln and "powered" in ln for ln in out.splitlines())


_CONTROLLER_ENV = "BB_CONTROLLER_SYSFS"


def _remember_controller(interface: str) -> None:
    """Record which driver owns the adapter while it still exists in sysfs.

    Kept in the environment, which survives the re-exec, because an unbound
    controller no longer shows up under /sys/class/bluetooth at all.
    """
    device = os.path.realpath(f"/sys/class/bluetooth/{interface}/device")
    driver = os.path.realpath(os.path.join(device, "driver"))
    if os.path.isdir(driver):
        os.environ[_CONTROLLER_ENV] = f"{driver}:{os.path.basename(device)}"


def _rebind_controller(interface: str) -> None:
    """Re-probe the adapter's driver, which reloads the controller firmware."""
    _remember_controller(interface)
    driver, _, name = os.environ.get(_CONTROLLER_ENV, "").rpartition(":")
    if not driver or not os.path.isdir(driver):
        print(f"meshd: no driver known for {interface}, cannot rebind", flush=True)
        return
    print(f"meshd: rebinding {name} to {driver}", flush=True)
    for action in ("unbind", "bind"):
        try:
            with open(os.path.join(driver, action), "w") as fh:
                fh.write(name)
        except OSError as e:
            print(f"meshd: {action} {name}: {e}", flush=True)
        time.sleep(2.0)


def recover_controller(interface: str) -> None:
    """Reload a dead controller's driver and bring BlueZ back up on it."""
    subprocess.run(["pkill", "-x", "btmgmt"], check=False)
    _rebind_controller(interface)
    subprocess.run(["systemctl", "restart", "bluetooth"], check=False, timeout=30)


def reexec(restart_bluez: bool, interface: str = "hci0", rebind: bool = False) -> None:
    """Replace this process with a fresh daemon, same command line."""
    if restart_bluez:
        # BlueZ too: restarting it is what clears half-open LE connections,
        # which a new daemon would otherwise inherit.
        subprocess.run(["pkill", "-x", "btmgmt"], check=False)
        if rebind:
            _rebind_controller(interface)
        subprocess.run(["systemctl", "restart", "bluetooth"], check=False, timeout=30)
        index = hci_index_from_interface(interface)
        # The UNO Q's controller can wedge for good (firmware reads time out,
        # the index vanishes from MGMT); only reloading its firmware helps.
        for attempt in range(2):
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not _adapter_powered(index):
                time.sleep(1.0)
            if _adapter_powered(index) or attempt:
                break
            _rebind_controller(interface)
            subprocess.run(["systemctl", "restart", "bluetooth"], check=False, timeout=30)
        time.sleep(2.0)
    print("meshd restarting", flush=True)
    # orig_argv keeps argv[0] as typed, so the process still matches
    # `pgrep -f '^python3.14 apps/meshd'` afterwards.
    os.execv(sys.executable, sys.orig_argv)


if __name__ == "__main__":
    raise SystemExit(main())
