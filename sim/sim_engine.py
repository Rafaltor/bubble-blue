from __future__ import annotations

import os
import tempfile
from dataclasses import replace

from config import PKT_HELLO, load_config
from src.control.hello import compute_anon_id
from src.control.hello_manager import HelloManager
from src.forwarding.cds import CDSAlgorithm, am_i_cds
from src.security.epoch import EpochStore
from src.security.keys import BBKeyStore

from sim.sim_transport import Position, SimBus, SimTransport

# Shared bootstrap group key for deterministic anon_ids across the simulation.
_GK = b"\x42" * 32


class SimNode:
    """
    One simulated node: real HelloManager on a SimTransport, no background thread.

    The CDS role exposed by ``role()`` is computed by the simulation engine via
    ``am_i_cds(..., algorithm=...)`` (approach b below), not via
    ``hello_mgr.is_relay``, because HelloManager.refresh_cds_role() always calls
    ``am_i_cds`` with the default ``WU_LI_1999`` and has no algorithm parameter.
    """

    def __init__(
        self,
        bus: SimBus,
        bd_addr: str,
        position: Position,
        *,
        group_key: bytes = _GK,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
    ) -> None:
        self.bd = bd_addr.upper()
        self.algorithm = algorithm
        self._group_key = group_key
        self.transport: SimTransport = bus.register(self.bd, position, self._on_receive)

        cfg = replace(
            load_config(),
            group_key=group_key,
            local_bd_addr=self.bd,
            remote_bd_addr="00:00:00:00:00:00",
            hello_interval_s=1,
            neighbor_timeout_s=30,
        )
        key_store = BBKeyStore.from_group_key(group_key, self.bd)
        fd, path = tempfile.mkstemp(prefix="bb-sim-epoch-")
        os.close(fd)
        epoch_store = EpochStore(group_key, persist_path=path, local_bd_addr=self.bd)

        # Real HelloManager — do NOT call .start(); the sim drives _send_hellos().
        self.hello_mgr = HelloManager(
            cfg, self.transport, key_store, epoch_store, quiet=True
        )
        self._relay = False
        self.refresh_role()

    def _on_receive(self, peer: str, data: bytes) -> None:
        """Inbound packet hook called synchronously by SimBus.deliver."""
        if data and data[0] == PKT_HELLO:
            self.hello_mgr.on_receive(peer, data)
            # hello_mgr.on_receive also calls refresh_cds_role() with WU_LI_1999;
            # the engine recomputes the authoritative role after each step().

    def refresh_role(self) -> None:
        """
        Recompute RELAY/LEAF with the engine's CDS algorithm (approach b).

        Peers are the nodes currently in radio range (transport.connections()),
        mapped to anon_ids with the same bootstrap key HelloManager uses.
        """
        peer_aids = frozenset(
            compute_anon_id(self._group_key, bd) for bd in self.transport.connections()
        )
        self._relay = am_i_cds(
            self.hello_mgr.anon_id,
            self.hello_mgr.table,
            peer_aids,
            algorithm=self.algorithm,
        )

    def role(self) -> str:
        """Current CDS role under the engine's algorithm."""
        return "RELAY" if self._relay else "LEAF"


class SimEngine:
    """
    Discrete-time simulation harness: one real HelloManager per node, no threads.

    CDS algorithm selection — approach (b), without modifying hello_manager.py:
      HelloManager.refresh_cds_role() calls ``am_i_cds`` with the default
      ``WU_LI_1999`` only. To run ``MPR`` (or any non-default algorithm) in the
      sim, each ``step()`` ends with ``SimNode.refresh_role()``, which calls
      ``am_i_cds(..., algorithm=self.algorithm)`` directly on the node's received-
      only NeighborTable and its in-range peer anon_ids. ``roles()`` therefore
      reflect the requested ``CDSAlgorithm``, not ``hello_mgr.is_relay``.
    """

    def __init__(
        self,
        positions: dict[str, Position],
        radius: float,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
        *,
        group_key: bytes = _GK,
    ) -> None:
        self.algorithm = algorithm
        self.group_key = group_key
        self.bus = SimBus(radius=radius)
        self.nodes: dict[str, SimNode] = {}
        for bd in sorted(positions):
            self.nodes[bd.upper()] = SimNode(
                self.bus,
                bd,
                positions[bd],
                group_key=group_key,
                algorithm=algorithm,
            )

    def step(self) -> None:
        """
        One discrete Hello cycle: every node sends Hellos, then roles refresh.

        Delivery is synchronous (SimBus.deliver), so all Hellos propagate before
        role recomputation within this call.
        """
        for bd in sorted(self.nodes):
            self.nodes[bd].hello_mgr._send_hellos()
        for bd in sorted(self.nodes):
            self.nodes[bd].refresh_role()

    def roles(self) -> dict[str, str]:
        """Current RELAY/LEAF map (bd_addr upper-case -> role string)."""
        return {bd: node.role() for bd, node in sorted(self.nodes.items())}

    def run_until_stable(self, max_steps: int = 100) -> int:
        """
        Run ``step()`` until roles are unchanged between two consecutive cycles.

        Returns the step count at which stability was reached (>= 1), or
        ``max_steps`` if roles never stabilized within the limit.
        """
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")

        prev = self.roles()
        for step in range(1, max_steps + 1):
            self.step()
            current = self.roles()
            if current == prev:
                return step
            prev = current
        return max_steps


if __name__ == "__main__":
    # Line A — B — C (x=0,1,2 ; R=1.0): A↔B, B↔C, not A↔C.
    A, B, C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"
    positions = {A: (0.0, 0.0), B: (1.0, 0.0), C: (2.0, 0.0)}

    engine = SimEngine(positions, radius=1.0, algorithm=CDSAlgorithm.WU_LI_1999)
    steps = engine.run_until_stable(max_steps=20)
    roles = engine.roles()

    print(f"topology: { {bd: engine.bus.neighbors(bd) for bd in sorted(engine.nodes)} }")
    print(f"converged in {steps} step(s)")
    for bd in sorted(roles):
        print(f"  {bd}  → {roles[bd]}")

    assert roles[B] == "RELAY", f"expected bridge B to RELAY, got {roles}"
    assert roles[A] == "LEAF" and roles[C] == "LEAF"
    print("\n✅ sim_engine line-3 self-test passed")
