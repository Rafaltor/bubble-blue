from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, replace

from config import PKT_HELLO, load_config
from src.control.hello_manager import HelloManager
from src.forwarding.cds import CDSAlgorithm
from src.security.epoch import EpochStore
from src.security.keys import BBKeyStore

from sim.sim_transport import Position, SimBus, SimTransport

# Shared bootstrap group key for deterministic anon_ids across the simulation.
_GK = b"\x42" * 32

RoleSnapshot = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ConvergenceResult:
    """
    Outcome of ``run_until_stable``.

    ``steps``: step index where convergence was detected (or ``max_steps``).
    ``status``: ``fixed_point`` (period-1), ``cycle`` (periodic oscillation), or
        ``max_steps`` (no pattern within the limit).
    ``period``: 1 for a fixed point, k for a cycle of period k, 0 if ``max_steps``.
    """

    steps: int
    status: str
    period: int


def _roles_snapshot(engine: SimEngine) -> RoleSnapshot:
    return tuple(sorted(engine.roles().items()))


class SimNode:
    """
    One simulated node: real HelloManager on a SimTransport, no background thread.

    CDS role is a single source of truth: ``hello_mgr.is_relay`` under the
    ``cds_algorithm`` passed to HelloManager (same path a real forwarder uses).
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
            cfg,
            self.transport,
            key_store,
            epoch_store,
            quiet=True,
            cds_algorithm=algorithm,
        )

    def _on_receive(self, peer: str, data: bytes) -> None:
        """Inbound packet hook called synchronously by SimBus.deliver."""
        if data and data[0] == PKT_HELLO:
            self.hello_mgr.on_receive(peer, data)

    def refresh_role(self) -> None:
        """Recompute RELAY/LEAF via HelloManager (configured CDS algorithm)."""
        self.hello_mgr.refresh_cds_role(verbose=False)

    def role(self) -> str:
        """Current CDS role under the configured algorithm."""
        return "RELAY" if self.hello_mgr.is_relay else "LEAF"


class SimEngine:
    """
    Discrete-time simulation harness: one real HelloManager per node, no threads.

    CDS algorithm selection is carried by HelloManager (``cds_algorithm``). Each
    node's ``hello_mgr.is_relay`` is the single source of truth for relay/leaf
    decisions — the same value a PacketForwarder wired to that HelloManager would
    use. ``SimNode.role()`` reads ``hello_mgr.is_relay`` directly; there is no
    separate parallel CDS computation in the sim.
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

    def run_until_stable(self, max_steps: int = 100) -> ConvergenceResult:
        """
        Run ``step()`` until role snapshots repeat.

        Detects three outcomes:
          - ``fixed_point``: current snapshot equals the immediately previous one
            (period 1).
          - ``cycle``: current snapshot equals an earlier one at distance k > 1
            (period k). Relevant for MPR on static topologies where roles can
            oscillate RELAY/LEAF with period >= 2.
          - ``max_steps``: limit reached with no repeated snapshot (period 0).

        The return value exposes ``.steps`` for callers that only need the step
        count (backward-compatible with the former ``int`` return).
        """
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")

        history: list[RoleSnapshot] = [_roles_snapshot(self)]
        for step in range(1, max_steps + 1):
            self.step()
            snapshot = _roles_snapshot(self)

            if snapshot == history[-1]:
                return ConvergenceResult(
                    steps=step, status="fixed_point", period=1
                )

            for i, prior in enumerate(history):
                if snapshot == prior:
                    period = len(history) - i
                    if period > 1:
                        return ConvergenceResult(
                            steps=step, status="cycle", period=period
                        )
                    break

            history.append(snapshot)

        return ConvergenceResult(steps=max_steps, status="max_steps", period=0)


if __name__ == "__main__":
    # Line A — B — C (x=0,1,2 ; R=1.0): A↔B, B↔C, not A↔C.
    # Wu-Li on a static line reaches a fixed point (no oscillation).
    #
    # Under MPR, ``run_until_stable`` may report status ``cycle`` instead: that is
    # not a sim bug but an election-algorithm instability (roles alternating
    # RELAY/LEAF with period >= 2). Such cycles are data for mobility/stability
    # analysis in the rapport — the sim's job is to detect and report them.
    A, B, C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"
    positions = {A: (0.0, 0.0), B: (1.0, 0.0), C: (2.0, 0.0)}

    engine = SimEngine(positions, radius=1.0, algorithm=CDSAlgorithm.WU_LI_1999)
    result = engine.run_until_stable(max_steps=20)
    roles = engine.roles()

    print(f"topology: { {bd: engine.bus.neighbors(bd) for bd in sorted(engine.nodes)} }")
    print(
        f"convergence: {result.status} in {result.steps} step(s)"
        f" (period={result.period})"
    )
    for bd in sorted(roles):
        print(f"  {bd}  → {roles[bd]}")

    assert result.status == "fixed_point", f"expected fixed point, got {result}"
    assert roles[B] == "RELAY", f"expected bridge B to RELAY, got {roles}"
    assert roles[A] == "LEAF" and roles[C] == "LEAF"
    print("\n✅ sim_engine line-3 self-test passed")
