"""
TimedEngine — SimPy-driven harness for real HelloManager instances.

Mirrors ``sim.sim_engine.SimEngine`` / ``SimNode`` but drives Hellos from
per-node SimPy processes (asynchronous, jittered) instead of synchronous
``step()`` rounds. No CDS or Hello logic is reimplemented here.
"""

from __future__ import annotations

import os
import random
import tempfile
from collections.abc import Generator
from dataclasses import replace

import simpy

from config import PKT_HELLO, load_config
from src.control.hello_manager import HelloManager
from src.forwarding.cds import CDSAlgorithm
from src.security.epoch import EpochStore
from src.security.keys import BBKeyStore

from sim.sim_engine import SimEngine, _GK
from sim.sim_transport import Position
from sim.timed.timed_bus import TimedBus


class TimedTransport:
    """Per-node façade for HelloManager over a ``TimedBus`` (same surface as ``SimTransport``)."""

    def __init__(self, bus: TimedBus, bd_addr: str) -> None:
        self.bus = bus
        self.bd = bd_addr.upper()
        self.sent_count = 0

    def connections(self) -> list[str]:
        return [bd.upper() for bd in self.bus.neighbors(self.bd)]

    def send(self, bd_addr: str, data: bytes) -> None:
        self.sent_count += 1
        self.bus.deliver(self.bd, bd_addr.upper(), bytes(data))


class TimedNode:
    """
    One simulated node: real HelloManager on a ``TimedTransport``, no background thread.

    CDS role is read from ``hello_mgr.is_relay`` (same path as ``SimNode``).
    Hellos are emitted by the SimPy ``hello_process`` generator, not ``HelloManager.start()``.
    """

    def __init__(
        self,
        env: simpy.Environment,
        bus: TimedBus,
        bd_addr: str,
        position: Position,
        *,
        hello_interval_s: float = 5.0,
        jitter_frac: float = 0.1,
        group_key: bytes = _GK,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
        rng: random.Random | None = None,
    ) -> None:
        self._env = env
        self.bd = bd_addr.upper()
        self.algorithm = algorithm
        self._hello_interval_s = max(0.001, float(hello_interval_s))
        self._jitter_frac = max(0.0, float(jitter_frac))
        self._rng = rng if rng is not None else random.Random(0)

        self.transport = TimedTransport(bus, self.bd)
        bus.register(self.bd, position, self._on_receive)

        cfg = replace(
            load_config(),
            group_key=group_key,
            local_bd_addr=self.bd,
            remote_bd_addr="00:00:00:00:00:00",
            hello_interval_s=self._hello_interval_s,
            neighbor_timeout_s=30,
        )
        key_store = BBKeyStore.from_group_key(group_key, self.bd)
        fd, path = tempfile.mkstemp(prefix="bb-timed-epoch-")
        os.close(fd)
        epoch_store = EpochStore(group_key, persist_path=path, local_bd_addr=self.bd)

        self.hello_mgr = HelloManager(
            cfg,
            self.transport,
            key_store,
            epoch_store,
            quiet=True,
            cds_algorithm=algorithm,
        )

    def _on_receive(self, peer: str, data: bytes) -> None:
        if data and data[0] == PKT_HELLO:
            self.hello_mgr.on_receive(peer, data)

    def refresh_role(self) -> None:
        self.hello_mgr.refresh_cds_role(verbose=False)

    def role(self) -> str:
        return "RELAY" if self.hello_mgr.is_relay else "LEAF"

    def hello_process(self) -> Generator[simpy.events.Event, None, None]:
        """Periodic Hello emission and CDS refresh on the SimPy clock."""
        while True:
            self.hello_mgr._send_hellos()
            self.refresh_role()
            jitter = self._rng.uniform(-self._jitter_frac, self._jitter_frac) * self._hello_interval_s
            yield self._env.timeout(self._hello_interval_s + jitter)


class TimedEngine:
    """
    Event-driven simulation harness: one real HelloManager per node, SimPy clock.

    Each node runs an independent ``hello_process`` so Hellos interleave according
    to simulated time (unlike synchronous ``SimEngine.step()``).
    """

    def __init__(
        self,
        positions: dict[str, Position],
        radius: float,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
        *,
        hello_interval_s: float = 5.0,
        jitter_frac: float = 0.1,
        tx_latency_s: float = 0.003,
        loss_prob: float = 0.0,
        seed: int = 0,
        group_key: bytes = _GK,
    ) -> None:
        self.algorithm = algorithm
        self.group_key = group_key
        self.env = simpy.Environment()
        bus_rng = random.Random(seed)
        self.bus = TimedBus(
            self.env,
            radius,
            tx_latency_s=tx_latency_s,
            loss_prob=loss_prob,
            rng=bus_rng,
        )
        self.nodes: dict[str, TimedNode] = {}
        for index, bd in enumerate(sorted(positions)):
            node_seed = seed * 1_000_003 + index
            self.nodes[bd.upper()] = TimedNode(
                self.env,
                self.bus,
                bd,
                positions[bd],
                hello_interval_s=hello_interval_s,
                jitter_frac=jitter_frac,
                group_key=group_key,
                algorithm=algorithm,
                rng=random.Random(node_seed),
            )
            self.env.process(self.nodes[bd.upper()].hello_process())

    @property
    def now(self) -> float:
        return self.env.now

    def run_for(self, duration_s: float) -> None:
        """Advance simulated time by ``duration_s``."""
        duration = max(0.0, float(duration_s))
        self.env.run(until=self.env.now + duration)

    def roles(self) -> dict[str, str]:
        return {bd: node.role() for bd, node in sorted(self.nodes.items())}


if __name__ == "__main__":
    A, B, C = "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"
    positions = {A: (0.0, 0.0), B: (1.0, 0.0), C: (2.0, 0.0)}
    algorithm = CDSAlgorithm.WU_LI_1999

    round_engine = SimEngine(positions, radius=1.0, algorithm=algorithm)
    round_result = round_engine.run_until_stable(max_steps=20)
    round_roles = round_engine.roles()

    timed_engine = TimedEngine(
        positions,
        radius=1.0,
        algorithm=algorithm,
        hello_interval_s=5.0,
        jitter_frac=0.1,
        tx_latency_s=0.003,
        loss_prob=0.0,
        seed=0,
    )
    timed_engine.run_for(30.0)
    timed_roles = timed_engine.roles()

    print(f"round-based: {round_result.status} in {round_result.steps} step(s) → {round_roles}")
    print(f"timed (t={timed_engine.now:.1f}s): {timed_roles}")

    assert round_result.status == "fixed_point", round_result
    assert round_roles[B] == "RELAY", round_roles
    assert round_roles[A] == "LEAF" and round_roles[C] == "LEAF"

    assert timed_roles == round_roles, f"timed roles {timed_roles} != round {round_roles}"
    print("\n✅ timed_engine line-3 matches round-based SimEngine")
