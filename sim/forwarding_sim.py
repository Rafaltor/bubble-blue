from __future__ import annotations

"""
Broadcast forwarding overhead harness — real PacketForwarder on SimTransport.

The simulator converges Hellos (CDS roles + neighbor tables), then injects one
group broadcast via ``PacketForwarder.send_broadcast``. Propagation is entirely
handled by ``forwarder.handle`` / relay logic in ``src/forwarding/forwarder.py``;
this module does not reimplement flooding.

Data unicast overhead is measured via ``SimBus.data_unicast_count`` (incremented
only when ``deliver()`` sees ``data[0] == PKT_DATA``), so Hello traffic is
excluded from broadcast cost metrics.
"""

import os
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Any

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import (  # noqa: E402
    PKT_ANNOUNCE,
    PKT_DATA,
    PKT_HELLO,
    PKT_REKEY,
    PKT_REKEY_FLOOD,
    PKT_SUBGROUP,
    load_config,
)
from src.control.hello_manager import HelloManager  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402
from src.forwarding.forwarder import PacketForwarder  # noqa: E402
from src.security.epoch import EpochStore  # noqa: E402
from src.security.keys import BBKeyStore  # noqa: E402

from sim.sim_engine import ConvergenceResult, SimEngine, _GK  # noqa: E402
from sim.sim_transport import DataLogEvent, Position, SimBus, SimTransport  # noqa: E402

_FWD_PKT_TYPES = frozenset(
    {PKT_DATA, PKT_SUBGROUP, PKT_REKEY, PKT_ANNOUNCE, PKT_REKEY_FLOOD}
)


def reconstruct_waves_from_log(
    log: list[DataLogEvent],
    source_bd: str,
    *,
    fallback_initial_ttl: int | None = None,
) -> dict[str, Any]:
    """
    Group passive ``SimBus`` PKT_DATA events into propagation waves.

    ``wave_index = initial_ttl - event_ttl`` where ``initial_ttl`` is read from
    the maximum TTL on packets first emitted by ``source_bd`` (robust to cfg).
    """
    src = source_bd.upper()
    source_events = [e for e in log if e["from"] == src]
    if source_events:
        initial_ttl = max(int(e["ttl"]) for e in source_events)
    elif fallback_initial_ttl is not None:
        initial_ttl = fallback_initial_ttl
    else:
        raise ValueError("cannot infer initial TTL: no source emissions in log")

    by_wave: dict[int, list[DataLogEvent]] = defaultdict(list)
    for event in log:
        wave_idx = initial_ttl - int(event["ttl"])
        by_wave[wave_idx].append(event)

    cumulative: set[str] = set()
    waves_out: list[dict[str, Any]] = []
    for wave_idx in sorted(by_wave):
        events = by_wave[wave_idx]
        unicasts = [
            {
                "from": e["from"],
                "to": e["to"],
                "delivered": bool(e["delivered_in_range"]),
            }
            for e in events
        ]
        newly: set[str] = set()
        for e in events:
            if e["delivered_in_range"] and e["to"] != src and e["to"] not in cumulative:
                newly.add(e["to"])
        cumulative |= newly
        waves_out.append(
            {
                "wave": wave_idx,
                "unicasts": unicasts,
                "newly_reached": sorted(newly),
                "cumulative_reached": sorted(cumulative),
            }
        )

    return {
        "initial_ttl": initial_ttl,
        "n_waves": len(waves_out),
        "waves": waves_out,
        "total_unicasts": len(log),
    }


def delivery_depth_from_waves(waves: list[dict[str, Any]]) -> int:
    """
    Last wave index (1-based count) that adds at least one newly reached node.

    ``n_waves`` may exceed this when deduplicated relays emit after full coverage
    (real unicast overhead, not delivery latency).
    """
    last_progress = -1
    for w in waves:
        if w.get("newly_reached"):
            last_progress = int(w["wave"])
    return last_progress + 1 if last_progress >= 0 else 0


@dataclass(frozen=True)
class BroadcastMetrics:
    """Outcome of one ``measure_broadcast`` call."""

    backbone_size: int
    data_unicasts: int
    receivers: frozenset[str]
    delivery_ratio: float
    convergence_status: str
    source_bd: str
    algorithm: str


class ForwardingSimNode:
    """
    Simulated node with real HelloManager + PacketForwarder on one SimTransport.

    Inbound routing (wired in ``_on_receive``):
      PKT_HELLO  → hello_mgr.on_receive
      PKT_DATA / PKT_SUBGROUP / PKT_REKEY / PKT_ANNOUNCE / PKT_REKEY_FLOOD
      → forwarder.handle
    """

    def __init__(
        self,
        bus: SimBus,
        bd_addr: str,
        position: Position,
        *,
        group_key: bytes = _GK,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
        ttl_max: int = 10,
    ) -> None:
        self.bd = bd_addr.upper()
        self.algorithm = algorithm
        self.transport: SimTransport = bus.register(self.bd, position, self._on_receive)
        self.delivered: list[tuple[str, str]] = []

        self.cfg = replace(
            load_config(),
            group_key=group_key,
            local_bd_addr=self.bd,
            remote_bd_addr="00:00:00:00:00:00",
            hello_interval_s=1,
            neighbor_timeout_s=30,
            ttl_max=ttl_max,
        )
        key_store = BBKeyStore.from_group_key(group_key, self.bd)
        fd, path = tempfile.mkstemp(prefix="bb-fwd-sim-epoch-")
        os.close(fd)
        epoch_store = EpochStore(group_key, persist_path=path, local_bd_addr=self.bd)

        self.hello_mgr = HelloManager(
            self.cfg,
            self.transport,
            key_store,
            epoch_store,
            quiet=True,
            cds_algorithm=algorithm,
        )
        self.forwarder = PacketForwarder(
            self.cfg,
            self.transport,
            self.hello_mgr,
            on_message=self._on_message,
        )
        # BBNode wires this; without it a member that misses the revocation
        # flood is never caught up, and the simulation invents a security
        # partition the deployed code does not have.
        self.hello_mgr.set_rekey_catchup(self.forwarder.send_rekey_catchup)

    def _on_receive(self, peer: str, data: bytes) -> None:
        if not data:
            return
        pkt_type = data[0]
        if pkt_type == PKT_HELLO:
            self.hello_mgr.on_receive(peer, data)
        elif pkt_type in _FWD_PKT_TYPES:
            self.forwarder.handle(peer, data)

    def _on_message(self, src_bd: str, text: str) -> None:
        self.delivered.append((src_bd.upper(), text))

    def refresh_role(self) -> None:
        self.hello_mgr.refresh_cds_role(verbose=False)

    def role(self) -> str:
        return "RELAY" if self.hello_mgr.is_relay else "LEAF"


class ForwardingSimEngine(SimEngine):
    """
    SimEngine variant whose nodes carry PacketForwarders for broadcast measurement.

    Call ``converge()`` before ``measure_broadcast()`` so CDS roles and Hello
    state are stable; no further Hellos are sent during measurement.
    """

    def __init__(
        self,
        positions: dict[str, Position],
        radius: float,
        algorithm: CDSAlgorithm = CDSAlgorithm.WU_LI_1999,
        *,
        group_key: bytes = _GK,
        ttl_max: int = 10,
    ) -> None:
        self.algorithm = algorithm
        self.group_key = group_key
        self.ttl_max = ttl_max
        self.bus = SimBus(radius=radius)
        self.nodes: dict[str, ForwardingSimNode] = {}
        for bd in sorted(positions):
            self.nodes[bd.upper()] = ForwardingSimNode(
                self.bus,
                bd,
                positions[bd],
                group_key=group_key,
                algorithm=algorithm,
                ttl_max=ttl_max,
            )
        self._convergence: ConvergenceResult | None = None
        self._backbone_size: int = 0

    def converge(self, max_steps: int = 100, announce_rounds: int = 2) -> ConvergenceResult:
        """Run Hello cycles until roles stabilize, then settle the ANNOUNCE plane.

        A real node floods PKT_ANNOUNCE on a timer from the moment it starts, so
        a converged mesh is one where every member knows every other member's
        public key — not just its direct neighbours', which is all Hello gives.

        The distinction is not academic. Without it the coordinator cannot wrap a
        rekey for a member it has never met directly, and revocation silently
        strands legitimate two-hop members at the old epoch. Skipping this makes
        the simulation invent a vulnerability the deployed code does not have.

        Pass ``announce_rounds=0`` to study that pre-ANNOUNCE window on purpose.
        """
        self._convergence = self.run_until_stable(max_steps=max_steps)
        self.run_announce_rounds(announce_rounds)
        roles = self.roles()
        self._backbone_size = sum(1 for r in roles.values() if r == "RELAY")
        return self._convergence

    def run_announce_rounds(self, rounds: int = 1) -> None:
        """Every node floods its public key binding, in radio order."""
        for _ in range(max(0, rounds)):
            with self.bus.breadth_first():
                for bd in sorted(self.nodes):
                    self.nodes[bd].hello_mgr.emit_announce()

    @property
    def backbone_size(self) -> int:
        return self._backbone_size

    @property
    def convergence(self) -> ConvergenceResult | None:
        return self._convergence

    def _ensure_converged(self, max_steps: int = 100) -> None:
        if self._convergence is None:
            self.converge(max_steps=max_steps)

    def _prepare_broadcast_probe(self) -> None:
        for node in self.nodes.values():
            node.delivered.clear()
        self.bus.reset_data_unicast_count()

    def _send_broadcast(self, src: str, ttl: int, text: str) -> None:
        source = self.nodes[src]
        old_cfg = source.forwarder._cfg  # noqa: SLF001 — sim-only TTL override
        source.forwarder._cfg = replace(old_cfg, ttl_max=ttl)  # noqa: SLF001
        try:
            source.forwarder.send_broadcast(text)
        finally:
            source.forwarder._cfg = old_cfg  # noqa: SLF001

    def _receivers_for_text(self, src: str, text: str) -> frozenset[str]:
        return frozenset(
            bd
            for bd, node in self.nodes.items()
            if bd != src and any(msg == text for _, msg in node.delivered)
        )

    def _delivery_ratio(self, src: str, text: str) -> float:
        n_nodes = len(self.nodes)
        if n_nodes <= 1:
            return 0.0
        return len(self._receivers_for_text(src, text)) / (n_nodes - 1)

    def measure_broadcast(
        self,
        source_bd: str,
        ttl: int,
        text: str = "probe",
        *,
        breadth_first: bool = False,
    ) -> BroadcastMetrics:
        """
        Inject one group broadcast from ``source_bd`` after convergence.

        Resets ``SimBus.data_unicast_count``, clears per-node delivery logs,
        sets TTL on the source forwarder for this probe, then calls
        ``send_broadcast``. Synchronous ``SimBus.deliver`` completes propagation
        inside that call (relays re-emit until TTL / dedup stops forwarding).
        """
        if self._convergence is None:
            raise RuntimeError("call converge() before measure_broadcast()")

        src = source_bd.upper()
        if src not in self.nodes:
            raise KeyError(f"unknown source node: {source_bd}")

        self._prepare_broadcast_probe()
        if breadth_first:
            # Radio order rather than call-stack order; see SimBus.breadth_first.
            with self.bus.breadth_first():
                self._send_broadcast(src, ttl, text)
        else:
            self._send_broadcast(src, ttl, text)

        return BroadcastMetrics(
            backbone_size=self._backbone_size,
            data_unicasts=self.bus.data_unicast_count,
            receivers=self._receivers_for_text(src, text),
            delivery_ratio=self._delivery_ratio(src, text),
            convergence_status=self._convergence.status,
            source_bd=src,
            algorithm=self.algorithm.value,
        )

    def measure_broadcast_with_waves(
        self,
        source_bd: str,
        ttl: int,
        text: str = "probe",
        *,
        max_steps: int = 100,
    ) -> dict[str, Any]:
        """
        Real forwarder broadcast + ``SimBus`` journal → wave reconstruction.

        Cross-check: ``total_unicasts`` from the journal must equal
        ``SimBus.data_unicast_count`` (same counter as ``measure_broadcast``).
        """
        self._ensure_converged(max_steps=max_steps)

        src = source_bd.upper()
        if src not in self.nodes:
            raise KeyError(f"unknown source node: {source_bd}")

        self._prepare_broadcast_probe()
        self.bus.start_data_log()
        try:
            self._send_broadcast(src, ttl, text)
        finally:
            self.bus.stop_data_log()

        log = self.bus.get_data_log()
        journal_total = len(log)
        counter_total = self.bus.data_unicast_count
        if journal_total != counter_total:
            raise AssertionError(
                "PKT_DATA journal incomplete vs data_unicast_count: "
                f"journal={journal_total}, counter={counter_total}"
            )

        wave_data = reconstruct_waves_from_log(log, src, fallback_initial_ttl=ttl)
        if wave_data["total_unicasts"] != counter_total:
            raise AssertionError(
                "wave reconstruction total_unicasts != data_unicast_count: "
                f"{wave_data['total_unicasts']} vs {counter_total}"
            )

        return {
            "total_unicasts": counter_total,
            "delivery_ratio": self._delivery_ratio(src, text),
            "n_waves": wave_data["n_waves"],
            "delivery_depth": delivery_depth_from_waves(wave_data["waves"]),
            "waves": wave_data["waves"],
        }


def compare_broadcast(
    positions: dict[str, Position],
    radius: float,
    source_bd: str,
    ttl: int,
    *,
    text: str = "probe",
    max_steps: int = 100,
) -> dict[str, Any]:
    """
    Measure broadcast overhead on the same topology under Wu-Li and MPR.

    Each algorithm gets a fresh engine (independent Hello state). Returns both
  metric bundles and ``delta_unicasts`` (MPR − Wu-Li data unicasts).
    """
    wu_engine = ForwardingSimEngine(
        positions, radius, CDSAlgorithm.WU_LI_1999, ttl_max=ttl
    )
    wu_engine.converge(max_steps=max_steps)
    wu = wu_engine.measure_broadcast(source_bd, ttl, text=text)

    mpr_engine = ForwardingSimEngine(
        positions, radius, CDSAlgorithm.MPR, ttl_max=ttl
    )
    mpr_engine.converge(max_steps=max_steps)
    mpr = mpr_engine.measure_broadcast(source_bd, ttl, text=text)

    return {
        "wu_li": wu,
        "mpr": mpr,
        "delta_unicasts": mpr.data_unicasts - wu.data_unicasts,
    }


def _line_positions(n_nodes: int) -> dict[str, Position]:
    from sim.topology_gen import _bd_addr_for_index

    return {_bd_addr_for_index(i): (float(i), 0.0) for i in range(n_nodes)}


def _bd_short(bd: str) -> str:
    return bd.replace(":", "")[-4:].upper()


def _resolve_discriminant_topology(
    n_nodes: int,
    radius: float,
    target_degree: float,
    preferred_seed: int,
    *,
    max_steps: int = 50,
    sweep_limit: int = 20_000,
) -> tuple[dict[str, Position], int, float, int, int]:
    """
    Return (positions, seed, area, wu_li_backbone, mpr_backbone).

    Tries ``preferred_seed`` first; if Wu-Li and MPR backbones match, scans
    seeds 0..sweep_limit-1 for the first topology where ``compare_one`` reports
    different ``cds_size`` at fixed_point.
    """
    from sim.metrics_roles import _area_for_target_degree, compare_one
    from sim.topology_gen import generate_connected_geometric

    def _try_seed(seed: int) -> tuple[dict[str, Position], float, int, int] | None:
        area = _area_for_target_degree(n_nodes, radius, target_degree)
        try:
            positions = generate_connected_geometric(n_nodes, area, radius, seed)
        except RuntimeError:
            return None
        cmp = compare_one(positions, radius, max_steps=max_steps)
        wu = cmp["wu_li"]["cds_size"]
        mpr = cmp["mpr"]["cds_size"]
        if wu is None or mpr is None:
            return None
        if wu == mpr:
            return None
        return positions, area, int(wu), int(mpr)

    hit = _try_seed(preferred_seed)
    if hit is not None:
        positions, area, wu_bb, mpr_bb = hit
        return positions, preferred_seed, area, wu_bb, mpr_bb

    print(
        f"  (seed {preferred_seed} ne discrimine plus — balayage 0..{sweep_limit - 1})"
    )
    for seed in range(sweep_limit):
        if seed == preferred_seed:
            continue
        hit = _try_seed(seed)
        if hit is not None:
            positions, area, wu_bb, mpr_bb = hit
            return positions, seed, area, wu_bb, mpr_bb

    raise RuntimeError(
        f"no discriminant topology in seeds 0..{sweep_limit - 1} "
        f"(n={n_nodes}, target_degree={target_degree})"
    )


def _measure_all_sources(
    positions: dict[str, Position],
    radius: float,
    ttl: int,
    *,
    max_steps: int = 50,
) -> list[tuple[str, BroadcastMetrics, BroadcastMetrics]]:
    """One converged engine per algo; broadcast from every node in turn."""
    sources = sorted(positions)
    engines = {
        CDSAlgorithm.WU_LI_1999: ForwardingSimEngine(
            positions, radius, CDSAlgorithm.WU_LI_1999, ttl_max=ttl
        ),
        CDSAlgorithm.MPR: ForwardingSimEngine(
            positions, radius, CDSAlgorithm.MPR, ttl_max=ttl
        ),
    }
    for eng in engines.values():
        eng.converge(max_steps=max_steps)

    rows: list[tuple[str, BroadcastMetrics, BroadcastMetrics]] = []
    for src in sources:
        tag = _bd_short(src)
        wu = engines[CDSAlgorithm.WU_LI_1999].measure_broadcast(
            src, ttl, text=f"probe-{tag}"
        )
        mpr = engines[CDSAlgorithm.MPR].measure_broadcast(
            src, ttl, text=f"probe-{tag}"
        )
        rows.append((src, wu, mpr))
    return rows


def _print_single_source_result(n: int, result: dict[str, Any]) -> None:
    for algo_label, metrics in (("Wu-Li 1999", result["wu_li"]), ("MPR", result["mpr"])):
        print(f"\n{algo_label} ({metrics.algorithm})")
        print(f"  convergence     : {metrics.convergence_status}")
        print(f"  backbone size   : {metrics.backbone_size}")
        print(f"  data unicasts   : {metrics.data_unicasts}")
        print(f"  receivers       : {len(metrics.receivers)} / {n - 1}")
        dr = metrics.delivery_ratio
        print(f"  delivery ratio  : {dr:.2%}", end="")
        if dr < 1.0:
            print("  ⚠ delivery < 100% (TTL ou backbone à diagnostiquer)")
        else:
            print()
    print(f"\ndelta unicasts (MPR − Wu-Li): {result['delta_unicasts']}")


def _print_multi_source_table(
    rows: list[tuple[str, BroadcastMetrics, BroadcastMetrics]],
) -> None:
    hdr = (
        f"{'source':>6}  {'Wu u':>5}  {'MPR u':>5}  {'Δ u':>5}  "
        f"{'Wu del':>7}  {'MPR del':>7}  note"
    )
    print(hdr)
    print("-" * len(hdr))

    wu_us: list[int] = []
    mpr_us: list[int] = []
    for src, wu, mpr in rows:
        delta = mpr.data_unicasts - wu.data_unicasts
        wu_us.append(wu.data_unicasts)
        mpr_us.append(mpr.data_unicasts)
        notes: list[str] = []
        if wu.delivery_ratio < 1.0:
            notes.append(f"Wu {wu.delivery_ratio:.0%}")
        if mpr.delivery_ratio < 1.0:
            notes.append(f"MPR {mpr.delivery_ratio:.0%}")
        note = " ⚠ " + ", ".join(notes) if notes else ""
        if note:
            note += " (<100% delivery)"
        print(
            f"{_bd_short(src):>6}  {wu.data_unicasts:>5}  {mpr.data_unicasts:>5}  "
            f"{delta:>+5}  {wu.delivery_ratio:>6.0%}  {mpr.delivery_ratio:>6.0%}"
            f"{note}"
        )

    n = len(rows)
    mean_wu = sum(wu_us) / n
    mean_mpr = sum(mpr_us) / n
    print("-" * len(hdr))
    print(
        f"{'MEAN':>6}  {mean_wu:>5.1f}  {mean_mpr:>5.1f}  "
        f"{mean_mpr - mean_wu:>+5.1f}  ({n} sources)"
    )


if __name__ == "__main__":
    radius = 1.0
    max_steps = 50

    # —— Scénario 1 : ligne (Wu-Li et MPR coïncident souvent) ——
    print("=" * 60)
    print("SCÉNARIO 1 — ligne (référence, backbones souvent identiques)")
    print("=" * 60)
    n = 5
    positions = _line_positions(n)
    source = sorted(positions)[0]
    ttl = n
    print(f"topology: line {n} nodes, R={radius}, source={source}, ttl={ttl}")
    _print_single_source_result(
        n, compare_broadcast(positions, radius, source, ttl, max_steps=max_steps)
    )

    # —— Scénario 2 : topologie géométrique discriminante ——
    print("\n" + "=" * 60)
    print("SCÉNARIO 2 — géométrique discriminante (backbones Wu-Li ≠ MPR)")
    print("=" * 60)
    geo_n = 10
    target_degree = 5.0
    preferred_seed = 9451
    positions, seed, area, wu_bb, mpr_bb = _resolve_discriminant_topology(
        geo_n, radius, target_degree, preferred_seed, max_steps=max_steps
    )
    ttl = geo_n
    print(
        f"topology: n={geo_n}, target_degree={target_degree}, R={radius}, "
        f"seed={seed}, area={area:.4f}, ttl={ttl}"
    )
    print(f"backbone (compare_one cds_size): Wu-Li={wu_bb}, MPR={mpr_bb}")

    rows = _measure_all_sources(positions, radius, ttl, max_steps=max_steps)
    wu_conv = rows[0][1].convergence_status
    mpr_conv = rows[0][2].convergence_status
    print(f"convergence (forwarding sim): Wu-Li={wu_conv}, MPR={mpr_conv}")
    print(f"backbone (forwarding sim):    Wu-Li={rows[0][1].backbone_size}, MPR={rows[0][2].backbone_size}")
    print("\nunicasts par source (toutes les sources, moyenne en bas) :")
    _print_multi_source_table(rows)

    print("\n(inspection only — chiffres bruts, pas de conclusion imposée)")
