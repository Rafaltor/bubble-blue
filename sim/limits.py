#!/usr/bin/env python3
"""
Topological operating limits: how far the mesh scales before it stops delivering.

Six boards cannot answer this, so it is answered in simulation — but on the real
``HelloManager`` and the real ``PacketForwarder``, which the sim engine drives
through a synthetic radio rather than reimplementing. What is simulated is the
medium; the protocol under test is the shipped one.

    python3.14 sim/limits.py --study scale
    python3.14 sim/limits.py --study density --json-out density.json

Two things are measured for each topology:

- **Delivery** from several sources, which either reaches every node or does
  not. Where it does not, the question is why, and the answer is almost always
  TTL rather than a hole in the backbone.
- **The smallest TTL that reaches everyone**, which is the honest expression of
  a topological limit: not "it breaks at N nodes" but "past N nodes the default
  TTL of 10 no longer spans the network".

Propagation runs in ``breadth_first`` mode throughout. The default synchronous
delivery walks the graph depth-first, which is not how a radio behaves and which
makes coverage depend on call order — see ``SimBus.breadth_first``. Numbers
gathered without it are pessimistic and, worse, not monotonic in TTL.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
from collections import deque

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.forwarding_sim import ForwardingSimEngine  # noqa: E402
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402

DEFAULT_TTL = 10  # config.py ships this
RADIUS = 1.0


def adjacency(positions: dict, radius: float = RADIUS) -> dict[str, list[str]]:
    bds = sorted(positions)
    return {
        a: [b for b in bds if b != a and math.dist(positions[a], positions[b]) <= radius]
        for a in bds
    }


def hop_distances(adj: dict[str, list[str]], src: str) -> dict[str, int]:
    """Shortest path in hops. The lower bound on any TTL that could work."""
    dist = {src: 0}
    queue = deque([src])
    while queue:
        node = queue.popleft()
        for nb in adj[node]:
            if nb not in dist:
                dist[nb] = dist[node] + 1
                queue.append(nb)
    return dist


def min_ttl_for_full_delivery(engine, src: str, max_ttl: int, tag: str) -> int | None:
    """Smallest TTL delivering to every node, or None if even ``max_ttl`` fails.

    Scanned upward rather than bisected: coverage *should* be monotonic in TTL
    once propagation is breadth-first, but that is the kind of assumption this
    study exists to check, not to build on.
    """
    for ttl in range(1, max_ttl + 1):
        m = engine.measure_broadcast(src, ttl=ttl, text=f"{tag}-{ttl}", breadth_first=True)
        if m.delivery_ratio >= 1.0:
            return ttl
    return None


def _sources(positions: dict, n_sources: int) -> list[str]:
    """Spread the sources through the address order rather than clustering them."""
    bds = sorted(positions)
    if n_sources >= len(bds):
        return bds
    step = len(bds) / n_sources
    return [bds[int(i * step)] for i in range(n_sources)]


def measure_topology(
    positions: dict, ttl_default: int, max_ttl: int, n_sources: int, algorithm
) -> dict:
    """Converge one topology, then probe it from several sources."""
    n = len(positions)
    engine = ForwardingSimEngine(positions, RADIUS, algorithm, ttl_max=max_ttl)
    conv = engine.converge(max_steps=60)

    adj = adjacency(positions)
    rows = []
    for src in _sources(positions, n_sources):
        m = engine.measure_broadcast(
            src, ttl=ttl_default, text=f"d{n}-{src[-2:]}", breadth_first=True
        )
        need = min_ttl_for_full_delivery(engine, src, max_ttl, tag=f"t{n}-{src[-2:]}")
        ecc = max(hop_distances(adj, src).values())
        rows.append(
            {
                "delivery_default_ttl": m.delivery_ratio,
                "min_ttl_full": need,
                "eccentricity": ecc,
                # Per delivered node, so sizes stay comparable.
                "unicasts_per_node": m.data_unicasts / max(1, n - 1),
            }
        )

    degrees = [len(v) for v in adj.values()]
    return {
        "n_nodes": n,
        "mean_degree": round(statistics.mean(degrees), 2),
        "convergence_status": conv.status,
        "relays": engine.backbone_size,
        "relay_frac": round(engine.backbone_size / n, 3),
        "delivery_default_ttl": min(r["delivery_default_ttl"] for r in rows),
        "min_ttl_full": (
            None
            if any(r["min_ttl_full"] is None for r in rows)
            else max(r["min_ttl_full"] for r in rows)
        ),
        "eccentricity": max(r["eccentricity"] for r in rows),
        "unicasts_per_node": round(
            statistics.mean(r["unicasts_per_node"] for r in rows), 2
        ),
    }


def run_study(
    sizes: list[int],
    degrees: list[float],
    seeds: int,
    ttl_default: int,
    max_ttl: int,
    n_sources: int,
    algorithm,
) -> list[dict]:
    out = []
    for n in sizes:
        for degree in degrees:
            area = _area_for_target_degree(n, radius=RADIUS, target_degree=degree)
            runs = []
            for seed in range(1, seeds + 1):
                try:
                    positions = generate_connected_geometric(n, area, RADIUS, seed=seed)
                except RuntimeError:
                    # Too sparse to be connected at this density; a real limit,
                    # not an error to hide.
                    continue
                runs.append(
                    measure_topology(positions, ttl_default, max_ttl, n_sources, algorithm)
                )
            if not runs:
                out.append({"n_nodes": n, "target_degree": degree, "connected_draws": 0})
                continue

            needs = [r["min_ttl_full"] for r in runs if r["min_ttl_full"] is not None]
            out.append(
                {
                    "n_nodes": n,
                    "target_degree": degree,
                    "connected_draws": len(runs),
                    "mean_degree": round(statistics.mean(r["mean_degree"] for r in runs), 2),
                    "relay_frac": round(statistics.mean(r["relay_frac"] for r in runs), 3),
                    # Worst source of the worst draw: a mesh is only as good as
                    # the node that cannot be reached.
                    "delivery_default_worst": round(
                        min(r["delivery_default_ttl"] for r in runs), 3
                    ),
                    "delivery_default_mean": round(
                        statistics.mean(r["delivery_default_ttl"] for r in runs), 3
                    ),
                    "min_ttl_full_worst": max(needs) if len(needs) == len(runs) else None,
                    "eccentricity_worst": max(r["eccentricity"] for r in runs),
                    "unicasts_per_node": round(
                        statistics.mean(r["unicasts_per_node"] for r in runs), 2
                    ),
                    "non_converging": sum(
                        1 for r in runs if r["convergence_status"] != "fixed_point"
                    ),
                }
            )
    return out


def print_rows(rows: list[dict], ttl_default: int) -> None:
    head = (
        f"{'n':>4} {'degre':>6} {'relais':>7} {'diam':>5} "
        f"{'TTL min':>8} {f'livr. TTL{ttl_default}':>13} {'reem./noeud':>12}"
    )
    print(head)
    print("-" * len(head))
    for r in rows:
        if not r.get("connected_draws"):
            print(f"{r['n_nodes']:>4} {r['target_degree']:>6} "
                  f"{'aucun tirage connexe a cette densite':>40}")
            continue
        need = r["min_ttl_full"] if "min_ttl_full" in r else r["min_ttl_full_worst"]
        need_s = str(need) if need is not None else ">max"
        flag = "" if r["delivery_default_worst"] >= 1.0 else "  <-- incomplet"
        print(
            f"{r['n_nodes']:>4} {r['mean_degree']:>6} {r['relay_frac']:>6.0%} "
            f"{r['eccentricity_worst']:>5} {need_s:>8} "
            f"{r['delivery_default_worst']:>12.0%} {r['unicasts_per_node']:>12.1f}{flag}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--study", choices=("scale", "density"), default="scale")
    ap.add_argument("--sizes", default="", help="comma-separated node counts")
    ap.add_argument("--degrees", default="", help="comma-separated target mean degrees")
    ap.add_argument("--seeds", type=int, default=5, help="topologies per point")
    ap.add_argument("--sources", type=int, default=3, help="broadcast sources per topology")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL, help="TTL under test")
    ap.add_argument("--max-ttl", type=int, default=40, help="ceiling when searching")
    ap.add_argument("--mpr", action="store_true", help="MPR instead of Wu-Li 1999")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()

    algorithm = CDSAlgorithm.MPR if args.mpr else CDSAlgorithm.WU_LI_1999

    if args.study == "scale":
        sizes = [int(s) for s in args.sizes.split(",")] if args.sizes else [
            10, 20, 30, 50, 75, 100, 150
        ]
        degrees = [float(d) for d in args.degrees.split(",")] if args.degrees else [6.0]
    else:
        sizes = [int(s) for s in args.sizes.split(",")] if args.sizes else [50]
        degrees = [float(d) for d in args.degrees.split(",")] if args.degrees else [
            3.0, 4.0, 6.0, 8.0, 12.0
        ]

    print(f"etude {args.study} — {algorithm.value}, {args.seeds} topologies par point, "
          f"{args.sources} sources, TTL teste {args.ttl}\n")
    rows = run_study(sizes, degrees, args.seeds, args.ttl, args.max_ttl,
                     args.sources, algorithm)
    print_rows(rows, args.ttl)

    usable = [r for r in rows if r.get("connected_draws")]
    ok = [r for r in usable if r["delivery_default_worst"] >= 1.0]
    if ok and args.study == "scale":
        print(f"\nA densite {ok[0]['mean_degree']:.0f}, le TTL par defaut de {args.ttl} "
              f"couvre jusqu'a {max(r['n_nodes'] for r in ok)} noeuds.")
        broken = [r for r in usable if r["delivery_default_worst"] < 1.0]
        if broken:
            r = broken[0]
            print(f"A {r['n_nodes']} noeuds il n'en atteint plus que "
                  f"{r['delivery_default_worst']:.0%} ; il en faudrait "
                  f"{r['min_ttl_full_worst'] or '>max'}.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"study": args.study, "ttl": args.ttl, "rows": rows}, fh, indent=2)
        print(f"\nJSON : {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
