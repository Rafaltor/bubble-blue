#!/usr/bin/env python3
"""
Load limits: how big a message, how fast, before the mesh starts dropping.

One board generates, the others only count. A single sender is deliberate — with
everyone transmitting, a loss cannot be attributed to the link, the relay or a
collision between senders, and the ceiling being measured is nobody's in
particular.

Delivery cannot be observed from the sender, so each message carries its step
and index, every listener records what reached it, and the orchestrator
cross-references. A message counts as delivered only if a listener saw that
exact index.

Board side, launched over SSH by the orchestrator:

    python3.14 scripts/bb_load.py --role listen --duration 300
    python3.14 scripts/bb_load.py --role send   --duration 300 --expect 3

Orchestrator, from a workstation:

    python3.14 scripts/bb_load.py --boards bench_boards.txt --sender rubik-q

The default schedule sweeps rate at a small payload, then payload at a rate the
first sweep showed to be safe, so the two limits are separated instead of
confounded.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import os
import shlex
import statistics
import sys
import time
from typing import NamedTuple

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

REMOTE_JSON = "/tmp/bb_load.json"
REMOTE_LOG = "/tmp/bb_load.log"
SSH_OVERHEAD_S = 90

# Sent before the steps to check the mesh carries anything at all; a campaign
# where even this is lost is a broken mesh, not a saturated one.
WARMUP_TEXT = "load-warmup"


class Step(NamedTuple):
    size: int  # plaintext bytes per message
    rate: float  # messages per second
    secs: float  # how long to hold it


def parse_steps(spec: str) -> list[Step]:
    """``size,rate,secs;size,rate,secs;...``"""
    steps = []
    for chunk in spec.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        size, rate, secs = (p.strip() for p in chunk.split(","))
        steps.append(Step(int(size), float(rate), float(secs)))
    return steps


def default_steps(max_size: int) -> list[Step]:
    """Rate first at a small payload, then size at a modest rate."""
    # Size first, rate second. Overload is destructive — a board that has just
    # been pushed past its limit stops sending entirely — so anything measured
    # after a rate sweep measures the damage instead of the payload.
    size_sweep = [Step(s, 5.0, 8.0) for s in (64, 128, 256, max_size)]
    rate_sweep = [Step(64, r, 8.0) for r in (10, 15, 20, 30)]
    return size_sweep + rate_sweep


def encode(step: int, idx: int, size: int) -> str:
    """``L<step>:<idx>:<padding>`` padded to exactly ``size`` bytes of ASCII."""
    head = f"L{step}:{idx}:"
    if len(head) >= size:
        return head
    return head + "x" * (size - len(head))


def decode(text: str) -> tuple[int, int] | None:
    if not text.startswith("L"):
        return None
    try:
        step, idx, _ = text.split(":", 2)
        return int(step[1:]), int(idx)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# board side
# --------------------------------------------------------------------------


def _wait_for_mesh(node, expect_peers: int, timeout_s: float) -> float:
    """Block until the mesh is complete, returning how long that took."""
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        if len(node.peers()) >= expect_peers:
            return time.monotonic() - start
        time.sleep(0.5)
    return -1.0


def run_listen(args) -> dict:
    from src.api.bb_api import BBNode

    received: list[tuple[float, str, str]] = []

    def on_message(sender: str, text: str) -> None:
        received.append((time.time(), sender, text))

    node = BBNode(interface=args.interface, quiet=True)
    node.on_message = on_message
    node.start(l2cap_accept_all=True)
    print(f"listen {args.tag} local={node.local_bd_addr}", flush=True)

    deadline = time.monotonic() + args.duration
    try:
        while time.monotonic() < deadline:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass

    per_step: dict[str, list[int]] = {}
    warmup = 0
    for _, _, text in received:
        if text == WARMUP_TEXT:
            warmup += 1
            continue
        parsed = decode(text)
        if parsed is None:
            continue
        step, idx = parsed
        per_step.setdefault(str(step), []).append(idx)

    out = {
        "role": "listen",
        "tag": args.tag,
        "local_bd_addr": node.local_bd_addr,
        "warmup_received": warmup,
        "total_received": len(received),
        # Indices only: enough to compute delivery and duplicates, small enough
        # to travel back over SSH.
        "received_per_step": {k: sorted(v) for k, v in per_step.items()},
    }
    node.stop()
    return out


def run_send(args) -> dict:
    from src.api.bb_api import BBNode

    steps = parse_steps(args.steps) if args.steps else default_steps(args.max_size)

    node = BBNode(interface=args.interface, quiet=True)
    # Required before start(), and worth counting: anything the generator hears
    # back from its own load would be a self-echo.
    echoes: list[str] = []
    node.on_message = lambda sender, text: echoes.append(text)
    node.start(l2cap_accept_all=True)
    print(f"send {args.tag} local={node.local_bd_addr}", flush=True)

    expect_peers = max(1, args.expect - 1)
    converged = _wait_for_mesh(node, expect_peers, args.converge_timeout)
    print(f"mesh: {len(node.peers())} pairs apres {converged:.1f}s", flush=True)

    warmup_ok = True
    try:
        node.send(WARMUP_TEXT)
    except Exception as e:  # noqa: BLE001
        warmup_ok = False
        print(f"warmup failed: {e}", flush=True)
    time.sleep(2.0)

    def run_one_step(i: int, step: Step) -> dict:
        period = 1.0 / step.rate if step.rate > 0 else 0.0
        sent = 0
        errors: dict[str, int] = {}
        # One message per error type: a bare count says something failed, not
        # what, and the whole point of a saturation test is the failure mode.
        error_texts: dict[str, str] = {}
        peers_before = len(node.peers())
        latencies: list[float] = []
        t0 = time.monotonic()
        next_at = t0
        end = t0 + step.secs
        while time.monotonic() < end:
            now = time.monotonic()
            if now < next_at:
                time.sleep(min(0.005, next_at - now))
                continue
            next_at += period
            text = encode(i, sent, step.size)
            call = time.monotonic()
            try:
                node.send(text)
                sent += 1
            except Exception as e:  # noqa: BLE001
                name = type(e).__name__
                errors[name] = errors.get(name, 0) + 1
                error_texts.setdefault(name, str(e)[:200])
            latencies.append(time.monotonic() - call)
        elapsed = time.monotonic() - t0

        return {
                "step": i,
                "size": step.size,
                "rate_target": step.rate,
                # What the board actually managed, which is the honest figure
                # once send() starts taking longer than the period.
                "rate_achieved": round(sent / elapsed, 2) if elapsed > 0 else 0.0,
                "sent": sent,
                "seconds": round(elapsed, 2),
                "errors": errors,
                "error_texts": error_texts,
                "peers_before": peers_before,
                "peers_after": len(node.peers()),
                "send_ms_mean": round(statistics.mean(latencies) * 1000, 2)
                if latencies
                else None,
                "send_ms_max": round(max(latencies) * 1000, 2) if latencies else None,
            }

    results = []
    for i, step in enumerate(steps):
        row = run_one_step(i, step)
        results.append(row)
        print(
            f"step {i}: {step.size}o x {step.rate}/s -> envoyes {row['sent']} "
            f"({row['rate_achieved']}/s), pairs "
            f"{row['peers_before']}->{row['peers_after']}, "
            f"erreurs {row['errors'] or 'aucune'} {row['error_texts'] or ''}",
            flush=True,
        )
        time.sleep(1.0)

    # Does the mesh carry traffic again once the load stops?
    #
    # Peer count is not the test. An overloaded board keeps its links up while
    # delivering nothing, so the only honest question is whether a quiet, small
    # message gets through after a pause. A ceiling the mesh recovers from is a
    # capacity figure; one it does not is an outage.
    recovery: dict[str, object] = {"peers_after_steps": len(node.peers())}
    if args.cooldown > 0:
        print(f"repos {args.cooldown}s avant le palier de recuperation...", flush=True)
        time.sleep(args.cooldown)
        idx = len(steps)
        row = run_one_step(idx, Step(64, 1.0, 8.0))
        row["is_recovery"] = True
        results.append(row)
        recovery["peers_after_cooldown"] = row["peers_after"]
        recovery["recovery_step"] = idx
        recovery["recovery_sent"] = row["sent"]
        print(f"palier de recuperation: envoyes {row['sent']} "
              f"({row['rate_achieved']}/s), pairs {row['peers_after']}", flush=True)

    out = {
        "role": "send",
        "tag": args.tag,
        "local_bd_addr": node.local_bd_addr,
        "converged_s": round(converged, 1),
        "peers_at_start": len(node.peers()),
        "warmup_sent": warmup_ok,
        "self_echoes": sum(1 for t in echoes if decode(t) is not None),
        "recovery": recovery,
        "steps": results,
    }
    node.stop()
    return out


# --------------------------------------------------------------------------
# orchestrator
# --------------------------------------------------------------------------


def _board_cmd(board, role: str, duration: float, expect: int, steps: str) -> str:
    env = ("env " + " ".join(shlex.quote(e) for e in board.env) + " ") if board.env else ""
    cmd = (
        f"{env}python3.14 scripts/bb_load.py --role {role}"
        f" --duration {duration} --expect {expect}"
        f" --tag {shlex.quote(board.tag)} --json-out {REMOTE_JSON}"
    )
    if role == "send" and steps:
        cmd += f" --steps {shlex.quote(steps)}"
    return cmd


def run_remote(board, repo: str, role: str, duration: float, expect: int, steps: str) -> None:
    inner = _board_cmd(board, role, duration, expect, steps)
    cmd = f"{board._cd(repo)} && {board._sudo(inner)} >{REMOTE_LOG} 2>&1"
    res = board._ssh(cmd, timeout=duration + SSH_OVERHEAD_S)
    if res.returncode != 0:
        tail = board._ssh(f"tail -n 15 {REMOTE_LOG}", timeout=45)
        board.error = (tail.stdout or res.stderr or "echec").strip()[-600:]
        return
    got = board._ssh(f"cat {REMOTE_JSON}", timeout=60)
    try:
        board.summary = json.loads(got.stdout)
    except json.JSONDecodeError:
        board.error = "JSON illisible"


def aggregate(sender, listeners: list) -> list[dict]:
    """Per step: what was sent, and what the worst listener actually saw."""
    if not sender.summary:
        return []
    rows = []
    for step in sender.summary.get("steps", []):
        idx = str(step["step"])
        sent = step["sent"]
        per_listener = []
        for b in listeners:
            if not b.summary:
                continue
            got = b.summary.get("received_per_step", {}).get(idx, [])
            uniq = len(set(got))
            per_listener.append(
                {
                    "tag": b.tag,
                    "received": uniq,
                    "duplicates": len(got) - uniq,
                    "ratio": (uniq / sent) if sent else 0.0,
                }
            )
        ratios = [p["ratio"] for p in per_listener] or [0.0]
        rows.append(
            {
                **step,
                "listeners": per_listener,
                "delivery_worst": round(min(ratios), 3),
                "delivery_mean": round(statistics.mean(ratios), 3),
                "goodput_Bs": round(step["size"] * step["rate_achieved"], 1),
            }
        )
    return rows


def print_report(sender, listeners: list, rows: list[dict]) -> None:
    print("\n=== EMETTEUR ===")
    s = sender.summary or {}
    print(f"{sender.tag}: {s.get('peers_at_start')} pairs, "
          f"convergence {s.get('converged_s')}s, warmup "
          f"{'OK' if s.get('warmup_sent') else 'ECHEC'}, "
          f"auto-echos {s.get('self_echoes')}")
    rec = s.get("recovery") or {}
    if rec.get("peers_after_steps") is not None:
        print(f"  apres charge : {rec['peers_after_steps']} pairs")
    for b in listeners:
        if b.summary:
            print(f"  ecoute {b.tag}: {b.summary.get('total_received')} messages recus "
                  f"(warmup {b.summary.get('warmup_received')})")
        else:
            print(f"  ecoute {b.tag}: {b.error or 'pas de resultat'}")

    head = (
        f"\n{'taille':>7} {'cadence':>8} {'atteinte':>9} {'envoyes':>8} "
        f"{'livraison':>10} {'debit o/s':>10} {'send ms max':>12} {'erreurs':>9}"
    )
    print(head)
    print("-" * (len(head) - 1))
    for r in rows:
        errs = sum(r["errors"].values()) if r["errors"] else 0
        flag = "" if r["delivery_worst"] >= 0.99 else "  <-- pertes"
        if r.get("is_recovery"):
            flag = ("  <-- RECUPERATION OK" if r["delivery_worst"] >= 0.99
                    else "  <-- TOUJOURS BLOQUE apres repos")
        print(
            f"{r['size']:>7} {r['rate_target']:>8} {r['rate_achieved']:>9} "
            f"{r['sent']:>8} {r['delivery_worst']:>9.0%} {r['goodput_Bs']:>10} "
            f"{str(r['send_ms_max']):>12} {errs:>9}{flag}"
        )

    load_rows = [r for r in rows if not r.get("is_recovery")]
    clean = [r for r in load_rows if r["delivery_worst"] >= 0.99]
    if clean:
        best_rate = max(r["rate_achieved"] for r in clean)
        best_gp = max(r["goodput_Bs"] for r in clean)
        print(f"\nSans perte : jusqu'a {best_rate}/s et {best_gp} o/s.")
    lossy = [r for r in load_rows if r["delivery_worst"] < 0.99]
    if lossy:
        r = lossy[0]
        print(f"Premiere perte a {r['size']} o x {r['rate_target']}/s "
              f"(livraison {r['delivery_worst']:.0%}).")


def orchestrate(args) -> int:
    from bb_bench import load_boards

    boards = load_boards(args.boards)
    if len(boards) < 2:
        print("il faut au moins deux cartes : un emetteur et un recepteur")
        return 2
    for b in boards:
        b.env = list(args.board_env)

    sender = next((b for b in boards if b.tag == args.sender), boards[0])
    listeners = [b for b in boards if b is not sender]
    print(f"charge: emetteur={sender.tag}, ecoute={', '.join(b.tag for b in listeners)}")

    if args.pull:
        for b in boards:
            ok = b.pull(args.repo)
            print(f"  {b.tag}: {'a jour' if ok else 'git pull ECHEC'}")

    steps = args.steps or ""
    plan = parse_steps(steps) if steps else default_steps(args.max_size)
    # Convergence, warm-up and the per-step pause all sit outside the steps.
    need = (sum(s.secs + 1.0 for s in plan) + args.converge_timeout
            + args.cooldown + 30)
    duration = args.duration or need
    print(f"{len(plan)} paliers, {duration:.0f}s par carte\n")

    with futures.ThreadPoolExecutor(max_workers=len(boards)) as pool:
        jobs = [
            pool.submit(run_remote, b, args.repo,
                        "send" if b is sender else "listen",
                        duration, len(boards), steps)
            for b in boards
        ]
        for j in jobs:
            j.result()

    if not sender.summary:
        print(f"emetteur muet: {sender.error}")
        return 1

    rows = aggregate(sender, listeners)
    print_report(sender, listeners, rows)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "sender": sender.summary,
                    "listeners": [b.summary for b in listeners if b.summary],
                    "rows": rows,
                },
                fh,
                indent=2,
            )
        print(f"\nJSON : {args.json_out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--role", choices=("send", "listen"), default="")
    ap.add_argument("--boards", default="", help="orchestrator mode")
    ap.add_argument("--sender", default="", help="board tag that generates load")
    ap.add_argument("--duration", type=float, default=0.0)
    ap.add_argument("--expect", type=int, default=3, help="total boards in the mesh")
    ap.add_argument("--steps", default="", help="size,rate,secs;...")
    ap.add_argument("--max-size", type=int, default=0, help="0 = transport maximum")
    ap.add_argument("--converge-timeout", type=float, default=60.0)
    ap.add_argument("--cooldown", type=float, default=25.0,
                    help="idle seconds before the recovery step (0 to skip)")
    ap.add_argument("--tag", default=os.uname().nodename)
    ap.add_argument("--interface", default="hci0")
    ap.add_argument("--repo", default="~/bubble-blue")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--board-env", action="append", default=[])
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()

    if not args.max_size:
        from config import load_config, max_payload

        try:
            args.max_size = max_payload(load_config().transport_kind)
        except Exception:  # noqa: BLE001 — orchestrator has no adapter to probe
            args.max_size = 470

    if args.boards:
        return orchestrate(args)

    if not args.role:
        ap.error("either --role (board side) or --boards (orchestrator)")
    if not args.duration:
        args.duration = 300.0

    summary = run_send(args) if args.role == "send" else run_listen(args)
    print("\n=== SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
