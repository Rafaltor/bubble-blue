#!/usr/bin/env python3
"""
Run a convergence and stability campaign across every board, then aggregate.

Until now each multi-board run was a hand-typed SSH loop, which is why no two
runs were quite comparable. This drives ``scripts/bb_probe.py`` on every board
at once, collects the per-board JSON and reduces it to the handful of numbers
worth quoting:

    python3 scripts/bb_bench.py --duration 300 --pull

Boards come from a file (default ``bench_boards.txt``, gitignored because it may
hold passwords — see ``bench_boards.example.txt``):

    # tag       target                  [sudo/ssh password]
    rubik-q     ubuntu@100.79.229.15     tmpXUV!!
    arduinoq    arduino@100.75.58.105    arduinoq

SSH keys are the better answer and the password column can be left out entirely
when they are in place; it exists because these boards ship with password auth.

Starting the boards is deliberately *simultaneous*: convergence time is only
meaningful if nobody had a head start, so the probes are launched in parallel
threads and each one measures from its own process start.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shlex
import subprocess
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DEFAULT_BOARDS = os.path.join(_ROOT, "bench_boards.txt")
REMOTE_JSON = "/tmp/bb_bench_probe.json"

# Room for SSH setup, the probe's own startup and the summary write-back, so a
# board that dies mid-run fails the campaign instead of hanging it.
SSH_OVERHEAD_S = 90


class Board:
    def __init__(self, tag: str, target: str, password: str = "") -> None:
        self.tag = tag
        self.target = target
        self.password = password
        self.summary: dict | None = None
        self.error = ""

    def _ssh(self, remote_cmd: str, timeout: float) -> subprocess.CompletedProcess:
        base = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            "-o", "BatchMode=no" if self.password else "BatchMode=yes",
            self.target,
            remote_cmd,
        ]
        if self.password:
            base = ["sshpass", "-p", self.password] + base
        return subprocess.run(
            base, capture_output=True, text=True, timeout=timeout, check=False
        )

    def _sudo(self, cmd: str) -> str:
        """Prefix a command with sudo, feeding the password when we have one.

        ``-S`` reads the password from stdin and ``-p ''`` suppresses the prompt
        that would otherwise end up in the captured output.
        """
        if self.password:
            return f"printf '%s\\n' {shlex.quote(self.password)} | sudo -S -p '' {cmd}"
        return f"sudo -n {cmd}"

    def pull(self, repo: str) -> bool:
        """Sync the board from git, so every board runs the same commit."""
        res = self._ssh(f"cd {shlex.quote(repo)} && git pull --ff-only 2>&1", timeout=120)
        if res.returncode != 0:
            self.error = f"git pull: {(res.stdout or res.stderr).strip()[:200]}"
            return False
        return True

    def run_probe(self, repo: str, duration: float, send_every: float, expect: int) -> None:
        probe = (
            f"python3.14 scripts/bb_probe.py"
            f" --duration {duration} --send-every {send_every}"
            f" --expect {expect} --tag {shlex.quote(self.tag)}"
            f" --json-out {REMOTE_JSON}"
        )
        cmd = f"cd {shlex.quote(repo)} && {self._sudo(probe)} >/dev/null 2>&1"
        try:
            res = self._ssh(cmd, timeout=duration + SSH_OVERHEAD_S)
        except subprocess.TimeoutExpired:
            self.error = "timeout: the probe never returned"
            return
        if res.returncode != 0:
            self.error = f"probe exited {res.returncode}: {(res.stderr or '').strip()[:200]}"
            return

        got = self._ssh(f"cat {REMOTE_JSON}", timeout=60)
        if got.returncode != 0:
            self.error = "no summary written"
            return
        try:
            self.summary = json.loads(got.stdout)
        except ValueError as e:
            self.error = f"unreadable summary: {e}"


def load_boards(path: str) -> list[Board]:
    boards: list[Board] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                print(f"bench: ligne ignoree (tag et cible attendus) : {line!r}", file=sys.stderr)
                continue
            boards.append(Board(parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
    return boards


def aggregate(boards: list[Board], expect: int) -> dict:
    """Reduce per-board summaries to the campaign-level numbers.

    Worst-case rather than mean throughout: a mesh is converged when the *last*
    board joined, and it is stable only if the shakiest link was.
    """
    ok = [b for b in boards if b.summary]
    if not ok:
        return {"boards_reporting": 0}

    locals_ = {b.summary.get("local", "") for b in ok} - {""}

    conv = [b.summary.get("time_to_full_mesh_s") for b in ok]
    converged = [c for c in conv if c is not None]

    # Delivery is the honest end-to-end check: a link that is up but silent
    # would still look healthy in the peer counts.
    delivery = []
    for b in ok:
        others = locals_ - {b.summary.get("local", "")}
        heard = set(b.summary.get("senders") or [])
        delivery.append(len(heard & others) / len(others) if others else 1.0)

    fracs = [
        b.summary.get("full_mesh_frac_steady")
        for b in ok
        if b.summary.get("full_mesh_frac_steady") is not None
    ]

    return {
        "boards_expected": expect,
        "boards_reporting": len(ok),
        "boards_fully_converged": len(converged),
        "convergence_last_board_s": max(converged) if converged else None,
        "convergence_first_board_s": min(converged) if converged else None,
        "full_mesh_frac_worst": min(fracs) if fracs else None,
        "flaps_total": sum(b.summary.get("flaps_after_warmup", 0) for b in ok),
        "relay_transitions_total": sum(b.summary.get("relay_transitions", 0) for b in ok),
        "delivery_worst": round(min(delivery), 3) if delivery else None,
        "delivery_mean": round(sum(delivery) / len(delivery), 3) if delivery else None,
    }


def print_report(boards: list[Board], agg: dict, expect: int) -> None:
    print("\n=== PAR CARTE ===")
    head = f"{'carte':<12} {'pairs':>7} {'conv.':>7} {'complet':>8} {'flaps':>6} {'relais':>7} {'recu de':>8}"
    print(head)
    print("-" * len(head))
    for b in boards:
        if not b.summary:
            print(f"{b.tag:<12} {'ECHEC':>7}  {b.error}")
            continue
        s = b.summary
        conv = s.get("time_to_full_mesh_s")
        frac = s.get("full_mesh_frac_steady")
        print(
            f"{b.tag:<12}"
            f" {s.get('mean_peers_steady', 0):>7}"
            f" {(f'{conv:.0f}s' if conv is not None else '—'):>7}"
            f" {(f'{frac:.0%}' if frac is not None else '—'):>8}"
            f" {s.get('flaps_after_warmup', 0):>6}"
            f" {s.get('relay_transitions', 0):>7}"
            f" {len(s.get('senders') or []):>8}"
        )

    print("\n=== CAMPAGNE ===")
    conv = agg.get("convergence_last_board_s")
    print(f"cartes ayant repondu       : {agg.get('boards_reporting')}/{expect}")
    print(f"maillage complet atteint   : {agg.get('boards_fully_converged')}/{agg.get('boards_reporting')} cartes")
    if conv is not None:
        print(f"convergence (derniere)     : {conv:.0f} s"
              f"  (premiere : {agg['convergence_first_board_s']:.0f} s)")
    if agg.get("full_mesh_frac_worst") is not None:
        print(f"temps en maillage complet  : {agg['full_mesh_frac_worst']:.0%} (carte la moins bonne)")
    print(f"flaps apres warm-up        : {agg.get('flaps_total')}")
    print(f"changements de role relais : {agg.get('relay_transitions_total')}")
    if agg.get("delivery_worst") is not None:
        print(f"livraison chat             : {agg['delivery_mean']:.0%} moyenne,"
              f" {agg['delivery_worst']:.0%} au pire")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--boards", default=DEFAULT_BOARDS, help="board list file")
    ap.add_argument("--duration", type=float, default=300.0, help="run time per board (s)")
    ap.add_argument("--send-every", type=float, default=20.0, help="chat period (s)")
    ap.add_argument("--repo", default="~/bubble-blue", help="repo path on the boards")
    ap.add_argument("--pull", action="store_true", help="git pull on every board first")
    ap.add_argument("--json-out", default="", help="write the full campaign JSON here")
    args = ap.parse_args()

    try:
        boards = load_boards(args.boards)
    except FileNotFoundError:
        print(f"bench: {args.boards} introuvable — copier bench_boards.example.txt",
              file=sys.stderr)
        return 2
    if not boards:
        print("bench: aucune carte dans la liste", file=sys.stderr)
        return 2

    expect = len(boards)
    print(f"bench: {expect} cartes, {args.duration:.0f} s par carte")

    if args.pull:
        print("bench: synchronisation git...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=expect) as pool:
            list(pool.map(lambda b: b.pull(args.repo), boards))
        failed = [b for b in boards if b.error]
        for b in failed:
            print(f"  {b.tag}: {b.error}", file=sys.stderr)
        if failed:
            print("bench: abandon — les cartes ne sont pas sur le meme commit", file=sys.stderr)
            return 1
        print("  toutes les cartes sur le meme commit")

    print(f"bench: lancement simultane, resultats dans ~{args.duration + 30:.0f} s...")
    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=expect) as pool:
        futures = [
            pool.submit(b.run_probe, args.repo, args.duration, args.send_every, expect)
            for b in boards
        ]
        concurrent.futures.wait(futures)
    print(f"bench: termine en {time.monotonic() - t0:.0f} s")

    agg = aggregate(boards, expect)
    print_report(boards, agg, expect)

    if args.json_out:
        payload = {
            "campaign": agg,
            "duration_s": args.duration,
            "boards": [
                {"tag": b.tag, "error": b.error, "summary": b.summary} for b in boards
            ],
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nJSON complet (series temporelles incluses) : {args.json_out}")

    return 0 if agg.get("boards_reporting") == expect else 1


if __name__ == "__main__":
    raise SystemExit(main())
