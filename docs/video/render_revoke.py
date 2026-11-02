#!/usr/bin/env python3
"""1080p clip: one real revocation on the same 18-node mesh as sim-wuli.mp4.

Roles, the excluded node, and who reads the next message come from
ForwardingSimEngine (PacketForwarder.revoke_member + send_broadcast).
The drawing only plays that result back.
"""

from __future__ import annotations

import os
import sys
from collections import deque

from PIL import Image, ImageDraw, ImageFont

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.forwarding_sim import ForwardingSimEngine, reconstruct_waves_from_log  # noqa: E402
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402

W, H = 1920, 1080
FPS = 30
N = 18
RADIUS = 1.0
SEED = 7
OUT = "/tmp/bb-revoke"

BG = (11, 18, 27)
INK = (230, 237, 245)
MUTED = (107, 123, 141)
LINK = (45, 62, 82)
LEAF = (74, 163, 255)
RELAY = (110, 232, 154)
WAVE = (255, 159, 67)
EXCL = (255, 107, 122)
COORD = (255, 209, 102)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "NotoSans-Bold.ttf" if bold else "NotoSans-Regular.ttf"
    return ImageFont.truetype(f"/usr/share/fonts/truetype/noto/{name}", size)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    area = _area_for_target_degree(N, RADIUS, 3.5)
    positions = generate_connected_geometric(N, area, RADIUS, SEED)
    engine = ForwardingSimEngine(positions, RADIUS, CDSAlgorithm.WU_LI_1999, ttl_max=40)
    result = engine.converge(max_steps=40, announce_rounds=2)
    roles = engine.roles()
    bds = sorted(engine.nodes)
    coord = next(b for b in bds if engine.nodes[b].hello_mgr.is_coordinator())
    victim = next(b for b in bds if roles[b] == "LEAF" and b != coord)

    with engine.bus.breadth_first():
        engine.nodes[coord].forwarder.revoke_member(victim)
    for _ in range(3):
        with engine.bus.breadth_first():
            engine.step()

    def epoch(bd: str) -> int:
        return engine.nodes[bd].hello_mgr.epoch_store.current_epoch()

    adopted = sorted(b for b in bds if b != victim and epoch(b) == epoch(coord))
    text = "after-revoke"
    for node in engine.nodes.values():
        node.delivered.clear()
    engine.bus.start_data_log()
    with engine.bus.breadth_first():
        engine.nodes[coord].forwarder.send_broadcast(text)
    engine.bus.stop_data_log()
    waves = reconstruct_waves_from_log(engine.bus.get_data_log(), coord)
    readers = {
        bd
        for bd, node in engine.nodes.items()
        if any(msg == text for _, msg in node.delivered)
    }
    print(
        f"convergence {result.status} coord {coord} victim {victim} "
        f"epoch {epoch(victim)}->{epoch(coord)} readers {len(readers)} "
        f"victim_reads {victim in readers} waves {waves['n_waves']}"
    )
    if victim in readers or len(readers) != len(bds) - 2:
        raise SystemExit("revocation result is not the one this clip claims")

    xs = [p[0] for p in positions.values()]
    ys = [p[1] for p in positions.values()]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    pad = 0.08 * max(maxx - minx, maxy - miny, 1.0)

    def xy(bd: str) -> tuple[float, float]:
        x, y = positions[bd]
        px = 140 + (x - minx + pad) / (maxx - minx + 2 * pad) * 1100
        py = 160 + (1 - (y - miny + pad) / (maxy - miny + 2 * pad)) * 780
        return px, py

    adj = {bd: sorted(engine.bus.neighbors(bd)) for bd in positions}
    edges = [(a, b) for a, nbs in adj.items() for b in nbs if a < b]

    # Rekey paints members in BFS order from the coordinator. The victim is
    # omitted because the forwarder left it on the old epoch.
    rekey_dist = {coord: 0}
    q = deque([coord])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v not in rekey_dist and v in adopted:
                rekey_dist[v] = rekey_dist[u] + 1
                q.append(v)
    rekey_hops = max(rekey_dist.values())

    reached_at: dict[str, int] = {}
    for wave in waves["waves"]:
        for bd in wave["newly_reached"]:
            reached_at.setdefault(bd, int(wave["wave"]))
    msg_hops = max(reached_at.values(), default=0)

    hop_frames = 36
    intro, mark, rekey_at = 50, 70, 130
    msg_at = rekey_at + (rekey_hops + 1) * hop_frames + 20
    total = msg_at + (msg_hops + 1) * hop_frames + 100

    f_title = font(54, True)
    f_sub = font(28)
    f_small = font(24)
    f_legend = font(26, True)

    def mix(c, a):
        return tuple(int(BG[k] + (c[k] - BG[k]) * a) for k in range(3))

    for i in range(total):
        im = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(im)
        d.text((80, 48), "BUBBLE-BLUE  ·  revocation", font=f_title, fill=INK)
        d.text(
            (80, 118),
            "Same 18-node mesh. One signed rekey. Measured on the real forwarder.",
            font=f_sub,
            fill=MUTED,
        )

        rekey_wave = -1
        if i >= rekey_at:
            rekey_wave = min(rekey_hops, (i - rekey_at) // hop_frames)
        msg_wave = -1
        if i >= msg_at:
            msg_wave = min(msg_hops, (i - msg_at) // hop_frames)
        show_x = i >= mark

        for a, b in edges:
            x1, y1 = xy(a)
            x2, y2 = xy(b)
            lit = False
            if msg_wave >= 0:
                da = reached_at.get(a)
                db = reached_at.get(b)
                if a == coord:
                    da = -1
                if b == coord:
                    db = -1
                if da is not None and db is not None and max(da, db) <= msg_wave and abs(da - db) == 1:
                    lit = True
            d.line((x1, y1, x2, y2), fill=WAVE if lit else LINK, width=4 if lit else 3)

        for bd in positions:
            x, y = xy(bd)
            relay = roles[bd] == "RELAY"
            r = 16 if relay else 11
            if bd == victim and show_x:
                color = EXCL
            elif bd == coord:
                color = COORD
            elif msg_wave >= 0 and bd in reached_at and reached_at[bd] <= msg_wave:
                color = RELAY if relay else LEAF
            elif rekey_wave >= 0 and bd in rekey_dist and rekey_dist[bd] <= rekey_wave:
                color = RELAY if relay else LEAF
            else:
                color = mix(RELAY if relay else LEAF, 0.85)
            d.ellipse((x - r, y - r, x + r, y + r), fill=color)
            if bd == victim and show_x:
                d.line((x - 7, y - 7, x + 7, y + 7), fill=BG, width=3)
                d.line((x - 7, y + 7, x + 7, y - 7), fill=BG, width=3)

        d.rounded_rectangle((1320, 220, 1840, 560), radius=18, fill=(19, 29, 42))
        d.text((1360, 248), "What you are seeing", font=f_legend, fill=INK)
        d.ellipse((1360, 318, 1388, 346), fill=COORD)
        d.text((1410, 316), "coordinator", font=f_small, fill=INK)
        d.ellipse((1360, 378, 1388, 406), fill=RELAY)
        d.text((1410, 376), "relay, still in the group", font=f_small, fill=INK)
        d.ellipse((1364, 442, 1384, 462), fill=LEAF)
        d.text((1410, 436), "member", font=f_small, fill=INK)
        d.ellipse((1360, 492, 1388, 520), fill=EXCL)
        d.text((1410, 490), "excluded", font=f_small, fill=INK)

        if i < mark:
            cap = "The group is up. Everyone shares the epoch-0 key."
        elif i < rekey_at:
            cap = "The coordinator excludes one member."
        elif msg_wave < 0:
            cap = "New group key, epoch 1. The excluded node keeps the old one."
        elif msg_wave < msg_hops:
            cap = "The next message. It does not stop for the excluded node."
        else:
            cap = "16 of 16 remaining members read it. The excluded node does not."
        d.text((80, 990), cap, font=f_sub, fill=INK)
        im.save(os.path.join(OUT, f"f{i:04d}.png"))
        if i % 90 == 0:
            print(f"frame {i}/{total}", flush=True)

    print(f"frames {total}")


if __name__ == "__main__":
    main()
