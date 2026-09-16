# Experimental plan — BUBBLE-BLUE implementation

This is the list of experiments the team agreed to have **written down before
the displays arrive**. A scenario that is not here will not be run on day one;
one that is here has a metric, a pass criterion, and a place in the paper.

Two classes:

| Class | Medium | Status | Paper section |
|-------|--------|--------|---------------|
| **A — already runnable** | Lab table, SSH, no screen | Preliminary numbers in the draft | §5.1–5.4 |
| **B — needs screens (and walking)** | Physical range, multi-hop line, field | Protocol written; not yet run | §5.5 |

Displays unblock B because an operator must read peer count, last message and
relay role **without SSH**, while carrying the board.

Hardware once complete: 3× RUBIK Pi 3 (DFRobot DFR0506 7″) + 3× Arduino UNO Q
(Adafruit 1651 2.8″ shield; one UNO Q may use HDMI). Batteries already
validated on RUBIK.

---

## A. Lab campaigns (no screen)

Reproducible from a workstation:

```bash
python3.14 scripts/bb_bench.py --boards bench_boards.txt --duration 300 --pull
python3.14 scripts/bb_bench.py --churn <tag> --churn-at 120 --churn-for 90
python3.14 scripts/bb_load.py  --boards bench_boards.txt --sender rubik-q
python3.14 sim/limits.py --study scale
python3.14 sim/limits.py --study density
python3.14 sim/limits.py --study revocation
```

| ID | Question | Instrument | Metric | Preliminary result |
|----|----------|------------|--------|--------------------|
| A1 | How long until a complete mesh? | `bb_bench` | `time_to_full_mesh_s` (worst board) | 7–14 s at 3 nodes |
| A2 | Does it stay complete? | `bb_bench` | `full_mesh_frac_steady`, flaps, relay transitions | 97–98 % complete; 0 relay flips |
| A3 | Do chat messages arrive? | `bb_bench` delivery | fraction of senders heard | 100 % at 3 nodes; 427/429 at 6 (manual) |
| A4 | Does `HELLO_MISSES` control departure? | `bb_bench --churn` + `--board-env` | presence-view delay | 17–21 s at 3; 32–36 s at 6 |
| A5 | How far does TTL 10 go? | `sim/limits.py --study scale` | min TTL = hop eccentricity | yes, on chain and geometric graphs; ~20 nodes at degree 4–5 |
| A6 | What density percolates? | `--study density` | connected draws, relay fraction | no connected draw below mean degree ~5; relays 52 % → 38 % as density rises |
| A7 | Does revocation leave anyone behind? | `--study revocation` | stranded members, victim leak | 0 / 0 once ANNOUNCE has run; join-window is the limit |
| A8 | Who saturates first? | `bb_load.py` | per-listener delivery | RUBIK: 30 msg/s lossless; UNO Q: ~10 msg/s then host-stack stall (`ENOSPC` L2CAP ident) |
| A9 | Is AES-GCM the bottleneck? | `encrypt_with_key` loop | packets/s vs BLE | 30 k–173 k pkt/s vs a few hundred on the link — **no** |
| A10 | Replay at 6 nodes | A1–A3 when the three offline boards are back | same table | pending |

**Method notes (do not drop when writing the paper).**

- Campaign figures are **worst-board**, not averages.
- Warm-up (25 s) is excluded from stability, included in convergence.
- Departure is timed on the **presence table**, not L2CAP sockets (a socket dies
  with its process regardless of `HELLO_MISSES`).
- Delivery is per listener. A “worst listener” column cannot tell a saturated
  mesh from one half-connected board.
- Simulation drives the shipped `HelloManager` / `PacketForwarder`; only the
  medium is synthetic. Floods use `SimBus.breadth_first()` (radio order).

---

## B. Field campaigns (screens required)

Run in this order. Each row is one sitting; do not skip the radius before the
line.

### B1 — One-hop radio range

**Question.** What is the physical communication radius, per platform pair?

**Setup.** Two nodes only. Line of sight. One chat every 5 s. Operator walks
until the screen shows 1 → 0 neighbours, then walks back.

**Repeats.** Indoor / outdoor; with / without a body in between;
RUBIK↔RUBIK, RUBIK↔UNO Q, UNO Q↔UNO Q.

**Record.** Distance at loss, distance at recovery (hysteresis), RSSI if
`hciconfig` / `btmon` is available without breaking the walk.

**Pass.** A radius in metres for each pair, with the indoor/outdoor delta.
This number sizes every later placement.

### B2 — Multi-hop line (forwarding / relays)

**Question.** Does a message cross a chain whose length is the hop diameter?
Does required TTL equal that diameter on hardware, as in simulation (A5)?

**Setup.** 3, then 4, then 6 nodes in a line. Place each node just **outside**
one-hop range of the node after next (use B1). Far-end screen shows last
message; status panel shows RELAY / LEAF.

**Check before measuring.** The far node must show **exactly one** neighbour.
A diagonal link turns the line into a shortcut and voids the hop count.

**Record.** End-to-end delivery; hop count; arrival delay; elected relays.
Optional: set `ttl_max` to diameter and to diameter−1.

**Pass.** Far end receives at TTL = diameter and misses at TTL = diameter−1.

### B3 — Partition and merge

**Question.** How does the mesh split and heal when two groups walk apart?

**Setup.** Two clusters of 2–3 nodes, each internally connected. Walk apart
until each screen shows only its own cluster. Walk back.

**Record.** Time to partition (expect ≈ `HELLO_INTERVAL × HELLO_MISSES` =
15 s at defaults); time to merge; flaps at the join.

**Pass.** Split is visible without SSH; merge restores chat; delay tracks the
configured threshold (cross-check A4).

### B4 — Departure / rejoin of a walking node

**Question.** Does the configurable miss count still govern a *moving* node?

**Setup.** One carrier walks out of range, waits 30 s, walks back. Repeat at
`HELLO_MISSES=2` and `=5` (same `.env` on every board).

**Record.** Disappearance and reappearance **as read on the screens**, plus
wall-clock. Rejoin time must *not* track the threshold (it is discovery + dial).

**Pass.** Disappearance delay scales with `HELLO_MISSES`; rejoin does not.

### B5 — Visible revocation

**Question.** After a coordinator revoke, does the victim go dark while
legitimate members keep reading? What happens inside the join window?

**Setup (nominal).** ≥4 nodes. Wait one ANNOUNCE period (~30 s) after the last
joiner. Revoke one node. Victim screen must stop showing group chat; others
continue. Victim taps a preset: nobody displays it.

**Setup (join window).** Revoke within a few seconds of a new node joining,
before ANNOUNCE has spread its key. Expect refusal or stranded members (A7).

**Pass.** Nominal: 0 leaks, 0 stranded. Join-window: documented failure mode,
not a surprise in the demo.

### B6 — Human load on the UNO Q

**Question.** Can preset-button chat saturate the board that A8 identified as
the limit?

**Setup.** One operator taps both UNO Q presets as fast as the resistive panel
allows, 30 s. A RUBIK does the same on the 7″ UI. Observers watch delivery.

**Record.** Messages sent / received. If the UNO Q goes silent with links still
up, check `dmesg` for `Unable to allocate ident: -28`. Recovery:
`systemctl restart bluetooth` (no reboot).

**Pass.** A single human cannot reach the ~10 msg/s ceiling. Several UNO Q
tapping together might — that is the demo risk.

### B7 — Battery + display endurance

**Question.** How long does a kiosk + mesh last on the batteries already
validated for the 7″ stack?

**Setup.** RUBIK on battery, DFR0506 on, `start_screen.sh`, chat every 20 s.
UNO Q on VIN + shield if available.

**Record.** Hours to power-off; moment Bluetooth becomes unstable (distinct
from the weeks-long QCA firmware stall in A, which is uptime of the
*controller*, not the battery).

**Pass.** A number that makes a 20-minute indoor demo a promise rather than a
hope.

### B8 — Indoor walk (deployment)

**Question.** Where does an office-floor mesh hold, cut, and elect a relay?

**Setup.** Nodes in separate rooms along an INRIA corridor. One carrier walks
with a RUBIK. Room screens show the passer-by, then their departure.

**Record.** A floor sketch: hold / cut / relay. Video if the walk is clean.

**Pass.** A reproducible path for the demonstration recording.

---

## Day-of-screens order

| Order | Duration | ID | Gate to the next |
|-------|----------|----|------------------|
| 0 | 1 h | Bring-up | Each screen type shows peers + last message |
| 1 | 1 h | B1 | A radius in metres |
| 2 | 1 h | B2 | Far-end delivery, relays visible |
| 3 | 30 min | B3 | ~15 s split, merge without SSH |
| 4 | 30 min | B4 | Threshold tracks outdoors |
| 5 | 30 min | B5 | Victim deaf, others not |
| 6 | 30 min | B6 | Demo does not stall the UNO Q |
| 7 | later | B7, B8, A10 | After 0–6 are green |

---

## What each experiment is *not*

- B1 is not a throughput test. One message every 5 s.
- B2 is not a range test. Placement is derived from B1.
- A8 / B6 are not “the mesh is slow”. They name **which board** saturates.
- Simulation (A5–A7) is not a substitute for B2 / B5; it is the hypothesis
  those field runs confirm or refute.

---

## Mapping to the publication

| Paper claim | Evidence available now | Evidence after screens |
|-------------|------------------------|------------------------|
| Open mesh, no Bluetooth pairing | Lab A1–A3 | B3, B8 (visible to a reviewer) |
| CDS forwards on shortest paths (no stretch) | Sim A5 | B2 with TTL = diameter / diameter−1 |
| Departure is a count of missed Hellos | Lab A4 | B3, B4 |
| Revocation excludes without stranding | Sim A7 | B5 |
| Crypto is not the throughput limit | Lab A9 | — (energy still open) |
| Data load can starve the control plane | Lab A8 (UNO Q) | B6 |
| Physical radius / indoor deployment | — | B1, B8 |
