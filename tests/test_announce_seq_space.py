"""
Two sequence counters, two anti-replay windows.

A node numbers its packets from two independent counters: HelloManager numbers
Hello, presence and ANNOUNCE, while PacketForwarder numbers DATA, SUBGROUP and
REKEY. Both start at zero, and they advance at completely different rates — the
Hello side on a timer, the data side only when someone sends a message.

A replay window assumes one monotonic counter per sender. Pointing both counters
at the same window makes the mesh drop good traffic: a chat message whose
sequence happens to equal that of an earlier ANNOUNCE from the same node was
rejected as a replay by *every* receiver, and by the relays too, so the message
vanished network-wide without a single error surfacing to the sender.

That is what these tests pin down: same sequence number, different counter,
still delivered.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.forwarding_sim import ForwardingSimEngine  # noqa: E402
from sim.metrics_roles import _area_for_target_degree  # noqa: E402
from sim.topology_gen import generate_connected_geometric  # noqa: E402
from src.forwarding.cds import CDSAlgorithm  # noqa: E402


def _mesh(n: int = 6, seed: int = 2):
    """A converged mesh with the ANNOUNCE plane left idle, so seqs stay small."""
    pos = generate_connected_geometric(
        n, _area_for_target_degree(n, 1.0, 8.0), 1.0, seed=seed
    )
    engine = ForwardingSimEngine(pos, 1.0, CDSAlgorithm.WU_LI_1999, ttl_max=20)
    engine.converge(max_steps=40, announce_rounds=0)
    return engine, sorted(engine.nodes)


def _received(engine, bds, src, text) -> int:
    return sum(
        1
        for b in bds
        if b != src and any(t == text for _, t in engine.nodes[b].delivered)
    )


def test_a_message_reusing_an_announce_sequence_still_arrives():
    engine, bds = _mesh()
    src = bds[0]
    hello, fwd = engine.nodes[src].hello_mgr, engine.nodes[src].forwarder

    with engine.bus.breadth_first():
        hello.emit_announce()
    burned = hello._seq  # the sequence the ANNOUNCE consumed

    # Walk the data counter up to that exact value and past it.
    delivered_at = {}
    while fwd._tx_seq <= burned + 1:
        text = f"msg-{fwd._tx_seq + 1}"
        with engine.bus.breadth_first():
            fwd.send_broadcast(text)
        delivered_at[fwd._tx_seq] = _received(engine, bds, src, text)

    others = len(bds) - 1
    assert delivered_at[burned] == others, (
        f"message avec seq={burned} recu par {delivered_at[burned]}/{others} "
        "— la sequence de l'ANNOUNCE l'a fait rejeter"
    )
    # Its neighbours in the sequence must be unaffected too.
    assert delivered_at[burned - 1] == others
    assert delivered_at[burned + 1] == others


def test_every_sequence_up_to_the_announce_burst_is_delivered():
    # A burst of announces burns several numbers; none of them may swallow a
    # message, and the loss was silent, so only delivery counts can catch it.
    engine, bds = _mesh(n=6, seed=5)
    src = bds[0]
    hello, fwd = engine.nodes[src].hello_mgr, engine.nodes[src].forwarder

    with engine.bus.breadth_first():
        for _ in range(3):
            hello.emit_announce()
    ceiling = hello._seq + 2

    others = len(bds) - 1
    losses = []
    while fwd._tx_seq < ceiling:
        text = f"burst-{fwd._tx_seq + 1}"
        with engine.bus.breadth_first():
            fwd.send_broadcast(text)
        if _received(engine, bds, src, text) != others:
            losses.append(fwd._tx_seq)

    assert not losses, f"messages perdus aux sequences {losses}"


# ---- the windows themselves ---------------------------------------------


def test_the_two_windows_do_not_see_each_other():
    engine, bds = _mesh(n=4)
    fwd = engine.nodes[bds[1]].forwarder
    peer = bds[0]

    assert fwd._check_announce_replay(peer, 7) is True
    # Same number, other counter: must not look like a replay.
    assert fwd._check_replay(peer, 7, 0) is True
    # Each still rejects a genuine repeat within its own space.
    assert fwd._check_announce_replay(peer, 7) is False
    assert fwd._check_replay(peer, 7, 0) is False


def test_the_relay_path_separates_the_two_spaces_as_well():
    # Delivery and relaying use different state; fixing only delivery would
    # still leave relays refusing to forward the message.
    engine, bds = _mesh(n=4)
    fwd = engine.nodes[bds[1]].forwarder
    peer = bds[0]

    announce_key = f"{peer}|ANNOUNCE"
    data_key = f"{peer}|FWD"
    assert fwd._check_relay_ingress(announce_key, 9, 0) is True
    assert fwd._check_relay_ingress(data_key, 9, 0) is True

    fwd._fwd_cache.mark(announce_key, 9)
    assert fwd._fwd_cache.seen(announce_key, 9) is True
    assert fwd._fwd_cache.seen(data_key, 9) is False


def test_announce_packets_are_still_deduplicated():
    # The fix must not turn ANNOUNCE into an unbounded flood amplifier.
    engine, bds = _mesh(n=4)
    fwd = engine.nodes[bds[1]].forwarder
    peer = bds[0]

    assert fwd._check_announce_replay(peer, 3) is True
    assert fwd._check_announce_replay(peer, 3) is False
    assert fwd._check_announce_replay(peer, 4) is True


if __name__ == "__main__":
    for fn in (
        test_a_message_reusing_an_announce_sequence_still_arrives,
        test_every_sequence_up_to_the_announce_burst_is_delivered,
        test_the_two_windows_do_not_see_each_other,
        test_the_relay_path_separates_the_two_spaces_as_well,
        test_announce_packets_are_still_deduplicated,
    ):
        fn()
        print(f"✅ {fn.__name__.removeprefix('test_').replace('_', ' ')}")
    print("\n✅ All announce/data sequence-space tests passed")
