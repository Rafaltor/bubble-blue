# Implementing BUBBLE-BLUE over BLE L2CAP: An Open Mesh with Private Groups

> **Source éditable :** [`overleaf/main.tex`](overleaf/main.tex) + [`overleaf/refs.bib`](overleaf/refs.bib)
> **PDF :** [`bb-conference.pdf`](bb-conference.pdf)
> Ce fichier Markdown n’est plus la source — Overleaf compile le `.tex`.

Paul-Maxence Baraton, Nadjib Achir, Philippe Jacquet  
INRIA, France

---

## Abstract

BUBBLE-BLUE (BB) is a multi-hop private group that rides on an *open* Bluetooth mesh: any BB node may forward, only holders of a group key may read. Prior work specified the construction and evaluated Connected Dominating Set (CDS) election in simulation. This paper reports the first implementation, on BLE L2CAP Connection-Oriented Channels, without Bluetooth pairing.

We describe the on-wire format, the split between a topological plane and an application plane, and a repeatable evaluation on Qualcomm Linux boards (RUBIK Pi 3 and Arduino UNO Q). A three-node mesh completes in 7–14 s, remains complete for 97–98 % of a steady run, and delivers 100 % of chat. Driving the *shipped* forwarder in simulation, the smallest TTL that reaches every node equals the source’s hop eccentricity: the CDS adds no path stretch. The practical limit is therefore a hop budget (default TTL 10 spans about twenty nodes at mean degree 4–5). AES-256-GCM runs at 30 k–173 k packets/s, far above the BLE link; the Arduino host stack saturates near 10 messages/s. Revocation excludes the victim in every trial and strands legitimate members only inside the join window, before public keys have flooded.

**Keywords:** Bluetooth Low Energy, L2CAP, mesh networks, connected dominating set, group communication.

---

## 1. Introduction

Infrastructure-less local communication still collapses, in practice, onto a Wi-Fi access point or a smartphone OS that will not host a third-party mesh. Bluetooth is ubiquitous and needs no operator. The SIG Mesh profile [9], however, is a different stack, designed for managed flooding (lighting, sensors), not for a private group that forms between people who share a key and nothing else.

BUBBLE-BLUE [1] proposed the opposite split: an **open topological mesh** that any BB node may join and relay, and **private application bubbles** readable only with a group key. Routing is a dynamic CDS. That note gives the algorithms and unit-disk simulations. It does not give a BLE transport, a frame layout, a revocation protocol that reaches two-hop members, or measurements on hardware.

This paper fills that gap. The implementation runs on two Qualcomm Linux boards over BLE L2CAP CoC [8]. Connections use `BT_SECURITY_LOW`: there is no SMP pairing, no bond, and no address allow-list. Membership is the group key. A node that has never met another can still talk to it. A passive sniffer in range can read routing headers; it cannot read payloads (§3.4).

**Contributions.**

1. A complete BB stack on BLE CoC, including the 26-byte routing header, packet types, opaque forwarding, and epoch-based revocation (§3).
2. A repeatable multi-board evaluation method and the figures it produces on two platforms (§4).
3. Characterised operating limits: hop-TTL, join-window revocation, and per-platform saturation—including two implementation defects the limit studies exposed and that are now fixed (§4.4).

The rest of this paper is organised as follows. Section 2 positions BB against CDS literature and existing BLE messengers. Section 3 presents the design. Section 4 evaluates the implementation. Section 5 concludes.

---

## 2. Related work

**CDS and multi-hop broadcast.** Wu and Li’s 1999 local rule [2] is our default election; their 2001 scheme [3] is the broader dominating-set routing setting. Multipoint relays [4] are the OLSR construction [5]; in BB, MPR is an alternative *algorithm* whose *result* is still a CDS. Jacquet’s analytic densities [6] and the 1D/2D unit-disk comparison in [1] are why Wu–Li was preferred for a first implementation: simpler, and better than MPR on the 2D disk in that note. Dumbo II [7] is the emergency-network precedent cited in [1]. BLE has no native IP-style broadcast: every local flood is a sequence of L2CAP unicasts. That cost model is why a CDS (fewer transmitters) matters more here than on Wi-Fi MANETs.

**BLE transports.** We use LE Connection-Oriented Channels [8], not RFCOMM (Classic, serial, no BLE equivalent) and not GATT as the data plane (serialised writes, no native fan-out to CDS neighbours). Advertising carries *presence* only. SIG Mesh [9] remains a separate, provisioned stack.

**Adjacent messengers.** BitChat [16] shows that a BLE-only chat can exist at consumer scale; it floods over GATT and elects no backbone. Briar [17] is delay-tolerant sync between *pre-paired* contacts over Classic RFCOMM, Wi-Fi and Tor—a different problem. Reticulum [18] is the closest Linux BLE stack; it is identity-routed, not CDS-routed. Bridgefy and BLEMeshChat likewise flood or store-and-forward without a CDS. None of these is a BB node. Netcore Causeway [19] shares high-level aims with different technology; we do not treat it as a baseline.

---

## 3. Design

A BB node is a Linux process that owns an HCI adapter, accepts CoC connections on PSM `0x0081`, and runs the control and forwarding logic below. Pairing is unused. Confidentiality is application-layer.

### 3.1 Open mesh, private bubble

Two planes share the same links and the same 26-byte header, and nothing else.

The **topological plane** is open. Any BB node may advertise presence, accept a connection, take part in CDS election, and relay a frame it cannot decrypt. AES-GCM failure is logged; it is never a reason to drop the relay.

The **application plane** is private. Group traffic, key announcement and revocation are readable only with the current group key. Membership is that 32-byte secret, not a Bluetooth bond.

This is the construction of [1], realised as opaque forwarding of group data by nodes that may not belong to the bubble.

### 3.2 Presence and sparse links

A node advertises a compact presence record in a connectable legacy advertisement (manufacturer data, magic `BB`): anonymous identifier, CDS flag, and the BD_ADDR at which it accepts CoC. Scanners accumulate a **presence catalog** indexed by anon_id. The catalog survives a dropped socket and is how a neighbour is redialled without pairing.

Links are not a full mesh. Each node caps its L2CAP degree and prefers CDS successors. On a six-node soak, boards held two or three links each and still reached the other five. When the CDS is empty—at start-up, and whenever legacy advertisements cannot carry neighbour lists under a ~27-byte budget—a node dials from the catalog rather than waiting for an air-only election that cannot see two-hop topology.

The implementation runs on RUBIK Pi 3 (Ubuntu, Bluetooth 5.0) and Arduino UNO Q (Debian plus an STM32, Bluetooth 5.1). CPython 3.14 is required for LE 4-tuple sockets. A privileged daemon owns the adapter; the UI is an unprivileged client, so restarting a display does not drop links.

### 3.3 Routing header and packet types

Every frame begins with a 26-byte cleartext header:

```
type (1) | src (6) | dst (6) | ttl (1) | seq (4 BE) | ts_ms (8 BE)
```

Relays decrement TTL on the wire, so TTL is **not** in the AES-GCM additional authenticated data; the rest of the header is. A relay without the group key can still forward, and cannot forge an AAD-covered field. Broadcast destination is `FF:FF:FF:FF:FF:FF`.

The ciphertext is AES-256-GCM [10, 11] with a 16-byte tag. There is no nonce on the wire: the per-packet key is derived from the group or pairwise secret, source, sequence and timestamp. Overhead is 42 bytes. Against a conservative 512-byte MTU that leaves 470 bytes of plaintext. Both boards negotiate L2CAP MTU 672, so a maximum-size message is still one frame; 512 is policy. A 471-byte payload is refused, never truncated.

| Type | Name | Plane | Role |
|------|------|-------|------|
| `0x01` | HELLO | both | Neighbour table, epoch, CDS inputs |
| `0x02` | DATA | private | Group broadcast |
| `0x04` | SUBGROUP | private | Addressed multicast |
| `0x05` | REKEY | private | Pairwise epoch catch-up |
| `0x06` | ANNOUNCE | private | Signed BD_ADDR → X25519 / Ed25519 |
| `0x07` | REKEY_FLOOD | private | Coordinator revocation |

Two sequence counters number these frames (Hello/ANNOUNCE versus DATA/REKEY). They must not share an anti-replay window (§4.4).

### 3.4 CDS, forwarding, and membership expiry

Roles follow Wu–Li 1999 [2]. MPR [4] is implemented in the simulator; boards run Wu–Li. A node forwards if it is RELAY, or if it has two or more L2CAP links (a bridge the CDS has not named—the usual case at the edge of range, where the advertisement graph is a clique and the L2CAP graph is a star). Duplicate suppression is keyed by `(src, seq)` and by which counter produced `seq`.

A neighbour is dropped after `HELLO_MISSES` consecutive silent Hello periods (default 3, minimum 2), i.e. 15 s at a 5 s interval. Counting periods keeps the threshold meaningful if the interval is retuned.

### 3.5 Security and revocation

Link encryption is off. Group AEAD is AES-256-GCM under the group key; pairwise keys are X25519 [13] after ANNOUNCE; rekeys are attested with Ed25519 [14]. The routing header is visible to a sniffer; payloads are not.

The coordinator is the member with the smallest anon_id among **all known members** (Hello-resolved *and* ANNOUNCE-learned). Election and validation of a rekey must use that same set (§4.4).

Only the coordinator may revoke. It bumps the epoch, rotates the group key, and floods `REKEY_FLOOD` wrapped under *pre-bump* pairwise keys, excluding the victim. Late members catch up on the next stale Hello. The coordinator cannot wrap a key it does not hold: Hello supplies direct neighbours only; everyone else arrives in ANNOUNCE (30 s). Revoking inside that **join window** is refused or strands legitimate members—an operating limit, not a demo surprise.

Both SoCs use ARMv8 Cryptography Extensions (`gcm-aes-ce` via OpenSSL). Qualcomm QCE is present but does not register GCM; it is not on the path.

---

## 4. Evaluation

Experiments use simultaneous probes on all boards, the same git commit, and **worst-board** figures (a mesh is complete when the last node has joined). Warm-up (25 s) is counted as convergence, not as instability. Departure is timed on the presence table, not on L2CAP sockets (a socket dies with its process regardless of `HELLO_MISSES`). Load tests use a single sender; each message carries an index, and delivery is that index seen by a listener. Simulation instantiates the shipped forwarder on a unit-disk radio and drains floods breadth-first (call-stack, depth-first delivery is not a radio).

### 4.1 Convergence, stability, and departure

| Setting | Nodes | Time to full mesh | Steady complete | Delivery |
|---------|------:|------------------:|----------------:|----------|
| Automated | 3 | 7–14 s | 97–98 % | 100 % |
| Automated | 2 | 3–14 s | 97 % | 100 % |
| Manual soak | 6 | ~40 s | stable after 60 s | 427/429 (99.5 %) |

The two losses in 429 were the first message (before convergence) and the last (during shutdown). Applications should display mesh state rather than assume delivery in the first tens of seconds. Relay role flips in the automated runs: 0. Steady-state L2CAP flaps: a few per run, all recovered.

Killing a node without notice, presence view:

| `HELLO_MISSES` | Expected | Measured departure | Rejoin |
|----------------|----------|--------------------|--------|
| 3 | 15 s | 17–21 s | 7–12 s |
| 6 | 30 s | 32–36 s | 7–10 s |

Departure tracks the configured miss count. Rejoin does not: it is discovery and dial.

### 4.2 Crypto is not the bottleneck

| Platform | 470 B encrypt+decrypt | Equivalent rate |
|----------|----------------------:|----------------:|
| RUBIK Pi 3 | 3.0 + 2.8 µs | 173 000 pkt/s |
| Arduino UNO Q | 18.2 + 15.2 µs | 30 000 pkt/s |

BLE CoC carries a few hundred packets per second. AES-GCM is two to three orders of magnitude above the link. Energy of the crypto path is not measured.

### 4.3 Topological and revocation limits (shipped code, simulated radio)

At mean degree ~4–5, the minimum TTL that delivers to every node equals the source eccentricity on every draw (chains and random geometric graphs):

| n | Degree | Diameter (hops) | Min TTL | Delivery at TTL 10 |
|--:|-------:|----------------:|--------:|-------------------:|
| 10 | 3.9 | 4 | 4 | 100 % |
| 20 | 4.3 | 8 | 8 | 100 % |
| 30 | 3.3 | 11 | 11 | 93 % |
| 50 | 5.2 | 13 | 13 | 94 % |
| 100 | 5.2 | 19 | 19 | 23 % |

There is no “it breaks at \(N\) nodes”. Past a 10-hop diameter, default TTL 10 no longer spans the network—about twenty nodes at this density. At six nodes the default is ample. Below mean degree ~5, no connected geometric draw in 100 trials (percolation). Denser graphs elect fewer relays (52 % → 38 %) and cost more per flood.

After ANNOUNCE has run, revocation at \(n=6\)–\(30\): 0 stranded members, 0 leaks to the victim. Cost grows from 12 to 83 emissions per node (roughly quadratic). Before ANNOUNCE, revocation is often refused. Rule: wait one ANNOUNCE period after a join.

### 4.4 Load and two defects the study caught

A single sender, 64–470 byte payloads. The RUBIK listener received 100 % through 30 msg/s. The UNO Q tracked to 10 msg/s, lost at 15, then delivered 0—including a 1 msg/s recovery step after 25 s idle—while its links stayed nominally up. The kernel logged `Unable to allocate ident: -28` (`ENOSPC` on BlueZ L2CAP *signalling* identifiers); controller `errors` counters stayed 0. Data-plane saturation delays Hellos, neighbours expire, auto-dial bursts, the ident pool empties. `systemctl restart bluetooth` recovers the board. A separate QCA firmware stall after ~6 weeks of uptime requires a reboot; it is not this failure.

Limit studies also found two protocol bugs, both now fixed.

*Shared anti-replay window.* Hello/ANNOUNCE and DATA were numbered from independent counters but checked against one window. A DATA frame whose sequence equalled an earlier ANNOUNCE from the same node was dropped by every receiver and every relay. Reproduction: sequence 4 delivered 5/5, sequence 5 (the ANNOUNCE) 0/5, sequence 6 delivered 5/5. Likely cause of the 2/429 soak losses. Fix: one window per counter.

*Split-brain coordinator.* Election used Hello-resolved neighbours only; validation of a rekey also counted ANNOUNCE-learned peers. On a stringy 30-node graph (mean degree 3.3) four nodes declared themselves coordinator; revocation was refused mesh-wide while the initiator’s epoch advanced; 28 of 29 legitimate members stayed on the old key. Fix: one membership view for both.

---

## 5. Conclusion

An open BLE mesh with private groups is implementable without pairing. On the boards we have, the mesh converges in seconds, the CDS does not stretch paths, and the default TTL is a hop budget rather than a magic node count. Revocation works once keys have been announced and fails in a documented window if they have not. Cryptography is not the throughput limit; the Arduino host stack is.

Physical range, indoor multi-hop lines, and walking partition/merge still require the pending displays (an operator must read peer count without SSH). Those experiments are specified; they are not in this paper. Energy of AES-GCM versus the radio, a six-node repeat of §4.1, and an Android CoC port are future work.

---

## Acknowledgements

We thank Wilfred (Qualcomm) for platform guidance and for the questions that produced the accelerator and host-stack measurements. The protocol note [1] acknowledges Matthieu Finiasz (OLVID) and Thomas Jaussouin and Olivier Berni (Lunabee); that debt carries over.

---

## References

[1] N. Achir and P. Jacquet, “BUBBLE-BLUE a multihop private network based on Bluetooth,” arXiv:2509.00967, 2025.

[2] J. Wu and H. Li, “On calculating connected dominating set for efficient routing in ad hoc wireless networks,” in *Proc. DIAL-M*, 1999, pp. 7–14.

[3] J. Wu and H. Li, “A dominating-set-based routing scheme in ad hoc wireless networks,” *Telecommunication Systems*, vol. 18, no. 1, pp. 13–36, 2001.

[4] A. Qayyum, L. Viennot, and A. Laouiti, “Multipoint relaying for flooding broadcast messages in mobile wireless networks,” in *Proc. HICSS*, 2002, pp. 3866–3875.

[5] T. Clausen and P. Jacquet, “Optimized Link State Routing Protocol (OLSR),” RFC 3626, 2003.

[6] P. Jacquet, “Analytical results on connected dominating sets in mobile ad hoc networks,” INRIA, 2004.

[7] K. Kanchanasut *et al.*, “DUMBO II: a V-2-I emergency network,” in *Proc. Asian Conf. Internet Engineering*, 2008, pp. 37–38.

[8] Bluetooth SIG, *Bluetooth Core Specification*, v5.0/v5.1.

[9] Bluetooth SIG, *Mesh Profile Specification*.

[10] M. Dworkin, “Recommendation for GCM and GMAC,” NIST SP 800-38D, 2007.

[11] J. Daemen and V. Rijmen, *The Design of Rijndael*. Springer, 2002.

[12] P. Mahajan and A. Sachdeva, “A study of encryption algorithms AES, DES and RSA for security,” *Global J. Comput. Sci. Technol.*, vol. 13, no. 15, 2013.

[13] A. Langley, M. Hamburg, and S. Turner, “Elliptic Curves for Security,” RFC 7748, 2016.

[14] S. Josefsson and I. Liusvaara, “EdDSA,” RFC 8032, 2017.

[15] BlueZ Project, *Linux Bluetooth protocol stack*. https://www.bluez.org/

[16] J. Stoll, *BitChat*. https://github.com/permissionlesstech/bitchat

[17] The Briar Project, *Briar*. https://briarproject.org/

[18] M. Blomnes, *Reticulum* / LXMF. https://reticulum.network/

[19] Netcore Network, *Causeway*, 2026.
