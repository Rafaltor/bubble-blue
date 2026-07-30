# BUBBLE-BLUE configuration

## Mesh ouvert et bulles privées

BUBBLE-BLUE is an **open topological mesh** with **private application bubbles**.

### Topological plane (open)

Accessible to **any BB node**, independent of `BUBBLE_BLUE_GROUP_KEY`:

| Mechanism | Module | Behaviour |
|-----------|--------|-----------|
| Presence AD | `src/transport/advertising.py` (`LEAdvertiser` / `update_presence`) | Legacy **connectable** Manufacturer Data: magic `BB`, protocol `0x01`, presence format **`0x02`**, compact Hello (anon_id, seq, CDS flag, BD_ADDR). Neighbor/MPR lists empty under `LEGACY_PRESENCE_MAX_VALUE_LEN` (~27 B value). |
| Periodic scan | `PresenceScanner` + `le_scan.mgmt_scan_records` | LE scan window **3 s**; BLE mesh defaults **period 2 s** / **steady 4 s** (set in `BBNode`); MGMT *Device Found* carries full EIR each hit |
| Link security | `ble_coc.apply_le_flowctl` | **`BT_SECURITY_LOW`** — no link encryption; app-layer crypto only (see note below) |
| Auto-dial | `BBNode._backbone_dial_targets` | CDS backbone when relays known; else **dial every heard peer**; one dial/pass; 8 s timeout; `force=True` |
| Public Hellos | `hello` / `HelloManager` | OTA + L2CAP; anon_ids learned on the wire (cross-group) |
| CDS / relay | `hello_manager`, `cds`, `forwarder._should_relay` | Wu-Li election; forward if CDS RELAY **or** ≥2 L2CAP links |

A foreign-group relay stays connected and **forwards opaque** `PKT_DATA` even when it cannot decrypt.

### Application plane (private)

Governed only by the **group key**:

- **Identity** — `PKT_ANNOUNCE` (signed Ed25519) + private Hello fields bind BD_ADDR → pubkeys for same-group peers.
- **Encryption** — AES-256-GCM per packet; wrong key → log `paquet non déchiffrable` at most, never eject the relay.
- **Chat** — only nodes sharing `BUBBLE_BLUE_GROUP_KEY` decrypt group messages.

### Lab overrides

| Mechanism | Effect |
|-----------|--------|
| `BUBBLE_BLUE_GROUP_MEMBERS` | Dial / allowlist |
| `BUBBLE_BLUE_TOPOLOGY` / `--topology` | Forced topology (e.g. line A—M—B) |
| `--peer` | Single peer |

Open mesh `.env`: **group key + transport** only.

### Link security note (`BT_SECURITY_LOW`)

Le CoC BLE utilise `BT_SECURITY_LOW` (pas de chiffrement de lien). La sécurité
est entièrement applicative (clé de groupe + AES-256-GCM). **Aucun
appairage/bond Bluetooth n’est nécessaire** : les boards ouvrent le canal
L2CAP directement, sans pairing préalable. C’est ce qui permet à des nœuds
qui ne se sont jamais rencontrés de communiquer, du moment qu’ils partagent
la clé de groupe.

Trade-off : un sniffer passif à portée peut lire le **header de routing** en
clair (type, src/dst, seq, ts). Payloads et Hello privés restent AES-GCM.

---

## Validation — open mesh (3+ boards)

Hardware: BB boards in common radio range, Python 3.14, `BUBBLE_BLUE_TRANSPORT=ble_l2cap`.

**`.env` (same on all nodes of a bubble):**

```bash
BUBBLE_BLUE_GROUP_KEY=<64 hex chars>
BUBBLE_BLUE_TRANSPORT=ble_l2cap
# no GROUP_MEMBERS / TOPOLOGY
```

**Procedure:**

```bash
sudo python3.14 bb_node.py --chat
```

**Expect:**

1. Presence heard → candidates → L2CAP links without typing BD_ADDRs (no Bluetooth pairing step).
2. `PKT_ANNOUNCE` burst then periodic identity bindings.
3. Multihop chat when the L2CAP graph is connected (relay via CDS or ≥2-link bridges).
4. Kill/restart a node → rediscovery via presence + reconnect without editing `.env`.

**Success criteria:** no manual addresses; recovery after restart; chat decryptable inside the bubble.

---

## Validation — cross-group relay (line A—M—B)

Demonstrates a middle node **M** with a **different** group key that still bridges A↔B.

| Node | Role | Group key | Topology |
|------|------|-----------|----------|
| **A** | endpoint | `GK_A` | `--topology <BD_M>` |
| **M** | relay | `GK_M` ≠ `GK_A` | `--topology <BD_A>,<BD_B>` |
| **B** | endpoint | `GK_A` | `--topology <BD_M>` |

**Expect:** M is RELAY (or ≥2-link bridge); M logs `paquet non déchiffrable` for A↔B chat; A and B decrypt end-to-end; M is never ejected.

Related unit coverage: `tests/test_cross_group_hello.py`.

---

## Protocol defaults (not board-specific)

| Setting | Value | Where |
|---------|-------|--------|
| L2CAP PSM (Classic) | `0x1001` | `config.PSM_BT_CLASSIC` |
| L2CAP PSM (BLE CoC) | `0x0081` | `config.PSM_BLE` |
| Hello interval | 5 s | `config.py` |
| Neighbor timeout | 15 s | `config.py` |
| Dial timeout (BLE) | 8 s | `ble_l2cap._DIAL_TIMEOUT_S` |
| ANNOUNCE burst / interval | see `config.py` | `ANNOUNCE_*` |
| TTL max | 10 | `config.py` |
| Replay window | 256 | `config.py` |

## Required per deployment

1. **`BUBBLE_BLUE_GROUP_KEY`** — private bubble (who decrypts chat).
2. **`BUBBLE_BLUE_TRANSPORT`** — prefer `ble_l2cap` for current presence plane.
3. **Peer list** — optional lab only (`GROUP_MEMBERS` / `TOPOLOGY` / `--topology` / `--peer`).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `BUBBLE_BLUE_GROUP_KEY` | 32-byte AES key (hex, 64 chars) |
| `BUBBLE_BLUE_TRANSPORT` | `ble_l2cap` or `bt_classic` |
| `BUBBLE_BLUE_GROUP_MEMBERS` | Lab dial / allowlist |
| `BUBBLE_BLUE_TOPOLOGY` | Same as `--topology` |
| `BUBBLE_BLUE_REMOTE_BD_ADDR` | Optional single peer |
| `BUBBLE_BLUE_INTERFACE` | HCI device (default `hci0`) |
| `BUBBLE_BLUE_LOCAL_BD_ADDR` | Override if `hciconfig` fails |
| `BUBBLE_BLUE_CHAT_ALIASES` | `/private` aliases |

## CLI (`bb_node.py`)

| Flag | Purpose |
|------|---------|
| `--chat` | Interactive chat |
| `--topology` | Peers (overrides env topology) |
| `--peer` | Single peer |
| `--interface` | HCI |
| `--scan SEC` | LE inquiry / presence |
| `--send` / `--dst` | One-shot send |
| `--identity` | Print local BD_ADDR + pubkeys |

## BLE coexistence (scan vs links)

Long LE scan windows can starve supervision on legacy controllers (kernel default ~420 ms).

Mitigations in software:

| Mechanism | BLE mesh default | Module |
|-----------|------------------|--------|
| Scan window | **3 s** | `PresenceScanner` |
| Active period | **2 s** | `BBNode` → scanner |
| Steady period | **4 s** | `BBNode` → scanner |
| Post-connect courtesy | **10 s** | `defer_next_pass()` |
| Dial budget | **1 dial / connect pass** | `BBNode._connect_peers` |

### Why MGMT (not `bluetoothctl scan`)

`bluetoothctl` only prints `ManufacturerData` when it **changes**. A stable BB presence never re-emits `[CHG] ManufacturerData` → invisible. MGMT *Device Found* delivers full EIR every detection (`src/transport/le_scan.py`). Discovery does **not** require any Bluetooth pairing UI.

### Optional debugfs tweak

```bash
echo 300 | sudo tee /sys/kernel/debug/bluetooth/hci0/supervision_timeout
```

(units of 10 ms; 300 ≈ 3 s). Optional when adaptive duty cycle is enough.

## Présentations HTML

| Fichier | Usage |
|---------|--------|
| [bb-cds-pipeline.html](bb-cds-pipeline.html) | Présentation synthétique du pipeline CDS |
| [bb-stack-actuel.html](bb-stack-actuel.html) | Vue stack tip (courte) |
| [archive/](archive/) | Anciens decks (historique) |

## Residual design notes (honest)

- **Empty OTA neighbor lists** under legacy AD → weak CDS election from air alone; **dial-every-heard** compensates in dense radio meshes.
- **Adv+scan contention** can still churn fragile boards; Extended Advertising was retired because many controllers only hear legacy AD.
- **`sim/`** models forwarding/CDS logically; it does **not** simulate OTA presence advertising.
- Security PDF: [special_security_BB.pdf](special_security_BB.pdf) (mostly aligned; identity file store vs derived-identity recommendation in §3.1).

## Common mistakes

- Offline peer left in `GROUP_MEMBERS` → dial timeouts (prefer open mesh).
- Different keys on A and B when they should chat → `paquet non déchiffrable`.
- Expecting M to decrypt foreign traffic in the cross-group test → wrong; M must only forward.
- Mixing `ble_l2cap` and `bt_classic` in one mesh → incompatible transports.
- Documenting PSM as only `0x1001` → wrong for BLE (`0x0081`).
- Expecting a Bluetooth pairing/bond step before chat → wrong; tip is `BT_SECURITY_LOW` + group key only.
