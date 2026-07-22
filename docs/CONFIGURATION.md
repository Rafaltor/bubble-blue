# BUBBLE-BLUE configuration

## Mesh ouvert et bulles privées

BUBBLE-BLUE est conçu comme un **mesh ouvert au niveau topologique** et des **bulles privées au niveau applicatif**.

### Plan topologique (ouvert)

Accessible à **tout nœud BB**, indépendamment de `BUBBLE_BLUE_GROUP_KEY` :

| Mécanisme | Module | Comportement |
|-----------|--------|--------------|
| Beacon universel | `src/transport/advertising.py` (`LEAdvertiser`) | AD statique : Flags `0x06` + Manufacturer Data company `0xFFFF`, magic ASCII `BB`, version protocole `0x01` |
| Scan périodique | `src/control/presence_scanner.py` (`PresenceScanner`) | Scan LE 3 s, filtre candidats BB ; duty cycle adaptatif (15 s actif → 60 s une fois tous les candidats admis connectés) ; courtoisie post-connexion (10 s) |
| Agent pairing | `src/transport/pairing_agent.py` (`PairingAgentSupervisor`) | `agent off` puis NoInputNoOutput (Just Works, évite MITM numérique ~20 s / Reason 0x13) |
| Auto-connect | transport L2CAP / `BBNode` | Établissement de liens vers les candidats détectés (sans adresses préconfigurées) |
| Hellos publics | `src/control/hello.py` | Partie publique lisible par tous ; anon_ids appris sur le fil (cross-group) |
| CDS / RELAY | `src/control/hello_manager.py`, `src/forwarding/cds.py` | Élection RELAY/LEAF sur la topologie anonyme ; forward **opaque** des `PKT_DATA` |

Un relais inter-groupe **reste connecté** et **continue de forwarder** même s’il ne peut pas déchiffrer le trafic d’un autre groupe.

### Plan applicatif (privé)

Gouverné uniquement par la **clé de groupe** :

- **Identité** — résolution via la partie **privée** des Hellos (membres du même groupe uniquement).
- **Chiffrement** — `PKT_DATA` chiffrés AES-GCM avec clé dérivée du groupe ; sans la clé : log `paquet non déchiffrable (mauvaise clé ?) de <src>` **au plus**, jamais d’expulsion du relais.
- **Chat** — seuls les nœuds partageant la même `BUBBLE_BLUE_GROUP_KEY` déchiffrent les messages du groupe.

### Overrides restrictifs (labo)

Ces réglages **ne font pas partie du modèle opportuniste** ; ils servent à cadrer une expérience :

| Mécanisme | Effet |
|-----------|--------|
| `BUBBLE_BLUE_GROUP_MEMBERS` | Liste de pairs à composer / allowlist de dial |
| `BUBBLE_BLUE_TOPOLOGY` / `--topology` | Topologie forcée (ex. ligne A—M—B) ; restreint accept/connect |
| `--peer` | Pair unique en complément |

En mode mesh ouvert, un `.env` **réduit** (clé + transport) suffit ; les adresses BD ne sont pas requises.

---

## Protocole de validation — 3 boards, deux temps

Matériel : trois boards BB (ex. 2× Rubik Pi + 1× UNO Q), portée radio commune, Python 3.14 + `BUBBLE_BLUE_TRANSPORT=ble_l2cap` si applicable.

### Temps 1 — Auto-établissement (mesh complet opportuniste)

**Objectif :** vérifier que le plan topologique ouvert suffit sans configuration d’adresses.

**Configuration `.env` (identique sur les 3 nœuds, sauf clé si vous testez déjà le même groupe) :**

```bash
BUBBLE_BLUE_GROUP_KEY=<64 hex chars, même clé partout>
BUBBLE_BLUE_TRANSPORT=ble_l2cap   # ou bt_classic selon le labo
# Pas de BUBBLE_BLUE_GROUP_MEMBERS
# Pas de BUBBLE_BLUE_TOPOLOGY
```

**Procédure :**

1. Démarrer les trois nœuds, sans `--topology` ni membres :
   ```bash
   sudo python3.14 bb_node.py --chat
   ```
2. **Attendu (< 30 s) :** full mesh — chaque nœud affiche **2 peer(s)** (ou 3 connexions symétriques selon affichage), Hellos échangés, rôles CDS stabilisés.
3. **Kill / restart** d’un nœud (ex. board du milieu) :
   - **Éviction** — les deux autres voient `peer déconnecté` ; le candidat disparaît du voisinage après timeout.
   - **Réintégration auto** — au redémarrage, le nœud est re-découvert (beacon + scan), reconnecté, réapparaît dans les tables Hello sans reconfiguration manuelle des BD_ADDR.

**Critères de succès :** aucune adresse saisie à la main ; mesh 3-cliques en moins de 30 s ; recovery après restart sans éditer `.env`.

### Temps 2 — Relais inter-groupe (test décisif, vision du préprint)

**Objectif :** démontrer qu’un nœud **M** d’un **groupe différent** devient RELAY et transporte le trafic chiffré entre **A** et **B** sans pouvoir le lire — scénario central de l’article (arXiv:2509.00967).

**Configuration :**

| Nœud | Rôle | Group key | Topologie |
|------|------|-----------|-----------|
| **A** | extrémité | `GK_A` (clé groupe A) | `--topology <BD_M>` |
| **M** | milieu (relais) | `GK_M` (**≠** `GK_A`) | `--topology <BD_A>,<BD_B>` |
| **B** | extrémité | `GK_A` (même clé que A) | `--topology <BD_M>` |

Topologie L2CAP forcée en **ligne A — M — B** (adjacence radio réelle ou placement physique). A et B partagent la même clé ; M a une clé distincte.

**Exemple de lancement :**

```bash
# Sur A (noter BD_ADDR de M après scan ou logs) :
sudo python3.14 bb_node.py --chat --topology AA:BB:CC:DD:EE:M0

# Sur M (clé différente dans .env) :
sudo python3.14 bb_node.py --chat --topology AA:BB:CC:DD:EE:A0,AA:BB:CC:DD:EE:B0

# Sur B (même clé que A) :
sudo python3.14 bb_node.py --chat --topology AA:BB:CC:DD:EE:M0
```

**Attendu :**

1. **Tables Hello** — M apparaît dans les voisinages de A et B (partie publique) ; A et B voient M ; topologie 2-hop cohérente (tests similaires : `tests/test_cross_group_hello.py`).
2. **Rôle CDS** — M affiche **RELAY** (gateway entre deux pairs symétriques non adjacents dans sa vue).
3. **Forward opaque** — M forwarde les `PKT_DATA` de A vers B (et inversement) ; sur M, logs **`paquet non déchiffrable`** au plus — **jamais** de drop ni d’expulsion de M du mesh.
4. **Chat multihop** — depuis A, message vers B (alias ou BD_ADDR) **traverse M** et arrive déchiffrable chez B ; M ne voit que des octets opaques.

**Critères d’échec :** M expulsé ou absent des tables ; M en LEAF alors qu’il est le seul pont A↔B ; A et B ne peuvent pas chatter via M ; M déchiffre le trafic du groupe A.

---

## What is **not** machine-specific (protocol defaults)

| Setting | Value | Where |
|---------|-------|--------|
| L2CAP PSM | `0x1001` | `config.py` |
| Hello interval | 5 s | `config.py` |
| Neighbor timeout | 15 s | `config.py` |
| TTL max | 10 | `config.py` |
| Replay window | 256 | `config.py` |
| Packet types / crypto sizes | constants | `config.py`, `src/security/` |

These are the same on every node unless you change the code.

## What **was** specific to the lab setup (now generalized)

| Item | Before | General behaviour now |
|------|--------|------------------------|
| `.env.example` | Real BD_ADDR (`40:D9:…`, `14:B5:…`) + zero key | Empty placeholders + comments |
| `BUBBLE_BLUE_GROUP_MEMBERS` | All boards listed including offline | Documented: list only **reachable** peers; local addr auto-ignored |
| `BUBBLE_BLUE_LOCAL_BD_ADDR` | Comment only | Implemented in `config.py` |
| `BUBBLE_BLUE_TOPOLOGY` | N/A | New env var (same as `--topology`) |
| `BUBBLE_BLUE_INTERFACE` | N/A | New env var (default `hci0`) |
| `--topology` required for chat | Easy to forget | Falls back to `.env` members / `BUBBLE_BLUE_TOPOLOGY` |
| `BUBBLE_BLUE_REMOTE_BD_ADDR` | Single fixed peer | Optional legacy; prefer `GROUP_MEMBERS` |
| Presentation HTML | Example logs with your BD_ADDR | Documentation only (unchanged) |
| Self-tests (`cds.py`, `hello.py`, …) | Example addresses in `if __name__` blocks | Harmless test fixtures (not used at runtime) |

## Required per deployment (every group of boards)

1. **`BUBBLE_BLUE_GROUP_KEY`** — defines the **private bubble** (who decrypts group chat). Same key on all nodes that should read each other's messages.
2. **Peer list (optional — lab override only)** — at least one of:
   - `BUBBLE_BLUE_GROUP_MEMBERS` in `.env`, or
   - `BUBBLE_BLUE_TOPOLOGY` in `.env`, or
   - `bb_node.py --topology ADDR,...`, or
   - `bb_node.py --peer ADDR` (single peer).

   Omit entirely for **open-mesh auto-discovery** (see [validation Temps 1](#temps-1--auto-établissement-mesh-complet-opportuniste)). When set, each node lists **other** nodes it should connect to (not its own BD_ADDR).

## Minimal recipes

### Open mesh (3 boards, no addresses)

See [Temps 1 — Auto-établissement](#temps-1--auto-établissement-mesh-complet-opportuniste): `.env` with group key + transport only, `bb_node.py --chat` on each board.

### Two boards (chat, explicit peers — lab)

```bash
# On each board: copy .env.example → .env, set the SAME group key,
# and GROUP_MEMBERS = the other board's BD_ADDR only.

sudo python3 bb_node.py --chat
```

### Listen-only + one dialer (no .env members)

```bash
# Board A (accepts any incoming):
sudo python3 bb_node.py --chat

# Board B:
sudo python3 bb_node.py --chat --topology <BD_ADDR_OF_A>
```

### Cross-group relay (3 boards, line A—M—B)

See [Temps 2 — Relais inter-groupe](#temps-2--relais-inter-groupe-test-décisif-vision-du-préprint): different key on M, `--topology` forcing a line.

### Discover peer BD_ADDR

```bash
sudo python3 bb_node.py --scan 8
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `BUBBLE_BLUE_GROUP_KEY` | 32-byte AES key (hex, 64 chars) |
| `BUBBLE_BLUE_GROUP_MEMBERS` | Comma-separated peers to dial / allowlist |
| `BUBBLE_BLUE_TOPOLOGY` | Same as `--topology` |
| `BUBBLE_BLUE_REMOTE_BD_ADDR` | Optional single peer (`--peer`) |
| `BUBBLE_BLUE_INTERFACE` | HCI device (default `hci0`) |
| `BUBBLE_BLUE_LOCAL_BD_ADDR` | Override if `hciconfig` fails |

## CLI (`bb_node.py`)

| Flag | Purpose |
|------|---------|
| `--chat` | Interactive chat |
| `--topology` | Peers (overrides env topology) |
| `--peer` | Single peer (merged with members) |
| `--interface` | HCI (default from env or `hci0`) |
| `--scan SEC` | BLE inquiry |
| `--send` / `--dst` | Send one message (non-chat mode) |

## Common mistakes

- **Offline peer in `GROUP_MEMBERS`** → `Connection timed out` / `Host is down` (remove it from the list, or use open mesh without members).
- **Different group keys on A and B** → `paquet non déchiffrable` on receive (expected on M in Temps 2 ; wrong if A and B should chat).
- **No peer list in lab mode** → node listens but never dials → `0 peer(s)` until the other side connects or beacon auto-connect kicks in.
- **Allowlist too strict (`--topology`)** → incoming connection rejected if peer BD_ADDR not in topology (intentional for Temps 2 line topology).
- **Confusing planes** → a foreign-group RELAY showing `paquet non déchiffrable` is **normal** ; it must still forward and stay in the mesh.

## BLE coexistence (scan vs active links)

On legacy controllers, a long LE scan window can starve connection supervision events and drop active L2CAP links (kernel default supervision timeout ≈ **420 ms** vs scan windows of several seconds).

BUBBLE-BLUE mitigates this in software:

| Mechanism | Default | Module |
|-----------|---------|--------|
| Scan window | **3 s** | `PresenceScanner.scan_window_s` |
| Active discovery period | **15 s** | `scan_period_s` while unknown / unconnected candidates remain |
| Steady period | **60 s** | `steady_period_s` when every non-quarantined discovered candidate is an admitted active peer (`idle_check` from `BBNode`) |
| Post-connect courtesy | **10 s** | `defer_next_pass()` after each peer connect — skips the next scan pass if it would fall inside the deferral window (SMP, GATT, first Hello) |

### Optional lab tweak (debugfs)

If links still drop under heavy RF or very old controllers, raise the **central supervision timeout** (units of 10 ms):

```bash
# Default is often 42 (= 420 ms). Suggest 300 (= 3 s) for demanding labs:
echo 300 | sudo tee /sys/kernel/debug/bluetooth/hci0/supervision_timeout
```

Requires debugfs mounted; replace `hci0` with your interface. This is **optional** when the adaptive scanner duty cycle is sufficient.

### Pairing agent (Just Works)

`PairingAgentSupervisor` keeps an interactive `bluetoothctl` with verified `NoInputNoOutput` default agent. **Do not** fire-and-forget `agent NoInputNoOutput` after `bluetoothctl` starts — it auto-registers `KeyboardDisplay` and silently rejects a later NoInputNoOutput, leading to numeric-comparison MITM and ~20 s disconnects (Reason **0x13**). Sequence: `agent off` → `agent NoInputNoOutput` → `default-agent` → `pairable on`.

### Bond automatique Just Works

Quand une board BLE découvre un pair BB **non-bondé**, l’ouverture du L2CAP CoC échoue avec `EPERM` (pas de lien chiffré). `BBNode` tente alors un bond Just Works via `PairingAgentSupervisor.ensure_bonded` (`info` → `pair`), puis retente le connect.

**Conditions obligatoires (sinon SMP demande un passkey) :**

1. **Les DEUX boards** doivent avoir `PairingAgentSupervisor` actif **avant** toute tentative de connexion / bond auto. Just Works n’est choisi que si **les deux** côtés déclarent `NoInputNoOutput`.
2. **Aucun `bluetoothctl` manuel** ne doit rester ouvert sur une board. Un shell interactif réenregistre `KeyboardDisplay` comme agent par défaut et casse le Just Works (négociation → numeric comparison).
3. Au démarrage le supervisor logue un avertissement s’il détecte d’autres PID `bluetoothctl`, et appelle `verify_just_works_capability()` (marqueurs `Agent registered` / `Default agent request successful` + absence de concurrent + probe D-Bus `org.bluez.AgentManager1`).

**Symptôme d’échec typique :**

```bash
journalctl -u bluetooth -b | grep -E 'device_confirm_passkey|Failed requesting authentication'
```

Si vous voyez `device_confirm_passkey` / `Failed requesting authentication`, un côté n’est **pas** en NoInputNoOutput (agent concurrent ou peer sans supervisor). Fermez tout `bluetoothctl` manuel, redémarrez les deux nodes BB, vérifiez les logs `[PAIRING] Just Works capability: CONFIRMED`.
