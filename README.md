# BUBBLE-BLUE

Implémentation du protocole mesh multi-hop **BUBBLE-BLUE** (arXiv:2509.00967) pour :

- **Rubik Pi 3** — Ubuntu Linux, Bluetooth 5.0
- **Arduino UNO Q** — Debian Linux, Bluetooth 5.1

Dépôt GitLab (INRIA) :

```text
git@gitlab.inria.fr:bb/bb_v1.git
```

Clone HTTPS (si pas de clé SSH) :

```text
https://gitlab.inria.fr/bb/bb_v1.git
```

---

## Board Setup

Installation complète d’une board pour faire tourner un nœud BB en **BLE L2CAP CoC**
(`BUBBLE_BLUE_TRANSPORT=ble_l2cap`). Cible : Rubik Pi 3 (Ubuntu arm64) et Arduino UNO Q
(Debian aarch64). Les étapes ci-dessous collent au code
(`src/transport/ble_l2cap.py`, `ble_coc.py`, `bb_node.py`, `config.py`, `requirements.txt`).

### 1. Prérequis — Python 3.14+ (obligatoire)

Le transport BLE exige CPython **≥ 3.14** avec le support socket LE L2CAP. Sans cela,
`src/transport/ble_l2cap.py` lève au import :

- `RuntimeError` si `sys.version_info < (3, 14)`
- `RuntimeError` si `socket.BDADDR_LE_PUBLIC` est absent

Pourquoi : le CoC LE utilise `socket.AF_BLUETOOTH` + `SOCK_SEQPACKET` +
`BTPROTO_L2CAP` et une adresse **4-tuple**
`(bd_addr, psm, cid, bdaddr_type)` avec `BDADDR_LE_PUBLIC` / `BDADDR_LE_RANDOM`
(API absente des builds Python plus anciens). PSM d’écoute : `PSM_BLE = 0x0081`
(`config.py`).

Outils système aussi requis par le code runtime :

| Outil | Utilisé par |
|-------|-------------|
| `hciconfig` | `config.get_local_bd_addr` |
| `btmgmt` | `LEAdvertiser` (advertising legacy) |
| `bluetoothctl` | `PairingAgentSupervisor` (`--chat`) |
| BlueZ / droits root | sockets L2CAP + scan MGMT |

```bash
sudo apt update
sudo apt install -y git bluez bluez-tools
# TODO: paquets apt exacts pour `hciconfig` / `btmgmt` selon distro
# (souvent fournis par `bluez` / `bluez-hcidump` / outils BlueZ du labo).
```

#### Ubuntu arm64 (Rubik Pi) — PPA deadsnakes

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.14 python3.14-venv python3.14-dev
python3.14 --version
```

#### Debian aarch64 (Arduino UNO Q) — compilation depuis les sources

**Critique :** installer les headers **avant** `./configure`. Sans `libbluetooth-dev`,
`AF_BLUETOOTH` / `BDADDR_LE_*` sont omis silencieusement ; sans `libssl-dev`, le module
`ssl` (et souvent `cryptography` / pip) casse.

```bash
sudo apt install -y \
  build-essential libffi-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev liblzma-dev \
  libssl-dev libbluetooth-dev \
  wget

cd /tmp
wget https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tgz
tar xf Python-3.14.6.tgz
cd Python-3.14.6
./configure --prefix=/usr/local --enable-optimizations
make -j"$(nproc)"
sudo make altinstall
python3.14 --version   # doit résoudre vers /usr/local/bin/python3.14
```

### 2. Vérification go / no-go CoC

À exécuter **avant** d’installer le reste. Si ce snippet échoue, le nœud BLE ne démarrera pas.

```bash
sudo python3.14 - <<'PY'
import socket

assert hasattr(socket, "AF_BLUETOOTH"), "AF_BLUETOOTH manquant (libbluetooth au build ?)"
assert hasattr(socket, "BDADDR_LE_PUBLIC"), "BDADDR_LE_PUBLIC manquant (Python < 3.14 ?)"
assert hasattr(socket, "BDADDR_LE_RANDOM"), "BDADDR_LE_RANDOM manquant"
assert socket.AF_BLUETOOTH is not None

print("AF_BLUETOOTH =", True)
print("BDADDR_LE_PUBLIC =", socket.BDADDR_LE_PUBLIC)
print("BDADDR_LE_RANDOM =", socket.BDADDR_LE_RANDOM)

# Bind 4-tuple LE (même forme que ble_l2cap / ble_coc) — psm dynamique 0 = auto.
s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
try:
    s.bind((socket.BDADDR_ANY, 0, 0, socket.BDADDR_LE_PUBLIC))
    print("LE 4-tuple bind: OK")
finally:
    s.close()
print("GO — environnement CoC LE utilisable")
PY
```

Résultat attendu (valeurs numériques de `BDADDR_LE_*` selon le build) :

```text
AF_BLUETOOTH = True
BDADDR_LE_PUBLIC = …
BDADDR_LE_RANDOM = …
LE 4-tuple bind: OK
GO — environnement CoC LE utilisable
```

Contrôle supplémentaire fourni par le repo (écoute réelle sur `PSM_BLE`) :

```bash
cd /chemin/vers/bubble-blue
sudo python3.14 -m src.transport.ble_l2cap
# attendu: "BLE L2CAP environment self-check passed"
```

### 3. Dépendances du projet — piège `sudo`

`bb_node.py` doit tourner en **root** (L2CAP + MGMT). Un `pip install --user` n’est
**pas** visible par root.

Depuis la racine du dépôt :

```bash
git clone git@gitlab.inria.fr:bb/bb_v1.git bubble-blue
cd bubble-blue

sudo python3.14 -m pip install --break-system-packages -r requirements.txt
# équivalent repo : ./scripts/install_py314_deps.sh
# (ajoute aussi --ignore-installed)
```

Contenu installé (`requirements.txt`) : `cryptography`, `cffi`, `simpy`.

Vérification **sous sudo** (le même interpréteur que le nœud) :

```bash
sudo python3.14 -c 'from cryptography.exceptions import InvalidTag; import simpy; print("OK")'
```

Attendu : une ligne `OK`.

### 4. Configuration `.env`

```bash
cp .env.example .env
```

Minimum pour BLE mesh ouvert :

```bash
# Générer une clé 32 octets (64 hex) — à recopier IDENTIQUE sur chaque board du groupe
python3.14 -c "import secrets; print(secrets.token_hex(32))"

# Dans .env :
BUBBLE_BLUE_GROUP_KEY=<64 hex chars>
BUBBLE_BLUE_TRANSPORT=ble_l2cap
```

- `BUBBLE_BLUE_GROUP_KEY` : appartenance à la bulle privée (chiffrement AES-GCM).
  Clés différentes ⇒ logs `paquet non déchiffrable` ; le mesh topologique peut
  quand même forwarder en opaque.
- `BUBBLE_BLUE_TRANSPORT=ble_l2cap` : sélectionne le transport CoC et le PSM
  `0x0081` (`config.load_config` → `PSM_BLE`). Ne pas laisser le défaut
  `bt_classic` (`PSM_BT_CLASSIC = 0x1001`) si tu vises le path presence BLE.
- `BUBBLE_BLUE_GROUP_MEMBERS` / `BUBBLE_BLUE_TOPOLOGY` : **optionnels** (labo /
  `--topology`). En mesh ouvert, les omettre.

Contrôle config (BD_ADDR locale via `hciconfig`) :

```bash
python3.14 config.py
```

Prérequis radio (le code **n’allume pas** le contrôleur tout seul) :

```bash
# TODO: séquence power-on exacte selon image board.
# Le runtime utilise ensuite btmgmt (advertising) et hciconfig (BD_ADDR).
sudo btmgmt --index 0 power on
hciconfig hci0
```

### 5. Lancement

```bash
sudo python3.14 bb_node.py --chat
```

Options utiles (voir `bb_node.py`) :

| Flag | Effet |
|------|--------|
| `--chat` | Boucle chat interactive |
| `--topology A,B,…` | Allowlist / dial list labo (sinon `.env` / découverte) |
| `--peer ADDR` | Pair unique fusionné à la config |
| `--interface hci0` | Contrôleur HCI |
| `--scan SEC` | Inquiry LE (hors mode chat) |

#### Ce que `--chat` automatise réellement (d’après le code)

Ordre approximatif dans `run_chat` → `BBNode.start(..., l2cap_accept_all=True)`
quand `BUBBLE_BLUE_TRANSPORT=ble_l2cap` :

1. **Agent Just Works** — `setup_ble_pairing_agent()` démarre un
   `PairingAgentSupervisor` (`bluetoothctl`, agent `NoInputNoOutput`).
2. **Transport CoC** — `BLEL2CAPTransport.start()` :
   - `LEAdvertiser.start()` via `btmgmt add-adv` (AD legacy connectable) ;
   - écoute L2CAP `SOCK_SEQPACKET` sur `PSM_BLE` (`0x0081`) avec
     `BT_MODE_LE_FLOWCTL` + **`BT_SECURITY_LOW`** (`ble_coc.apply_le_flowctl`) :
     **aucun chiffrement / bonding SMP n’est requis pour ouvrir le CoC**
     (la crypto est applicative).
3. **HelloManager** — Hellos périodiques sur les liens + (BLE) plan presence.
4. **Découverte** — `MgmtLEScanner` + `PresenceScanner` : candidats BB repérés
   via Manufacturer Data `BB…` ; la presence plane pousse un Hello compact dans
   l’advert (`update_presence` / `LEGACY_PRESENCE_MAX_VALUE_LEN`).
5. **Auto-dial** — thread de connexion vers les cibles
   (`_backbone_dial_targets` / candidats) ; accept de tout peer entrant
   (`l2cap_accept_all=True`) sauf allowlist `--topology`.
6. **Chat** — messages chiffrés sous `GROUP_KEY` ; rôle CDS affiché
   (`RELAY` / `LEAF`).

**Appairage manuel : non requis en nominal.** Le CoC s’ouvre en
`BT_SECURITY_LOW`. L’agent Just Works est démarré (chemin héritage /
compatibilité) mais le bring-up nominal **ne dépend pas** d’un bond SMP réussi
ni d’une confirmation passkey.

Note code : le chemin `BBNode._try_auto_bond` (bond auto sur `EPERM`) n’est
actif que si `BBNode(..., setup_pairing_agent=True)`. Sous `--chat`,
`setup_pairing_agent=False` sur `BBNode` (l’agent tourne à part dans
`bb_node.py`) — ce filet auto-bond **n’est donc pas** celui qui ouvre les liens
en mode chat.

Attendu après quelques secondes (boards en portée, même clé / transport) :

```text
transport ble_l2cap · PSM 0x0081 · local … · RELAY|LEAF · N peer(s)
```

Labo topologie forcée :

```bash
sudo python3.14 bb_node.py --chat --topology AA:BB:CC:DD:EE:02
```

Ne **jamais** committer `.env` ni `.bb-identity-*.bin`.

---

## Pièges & dépannage (Bluetooth)

Gotchas durement appris sur le labo. Chaque entrée : symptôme → cause → solution.
Quand l’état **actuel** du code contredit un récit historique, c’est signalé explicitement.

### 1. Ne jamais `btmgmt power off` (Qualcomm wcn399x / Arduino UNO Q)

| | |
|--|--|
| **Symptôme** | Après un cycle `power off` / `power on` via `btmgmt` : dmesg avec `mem_dump_status`, `Reading QCA version information failed -110`, `Retry BT power ON` ; `btmgmt` affiche `Index list with 0 items` ; sockets L2CAP → `ENOSYS` (errno 38, *Function not implemented*). |
| **Cause** | Sur ce firmware, un power-cycle `btmgmt` est toxique : l’adaptateur disparaît jusqu’à recharge propre du firmware. |
| **Solution** | **Reboot de la board** (seul moyen fiable de recharger le firmware). Ne pas piloter l’advertising via un cycle power `btmgmt`. Le code utilise `btmgmt add-adv` / `LEAdvertiser` sans power off/on. |

> Pas de garde-fou logiciel dans le repo : c’est une règle **opératoire** labo.

### 2. Aucun `bluetoothctl` manuel pendant `bb_node`

| | |
|--|--|
| **Symptôme** | Bond / SMP en passkey : `journalctl -u bluetooth` montre `device_confirm_passkey`, `Failed requesting authentication` ; déconnexions ~20 s (HCI Reason **0x13**). |
| **Cause** | Un `bluetoothctl` résiduel réenregistre un agent **KeyboardDisplay**, qui écrase le **NoInputNoOutput** du `PairingAgentSupervisor` → numeric comparison au lieu de Just Works (`pairing_agent.py`). |
| **Solution** | Fermer **tous** les `bluetoothctl` avant `bb_node`. Le supervisor logge `Just Works capability: CONFIRMED` / `FRAGILE` / `FAILED` et avertit (`AVERTISSEMENT: agent concurrent détecté…`). |

> Toujours pertinent : `--chat` démarre bien un `PairingAgentSupervisor`. Moins critique pour ouvrir le CoC en tip (`BT_SECURITY_LOW`, voir §4), mais indispensable dès qu’un bond SMP est tenté.

### 3. Même version de code sur toutes les boards

| | |
|--|--|
| **Symptôme** | Log `unsupported private hello version: 0x03` (ou autre) ; boards visibles en présence mais voisinage / identité privée cassés. |
| **Cause** | Format Hello privé désynchronisé (`src/control/hello.py` : parseur n’accepte que les versions connues ; tip actuel émet **v0x03** si clé Ed25519 présente). Une board trop vieille refuse le Hello privé. |
| **Solution** | `git pull` partout ; vérifier le même commit : `git log --oneline -1`. |

### 4. `EPERM` (errno 13) sur connect — **attention : tip ≠ récit MEDIUM**

| | |
|--|--|
| **Symptôme (historique, `BT_SECURITY_MEDIUM`)** | `connect … failed: [Errno 13] Permission denied` en boucle ; peer connecté/déconnecté. |
| **Cause (historique)** | CoC LE en **MEDIUM** exige un lien chiffré ; sans bond SMP, le kernel refuse (`EPERM`). |
| **État tip (code actuel)** | `ble_coc.apply_le_flowctl` force **`BT_SECURITY_LOW`** précisément pour **éviter** ce `EPERM` et le flapping SMP / Reason 0x13. En nominal, un pair **non bondé doit pouvoir ouvrir le CoC**. |
| **Filet restant** | Si un `EPERM` survient encore, `BBNode._connect_peers` tente `_try_auto_bond` → `ensure_bonded` + backoff (`_backoff_after_connect_fail`). **Mais** sous `bb_node.py --chat`, `BBNode(..., setup_pairing_agent=False)` : le supervisor vit hors de `BBNode`, donc **`_try_auto_bond` n’a pas de supervisor** et échoue immédiatement. |
| **Solution tip** | Garder `BT_SECURITY_LOW` (défaut). Ne pas « diagnostiquer EPERM = il faut binder » comme le path nominal. Si tu repasses en `MEDIUM`, il faudra agent Just Works **sur les deux boards** *et* `setup_pairing_agent=True` sur `BBNode` pour que l’auto-bond fonctionne. |

### 5. Compilation CPython sans headers = modules omis silencieusement

| | |
|--|--|
| **Symptôme** | `AF_BLUETOOTH` ou `ssl` absents alors que `python3.14 --version` affiche 3.14.x. |
| **Cause** | `libbluetooth-dev` / `libssl-dev` absents au moment du `./configure` → modules non compilés, sans erreur fatale. |
| **Solution** | Installer les `-dev` **avant** `./configure`, puis recompiler (`make altinstall`). Refaire le test go/no-go CoC du § Board Setup. |

### 6. `SOCK_SEQPACKET` obligatoire pour le CoC LE

| | |
|--|--|
| **Symptôme** | Transfert / CoC LE cassé si on réutilise le pattern Classic. |
| **Cause** | BLE CoC (`ble_coc.new_socket` / `ble_l2cap`) utilise `AF_BLUETOOTH` + **`SOCK_SEQPACKET`** + `BTPROTO_L2CAP`. Le transport Classic (`l2cap.py`) utilise **`SOCK_STREAM`** — ce n’est **pas** interchangeable. |
| **Solution** | Ne pas « unifier » les sockets à la main ; passer par `make_transport("ble_l2cap")` / `ble_coc`. |

### 7. Persistance des bonds BlueZ

| | |
|--|--|
| **Symptôme** | Bonds disparus après reboot ; (surtout pertinent si lien en `MEDIUM`). |
| **Cause** | BlueZ stocke les bonds sous `/var/lib/bluetooth/<adapter>/`. Si `/var` est en **tmpfs**, tout est perdu au reboot. |
| **Solution** | `mount \| grep tmpfs` — vérifier que `/var` (ou `/var/lib`) n’est pas volatil. |
| **Note tip** | Avec **`BT_SECURITY_LOW`**, le mesh **n’a pas besoin** de bonds pour le CoC. Un bond perdu ne bloque plus le path nominal ; le récit « se refait tout seul via auto-bond » ne s’applique pleinement que si auto-bond est réellement branché (voir §4). |

---


| Plan | Rôle |
|------|------|
| **Presence (OTA)** | Hello compact en AD **legacy connectable** (`presence` v0x02) : anon_id, seq, flag CDS, BD_ADDR |
| **Scan** | MGMT *Device Found* → `PresenceScanner` (fenêtre 3 s, période 2 s / steady 4 s) |
| **Dial** | Backbone CDS si relays connus ; sinon **dial every heard** ; 1 dial/passe ; timeout 8 s |
| **Contrôle** | Hellos OTA + L2CAP ; CDS Wu-Li |
| **Identité** | `PKT_ANNOUNCE` (burst + périodique) |
| **Forward** | RELAY CDS **ou** ≥ 2 liens L2CAP |
| **Crypto** | AES-256-GCM ; lien `BT_SECURITY_LOW` |

### Mesh ouvert / bulles privées

| Plan | Gouverné par |
|------|----------------|
| Topologique (discovery, CDS, forward opaque) | Ouvert à tout nœud BB |
| Applicatif (chat, déchiffrement) | `BUBBLE_BLUE_GROUP_KEY` |

Détails : [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Présentations HTML

| Fichier | Usage |
|---------|--------|
| [docs/bb-cds-pipeline.html](docs/bb-cds-pipeline.html) | **Présentation CDS** (à ouvrir dans le navigateur) |
| [docs/bb-stack-actuel.html](docs/bb-stack-actuel.html) | Vue stack courte à jour |
| [docs/archive/](docs/archive/) | Anciens decks (historique uniquement) |

Navigation slides : flèches ← → · molette · `F` plein écran.

---

## Structure du dépôt

| Path | Contenu |
|------|---------|
| `bb_node.py` | Entrypoint CLI |
| `config.py` | Defaults (PSM Classic `0x1001`, BLE `0x0081`, timers) |
| `src/api/` | `BBNode` |
| `src/transport/` | L2CAP, advertising, scan MGMT |
| `src/control/` | Hello, presence, ANNOUNCE |
| `src/forwarding/` | CDS + forwarder |
| `src/security/` | Crypto / keys / signing |
| `tests/` | Tests |
| `sim/` | Simulation (pas de modèle OTA presence) |
| `docs/` | Config, PDF sécu, HTML |
| `scripts/install_py314_deps.sh` | Install deps root |

---

## Statut

- Mesh BLE ouvert avec presence legacy + auto-dial + ANNOUNCE
- Multihop chat validé Arduino ↔ Rubik
- Risques résiduels : contention adv+scan ; listes voisins OTA vides (compensées par dial-heard)

Spec sécu : [docs/special_security_BB.pdf](docs/special_security_BB.pdf).

## Références

- Paper : [arXiv:2509.00967](https://arxiv.org/abs/2509.00967)
- Config lab : [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
