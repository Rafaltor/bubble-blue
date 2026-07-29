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
| BlueZ / droits root | sockets L2CAP + scan MGMT |

> Le CoC BLE utilise `BT_SECURITY_LOW` (pas de chiffrement de lien). La sécurité
> est entièrement applicative (clé de groupe + AES-256-GCM). **Aucun
> appairage/bond Bluetooth n’est nécessaire** : les boards ouvrent le canal
> L2CAP directement, sans pairing préalable. C’est ce qui permet à des nœuds
> qui ne se sont jamais rencontrés de communiquer, du moment qu’ils partagent
> la clé de groupe.

```bash
sudo apt update
sudo apt install -y git bluez bluez-tools
# TODO: paquets apt exacts pour `hciconfig` / `btmgmt` selon distro
# (souvent fournis par `bluez` / `bluez-hcidump` / outils BlueZ du labo).
```

#### Ubuntu arm64 (Rubik Pi) — PPA deadsnakes

Sur Ubuntu, **ne pas** compiler depuis les sources si le PPA suffit :

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.14 python3.14-venv python3.14-dev
python3.14 --version
python3.14 -c "import socket; print('AF_BLUETOOTH', hasattr(socket, 'AF_BLUETOOTH'))"
```

#### Debian aarch64 (Arduino UNO Q) — compilation depuis les sources

Sur Debian (UNO Q), deadsnakes n’est en général **pas** disponible : il faut
compiler CPython 3.14. **Critique :** installer les headers **avant**
`./configure`. Sans `libbluetooth-dev`, `AF_BLUETOOTH` / `BDADDR_LE_*` sont
omis **silencieusement** ; sans `libssl-dev`, `ssl` casse.

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

# Vérifs post-install (obligatoires sur board vierge)
/usr/local/bin/python3.14 --version
/usr/local/bin/python3.14 -c "import socket, ssl; print('AF_BLUETOOTH', hasattr(socket, 'AF_BLUETOOTH')); print('ssl OK')"
```

Si `AF_BLUETOOTH` est `False` : headers manquants au configure → réinstaller
les `-dev`, puis **re**configure / rebuild / `altinstall` (un simple
`apt install` après coup ne répare pas un binaire déjà compilé).

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

1. **Transport CoC** — `BLEL2CAPTransport.start()` :
   - `LEAdvertiser.start()` via `btmgmt add-adv` (AD legacy connectable) ;
   - écoute L2CAP `SOCK_SEQPACKET` sur `PSM_BLE` (`0x0081`) avec
     `BT_MODE_LE_FLOWCTL` + **`BT_SECURITY_LOW`** (`ble_coc.apply_le_flowctl`).
2. **HelloManager** — Hellos périodiques sur les liens + (BLE) plan presence.
3. **Découverte** — `MgmtLEScanner` + `PresenceScanner` : candidats BB repérés
   via Manufacturer Data `BB…` ; la presence plane pousse un Hello compact dans
   l’advert (`update_presence` / `LEGACY_PRESENCE_MAX_VALUE_LEN`).
4. **Auto-dial** — thread de connexion vers les cibles
   (`_backbone_dial_targets` / candidats) ; accept de tout peer entrant
   (`l2cap_accept_all=True`) sauf allowlist `--topology`.
5. **Chat** — messages chiffrés sous `GROUP_KEY` ; rôle CDS affiché
   (`RELAY` / `LEAF`).

Le CoC BLE utilise `BT_SECURITY_LOW` (pas de chiffrement de lien). La sécurité
est entièrement applicative (clé de groupe + AES-256-GCM). **Aucun
appairage/bond Bluetooth n’est nécessaire** : les boards ouvrent le canal
L2CAP directement, sans pairing préalable. C’est ce qui permet à des nœuds
qui ne se sont jamais rencontrés de communiquer, du moment qu’ils partagent
la clé de groupe.

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

Gotchas durement appris sur le labo. Chaque entrée : **Symptôme** / **Cause** / **Solution**.

> **Cohérence code :** `LEAdvertiser` (`src/transport/advertising.py`) pilote
> l’advert via `btmgmt add-adv` / `rm-adv` / `advinfo` — **jamais**
> `btmgmt power off`. Aucune garde anti-power-off dans le repo : règle
> **opératoire**.

---

### 1. ⚠️ NE JAMAIS faire `btmgmt power off` (Qualcomm / Arduino UNO Q)

> **PIÈGE LE PLUS COÛTEUX.** Contrôleurs Qualcomm **wcn399x** (Arduino UNO Q
> notamment). Un seul `btmgmt power off` peut tuer l’adaptateur jusqu’au reboot.

| | |
|--|--|
| **Symptôme** | Après un cycle power via `btmgmt` : dmesg montre `mem_dump_status`, `Reading QCA version information failed (-110)`, `Retry BT power ON`. L’adaptateur disparaît (`btmgmt info` → `Index list with 0 items` ; `hciconfig` → DOWN). **Toute** opération socket L2CAP renvoie `ENOSYS` : `[Errno 38] Function not implemented`. |
| **Cause** | Le cycle `power off` / `power on` via `btmgmt` est **toxique** pour ce firmware QCA — il ne se réinitialise pas correctement. |
| **Solution** | **`sudo reboot`** de la board (recharge le firmware au démarrage). Pour l’advertising : **ne pas** utiliser de cycle power `btmgmt` — le nœud BB l’active à chaud via `btmgmt add-adv` (`LEAdvertiser`) / BlueZ. |

```bash
# INTERDIT sur UNO Q / wcn399x :
#   btmgmt power off
#   btmgmt --index 0 power off
```

---

### 2. Même version de code sur toutes les boards

| | |
|--|--|
| **Symptôme** | Log `unsupported private hello version: 0x0X` ; boards se découvrent (presence) mais ne forment pas de voisinage / chat ne passe pas. |
| **Cause** | Format du Hello privé désynchronisé entre commits déployés (`src/control/hello.py` — tip émet **v0x03** avec Ed25519 ; une board trop vieille refuse). |
| **Solution** | Sur **chaque** board : `git pull` puis vérifier le même commit : `git log --oneline -1`. |

---

### 3. Compilation CPython 3.14 sur Debian — headers requis

| | |
|--|--|
| **Symptôme** | `python3.14 -c "import socket; print(hasattr(socket,'AF_BLUETOOTH'))"` → `False`, ou `import ssl` échoue, malgré un binaire 3.14.x. |
| **Cause** | `libbluetooth-dev` et/ou `libssl-dev` absents au `./configure` → modules omis **silencieusement**. |
| **Solution** | Installer les `-dev` **avant** configure, puis recompiler (procédure complète : § Board Setup → Debian). Contrôle : |

```bash
sudo apt install -y libbluetooth-dev libssl-dev \
  build-essential libffi-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev liblzma-dev
# puis depuis les sources Python-3.14.x :
./configure --prefix=/usr/local --enable-optimizations
make -j"$(nproc)"
sudo make altinstall
python3.14 -c "import socket, ssl; assert hasattr(socket, 'AF_BLUETOOTH'); print('OK')"
```

Sur **Ubuntu / Rubik** : préférer deadsnakes (même section Board Setup) — pas de compile sources.

---

### 4. Récupérer un adaptateur Bluetooth planté

Après crash firmware, état incohérent, ou suite à une manip power :

| | |
|--|--|
| **Symptôme** | `hciconfig` DOWN ; `btmgmt info` sans index ; L2CAP `ENOSYS` ; `bb_node` ne peut ni advert ni connect. |
| **Cause** | Daemon BlueZ / contrôleur dans un état incohérent ; ou firmware QCA déjà tué (voir §1). |
| **Solution** | Escalade courte → reboot si l’index ne revient pas : |

```bash
sudo systemctl restart bluetooth
sudo hciconfig hci0 up

# Vérifier :
hciconfig -a          # attendu : UP RUNNING
btmgmt info           # attendu : Index list with 1 item

# Si l'index reste à 0 items → firmware probablement mort :
sudo reboot
# puis re-vérifier hciconfig -a / btmgmt info
```

> Si le plantage suit un `btmgmt power off` sur wcn399x : **reboot immédiat**
> (le `systemctl restart` ne suffit en général pas).

---

### 5. Pas d’appairage Bluetooth requis (sécurité applicative)

| | |
|--|--|
| **Symptôme** | Confusion « il faut binder / pairer les boards avant le chat ». |
| **Cause** | Ancien chemin `BT_SECURITY_MEDIUM` (SMP) — **obsolète** pour le tip. |
| **Solution** | Le CoC BLE utilise `BT_SECURITY_LOW` (`ble_coc.apply_le_flowctl`). La sécurité est entièrement applicative (clé de groupe + AES-256-GCM). **Aucun appairage/bond Bluetooth n’est nécessaire.** |

---

### 6. `SOCK_SEQPACKET` obligatoire pour le CoC LE

| | |
|--|--|
| **Symptôme** | Transfert / CoC LE cassé si on réutilise le pattern Classic. |
| **Cause** | BLE CoC (`ble_coc` / `ble_l2cap`) = `SOCK_SEQPACKET` ; Classic (`l2cap.py`) = `SOCK_STREAM` — non interchangeables. |
| **Solution** | Passer par `make_transport("ble_l2cap")` / `ble_coc`, ne pas unifier les sockets à la main. |

---

## Architecture (runtime tip)

| Plan | Rôle |
|------|------|
| **Presence (OTA)** | Hello compact en AD **legacy connectable** (`presence` v0x02) : anon_id, seq, flag CDS, BD_ADDR |
| **Scan** | MGMT *Device Found* → `PresenceScanner` (fenêtre 3 s, période 2 s / steady 4 s) |
| **Dial** | Backbone CDS si relays connus ; sinon **anneau sparse** (successors anon_id) + cap de degré ; 1 dial/passe ; timeout 8 s |
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
