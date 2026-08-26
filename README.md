# BUBBLE-BLUE

Implémentation du protocole mesh multi-hop **BUBBLE-BLUE** (arXiv:2509.00967) pour :

- **Rubik Pi 3** — Ubuntu Linux, Bluetooth 5.0
- **Arduino UNO Q** — Debian Linux, Bluetooth 5.1

Dépôts :

| Remote | URL | Usage |
|--------|-----|-------|
| `origin` | `https://github.com/Rafaltor/bubble-blue.git` | **Déploiement boards** (`git pull`) |
| `gitlab` | `git@gitlab.inria.fr:bb/bb_v1.git` | Miroir INRIA |

Les boards suivent `origin`. Pour déployer : commit + push sur GitHub, puis
`git pull` sur chaque board — ne pas copier de fichiers à la main (`scp`),
sous peine de laisser des arbres de travail divergents.

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

Le paquet **`bluez`** fournit à lui seul `hciconfig`, `btmgmt` et `btmon`
(vérifié sur Debian 13 / BlueZ 5.82, image Arduino UNO Q) :

```bash
sudo apt update
sudo apt install -y git bluez

# Contrôle : les trois doivent répondre
command -v hciconfig btmgmt btmon
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

Sur les images Rubik Pi et UNO Q, `bluetooth.service` monte l’adaptateur au
boot — il n’y a normalement **rien à faire**. Contrôle :

```bash
hciconfig hci0      # attendu : UP RUNNING
btmgmt info         # attendu : Index list with 1 item
```

Si l’adaptateur est `DOWN` :

```bash
sudo systemctl restart bluetooth
sudo hciconfig hci0 up
```

> **Ne jamais** utiliser `btmgmt power on/off` pour réveiller la radio : sur les
> contrôleurs QCA (UNO Q) ce cycle tue le firmware jusqu’au reboot (§1 des
> pièges). Le runtime n’en a pas besoin — il active l’advertising à chaud via
> `btmgmt add-adv`.

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

#### Avant de rebooter : chercher un `btmgmt` zombie

| | |
|--|--|
| **Symptôme** | `btmgmt info` ne rend **jamais la main** (aucune sortie, pas d’erreur) alors que `hciconfig hci0` affiche `UP RUNNING`. `bb_node` se fige au démarrage dans `LEAdvertiser.start()`. |
| **Cause** | Un `btmgmt` précédent est resté bloqué et **monopolise la socket MGMT** — typiquement un `btmgmt power on` lancé à la main qui n’est jamais revenu. Observé sur une board avec un processus figé depuis 28 jours. |
| **Solution** | Tuer les zombies **par PID** puis relancer BlueZ : |

```bash
ps -eo pid,etime,args | grep '[b]tmgmt'   # noter les PID et leur âge
sudo kill -9 <PID>...
sudo systemctl restart bluetooth
timeout 10 btmgmt info                    # doit répondre en < 1 s
```

> Ne pas utiliser `pkill -f btmgmt` depuis un script : le motif matche aussi la
> ligne de commande du shell appelant, qui se tue lui-même.

**Attention au contexte d’exécution.** Si `btmgmt` se fige y compris **sans
`sudo`** (au lieu de renvoyer une erreur de permission immédiate), il ne parle
pas du tout à la socket MGMT : c’est l’environnement appelant qui est en cause,
pas l’adaptateur. Un shell confiné (namespace utilisateur, sandbox d’agent,
conteneur sans `CAP_NET_ADMIN`) produit exactement ce symptôme, et le `btmgmt`
laissé derrière reste bloqué indéfiniment. Vérifier depuis un shell normal
avant de conclure à une panne matérielle :

```bash
ssh user@la-machine 'timeout 8 sudo btmgmt info'   # doit répondre en < 2 s
```

Un reboot ne corrige **pas** ce cas — il faut lancer le nœud depuis un shell
non confiné.

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
| **Dial** | Backbone CDS si relays connus ; sinon **dial tout le catalogue de présence** ; 1 dial/passe ; timeout 8 s |
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

> **Catalogue de présence vs `heard`.** Le set `heard` expire (TTL 25 s) et le
> scanner se met volontairement en veille quand tous les candidats connus sont
> déjà connectés. Un mesh stable « oublie » donc tout le monde en moins d’une
> minute. Le dial part du **catalogue cumulé** (`_presence_addr`, tout anon_id
> vu depuis le démarrage) : sans ça, la liste de dial est vide au moment précis
> où un lien tombe, et le nœud ne peut plus jamais revenir
> (`tests/test_dial_recovery.py`).

---

## API applicative (pour une app / un écran)

Tout passe par `BBNode` — pas besoin de toucher au transport ni au forwarder.

```python
from src.api.bb_api import BBNode

node = BBNode(interface="hci0", quiet=True)

# Callbacks — à brancher AVANT start(). on_message est obligatoire.
node.on_message = lambda sender_bd, text: print(f"{sender_bd}: {text}")
node.on_peer_connected = lambda bd: print(f"+ {bd}")
node.on_peer_disconnected = lambda bd: print(f"- {bd}")
node.on_log = lambda msg, is_err: None          # diagnostics facultatifs

node.start(l2cap_accept_all=True)               # root requis (L2CAP + MGMT)
try:
    node.send("hello mesh")                     # broadcast groupe
finally:
    node.stop()
```

| Membre | Type | Usage écran |
|--------|------|-------------|
| `on_message(sender_bd, text)` | callback | Afficher un message reçu |
| `on_peer_connected(bd)` / `on_peer_disconnected(bd)` | callback | Mettre à jour la liste des voisins |
| `on_log(msg, is_err)` | callback | Journal / debug (facultatif) |
| `send(text)` | méthode | Broadcast à la bulle |
| `send_unicast(text, dst_bd)` | méthode | Message dirigé (`via_peer=` pour forcer le lien) |
| `send_subgroup(text, recipients)` | méthode | Multicast sous-groupe |
| `peers()` | `list[str]` | Voisins L2CAP actifs |
| `is_relay()` | `bool` | Badge RELAY / LEAF |
| `local_bd_addr` | `str` | Identité locale à afficher |
| `current_epoch()` | `int` | Époque de clé courante |

Points à connaître côté UI :

- `send()` lève si aucun pair n’est connecté — afficher l’état plutôt que
  planter, et réessayer quand `on_peer_connected` arrive.
- Les callbacks sont appelés depuis des **threads** du runtime : passer par la
  file d’événements du toolkit graphique avant de toucher aux widgets.
- Les messages émis localement ne reviennent **pas** via `on_message` : afficher
  ses propres envois directement dans l’UI.

Exemple complet et exécutable : [`scripts/bb_probe.py`](scripts/bb_probe.py).

---

## Application écran (`apps/`)

### Pourquoi deux processus

Le mesh exige **Python 3.14** (sockets L2CAP LE) alors que **PyGObject n’existe
que pour le Python de la distribution** : les deux ne peuvent pas partager un
interpréteur. Ils communiquent donc par une socket Unix en JSON ligne à ligne.

Cette frontière est un choix, pas seulement une contrainte :

- l’interface ne tourne **pas en root** — seul le démon en a besoin ;
- l’UI peut planter ou être relancée **sans faire tomber les liens**, qui
  mettent ~40 s à converger ;
- c’est exactement là que passerait le Bridge RPC si les UNO Q étaient équipées
  de leur shield (l’UI serait alors un sketch côté STM32, le démon ne bouge pas).

| Fichier | Interpréteur | Droits | Rôle |
|---------|--------------|--------|------|
| `apps/meshd.py` | 3.14 | root | Porte le `BBNode`, sert la socket |
| `apps/screen_ui.py` | système | utilisateur | Interface tactile GTK4 |
| `apps/protocol.py` | les deux | — | Format de trame partagé |
| `scripts/meshd_client.py` | système | utilisateur | Client terminal (sans écran) |
| `scripts/meshd_fake.py` | système | utilisateur | Démon simulé, sans radio |

Le protocole complet est décrit en tête de [`apps/protocol.py`](apps/protocol.py).

### Développer sans matériel

`meshd_fake.py` sert le vrai protocole sans toucher au Bluetooth — pas
d’adaptateur, pas de root, pas d’attente de convergence :

```bash
python3 scripts/meshd_fake.py --socket /tmp/bb.sock &
python3 apps/screen_ui.py    --socket /tmp/bb.sock
```

### Sur une board

```bash
# 1. le démon (root, une seule instance)
sudo python3.14 apps/meshd.py

# 2. l'interface, en utilisateur normal
python3 apps/screen_ui.py --kiosk
```

Lancé via `sudo`, le démon donne l’accès à la socket au **groupe de
l’utilisateur appelant** (`root:<groupe>`, mode `0660`) : l’UI s’y connecte sans
privilège, mais la socket n’est pas ouverte à tout le monde — qui peut y écrire
peut publier dans le chat au nom de la board.

Sans écran physique, le client terminal suffit à valider une board :

```bash
python3 scripts/meshd_client.py                                  # interactif
python3 scripts/meshd_client.py --send "test" --duration 60      # scripté
```

### Pile graphique (Rubik Pi 3)

Le Rubik est livré *headless* : ni serveur graphique, ni typelib GTK.

```bash
sudo apt-get install -y gir1.2-gtk-4.0 cage
```

`cage` est un compositeur Wayland kiosque — une seule application, plein écran,
pas d’environnement de bureau :

```bash
cage -- python3 apps/screen_ui.py --kiosk
```

### Interface

Dimensionnée pour la dalle 1024×600. Elle embarque **son propre clavier
AZERTY** : les dalles sont tactiles uniquement et une session kiosque n’a pas de
shell d’où lancer un clavier système. Le clavier reste replié tant que la zone
de saisie n’a pas été touchée, pour laisser la hauteur à la conversation.

> **Piège de test.** Pour capturer l’UI sous `Xvfb`, forcer `GSK_RENDERER=cairo`
> (sinon GTK4 rend via le pilote Adreno, hors du framebuffer capturable) et
> vérifier qu’aucun `/tmp/.X99-lock` d’une instance précédente ne traîne — c’est
> ce verrou qui produit des captures vides alors que l’application va bien.

### Ce qui est vérifié

| Vérification | Résultat |
|--------------|----------|
| Contrat démon↔UI (`tests/test_meshd_protocol.py`) | 7 cas, sans adaptateur |
| Chat réel à travers le démon (arduinoq ↔ rubik-inria) | **14 envoyés / 14 reçus**, 0 refus |
| UI GTK4 sur Rubik Pi 3, 1024×600 | rendu conforme sur le matériel cible |
| Tenue de l’UI (démon simulé) | 4 h continues, aucune erreur |

---

## Tests

Les fichiers de `tests/` sont autonomes (aucune dépendance de dev, pytest
n’est pas requis) — c’est ce qui permet de les lancer tels quels sur les boards :

```bash
./scripts/run_tests.sh                          # python3.14, sinon python3
PYTHON=./.venv314/bin/python ./scripts/run_tests.sh
```

Bancs matériels (nécessitent des boards en portée) :

| Script | Usage |
|--------|-------|
| `scripts/bb_probe.py` | Soak multi-board : stabilité des liens + livraison chat, résumé JSON |
| `scripts/meshd_client.py` | Chat en terminal via le démon — valide une board sans écran |
| `scripts/phase1a_manual.py` | Banc crypto interactif (`server` / `client` / `intruder` / `replay`) |

Soak type — même commande sur chaque board, puis comparer les résumés :

```bash
sudo python3.14 scripts/bb_probe.py --duration 300 --send-every 20
```

À lire dans le JSON : `flaps_after_warmup` doit rester à 0, et chaque board
doit apparaître dans les `senders` des autres.

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
| `apps/` | Application écran : démon mesh + UI GTK4 |
| `tests/` | Tests autonomes (sans pytest) |
| `sim/` | Simulation (pas de modèle OTA presence) |
| `docs/` | Config, PDF sécu, HTML |
| `scripts/run_tests.sh` | Runner de tests sans dépendance |
| `scripts/bb_probe.py` | Soak stabilité + chat (résumé JSON) |
| `scripts/meshd_client.py` | Client chat en terminal (sans écran) |
| `scripts/meshd_fake.py` | Démon simulé pour développer l’UI |
| `scripts/phase1a_manual.py` | Banc crypto interactif |
| `scripts/install_py314_deps.sh` | Install deps root |

---

## Statut

Mesh BLE ouvert : presence legacy + auto-dial + ANNOUNCE + chat multihop.

Mesuré sur boards (Rubik Pi + Arduino UNO Q, `scripts/bb_probe.py`) :

| Scénario | Résultat |
|----------|----------|
| **Soak 5 min, 6 nœuds** | Mesh **non partitionné** : chaque nœud reçoit des 5 autres |
| ⤷ régime établi (60–290 s) | **0 événement de lien** — aucune coupure, aucun flap |
| ⤷ livraison chat | **427/429** (99,5 %) hors convergence et arrêt |
| ⤷ multi-hop | 3 voisins directs max par nœud, portée 6/6 → relais effectif |
| ⤷ CDS | 5 nœuds sur 6 élus RELAY |
| Coupure d’un nœud puis retour | Lien rétabli en **~7 s**, aucune perte ensuite |
| Chat via `apps/meshd.py` (2 nœuds) | **14/14** dans les deux sens, 0 refus |
| Suite unitaire (locale + boards) | **19/19** |

Topologie mesurée (6 nœuds) : chaque nœud n’ouvre que **2 à 3 liens L2CAP**
et le reste passe en multi-hop — c’est le comportement sparse recherché, pas
un full-mesh O(N²).

Les pertes se limitent au **premier** message (émis avant convergence, ~40 s à
6 nœuds) et aux **derniers** (émis pendant l’arrêt des nœuds). Une application
doit donc tolérer une fenêtre de convergence au démarrage : afficher l’état du
mesh plutôt que supposer la livraison.

Risques résiduels :

- **Contention adv+scan** sur contrôleurs fragiles : les liens tombent parfois
  sur supervision timeout (`Errno 110`). La reprise est automatique depuis le
  catalogue de présence, mais la coupure reste visible côté application.
- **Listes de voisins OTA vides** sous AD legacy → l’élection CDS depuis l’air
  seul est faible ; compensée par le dial sur catalogue.
- **Firmware QCA fragile** (UNO Q) : un adaptateur peut tomber à
  `btmgmt info → 0 items` et n’être récupérable que par reboot (§1 et §4).
- **Liens en limite de portée** : après un `ETIMEDOUT`, le backoff monte
  jusqu’à 90 s et l’arête reste volontairement supprimée. Le mesh route par
  ailleurs — c’est le comportement voulu, pas une panne.

Spec sécu : [docs/special_security_BB.pdf](docs/special_security_BB.pdf).

## Références

- Paper : [arXiv:2509.00967](https://arxiv.org/abs/2509.00967)
- Config lab : [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
