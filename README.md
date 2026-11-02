# BUBBLE-BLUE

Implémentation du protocole mesh multi-hop Bluetooth BUBBLE-BLUE ([arXiv:2509.00967](https://arxiv.org/abs/2509.00967)).

Les nœuds tournent sur Rubik Pi 3 (Ubuntu, Bluetooth 5.0) et Arduino UNO Q (Debian, Bluetooth 5.1). Le transport est un canal BLE L2CAP orienté connexion. La pile fait la découverte (Hello), la diffusion d'état (CDS), le relais multi-sauts et le chiffrement AES.

Les cartes suivent ce dépôt : commit, push, puis `git pull` sur chaque board. Le miroir INRIA est `git@gitlab.inria.fr:bb/bb_v1.git`.

## Lancer un nœud

Le setup complet est dans la section Board Setup. Une fois la board prête :

```bash
sudo python3.14 bb_node.py --chat
```

## Documents

| Fichier | Rôle |
| --- | --- |
| `README.md` | Installation des boards, lancement, pièges Bluetooth |
| `docs/CONFIGURATION.md` | `.env`, mesh ouvert ou liste d'adresses, timers |
| `docs/EXPERIMENTS.md` | Plan d'expériences |
| `docs/paper/bb-implementation-draft.md` | Version technique longue |

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

#### Départ d’un nœud

Un voisin n’est retiré qu’après **plusieurs Hello consécutifs manqués**, jamais
au premier : perdre une annonce est banal sur le 2,4 GHz partagé, et y réagir
ferait ré-élire les relais pour un nœud qui n’est jamais parti.

```bash
BUBBLE_BLUE_HELLO_INTERVAL_S=5    # période d'émission
BUBBLE_BLUE_HELLO_MISSES=3        # minimum 2
```

Le délai de retrait est le produit des deux (5 × 3 = 15 s par défaut, valeur
historique inchangée). L’exprimer en **nombre de périodes** plutôt qu’en
secondes fixes lui conserve son sens si l’intervalle est retouché : passer
l’intervalle à 2 s donne 6 s de tolérance, toujours 3 annonces manquées.

Monter `MISSES` sur un déploiement bruité ou mobile, le descendre pour réagir
plus vite à un départ réel. Une valeur de 1 est refusée — c’est exactement
l’instabilité que ce seuil existe pour éviter. Une saisie invalide retombe sur
le défaut avec un avertissement, plutôt que d’empêcher la board de démarrer.

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

#### Les boards se découvrent mais ne se connectent jamais

| | |
|--|--|
| **Symptôme** | `hciconfig` dit `UP RUNNING`, les voisins apparaissent puis disparaissent (`voisins=1` puis `0`), et le démon logue `BLE L2CAP socket error : [Errno 38] Function not implemented`. |
| **Cause** | Le contrôleur QCA rejette `Opcode 0x2039` (*LE Extended Create Connection*) avec `-38`. Observé sur une board après **4 semaines d’uptime** : le firmware se dégrade sans que l’adaptateur tombe. |
| **Solution** | Recharger le firmware — un `restart bluetooth` seul ne suffit pas, il faut faire descendre l’interface d’abord. Pas besoin de rebooter. |

```bash
sudo dmesg | grep -i 'hci0'            # chercher "Opcode 0x2039 failed: -38"

sudo hciconfig hci0 down
sudo systemctl restart bluetooth
sudo hciconfig hci0 up

sudo dmesg | tail -5                   # attendu : "QCA setup on UART is completed"
```

L’`ENOSYS` vient du contrôleur, **pas de Python** : vérifier au passage que la
socket se crée bien, sinon c’est l’interpréteur qui est en cause (§1) :

```bash
python3.14 -c "import socket; socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)"
```

#### Le mesh se défait au bout de 10–20 minutes (UNO Q)

Deux causes noyau, toutes deux contournées dans le code :

| | |
|--|--|
| **Symptôme 1** | `dmesg` : `Unable to allocate ident: -28`, puis plus rien ne passe sur les liens de l’UNO Q. |
| **Cause** | Noyau 7.0 de l’UNO Q : chaque *LE Flow Control Credit* consomme un identifiant L2CAP jamais rendu (corrigé en amont par `6e1930ece855`). Un crédit par paquet reçu : les 254 identifiants d’un lien s’épuisent en ~15 min. |
| **Contournement** | Le lien est **recyclé** avant épuisement (200 crédits, `BUBBLE_BLUE_L2CAP_IDENT_BUDGET`, `0` = désactivé) : fermeture + déconnexion MGMT, puis nouvelle connexion avec un pool neuf. |
| **Symptôme 2** | Après un recyclage, un UNO Q ne se reconnecte plus : `connect … timed out after 8s` sans aucun *LE Extended Create Connection* dans `btmon`. |
| **Cause** | Le pilote `hci_qca` déclare le WCN3988 sans `QCA_CAP_VALID_LE_STATES` : le noyau refuse d’initier une connexion tant que l’adaptateur est *peripheral* sur un lien. |
| **Contournement** | Rôle de lien : l’UNO Q est **`central`** (détecté automatiquement) — il annonce en non-connectable et ouvre lui-même tous ses liens. |

`meshd --link-role peripheral` sur les écrans du stand : ils acceptent sans
jamais composer, donc tout le trafic passe par les relais (sinon, posées sur la
même table, les deux Rubik se lient directement). Sur le stand, chaque UNO Q
est ainsi relié aux deux écrans : trois chemins indépendants.

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
- c’est la frontière qu’emprunte le panneau UNO Q, où l’affichage est un sketch
  sur le STM32 : le démon ne bouge pas, seul le client change.

| Fichier | Interpréteur | Droits | Rôle |
|---------|--------------|--------|------|
| `apps/meshd.py` | 3.14 | root | Porte le `BBNode`, sert la socket |
| `apps/screen_ui.py` | système | utilisateur | Interface tactile GTK4 |
| `apps/protocol.py` | les deux | — | Format de trame partagé |
| `apps/unoq_panel.py` | système | utilisateur | Panneau UNO Q : mesh → sketch |
| `scripts/meshd_client.py` | système | utilisateur | Client terminal (sans écran) |
| `scripts/meshd_fake.py` | système | utilisateur | Démon simulé, sans radio |
| `scripts/start_screen.sh` | — | — | Lanceur : démon + UI en une commande |

Le protocole complet est décrit en tête de [`apps/protocol.py`](apps/protocol.py).

### Développer sans matériel

`meshd_fake.py` sert le vrai protocole sans toucher au Bluetooth — pas
d’adaptateur, pas de root, pas d’attente de convergence :

```bash
python3 scripts/meshd_fake.py --socket /tmp/bb.sock &
python3 apps/screen_ui.py    --socket /tmp/bb.sock
```

### Brancher la dalle (DFRobot DFR0506, 7″ 1024×600)

La dalle est **HDMI pour la vidéo** et **micro-USB pour le tactile** (HID, sans
driver) — deux câbles, pas un. Côté matériel :

- alimentation **≥ 1,5 A en 5 V**, sinon le tactile devient mou (cause n°1 de
  « l’écran répond mal ») ;
- rafraîchissement **43 Hz**, pas 60 Hz — à 60 Hz l’image ne remplit pas la dalle ;
- luminosité réglable uniquement par le **potentiomètre au dos**, pas en logiciel.

Vérifier que la dalle est vue avant de lancer quoi que ce soit :

```bash
cat /sys/class/drm/card0-HDMI-A-1/status     # doit passer à "connected"
```

### Lancer

Une seule commande, qui démarre le démon s’il ne tourne pas, attend la socket,
puis choisit le mode d’affichage :

```bash
./scripts/start_screen.sh              # auto
./scripts/start_screen.sh --kiosk      # force cage (board dédiée)
./scripts/start_screen.sh --windowed   # force une fenêtre (dans un bureau)
./scripts/start_screen.sh --fake       # mesh simulé, sans adaptateur ni root
```

Le mode dépend de ce que la board a déjà :

| Board | Ce qui se passe à l’écran | Mode |
|-------|---------------------------|------|
| `rubik-q` | GNOME est installé → **écran de connexion GDM** (masqué par l'autostart) | ouvrir un terminal, `windowed` |
| `rubik-inria`, `rubik3` | headless, rien ne tient le DRM | `kiosk` via `cage` |

Le démon **reste en vie quand l’interface se ferme** : les liens mettent ~40 s à
converger, il serait absurde de les perdre en relançant l’UI.

Lancé manuellement, l’équivalent est :

```bash
sudo python3.14 apps/meshd.py          # 1. démon (root, une seule instance)
python3 apps/screen_ui.py --kiosk      # 2. interface, utilisateur normal
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

### Démarrage automatique au boot (stand)

Sur le stand, chaque carte doit rejoindre le mesh seule après une coupure de
courant. Une commande par carte installe les prérequis manquants (dépendances
python3.14, cage, GTK 4), écrit `/etc/bubble-blue.env` et active les services
systemd :

```bash
sudo ./scripts/install_autostart.sh relay                  # arduinoq, arduino2, arduino3
sudo ./scripts/install_autostart.sh screen --admin         # rubik-q (bouton « Restart mesh »)
sudo ./scripts/install_autostart.sh screen --pixman        # rubik-inria (pas de GL)
sudo ./scripts/install_autostart.sh uninstall              # retour au lancement manuel
```

| Service | Cartes | Rôle |
|---------|--------|------|
| `bubble-blue-meshd` | toutes | démon mesh, relancé s’il meurt ; écrans en rôle `peripheral` |
| `bubble-blue-screen` | écrans | kiosque `cage` sur la dalle |

- Sur une carte écran, le gestionnaire de connexion (GDM) est **masqué** :
  sinon il prend la dalle au boot avant `cage`. Pour retrouver le bureau
  Ubuntu (Wi-Fi, réglages), toucher **Desktop** deux fois, en haut à droite
  du kiosque : le kiosque s'arrête et GDM reprend la dalle. Au boot suivant
  le kiosque revient. À la main : `sudo systemctl stop bubble-blue-screen`
  puis `sudo systemctl unmask gdm gdm3 && sudo systemctl start gdm3`.
- Après un boot, le mesh complet se reforme en 2 à 3 minutes. Le bouton
  « Restart mesh » fonctionne à l’identique sous systemd.
- Logs : `journalctl -u bubble-blue-meshd -f` (plus de `/tmp/bb-meshd.log`).
- Mettre à jour une carte : `git pull` puis
  `sudo systemctl restart bubble-blue-meshd`.
- `btmgmt` ne se termine jamais quand son entrée standard est `/dev/null`
  (c'est le cas sous systemd) : le code lui passe un pipe vide. Garder ce
  détail en tête pour tout nouvel appel à `btmgmt` ou `bluetoothctl`.

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

Deux conditions pour que `cage` démarre : **rien d’autre ne doit tenir le DRM**
(sur une board avec GDM actif, il faut `sudo systemctl disable --now gdm3`), et
l’utilisateur doit pouvoir lire les périphériques d’entrée. Lancé depuis une
session locale, logind s’en charge ; lancé **depuis SSH** il n’y a pas de seat,
et il faut alors ajouter l’utilisateur au groupe `input` :

```bash
sudo usermod -aG input "$USER"      # relogin nécessaire
```

### Interface

Dimensionnée pour la dalle 1024×600 et pour un stand de démo :

- **à gauche**, le chat et **six messages préenregistrés** à toucher
  ([`apps/presets.txt`](apps/presets.txt), une ligne par bouton, `{name}` = nom
  de la board). Pas de clavier : les visiteurs n’ont rien à taper. Une pause de
  1,5 s entre deux envois empêche une foule de transformer les boutons en charge ;
- **à droite**, la **carte du mesh en direct** : chaque board et chaque lien,
  et chaque message dessiné saut par saut à travers les relais, sa bulle
  n’apparaissant qu’à l’arrivée. Le dernier saut est celui par lequel le
  message est réellement entré ; chaque bulle dit combien de sauts il a faits.
  Les noms viennent de [`apps/node_names.txt`](apps/node_names.txt).

Chaque démon diffuse ses propres liens au reste du mesh (à chaque changement,
plus un battement lent de 60 s), dans le plan chiffré du groupe — c’est ce qui
permet à chaque écran de dessiner le graphe entier.

**Redémarrer tout le mesh depuis une board** — bouton *Restart mesh* (lancer
l’UI avec `--admin`, à réserver à l’écran du stand, deux appuis pour
confirmer), ou en SSH :

```bash
python3 scripts/meshd_client.py --restart
```

Chaque démon redémarre BlueZ puis se ré-exécute ; un contrôleur qui ne revient
pas voit son firmware rechargé (rebind du pilote). Un démon ignore les ordres
reçus pendant sa première minute, pour qu’une copie en retard ne relance pas la
boucle. Il faut que les boards soient joignables **par le mesh** — pas besoin de
réseau IP entre elles.

> **Piège de test.** Pour capturer l’UI sous `Xvfb`, forcer `GSK_RENDERER=cairo`
> (sinon GTK4 rend via le pilote Adreno, hors du framebuffer capturable) et
> vérifier qu’aucun `/tmp/.X99-lock` d’une instance précédente ne traîne — c’est
> ce verrou qui produit des captures vides alors que l’application va bien.

### Ce qui est vérifié

| Vérification | Résultat |
|--------------|----------|
| Contrat démon↔UI (`tests/test_meshd_protocol.py`) | 16 cas, sans adaptateur |
| Chat réel à travers le démon (arduinoq ↔ rubik-inria) | **14 envoyés / 14 reçus**, 0 refus |
| UI GTK4 sur Rubik Pi 3, 1024×600 | rendu conforme sur le matériel cible |
| Tenue de l’UI (démon simulé) | 4 h continues, aucune erreur |

---

## Panneau d’état UNO Q (`apps/unoq/`)

Sur Rubik l’écran est en HDMI et l’interface est une application Linux. Sur
UNO Q le shield est câblé **au STM32**, pas au SoC Linux : l’affichage doit donc
être un sketch. Le mesh, lui, ne bouge pas — il reste côté Linux, où il est déjà
validé.

```
meshd.py (3.14, root) ──socket Unix──▶ unoq_panel.py (système, utilisateur)
                                              │  Router Bridge (msgpack-RPC)
                                              ▼
                                    /var/run/arduino-router.sock
                                              │
                                       panel.ino (STM32)
                                              │
                                  ILI9341 (SPI) + TSC2007 (I²C)
```

Le contrat RPC tient en quatre méthodes, décrites en tête de
[`apps/unoq/panel/panel.ino`](apps/unoq/panel/panel.ino) : Linux pousse
`panel_status`, `panel_message` et `panel_presets`, le sketch rappelle
`panel_preset(index)` quand un bouton est touché. **Les deux boutons envoient donc
toujours ce qu’ils affichent** : les libellés viennent du même endroit que les
textes.

Le texte part déjà **tronqué et translittéré en ASCII** : la police intégrée de
GFX n’a pas d’accents, et découper côté Linux évite au sketch une gymnastique de
chaînes pour laquelle il n’a pas de budget RAM.

### Installer la bibliothèque du Bridge

Le client Python du Router Bridge **n’est pas sur PyPI** : il est livré dans
l’image conteneur d’App Lab. Le script en extrait les deux seuls modules utiles —
importer le paquet complet tirerait numpy, opencv et une pile audio pour un
panneau d’état.

```bash
./scripts/install_unoq_bridge.sh      # → ~/.local/lib/bubble-blue
```

### Flasher le sketch

```bash
arduino-cli lib install "Adafruit GFX Library" "Adafruit ILI9341" "Adafruit TSC2007"
arduino-cli compile -u -b arduino:zephyr:unoq apps/unoq/panel
```

Compiler **depuis le chemin du dépôt** : `arduino-cli` retrouve le binaire par un
hachage du chemin, et un `upload` après compilation ailleurs échoue sur
« Compiled sketch not found ». Ne pas passer `-p` non plus — le port réseau
réclame des identifiants interactifs, alors que sans port l’outil local
(`remoteocd`) fait le travail.

### Lancer

```bash
sudo python3.14 apps/meshd.py                                    # 1. le mesh
python3 apps/unoq_panel.py --preset "OK|Bien recu" \
                           --preset "ARRIVE|J'arrive"            # 2. le panneau
```

`--preset` accepte `LABEL|texte` — le libellé est ce qui tient sur le bouton, le
texte est ce qui part dans le chat. Sans barre verticale, le libellé est déduit
du texte.

### Voir le panneau sans shield

`panel_fake_sketch.py` enregistre les mêmes méthodes RPC que le sketch et redessine
le panneau en texte, avec le même découpage 25 colonnes × 3 lignes. C’est un aperçu
de la mise en page, et surtout un moyen d’exercer toute la chaîne avant qu’un
shield existe :

```bash
python3 scripts/panel_fake_sketch.py     # 1/2 + Entrée = appui bouton
```

Ne pas le laisser tourner en même temps que le vrai sketch : les deux
fourniraient les mêmes méthodes.

### Brancher le shield (Adafruit 1651, 2,8″ 320×240)

Écran **SPI** (DC 9, CS 10), tactile **résistif TSC2007 en I²C** à `0x48` — les
révisions récentes ont remplacé le STMPE610, qui n’est plus fabriqué. Le shield
prend son niveau logique sur **IOREF**, que l’UNO Q fournit en 3,3 V.

> **Si l’écran reste noir.** Le shield existe en deux câblages SPI : broches
> 11-13, ou header ICSP. Selon la révision reçue, il faut couper/ponter les
> jumpers au dos — c’est la première chose à vérifier avant de suspecter le code.

> **Si les boutons répondent à côté.** Les constantes de calibration en tête du
> sketch sont les valeurs nominales d’Adafruit, et les dalles varient. Chaque
> appui émet `panel_touch_raw` : lire les couples bruts dans le journal Linux et
> ajuster `TS_MINX`/`TS_MAXX`/`TS_MINY`/`TS_MAXY`. La rangée de boutons est
> découpée en deux moitiés d’écran, donc une calibration fausse échange les deux
> boutons au pire — elle ne les rend pas inatteignables.

### Si le tactile ne répond pas du tout

Le sketch **ne fige pas** le verdict au démarrage : il resonde le TSC2007 toutes
les 5 s, donc un bus I²C froid ou un shield remis en place sur une carte allumée
se rattrape sans reset. Tant qu’il n’a pas répondu, les boutons sont **grisés**
plutôt que faussement actifs, et la bande d’état affiche `TACTILE HS`.

Le verdict remonte à Linux **en réponse au push de statut**, pas par une
annonce : le MCU démarre bien avant Linux et le panneau se relance librement,
donc une notification au boot serait criée dans le vide. Elle voyage sur le
battement de cœur, et n’est journalisée qu’aux transitions :

```
panel: TACTILE HS - boutons inertes, utiliser --tap 0|1
```

Le chat reste utilisable sans y toucher — l’envoi passe par le même nom RPC que
le sketch, donc c’est le panneau en cours d’exécution qui envoie son propre texte
de préréglage :

```bash
python3 apps/unoq_panel.py --tap 0      # comme un appui sur le bouton gauche
python3 apps/unoq_panel.py --tap 1
```

Si le tactile est mort côté matériel, deux issues, par coût croissant :

| Issue | Ce que ça coûte |
|-------|-----------------|
| Écran HDMI sur cette carte plutôt que le shield | rien à développer (voir plus bas) |
| Boutons physiques sur broches libres (D5/D6) | soudure ou entretoises : le shield recouvre les broches |

### Un UNO Q en HDMI plutôt qu’en shield

Rien à redévelopper : la Debian 13 des UNO Q a `gir1.2-gtk-4.0` (4.18) et `cage`
en dépôt, donc l’application GTK4 des Rubik tourne telle quelle. C’est
`start_screen.sh` qui s’applique, pas cette section.

### Ce qui est vérifié

| Vérification | Résultat |
|--------------|----------|
| Logique du panneau (`tests/test_unoq_panel.py`) | 13 cas, sans shield ni radio |
| Empreinte du sketch sur STM32U585 | **38 Ko flash (4 %)**, 4,3 Ko RAM (3 %) |
| Sketch flashé, méthodes RPC jointes depuis Linux | `panel_status` / `panel_message` / `panel_presets` : OK |
| Poussée continue vers le sketch réel | 90 s, 0 erreur |
| Bouton → mesh (arduinoq → arduino2) | `J'arrive` reçu sur la carte pair |
| Message entrant → panneau | affiché, coupé sur 2 lignes, expéditeur correct |
| Détection du tactile absent (carte sans shield) | `panel_status` → `False`, signalé **une seule fois** |
| `--tap` avec tactile HS | préréglage envoyé, même chemin qu’un appui |

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
| `scripts/panel_fake_sketch.py` | Aperçu texte du panneau UNO Q — exerce le Bridge sans shield |
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
| `apps/unoq/panel/` | Sketch STM32 du panneau d’état (shield Adafruit 1651) |
| `tests/` | Tests autonomes (sans pytest) |
| `sim/` | Simulation (pas de modèle OTA presence) |
| `sim/limits.py` | Limites topologiques et révocation (échelle, densité, TTL) |
| `scripts/bb_load.py` | Limites de charge (taille, cadence, saturation du lien) |
| `docs/` | Config, PDF sécu, HTML |
| `docs/EXPERIMENTS.md` | Plan d’expériences (labo + terrain dès les dalles) |
| `docs/paper/bb-implementation-draft.md` | Brouillon technique de l’article (version longue) |
| `scripts/run_tests.sh` | Runner de tests sans dépendance |
| `scripts/bb_probe.py` | Sonde par carte : convergence, stabilité, chat (JSON) |
| `scripts/bb_bench.py` | Campagne multi-cartes : lance les sondes et agrège |
| `scripts/meshd_client.py` | Client chat en terminal (sans écran) |
| `scripts/meshd_fake.py` | Démon simulé pour développer l’UI |
| `scripts/panel_fake_sketch.py` | Aperçu texte du panneau UNO Q |
| `scripts/phase1a_manual.py` | Banc crypto interactif |
| `scripts/install_py314_deps.sh` | Install deps root |
| `scripts/install_unoq_bridge.sh` | Client Router Bridge pour le panneau UNO Q |

---

## Accélération cryptographique

Question posée en réunion : les accélérateurs matériels des plateformes sont-ils
exploités ? **Oui, déjà** — et pas par l’accélérateur auquel on pense.

Les deux SoC exposent les *Cryptography Extensions* ARMv8 (`aes pmull sha1 sha2`
dans `/proc/cpuinfo`), et le noyau enregistre `gcm(aes)` sous le pilote
**`gcm-aes-ce`** : le suffixe `ce` désigne ces extensions, donc de l’AES exécuté
par des instructions dédiées du CPU. Notre chemin passe par
`cryptography.AESGCM`, adossé à OpenSSL, qui les emprunte.

Le moteur Qualcomm QCE est bien présent, mais il **n’enregistre pas GCM** — que
du CBC et du CCM (`ccm-aes-qce`, `authenc-hmac-sha256-cbc-aes-qce`) — et n’expose
aucun `/dev/qcedev` côté espace utilisateur. L’y router demanderait de changer de
mode AEAD pour un chemin plus lent que celui déjà pris.

Mesures du chemin de chiffrement réel (`encrypt_with_key` + `decrypt_with_key`,
AAD de 26 o, moyenne sur 20 000 itérations) :

| Plateforme | Charge BLE (470 o) | Aller-retour |
|------------|--------------------|--------------|
| RUBIK Pi 3 | 3,0 µs + 2,8 µs | **173 000 paquets/s** |
| Arduino UNO Q | 18,2 µs + 15,2 µs | **30 000 paquets/s** |

À comparer au lien BLE CoC, qui transporte au mieux quelques centaines de
paquets par seconde : **la crypto est deux à trois ordres de grandeur au-dessus
du besoin**. Optimiser là n’achèterait rien de mesurable sur le débit — la marge
est dans la radio et la topologie. L’angle qui resterait défendable est
énergétique, pas latence, et demanderait une mesure de consommation dédiée.

> À noter pour l’interprétation : à 470 o, l’essentiel de ces microsecondes est
> le coût d’objet Python par appel, pas l’AES lui-même. On ne peut pas le mettre
> en cache ici, la clé étant dérivée par paquet.

---

## Banc de convergence et de stabilité

Les campagnes multi-cartes se lançaient jusqu’ici à la main, carte par carte en
SSH — d’où des runs jamais tout à fait comparables. `scripts/bb_bench.py` pilote
`scripts/bb_probe.py` sur toutes les cartes **simultanément** (un démarrage
échelonné flatterait la convergence), collecte les JSON et réduit le tout aux
quelques chiffres citables.

```bash
cp bench_boards.example.txt bench_boards.txt   # gitignoré : contient des mots de passe
python3.14 scripts/bb_bench.py --duration 300 --pull --json-out campagne.json
```

`--pull` synchronise les cartes par git et **abandonne** si l’une d’elles n’est
pas sur le même commit : comparer des cartes qui n’exécutent pas le même code ne
veut rien dire. Le chemin du dépôt se règle par carte dans le fichier de liste,
les cartes ayant été installées à des dates différentes et n’étant pas d’accord
entre elles.

### Ce que mesurent les métriques

Deux conventions gouvernent la lecture. Le **warm-up** (25 s) est la phase de
convergence : les liens qui s’y forment ne sont pas des flaps, donc la stabilité
l’ignore — mais la convergence, elle, se mesure dedans et n’est pas tronquée. Le
**régime établi** est tout ce qui suit ; une moyenne qui mélangerait les deux ne
dirait rien de l’un ni de l’autre.

| Métrique | Ce qu’elle capture |
|----------|--------------------|
| `time_to_full_mesh_s` | Délai avant que la carte voie **toutes** les autres, depuis le lancement du processus (découverte et dial compris) |
| `full_mesh_frac_steady` | Part du régime établi passée en maillage complet — une partition transitoire s’y voit |
| `flaps_after_warmup` | Liens tombés une fois le mesh posé, et leur taux horaire |
| `relay_transitions` | Changements de rôle CDS : un relais qui change d’avis coûte aussi cher qu’un lien qui tombe |
| `delivery` | Part des autres cartes effectivement **entendues** en chat — un lien monté mais muet ne se voit que là |

Les chiffres de campagne sont des **pires cas**, pas des moyennes : un mesh est
convergé quand la *dernière* carte a rejoint, et stable seulement si le maillon
le plus faible l’était. La série par seconde est conservée brute dans le JSON,
de quoi retracer une courbe sans refaire tourner six cartes.

`--expect` (renseigné automatiquement par `bb_bench`) est ce qui distingue le
banc du simple soak : sans savoir combien de cartes participent, « convergé » n’a
pas de définition, et les champs correspondants restent nuls plutôt que de
produire un nombre faussement assuré.

### Référence du 9 septembre (2 nœuds)

| Mesure | Résultat |
|--------|----------|
| Convergence | **3–14 s** selon la campagne (2 à 3 nœuds) |
| Temps en maillage complet | **97 %** du régime établi (carte la moins bonne) |
| Flaps après warm-up | 5 sur 2 × 275 s, tous rattrapés |
| Changements de rôle relais | **0** |
| Livraison chat | **100 %** |

Campagne réduite à deux Rubik : les trois autres cartes étaient hors ligne et
l’UNO Q a échoué au lancement (voir ci-dessous). Les chiffres à 6 nœuds du
tableau *Statut* proviennent de la campagne manuelle antérieure et restent la
référence à cette échelle.

### Scénario de départ / retour

```bash
python3.14 scripts/bb_bench.py --duration 300 --pull \
    --churn rubik-inria --churn-at 120 --churn-for 90
```

La carte désignée est **tuée sans préavis** à `--churn-at` — un nœud qui s’en va
ne dit pas au revoir — puis relancée après `--churn-for`. Ce sont les *autres*
cartes qui mesurent.

Le délai se lit sur la **vue de présence**, pas sur les liens L2CAP. La
distinction est le cœur du scénario : une socket meurt avec son processus, quel
que soit le seuil de Hello configuré, donc chronométrer un lien reviendrait à
chronométrer le noyau. C’est la table de voisins que le seuil fait expirer, donc
c’est elle qu’on observe. La corrélation entre cartes passe par l’horloge murale,
les cartes étant synchronisées à ~20 ms — négligeable face à un délai en dizaines
de secondes.

### Validation du seuil configurable

Le paramètre ne vaut que si le délai mesuré bouge avec lui. Deux campagnes
identiques, seul `BUBBLE_BLUE_HELLO_MISSES` change (`--board-env` l’impose aux
sondes sans toucher au `.env` des cartes) :

| `HELLO_MISSES` | Attendu | Départ vu par `rubik-q` | par `arduinoq` | Retour |
|----------------|---------|-------------------------|----------------|--------|
| 3 (défaut) | 15 s | **21 s** | **17 s** | 12 s / 7 s |
| 6 | 30 s | **36 s** | **32 s** | 7 s / 10 s |

Le délai suit bien le réglage. Le dépassement de quelques secondes est attendu :
l’échantillonnage est à la seconde, et une entrée de présence peut être
rafraîchie de seconde main par les voisins annoncés d’un autre nœud — un départ
se propage donc un peu plus lentement qu’il n’est détecté en direct.

Le **retour** ne bouge pas avec le seuil, et c’est cohérent : il dépend de la
découverte et du dial, pas de l’expiration.

> Une première campagne avait relevé 58 s sur une carte. Non reproduit à
> l’identique, et la relance de cette campagne était par ailleurs cassée : gardé
> ici comme rappel qu’une mesure isolée sur ce banc ne vaut rien sans rejeu.

### Limite d’exploitation observée : dégradation du contrôleur QCA

Résultat de caractérisation à part entière, et le premier point dur trouvé par
le banc : après **5 semaines et 6 jours** d’uptime continu, le contrôleur QCA de
l’UNO Q refuse `btmgmt add-adv`, l’adaptateur reste `DOWN` et `dmesg` accumule

```
Bluetooth: hci0: Reading QCA version information failed (-110)
Bluetooth: hci0: Opcode 0x2039 failed: -110        # LE Extended Create Connection
```

Un redémarrage de la pile (`hciconfig down` + `systemctl restart bluetooth`)
avait suffi lors des occurrences précédentes ; à ce stade il échoue avec
`Operation not supported (95)` sans même recharger le firmware. **Seul un reboot
récupère la carte** — vérifié le 9 septembre : adaptateur `UP RUNNING` et carte
opérationnelle dans la campagne suivante. À retenir pour un déploiement longue
durée : surveiller l’état de l’adaptateur, pas seulement le processus.

---

## Limites topologiques (`sim/limits.py`)

Six cartes ne peuvent pas répondre à « jusqu’où ça monte ». La question se
traite donc en simulation — mais sur le **vrai** `HelloManager` et le **vrai**
`PacketForwarder`, que le moteur pilote à travers une radio synthétique au lieu
de les réimplémenter. Ce qui est simulé, c’est le milieu ; le protocole testé
est celui qui est déployé.

```bash
python3.14 sim/limits.py --study scale      # taille, à densité constante
python3.14 sim/limits.py --study density    # densité, à taille constante
```

### Correction préalable : l’ordre de propagation

Le bus livrait les paquets **de façon synchrone** : le gestionnaire du
destinataire s’exécutait depuis la pile d’appel de l’émetteur, donc une
diffusion explorait le graphe **en profondeur d’abord** — une branche parcourue
jusqu’au bout avant que ses sœurs n’entendent quoi que ce soit. Une radio fait
l’inverse : tous les voisins reçoivent la même émission en même temps.

L’écart n’est pas cosmétique, parce que la suppression des doublons fige la
première copie arrivée. En profondeur d’abord, ce peut être une copie venue par
un long détour, avec peu de TTL restant : tout le sous-arbre derrière elle est
alors exploré avec un budget amputé. Symptôme observé : une couverture **non
monotone** en TTL (85 % à TTL 10, puis 51 % à TTL 15 à 75 nœuds).

`SimBus.breadth_first()` met les livraisons en file et les draine niveau par
niveau. Toute mesure ci-dessous l’utilise ; sans lui les chiffres sont
pessimistes et dépendent de l’ordre des appels.

| n | Profondeur d’abord (TTL 10) | Ordre radio (TTL 10) |
|---|------------------------------|----------------------|
| 30 | 83 % | **100 %** |
| 50 | 78 % | **100 %** |
| 75 | 85 % | 86 % |

### Résultat : le CDS n’allonge aucun chemin

Sur **tous** les points mesurés, le TTL minimal qui atteint tout le monde est
exactement égal à l’excentricité de la source en sauts :

| n | Degré moyen | Relais | Diamètre | TTL min | Livraison à TTL 10 |
|---|-------------|--------|----------|---------|--------------------|
| 10 | 3,9 | 45 % | 4 | **4** | 100 % |
| 20 | 4,3 | 50 % | 8 | **8** | 100 % |
| 30 | 3,3 | 67 % | 11 | **11** | 93 % |
| 50 | 5,2 | 52 % | 13 | **13** | 94 % |
| 75 | 4,9 | 48 % | 17 | **17** | 54 % |
| 100 | 5,2 | 55 % | 19 | **19** | 23 % |

Autrement dit le dorsale CDS relaie **le long des plus courts chemins**, sans
détour. C’est une propriété du `PacketForwarder` livré, pas du simulateur : elle
est donc vérifiée par `sim/test_limits.py`, sur chaînes (où aucune route
alternative n’existe) comme sur graphes géométriques aléatoires.

### La limite d’exploitation est le TTL, pas la taille

Il n’y a donc pas de « ça casse à N nœuds ». Il y a : **au-delà d’un diamètre de
10 sauts, le TTL par défaut ne traverse plus le réseau.** À un degré moyen de 4
à 5, cela correspond à une vingtaine de nœuds. Au-delà, `ttl_max` doit suivre le
diamètre — et le diamètre croît avec la taille à densité constante.

Pour la démo à 6 nœuds, le TTL par défaut de 10 est très largement suffisant :
la limite ne mord qu’à une échelle qu’on n’atteindra pas physiquement.

### Densité : plus dense coûte moins de relais mais plus d’émissions

| Degré moyen visé | Degré obtenu | Relais | Diamètre | Réémissions / nœud |
|------------------|--------------|--------|----------|--------------------|
| 3 | *aucun tirage connexe* | — | — | — |
| 4 | *aucun tirage connexe* | — | — | — |
| 6 | 5,2 | 52 % | 13 | 4,2 |
| 8 | 6,0 | 47 % | 11 | 5,1 |
| 12 | 8,9 | **38 %** | 7 | 8,1 |

Deux tendances opposées : densifier **réduit** la part de relais (52 % → 38 %),
le CDS ayant besoin de proportionnellement moins de nœuds pour dominer un graphe
serré, mais **augmente** le coût par diffusion, chaque relais ayant plus de
voisins à servir.

En dessous d’un degré moyen d’environ 5, aucun tirage n’est connexe en 100
essais : c’est le seuil de percolation, et la limite physique en deçà de laquelle
la question du routage ne se pose même plus.

> Réserve méthodologique : le degré obtenu est inférieur au degré visé (effets de
> bord — les nœuds près du bord ont moins de voisins) et le filtrage sur
> connexité biaise vers les tirages denses. Les tableaux reportent donc le degré
> **mesuré**, pas la consigne.

---

## Limites de sécurité : la révocation (`--study revocation`)

```bash
python3.14 sim/limits.py --study revocation
```

Le scénario révoque un membre depuis le coordinateur, puis mesure trois choses :
les **égarés** (membres légitimes restés à l’ancienne époque, qui ne lisent donc
plus le groupe), les **fuites** (la victime lit-elle encore le trafic d’après ?)
et le **coût** en émissions.

Cette campagne a mis au jour deux défauts du code livré, tous deux corrigés.

### Défaut 1 — ANNOUNCE avalait des messages de chat

Un nœud numérote ses paquets depuis **deux compteurs indépendants** :
`HelloManager` numérote Hello, presence et ANNOUNCE ; `PacketForwarder`
numérote DATA, SUBGROUP et REKEY. Les deux partent de zéro et avancent à des
rythmes très différents — l’un sur minuterie, l’autre seulement quand quelqu’un
écrit.

Or les deux étaient contrôlés par la **même** fenêtre anti-rejeu par émetteur, et
par le même cache de réémission. Une fenêtre anti-rejeu suppose un compteur
unique et monotone par émetteur : partagée entre deux compteurs, elle jette du
trafic légitime. Un message dont la séquence coïncidait avec celle d’un ANNOUNCE
antérieur du même nœud était rejeté comme rejeu par **tous** les destinataires,
et refusé par **tous** les relais. Le message disparaissait à l’échelle du mesh
sans que rien ne remonte à l’expéditeur.

Reproduction déterministe :

| Séquence du message | Reçu par |
|---------------------|----------|
| 4 | 5/5 |
| **5** (celle de l’ANNOUNCE) | **0/5** |
| 6 | 5/5 |

ANNOUNCE a désormais sa propre fenêtre, et le cache de relayage est indexé par le
compteur d’origine du paquet. Verrouillé par `tests/test_announce_seq_space.py`.

C’est très probablement l’explication des rares pertes jamais élucidées des
campagnes précédentes (427/429 messages, 99,5 %).

### Défaut 2 — plusieurs coordinateurs sur un mesh épars

L’autorité de révocation repose sur une règle unique : le membre de plus petit
`anon_id` parle pour le groupe. Cette règle était appliquée **deux fois sur deux
bases différentes** :

| | Base de membres |
|---|---|
| Élire (`is_coordinator`) | membres résolus par Hello — **voisins directs seulement** |
| Valider (côté récepteur) | membres résolus **+ pairs appris par ANNOUNCE** |

Sur un mesh dense les deux vues coïncident et rien ne se voit. Sur un mesh épars
la vue de voisinage est un sous-ensemble strict : plusieurs nœuds se trouvent
chacun le plus petit et agissent en coordinateur, et toute révocation qu’ils
émettent est refusée partout en « not coordinator » — pendant que l’initiateur
voit sa propre époque avancer et se croit servi.

Mesuré sur un mesh filiforme de 30 nœuds (degré moyen 3,3) : **4 coordinateurs**
auto-déclarés et **28 des 29** membres légitimes abandonnés sur l’ancienne clé.

L’élection utilise maintenant la même base que la validation. Verrouillé par
`tests/test_coordinator_agreement.py`.

### Résultats après correction

| n | ANNOUNCE établi | Révocations refusées | Égarés | Fuites | Émissions / nœud |
|---|-----------------|----------------------|--------|--------|------------------|
| 6 | non | 2 / 4 | 3 | 0 | 10,8 |
| 6 | oui | 0 | **0** | **0** | 12,0 |
| 10 | non | 3 / 4 | 5 | 0 | 10,5 |
| 10 | oui | 0 | **0** | **0** | 32,5 |
| 20 | non | 4 / 4 | — | 0 | — |
| 20 | oui | 0 | **0** | **0** | 77,1 |
| 30 | non | 4 / 4 | — | 0 | — |
| 30 | oui | 0 | **0** | **0** | 82,8 |

La victime n’a **jamais** lu le trafic postérieur, dans aucune configuration —
y compris celles où la révocation échouait par ailleurs. L’exclusion elle-même
n’a jamais été en défaut ; c’est la mise à jour des membres restants qui l’était.

### Deux limites d’exploitation

**La fenêtre d’adhésion.** Le coordinateur ne peut envelopper une clé que pour un
membre dont il détient la clé publique, et Hello ne fournit que celles des voisins
directs — les autres arrivent par ANNOUNCE, diffusé toutes les 30 s. Révoquer
avant que ce plan ne soit établi est soit **refusé d’emblée**, soit source
d’égarés. En pratique : **laisser passer un intervalle d’ANNOUNCE après l’arrivée
d’un nœud avant de révoquer.**

**Le coût.** Il croît d’environ 12 à 83 émissions par nœud entre 6 et 30 membres,
soit un total à peu près **quadratique** en la taille du groupe : chaque membre
exige son propre enveloppement de clé, et chaque paquet du flood est relayé par
toute la dorsale. À 6 nœuds c’est négligeable ; c’est le poste à surveiller si le
groupe grandit.

> Observation mineure non corrigée : `revoke_member` appelle `emit_announce()`
> après avoir changé de clé, si bien que cet ANNOUNCE est chiffré sous une clé que
> personne ne possède encore — il produit un échec de déchiffrement par pair
> (29 sur 30 nœuds). Sans conséquence fonctionnelle, mais cela pollue les journaux
> et peut déclencher des rappels `on_decrypt_fail` sans objet.

---

## Limites de charge (`scripts/bb_load.py`)

```bash
python3.14 scripts/bb_load.py --boards bench_boards.txt --sender rubik-q
```

Une carte génère, les autres comptent. L’émetteur unique est délibéré : quand
tout le monde émet, une perte n’est imputable ni au lien, ni au relais, ni à une
collision entre émetteurs, et le plafond mesuré n’est celui de personne. La
livraison n’étant pas observable depuis l’émetteur, chaque message porte son
palier et son indice, chaque récepteur note ce qui lui parvient, et
l’orchestrateur recoupe — un message n’est livré que si un récepteur a vu cet
indice exact.

### La borne de taille

| Transport | MTU | Surcoût | Charge utile |
|-----------|-----|---------|--------------|
| BLE L2CAP | 512 | 42 o | **470 o** |
| BT Classic | 1021 | 42 o | 979 o |

À 470 octets, la trame fait exactement 512 — la borne est atteinte pile, sans
marge. 471 octets est refusé par une exception explicite (`PayloadTooLarge`),
jamais tronqué silencieusement.

Ce que cela vaut en caractères de chat, ce qui compte pour l’interface :

| | Octets par caractère | Caractères par message |
|---|---|---|
| ASCII | 1 | 470 |
| Français accentué | 2 | **235** |
| Emoji | 4 | **117** |

Le MTU réellement négocié sur les cartes est **672**, au-dessus des 512
configurés : un message de taille maximale passe donc en une seule trame L2CAP,
sans fragmentation. Les 512 de `config.py` sont un choix prudent, pas une
contrainte du lien.

### Le plafond est celui d’une carte, pas du protocole

| Palier | rubik-inria | arduinoq |
|--------|-------------|----------|
| 128 o × 5/s | 40/40 | 40/40 |
| 256 o × 5/s | 40/40 | 40/40 |
| 470 o × 5/s | 40/40 | 40/40 |
| 64 o × 10/s | 80/80 | 80/80 |
| 64 o × 15/s | 120/120 | 87/120 |
| 64 o × 20/s | 63/63 | **0/63** |
| 64 o × 30/s | 240/240 | **0/240** |
| récupération (64 o × 1/s) | 8/8 | **0/8** |

Le Rubik Pi encaisse **tous** les paliers sans une seule perte, jusqu’à 30 msg/s
et 2,35 ko/s. L’Arduino UNO Q suit jusqu’à 10 msg/s, fléchit à 15, puis tombe à
zéro et **n’y revient pas** — même à 1 msg/s après 25 s de repos.

> Avertissement méthodologique, appris à mes dépens : la colonne « pire
> récepteur » ne distingue pas un mesh saturé d’une carte à moitié connectée, et
> ces deux diagnostics mènent en sens opposés. Un premier dépouillement concluait
> à un effondrement général du mesh ; le détail par récepteur a montré que la
> carte saine avait reçu 701 messages sur 701. C’est pourquoi le rapport affiche
> désormais chaque récepteur séparément.

### Cause de l’enlisement : la pile hôte, pas la radio

Sur l’Arduino bloqué, le noyau répète :

```
Bluetooth: Unable to allocate ident: -28
```

`-28` est `ENOSPC` : le pool d’identifiants de **signalisation** L2CAP de BlueZ
est épuisé. Le contrôleur lui-même est irréprochable au même instant
(`errors:0` en RX comme en TX) — ce n’est donc ni la radio ni le firmware.

Le mécanisme est systémique et vaut d’être noté : saturer le plan de données
retarde les Hellos, les voisins expirent, l’auto-dial repart, et cette rafale de
demandes de connexion L2CAP épuise le pool d’identifiants. **La charge de données
affame le plan de contrôle, qui se venge sur la pile.**

Un `systemctl restart bluetooth` suffit à rétablir la carte — pas besoin de
redémarrer. Vérifié : mesh revenu à 3/3, convergence 8–10 s, livraison 100 %.

### En pratique

Pour la démo, la marge est confortable : le chat humain se compte en messages par
minute, pas par seconde. À retenir tout de même que **l’Arduino UNO Q est le nœud
limitant** — c’est lui qui fixe le plafond du groupe, autour de 10 msg/s — et que
la panne, si on le pousse, est un enlisement silencieux qui garde ses liens
ouverts tout en ne livrant plus rien.

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
| Suite unitaire (locale + boards) | **22/22** |

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

## Publication

L’article de protocole et de simulation est [arXiv:2509.00967](https://arxiv.org/abs/2509.00967)
(Achir & Jacquet). La version **technique complète** — implémentation BLE,
formats de trame, banc de mesure, limites déjà chiffrées, plan terrain — se
rédige directement ici, pas via un rapport à convertir plus tard :

- Brouillon conférence : [`docs/paper/bb-implementation-draft.md`](docs/paper/bb-implementation-draft.md)
  (canevas IEEE ~6 p. ; le plan terrain reste dans EXPERIMENTS.md, pas dans l’article)
- Expériences figées avant les dalles : [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md)

Une note courte de conférence se découpe dans le même texte (section *Cut-down*
du brouillon). Le rapport technique *est* cette version longue.

## Références

- Paper protocole : [arXiv:2509.00967](https://arxiv.org/abs/2509.00967)
- Brouillon implémentation : [docs/paper/bb-implementation-draft.md](docs/paper/bb-implementation-draft.md)
- Plan d’expériences : [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)
- Config lab : [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
