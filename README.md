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

## Setup board vierge (de zéro au chat mesh)

Procédure pour une board **neuve** (Rubik ou UNO Q) qui doit développer / faire tourner ce repo.

### 0. Prérequis matériels

- Board alimentée, accès SSH (ou console locale)
- Contrôleur Bluetooth intégré (`hci0` en général)
- Compte GitLab INRIA avec accès au projet `bb/bb_v1`
- Clé SSH déposée sur GitLab **ou** token HTTPS

### 1. Système de base

```bash
sudo apt update
sudo apt install -y \
  git \
  build-essential \
  pkg-config \
  libffi-dev \
  libssl-dev \
  bluez \
  bluez-tools \
  rfkill
```

Vérifier Python 3.14 (requis pour `ble_l2cap`) :

```bash
python3.14 --version
# Si absent : installer via le paquet / deadsnakes / image board fournie par le labo.
# Sur beaucoup d’images labo, python3.14 est déjà présent.
```

Bluetooth up :

```bash
sudo rfkill unblock bluetooth
sudo systemctl enable --now bluetooth
sudo btmgmt -i hci0 power on
hciconfig hci0    # ou: bluetoothctl show
```

### 2. Cloner le dépôt

```bash
cd ~
# SSH (recommandé)
git clone git@gitlab.inria.fr:bb/bb_v1.git bubble-blue
cd bubble-blue

# ou HTTPS
# git clone https://gitlab.inria.fr/bb/bb_v1.git bubble-blue
```

### 3. Dépendances Python (même interpréteur que `sudo`)

`bb_node.py` tourne en **root** (sockets L2CAP / MGMT). Les paquets installés en `--user` sont invisibles pour root.

```bash
./scripts/install_py314_deps.sh
# équivalent :
# sudo python3.14 -m pip install --break-system-packages --ignore-installed -r requirements.txt
```

### 4. Configuration `.env`

```bash
cp .env.example .env
python3 -c "import os; print(os.urandom(32).hex())"   # générer une clé
nano .env   # ou vim / editor
```

Minimum pour un **mesh ouvert** (recommandé) :

```bash
BUBBLE_BLUE_GROUP_KEY=<64 hex chars — IDENTIQUE sur toutes les boards de la bulle>
BUBBLE_BLUE_TRANSPORT=ble_l2cap
```

Ne **pas** remplir `GROUP_MEMBERS` / `TOPOLOGY` sauf contrainte labo (ligne forcée, etc.).

Vérifier l’adresse locale :

```bash
python3 config.py
```

### 5. Premier lancement

```bash
# Découverte presence BB autour de soi (8 s)
sudo python3.14 bb_node.py --scan 8

# Chat mesh interactif
sudo python3.14 bb_node.py --chat
```

Attendu sans liste d’adresses : candidats découverts → liens L2CAP → ligne du type
`transport ble_l2cap · PSM 0x0081 · … · RELAY|LEAF · N peer(s)`.

Commandes utiles dans le chat : `/help`, `/private <alias|BD> message`.

### 6. Multi-boards (même bulle)

Sur **chaque** board :

1. Même commit Git
2. Même `BUBBLE_BLUE_GROUP_KEY`
3. `BUBBLE_BLUE_TRANSPORT=ble_l2cap`
4. `sudo python3.14 bb_node.py --chat`

Portée radio commune ; pas besoin d’échanger les BD_ADDR en mode ouvert.

### 7. Mode labo (topologie forcée)

```bash
# Exemple ligne A — M — B (voir docs/CONFIGURATION.md)
sudo python3.14 bb_node.py --chat --topology AA:BB:CC:DD:EE:M0
```

Ou via `.env` : `BUBBLE_BLUE_GROUP_MEMBERS` / `BUBBLE_BLUE_TOPOLOGY`.

### 8. Tests unitaires (sans radio)

```bash
python3.14 -m pip install --user pytest   # si besoin, sans sudo
python3.14 -m pytest tests/ -q
```

### 9. Problèmes fréquents

| Symptôme | Piste |
|----------|--------|
| `ModuleNotFoundError` sous `sudo` | Réinstaller avec `./scripts/install_py314_deps.sh` |
| `0 peer(s)` longtemps | BT down, boards hors portée, transport différent, ou RF saturé |
| `Permission denied` L2CAP / MGMT | Lancer avec `sudo` |
| `paquet non déchiffrable` | Clés de groupe différentes (normal sur un relais inter-groupe) |
| Scan ne voit personne | Vérifier `btmgmt power on` ; path = MGMT, pas `bluetoothctl scan` seul |

Ne **jamais** committer `.env` ni `.bb-identity-*.bin` (déjà ignorés).

---

## Architecture (runtime tip)

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
