# BUBBLE-BLUE

Implementation of the **BUBBLE-BLUE** multi-hop Bluetooth networking protocol (see arXiv:2509.00967) targeting:

- **Rubik Pi 3**: Ubuntu Linux, Bluetooth 5.0
- **Arduino UNO Q**: Debian Linux, Bluetooth 5.1

The goal of this project is to provide a reproducible, engineering-oriented implementation of the protocol stack (from L2CAP transport to control/forwarding/security), suitable for experimentation and on-device validation.

## Scope

- **Protocol stack**: L2CAP transport, control plane (Hello/CDS), forwarding, and security (AES)
- **Platforms**: Linux user space (Pi-class SBCs) and Linux-capable Arduino-class device (UNO Q)
- **Experimentation**: logging, captures, and controlled test scenarios for multihop behavior

Non-goals (at this stage) typically include full product hardening, comprehensive interoperability with all Bluetooth chipsets, and certification-oriented testing.

## Architecture

The stack is organized into layered components:

### Transport (L2CAP)

- Uses Bluetooth **L2CAP** channels for reliable, connection-oriented data transport.
- Responsible for connection establishment, MTU negotiation (when applicable), and framing boundaries compatible with upper-layer protocol messages.

### Control plane (Hello / CDS)

- **Hello**: neighbor discovery and link/peer liveness.
- **CDS** (Control/Data Synchronization): dissemination of control state required to operate multihop forwarding.

This layer is responsible for maintaining neighborhood state and distributing the minimal information needed for routing/forwarding decisions.

## Mesh ouvert et bulles privées

BUBBLE-BLUE sépare volontairement **deux plans** :

| Plan | Rôle | Gouverné par |
|------|------|--------------|
| **Topologique** (beacon, scan, auto-connect, Hellos publics, CDS) | Découverte, adjacence L2CAP, élection RELAY/LEAF, forward opaque | **Ouvert** à tout nœud BB, quel que soit son groupe |
| **Applicatif** (identité, chat, chiffrement) | Résolution d’identité (partie privée des Hellos), déchiffrement `PKT_DATA`, appartenance au groupe | **Clé de groupe** (`BUBBLE_BLUE_GROUP_KEY`) |

**Beacon universel** — chaque nœud annonce un marqueur BB statique (Manufacturer Data `0xFFFF` + magic `BB`, voir `src/transport/advertising.py`). Tout observateur peut reconnaître un participant Bubble-Blue sans connaître sa clé.

**Scan & auto-connect** — `PresenceScanner` (`src/control/presence_scanner.py`) détecte les candidats BB ; la couche transport établit les liens L2CAP sans liste d’adresses préconfigurée.

**Hellos publics & CDS** — la partie publique des Hellos et l’algorithme CDS (Wu-Li / MPR) fonctionnent entre nœuds de groupes différents : un relais inter-groupe voit la topologie anonyme et peut **forwarder des paquets opaques** sans les déchiffrer.

**Bulles privées** — seule la couche applicative est « fermée » : sans la bonne clé, un nœud logue au plus `paquet non déchiffrable` et **n’expulse jamais** le relais ; le forward multihop continue.

**Override labo** — `BUBBLE_BLUE_GROUP_MEMBERS`, `BUBBLE_BLUE_TOPOLOGY` et `--topology` restent des **restrictions explicites** pour cadrer une expérience (ligne A—M—B, pairs offline, etc.). En production opportuniste, un `.env` réduit à clé + transport suffit.

Protocole de validation 3 boards (deux temps) : [docs/CONFIGURATION.md](docs/CONFIGURATION.md#mesh-ouvert-et-bulles-privées).

### Forwarding plane

- Multihop forwarding of BUBBLE-BLUE packets based on control-plane state.
- Handles hop-limits/TTL, duplicate suppression (where applicable), and basic queueing/backpressure policies.

### Security (AES)

- Payload protection using **AES** (exact mode/keying parameters depend on the implementation configuration).
- Designed to keep cryptographic material out of the repository via local configuration files (see `.gitignore`).
- Legacy crypto API (`encrypt_for_group`) moved to `src/security/legacy.py`.

## Hardware requirements

### Rubik Pi 3 node(s)

- Rubik Pi 3 running **Ubuntu Linux**
- Bluetooth **5.0** controller (on-board or USB)
- Sufficient storage to collect logs and traces during experiments

### Arduino UNO Q node(s)

- Arduino UNO Q running **Debian Linux**
- Bluetooth **5.1** controller (as provided by the platform)
- Serial access for provisioning and debugging (recommended)

### Optional tooling

- USB Bluetooth dongles for reproducible controller behavior across nodes
- Sniffer/capture capability (e.g., HCI snoop logs) for debugging and performance evaluation

## Software requirements

- Linux user space with BlueZ (or compatible Bluetooth stack)
- **Python 3.14+** on boards using BLE L2CAP CoC (`BUBBLE_BLUE_TRANSPORT=ble_l2cap`); Python 3.12+ for BT Classic only
- Python deps: `python3.14 -m pip install --user -r requirements.txt` (system `cryptography` is built for another Python and will panic on 3.14)
- A C/C++ toolchain (gcc/clang) if building native components or helpers

## Installation

1. Clone the repository.
2. Copy `.env.example` to `.env` and set a shared group key (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)).
3. Install Python dependencies for **the same Python you run with sudo** (required on Python 3.14):

```bash
./scripts/install_py314_deps.sh
# equivalent:
sudo python3.14 -m pip install --break-system-packages --ignore-installed -r requirements.txt
```

`pip install --user` alone is not enough when using `sudo python3.14` — root does not see `~/.local`.

4. Install BlueZ tools (`hciconfig`, `bluetoothctl`) and ensure Bluetooth is up.
5. Run the node (requires `sudo` for L2CAP on most boards):

```bash
# Show local BD_ADDR and config
python3 config.py

# Discover nearby controllers (BB beacons included when ManufacturerData is present)
sudo python3 bb_node.py --scan 8

# Interactive mesh chat — open mesh: key + transport only in .env
# Lab override: list peers in GROUP_MEMBERS or --topology
sudo python3 bb_node.py --chat
```

**Minimal open-mesh setup:** same transport on every board; `BUBBLE_BLUE_GROUP_KEY` defines the **private bubble** (who can decrypt chat). Peer lists (`GROUP_MEMBERS`, `--topology`) are optional **lab restrictions** — see [Mesh ouvert et bulles privées](docs/CONFIGURATION.md#mesh-ouvert-et-bulles-privées).

**Two-node lab (explicit peers):** same group key; each board lists the other's BD_ADDR in `BUBBLE_BLUE_GROUP_MEMBERS` (or use `--topology`). Details: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Repository structure

This repository currently contains:

- `src/`: protocol implementation and supporting libraries
- `tests/`: unit/integration tests and experimental scenarios

As the project matures, the structure may expand to include:

- `docs/`: protocol notes, engineering decisions, and experiment reports
- `tools/`: CLI utilities, provisioning scripts, and capture helpers
- `firmware/` or `embedded/`: device-specific components (if needed)

## Current status

Runnable stack on Linux + BlueZ:

- **Entrypoint:** `bb_node.py` (`--chat`, `--topology`, `--scan`, `--send`)
- **API:** `src/api/bb_api.py` (`BBNode`)
- **Planes:** L2CAP transport, Hello/CDS control, PKT_DATA forwarder, AES-GCM group crypto
- **Open mesh layer:** universal BB beacon (`LEAdvertiser`), periodic presence scan (`PresenceScanner`), cross-group Hello/CDS

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for environment variables, open-mesh vs lab overrides, and the 3-board validation protocol.

## Security notes

- Do **not** commit credentials, long-lived keys, or device-specific configuration.
- Store secrets in local `.env` or `config.local.*` files (ignored by git).
- Prefer committing `*.example` templates and documenting required variables instead.

## References

- **BUBBLE-BLUE protocol paper**: arXiv:2509.00967

