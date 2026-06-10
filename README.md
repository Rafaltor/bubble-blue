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
- Python 3.x for orchestration, tooling, and experiments
- A C/C++ toolchain (gcc/clang) if building native components or helpers

## Installation

1. Clone the repository.
2. Copy `.env.example` to `.env` and set a shared group key (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)).
3. Install BlueZ tools (`hciconfig`, `bluetoothctl`) and ensure Bluetooth is up.
4. Run the node (requires `sudo` for L2CAP on most boards):

```bash
# Show local BD_ADDR and config
python3 config.py

# Discover nearby controllers
sudo python3 bb_node.py --scan 8

# Interactive mesh chat (configure peers in .env or --topology)
sudo python3 bb_node.py --chat
```

**Two-node minimum:** same `BUBBLE_BLUE_GROUP_KEY` on both boards; each board lists the other's BD_ADDR in `BUBBLE_BLUE_GROUP_MEMBERS` (or use `--topology` on one side). Details: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

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

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for environment variables and deployment patterns.

## Security notes

- Do **not** commit credentials, long-lived keys, or device-specific configuration.
- Store secrets in local `.env` or `config.local.*` files (ignored by git).
- Prefer committing `*.example` templates and documenting required variables instead.

## References

- **BUBBLE-BLUE protocol paper**: arXiv:2509.00967

