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

The exact build/run commands depend on the current state of the repository. A typical setup on a Linux node is:

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install Python dependencies (if present in `requirements.txt` / `pyproject.toml`).
4. Ensure Bluetooth is enabled and the controller is visible to the OS (via `bluetoothctl` / BlueZ tools).
5. Run the node agent/service (entrypoint to be defined by the repository structure).

If you add a concrete entrypoint (e.g. `src/bubble_blue/node.py`), update this section with the exact commands for both Rubik Pi 3 and Arduino UNO Q.

## Repository structure

This repository currently contains:

- `src/`: protocol implementation and supporting libraries
- `tests/`: unit/integration tests and experimental scenarios

As the project matures, the structure may expand to include:

- `docs/`: protocol notes, engineering decisions, and experiment reports
- `tools/`: CLI utilities, provisioning scripts, and capture helpers
- `firmware/` or `embedded/`: device-specific components (if needed)

## Current status

This project is under active development.

Recommended next steps for making the repository immediately runnable:

- Define a clear **node entrypoint** (CLI/service) for each platform.
- Add dependency manifests (`pyproject.toml` or `requirements.txt`) and pinned tool versions where appropriate.
- Document the **AES configuration** (mode, key derivation, rotation strategy) and threat model assumptions.
- Provide a minimal **two-node** and **three-node multihop** demo with expected logs/output.

## Security notes

- Do **not** commit credentials, long-lived keys, or device-specific configuration.
- Store secrets in local `.env` or `config.local.*` files (ignored by git).
- Prefer committing `*.example` templates and documenting required variables instead.

## References

- **BUBBLE-BLUE protocol paper**: arXiv:2509.00967

