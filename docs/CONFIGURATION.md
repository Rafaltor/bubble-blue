# BUBBLE-BLUE configuration

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

1. **`BUBBLE_BLUE_GROUP_KEY`** — identical on **all** nodes (generate once).
2. **Peer list** — at least one of:
   - `BUBBLE_BLUE_GROUP_MEMBERS` in `.env`, or
   - `BUBBLE_BLUE_TOPOLOGY` in `.env`, or
   - `bb_node.py --topology ADDR,...`, or
   - `bb_node.py --peer ADDR` (single peer).

Each node must list **other** nodes it should connect to (not its own BD_ADDR).

## Minimal recipes

### Two boards (chat)

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

- **Offline peer in `GROUP_MEMBERS`** → `Connection timed out` / `Host is down` (remove it from the list).
- **Different group keys** → `paquet non déchiffrable` on receive.
- **No peer list anywhere** → node listens but never dials → `0 peer(s)` until the other side connects.
- **Allowlist too strict** → incoming connection rejected if peer BD_ADDR not in members/topology.
