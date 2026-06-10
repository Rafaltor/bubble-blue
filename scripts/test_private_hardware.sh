#!/usr/bin/env bash
# Hardware private message test — run on Node A (sender)
# Usage: ./scripts/test_private_hardware.sh <BD_ADDR_B> [--topology <addrs>]
#
# Expected result:
#   Node A encrypts with pairwise key K_pair(A,B)
#   Node B decrypts successfully and prints the message
#   Any relay (Node C) forwards opaquely, cannot read content

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BD_ADDR_B="${1:-}"
shift || true
TOPOLOGY_ARGS=()

if [[ -z "$BD_ADDR_B" ]]; then
  echo "Usage: $0 <BD_ADDR_B> [--topology ADDR[,ADDR...]]" >&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology)
      if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <BD_ADDR_B> [--topology ADDR[,ADDR...]]" >&2
        exit 1
      fi
      TOPOLOGY_ARGS=(--topology "$2")
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 <BD_ADDR_B> [--topology ADDR[,ADDR...]]" >&2
      exit 1
      ;;
  esac
done

MSG="PRIVATE_TEST_$(date +%s)"

cat <<EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BUBBLE-BLUE — hardware private message test
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Test plan:
  • Node A (this host) → Node B ($BD_ADDR_B) via --private
  • Payload: $MSG
  • K_pair derived from X25519 keys exchanged in Hello (group-encrypted)
  • Any relay Node C should forward ciphertext opaquely (no decrypt)

Prerequisites:
  • Node B listening: python3 bb_node.py [--topology ...]
  • Hello exchange completed (wait ~5–10 s after connect)
  • Same BUBBLE_BLUE_GROUP_KEY on all nodes

EOF

echo "[APP] Sending private message to $BD_ADDR_B …"
python3 bb_node.py \
  --peer "$BD_ADDR_B" \
  --private \
  --send "$MSG" \
  "${TOPOLOGY_ARGS[@]}"

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verify on Node B (receiver)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ Terminal shows incoming message with sender BD address, e.g.:
    [<sender BD_ADDR>] $MSG
  ✓ No decrypt-fail / InvalidTag errors

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verify on Node C (relay, if present)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ May see [FWD] relay logs (opaque forward)
  ✓ Must NOT see [APP] message delivery with plaintext "$MSG"
  ✓ Must NOT see decrypt-fail for this packet (relay does not decrypt)

Identity continuity (optional):
  python3 bb_node.py --show-identity
  Compare X25519 public key hex across reboots (stable with from_group_key).

EOF
