#!/usr/bin/env bash
# Bring up the screen app: mesh daemon (root) + touch UI (user), in one command.
#
#   ./scripts/start_screen.sh              # auto: kiosk if no compositor, else windowed
#   ./scripts/start_screen.sh --kiosk      # force cage (dedicated panel, no desktop)
#   ./scripts/start_screen.sh --windowed   # force a plain window (inside a desktop)
#   ./scripts/start_screen.sh --fake       # simulated mesh, no adapter, no root
#   ./scripts/start_screen.sh --admin      # add the "Restart mesh" button (stand board only)
#
# The daemon keeps running when the UI exits: links take ~40 s to converge and
# should survive restarting the interface.
set -uo pipefail

cd "$(dirname "$0")/.."

SOCKET="${BUBBLE_BLUE_SOCKET:-/run/bubble-blue/meshd.sock}"
MODE=auto
FAKE=0
UI_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --kiosk)    MODE=kiosk ;;
    --windowed) MODE=windowed ;;
    --fake)     FAKE=1; SOCKET=/tmp/bubble-blue-fake.sock ;;
    --socket)   shift; SOCKET="$1" ;;
    --admin)    UI_ARGS+=(--admin) ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

PY314=python3.14
command -v $PY314 >/dev/null 2>&1 || PY314=python3

# ---- 1. daemon ------------------------------------------------------------

# A stale socket file survives a daemon that died, so probe by connecting.
socket_ready() {
  python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('$SOCKET')
except OSError:
    sys.exit(1)
" 2>/dev/null
}

if socket_ready; then
  echo "démon déjà en écoute sur $SOCKET"
else
  if [ "$FAKE" = 1 ]; then
    echo "démarrage du démon simulé…"
    nohup python3 scripts/meshd_fake.py --socket "$SOCKET" >/tmp/bb-meshd.log 2>&1 &
  else
    echo "démarrage du démon mesh (sudo requis pour L2CAP + MGMT)…"
    sudo -b env BUBBLE_BLUE_SOCKET="$SOCKET" \
      $PY314 apps/meshd.py --socket "$SOCKET" >/tmp/bb-meshd.log 2>&1
  fi

  printf "attente de la socket"
  for _ in $(seq 1 60); do
    if socket_ready; then
      echo " — prête"
      break
    fi
    printf "."
    sleep 1
  done
  if ! socket_ready; then
    echo
    echo "le démon n'a pas ouvert $SOCKET — voir /tmp/bb-meshd.log" >&2
    tail -20 /tmp/bb-meshd.log >&2
    exit 1
  fi
fi

# ---- 2. interface ---------------------------------------------------------

# Inside an existing desktop there is already a compositor holding DRM master,
# so cage cannot start: fall back to a plain window.
if [ "$MODE" = auto ]; then
  if [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${DISPLAY:-}" ]; then
    MODE=windowed
  elif command -v cage >/dev/null 2>&1; then
    MODE=kiosk
  else
    echo "aucune session graphique et cage absent." >&2
    echo "  écran branché sur une board dédiée : sudo apt-get install -y cage" >&2
    echo "  pas d'écran : python3 scripts/meshd_client.py --socket $SOCKET" >&2
    exit 1
  fi
fi

echo "interface : mode $MODE"

if [ "$MODE" = kiosk ]; then
  if ! command -v cage >/dev/null 2>&1; then
    echo "cage absent — sudo apt-get install -y cage" >&2
    exit 1
  fi
  exec cage -- python3 apps/screen_ui.py --socket "$SOCKET" --kiosk "${UI_ARGS[@]}"
else
  exec python3 apps/screen_ui.py --socket "$SOCKET" "${UI_ARGS[@]}"
fi
