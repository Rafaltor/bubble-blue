#!/usr/bin/env bash
# Install what apps/unoq_panel.py needs to reach the sketch on an UNO Q.
#
# The Router Bridge client ships inside the App Lab container image rather than
# on PyPI, so we lift the two modules we actually use out of that image. Only
# bridge.py and logger.py are taken: importing the whole arduino package would
# drag in numpy, opencv and an audio stack that have nothing to do with a status
# panel.
#
#   ./scripts/install_unoq_bridge.sh
#
# Needs sudo for docker and apt, nothing else. Re-running is harmless.

set -euo pipefail

DEST="${BB_PYLIB:-$HOME/.local/lib/bubble-blue}"
IMAGE_REPO="ghcr.io/arduino/app-bricks/python-apps-base"

say() { printf '%s\n' "$*"; }
die() { printf 'erreur: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker absent — cette carte n'est pas une UNO Q ?"

say "== msgpack =="
if python3 -c 'import msgpack' 2>/dev/null; then
  say "   deja present"
else
  sudo apt-get install -y -q python3-msgpack >/dev/null
  python3 -c 'import msgpack' || die "msgpack toujours introuvable apres installation"
  say "   installe"
fi

say "== image App Lab =="
IMAGE=$(sudo docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep "^${IMAGE_REPO}:" | sort -V | tail -1 || true)
[ -n "$IMAGE" ] || die "image ${IMAGE_REPO} absente — ouvrir App Lab une fois pour la telecharger"
say "   $IMAGE"

# Resolve the interpreter directory inside the image rather than hardcoding a
# Python version that will move under us on the next App Lab release.
SITE=$(sudo docker run --rm --entrypoint sh "$IMAGE" -c \
       'ls -d /usr/local/lib/python*/site-packages/arduino/app_utils' 2>/dev/null | head -1)
[ -n "$SITE" ] || die "arduino/app_utils introuvable dans $IMAGE"

say "== extraction =="
CID=$(sudo docker create "$IMAGE")
trap 'sudo docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

TMP=$(mktemp -d)
for mod in bridge.py logger.py; do
  sudo docker cp "$CID:$SITE/$mod" "$TMP/$mod" >/dev/null \
    || die "copie de $mod echouee"
done
sudo chown "$(id -u):$(id -g)" "$TMP"/*.py

PKG="$DEST/arduino/app_utils"
mkdir -p "$PKG"
: > "$DEST/arduino/__init__.py"
mv "$TMP/bridge.py" "$TMP/logger.py" "$PKG/"
printf 'from .bridge import Bridge, call, notify, provide\n' > "$PKG/__init__.py"
rmdir "$TMP"
say "   $DEST"

say "== verification =="
PYTHONPATH="$DEST" python3 -c 'from arduino.app_utils import Bridge; print("   import OK")'

if [ -S /var/run/arduino-router.sock ]; then
  # A router with no sketch answers "method not available", which still proves
  # the socket, the msgpack framing and the round-trip all work.
  PYTHONPATH="$DEST" python3 - <<'PY'
from arduino.app_utils import Bridge
try:
    Bridge.call("panel_ping", timeout=3)
    print("   routeur OK")
except ValueError:
    print("   routeur OK (aucun sketch ne repond, c'est attendu)")
except Exception as e:
    raise SystemExit(f"   routeur muet: {type(e).__name__}: {e}")
PY
else
  say "   /var/run/arduino-router.sock absent — arduino-router tourne-t-il ?"
fi

say
say "Pret. apps/unoq_panel.py trouvera la bibliotheque tout seul."
