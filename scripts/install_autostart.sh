#!/usr/bin/env bash
# Start the mesh (and the stand screen) at boot, prerequisites included.
#
#   sudo ./scripts/install_autostart.sh relay                     # UNO Q relay
#   sudo ./scripts/install_autostart.sh screen                    # Rubik with a panel
#   sudo ./scripts/install_autostart.sh screen --admin            # + "Restart mesh" button
#   sudo ./scripts/install_autostart.sh screen --pixman           # panel without working GL
#   sudo ./scripts/install_autostart.sh screen --keep-role        # UI on a UNO Q: keep central, still dial
#   sudo ./scripts/install_autostart.sh uninstall
#
# Screen boards take the peripheral link role so traffic always crosses the
# relays, and lose their display manager: cage needs the panel to itself.
# Re-running is harmless; it restarts the services with the new settings.
#
# Logs: journalctl -u bubble-blue-meshd -f   /   journalctl -u bubble-blue-screen -f

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNITS="$REPO/deploy/systemd"
ENV_FILE=/etc/bubble-blue.env
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

say() { printf '%s\n' "$*"; }
die() { printf 'erreur: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "lancer avec sudo"

MODE="${1:-}"
[ $# -gt 0 ] && shift
ADMIN=0
PIXMAN=0
KEEP_ROLE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --admin)     ADMIN=1 ;;
    --pixman)    PIXMAN=1 ;;
    --keep-role) KEEP_ROLE=1 ;;
    *) die "option inconnue: $1" ;;
  esac
  shift
done

stop_manual() {
  systemctl stop bubble-blue-screen.service bubble-blue-meshd.service 2>/dev/null || true
  # Anchored so the pattern never matches this script's own command line.
  pkill -f '^python3.14 apps/meshd' 2>/dev/null || true
  pkill -x cage 2>/dev/null || true
  for _ in $(seq 1 20); do
    pgrep -f '^python3.14 apps/meshd' >/dev/null || pgrep -x cage >/dev/null || break
    sleep 0.5
  done
  pkill -9 -f '^python3.14 apps/meshd' 2>/dev/null || true
  pkill -9 -x cage 2>/dev/null || true
  pkill -x btmgmt 2>/dev/null || true
}

if [ "$MODE" = uninstall ]; then
  stop_manual
  systemctl disable bubble-blue-screen.service bubble-blue-meshd.service 2>/dev/null || true
  rm -f /etc/systemd/system/bubble-blue-meshd.service /etc/systemd/system/bubble-blue-screen.service "$ENV_FILE"
  systemctl daemon-reload
  say "autostart retiré. Pour retrouver le bureau : sudo systemctl unmask gdm && sudo systemctl start gdm"
  exit 0
fi

case "$MODE" in
  relay|screen) ;;
  *) die "usage: $0 relay | screen [--admin] [--pixman] [--keep-role] | uninstall" ;;
esac

# ---- prerequisites ---------------------------------------------------------

say "== prérequis =="
command -v python3.14 >/dev/null || die "python3.14 absent"
command -v btmgmt >/dev/null || die "btmgmt absent (paquet bluez)"
[ -f "$REPO/.env" ] || die "$REPO/.env absent (clé de groupe BUBBLE_BLUE_GROUP_KEY)"
grep -q '^BUBBLE_BLUE_GROUP_KEY=.' "$REPO/.env" || die "BUBBLE_BLUE_GROUP_KEY vide dans $REPO/.env"

if ! python3.14 -c 'import cryptography' 2>/dev/null; then
  say "   dépendances python3.14…"
  python3.14 -m pip install -q --break-system-packages --ignore-installed -r "$REPO/requirements.txt"
fi
say "   python3.14 + cryptography OK"

systemctl enable -q bluetooth.service
command -v rfkill >/dev/null && rfkill unblock bluetooth || true
say "   bluetooth activé au boot"

if [ "$MODE" = screen ]; then
  missing=()
  command -v cage >/dev/null || missing+=(cage)
  python3 -c 'import gi; gi.require_version("Gtk", "4.0"); from gi.repository import Gtk' 2>/dev/null \
    || missing+=(python3-gi gir1.2-gtk-4.0)
  if [ ${#missing[@]} -gt 0 ]; then
    say "   installation: ${missing[*]}"
    apt-get install -y -q "${missing[@]}" >/dev/null
  fi
  say "   cage + GTK 4 OK"
fi

# ---- configuration ---------------------------------------------------------

say "== $ENV_FILE =="
OWNER_GROUP="$(id -gn "${SUDO_USER:-root}")"
{
  echo "# Written by scripts/install_autostart.sh ($MODE)"
  # The user's group keeps meshd_client.py and a windowed UI usable without sudo.
  echo "BB_MESHD_ARGS=--group $OWNER_GROUP"
  if [ "$MODE" = screen ]; then
    # UNO Q cannot dial while peripheral. A kiosk on a relay keeps auto/central.
    if [ "$KEEP_ROLE" != 1 ]; then
      echo "BUBBLE_BLUE_LINK_ROLE=peripheral"
    fi
    if [ "$ADMIN" = 1 ]; then echo "BB_UI_ARGS=--admin"; else echo "BB_UI_ARGS="; fi
    if [ "$PIXMAN" = 1 ]; then
      echo "WLR_RENDERER=pixman"
      echo "GSK_RENDERER=cairo"
    fi
  fi
} > "$ENV_FILE"
sed 's/^/   /' "$ENV_FILE"

# ---- units -----------------------------------------------------------------

say "== services =="
stop_manual

install_unit() {
  sed "s|@REPO@|$REPO|g" "$UNITS/$1" > "/etc/systemd/system/$1"
}
install_unit bubble-blue-meshd.service
if [ "$MODE" = screen ]; then
  install_unit bubble-blue-screen.service
  dm="$(basename "$(readlink -f /etc/systemd/system/display-manager.service 2>/dev/null)" 2>/dev/null || true)"
  # Ubuntu's gdm.service is static (debconf owns the alias), so only a mask
  # keeps it off the panel at boot.
  if [ -n "$dm" ] && [ "$dm" != display-manager.service ] && systemctl cat "$dm" >/dev/null 2>&1; then
    systemctl mask --now -q "$dm" 2>/dev/null || true
    say "   $dm masqué (cage a besoin de l'écran) — retour au bureau : bouton Desktop, deux tapes"
  fi
else
  systemctl disable --now -q bubble-blue-screen.service 2>/dev/null || true
  rm -f /etc/systemd/system/bubble-blue-screen.service
fi

systemctl daemon-reload
systemctl enable -q --now bubble-blue-meshd.service
[ "$MODE" = screen ] && systemctl enable -q --now bubble-blue-screen.service

sleep 5
for unit in bubble-blue-meshd bubble-blue-screen; do
  [ "$unit" = bubble-blue-screen ] && [ "$MODE" != screen ] && continue
  say "   $unit: $(systemctl is-active "$unit") / $(systemctl is-enabled "$unit")"
done
say
say "Prêt : le mesh démarre tout seul au prochain boot."
say "Logs : journalctl -u bubble-blue-meshd -f"
