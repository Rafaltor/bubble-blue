#!/bin/bash
# Cage needs the panel to itself. Mask GDM before the kiosk starts; the
# Desktop button unmasks it. A board with no display manager is not an error.
set +e
for unit in gdm.service gdm3.service; do
  systemctl mask --now "$unit" >/dev/null 2>&1
done
exit 0
