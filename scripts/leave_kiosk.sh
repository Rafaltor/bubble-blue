#!/bin/bash
# Hand the panel back to the Ubuntu desktop.
# Must run outside bubble-blue-screen (systemd-run): stopping that service
# kills every process in its cgroup.
set -euo pipefail
systemctl stop bubble-blue-screen.service
# cage has to release the DRM device before GDM can take the panel.
sleep 1
for unit in gdm.service gdm3.service; do
  systemctl unmask "$unit" >/dev/null 2>&1 || true
done
systemctl start gdm3.service || systemctl start gdm.service
