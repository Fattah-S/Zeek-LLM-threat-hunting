#!/bin/bash
# Starts the role's services, the packet mirror, and the role's traffic generator.
. /lab/common.sh
set -u
echo "[$(hostname)] role=$ROLE ip=$(hostname -I)"
capture_loop &

case "$ROLE" in
  dc)          /lab/role_dc.sh ;;
  fileserver)  /lab/role_smb.sh fileserver ;;
  workstation) /lab/role_smb.sh workstation & sleep 3; python3 /lab/traffic/benign.py ;;
  attacker)    /lab/role_smb.sh workstation & sleep 3; python3 /lab/traffic/benign.py & python3 /lab/traffic/attack.py ;;
  sccm)        python3 /lab/traffic/admin_noise.py ;;
  internet)    /lab/role_internet.sh ;;
  c2)          openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=cdn-update-check.online" -keyout /tmp/k.pem -out /tmp/c.pem 2>/dev/null; exec python3 /lab/traffic/web.py --c2 ;;
  orchestrator) /lab/orchestrator.sh ;;
  *) echo "unknown ROLE $ROLE"; exit 1 ;;
esac
wait
