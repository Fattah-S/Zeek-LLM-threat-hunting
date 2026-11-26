#!/bin/bash
# Runs the "days" of the lab: N clean baseline sessions, then one attack session.
# Each session is a time-compressed day: same traffic mix, minutes instead of hours.
. /lab/common.sh
BASELINE_SESSIONS=${BASELINE_SESSIONS:-3}
BASELINE_SECONDS=${BASELINE_SECONDS:-240}
ATTACK_SECONDS=${ATTACK_SECONDS:-420}
if [ -f "$PCAP/lab_done" ] && [ "${FORCE_RERUN:-0}" != 1 ]; then
  echo "[orchestrator] capture already exists (set FORCE_RERUN=1 or 'docker compose down -v' to redo)"; echo done > $CONTROL/session; exit 0
fi
rm -rf $PCAP/* ; echo idle > $CONTROL/session
until [ -f $CONTROL/dc_ready ]; do sleep 2; done
sleep 10   # let SMB servers come up
run() { echo "[orchestrator] session $1 for ${2}s"; echo "$1" > $CONTROL/session; sleep "$2"
        echo idle > $CONTROL/session; sleep 3; touch "$PCAP/$1/CLOSED"; }
for i in $(seq 1 $BASELINE_SESSIONS); do run "baseline-$i" "$BASELINE_SECONDS"; done
run attack-day "$ATTACK_SECONDS"
echo done > $CONTROL/session; touch $PCAP/lab_done
echo "[orchestrator] all sessions captured"
