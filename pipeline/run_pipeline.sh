#!/bin/bash
# Pipeline container: wait for the sensor, then
#   features -> Isolation Forest -> SHAP -> store -> LLM triage -> evaluation (LLM answers + judge)
# The dashboard starts first and fills in as stages finish.
set -u
LOGS=${LOGS:-/logs}; DATA=${NSM_DATA:-/data}; DAY=${HUNT_DAY:-attack-day}
mkdir -p "$DATA/out" "$DATA/results"
st() { printf '{"stage":"%s","detail":"%s"}' "$1" "$2" > "$DATA/status.json"; echo "[pipeline] $1: $2"; }
python3 server.py &
st waiting "waiting for Zeek logs of the baseline days and $DAY"
until [ -f "$LOGS/$DAY/DONE" ]; do sleep 5; done
if [ ! -f "$DATA/out/.scored-$DAY" ]; then
  st scoring "features, Isolation Forest, SHAP and hunts"
  python3 hunt.py --baseline "$LOGS/baseline-*" --day "$LOGS/$DAY" --out "$DATA/out" --hosts "$NSM_HOSTNAMES" | tee "$DATA/out/hunt.txt"
  python3 store.py "$DATA/out" && touch "$DATA/out/.scored-$DAY"
fi
st triage "LLM triage cards for the top cases (falls back to a template if the model is not pulled yet)"
python3 llm.py >/dev/null 2>&1
LLM_URL="$OLLAMA_URL/v1" python3 triage.py --cases "$DATA/out/cases.json" --logs "$LOGS/$DAY" --out "$DATA/out/triage.json" --model "$LLM_MODEL"
st evaluating "asking the analyst questions, judging the answers, scoring against ground truth"
[ -f "$LOGS/$DAY/ground_truth.json" ] && python3 evaluate.py --day "$LOGS/$DAY" --out "$DATA/results" --hosts "$NSM_HOSTNAMES"
st ready "done"
echo "[pipeline] ready: http://localhost:8080"
wait
