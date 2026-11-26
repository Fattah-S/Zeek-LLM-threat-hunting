#!/usr/bin/env bash
# Synthetic demo: the same detection pipeline on generated Zeek logs, no Docker. ~1 minute.
# Run from the synthetic/ folder:  cd synthetic && bash run_demo.sh
set -e
P=../pipeline                                   # the pipeline code lives here
pip install -q -r $P/requirements.txt 2>/dev/null || true
python3 generate_lab.py                          # 5 clean days + an intrusion day (writes data/ + data/hosts.json)
python3 $P/hunt.py --baseline data/baseline --day data/hunt --out out --hosts data/hosts.json
python3 $P/triage.py --offline --cases out/cases.json --logs data/hunt --out out/triage.json
python3 $P/build_dashboard.py --cases out/cases.json --triage out/triage.json --out out/dashboard.html
# feedback loop: analyst labels -> XGBoost -> rank an unseen day where other hosts are attacked
python3 simulate_feedback.py out/cases.json data/hunt/ground_truth.csv feedback/labels.csv
python3 $P/train_feedback.py --labels feedback/labels.csv --day-out out
python3 generate_lab.py --variant 1
python3 $P/hunt.py --baseline data/baseline --day data/hunt_v1 --out out_v1 --hosts data/hosts.json --xgb feedback/model_xgb.joblib
echo "done -> open synthetic/out/dashboard.html"
