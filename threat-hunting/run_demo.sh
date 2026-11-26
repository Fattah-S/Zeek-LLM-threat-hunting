#!/usr/bin/env bash
# Full demo, ~1 minute on a laptop. Run from a local copy of this folder.
set -e
python3 generate_lab.py                         # 5 clean days + the intrusion day
python3 hunt.py --out out                       # hunts + Isolation Forest + SHAP -> out/cases.json
python3 triage.py --offline                     # template cards; with Ollama running: python3 triage.py
python3 build_dashboard.py                      # out/dashboard.html (add --png out/dashboard.png if playwright is installed)
# feedback loop: analyst labels -> XGBoost -> rank an unseen day where other hosts are attacked
python3 simulate_feedback.py out/cases.json data/hunt/ground_truth.csv feedback/labels.csv
python3 train_feedback.py --labels feedback/labels.csv --day-out out
python3 generate_lab.py --variant 1
python3 hunt.py --day data/hunt_v1 --out out_v1 --xgb feedback/model_xgb.joblib
