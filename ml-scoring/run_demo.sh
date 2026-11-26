#!/usr/bin/env bash
# Full loop on synthetic data: generate -> score (IF) -> analyst feedback -> XGBoost -> score unseen day.
set -euo pipefail
cd "$(dirname "$0")"
python3 generate_synthetic.py --test-day                      # data/baseline (5 days), data/score, data/test
python3 score.py --score data/score --out out --top 20        # Isolation Forest + SHAP
python3 evaluate.py --out out --truth data/score/ground_truth.csv
python3 simulate_feedback.py --out out --top 50               # "analyst" labels top 50 TP/FP
python3 train_feedback.py --scored out/scored_alerts.csv --baseline out/baseline_alerts.csv
python3 score.py --score data/test --out out_test --xgb feedback/model_xgb.joblib --top 20
python3 evaluate.py --out out_test --truth data/test/ground_truth.csv --top 20
