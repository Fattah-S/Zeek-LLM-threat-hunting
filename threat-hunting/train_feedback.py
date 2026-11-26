"""Analyst feedback -> XGBoost. The model learns which hunts/anomalies your analysts call TP.

  python train_feedback.py --labels feedback/labels.csv --day-out out --model feedback/model_xgb.joblib
  python hunt.py --day data/next_day --xgb feedback/model_xgb.joblib

labels.csv (exported by the dashboard's "Export labels" button):
  case_id,host,label,reason,analyst      label = TP or FP

Labels accumulate in feedback/training_set.csv across days. Baseline host-days are added as
extra negatives (GUESS: the baseline is clean) until there are enough real FP labels.
"""
import argparse
import os

import joblib
import pandas as pd
from xgboost import XGBClassifier

from hunts import FEATURES


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="feedback/labels.csv")
    ap.add_argument("--day-out", default="out", help="hunt.py output folder of the labelled day")
    ap.add_argument("--model", default="feedback/model_xgb.joblib")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.model) or ".", exist_ok=True)
    X = pd.read_csv(os.path.join(a.day_out, "host_model_input.csv"))
    lab = pd.read_csv(a.labels)
    day = X.merge(lab[["host", "label"]], left_on="name", right_on="host", suffixes=("", "_l"))
    day["y"] = (day.label == "TP").astype(int)
    store = os.path.join(os.path.dirname(a.model) or ".", "training_set.csv")
    hist = pd.read_csv(store) if os.path.exists(store) else pd.DataFrame()
    hist = pd.concat([hist, day[FEATURES + ["if_score", "y"]]], ignore_index=True)
    hist.to_csv(store, index=False)
    neg = pd.read_csv(os.path.join(a.day_out, "baseline_model_input.csv")).assign(y=0)
    train = pd.concat([hist, neg[FEATURES + ["if_score", "y"]]], ignore_index=True)
    pos = max(1, train.y.sum())
    m = XGBClassifier(n_estimators=200, max_depth=3, learning_rate=0.1, min_child_weight=0.5,
                      scale_pos_weight=(len(train) - pos) / pos, eval_metric="logloss")
    m.fit(train[FEATURES + ["if_score"]], train.y)
    joblib.dump(m, a.model)
    imp = sorted(zip(m.feature_importances_, FEATURES + ["if_score"]), reverse=True)[:6]
    print(f"trained on {len(hist)} analyst labels ({int(hist.y.sum())} TP) + {len(neg)} baseline negatives")
    print("top features:", ", ".join(f"{n} {v:.2f}" for v, n in imp))


if __name__ == "__main__":
    main()
