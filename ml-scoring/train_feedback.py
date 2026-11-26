"""Close the loop: train XGBoost on analyst TP/FP verdicts.

  python train_feedback.py --labels feedback/labels.csv --scored out/scored_alerts.csv \
                           --baseline out/baseline_alerts.csv

1. Joins the labels with the feature snapshot of each alert (from scored_alerts.csv) and appends
   them to feedback/training_set.csv, so labels from many days accumulate.
2. Trains XGBoost on features + the Isolation Forest score (so the supervised model starts
   from what the unsupervised one already knows and learns what analysts call noise).
3. Saves feedback/model_xgb.joblib for score.py --xgb.

GUESS: with few true positives we also add a sample of baseline alerts as FP
("--baseline-negatives"), assuming the baseline was clean. Turn it off (0) once you have
a few hundred real labels.
"""
import argparse
import os

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from features import FEATURE_COLS

MODEL_COLS = FEATURE_COLS + ["if_score"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="feedback/labels.csv")
    ap.add_argument("--scored", default="out/scored_alerts.csv")
    ap.add_argument("--baseline", default="out/baseline_alerts.csv")
    ap.add_argument("--baseline-negatives", type=int, default=500)
    ap.add_argument("--store", default="feedback/training_set.csv")
    ap.add_argument("--model", default="feedback/model_xgb.joblib")
    a = ap.parse_args()

    labels = pd.read_csv(a.labels)
    scored = pd.read_csv(a.scored)
    new = labels.merge(scored[["alert_id", "window"] + MODEL_COLS], on=["alert_id", "window"])
    if os.path.exists(a.store):
        new = pd.concat([pd.read_csv(a.store), new]).drop_duplicates(
            ["alert_id", "window"], keep="last")
    new.to_csv(a.store, index=False)

    train = new[MODEL_COLS + ["label"]].copy()
    train["y"] = (train["label"] == "TP").astype(int)
    if a.baseline_negatives and os.path.exists(a.baseline):
        base = pd.read_csv(a.baseline)
        neg = base.sample(min(a.baseline_negatives, len(base)), random_state=0)[MODEL_COLS]
        neg["y"] = 0
        train = pd.concat([train, neg], ignore_index=True)

    pos, negn = int(train.y.sum()), int((train.y == 0).sum())
    print(f"training set: {pos} TP, {negn} FP/negatives ({len(new)} analyst labels in store)")
    if pos < 2 or negn < 2:
        raise SystemExit("need at least 2 TP and 2 FP to train")
    if pos < 30:
        print(f"WARNING: only {pos} true positives. The model will overfit to these attacks; "
              "keep Isolation Forest in the loop until you have more labels.")

    model = XGBClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.1, subsample=0.9,
        colsample_bytree=0.8, min_child_weight=1, scale_pos_weight=negn / pos,
        eval_metric="logloss", random_state=0)
    model.fit(train[MODEL_COLS], train["y"])
    os.makedirs(os.path.dirname(a.model) or ".", exist_ok=True)
    joblib.dump({"model": model, "columns": MODEL_COLS}, a.model)

    imp = pd.Series(model.feature_importances_, index=MODEL_COLS).sort_values(ascending=False)
    print("top features learned from feedback:", ", ".join(f"{k} {v:.2f}" for k, v in imp.head(6).items()))
    print(f"saved {a.model}")


if __name__ == "__main__":
    main()
