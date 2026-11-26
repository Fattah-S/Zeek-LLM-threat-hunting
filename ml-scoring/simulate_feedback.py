"""Pretend to be the analyst: label the top-N alerts TP/FP using the synthetic ground truth.

In production this file is replaced by the real analyst verdicts (from the Sentinel incident
close reason, a triage UI, etc.) written in the same format:

  alert_id,window,label,analyst,note
  10.0.0.31 -> api-telemetry-check.top,20422,TP,mohamed,C2 beacon
"""
import argparse
import os

import pandas as pd

from evaluate import labelled_alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out")
    ap.add_argument("--truth", default="data/score/ground_truth.csv")
    ap.add_argument("--top", type=int, default=50, help="analyst reviews this many alerts")
    ap.add_argument("--labels", default="feedback/labels.csv")
    a = ap.parse_args()

    scored, _ = labelled_alerts(a.out, a.truth)
    reviewed = scored.head(a.top)
    labels = pd.DataFrame({
        "alert_id": reviewed["alert_id"],
        "window": reviewed["window"],
        "label": ["FP" if s == "-" else "TP" for s in reviewed["scenario"]],
        "analyst": "simulated",
        "note": reviewed["scenario"].replace("-", "benign"),
    })
    os.makedirs(os.path.dirname(a.labels) or ".", exist_ok=True)
    labels.to_csv(a.labels, index=False)
    print(f"wrote {len(labels)} labels ({(labels.label == 'TP').sum()} TP / "
          f"{(labels.label == 'FP').sum()} FP) -> {a.labels}")


if __name__ == "__main__":
    main()
