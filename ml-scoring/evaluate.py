"""Check where each injected attack landed in the ranking (synthetic data only).

  python evaluate.py --out out --truth data/score/ground_truth.csv --top 20
"""
import argparse
import os

import pandas as pd


def labelled_alerts(out_dir, truth_csv):
    scored = pd.read_csv(os.path.join(out_dir, "scored_alerts.csv")).reset_index(drop=True)
    members = pd.read_csv(os.path.join(out_dir, "alert_members.csv"))
    truth = pd.read_csv(truth_csv)
    m = members.merge(truth, on="uid")
    scen = m.groupby(["alert_id", "window"])["scenario"].agg(lambda s: s.mode()[0])
    scored["scenario"] = [scen.get((a, w), "-") for a, w in zip(scored.alert_id, scored.window)]
    return scored, truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out")
    ap.add_argument("--truth", default="data/score/ground_truth.csv")
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()

    scored, truth = labelled_alerts(a.out, a.truth)
    n_scen = truth["scenario"].nunique()
    print(f"{len(scored)} alerts, {n_scen} injected scenarios\n\n{'scenario':<12} rank   risk")
    found = 0
    for scen, grp in scored[scored.scenario != "-"].groupby("scenario"):
        best = grp.index.min()
        found += best < a.top
        print(f"{scen:<12} {best + 1:>4}  {scored.loc[best, 'risk_score']:6.2f}")
    hits = (scored.head(a.top)["scenario"] != "-").sum()
    print(f"\ncaught in top {a.top}: {found}/{n_scen} scenarios | precision@{a.top}: {hits}/{a.top}")


if __name__ == "__main__":
    main()
