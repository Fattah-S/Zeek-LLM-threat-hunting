"""Score Zeek traffic with Isolation Forest, rank alerts, explain each with the explainability layer.

  python score.py --baseline data/baseline --score data/score --top 20 --out out

Once analysts have labelled alerts TP/FP and train_feedback.py has built an XGBoost model,
rank with it instead:  python score.py --score data/test --xgb feedback/model_xgb.joblib

Outputs (in --out):
  top_alerts.json      Top-N alerts with explanation reasons. Hand-off to the LLM triage agent.
  scored_alerts.csv    Every alert with features + scores (input for analyst feedback).
  alert_members.csv    Zeek uid -> alert mapping (evidence lookup in the SIEM).
  model_iforest.joblib Trained Isolation Forest + feature builder.
"""
import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from explainability import TreeAttribution
from sklearn.ensemble import IsolationForest

from features import FEATURE_COLS, FEATURES, LOG_FEATURES, FeatureBuilder, read_zeek_json


def human_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(n) < 1024:
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def readable(feature, v):
    """Turn a model feature value back into something an analyst understands."""
    if feature in LOG_FEATURES:
        v = float(np.expm1(v))
        if feature == "max_duration":
            return f"{v:,.1f}s"
        if feature.startswith("bytes"):
            return human_bytes(v)
        return f"{v:,.0f}"
    if feature == "out_in_ratio":
        return f"{np.exp(v):,.2f}x"
    if feature in {"is_external", "new_domain"}:
        return "yes" if v >= 0.5 else "no"
    if feature in {"failed_ratio", "nxdomain_ratio", "rare_qtype_ratio"}:
        return f"{v:.0%}"
    if feature == "if_score":
        return f"{v:.3f}"
    return f"{v:.2f}"


def load(dirpath):
    conn = read_zeek_json(os.path.join(dirpath, "conn.log"))
    dns_path = os.path.join(dirpath, "dns.log")
    dns = read_zeek_json(dns_path) if os.path.exists(dns_path) else None
    return conn, dns


def explain_reasons(contrib_row, x_row, cols, medians, k=5):
    """Top-k features pushing risk UP for one alert."""
    out = []
    for j in np.argsort(-contrib_row)[:k]:
        if contrib_row[j] <= 0:
            continue
        f = cols[j]
        out.append({
            "feature": f,
            "description": FEATURES.get(f, "Isolation Forest anomaly score"),
            "value": readable(f, x_row[f]),
            "baseline_median": readable(f, medians[f]) if f in medians else None,
            "contribution": round(float(contrib_row[j]), 4),
        })
    return out


def indicators(al):
    """Plain detections next to the ML score. Isolation Forest can't weigh what a clean baseline
    almost never contains (cousin domains, DGA bursts); these make sure the analyst and the LLM
    still see them, and XGBoost learns their weight from feedback."""
    out = []
    if al.get("lookalike_score", 0) >= 0.85 and isinstance(al.get("lookalike_of"), str):
        out.append(f"cousin/lookalike domain of '{al.lookalike_of}' (similarity {al.lookalike_score:.2f})")
    if al.get("new_domain", 0):
        out.append("domain never seen before in this network")
    if al.get("domain_randomness", 0) >= 4.8:
        out.append(f"random-looking (DGA-like) domain names, score {al.domain_randomness:.1f}")
    if al.get("nxdomain_ratio", 0) >= 0.5 and np.expm1(al.n_unique_queries) >= 20:
        out.append(f"burst of {np.expm1(al.n_unique_queries):.0f} failed lookups (NXDOMAIN): possible DGA")
    n_q = np.expm1(al.n_unique_queries)
    if n_q >= 50 and al.get("nxdomain_ratio", 0) >= 0.5 and al.get("label_len_mean", 0) >= 15 \
            and al.get("label_len_std", 99) <= 4:
        out.append(f"{n_q:.0f} failed lookups of long names with similar length "
                   f"({al.label_len_mean:.0f} +/- {al.label_len_std:.1f} chars, TLD cut off): "
                   "GameOver-Zeus-style DGA")
    if al.get("dns_entropy", 0) >= 3.5 and np.expm1(al.n_unique_queries) >= 50:
        out.append("many long random subdomains under one domain: possible DNS tunnelling")
    if al.get("rare_qtype_ratio", 0) >= 0.3:
        out.append(f"{al.rare_qtype_ratio:.0%} of DNS queries are TXT/NULL/ANY")
    if al.get("beacon_regularity", 0) >= 0.8 and np.expm1(al.n_dst_ips) <= 3:
        out.append(f"regular timing (regularity {al.beacon_regularity:.2f}): possible C2 beacon")
    if al.get("port_rarity", 0) >= 4.0 and al.get("is_external", 0):
        out.append("destination port almost never seen in the baseline")
    if al.get("failed_ratio", 0) >= 0.8 and np.expm1(al.n_dst_ports) >= 20:
        out.append(f"{np.expm1(al.n_dst_ports):.0f} ports with mostly failed connections: scanning")
    return out


# High-confidence detections that are guaranteed a place in the top N even when the model
# ranks them low. GUESS: thresholds tuned on synthetic data only.
STRONG_RULES = {
    "rule: cousin/lookalike domain": lambda d: d["lookalike_score"] >= 0.85,
}


def pin_strong_rules(alerts, n_top):
    head = alerts.head(n_top)
    rest = alerts.iloc[n_top:]
    pinned = []
    for name, rule in STRONG_RULES.items():
        hit = rest[rule(rest)]
        hit = hit.assign(scored_by=name)
        pinned.append(hit)
    pinned = pd.concat(pinned).head(max(n_top // 4, 1)) if pinned else rest.head(0)
    pinned = pinned[~pinned.index.duplicated()]
    if pinned.empty:
        return alerts
    keep = head.head(n_top - len(pinned))
    dropped = head.iloc[len(keep):]
    return pd.concat([keep, pinned, dropped, rest.drop(pinned.index)])


def build_alert_json(top, conns, reasons):
    result = []
    for rank, ((_, al), rs) in enumerate(zip(top.iterrows(), reasons), 1):
        cc = conns[(conns["alert_id"] == al.alert_id)
                   & (conns["ts"] >= al.first_ts) & (conns["ts"] <= al.last_ts)].sort_values("ts")
        result.append({
            "rank": rank,
            "alert_id": al.alert_id,
            "src": al.src,
            "target": al.target,
            "lookalike_of": al.lookalike_of if isinstance(al.get("lookalike_of"), str) else None,
            "risk_score": round(float(al.risk_score), 2),
            "scored_by": al.scored_by,
            "n_connections": int(len(cc)),
            "first_seen": pd.to_datetime(al.first_ts, unit="s", utc=True).isoformat(),
            "last_seen": pd.to_datetime(al.last_ts, unit="s", utc=True).isoformat(),
            "bytes_out": human_bytes(float(cc["orig_bytes"].sum())),
            "bytes_in": human_bytes(float(cc["resp_bytes"].sum())),
            "dst_ips": sorted(set(cc["id.resp_h"]))[:10],
            "dst_ports": sorted(set(int(p) for p in cc["id.resp_p"]))[:10],
            "sample_uids": list(cc["uid"][:10]),
            "sample_queries": [q for q in cc["query"].dropna().unique()[:3]],
            "indicators": indicators(al),
            "explanations": rs,
            "explanation": "; ".join(
                f"{r['description']} = {r['value']}"
                + (f" (baseline median {r['baseline_median']})" if r["baseline_median"] else "")
                for r in rs),
        })
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="data/baseline")
    ap.add_argument("--score", default="data/score")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--out", default="out")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--xgb", default=None, help="path to model_xgb.joblib from train_feedback.py")
    ap.add_argument("--novelty-slots", type=int, default=5,
                    help="with --xgb: reserve this many of the top N for the most anomalous alerts "
                         "(Isolation Forest) that XGBoost did not pick, so new attack types still surface")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    b_conn, b_dns = load(a.baseline)
    s_conn, s_dns = load(a.score)
    fb = FeatureBuilder().fit(b_conn, b_dns)
    base, _ = fb.transform(b_conn, b_dns)
    alerts, conns = fb.transform(s_conn, s_dns)

    # GUESS: the baseline window is assumed mostly clean. If it already contains an attack,
    # that attack becomes "normal"; use a longer baseline and drop known-bad hosts from it.
    # max_samples = all rows: with the default 256, small dense groups of normal traffic
    # (e.g. NTP) got isolated quickly and out-ranked real attacks.
    iforest = IsolationForest(n_estimators=a.trees, max_samples=min(len(base), 4096),
                              random_state=0).fit(base[FEATURE_COLS])
    base_scores = np.sort(-iforest.score_samples(base[FEATURE_COLS]))
    alerts["if_score"] = -iforest.score_samples(alerts[FEATURE_COLS])
    # risk 0-100 = percentile vs baseline alerts, so 99 means "weirder than 99% of a normal day"
    alerts["if_risk"] = np.searchsorted(base_scores, alerts["if_score"]) / len(base_scores) * 100
    joblib.dump({"model": iforest, "features": fb}, os.path.join(a.out, "model_iforest.joblib"))
    base["if_score"] = -iforest.score_samples(base[FEATURE_COLS])
    base.to_csv(os.path.join(a.out, "baseline_alerts.csv"), index=False)

    alerts["risk_score"] = alerts["if_risk"]
    alerts["scored_by"] = "isolation_forest"
    alerts = alerts.sort_values("if_score", ascending=False)
    if a.xgb:
        bundle = joblib.load(a.xgb)
        xcols = bundle["columns"]
        xgb_model = bundle["model"]
        alerts["xgb_prob"] = xgb_model.predict_proba(alerts[xcols])[:, 1]
        # XGBoost only knows the attacks analysts have labelled so far. It overfits to those, so a
        # few slots stay with the unsupervised model: the most anomalous alerts XGBoost ranked low.
        by_xgb = alerts.sort_values(["xgb_prob", "if_score"], ascending=False)
        n_x = max(a.top - a.novelty_slots, 0)
        top_x = by_xgb.head(n_x).copy()
        top_x["risk_score"] = top_x["xgb_prob"] * 100
        top_x["scored_by"] = "xgboost (analyst feedback)"
        novelty = alerts.drop(top_x.index).head(a.top - n_x).copy()
        novelty["scored_by"] = "novelty slot (isolation_forest)"
        rest = by_xgb.drop(top_x.index.union(novelty.index)).copy()
        rest["risk_score"] = rest["xgb_prob"] * 100
        rest["scored_by"] = "xgboost (analyst feedback)"
        alerts = pd.concat([top_x, novelty, rest])

    alerts = pin_strong_rules(alerts, a.top)

    alerts.to_csv(os.path.join(a.out, "scored_alerts.csv"), index=False)
    # which Zeek uids make up each alert: lets the LLM agent / analyst pull evidence from the SIEM
    conns["window"] = (conns["ts"] // fb.window_s).astype(int)
    conns[["uid", "alert_id", "window"]].to_csv(os.path.join(a.out, "alert_members.csv"), index=False)

    top = alerts.head(a.top)
    if_expl = TreeAttribution(iforest)
    xgb_expl = TreeAttribution(xgb_model) if a.xgb else None
    reasons = []
    for i in range(len(top)):
        row = top.iloc[[i]]
        if row["scored_by"].iat[0].startswith("xgboost"):
            sv = xgb_expl.contributions(row[xcols])[0]           # positive = towards TP
            reasons.append(explain_reasons(sv, row.iloc[0], xcols, fb.medians))
        else:
            sv = -if_expl.contributions(row[FEATURE_COLS])[0]    # IF explains path length: flip sign
            reasons.append(explain_reasons(sv, row.iloc[0], FEATURE_COLS, fb.medians))
    result = build_alert_json(top, conns, reasons)
    with open(os.path.join(a.out, "top_alerts.json"), "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"scored {len(conns):,} connections -> {len(alerts):,} alerts; top {len(result)}:")
    for r in result:
        tag = {"n": "*", "r": "!"}.get(r["scored_by"][0], " ")  # * novelty slot, ! pinned by rule
        print(f"  #{r['rank']:>2}{tag}risk {r['risk_score']:6.2f}  {r['alert_id'][:58]:<58} "
              f"n={r['n_connections']:<4} {', '.join(x['feature'] for x in r['explanations'][:3])}")


if __name__ == "__main__":
    main()
