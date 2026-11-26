"""Daily hunt: run all hunts, score every host with ML, explain with SHAP, group into cases.

  python hunt.py --baseline data/baseline --day data/hunt --out out [--xgb feedback/model_xgb.joblib]

Outputs (in --out):
  cases.json        ranked hunt cases: hosts, findings (ATT&CK + Zeek uids), SHAP reasons,
                    attack path, timeline. This is what the LLM agent and the dashboard read.
  host_scores.csv   every host with features, ML risk, hunt score (input for analyst feedback)
"""
import argparse
import glob
import json
import os

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import IsolationForest

from hunts import FEATURE_TEXT, FEATURES, LM_FEATURES, HuntEngine, load_day, workstation

# ip -> {"name": ..., "role": ...}. In production this comes from DHCP / DNS / the CMDB.
HOSTINFO = {}


def load_hostnames(path):
    global HOSTINFO
    if path and os.path.exists(path):
        HOSTINFO = json.load(open(path))
EXEC_HUNTS = {"LM-01", "LM-02", "LM-03", "LM-04"}  # code or a session actually moved to the target


def name(ip):
    return HOSTINFO.get(ip, {}).get("name", ip)


def role(ip):
    return HOSTINFO.get(ip, {}).get("role", "workstation" if workstation(ip) else "host")


def transform(df):
    X = df[FEATURES].astype(float).copy()
    for c in X.columns:
        if c not in ("failed_internal_ratio", "max_beacon_score", "nx_randomness"):
            X[c] = np.log1p(X[c])
    return X


def self_delta(df, host_med):
    """UEBA style: compare each host with its OWN baseline, not with every other host.
    A server that always talks to 15 hosts is normal; a workstation that suddenly does is not."""
    X = transform(df)
    # a host with no history of its own is compared with the typical host (peer baseline)
    peer = host_med.median()
    ref = transform(host_med.reindex(df.host).fillna(peer).reset_index(drop=True))
    # one-sided: for hunting only "more than usual" matters (a quiet day is not suspicious)
    return (X.reset_index(drop=True) - ref).clip(lower=0).set_axis(X.index)


def shap_reasons(explainer, X, raw, base_med, sign=-1, k=5):
    sv = explainer.shap_values(X) * sign            # IF: low path length = anomalous, so flip
    out = []
    for i in range(len(X)):
        order = np.argsort(-sv[i])
        reasons = []
        for j in order[:k]:
            if sv[i, j] <= 0:
                break
            f = FEATURES[j]
            v, m = raw.iloc[i][f], base_med.loc[raw.iloc[i]["host"], f] if raw.iloc[i]["host"] in base_med.index else 0
            fmt = (lambda x: f"{x:.2f}") if f in ("failed_internal_ratio", "max_beacon_score", "nx_randomness", "max_ext_duration_h") else (lambda x: f"{x:.0f}")
            reasons.append({"feature": f, "text": FEATURE_TEXT[f], "value": float(v), "baseline_median": float(m),
                            "contribution": round(float(sv[i, j]), 4),
                            "explanation": f"{FEATURE_TEXT[f]} = {fmt(v)} (this host usually {fmt(m)})"})
        out.append(reasons)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="data/baseline", help="folder of day*/ folders, or a glob like '/logs/baseline-*'")
    ap.add_argument("--hosts", default=os.environ.get("NSM_HOSTNAMES"), help="hostnames.json (ip -> name, role)")
    ap.add_argument("--day", default="data/hunt")
    ap.add_argument("--out", default="out")
    ap.add_argument("--xgb", default=None, help="XGBoost model from train_feedback.py (ranks with analyst feedback)")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    load_hostnames(a.hosts or os.path.join(os.path.dirname(a.baseline.rstrip("/*")), "hosts.json"))
    dirs = sorted(glob.glob(os.path.join(a.baseline, "day*"))) or sorted(d for d in glob.glob(a.baseline) if os.path.isdir(d))
    print(f"learning normal from {len(dirs)} baseline days ...")
    days = [load_day(d) for d in dirs]
    eng = HuntEngine().fit(days)
    per_day = [eng.run(d)[0] for d in days]
    base = pd.concat(per_day, ignore_index=True)
    base_med = base.groupby("host")[FEATURES].median()
    # leave-one-day-out: each baseline day vs the OTHER days, so the model sees honest day-to-day noise
    Xb = pd.concat([self_delta(df, pd.concat(per_day[:i] + per_day[i + 1:]).groupby("host")[FEATURES].median())
                    for i, df in enumerate(per_day)], ignore_index=True)
    forest = IsolationForest(n_estimators=300, max_samples=len(Xb), random_state=0).fit(Xb)
    base_scores = -forest.score_samples(Xb)
    joblib.dump({"forest": forest, "base_scores": base_scores, "base_med": base_med}, os.path.join(a.out, "model_iforest.joblib"))

    print(f"hunting in {a.day} ...")
    feats, findings, edges = eng.run(load_day(a.day))
    X = self_delta(feats, base_med)
    s = -forest.score_samples(X)
    feats["ml_risk"] = [round(100 * (base_scores < v).mean(), 1) for v in s]   # percentile vs baseline hosts
    reasons = shap_reasons(shap.TreeExplainer(forest), X, feats, base_med)
    model_name = "Isolation Forest"
    if a.xgb:
        m = joblib.load(a.xgb)
        Xx = X.assign(if_score=s)
        feats["ml_risk"] = (100 * m.predict_proba(Xx)[:, 1]).round(1)
        sv = shap.TreeExplainer(m).shap_values(Xx)
        reasons = shap_reasons(type("E", (), {"shap_values": lambda self, _: sv[:, :len(FEATURES)]})(), X, feats, base_med, sign=1)
        model_name = "XGBoost (analyst feedback)"

    live = [f for f in findings if not f["suppressed"]]
    by_host = {}
    for f in live:
        by_host.setdefault(f["src"], []).append(f)
    feats["hunt_score"] = [max([f["severity"] for f in by_host.get(h, [])], default=0) for h in feats.host]
    feats["n_hunts"] = [len({f["hunt"] for f in by_host.get(h, [])}) for h in feats.host]
    # hunts = known-bad behaviour, ML = "unusual for this host". ML alone is a hunting lead (max 70),
    # ML agreeing with a hunt raises confidence.
    feats["score"] = np.minimum(99, np.maximum(feats.hunt_score, 0.7 * feats.ml_risk)
                                + 4 * np.maximum(0, feats.n_hunts - 1)
                                + np.where((feats.hunt_score > 0) & (feats.ml_risk >= 90), 8, 0)).round(1)
    feats["name"] = feats.host.map(name)
    feats.to_csv(os.path.join(a.out, "host_scores.csv"), index=False)
    X.assign(host=feats.host.values, name=feats.name.values, if_score=s).to_csv(os.path.join(a.out, "host_model_input.csv"), index=False)
    Xb.assign(if_score=base_scores).to_csv(os.path.join(a.out, "baseline_model_input.csv"), index=False)

    # ---- group into cases: hosts joined by lateral movement where code/session moved ----
    parent = {}
    find = lambda x: x if parent.setdefault(x, x) == x else find(parent[x])
    suspects = set(by_host) | set(feats.host[feats.ml_risk >= 95])
    for h in suspects:
        find(h)
    for src, dst, hunt in edges:
        if hunt in EXEC_HUNTS:
            parent[find(dst)] = find(src)
    groups = {}
    for h in list(parent):
        groups.setdefault(find(h), set()).add(h)

    fi = feats.set_index("host")
    rs = dict(zip(feats.host, reasons))
    cases = []
    for root, members in groups.items():
        hosts = sorted(members, key=lambda h: (-fi.loc[h, "score"], -fi.loc[h, "hunt_score"]) if h in fi.index else (0, 0))
        cf = sorted([f for f in live if f["src"] in members], key=lambda f: f["first_ts"] or 0)
        tactics = sorted({f["tactic"] for f in cf})
        touched = sorted({d for s_, d, _ in edges if s_ in members} - members)
        top = max(fi.loc[h, "score"] for h in hosts if h in fi.index)
        chain = any(t == "Command and Control" for t in tactics) and any(t != "Command and Control" for t in tactics)
        score = min(100, top + (5 if chain else 0))
        for f in cf:
            f["src_name"], f["dst_name"] = name(f["src"]), name(f["dst"])
        cases.append({
            "score": round(float(score), 1),
            "severity": "critical" if score >= 90 else "high" if score >= 75 else "medium" if score >= 50 else "low",
            "title": "", "tactics": tactics, "kill_chain": chain,
            "hosts": [{"ip": h, "name": name(h), "role": role(h), "score": float(fi.loc[h, "score"]),
                       "ml_risk": float(fi.loc[h, "ml_risk"]), "hunt_score": float(fi.loc[h, "hunt_score"]),
                       "shap": rs[h], "features": {k: float(fi.loc[h, k]) for k in FEATURES if fi.loc[h, k]}}
                      for h in hosts if h in fi.index],
            "touched_hosts": [{"ip": t, "name": name(t), "role": role(t)} for t in touched],
            "attack_path": [{"src": name(s_), "dst": name(d), "hunt": h} for s_, d, h in edges if s_ in members],
            "findings": cf,
        })
    cases.sort(key=lambda c: -c["score"])
    for i, c in enumerate(cases, 1):
        c["case_id"] = f"HUNT-{i:03d}"
        lead = c["hosts"][0]["name"]
        names = list(dict.fromkeys(f["name"].split(" (")[0] for f in sorted(c["findings"], key=lambda f: -f["severity"])))
        c["title"] = f"{lead}: " + (", ".join(names[:3]) if names else "ML anomaly only") + (f" +{len(names) - 3} more" if len(names) > 3 else "")
    out = {"model": model_name, "hunt_day": a.day, "hosts_scored": len(feats),
           "findings_total": len(findings), "findings_suppressed": len(findings) - len(live),
           "cases": cases[:a.top]}
    json.dump(out, open(os.path.join(a.out, "cases.json"), "w"), indent=2, default=float)

    print(f"\n{len(feats)} hosts, {len(findings)} hunt hits ({len(findings) - len(live)} suppressed as known admin behaviour), {len(cases)} cases\n")
    for c in cases[:a.top]:
        print(f"{c['case_id']}  {c['score']:5.1f}  {c['severity']:8s} {c['title']}")
        for h in c["hosts"]:
            print(f"     {h['name']:7s} score {h['score']:5.1f}  ML {h['ml_risk']:5.1f}  hunts {h['hunt_score']:3.0f}  "
                  f"SHAP: {'; '.join(r['explanation'] for r in h['shap'][:3])}")
    gt = os.path.join(a.day, "ground_truth.csv")
    if os.path.exists(gt):
        t = pd.read_csv(gt)
        rank = {h["name"]: c["case_id"] for c in cases for h in c["hosts"]}
        print("\nground truth:")
        for host, g in t.groupby("host"):
            print(f"  {host}: {', '.join(g.technique)} -> {rank.get(host, 'MISSED')}")


if __name__ == "__main__":
    main()
