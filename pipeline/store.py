"""The store: every scored day lands in SQLite, and the LLM only ever answers from here.

  Zeek -> features -> Isolation Forest -> explainability -> [store] -> analyst asks -> LLM answers -> judge

Tables: runs, hosts (score, ML risk, explanation reasons), cases, findings, qa (every question,
answer, judge verdict and metrics), labels (analyst TP/FP).
"""
import json
import os
import sqlite3
import time

import pandas as pd

DB = os.environ.get("NSM_DB", "/data/nsm.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, day TEXT, created REAL, model TEXT,
    hosts_scored INT, findings_total INT, findings_suppressed INT, cases_json TEXT);
CREATE TABLE IF NOT EXISTS hosts (run_id INT, ip TEXT, name TEXT, role TEXT, score REAL, ml_risk REAL,
    hunt_score REAL, features TEXT, explanations TEXT);
CREATE TABLE IF NOT EXISTS findings (run_id INT, case_id TEXT, hunt TEXT, name TEXT, tactic TEXT, attack TEXT,
    src TEXT, dst TEXT, severity INT, first_ts REAL, detail TEXT, uids TEXT);
CREATE TABLE IF NOT EXISTS qa (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INT, ts REAL, question TEXT,
    answer TEXT, model TEXT, judge TEXT, metrics TEXT, context TEXT);
CREATE TABLE IF NOT EXISTS labels (run_id INT, case_id TEXT, host TEXT, label TEXT, reason TEXT, analyst TEXT, ts REAL);
"""


def connect(db=DB):
    os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def save_run(out_dir, db=DB):
    """Load hunt.py output (cases.json + host_scores.csv) into the store. Returns run_id."""
    cases = json.load(open(os.path.join(out_dir, "cases.json")))
    hs = pd.read_csv(os.path.join(out_dir, "host_scores.csv"))
    reasons_by_host = {h["ip"]: h["explanations"] for c in cases["cases"] for h in c["hosts"]}
    c = connect(db)
    cur = c.execute("INSERT INTO runs (day, created, model, hosts_scored, findings_total, findings_suppressed, cases_json)"
                    " VALUES (?,?,?,?,?,?,?)", (cases["hunt_day"], time.time(), cases["model"], cases["hosts_scored"],
                                               cases["findings_total"], cases["findings_suppressed"], json.dumps(cases)))
    run = cur.lastrowid
    feats = [k for k in hs.columns if k not in ("host", "name", "ml_risk", "hunt_score", "n_hunts", "score")]
    for _, r in hs.iterrows():
        c.execute("INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?)",
                  (run, r.host, r["name"], "", float(r.score), float(r.ml_risk), float(r.hunt_score),
                   json.dumps({k: float(r[k]) for k in feats if r[k]}), json.dumps(reasons_by_host.get(r.host, []))))
    for case in cases["cases"]:
        for f in case["findings"]:
            c.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (run, case["case_id"], f["hunt"], f["name"], f["tactic"], f["attack"], f["src"], f["dst"],
                       f["severity"], f["first_ts"], f["detail"], json.dumps(f["evidence_uids"])))
    c.commit()
    return run


def latest_run(db=DB):
    c = connect(db)
    r = c.execute("SELECT * FROM runs ORDER BY run_id DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def save_qa(run_id, question, answer, model, judge, metrics, context, db=DB):
    c = connect(db)
    c.execute("INSERT INTO qa (run_id, ts, question, answer, model, judge, metrics, context) VALUES (?,?,?,?,?,?,?,?)",
              (run_id, time.time(), question, answer, model, json.dumps(judge), json.dumps(metrics), json.dumps(context)))
    c.commit()


def save_label(run_id, case_id, host, label, reason, analyst="analyst", db=DB):
    c = connect(db)
    c.execute("INSERT INTO labels VALUES (?,?,?,?,?,?,?)", (run_id, case_id, host, label, reason, analyst, time.time()))
    c.commit()


def labels(db=DB):
    return [dict(r) for r in connect(db).execute("SELECT * FROM labels ORDER BY ts")]


if __name__ == "__main__":
    import sys
    print("run", save_run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else DB))
