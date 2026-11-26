"""Stand-in for the analyst: labels every host in the top cases TP/FP from ground truth."""
import csv, json, sys
cases = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "out/cases.json"))["cases"]
truth = {r["host"] for r in csv.DictReader(open(sys.argv[2] if len(sys.argv) > 2 else "data/hunt/ground_truth.csv"))}
out = sys.argv[3] if len(sys.argv) > 3 else "feedback/labels.csv"
import os; os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["case_id", "host", "label", "reason", "analyst"])
    for c in cases:
        for h in c["hosts"]:
            if h["score"] >= 40 or h["name"] in truth:
                w.writerow([c["case_id"], h["name"], "TP" if h["name"] in truth else "FP", "simulated", "sim"])
print("labels ->", out)
