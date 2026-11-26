"""Lab validation: how well did the platform do on the attack day, against the ground truth
the attacker container wrote (the pipeline itself never reads it).

  python evaluate.py --day /logs/attack-day --out /data/results

Reports:
  1. Detection: per technique (did the expected hunt fire on the attacking host?),
     finding precision, host precision/recall, known-admin-noise suppression.
  2. "Ask the network": for each analyst question, the LLM answer, the LLM-judge grades and the
     algorithmic metrics (host / technique F1, semantic similarity, ROUGE-L), next to the
     no-LLM template baseline.
Writes results/metrics.json and results/RESULTS.md.
"""
import argparse
import json
import os
import time

import ask
import judge
import llm
import store

QUESTIONS = [
    "What abnormal behaviour happened on the network today?",
    "Which hosts should I investigate first, and why did the model flag them?",
    "Is there any sign of credential theft or lateral movement?",
]
EXEC_OR_CRED = {"LM-01", "LM-02", "LM-03", "LM-04", "LM-07"}


def reference_answer(gt, hostinfo):
    name = lambda ip: hostinfo.get(ip, {}).get("name", ip)
    src = ", ".join(name(h) for h in gt["compromised_hosts"])
    steps = "; ".join(f"{s['technique']} from {name(s['src'])} to {name(s['target']) if s['target'] in hostinfo else s['target']}"
                      for s in gt["steps"])
    return (f"{src} is compromised. It talks to a command-and-control server ({', '.join(gt['c2'])}). "
            f"Observed today: {steps}. Investigate {src} first, then the hosts it reached. "
            f"Isolate the host, reset the stolen admin account and krbtgt, rotate the service account passwords, block the C2 domain.")


def detection_metrics(gt, cases, hostinfo):
    name = lambda ip: hostinfo.get(ip, {}).get("name", ip)
    live = [f for c in cases["cases"] for f in c["findings"]]
    comp = set(gt["compromised_hosts"])
    per_tech, seen = [], set()
    for s in gt["steps"]:
        if s["expected_hunt"] in seen:   # one row per technique (PsExec hits two targets, one technique)
            continue
        seen.add(s["expected_hunt"])
        hit = [f for f in live if f["hunt"] == s["expected_hunt"] and f["src"] == s["src"]]
        per_tech.append({"technique": s["technique"], "hunt": s["expected_hunt"], "detected": bool(hit),
                         "evidence": hit[0]["detail"] if hit else "no network evidence (the RPC was refused before Zeek could log it)"})
    tp_f = [f for f in live if f["src"] in comp]
    host_rows = [h for c in cases["cases"] for h in c["hosts"]]
    alerted = {h["ip"] for h in host_rows if h["score"] >= 75}
    rank = next((i for i, c in enumerate(cases["cases"], 1) if any(h["ip"] in comp for h in c["hosts"])), None)
    return {
        "techniques_detected": sum(t["detected"] for t in per_tech), "techniques_total": len(per_tech),
        "per_technique": per_tech,
        "findings_total_unsuppressed": len(live), "findings_true": len(tp_f),
        "finding_precision": round(len(tp_f) / len(live), 3) if live else 0,
        "host_alerts": sorted(name(h) for h in alerted),
        "host_precision": round(len(alerted & comp) / len(alerted), 3) if alerted else 0,
        "host_recall": round(len(alerted & comp) / len(comp), 3),
        "compromised_case_rank": rank,
        "suppressed_known_admin": cases["findings_suppressed"],
        "gold_hosts": sorted({name(h) for h in comp} | {name(s["target"]) for s in gt["steps"]
                                                        if s["expected_hunt"] in EXEC_OR_CRED and s["target"] in hostinfo}),
        "gold_techniques": sorted({judge.HUNT_TO_TECH[s["expected_hunt"]] for s in gt["steps"]
                                   if any(t["detected"] for t in per_tech if t["hunt"] == s["expected_hunt"])}),
    }


def md(results):
    d = results["detection"]
    out = ["# Lab results", "", f"Attack day: `{results['day']}` · generated {results['generated']}", "",
           "## Detection", "",
           f"| Metric | Value |", "|---|---|",
           f"| Techniques detected | **{d['techniques_detected']} / {d['techniques_total']}** |",
           f"| Compromised host's case rank | #{d['compromised_case_rank']} |",
           f"| Host alerts (score ≥ 75) | {', '.join(d['host_alerts']) or '-'} |",
           f"| Host precision / recall | {d['host_precision']:.0%} / {d['host_recall']:.0%} |",
           f"| Finding precision (hits on the compromised host / all unsuppressed hits) | {d['finding_precision']:.0%} ({d['findings_true']}/{d['findings_total_unsuppressed']}) |",
           f"| Deployment-server hits suppressed as known admin behaviour | {d['suppressed_known_admin']} |", "",
           "| Technique | Hunt | Detected | Evidence |", "|---|---|---|---|"]
    out += [f"| {t['technique']} | {t['hunt']} | {'yes' if t['detected'] else '**no**'} | {t['evidence'][:110]} |" for t in d["per_technique"]]
    out += ["", "> WMI (LM-02) and the remote scheduled task (LM-03) are attempted against Samba, which refuses the DCOM / "
            "task-scheduler RPC before any operation is carried out, so Zeek has nothing to log. On Windows targets the "
            "bind and the call are logged and both hunts fire — these two are a limitation of the Samba lab, not of the detection."]
    out += ["", "## Ask the network: LLM answer quality", "",
            f"Answerer: `{results['llm_model']}` · judge: `{results['judge_model']}` · gold hosts: {', '.join(d['gold_hosts'])} · gold techniques: {len(d['gold_techniques'])}", "",
            "| Question | Answered by | Judge (faith/rel/comp/act) | Verdict | Host F1 | Technique F1 | Semantic sim. | ROUGE-L |",
            "|---|---|---|---|---|---|---|---|"]
    for q in results["qa"]:
        rows = [("LLM", q["llm"]), ("baseline", q["template"])]
        first = True
        for _, r in rows:
            if not r:
                continue
            j = r["judge"]
            js = f"{j.get('faithfulness','-')}/{j.get('relevance','-')}/{j.get('completeness','-')}/{j.get('actionability','-')}"
            m = r["metrics"]
            out.append(f"| {q['question'] if first else '〃'} | {r['model'][:40]} | {js} | {j.get('verdict')} | "
                       f"{m['hosts']['f1']:.2f} | {m['techniques']['f1']:.2f} | {m['semantic_similarity']:.2f} | {m['rouge_l']:.2f} |")
            first = False
    out += ["", f"Similarity method: {results['qa'][0]['template']['metrics']['similarity_method'] if results['qa'] else '-'}", "",
            "## Example answer", "", f"**Q:** {results['qa'][0]['question']}", "", "```", results["qa"][0]["llm"]["answer"] if results["qa"][0]["llm"] else results["qa"][0]["template"]["answer"], "```"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", default="/logs/attack-day")
    ap.add_argument("--hosts", default=os.environ.get("NSM_HOSTNAMES", "hostnames.json"))
    ap.add_argument("--out", default="/data/results")
    ap.add_argument("--wait-llm", type=int, default=int(os.environ.get("WAIT_FOR_LLM_SECONDS", 1800)))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    gt = json.load(open(os.path.join(a.day, "ground_truth.json")))
    hostinfo = json.load(open(a.hosts))
    run = store.latest_run()
    cases = json.loads(run["cases_json"])
    det = detection_metrics(gt, cases, hostinfo)
    ref = reference_answer(gt, hostinfo)
    gold_h, gold_t = set(det["gold_hosts"]), set(det["gold_techniques"])
    print(f"detection: {det['techniques_detected']}/{det['techniques_total']} techniques, case rank #{det['compromised_case_rank']}")
    have_llm = llm.wait_for([llm.LLM_MODEL], a.wait_llm)
    print("LLM available:", have_llm)
    qa = []
    for q in QUESTIONS:
        row = {"question": q, "llm": None}
        ctx, run_id = ask.build_context()
        tmpl = ask.template_answer(ctx)
        row["template"] = {"model": "template (no LLM)", "answer": tmpl, "judge": judge.judge(q, ctx, tmpl),
                           "metrics": judge.metrics(tmpl, ref, gold_h, gold_t, hostinfo)}
        if have_llm:
            r = ask.ask(q)
            row["llm"] = {"model": r["model"], "answer": r["answer"], "latency_s": r.get("latency_s"),
                          "judge": judge.judge(q, r["context"], r["answer"]),
                          "metrics": judge.metrics(r["answer"], ref, gold_h, gold_t, hostinfo)}
            store.save_qa(run_id, q, r["answer"], r["model"], row["llm"]["judge"], row["llm"]["metrics"], r["context"])
            print(f"Q: {q}\n  judge={row['llm']['judge'].get('verdict')} hostF1={row['llm']['metrics']['hosts']['f1']} "
                  f"techF1={row['llm']['metrics']['techniques']['f1']} sim={row['llm']['metrics']['semantic_similarity']}")
        qa.append(row)
    res = {"day": a.day, "generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "detection": det,
           "llm_model": llm.LLM_MODEL if have_llm else "not available in this environment (run `docker compose up` locally, where Ollama is reachable)",
           "judge_model": llm.JUDGE_MODEL if llm.available(llm.JUDGE_MODEL) else "requires local Ollama", "llm_available": have_llm,
           "reference_answer": ref, "qa": qa}
    json.dump(res, open(os.path.join(a.out, "metrics.json"), "w"), indent=2, default=str)
    open(os.path.join(a.out, "RESULTS.md"), "w").write(md(res))
    print(md(res))


if __name__ == "__main__":
    main()
