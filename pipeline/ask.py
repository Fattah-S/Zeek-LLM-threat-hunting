"""Ask the network: the analyst asks in plain language, the LLM answers ONLY from the store.

  question -> retrieve today's top new behaviours from the store (scores, explanation reasons, hunt
  findings) -> one LLM call with that context -> answer with citations -> judge checks it

The LLM never sees raw logs and never decides what is anomalous: the Isolation Forest and the
hunts did that, and the explainability layer says why. The LLM is the translator at the end.

  python ask.py "What abnormal behaviour happened on the network today?"
"""
import json
import sys
import time

import llm
import store

SYSTEM = """You are a SOC assistant for a network security monitoring platform.
You get CONTEXT produced by the platform for one day of Zeek network logs:
- cases ranked by risk score. Each host has an ML risk (Isolation Forest, compared with that host's own normal),
  explanation reasons (why the model scored it high: "feature = today's value (this host usually X)"),
  and hunt findings (known attacker techniques with MITRE ATT&CK ids and evidence).
Rules:
1. Answer ONLY from the CONTEXT. If it does not contain the answer, say so. Never invent hosts, IPs, domains or techniques.
2. Lead with the most important finding. For each abnormal behaviour give: host, what happened, why it was flagged
   (quote the explanation reason or hunt evidence), and the ATT&CK technique.
3. Cite sources in square brackets, e.g. [HUNT-001 LM-07] or [EXPL WS-04].
4. Separate confirmed hunt evidence from ML-only anomalies (leads to check, not alerts).
5. End with 2-4 concrete next steps. Be concise: an analyst reads this in one minute."""


def build_context(top=5, db=store.DB):
    run = store.latest_run(db)
    if not run:
        return None
    cases = json.loads(run["cases_json"])
    ctx = {"day": run["day"], "hosts_scored": run["hosts_scored"], "hunt_hits": run["findings_total"],
           "suppressed_as_known_admin_behaviour": run["findings_suppressed"], "cases": []}
    for c in cases["cases"][:top]:
        ctx["cases"].append({
            "case_id": c["case_id"], "score": c["score"], "severity": c["severity"], "tactics": c["tactics"],
            "hosts": [{"name": h["name"], "ip": h["ip"], "role": h["role"], "ml_risk": h["ml_risk"],
                       "hunt_score": h["hunt_score"], "why_flagged": [r["explanation"] for r in h["explanations"][:4]]}
                      for h in c["hosts"] if h["hunt_score"] > 0 or h["ml_risk"] >= 80][:4],
            "findings": [{"id": f["hunt"], "technique": f["name"], "attack": f["attack"], "src": f["src_name"],
                          "dst": f["dst_name"], "evidence": f["detail"]} for f in c["findings"]][:12],
            "touched_hosts": [t["name"] for t in c["touched_hosts"]][:10]})
    return ctx, run["run_id"]


def template_answer(ctx):
    """No-LLM baseline: the same facts, stitched by a template. Used when Ollama is down,
    and in the evaluation as the baseline the LLM has to beat."""
    lines = [f"{ctx['hosts_scored']} hosts scored, {ctx['hunt_hits']} hunt hits "
             f"({ctx['suppressed_as_known_admin_behaviour']} suppressed as known admin behaviour)."]
    for c in ctx["cases"]:
        h = c["hosts"][0] if c["hosts"] else {"name": "?", "why_flagged": []}
        techs = "; ".join(f"{f['technique']} ({f['attack'].split(',')[0]}) {f['src']} -> {f['dst']}" for f in c["findings"][:6])
        lines.append(f"[{c['case_id']}] {c['severity']} {h['name']}: {techs or 'ML anomaly only'}. "
                     f"Why: {'; '.join(h['why_flagged'][:2])}.")
    return "\n".join(lines)


def ask(question, top=5, db=store.DB, use_llm=True):
    built = build_context(top, db)
    if not built:
        return {"answer": "No scored day in the store yet. The sensor and pipeline are still running.", "model": None}
    ctx, run_id = built
    user = f"QUESTION: {question}\n\nCONTEXT (JSON):\n{json.dumps(ctx, indent=1)}"
    if use_llm and llm.available(llm.LLM_MODEL):
        try:
            answer, secs = llm.chat(llm.LLM_MODEL, SYSTEM, user)
            return {"answer": answer, "model": llm.LLM_MODEL, "latency_s": round(secs, 1), "context": ctx, "run_id": run_id}
        except Exception as e:
            err = str(e)
    else:
        err = f"{llm.LLM_MODEL} not available on Ollama"
    return {"answer": template_answer(ctx), "model": f"template (LLM unavailable: {err})", "latency_s": 0,
            "context": ctx, "run_id": run_id}


if __name__ == "__main__":
    q = " ".join(sys.argv[1:]) or "What abnormal behaviour happened on the network today?"
    r = ask(q)
    print(f"Q: {q}\n[{r['model']}]\n{r['answer']}")
