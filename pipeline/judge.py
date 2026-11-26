"""Quality checks for the LLM's answer.

1. LLM-as-a-judge: a second open-source model, from a different family than the answerer
   (less self-preference), grades the answer against the same context the answerer saw.
2. Algorithmic metrics (no LLM involved):
   - host P/R/F1 and technique P/R/F1: what the answer names vs the attack's ground truth
   - semantic similarity: cosine of embeddings (answer vs a reference answer written from the
     ground truth); falls back to TF-IDF cosine when no embedding model is available
   - ROUGE-L: word overlap with the reference (longest common subsequence)
   BERTScore is the heavier option for the same question; embedding cosine is used here because
   it runs on the same Ollama server with no extra 2 GB of PyTorch.
"""
import math
import re

import llm

JUDGE_SYSTEM = """You are a strict reviewer of SOC triage answers. You get a QUESTION, the CONTEXT the assistant
was given (platform output: ML scores, explanation reasons, hunt findings) and the ANSWER. Grade only against the CONTEXT.
- faithfulness 1-5: every claim is supported by the CONTEXT (5 = nothing invented).
- relevance 1-5: answers the question that was asked.
- completeness 1-5: covers the highest-risk cases and their key evidence.
- actionability 1-5: next steps are concrete and fit the evidence.
List every claim not supported by the CONTEXT in unsupported_claims. verdict = "pass" if faithfulness >= 4
and relevance >= 4, else "fail"."""

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "faithfulness": {"type": "integer"}, "relevance": {"type": "integer"},
        "completeness": {"type": "integer"}, "actionability": {"type": "integer"},
        "unsupported_claims": {"type": "array", "items": {"type": "string"}},
        "verdict": {"type": "string", "enum": ["pass", "fail"]}, "reason": {"type": "string"},
    },
    "required": ["faithfulness", "relevance", "completeness", "actionability", "unsupported_claims", "verdict", "reason"],
}

TECHNIQUES = {  # canonical technique -> words an answer would use
    "beaconing": [r"beacon", r"T1071"], "c2_tunnel": [r"long[- ]lived", r"tunnel", r"long connection", r"T1572"],
    "dga": [r"\bDGA\b", r"random[- ]looking", r"domain generation", r"T1568"],
    "sweep": [r"sweep", r"\bscan", r"T1046"], "kerberoasting": [r"kerberoast", r"RC4 service ticket", r"T1558"],
    "psexec": [r"psexec", r"admin share", r"remote service", r"ADMIN\$", r"T1569", r"T1021\.002"],
    "dcsync": [r"dcsync", r"drsuapi", r"DRSGetNCChanges", r"T1003"],
    "pass_the_hash": [r"pass[- ]the[- ]hash", r"NTLM fan", r"T1550"],
    "wmi": [r"\bWMI\b", r"DCOM", r"T1047"], "sched_task": [r"scheduled task", r"T1053"],
    "rdp": [r"\bRDP\b", r"T1021\.001"],
}
HUNT_TO_TECH = {"C2-01": "beaconing", "C2-02": "c2_tunnel", "C2-03": "dga", "LM-08": "sweep", "LM-06": "kerberoasting",
                "LM-01": "psexec", "LM-07": "dcsync", "LM-05": "pass_the_hash", "LM-02": "wmi", "LM-03": "sched_task",
                "LM-04": "rdp"}


def judge(question, context, answer):
    import json
    if not llm.available(llm.JUDGE_MODEL):
        return {"verdict": "n/a", "reason": f"judge model {llm.JUDGE_MODEL} not available"}
    user = f"QUESTION: {question}\n\nCONTEXT:\n{json.dumps(context, indent=1)}\n\nANSWER:\n{answer}"
    try:
        out, secs = llm.chat(llm.JUDGE_MODEL, JUDGE_SYSTEM, user, schema=JUDGE_SCHEMA, temperature=0)
        out["judge_model"], out["latency_s"] = llm.JUDGE_MODEL, round(secs, 1)
        return out
    except Exception as e:
        return {"verdict": "n/a", "reason": f"judge failed: {e}"}


def prf(pred, gold):
    tp = len(pred & gold)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gold) if gold else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
            "predicted": sorted(pred), "expected": sorted(gold)}


def hosts_in(text, hostinfo):
    found = set()
    for ip, h in hostinfo.items():
        if re.search(rf"(?<![\w.]){re.escape(ip)}(?![\w.])", text) or re.search(rf"\b{re.escape(h['name'])}\b", text, re.I):
            found.add(h["name"])
    return found


def techniques_in(text):
    return {t for t, pats in TECHNIQUES.items() if any(re.search(p, text, re.I) for p in pats)}


def rouge_l(a, b):
    x, y = re.findall(r"\w+", a.lower()), re.findall(r"\w+", b.lower())
    if not x or not y:
        return 0.0
    prev = [0] * (len(y) + 1)
    for xi in x:
        cur = [0]
        for j, yj in enumerate(y):
            cur.append(prev[j] + 1 if xi == yj else max(prev[j + 1], cur[j]))
        prev = cur
    lcs = prev[-1]
    p, r = lcs / len(x), lcs / len(y)
    return round(2 * p * r / (p + r), 3) if lcs else 0.0


def cosine(u, v):
    d = sum(a * b for a, b in zip(u, v))
    return d / (math.sqrt(sum(a * a for a in u)) * math.sqrt(sum(b * b for b in v)) or 1)


def similarity(answer, reference):
    try:
        if llm.available(llm.EMBED_MODEL):
            a, b = llm.embed([answer, reference])
            return {"semantic_similarity": round(cosine(a, b), 3), "similarity_method": f"embedding cosine ({llm.EMBED_MODEL})"}
    except Exception:
        pass
    from sklearn.feature_extraction.text import TfidfVectorizer
    m = TfidfVectorizer().fit_transform([answer, reference])
    return {"semantic_similarity": round(float((m[0] @ m[1].T).toarray()[0, 0]), 3), "similarity_method": "TF-IDF cosine (no embedding model)"}


def metrics(answer, reference, gold_hosts, gold_techniques, hostinfo):
    return {"hosts": prf(hosts_in(answer, hostinfo) & (set(h["name"] for h in hostinfo.values())), gold_hosts),
            "techniques": prf(techniques_in(answer), gold_techniques),
            **similarity(answer, reference), "rouge_l": rouge_l(answer, reference)}
