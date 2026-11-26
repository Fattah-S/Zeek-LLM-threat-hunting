"""LLM triage agent: turns each hunt case into a short analyst-ready triage card.

Default backend: Ollama running an OPEN-SOURCE model on your own machine/server, so no log
data leaves the company. Any other OpenAI-compatible server (vLLM, llama.cpp) works too.

  ollama pull qwen3:14b                       # once
  python triage.py                            # uses http://localhost:11434/v1 + qwen3:14b
  python triage.py --model qwen3:32b          # bigger GPU
  python triage.py --llm-url http://gpu-host:8000/v1 --model Qwen/Qwen3-32B-AWQ   # vLLM instead
  python triage.py --offline                  # no LLM: template card, same JSON shape

Settings can also come from env vars: LLM_URL, LLM_MODEL (and LLM_API_KEY if your server needs one).

Pipeline mode (as in the v1 design): the code gathers ALL evidence first (here from the Zeek
files by uid; in production the same uids go into fixed, read-only KQL queries against
Sentinel), then makes ONE LLM call per case with guided JSON output. The model never writes
free KQL and never touches the SIEM directly.
"""
import argparse
import json
import os
import urllib.request

from hunts import load_day

SCHEMA = {
    "type": "object",
    "properties": {
        "assessment": {"type": "string", "enum": ["likely_malicious", "suspicious", "likely_benign"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "headline": {"type": "string"},
        "summary": {"type": "string"},
        "attack_story": {"type": "array", "items": {"type": "string"}},
        "evidence": {"type": "array", "items": {"type": "object", "properties": {
            "claim": {"type": "string"}, "source": {"type": "string"}}, "required": ["claim", "source"]}},
        "benign_explanations": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["assessment", "confidence", "headline", "summary", "attack_story", "evidence", "next_steps"],
}

SYSTEM = """You are a SOC threat-hunting assistant. You get one hunt case built from Zeek logs:
hunt findings (each with a MITRE ATT&CK id and Zeek uids), an ML risk score with SHAP reasons,
and raw Zeek log rows pulled as evidence. Write a triage card for a tier-2 analyst.
Rules:
- Use ONLY the facts in the case. Every evidence claim must cite a finding id (e.g. LM-01) or a Zeek uid.
- Say what is known vs. guessed. If a benign explanation is plausible (admin tool, backup job), list it.
- Order the attack story by time and name the ATT&CK technique for each step.
- Next steps must be concrete (isolate host X, reset account Y, check EDR on Z, query ...).
- Do not decide TP/FP: the analyst does. Reply with JSON only, matching the schema."""

LOG_FIELDS = {
    "conn": ["id.resp_p", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"],
    "dce_rpc": ["endpoint", "operation", "named_pipe"], "smb_mapping": ["path", "share_type"],
    "smb_files": ["action", "path", "name"], "kerberos": ["request_type", "client", "service", "cipher"],
    "ntlm": ["username", "hostname", "server_nb_computer_name"], "rdp": ["cookie", "result", "client_name"],
    "dns": ["query", "rcode_name"], "ssl": ["server_name", "ja3"],
}


def gather_evidence(case, logs, per_finding=3):
    """Stand-in for the SIEM lookup: pull the Zeek rows behind each finding by uid."""
    out = []
    for f in case["findings"]:
        uids = set(f["evidence_uids"][:per_finding])
        rows = []
        for log, cols in LOG_FIELDS.items():
            df = logs[log]
            if len(df):
                for _, r in df[df.uid.isin(uids)].iterrows():
                    rows.append({"log": f"{log}.log", "uid": r.uid, "src": r["id.orig_h"], "dst": r["id.resp_h"],
                                 **{c: r[c] for c in cols if c in r and r[c] == r[c]}})
        out.append({"finding": f["hunt"], "rows": rows[:6]})
    return out


def build_prompt(case, evidence):
    slim = {k: case[k] for k in ["case_id", "score", "severity", "tactics", "kill_chain", "attack_path", "touched_hosts"]}
    slim["hosts"] = [{k: h[k] for k in ["name", "ip", "role", "score", "ml_risk", "hunt_score"]} |
                     {"shap": [r["explanation"] for r in h["shap"]]} for h in case["hosts"][:4]]
    slim["findings"] = [{k: f[k] for k in ["hunt", "name", "attack", "severity", "src_name", "dst_name", "count", "first_ts", "detail"]}
                        for f in case["findings"]]
    return json.dumps({"case": slim, "zeek_evidence": evidence}, default=str)


def call_llm(url, model, prompt, timeout=300):
    body = {"model": model, "temperature": 0.1, "max_tokens": 1500,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            # structured output: Ollama (>= 0.5) and vLLM both accept a json_schema response_format
            "response_format": {"type": "json_schema", "json_schema": {"name": "triage", "schema": SCHEMA}}}
    req = urllib.request.Request(url.rstrip("/") + "/chat/completions", json.dumps(body).encode(),
                                 {"Content-Type": "application/json",
                                  "Authorization": f"Bearer {os.environ.get('LLM_API_KEY', 'none')}"})
    txt = json.load(urllib.request.urlopen(req, timeout=timeout))["choices"][0]["message"]["content"]
    txt = txt.split("</think>")[-1].strip()  # Qwen3 thinking mode
    return json.loads(txt[txt.find("{"): txt.rfind("}") + 1])


def hhmm(ts):
    h = (ts % 86400) / 3600
    return f"{int(h):02d}:{int(h % 1 * 60):02d}"


def cap(t):
    return t[:1].upper() + t[1:]


def headline(case, c2, lm, creds):
    lead = case["hosts"][0]["name"]
    bits = []
    if c2:
        bits.append("C2 " + "/".join(dict.fromkeys({"C2-01": "beacon", "C2-02": "tunnel", "C2-03": "DGA", "C2-04": "new domain"}[f["hunt"]] for f in c2)))
    moved = {f["dst_name"] for f in lm if f["hunt"] in ("LM-01", "LM-02", "LM-03", "LM-04")}
    if moved:
        bits.append(f"lateral movement to {len(moved)} hosts")
    if any(f["hunt"] == "LM-07" for f in creds):
        bits.append("DCSync")
    elif creds:
        bits.append("credential theft")
    return f"{lead} looks compromised: " + " + ".join(bits) if len(bits) > 1 else f"{lead}: " + (bits[0] if bits else "suspicious activity")


def offline_card(case):
    """No GPU? Same JSON shape, written from the case data by a template. Clearly labelled."""
    fs = case["findings"]
    lead = case["hosts"][0]
    if not fs:
        return {"assessment": "suspicious", "confidence": "low",
                "headline": f"{lead['name']} behaves unusually for itself, but no hunt matched",
                "summary": f"ML risk {lead['ml_risk']:.0f}/100 compared with this host's own baseline. "
                           f"Top reasons: {'; '.join(r['explanation'] for r in lead['shap'][:3])}. "
                           "No known lateral-movement or C2 pattern fired, so this is a lead to check, not an alert.",
                "attack_story": [], "evidence": [{"claim": r["explanation"], "source": "SHAP"} for r in lead["shap"][:3]],
                "benign_explanations": ["new software or a changed user routine", "small deviations on a quiet host"],
                "next_steps": [f"Look at {lead['name']}'s connections for the top SHAP feature", "Mark FP if it is explained: the model learns from it"]}
    story = [f"{hhmm(f['first_ts'])} {f['src_name']} → {f['dst_name']}: {f['name'].split(' (')[0]} ({f['attack'].split(',')[0]})" for f in fs]
    c2 = [f for f in fs if f["hunt"].startswith("C2")]
    lm = [f for f in fs if f["hunt"].startswith("LM")]
    srcs = list(dict.fromkeys(f["src_name"] for f in fs))
    creds = [f for f in fs if f["hunt"] in ("LM-05", "LM-06", "LM-07")]
    parts = []
    if c2:
        parts.append(f"{c2[0]['src_name']} shows command-and-control traffic ({', '.join(dict.fromkeys(f['name'].split(' (')[0].lower() for f in c2))})")
    if lm:
        moved = sorted({f["dst_name"] for f in lm if f["hunt"] in ("LM-01", "LM-02", "LM-03", "LM-04")})
        parts.append(f"lateral movement from {', '.join(dict.fromkeys(f['src_name'] for f in lm))}"
                     + (f" to {', '.join(moved)}" if moved else ""))
    if creds:
        parts.append("credential theft activity (" + ", ".join(dict.fromkeys(f["name"].split(" (")[0] for f in creds)) + ")")
    import re as _re
    acc = sorted({m.group(1) for f in fs for m in [_re.search(r"as '([^']+)'", f["detail"])] if m})
    steps = [f"Isolate {', '.join(srcs[:2])} in EDR and capture memory before reboot"]
    if any(f["hunt"] == "LM-07" for f in fs):
        steps.append("Treat the domain as compromised: DCSync means password hashes (possibly krbtgt) were read. Plan a double krbtgt reset")
    if acc:
        steps.append(f"Disable / reset accounts seen in the activity: {', '.join(acc)}")
    if any(f["hunt"] == "LM-06" for f in fs):
        steps.append("Rotate passwords of the kerberoasted service accounts and move them to AES-only / gMSA")
    if c2:
        steps.append(f"Block {', '.join(dict.fromkeys(f['dst_name'] for f in c2 if f['hunt'] != 'C2-03'))} at the proxy/firewall and search all hosts for the same domain/IP/JA3")
    steps.append("Check the touched hosts for the dropped service binary / scheduled task: " + ", ".join(t["name"] for t in case["touched_hosts"][:6]))
    benign = []
    if any(f["hunt"] in ("LM-01", "LM-04", "LM-05") for f in fs):
        benign.append("an IT admin using PsExec/RDP during an incident or migration (no change ticket found in the case data)")
    if c2 and not lm:
        benign.append("an unknown update agent or telemetry client polling home")
    return {
        "assessment": "likely_malicious" if case["score"] >= 75 else "suspicious",
        "confidence": "high" if len({f["hunt"] for f in fs}) >= 3 else "medium",
        "headline": headline(case, c2, lm, creds),
        "summary": (cap("; ".join(parts)) + ". "
                    f"{len(fs)} hunt hits over {len(case['hosts'])} hosts. ML agrees: {lead['name']} is "
                    f"{lead['ml_risk']:.0f}/100 unusual for itself ({lead['shap'][0]['explanation'] if lead['shap'] else 'n/a'})."),
        "attack_story": story,
        "evidence": [{"claim": f["detail"], "source": f"{f['hunt']} · uid {f['evidence_uids'][0]}"} for f in sorted(fs, key=lambda f: -f["severity"])[:5]],
        "benign_explanations": benign,
        "next_steps": steps,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="out/cases.json")
    ap.add_argument("--logs", default="data/hunt")
    ap.add_argument("--out", default="out/triage.json")
    ap.add_argument("--llm-url", default=os.environ.get("LLM_URL", "http://localhost:11434/v1"), help="Ollama by default")
    ap.add_argument("--model", default=os.environ.get("LLM_MODEL", "qwen3:14b"))
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    data = json.load(open(a.cases))
    logs = load_day(a.logs)
    cards = {}
    for case in data["cases"]:
        ev = gather_evidence(case, logs)
        prompt = build_prompt(case, ev)
        if a.offline:
            card, by = offline_card(case), "offline template (no LLM called)"
        else:
            try:
                card, by = call_llm(a.llm_url, a.model, prompt), a.model
            except Exception as e:  # keep the queue moving; the analyst still has findings + SHAP
                print(f"{case['case_id']}: LLM failed ({e}), using template")
                card, by = offline_card(case), "offline template (LLM call failed)"
        cards[case["case_id"]] = {**card, "generated_by": by, "prompt_chars": len(prompt), "evidence": card.get("evidence", []),
                                  "zeek_rows": ev}
        print(f"{case['case_id']}: {card['assessment']:16s} {card['headline'][:90]}")
    json.dump(cards, open(a.out, "w"), indent=2, default=str)


if __name__ == "__main__":
    main()
