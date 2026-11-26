"""Dashboard + API for the analyst (Python standard library only).

  GET  /              the dashboard for the latest scored day (from the store)
  POST /api/ask       {"question": "..."} -> LLM answer from the store + LLM-judge grades
  POST /api/label     {"case_id", "host", "label": "TP"|"FP", "reason"} -> labels table (feeds retraining)
  GET  /api/labels.csv, /api/status, /api/results, /healthz
"""
import csv
import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ask
import judge
import llm
import store
from build_dashboard import render

DATA = os.environ.get("NSM_DATA", "/data")
STATUS = os.path.join(DATA, "status.json")

WAITING = """<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5"><title>NSM Hunt Console</title>
<style>body{background:#0b0f17;color:#e6ebf5;font:15px DejaVu Sans,Arial;display:grid;place-items:center;height:100vh;margin:0}
div{max-width:640px}code{color:#5aa9ff}</style></head><body><div><h2>NSM Hunt Console</h2><p>The lab is running. %s</p>
<p>This page refreshes by itself. Follow along with <code>docker compose logs -f orchestrator sensor pipeline</code>.</p></div></body></html>"""


def status():
    try:
        return json.load(open(STATUS))
    except Exception:
        return {"stage": "starting", "detail": "waiting for the sensor"}


class H(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = min(int(self.headers.get("Content-Length", 0)), 100_000)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, "ok", "text/plain")
        if self.path == "/api/status":
            return self.send(200, json.dumps(status()))
        if self.path == "/api/results":
            p = os.path.join(DATA, "results", "metrics.json")
            return self.send(200, open(p).read()) if os.path.exists(p) else self.send(404, "{}")
        if self.path == "/api/labels.csv":
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["case_id", "host", "label", "reason", "analyst"])
            for r in store.labels():
                w.writerow([r["case_id"], r["host"], r["label"], r["reason"], r["analyst"]])
            return self.send(200, out.getvalue(), "text/csv")
        if self.path in ("/", "/index.html"):
            run = store.latest_run()
            if not run:
                st = status()
                return self.send(200, WAITING % f"Stage: <b>{st['stage']}</b>. {st.get('detail', '')}", "text/html")
            d = json.loads(run["cases_json"])
            d["llm_model"], d["source"] = llm.LLM_MODEL, os.path.basename(d.get("hunt_day", ""))
            tri = os.path.join(DATA, "out", "triage.json")
            t = json.load(open(tri)) if os.path.exists(tri) else {}
            return self.send(200, render(d, t, live=True), "text/html; charset=utf-8")
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if self.headers.get("Origin") and self.headers["Origin"] != f"http://{self.headers.get('Host')}":
            return self.send(403, '{"error":"cross-origin"}')
        if self.path == "/api/ask":
            b = self.body()
            q = str(b.get("question", ""))[:500]
            hist = [{"role": m.get("role"), "content": str(m.get("content", ""))[:4000]}
                    for m in (b.get("history") or []) if isinstance(m, dict) and m.get("role") in ("user", "assistant")][-8:]
            r = ask.ask(q, history=hist)
            r["judge"] = judge.judge(q, r.get("context"), r["answer"]) if r.get("context") else {}
            if r.get("run_id"):
                store.save_qa(r["run_id"], q, r["answer"], r["model"], r["judge"], {}, r["context"])
            r.pop("context", None)
            return self.send(200, json.dumps(r, default=str))
        if self.path == "/api/label":
            b = self.body()
            if b.get("label") not in ("TP", "FP"):
                return self.send(400, '{"error":"label must be TP or FP"}')
            run = store.latest_run()
            store.save_label(run["run_id"] if run else 0, str(b.get("case_id"))[:20], str(b.get("host"))[:40],
                             b["label"], str(b.get("reason", ""))[:200])
            return self.send(200, '{"ok":true}')
        self.send(404, "{}")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"[pipeline] dashboard on http://localhost:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
