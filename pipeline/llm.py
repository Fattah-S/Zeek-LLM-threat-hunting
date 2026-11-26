"""Minimal client for a local Ollama server (open-source models only; nothing leaves the network)."""
import json
import os
import re
import time
import urllib.request

OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
LLM_MODEL = os.environ.get("LLM_MODEL", "qwen3:8b")
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "gemma3:4b")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")


def _post(path, body, timeout=600):
    req = urllib.request.Request(OLLAMA + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def available(model):
    try:
        tags = json.load(urllib.request.urlopen(OLLAMA + "/api/tags", timeout=5))
        names = {m["name"] for m in tags.get("models", [])}
        return model in names or f"{model}:latest" in names
    except Exception:
        return False


def wait_for(models, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if all(available(m) for m in models):
            return True
        time.sleep(10)
    return False


def chat(model, system, user, schema=None, temperature=0.1, timeout=900, history=None):
    """One chat call. history: prior [{role, content}] turns for a multi-turn conversation.
    With schema, Ollama constrains the output to that JSON schema."""
    msgs = [{"role": "system", "content": system}]
    for m in history or []:
        if m.get("role") in ("user", "assistant") and m.get("content"):
            msgs.append({"role": m["role"], "content": str(m["content"])})
    msgs.append({"role": "user", "content": user})
    body = {"model": model, "stream": False, "options": {"temperature": temperature, "num_ctx": 16384},
            "messages": msgs}
    if schema:
        body["format"] = schema
    t = time.time()
    out = _post("/api/chat", body, timeout)["message"]["content"]
    out = re.sub(r"<think>.*?</think>", "", out, flags=re.S).strip()   # qwen3 thinking blocks
    return (json.loads(out) if schema else out), time.time() - t


def embed(texts, model=None):
    return _post("/api/embed", {"model": model or EMBED_MODEL, "input": texts}, 300)["embeddings"]
