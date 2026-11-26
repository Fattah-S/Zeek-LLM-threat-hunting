"""Feature engineering for Zeek conn.log (+ dns.log for domain context).

Two levels:
  1. enrich(conn, dns)   -> one row per connection, with domain, DNS query, port, state info.
  2. aggregate(enriched) -> one row per ALERT = (internal source host, target) in a time window.
     target = registered domain if known, else "failed connections" bucket (scans), else dest IP.

The model scores step 2. Scoring single connections was tried first: heavy-tailed but normal
traffic (big SMB/HTTPS transfers) out-ranked the attacks, because a single connection can't
show behaviour over time (beaconing, scanning, tunnelling). Pair-level aggregates fix that and
also give the analyst one alert per story instead of 600 beacon rows.

FeatureBuilder.fit() learns "what normal looks like" from a baseline window (port
frequencies, known domains, medians used in explanations).
"""
import json
import math
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache

import numpy as np
import pandas as pd

FAILED_STATES = {"REJ", "S0", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
RARE_QTYPES = {"TXT", "NULL", "ANY", "KEY", "AXFR"}
NXDOMAIN_TARGET = "failed DNS lookups (NXDOMAIN)"

# GUESS: seed text for the character-bigram model behind domain_randomness (the idea of
# freq.py). For real use, train it on the Tranco/Alexa top 1M domains instead.
_SEED_TEXT = """
the and for you that with this from have are not all can was but what about when your
more time will been they which their there would other into some could them make than
first then like just only over know also people these back after work good well year
because most where much need home help search online service business information
account login mail cloud update security support system network server data center
office drive share video music news shop store market secure portal connect access
microsoft google amazon apple facebook twitter linkedin github slack zoom yahoo office
windows outlook teams skype adobe oracle cisco dropbox netflix spotify wikipedia reddit
instagram youtube paypal ebay salesforce atlassian docker python stack overflow mozilla
cdn api static media images assets content delivery analytics tracking telemetry status
"""


def _label(domain):
    """'mail.google.com' -> 'google'  (the part a DGA or typosquatter actually controls)."""
    if not isinstance(domain, str) or not domain:
        return ""
    parts = domain.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


class BigramModel:
    """Average surprise per character pair. ~3-4 for English-like names, 6+ for random strings."""

    def __init__(self, words):
        self.counts = Counter()
        self.first = Counter()
        for w in words:
            w = f"^{_norm_chars(w)}$"
            for a, b in zip(w, w[1:]):
                self.counts[a + b] += 1
                self.first[a] += 1
        self.vocab = 38  # a-z, digit class, '-', ^, $

    @lru_cache(maxsize=100_000)
    def score(self, label):
        if not label:
            return 0.0
        w = f"^{_norm_chars(label)}$"
        lp = [-math.log((self.counts[a + b] + 0.1) / (self.first[a] + 0.1 * self.vocab))
              for a, b in zip(w, w[1:])]
        return float(np.mean(lp))


def _norm_chars(s):
    return "".join("0" if ch.isdigit() else ch for ch in s.lower() if ch.isalnum() or ch == "-")


_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("3", "e"), ("5", "s"), ("@", "a")]


def _unhomoglyph(s):
    """All plausible 'what it pretends to be' spellings ('1' can stand for l or i)."""
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return {s.replace("1", "l"), s.replace("1", "i")}


def lookalike_match(label, popular_labels):
    """(score, popular label it imitates). Exact matches don't count.
    'rnicrosoft' vs 'microsoft' -> 1.0 after homoglyph folding; 'g1thub' vs 'github' -> 1.0."""
    if not label or label in popular_labels:
        return 0.0, None
    folded = _unhomoglyph(label)
    best, match = 0.0, None
    for p in popular_labels:
        if p in folded:
            return 1.0, p
        if abs(len(p) - len(label)) <= 3:
            r = SequenceMatcher(None, label, p).ratio()
            if r > best:
                best, match = r, p
    return (best, match) if best >= 0.75 else (0.0, None)


def lookalike_score(label, popular_labels):
    return lookalike_match(label, popular_labels)[0]

# alert-level feature -> human description (used by SHAP explanations and the LLM prompt)
FEATURES = {
    "n_conn":              "number of connections",
    "bytes_out":           "total bytes sent out by the internal host",
    "bytes_in":            "total bytes received",
    "out_in_ratio":        "upload/download ratio",
    "max_duration":        "longest connection duration",
    "beacon_regularity":   "timing regularity (1 = clockwork, beacon-like)",
    "new_domain":          "domain never seen in the baseline",
    "domain_host_count":   "internal hosts that talk to this domain",
    "port_rarity":         "rarity of the destination port",
    "is_external":         "destination outside the network",
    "failed_ratio":        "share of rejected / unanswered connections",
    "n_dst_ips":           "distinct destination IPs",
    "n_dst_ports":         "distinct destination ports",
    "n_unique_queries":    "distinct DNS names queried",
    "dns_entropy":         "randomness of DNS subdomains (entropy)",
    "domain_randomness":   "how random the domain name looks (freq.py-style, DGA)",
    "lookalike_score":     "similarity of a NEW domain to a popular one (cousin domain)",
    "nxdomain_ratio":      "share of DNS lookups that failed (NXDOMAIN)",
    "rare_qtype_ratio":    "share of DNS queries of unusual type (TXT/NULL/ANY)",
    "label_len_mean":      "average domain length with the TLD cut off",
    "label_len_std":       "spread of domain lengths (low with many names = generated, e.g. GameOver Zeus)",
}
FEATURE_COLS = list(FEATURES)
LOG_FEATURES = {"n_conn", "bytes_out", "bytes_in", "max_duration", "domain_host_count",
                "n_dst_ips", "n_dst_ports", "n_unique_queries"}


def read_zeek_json(path):
    """Read a Zeek JSON-lines log (LogAscii::use_json=T)."""
    with open(path) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    return pd.DataFrame(rows)


def registered_domain(q):
    # GUESS: naive "last two labels". Use tldextract for real data (co.uk, com.eg, ...).
    if not isinstance(q, str) or not q:
        return None
    parts = q.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q


def subdomain_entropy(q):
    if not isinstance(q, str):
        return np.nan
    sub = "".join(q.rstrip(".").split(".")[:-2])
    if not sub:
        return 0.0
    c, n = Counter(sub), len(sub)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def is_private(ip):
    if not isinstance(ip, str):
        return False
    if ip.startswith(("10.", "192.168.", "127.", "fe80:", "fd")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except ValueError:
            return False
    return False


def beacon_regularity(ts):
    """1 - coefficient of variation of inter-arrival gaps. ~1 = clockwork.
    GUESS: needs >= 10 connections; jittered/sleeping beacons need a smarter test (e.g. FFT)."""
    if len(ts) < 10:
        return 0.0
    gaps = np.diff(np.sort(np.asarray(ts, dtype=float)))
    gaps = gaps[gaps > 0]
    if len(gaps) < 9:
        return 0.0
    return float(max(0.0, 1.0 - gaps.std() / gaps.mean()))


def enrich(conn, dns=None):
    """Per-connection enrichment: domain, DNS query, failure flag, numeric cleanup."""
    c = conn.copy()
    for col in ["duration", "orig_bytes", "resp_bytes"]:
        c[col] = pd.to_numeric(c.get(col), errors="coerce").fillna(0).clip(lower=0)
    c["query"] = None
    c["domain"] = None
    c["rcode"] = None
    c["qtype"] = None
    if dns is not None and not dns.empty:
        # Zeek shares the uid between a DNS connection and its dns.log entry
        d1 = dns.drop_duplicates("uid", keep="last").set_index("uid")
        c["query"] = c["uid"].map(d1["query"])
        c["rcode"] = c["uid"].map(d1["rcode_name"]) if "rcode_name" in d1 else None
        c["qtype"] = c["uid"].map(d1["qtype_name"]) if "qtype_name" in d1 else None
        ip2dom = {}
        for q, answers in zip(dns["query"], dns.get("answers", pd.Series([None] * len(dns)))):
            if isinstance(answers, list):
                for ans in answers:
                    ip2dom[ans] = q
        # GUESS: non-DNS connections get the last name that resolved to the dest IP.
        # Better on real data: ssl.log server_name / http.log host, joined by uid.
        c["domain"] = c["query"].where(c["query"].notna(), c["id.resp_h"].map(ip2dom))
        c["domain"] = c["domain"].map(registered_domain)
    c["nxdomain"] = (c["rcode"] == "NXDOMAIN").astype(int)
    c["q_domain"] = c["query"].map(registered_domain).where(c["query"].notna(), c["domain"])
    # failed lookups all go to one bucket per host, so a DGA burst is one alert, not 150
    c.loc[c["nxdomain"] == 1, "domain"] = None
    c["failed"] = c["conn_state"].isin(FAILED_STATES).astype(int)
    c["external"] = (~c["id.resp_h"].map(is_private)).astype(int)
    c["target"] = np.where(c["domain"].notna(), c["domain"],
                  np.where(c["nxdomain"] == 1, NXDOMAIN_TARGET,
                  np.where(c["failed"] == 1, "failed connections (multiple hosts)",
                           c["id.resp_h"])))
    c["alert_id"] = c["id.orig_h"] + " -> " + c["target"].astype(str)
    return c


class FeatureBuilder:
    """window_hours: alerts are built per (src, target, time window). The baseline is cut into
    the same windows so a 5-day baseline gives ~5x more training rows at the same scale."""

    def __init__(self, window_hours=24):
        self.window_s = window_hours * 3600

    def fit(self, conn, dns=None):
        c = enrich(conn, dns)
        port_freq = c["id.resp_p"].value_counts() / len(c)
        self.port_rarity = (-np.log10(port_freq)).to_dict()
        self.unseen_port_rarity = float(-np.log10(1.0 / len(c)))
        self.known_domains = set(c["domain"].dropna())
        hosts = c.groupby("domain")["id.orig_h"].nunique()
        # GUESS: "popular" = used by >= 20% of internal hosts in the baseline. Add your own
        # brand, bank and key partners here so cousins of them are caught too.
        min_hosts = max(3, 0.2 * c["id.orig_h"].nunique())
        self.popular_labels = {_label(d) for d in hosts[hosts >= min_hosts].index} - {""}
        self.bigram = BigramModel(_SEED_TEXT.split() + [_label(d) for d in self.known_domains])
        feats = self.aggregate(c, fitting=True)
        self.medians = feats[FEATURE_COLS].median().to_dict()
        return self

    def transform(self, conn, dns=None):
        """Returns (alerts dataframe, enriched connections)."""
        c = enrich(conn, dns)
        return self.aggregate(c), c

    def aggregate(self, c, fitting=False):
        c = c.copy()
        c["port_rarity"] = c["id.resp_p"].map(self.port_rarity).fillna(self.unseen_port_rarity)
        c["q_entropy"] = c["query"].map(subdomain_entropy)
        c["randomness"] = c["q_domain"].map(lambda d: self.bigram.score(_label(d)) if isinstance(d, str) else np.nan)
        c["rare_qtype"] = c["qtype"].isin(RARE_QTYPES).astype(int)
        c["is_dns"] = c["query"].notna().astype(int)
        c["window"] = (c["ts"] // self.window_s).astype(int)
        hosts_per_dom = c.groupby(["window", "domain"])["id.orig_h"].nunique()

        g = c.groupby(["alert_id", "window"])
        a = pd.DataFrame({
            "src": g["id.orig_h"].first(),
            "target": g["target"].first(),
            "domain": g["domain"].first(),
            "first_ts": g["ts"].min(),
            "last_ts": g["ts"].max(),
            "n_conn": g["uid"].count(),
            "bytes_out": g["orig_bytes"].sum(),
            "bytes_in": g["resp_bytes"].sum(),
            "max_duration": g["duration"].max(),
            "is_external": g["external"].max(),
            "failed_ratio": g["failed"].mean(),
            "n_dst_ips": g["id.resp_h"].nunique(),
            "n_dst_ports": g["id.resp_p"].nunique(),
            "port_rarity": g["port_rarity"].max(),
            "n_unique_queries": g["query"].nunique(),
            "dns_entropy": g["q_entropy"].mean(),
            "beacon_regularity": g["ts"].apply(beacon_regularity),
            "domain_randomness": g["randomness"].mean(),
            "n_dns": g["is_dns"].sum(),
            "n_nxdomain": g["nxdomain"].sum(),
            "n_rare_qtype": g["rare_qtype"].sum(),
        })
        a["domain_randomness"] = a["domain_randomness"].fillna(0)  # no domain at all
        a["nxdomain_ratio"] = (a["n_dns"] > 0) * a["n_nxdomain"] / a["n_dns"].clip(lower=1)
        a["rare_qtype_ratio"] = (a["n_dns"] > 0) * a["n_rare_qtype"] / a["n_dns"].clip(lower=1)
        a = a.drop(columns=["n_dns", "n_nxdomain", "n_rare_qtype"])
        # length of each distinct domain label (TLD cut off, as in the GameOver Zeus hunt):
        # a DGA's names cluster in a narrow, unusual length band
        c["label_len"] = c["q_domain"].map(lambda d: len(_label(d)) if isinstance(d, str) else np.nan)
        u = c.dropna(subset=["label_len"]).drop_duplicates(["alert_id", "window", "q_domain"])
        ll = u.groupby(["alert_id", "window"])["label_len"].agg(["mean", "std"])
        a["label_len_mean"] = ll["mean"].reindex(a.index).fillna(0)
        a["label_len_std"] = ll["std"].reindex(a.index).fillna(0)
        a["out_in_ratio"] = np.log((a["bytes_out"] + 1) / (a["bytes_in"] + 1))
        a["dns_entropy"] = a["dns_entropy"].fillna(0)
        if fitting:
            # inside the baseline, "new" = seen in only one baseline window. Without this the
            # feature is always 0 in training and Isolation Forest can never split on it.
            n_win = c["window"].nunique()
            dom_windows = c.groupby("domain")["window"].nunique()
            a["new_domain"] = (a["domain"].map(dom_windows).eq(1) & (n_win > 1)).astype(int)
        else:
            a["new_domain"] = (a["domain"].notna() & ~a["domain"].isin(self.known_domains)).astype(int)
        matches = [lookalike_match(_label(d), self.popular_labels) if n else (0.0, None)
                   for d, n in zip(a["domain"], a["new_domain"])]
        a["lookalike_score"] = [m[0] for m in matches]
        a["lookalike_of"] = [m[1] for m in matches]
        # no domain (internal / raw IP) -> treat as common so it isn't flagged just for that
        keys = list(zip(a.index.get_level_values("window"), a["domain"]))
        a["domain_host_count"] = pd.Series([hosts_per_dom.get(k, np.nan) for k in keys],
                                           index=a.index).fillna(
            hosts_per_dom.max() if len(hosts_per_dom) else 1)
        for col in LOG_FEATURES:
            a[col] = np.log1p(a[col])
        return a.reset_index()
