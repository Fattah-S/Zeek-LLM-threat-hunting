"""Hunt analytics for lateral movement (LM) and command & control (C2) on Zeek logs.

Two outputs per day of logs:
  1. host features  (one row per internal host): what the ML model scores
  2. findings       (hunt hits): known-bad behaviours with an ATT&CK id, source, target and
                    the Zeek uids that prove it (for pulling evidence from the SIEM)

Every hunt is a hypothesis an analyst would test by hand; the code just runs all of them
every day. See README.md for why each one works.
"""
import ipaddress
import json
import math
import os
from functools import lru_cache
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

# ---- network config (env vars; defaults fit the synthetic data) ----------------------------
def _cidrs(v):
    return [ipaddress.ip_network(c.strip()) for c in v.split(",") if c.strip()]


INTERNAL_NETS = _cidrs(os.environ.get("NSM_INTERNAL_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
WORKSTATION_NETS = _cidrs(os.environ.get("NSM_WORKSTATION_CIDRS", "10.10.1.0/24"))
DCS = set(os.environ.get("NSM_DCS", "10.10.0.10,10.10.0.11").split(","))
# DNS resolvers (forwarders re-ask upstream, so they mirror every client's lookups): don't blame them
RESOLVERS = set(os.environ.get("NSM_RESOLVERS", os.environ.get("NSM_DCS", "10.10.0.10,10.10.0.11")).split(","))
SWEEP_MIN_HOSTS = int(os.environ.get("NSM_SWEEP_MIN_HOSTS", 20))
DGA_RANDOMNESS = float(os.environ.get("NSM_DGA_RANDOMNESS", 3.8))  # per-name bigram "surprise": ~3 for words, 4+ random
LONG_CONN_SECONDS = float(os.environ.get("NSM_LONG_CONN_SECONDS", 4 * 3600))
ADMIN_PORTS = {135, 139, 445, 3389, 5985, 5986}
WORK_HOURS = (7, 20)                          # GUESS: local working hours (logs are UTC here)
EXEC_EXT = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".sys")
WMI_ENDPOINTS = {"IRemoteSCMActivator", "ISystemActivator", "IWbemServices", "IWbemLevel1Login"}
TASK_ENDPOINTS = {"ITaskSchedulerService", "atsvc"}
KNOWN_SHARE = 0.6  # a (source, hunt) pair seen on >= 60% of baseline days is "known admin behaviour"

HUNTS = {
    # id: (name, tactic, ATT&CK, base severity 0-100)
    "LM-01": ("Admin share + remote service (PsExec style)", "Lateral Movement", "T1021.002, T1569.002", 85),
    "LM-02": ("Remote WMI / DCOM execution", "Lateral Movement", "T1047, T1021.003", 80),
    "LM-03": ("Remote scheduled task", "Lateral Movement", "T1053.005", 75),
    "LM-04": ("Unusual RDP (workstation to workstation, off hours, new pair)", "Lateral Movement", "T1021.001", 60),
    "LM-05": ("NTLM fan-out with one account (pass-the-hash)", "Lateral Movement", "T1550.002", 75),
    "LM-06": ("Kerberoasting (RC4 service tickets for many SPNs)", "Credential Access", "T1558.003", 80),
    "LM-07": ("DCSync from a non-DC", "Credential Access", "T1003.006", 95),
    "LM-08": ("Internal sweep of SMB/RPC/RDP ports", "Discovery", "T1046, T1135", 55),
    "C2-01": ("Beaconing (regular timing + same-size payloads)", "Command and Control", "T1071.001, T1573", 75),
    "C2-02": ("Long-lived external connection", "Command and Control", "T1572, T1571", 55),
    "C2-03": ("DGA: burst of random-looking failed lookups", "Command and Control", "T1568.002", 70),
    "C2-04": ("New domain + TLS client fingerprint (JA3) never seen", "Command and Control", "T1071.001", 45),
}

COMMON = """the and for are but not you all any can her was one our out day get has him his how man new
now old see two way who boy did its let put say she too use dad mom about after again below could every
first found great house large learn never other place plant point right small sound spell still study
their there these thing think three water where which world would write office google microsoft mail
cloud update login secure online service portal account support news shop store media video music book
data center group global network system digital market home health travel bank web app api cdn static
images content analytics telemetry sync status windows apple amazon github linkedin teams zoom outlook""".split()


class Bigram:
    """Average surprise per character pair: ~3 for English-like labels, 5+ for random strings."""

    def __init__(self, words):
        self.c, self.f = Counter(), Counter()
        for w in words:
            w = f"^{w.lower()}$"
            for a, b in zip(w, w[1:]):
                self.c[a + b] += 1
                self.f[a] += 1

    def score(self, label):
        w = f"^{label.lower()}$"
        return float(np.mean([-math.log((self.c[a + b] + 0.1) / (self.f[a] + 3.8)) for a, b in zip(w, w[1:])]))


def label_of(q):
    parts = str(q).rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def read_log(day_dir, name):
    p = os.path.join(day_dir, f"{name}.log")
    if not os.path.exists(p):
        return pd.DataFrame()
    rows = [json.loads(l) for l in open(p) if l.strip() and not l.startswith("#")]
    df = pd.DataFrame(rows)
    for c in ["path", "name", "action", "endpoint", "operation", "cipher", "request_type", "service", "username",
              "rcode_name", "query", "server_name", "cookie", "conn_state", "client"]:
        if c in df:
            df[c] = df[c].fillna("").astype(str)
    for c in ["duration", "orig_bytes", "resp_bytes"]:
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df


def load_day(day_dir):
    names = ["conn", "dns", "ssl", "kerberos", "ntlm", "smb_mapping", "smb_files", "dce_rpc", "rdp"]
    return {n: read_log(day_dir, n) for n in names}


@lru_cache(maxsize=100_000)
def _in(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def internal(ip):
    return isinstance(ip, str) and _in(ip, tuple(INTERNAL_NETS))


def workstation(ip):
    return isinstance(ip, str) and _in(ip, tuple(WORKSTATION_NETS))


def hour_of(ts):
    return (np.asarray(ts, dtype=float) % 86400) / 3600


def beacon_score(ts, ob, window=None):
    """RITA-style. Each part is 0..1 and robust to jitter:
       timing    1 - MAD/median of gaps  (20% jitter still scores ~0.9; human browsing ~0.1)
       skew      1 - Bowley skew of gaps (beacons have symmetric gaps)
       size      1 - MAD/median of bytes sent (same command poll every time)
       coverage  share of the observation window with traffic, in 24 equal slices
                 (malware doesn't go home at 6pm; on a 24h window a slice is one hour)"""
    ts = np.sort(np.asarray(ts, dtype=float))
    if len(ts) < 20:
        return 0.0, {}
    g = np.diff(ts)
    g = g[g > 0]
    med = np.median(g)
    timing = max(0.0, 1 - np.median(np.abs(g - med)) / med) if med > 0 else 0.0
    q1, q2, q3 = np.percentile(g, [25, 50, 75])
    skew = 1 - min(1.0, abs(q1 + q3 - 2 * q2) / (q3 - q1)) if q3 > q1 else 1.0
    ob = np.asarray(ob, dtype=float)
    mob = np.median(ob)
    size = max(0.0, 1 - np.median(np.abs(ob - mob)) / mob) if mob > 0 else 0.0
    t0, t1 = window if window else (ts[0] // 86400 * 86400, ts[0] // 86400 * 86400 + 86400)
    coverage = len(set(np.clip(((ts - t0) / max(t1 - t0, 1) * 24).astype(int), 0, 23))) / 24
    parts = {"timing": timing, "skew": skew, "size": size, "coverage": coverage, "interval_s": float(med)}
    return float(np.mean([timing, skew, size, coverage])), parts


class HuntEngine:
    def __init__(self):
        self.bigram = None
        self.known_domains, self.known_ja3 = set(), set()
        self.known_pairs = defaultdict(set)          # src -> {(dst, port)}
        self.known_hunts = Counter()                 # (src, hunt) -> days seen

    # ---- learn "normal" ----------------------------------------------------------------
    def fit(self, days):
        labels = list(COMMON)
        for logs in days:
            dns, ssl, conn = logs["dns"], logs["ssl"], logs["conn"]
            ok = dns[dns.rcode_name == "NOERROR"]
            self.known_domains |= set(ok["query"])
            labels += [label_of(q) for q in ok["query"].unique()]
            if "ja3" in ssl:
                self.known_ja3 |= set(ssl["ja3"].dropna())
            c = conn[conn["id.orig_h"].map(internal) & conn["id.resp_h"].map(internal) & (conn.conn_state == "SF")]
            for s, d, p in c[["id.orig_h", "id.resp_h", "id.resp_p"]].drop_duplicates().itertuples(index=False):
                self.known_pairs[s].add((d, p))
        self.bigram = Bigram(labels)
        for logs in days:  # which hunts fire every day on their own (SCCM, jump hosts, DC replication)
            _, findings, _ = self.run(logs, suppress=False)
            for key in {(f["src"], f["hunt"]) for f in findings}:
                self.known_hunts[key] += 1
        self.n_days = len(days)
        return self

    # ---- run all hunts on one day ------------------------------------------------------
    def run(self, logs, suppress=True):
        conn, dns, ssl = logs["conn"], logs["dns"], logs["ssl"]
        hosts = sorted(h for h in conn["id.orig_h"].unique() if internal(h))
        F = {h: defaultdict(float) for h in hosts}
        findings = []

        def hit(hunt, src, dst, uids, detail, count=1, ts=None, extra=0):
            name, tactic, attack, sev = HUNTS[hunt]
            findings.append({"hunt": hunt, "name": name, "tactic": tactic, "attack": attack,
                             "severity": min(100, sev + extra), "src": src, "dst": dst, "count": int(count),
                             "first_ts": float(np.min(ts)) if ts is not None and len(ts) else None,
                             "last_ts": float(np.max(ts)) if ts is not None and len(ts) else None,
                             "detail": detail, "evidence_uids": list(dict.fromkeys(uids))[:25]})

        east = conn[conn["id.orig_h"].map(internal) & conn["id.resp_h"].map(internal)]
        east = east[east["id.resp_h"] != east["id.orig_h"]]
        for h, g in east.groupby("id.orig_h"):
            adm = g[g["id.resp_p"].isin(ADMIN_PORTS)]
            F[h]["internal_fanout"] = adm["id.resp_h"].nunique()
            ok = adm[adm.conn_state == "SF"]
            new = {(d, p) for d, p in ok[["id.resp_h", "id.resp_p"]].itertuples(index=False)} - self.known_pairs[h]
            F[h]["new_internal_pairs"] = len(new)
            F[h]["failed_internal_ratio"] = float((adm.conn_state != "SF").mean()) if len(adm) else 0
            # LM-08 sweep: many internal targets on admin ports, mostly failing
            if F[h]["internal_fanout"] >= SWEEP_MIN_HOSTS and F[h]["failed_internal_ratio"] >= 0.5:
                hit("LM-08", h, f"{F[h]['internal_fanout']:.0f} hosts", adm.uid,
                    f"{len(adm)} connections to {F[h]['internal_fanout']:.0f} internal hosts on ports "
                    f"{sorted(adm['id.resp_p'].unique().tolist())}, {F[h]['failed_internal_ratio']:.0%} failed",
                    len(adm), adm[adm.conn_state != "SF"].ts)

        # LM-01 admin share + executable written + remote service
        smbm, smbf, rpc = logs["smb_mapping"], logs["smb_files"], logs["dce_rpc"]
        adm_share = smbm[smbm.path.str.upper().str.endswith(("\\ADMIN$", "\\C$"))] if len(smbm) else smbm
        writes = smbf[(smbf.action == "SMB::FILE_WRITE") & smbf.path.str.upper().str.endswith(("\\ADMIN$", "\\C$"))
                      & smbf.name.str.lower().str.endswith(EXEC_EXT)] if len(smbf) else smbf
        svc = rpc[(rpc.endpoint == "svcctl")] if len(rpc) else rpc  # OpenSCManager/Create/Start: remote service control
        for (s, d), g in adm_share.groupby(["id.orig_h", "id.resp_h"]):
            F[s]["admin_share_maps"] += 1
            w = writes[(writes["id.orig_h"] == s) & (writes["id.resp_h"] == d)]
            v = svc[(svc["id.orig_h"] == s) & (svc["id.resp_h"] == d)]
            F[s]["exec_written_to_share"] += int(len(w) > 0)
            F[s]["remote_service_created"] += int(len(v) > 0)
            if len(v):  # admin share + service control to the same host (PsExec / smbexec / deployment tools)
                drop = f"dropped {w.name.iloc[0]}, " if len(w) else ""
                hit("LM-01", s, d, list(g.uid) + list(w.uid) + list(v.uid),
                    f"mapped {g.path.iloc[0]}, {drop}svcctl ({', '.join(sorted(v.operation.unique()))}) "
                    "- remote service control over the admin share (PsExec pattern)",
                    len(g) + len(w) + len(v), pd.concat([g.ts, w.ts, v.ts]))
        if len(rpc):
            # LM-02 WMI / DCOM
            wmi = rpc[rpc.endpoint.isin(WMI_ENDPOINTS)]
            for (s, d), g in wmi.groupby(["id.orig_h", "id.resp_h"]):
                F[s]["remote_wmi"] += 1
                hit("LM-02", s, d, g.uid, f"DCE-RPC {', '.join(sorted(set(g.endpoint + '::' + g.operation)))}", len(g), g.ts)
            # LM-03 scheduled task
            task = rpc[rpc.endpoint.isin(TASK_ENDPOINTS) & rpc.operation.str.contains("Register|JobAdd|Create")]
            for (s, d), g in task.groupby(["id.orig_h", "id.resp_h"]):
                F[s]["remote_task"] += 1
                hit("LM-03", s, d, g.uid, f"{g.endpoint.iloc[0]}::{', '.join(g.operation.unique())}", len(g), g.ts)
            # LM-07 DCSync: AD replication from a host that is not a domain controller.
            # Only DCs replicate the directory. The signature is DRSGetNCChanges; the DRSBind +
            # DRSCrackNames that lead up to it are logged too, so an attempt is caught even if the
            # final pull is refused (e.g. Mimikatz run as a non-privileged user, or blocked at the DC).
            REPL_OPS = {"DRSGetNCChanges", "DRSCrackNames", "DRSBind"}
            drs = rpc[(rpc.endpoint == "drsuapi") & rpc.operation.isin(REPL_OPS) & ~rpc["id.orig_h"].isin(DCS)]
            for (s, d), g in drs.groupby(["id.orig_h", "id.resp_h"]):
                ops = g.operation.value_counts().to_dict()
                pull = int(ops.get("DRSGetNCChanges", 0))
                F[s]["dcsync_calls"] += pull or len(g)
                verb = (f"{pull} x drsuapi::DRSGetNCChanges" if pull else
                        f"drsuapi replication calls ({', '.join(sorted(ops))})")
                hit("LM-07", s, d, g.uid, f"{verb} from a host that is not a domain controller "
                    "(only domain controllers replicate the directory: DCSync)", len(g), g.ts)

        # LM-04 RDP
        rdp = logs["rdp"]
        ws = workstation
        for s, g in (rdp.groupby("id.orig_h") if len(rdp) else []):
            hrs = hour_of(g.ts)
            off = (hrs < WORK_HOURS[0]) | (hrs >= WORK_HOURS[1])
            wk2wk = g["id.resp_h"].map(ws) & ws(s)
            newp = ~g.apply(lambda r: (r["id.resp_h"], 3389) in self.known_pairs[s], axis=1)
            F[s]["rdp_dst"] = g["id.resp_h"].nunique()
            F[s]["rdp_offhours"] = int(off.sum())
            F[s]["rdp_wk2wk"] = int(wk2wk.sum())
            for (_, r), o, w, n in zip(g.iterrows(), off, wk2wk, newp):
                reasons = [x for x, on in [("off hours", o), ("workstation to workstation", w), ("new pair", n)] if on]
                if len(reasons) >= 2:
                    hit("LM-04", s, r["id.resp_h"], [r.uid], f"RDP as '{r.cookie}' ({', '.join(reasons)}), "
                        f"{int(hour_of([r.ts])[0]):02d}:{int(hour_of([r.ts])[0] % 1 * 60):02d} UTC",
                        1, [r.ts], extra=10 * (len(reasons) - 2))

        # LM-05 NTLM fan-out
        ntlm = logs["ntlm"]
        for (s, u), g in (ntlm.groupby(["id.orig_h", "username"]) if len(ntlm) else []):
            F[s]["ntlm_dst"] = max(F[s]["ntlm_dst"], g["id.resp_h"].nunique())
            if g["id.resp_h"].nunique() >= 5 and g.ts.max() - g.ts.min() <= 3600:
                hit("LM-05", s, f"{g['id.resp_h'].nunique()} hosts", g.uid,
                    f"NTLM logons as '{u}' to {g['id.resp_h'].nunique()} hosts in "
                    f"{(g.ts.max() - g.ts.min()) / 60:.0f} min (this host normally uses Kerberos)", len(g), g.ts)
                findings[-1]["targets"] = sorted(g["id.resp_h"].unique())

        # LM-06 Kerberoasting
        krb = logs["kerberos"]
        if len(krb):
            tgs = krb[krb.request_type == "TGS"]
            for s, g in tgs.groupby("id.orig_h"):
                rc4 = g[g.cipher.str.contains("rc4")]
                F[s]["tgs_services"] = g.service.nunique()
                F[s]["rc4_tgs_services"] = rc4.service.nunique()
                if rc4.service.nunique() >= 5 and rc4.ts.max() - rc4.ts.min() <= 3600:
                    hit("LM-06", s, "DC (KDC)", rc4.uid, f"{rc4.service.nunique()} RC4 service tickets in "
                        f"{(rc4.ts.max() - rc4.ts.min()) / 60:.1f} min, e.g. {', '.join(rc4.service.unique()[:3])}",
                        len(rc4), rc4.ts)

        # ---- C2 ------------------------------------------------------------------------
        ext = conn[conn["id.orig_h"].map(internal) & ~conn["id.resp_h"].map(internal)]
        ext = ext[ext["id.resp_p"] != 53]
        span = (float(conn.ts.min()), float(conn.ts.max()))
        window = span if span[1] - span[0] < 20 * 3600 else None  # lab sessions are minutes long
        sni = dict(zip(ssl.uid, ssl.server_name)) if len(ssl) else {}
        ja3 = dict(zip(ssl.uid, ssl.ja3)) if len(ssl) and "ja3" in ssl else {}
        # group by the destination SERVICE (TLS server name if known, else IP). Many sites behind one
        # IP (CDN, or a lab where every site shares an address) must not merge into one fake beacon.
        ext = ext.assign(dest=[sni.get(u) or d for u, d in zip(ext.uid, ext["id.resp_h"])])
        for (s, dom), g in ext.groupby(["id.orig_h", "dest"]):
            d = g["id.resp_h"].iloc[0]
            score, parts = beacon_score(g.ts, g.orig_bytes, window)
            if score > F[s]["max_beacon_score"]:
                F[s]["max_beacon_score"] = score
            if score >= 0.8:
                hit("C2-01", s, dom, g.uid, f"{len(g)} connections to {dom} ({d}) every ~{parts['interval_s']:.0f}s, "
                    f"timing {parts['timing']:.2f}, payload size {parts['size']:.2f}, active {parts['coverage']:.0%} of the day "
                    f"(beacon score {score:.2f})", len(g), g.ts, extra=int((score - 0.8) * 100))
            long = g[g.duration >= LONG_CONN_SECONDS]
            F[s]["max_ext_duration_h"] = max(F[s]["max_ext_duration_h"], g.duration.max() / 3600)
            if len(long):
                r = long.iloc[0]
                hit("C2-02", s, dom, long.uid, f"{r.duration / 3600:.1f}h connection to {dom}:{r['id.resp_p']}, "
                    f"only {r.orig_bytes / 1e6:.1f} MB out / {r.resp_bytes / 1e6:.1f} MB in (interactive, not a download)",
                    len(long), long.ts)
            new_ja3 = {ja3[u] for u in g.uid if u in ja3} - self.known_ja3
            if dom not in self.known_domains and dom != d and (new_ja3 or not ja3):
                F[s]["new_domain_new_ja3"] += 1
                why = (f"with JA3 {next(iter(new_ja3))} that no host used during the baseline" if new_ja3
                       else "(no JA3 in this sensor's ssl.log, so domain novelty only)")
                hit("C2-04", s, dom, g.uid, f"first time anyone here reached {dom}, {why}", len(g), g.ts)
        if len(dns):
            dns = dns[~dns["id.orig_h"].isin(RESOLVERS)]   # forwarders mirror clients; skip them
            # DGA = one host asking for many random-looking names. Keyed on the NAMES (robust to how
            # the resolver reports the failure), restricted to names that did not resolve (NXDOMAIN,
            # or an empty answer), which is what a DGA's dead rendezvous domains look like.
            failed = dns[(dns.rcode_name == "NXDOMAIN") | (dns["answers"].map(lambda a: not a if isinstance(a, list) else True))]
            for s, g in failed.groupby("id.orig_h"):
                rand_names = sorted({q for q in g["query"].unique() if self.bigram.score(label_of(q)) >= DGA_RANDOMNESS})
                nx = g[g.rcode_name == "NXDOMAIN"]
                F[s]["nxdomain_names"] = nx["query"].nunique()
                F[s]["nx_randomness"] = float(np.mean([self.bigram.score(label_of(q)) for q in nx["query"].unique()])) if len(nx) else 0.0
                if len(rand_names) >= 30:
                    uids = g[g["query"].isin(rand_names)].uid
                    hit("C2-03", s, f"{len(rand_names)} domains", uids, f"{len(rand_names)} distinct random-looking names "
                        f"that did not resolve, e.g. {', '.join(rand_names[:3])} (domain generation algorithm)", len(uids), g.ts)
            for s in hosts:
                F[s]["new_domains"] = 0
            ok = dns[dns.rcode_name == "NOERROR"]
            for s, g in ok.groupby("id.orig_h"):
                if s in F:
                    F[s]["new_domains"] = len(set(g["query"]) - self.known_domains)

        # suppress hunts this source does on most baseline days (SCCM, jump host, ...)
        if suppress:
            for f in findings:
                days = self.known_hunts[(f["src"], f["hunt"])]
                f["suppressed"] = self.n_days > 0 and days >= max(1, math.ceil(KNOWN_SHARE * self.n_days))
                f["suppressed_reason"] = f"{f['src']} did this on {days} of the baseline days (known admin behaviour)" if f["suppressed"] else ""
        feats = pd.DataFrame([{**{k: 0.0 for k in FEATURES}, **F[h], "host": h} for h in hosts])
        edges = []
        for f in findings:
            if not f.get("suppressed"):
                edges += [(f["src"], d, f["hunt"]) for d in f.get("targets", [f["dst"]]) if internal(d)]
        return feats[["host"] + FEATURES], findings, edges


FEATURES = ["internal_fanout", "new_internal_pairs", "failed_internal_ratio", "admin_share_maps",
            "exec_written_to_share", "remote_service_created", "remote_wmi", "remote_task", "dcsync_calls",
            "rdp_dst", "rdp_offhours", "rdp_wk2wk", "ntlm_dst", "tgs_services", "rc4_tgs_services",
            "max_beacon_score", "max_ext_duration_h", "new_domain_new_ja3", "nxdomain_names", "nx_randomness",
            "new_domains"]

FEATURE_TEXT = {
    "internal_fanout": "internal hosts contacted on admin ports", "new_internal_pairs": "new internal host/port pairs",
    "failed_internal_ratio": "share of failed internal connections", "admin_share_maps": "ADMIN$/C$ shares mapped",
    "exec_written_to_share": "executables written to admin shares", "remote_service_created": "remote services created",
    "remote_wmi": "hosts hit with remote WMI", "remote_task": "remote scheduled tasks", "dcsync_calls": "DCSync calls",
    "rdp_dst": "RDP destinations", "rdp_offhours": "off-hours RDP sessions", "rdp_wk2wk": "workstation-to-workstation RDP",
    "ntlm_dst": "NTLM destinations (one account)", "tgs_services": "distinct service tickets",
    "rc4_tgs_services": "RC4 service tickets", "max_beacon_score": "beacon score", "max_ext_duration_h": "longest external connection (h)",
    "new_domain_new_ja3": "new domains with unseen JA3", "nxdomain_names": "failed DNS names", "nx_randomness": "randomness of failed names",
    "new_domains": "domains never seen before",
}
LM_FEATURES = FEATURES[:15]
