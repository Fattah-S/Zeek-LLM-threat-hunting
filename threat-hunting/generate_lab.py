"""Synthetic Zeek logs for a small Windows domain, for hunting lateral movement and C2.

Writes JSON-lines Zeek logs with real Zeek field names:
  conn.log dns.log ssl.log kerberos.log ntlm.log smb_mapping.log smb_files.log dce_rpc.log rdp.log

  data/baseline/day1..dayN   clean days (what "normal" looks like)
  data/hunt/                 normal traffic + one intrusion (the day we hunt in)
  data/ground_truth.csv      which host did which technique (only evaluate.py reads it)

The network (GUESS: invented, swap in your own Zeek logs):
  DC01 10.10.0.10, DC02 10.10.0.11 (domain controllers, replicate with each other)
  FS01 10.10.0.20 file server, SQL01 10.10.0.30, WEB01 10.10.0.40
  JUMP01 10.10.0.50 admin jump host (RDPs to servers every day: legit)
  SCCM01 10.10.0.60 software deployment (ADMIN$ + remote services on workstations every day: legit,
                     looks exactly like PsExec. It is the classic false positive.)
  WS-01..WS-40 10.10.1.11-50 workstations, WS-ADM 10.10.1.5 the IT admin's workstation

The intrusion on the hunt day (variant 0):
  C2       WS-17  HTTPS beacon to cdn-update-check.online every ~300s with 20% jitter, 24h
  C2       WS-17  one 7h low-volume connection to 91.215.85.17:443 (interactive tunnel)
  C2       WS-33  DGA: ~200 random .info names, almost all NXDOMAIN (a second, separate infection)
  LM       WS-17  SMB/RPC sweep of 10.10.1.0/24 (recon)
  LM       WS-17  Kerberoasting: RC4 TGS tickets for 18 service accounts in 2 minutes
  LM       WS-17  -> WS-22, SQL01  PsExec style: ADMIN$ + write PSEXESVC.exe + svcctl CreateServiceW
  LM       WS-17  -> WS-08  WMI exec (IRemoteSCMActivator + IWbemServices ExecMethod)
  LM       WS-17  -> DC01   DCSync (drsuapi DRSGetNCChanges from a workstation)
  LM       WS-22  -> FS01, WS-30  RDP at 02:00-03:00, workstation to workstation
  LM       WS-22  pass-the-hash: NTLM as adm_it to 9 hosts in 6 minutes
  LM       WS-22  -> WEB01 remote scheduled task (ITaskSchedulerService SchRpcRegisterTask)
"""
import argparse
import csv
import json
import os
import random
import uuid

import numpy as np

SERVERS = {"DC01": "10.10.0.10", "DC02": "10.10.0.11", "FS01": "10.10.0.20", "SQL01": "10.10.0.30",
           "WEB01": "10.10.0.40", "JUMP01": "10.10.0.50", "SCCM01": "10.10.0.60"}
WS = {f"WS-{i:02d}": f"10.10.1.{10 + i}" for i in range(1, 41)}
WS["WS-ADM"] = "10.10.1.5"
HOSTS = {**SERVERS, **WS}
DNS_SERVER = SERVERS["DC01"]
DOMAIN = "CORP"
SPNS = ["cifs/FS01", "ldap/DC01", "host/DC01", "cifs/DC01", "HTTP/WEB01", "MSSQLSvc/SQL01:1433"]
ROAST_SPNS = [f"MSSQLSvc/sql{i:02d}.corp.local:1433" for i in range(1, 7)] + \
             [f"HTTP/app{i:02d}.corp.local" for i in range(1, 7)] + \
             [f"svc_{n}/srv.corp.local" for n in ["backup", "report", "sharepoint", "scan", "crm", "bi"]]
WEB = {"www.google.com": "142.250.74.36", "outlook.office365.com": "52.97.146.162",
       "teams.microsoft.com": "52.113.194.132", "github.com": "140.82.121.4",
       "www.linkedin.com": "13.107.42.14", "update.microsoft.com": "13.107.4.50",
       "cdn.jsdelivr.net": "151.101.1.229", "api.zoom.us": "170.114.52.2",
       "login.microsoftonline.com": "20.190.160.1", "s3.amazonaws.com": "52.217.33.86"}
LONG_TAIL = {f"site{i}.example{i % 7}.com": f"203.0.{i // 250}.{i % 250 + 1}" for i in range(300)}
BROWSER_JA3 = ["773906b0efdefa24a7f2b8eb6985bf37", "cd08e31494f9531f560d64c695473da9",
               "b32309a26951912be7dba376398abc3b"]


class Gen:
    def __init__(self, seed):
        self.rng = np.random.default_rng(seed)
        self.r = random.Random(seed)
        self.logs = {k: [] for k in ["conn", "dns", "ssl", "kerberos", "ntlm", "smb_mapping",
                                     "smb_files", "dce_rpc", "rdp"]}
        self.truth = []

    def uid(self):
        return "C" + uuid.UUID(int=self.r.getrandbits(128)).hex[:17]

    def ids(self, src, dst, dport):
        return {"id.orig_h": src, "id.orig_p": int(self.rng.integers(49152, 65535)),
                "id.resp_h": dst, "id.resp_p": dport}

    def conn(self, ts, src, dst, dport, service=None, proto="tcp", duration=0.5, ob=500, rb=1500,
             state="SF", label=None):
        u = self.uid()
        row = {"ts": round(ts, 6), "uid": u, **self.ids(src, dst, dport), "proto": proto,
               "service": service, "duration": round(float(duration), 6), "orig_bytes": int(ob),
               "resp_bytes": int(rb), "conn_state": state,
               "local_orig": src.startswith("10."), "local_resp": dst.startswith("10."),
               "orig_pkts": max(1, int(ob / 900) + 1), "resp_pkts": max(0, int(rb / 1200) + 1) if state == "SF" else 0}
        self.logs["conn"].append(row)
        if label:
            self.truth.append((src, label[0], label[1]))
        return row

    def ev(self, log, c, **fields):
        self.logs[log].append({"ts": c["ts"], "uid": c["uid"], **{k: c[k] for k in
                               ["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]}, **fields})

    # ---- building blocks -------------------------------------------------------------
    def web(self, ts, src, dom=None, ip=None, ja3=None, ob=None, rb=None, dur=None, label=None):
        if dom is None:
            dom, ip = self.r.choice(list(WEB.items())) if self.r.random() < 0.7 else self.r.choice(list(LONG_TAIL.items()))
        d = self.conn(ts - 0.05, src, DNS_SERVER, 53, "dns", "udp", 0.02, 40, 90, label=label)
        self.ev("dns", d, proto="udp", query=dom, qtype_name="A", rcode_name="NOERROR",
                answers=[ip], TTLs=[300.0])
        c = self.conn(ts, src, ip, 443, "ssl", duration=dur if dur is not None else self.rng.lognormal(1, 1.2),
                      ob=ob if ob is not None else self.rng.lognormal(7.5, 1), rb=rb if rb is not None else self.rng.lognormal(10, 1.5),
                      label=label)
        self.ev("ssl", c, version="TLSv13", server_name=dom, established=True,
                ja3=ja3 or self.r.choice(BROWSER_JA3))

    def kerberos(self, ts, src, user, service, cipher="aes256-cts-hmac-sha1-96", req="TGS", label=None):
        c = self.conn(ts, src, SERVERS["DC01"], 88, "krb", duration=0.01, ob=1400, rb=1500, label=label)
        self.ev("kerberos", c, request_type=req, client=f"{user}/{DOMAIN}", service=service,
                success=True, cipher=cipher, forwardable=True, renewable=True)

    def smb_map(self, ts, src, dst, share, label=None, write=None):
        c = self.conn(ts, src, dst, 445, "smb", duration=self.rng.lognormal(1, 0.8),
                      ob=self.rng.lognormal(8, 1), rb=self.rng.lognormal(9, 1.5), label=label)
        name = next(k for k, v in HOSTS.items() if v == dst)
        self.ev("smb_mapping", c, path=f"\\\\{name}\\{share}", service="-", share_type="DISK" if share != "IPC$" else "PIPE")
        if write:
            self.ev("smb_files", c, action="SMB::FILE_WRITE", path=f"\\\\{name}\\{share}", name=write,
                    size=int(self.rng.integers(300_000, 400_000)))
        else:
            self.ev("smb_files", c, action="SMB::FILE_OPEN", path=f"\\\\{name}\\{share}",
                    name=self.r.choice(["Q3-report.xlsx", "budget.docx", "notes.txt", "deck.pptx"]),
                    size=int(self.rng.lognormal(11, 1.5)))
        return c

    def rpc(self, ts, src, dst, endpoint, ops, pipe=None, label=None, port=135):
        c = self.conn(ts, src, dst, port, "dce_rpc", duration=0.3, ob=1800, rb=1200, label=label)
        for i, op in enumerate(ops):
            self.ev("dce_rpc", {**c, "ts": ts + i * 0.05}, rtt=0.001, named_pipe=pipe or str(port),
                    endpoint=endpoint, operation=op)

    def rdp(self, ts, src, dst, user, dur, label=None):
        c = self.conn(ts, src, dst, 3389, "rdp", duration=dur, ob=self.rng.lognormal(12, 0.5),
                      rb=self.rng.lognormal(14, 0.5), label=label)
        self.ev("rdp", c, cookie=user, result="Success", security_protocol="HYBRID",
                client_name=next(k for k, v in HOSTS.items() if v == src))

    def ntlm(self, ts, src, dst, user, label=None):
        c = self.conn(ts, src, dst, 445, "smb,ntlm", duration=0.4, ob=2500, rb=1800, label=label)
        self.ev("ntlm", c, username=user, domainname=DOMAIN,
                hostname=next(k for k, v in HOSTS.items() if v == src),
                server_nb_computer_name=next(k for k, v in HOSTS.items() if v == dst), success=True)

    # ---- one normal day --------------------------------------------------------------
    def normal_day(self, d0):
        rng, r = self.rng, self.r
        hour = lambda: d0 + float(np.clip(rng.normal(13, 2.5), 7, 20)) * 3600
        for name, ip in WS.items():
            user = "it_admin" if name == "WS-ADM" else f"user{name[-2:]}"
            self.kerberos(d0 + 8 * 3600 + rng.uniform(0, 3600), ip, user, "krbtgt/CORP", req="AS")
            for _ in range(int(rng.integers(150, 300))):
                self.web(hour(), ip)
            for _ in range(int(rng.integers(10, 40))):
                self.smb_map(hour(), ip, SERVERS["FS01"], r.choice(["Shares", "Finance", "HR", "IT"]))
            for _ in range(int(rng.integers(8, 20))):
                self.kerberos(hour(), ip, user, r.choice(SPNS))
            for _ in range(int(rng.integers(3, 8))):
                self.rpc(hour(), ip, SERVERS["DC01"], r.choice(["lsarpc", "netlogon", "samr"]),
                         [r.choice(["LsarLookupNames3", "NetrLogonGetDomainInfo", "SamrConnect5"])], pipe="\\pipe\\lsass", port=445)
            for _ in range(int(rng.poisson(3))):  # normal failed lookups: WPAD, typos, dead names
                c = self.conn(hour(), ip, DNS_SERVER, 53, "dns", "udp", 0.02, 40, 100)
                self.ev("dns", c, proto="udp", query=r.choice(["wpad.corp.local", "gooogle.com", "printer-3f.corp.local",
                        "outlok.office365.com", "isatap.corp.local", "githb.com", "fileserver.corp.local"]),
                        qtype_name="A", rcode_name="NXDOMAIN", answers=[], TTLs=[])
            if rng.random() < 0.2:  # some apps still do NTLM to the file server
                self.ntlm(hour(), ip, SERVERS["FS01"], user)
            if rng.random() < 0.01:  # normal noise: someone helps a colleague over RDP once in a while
                other = r.choice([v for k, v in WS.items() if v != ip])
                self.rdp(hour(), ip, other, user, rng.uniform(300, 1500))
        # IT admin + jump host RDP to servers, daily
        for s in ["FS01", "SQL01", "WEB01", "DC01"]:
            self.rdp(hour(), WS["WS-ADM"], SERVERS[s], "it_admin", rng.uniform(600, 3000))
            self.rdp(hour(), SERVERS["JUMP01"], SERVERS[s], "it_admin", rng.uniform(600, 3000))
        # SCCM: deploys to ~15 workstations a day with ADMIN$ + a remote service (legit PsExec look-alike)
        for name in r.sample([k for k in WS if k != "WS-ADM"], 15):
            t = d0 + rng.uniform(1, 5) * 3600
            self.smb_map(t, SERVERS["SCCM01"], WS[name], "ADMIN$", write="ccmsetup.exe")
            self.rpc(t + 2, SERVERS["SCCM01"], WS[name], "svcctl",
                     ["OpenSCManagerW", "CreateServiceW", "StartServiceW"], pipe="\\pipe\\svcctl", port=445)
        # domain controllers replicate (DCSync traffic that is normal)
        for _ in range(48):
            t = d0 + rng.uniform(0, 86400)
            self.rpc(t, SERVERS["DC02"], SERVERS["DC01"], "drsuapi", ["DRSBind", "DRSGetNCChanges"])
        # servers do some web (updates)
        for s in ["FS01", "SQL01", "WEB01", "SCCM01"]:
            for _ in range(20):
                self.web(d0 + rng.uniform(0, 86400), SERVERS[s], "update.microsoft.com", WEB["update.microsoft.com"])

    # ---- the intrusion ---------------------------------------------------------------
    def intrusion(self, d0, variant=0):
        rng, r = self.rng, self.r
        if variant == 0:
            p0, p1, dga_h = "WS-17", "WS-22", "WS-33"
            wmi_t, rdp_t = "WS-08", "WS-30"
            c2_dom, c2_ip, tun_ip, period = "cdn-update-check.online", "45.155.205.99", "91.215.85.17", 300
            dga_tld = ".info"
        else:
            pool = [k for k in WS if k != "WS-ADM"]
            p0, p1, dga_h, wmi_t, rdp_t = r.sample(pool, 5)
            c2_dom, c2_ip, tun_ip, period = "telemetry-sync.site", "185.174.101.12", "193.233.48.9", 900
            dga_tld = ".xyz"
        P0, P1 = WS[p0], WS[p1]
        ja3_bad = "72a589da586844d7f0818ce684948eea"  # e.g. a Cobalt Strike / Sliver default stack

        # C2-01 beacon, jittered 20%, all day, small consistent payloads
        t = d0 + rng.uniform(0, 600)
        while t < d0 + 86400:
            self.web(t, P0, c2_dom, c2_ip, ja3=ja3_bad, ob=rng.normal(620, 20), rb=rng.normal(310, 15),
                     dur=rng.normal(0.4, 0.05), label=("C2", "beacon"))
            t += period * rng.uniform(0.8, 1.2)
        # C2-02 long low-volume tunnel
        self.conn(d0 + 9.2 * 3600, P0, tun_ip, 443, "ssl", duration=7 * 3600, ob=2.4e6, rb=1.1e6,
                  label=("C2", "long_connection"))
        # C2-03 DGA on a different host
        t = d0 + 4 * 3600
        for i in range(200):
            name = "".join(r.choices("abcdefghijklmnopqrstuvwxyz", k=int(rng.integers(12, 17)))) + dga_tld
            hit = i == 199
            c = self.conn(t, WS[dga_h], DNS_SERVER, 53, "dns", "udp", 0.03, 45, 100, label=("C2", "dga"))
            self.ev("dns", c, proto="udp", query=name, qtype_name="A",
                    rcode_name="NOERROR" if hit else "NXDOMAIN", answers=["194.87.31.8"] if hit else [], TTLs=[60.0] if hit else [])
            t += rng.uniform(1, 30)

        # LM-08 recon sweep: 445/135/3389 to the whole workstation subnet
        t = d0 + 10 * 3600
        for i in range(1, 255):
            for port in (445, 135, 3389):
                live = f"10.10.1.{i}" in WS.values()
                self.conn(t, P0, f"10.10.1.{i}", port, None, duration=0.001 if live else 0,
                          ob=0, rb=0, state="REJ" if live and port == 3389 else ("S0" if not live else "SF"),
                          label=("LM", "recon_sweep"))
                t += 0.02
        # LM-06 kerberoasting
        t = d0 + 10.3 * 3600
        for spn in ROAST_SPNS:
            self.kerberos(t, P0, f"user{p0[-2:]}", spn, cipher="rc4-hmac", label=("LM", "kerberoasting"))
            t += rng.uniform(2, 8)
        # LM-01 PsExec to P1 and SQL01
        for i, dst in enumerate([P1, SERVERS["SQL01"]]):
            t = d0 + (11 + i * 0.5) * 3600
            self.smb_map(t, P0, dst, "ADMIN$", write="PSEXESVC.exe", label=("LM", "psexec"))
            self.rpc(t + 1.5, P0, dst, "svcctl", ["OpenSCManagerW", "CreateServiceW", "StartServiceW"],
                     pipe="\\pipe\\svcctl", port=445, label=("LM", "psexec"))
        # LM-02 WMI
        t = d0 + 12.4 * 3600
        self.rpc(t, P0, WS[wmi_t], "IRemoteSCMActivator", ["RemoteCreateInstance"], label=("LM", "wmi"))
        self.rpc(t + 1, P0, WS[wmi_t], "IWbemServices", ["NTLMLogin", "ExecMethod"], port=49667, label=("LM", "wmi"))
        # LM-07 DCSync from a workstation
        self.rpc(d0 + 13 * 3600, P0, SERVERS["DC01"], "drsuapi", ["DRSBind", "DRSGetNCChanges", "DRSGetNCChanges"],
                 label=("LM", "dcsync"))
        # LM-04 RDP from P1 at night
        for i, dst in enumerate([SERVERS["FS01"], WS[rdp_t]]):
            self.rdp(d0 + (2 + i * 0.6) * 3600, P1, dst, "svc_backup", rng.uniform(900, 2000), label=("LM", "rdp_pivot"))
        # LM-05 pass-the-hash: NTLM fan-out with an admin account
        t = d0 + 14 * 3600
        targets = r.sample([v for k, v in WS.items() if v not in (P0, P1)], 7) + [SERVERS["SQL01"], SERVERS["WEB01"]]
        for dst in targets:
            self.ntlm(t, P1, dst, "adm_it", label=("LM", "pass_the_hash"))
            t += rng.uniform(20, 50)
        # LM-03 remote scheduled task
        self.rpc(d0 + 14.5 * 3600, P1, SERVERS["WEB01"], "ITaskSchedulerService",
                 ["SchRpcRegisterTask", "SchRpcRun"], pipe="\\pipe\\atsvc", port=445, label=("LM", "sched_task"))


def write(day_dir, logs):
    os.makedirs(day_dir, exist_ok=True)
    for name, rows in logs.items():
        with open(os.path.join(day_dir, f"{name}.log"), "w") as f:
            for row in sorted(rows, key=lambda x: x["ts"]):
                f.write(json.dumps(row) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--baseline-days", type=int, default=5)
    ap.add_argument("--variant", type=int, default=0, help="0 = scenario in the docstring, 1 = other hosts/domains")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    t0 = 1_767_225_600  # 2026-01-01 00:00 UTC
    for d in range(a.baseline_days):
        g = Gen(a.seed + d)
        g.normal_day(t0 + d * 86400)
        write(os.path.join(a.out, "baseline", f"day{d + 1}"), g.logs)
    g = Gen(a.seed + 100 + a.variant)
    day = t0 + a.baseline_days * 86400
    g.normal_day(day)
    g.intrusion(day, a.variant)
    hunt_dir = os.path.join(a.out, "hunt" if a.variant == 0 else f"hunt_v{a.variant}")
    write(hunt_dir, g.logs)
    ip2name = {v: k for k, v in HOSTS.items()}
    with open(os.path.join(hunt_dir, "ground_truth.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "tactic", "technique"])
        for row in sorted(set((ip2name[s], t, q) for s, t, q in g.truth)):
            w.writerow(row)
    print(f"wrote {a.baseline_days} baseline days + {hunt_dir}")


if __name__ == "__main__":
    main()
