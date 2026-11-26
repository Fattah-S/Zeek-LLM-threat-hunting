"""Generate synthetic Zeek conn.log + dns.log (JSON lines, real Zeek field names).

Days 1..N (default 5) = clean baseline (used to train the model).
Next day = normal traffic + injected attacks (the data we score).

Injected scenarios on the scored day (ground truth written to ground_truth.csv, never
read by the model, only by evaluate.py):
  exfil      10.0.0.23 -> 185.220.101.7:443   long connection, ~600 MB out, new domain
  beacon     10.0.0.31 -> 45.155.205.99:443   every ~60s +/- 2s, tiny payloads, new domain
  portscan   10.0.0.45 -> 10.0.0.0/24         hundreds of ports, REJ / S0
  rare_port  10.0.0.12 -> 91.92.240.15:4444    interactive session on a rare port
  dns_tunnel 10.0.0.52 -> 10.0.0.2:53          very many DNS queries to one odd domain
  dga        10.0.0.36 -> ~150 random .com names, almost all NXDOMAIN
  lookalike  10.0.0.19 -> rnicrosoft.com         cousin domain of microsoft.com (phishing)
  gameover_zeus 10.0.0.47 -> ~1000 20-30 char alphanumeric names, .com/.net/.org/.biz, NXDOMAIN

GUESS: traffic mix (ports, byte sizes, hosts) is invented to look like a small
office. Replace with your own Zeek logs as soon as you have them.
"""
import argparse
import csv
import json
import os
import random
import uuid

import numpy as np

RNG = np.random.default_rng(7)
random.seed(7)

INTERNAL = [f"10.0.0.{i}" for i in range(10, 60)]
DNS_SERVER = "10.0.0.2"
FILE_SERVER = "10.0.0.5"

# popular destinations: domain -> ip
POPULAR = {
    "www.google.com": "142.250.74.36",
    "outlook.office365.com": "52.97.146.162",
    "teams.microsoft.com": "52.113.194.132",
    "github.com": "140.82.121.4",
    "slack.com": "34.226.36.10",
    "www.linkedin.com": "13.107.42.14",
    "s3.amazonaws.com": "52.217.33.86",
    "update.microsoft.com": "13.107.4.50",
    "cdn.jsdelivr.net": "151.101.1.229",
    "api.zoom.us": "170.114.52.2",
}
NEW_WORDS = ["green", "recipe", "travel", "daily", "smart", "home", "garden", "tech", "news",
             "best", "local", "pet", "photo", "learn", "code", "city", "food", "health", "game",
             "music", "book", "car", "shop", "deal", "event", "sport", "kids", "craft", "film"]
LONG_TAIL = {f"site{i}.example{ i % 7 }.com": f"203.0.{i // 250}.{i % 250 + 1}" for i in range(400)}


def uid():
    return "C" + uuid.UUID(int=random.getrandbits(128)).hex[:17]


def conn(ts, src, dst, dport, proto="tcp", service=None, duration=0.0,
         ob=0, rb=0, state="SF", sport=None):
    return {
        "ts": round(ts, 6), "uid": uid(),
        "id.orig_h": src, "id.orig_p": sport or int(RNG.integers(49152, 65535)),
        "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "service": service,
        "duration": round(duration, 6), "orig_bytes": int(ob), "resp_bytes": int(rb),
        "conn_state": state, "local_orig": src.startswith("10."),
        "local_resp": dst.startswith("10."), "missed_bytes": 0,
        "orig_pkts": max(1, int(ob / 900) + 1) if state == "SF" else 1,
        "resp_pkts": max(0, int(rb / 1200) + 1) if state == "SF" else 0,
    }


def dns(ts, src, query, answers, qtype="A", conn_uid=None, rcode="NOERROR"):
    return {
        "ts": round(ts, 6), "uid": conn_uid or uid(), "id.orig_h": src,
        "id.orig_p": int(RNG.integers(49152, 65535)), "id.resp_h": DNS_SERVER,
        "id.resp_p": 53, "proto": "udp", "query": query, "qtype_name": qtype,
        "rcode_name": rcode, "answers": answers, "TTLs": [300.0] * len(answers),
    }


def normal_day(day_start):
    conns, dnss = [], []
    for host in INTERNAL:
        n = int(RNG.integers(250, 600))
        # office hours heavy, some night noise
        hours = np.concatenate([RNG.normal(13, 3, int(n * 0.9)), RNG.uniform(0, 24, n - int(n * 0.9))])
        for h in np.clip(hours, 0, 23.999):
            ts = day_start + h * 3600 + RNG.uniform(0, 60)
            r = RNG.random()
            if r < 0.55:  # https to popular
                dom = random.choice(list(POPULAR))
                ip = POPULAR[dom]
                dc = conn(ts - 0.05, host, DNS_SERVER, 53, "udp", "dns", 0.02, 40, 90)
                conns.append(dc)
                dnss.append(dns(ts - 0.05, host, dom, [ip], conn_uid=dc["uid"]))
                conns.append(conn(ts, host, ip, 443, service="ssl",
                                  duration=RNG.lognormal(1.0, 1.2),
                                  ob=RNG.lognormal(7.5, 1.0), rb=RNG.lognormal(10, 1.5)))
            elif r < 0.75:  # long tail web (1 in 15 is a brand-new benign domain)
                if RNG.random() < 1 / 15:
                    dom = (random.choice(NEW_WORDS) + random.choice(["", "-"]) + random.choice(NEW_WORDS)
                           + random.choice([".com", ".net", ".io", ".org", ".co"]))
                    ip = f"198.18.{int(RNG.integers(0, 255))}.{int(RNG.integers(1, 255))}"
                else:
                    dom = random.choice(list(LONG_TAIL))
                    ip = LONG_TAIL[dom]
                dc = conn(ts - 0.05, host, DNS_SERVER, 53, "udp", "dns", 0.02, 40, 90)
                conns.append(dc)
                dnss.append(dns(ts - 0.05, host, dom, [ip], conn_uid=dc["uid"]))
                port = 443 if RNG.random() < 0.85 else 80
                conns.append(conn(ts, host, ip, port, service="ssl" if port == 443 else "http",
                                  duration=RNG.lognormal(0.5, 1.0),
                                  ob=RNG.lognormal(7, 0.8), rb=RNG.lognormal(9.5, 1.5)))
            elif r < 0.88:  # SMB to file server
                conns.append(conn(ts, host, FILE_SERVER, 445, service="smb",
                                  duration=RNG.lognormal(1.5, 1.0),
                                  ob=RNG.lognormal(8, 1.5), rb=RNG.lognormal(10, 2.0)))
            elif r < 0.95:  # kerberos/ldap to DC
                port = random.choice([88, 389])
                conns.append(conn(ts, host, "10.0.0.3", port, service="krb" if port == 88 else "ldap",
                                  duration=RNG.lognormal(-2, 0.5), ob=RNG.lognormal(6.5, 0.4),
                                  rb=RNG.lognormal(7, 0.4)))
            elif r < 0.99:  # ntp
                conns.append(conn(ts, host, "10.0.0.2", 123, "udp", "ntp", 0.01, 48, 48))
            else:  # normal failed lookups: WPAD, typos, dead internal names
                q = random.choice(["wpad.corp.local", "gooogle.com", "printer-3f.corp.local",
                                   "outlok.office365.com", "isatap.corp.local", "githb.com"])
                dc = conn(ts, host, DNS_SERVER, 53, "udp", "dns", 0.02, 40, 100)
                conns.append(dc)
                dnss.append(dns(ts, host, q, [], conn_uid=dc["uid"], rcode="NXDOMAIN"))
    return conns, dnss


def attacks(day_start, variant=0):
    """variant 0 = the hosts/domains listed at the top. variant>0 = same techniques on
    other hosts, other domains, slightly different parameters (an unseen test day)."""
    conns, dnss, truth = [], [], []
    if variant == 0:
        h_ex, h_bc, h_sc, h_rp, h_dt = "10.0.0.23", "10.0.0.31", "10.0.0.45", "10.0.0.12", "10.0.0.52"
        d_ex, d_bc, d_dt = "cdn-sync-update.xyz", "api-telemetry-check.top", "dnsx-relay.club"
        period, rport = 60, 4444
        h_dga, h_la, d_la, dga_len, dga_tld = "10.0.0.36", "10.0.0.19", "rnicrosoft.com", 12, ".com"
        h_goz, goz_n, goz_len = "10.0.0.47", 1000, (20, 30)
    else:
        h_ex, h_bc, h_sc, h_rp, h_dt, h_dga, h_la, h_goz = random.sample(INTERNAL, 8)
        goz_n, goz_len = 700, (24, 34)
        d_ex, d_bc, d_dt = "files-backup-cloud.site", "status-ping-svc.online", "q.tunl-ns.icu"
        period, rport = 300, 8443
        d_la, dga_len, dga_tld = "g1thub.com", 16, ".net"

    def add(c, label):
        conns.append(c)
        truth.append((c["uid"], label))

    # exfil
    ts = day_start + 2.5 * 3600
    dnss.append(dns(ts - 0.1, h_ex, d_ex, ["185.220.101.7"]))
    add(conn(ts, h_ex, "185.220.101.7", 443, service="ssl", duration=3540,
             ob=6.2e8, rb=2.1e5), "exfil")

    # beacon every ~60s for 10 hours
    dnss.append(dns(day_start + 1 * 3600 - 1, h_bc, d_bc, ["45.155.205.99"]))
    t = day_start + 1 * 3600
    while t < day_start + 11 * 3600:
        add(conn(t, h_bc, "45.155.205.99", 443, service="ssl",
                 duration=RNG.normal(0.35, 0.05), ob=RNG.normal(410, 15), rb=RNG.normal(220, 10)), "beacon")
        t += period + RNG.normal(0, period / 30)

    # port scan
    t = day_start + 20 * 3600
    for i in range(400):
        dst = f"10.0.0.{int(RNG.integers(1, 255))}"
        port = int(RNG.integers(1, 10000))
        add(conn(t + i * 0.05, h_sc, dst, port, duration=0,
                 state=random.choice(["REJ", "S0"])), "portscan")

    # rare port interactive session
    ts = day_start + 15 * 3600
    for i in range(6):
        add(conn(ts + i * 400, h_rp, "91.92.240.15", rport, duration=RNG.uniform(200, 380),
                 ob=RNG.uniform(3e4, 8e4), rb=RNG.uniform(2e5, 6e5)), "rare_port")

    # dns tunnel: many long random subdomains to one domain
    t = day_start + 9 * 3600
    for i in range(900):
        sub = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=48))
        dc = conn(t, h_dt, DNS_SERVER, 53, "udp", "dns", 0.03,
                  RNG.integers(120, 180), RNG.integers(200, 260))
        add(dc, "dns_tunnel")
        dnss.append(dns(t, h_dt, f"{sub}.{d_dt}", ["198.51.100.77"], qtype="TXT",
                        conn_uid=dc["uid"]))
        t += RNG.exponential(4)

    # DGA malware: tries ~150 random-looking domains, almost all NXDOMAIN, one resolves
    t = day_start + 6 * 3600
    for i in range(150):
        name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=dga_len)) + dga_tld
        hit = i == 149
        dc = conn(t, h_dga, DNS_SERVER, 53, "udp", "dns", 0.03, 45, 110 if hit else 100)
        add(dc, "dga")
        dnss.append(dns(t, h_dga, name, ["193.42.33.10"] if hit else [], conn_uid=dc["uid"],
                        rcode="NOERROR" if hit else "NXDOMAIN"))
        t += RNG.uniform(0.5, 2)

    # GameOver Zeus style DGA: ~1000 long alphanumeric names a day across .com/.net/.org/.biz,
    # lengths in a narrow band, spread over hours (slower than the burst above), almost all NXDOMAIN
    t = day_start + 2 * 3600
    for i in range(goz_n):
        name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789",
                                      k=int(RNG.integers(goz_len[0], goz_len[1] + 1))))
        name += random.choice([".com", ".net", ".org", ".biz"])
        hit = i % 400 == 399
        dc = conn(t, h_goz, DNS_SERVER, 53, "udp", "dns", 0.03, 55, 120 if hit else 110)
        add(dc, "gameover_zeus")
        dnss.append(dns(t, h_goz, name, ["185.11.22.33"] if hit else [], conn_uid=dc["uid"],
                        rcode="NOERROR" if hit else "NXDOMAIN"))
        t += RNG.exponential(60)

    # cousin / lookalike domain (phishing page): looks like normal browsing otherwise
    ts = day_start + 10.5 * 3600
    dc = conn(ts - 0.05, h_la, DNS_SERVER, 53, "udp", "dns", 0.02, 40, 90)
    add(dc, "lookalike")
    dnss.append(dns(ts - 0.05, h_la, d_la, ["104.21.88.200"], conn_uid=dc["uid"]))
    for i in range(4):
        add(conn(ts + i * 20, h_la, "104.21.88.200", 443, service="ssl", duration=RNG.lognormal(1, 0.5),
                 ob=RNG.lognormal(7.5, 0.5), rb=RNG.lognormal(10.5, 0.5)), "lookalike")
    return conns, dnss, truth


def write_jsonl(path, rows):
    rows = sorted(rows, key=lambda r: r["ts"])
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--baseline-days", type=int, default=5)
    ap.add_argument("--test-day", action="store_true",
                    help="also write data/test: one more unseen day with attack variants on other hosts")
    a = ap.parse_args()
    os.makedirs(f"{a.out}/baseline", exist_ok=True)
    os.makedirs(f"{a.out}/score", exist_ok=True)
    d1 = 1764028800.0  # 2025-11-25 00:00 UTC
    d2 = d1 + 86400 * a.baseline_days

    c1, n1 = [], []
    for d in range(a.baseline_days):
        c, n = normal_day(d1 + 86400 * d)
        c1 += c
        n1 += n
    write_jsonl(f"{a.out}/baseline/conn.log", c1)
    write_jsonl(f"{a.out}/baseline/dns.log", n1)

    c2, n2 = normal_day(d2)
    ca, na, truth = attacks(d2)
    write_jsonl(f"{a.out}/score/conn.log", c2 + ca)
    write_jsonl(f"{a.out}/score/dns.log", n2 + na)
    with open(f"{a.out}/score/ground_truth.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["uid", "scenario"])
        w.writerows(truth)
    if a.test_day:
        os.makedirs(f"{a.out}/test", exist_ok=True)
        d3 = d2 + 86400
        c3, n3 = normal_day(d3)
        ca3, na3, truth3 = attacks(d3, variant=1)
        write_jsonl(f"{a.out}/test/conn.log", c3 + ca3)
        write_jsonl(f"{a.out}/test/dns.log", n3 + na3)
        with open(f"{a.out}/test/ground_truth.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["uid", "scenario"])
            w.writerows(truth3)
        print(f"test day: {len(c3) + len(ca3)} conns, attacks on hosts "
              f"{sorted(set(c['id.orig_h'] for c in ca3))}")
    print(f"baseline: {len(c1)} conns | score day: {len(c2) + len(ca)} conns "
          f"({len(ca)} malicious across {len(set(s for _, s in truth))} scenarios)")


if __name__ == "__main__":
    main()
