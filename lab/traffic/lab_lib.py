"""Shared helpers for the lab traffic generators (real protocols via Samba + Impacket)."""
import io
import os
import random
import socket
import subprocess
import time

import dns.resolver

CONTROL = "/control/session"
DC = "10.77.0.10"
DOMAIN = "CORP"
REALM = "corp.lab"
HOSTS = {"dc01": "10.77.0.10", "fs01": "10.77.0.20", "sccm01": "10.77.0.60",
         "ws-01": "10.77.0.101", "ws-02": "10.77.0.102", "ws-03": "10.77.0.103",
         "ws-04": "10.77.0.104", "ws-05": "10.77.0.105"}
SITES = ["www.news-daily.com", "mail.office-cloud.com", "teams.office-cloud.com", "cdn.static-js.net",
         "api.weather-now.io", "www.search-engine.com", "updates.vendor-soft.com"]

_res = dns.resolver.Resolver(configure=False)
_res.nameservers = [DC]
_res.lifetime = 3


def session():
    try:
        return open(CONTROL).read().strip()
    except OSError:
        return "idle"


def active():
    s = session()
    return s not in ("idle", "done")


def log(*a):
    print(f"[{socket.gethostname()} {time.strftime('%H:%M:%S')}]", *a, flush=True)


def resolve(name):
    """DNS lookup through the domain controller (it forwards public names to the 'internet')."""
    try:
        return _res.resolve(name, "A")[0].to_text()
    except Exception:
        return None


def sh(cmd, timeout=20):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return -1


def deploy_service(target, user, password="", nthash="", filename="ccmsetup.exe", svc="ccmexec"):
    """What PsExec and software-deployment tools do: write an exe to ADMIN$, then create and
    start a service over \\pipe\\svcctl. Samba refuses the service, but the requests are real."""
    from impacket.dcerpc.v5 import scmr, transport
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(target, target, timeout=5)
    conn.login(user, password, DOMAIN, "", nthash)
    payload = io.BytesIO(os.urandom(random.randint(30_000, 60_000)))
    conn.putFile("ADMIN$", filename, payload.read)  # callback returns chunks, then b"" to finish
    rpc = transport.SMBTransport(target, filename=r"\svcctl", smb_connection=conn).get_dce_rpc()
    rpc.connect()
    rpc.bind(scmr.MSRPC_UUID_SCMR)
    try:
        h = scmr.hROpenSCManagerW(rpc)["lpScHandle"]
        s = scmr.hRCreateServiceW(rpc, h, svc + "\x00", svc + "\x00", lpBinaryPathName=f"%SystemRoot%\\{filename}\x00")
        scmr.hRStartServiceW(rpc, s["lpServiceHandle"])
    except Exception as e:  # expected on Samba: no Windows service manager
        log(f"svcctl on {target}: {type(e).__name__}")
    rpc.disconnect()
    conn.logoff()
