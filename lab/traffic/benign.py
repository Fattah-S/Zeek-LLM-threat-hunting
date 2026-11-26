"""Normal user activity on a workstation, while a session is running:
web browsing (DNS + HTTPS), Kerberos SMB to the DC share, NTLM SMB to the file server,
LDAP lookups, and the odd failed DNS lookup (typos, WPAD)."""
import os
import random
import time

import requests
import urllib3

from lab_lib import DC, HOSTS, SITES, active, log, resolve, sh

urllib3.disable_warnings()
USER = os.environ.get("LAB_USER", "user01")
PW = "User-Passw0rd!"
open("/etc/krb5.conf", "w").write(f"""[libdefaults]
 default_realm = CORP.LAB
 dns_lookup_kdc = false
 rdns = false
[realms]
 CORP.LAB = {{
  kdc = {DC}
  admin_server = {DC}
 }}
[domain_realm]
 .corp.lab = CORP.LAB
""")


def web():
    name = random.choice(SITES)
    ip = resolve(name)
    if ip:
        try:
            requests.get(f"https://{name}/", timeout=5, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"})
        except Exception:
            pass


def typo():
    resolve(random.choice(["wpad.corp.lab", "www.news-dialy.com", "mail.offce-cloud.com", "printer-2f.corp.lab"]))


def dc_share():  # Kerberos: TGT + cifs/dc01 service ticket, then SMB
    sh(f"echo '{PW}' | kinit {USER}@CORP.LAB >/dev/null 2>&1; "
       f"smbclient //dc01.corp.lab/shares --use-kerberos=required -c 'get report.txt /dev/null' >/dev/null 2>&1")


def file_server():  # legacy file server with NTLM
    from impacket.smbconnection import SMBConnection
    try:
        c = SMBConnection(HOSTS["fs01"], HOSTS["fs01"], timeout=5)
        c.login(USER, PW, "CORP")
        c.getFile("data", "sales.csv", lambda d: None)
        c.logoff()
    except Exception as e:
        log("fs01", type(e).__name__)


def ldap():
    sh(f"ldapsearch -x -H ldap://{DC} -D {USER}@corp.lab -w '{PW}' -b dc=corp,dc=lab '(sAMAccountName={USER})' cn >/dev/null 2>&1")


ACTIONS = [(web, 55), (dc_share, 12), (file_server, 15), (ldap, 10), (typo, 3)]
log("benign traffic for", USER)
while True:
    if active():
        f = random.choices([a for a, _ in ACTIONS], [w for _, w in ACTIONS])[0]
        f()
        time.sleep(random.uniform(1, 5))
    else:
        time.sleep(1)
