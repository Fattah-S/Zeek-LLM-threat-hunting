"""The deployment server (think SCCM/Intune agent push): every ~30s it copies an installer to a
workstation's ADMIN$ share and creates a service. Byte-for-byte this looks like PsExec, and it
happens every day, so the hunt pipeline must learn it as normal from the baseline."""
import random
import time

from lab_lib import HOSTS, active, deploy_service, log

# the deployment server authenticates to and pushes a package to every workstation each day.
# This is the legitimate behaviour that looks exactly like PsExec + NTLM fan-out, and the platform
# must learn it from the baseline and suppress it. So it must happen on every session, attack included.
targets = [ip for n, ip in HOSTS.items() if n.startswith("ws-")]
while True:
    if active():
        for t in random.sample(targets, min(len(targets), 7)):
            if not active():
                break
            try:
                deploy_service(t, "svc_deploy", "Deploy-Passw0rd!", filename="ccmsetup.exe", svc="ccmsetup")
                log("deployed to", t)
            except Exception as e:
                log("deploy failed", t, type(e).__name__)
            time.sleep(random.uniform(4, 8))
    else:
        time.sleep(1)
