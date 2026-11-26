# Lab results

> This snapshot was generated end-to-end from the Docker lab (real Zeek logs of a real Impacket attack). The **detection** numbers are live. The **Ask-the-network** table shows the no-LLM *template baseline*, because this snapshot was produced in an environment where the Ollama model registry was unreachable. When you run `docker compose up` locally, the LLM answers and the LLM-judge grades fill the same table (the answerer and embedding similarity replace the template row), and you can watch them live in the dashboard's **Ask the network** box.

Attack day: `/logs/attack-day` · generated 2026-11-26 14:30 UTC

## Detection

| Metric | Value |
|---|---|
| Techniques detected | **8 / 10** |
| Compromised host's case rank | #1 |
| Host alerts (score ≥ 75) | WS-04 |
| Host precision / recall | 100% / 100% |
| Finding precision (hits on the compromised host / all unsuppressed hits) | 100% (10/10) |
| Deployment-server hits suppressed as known admin behaviour | 6 |

| Technique | Hunt | Detected | Evidence |
|---|---|---|---|
| C2 beaconing | C2-01 | yes | 38 connections to cdn-update-check.online (10.77.0.250) every ~8s, timing 0.88, payload size 1.00, active 100% |
| Long-lived C2 tunnel | C2-02 | yes | 0.1h connection to 10.77.0.250:8443, only 0.0 MB out / 0.0 MB in (interactive, not a download) |
| DGA lookups | C2-03 | yes | 56 distinct random-looking names that did not resolve, e.g. aeurnuyjjnzg.info, aiglrudtfljvcuvf.info, akqteqtr |
| Internal port sweep | LM-08 | yes | 66 connections to 9 internal hosts on ports [135, 445, 3389], 58% failed |
| Kerberoasting | LM-06 | yes | 6 RC4 service tickets in 0.2 min, e.g. MSSQLSvc/sql.corp.lab:1433, MSSQLSvc/web.corp.lab:1433, MSSQLSvc/backup |
| PsExec-style remote service | LM-01 | yes | mapped \\10.77.0.102\ADMIN$, svcctl (OpenSCManagerW) - remote service control over the admin share (PsExec pat |
| DCSync | LM-07 | yes | drsuapi replication calls (DRSBind, DRSCrackNames) from a host that is not a domain controller (only domain co |
| Pass-the-hash NTLM fan-out | LM-05 | yes | NTLM logons as 'adm_it' to 6 hosts in 2 min (this host normally uses Kerberos) |
| WMI remote exec attempt | LM-02 | **no** | no network evidence (the RPC was refused before Zeek could log it) |
| Remote scheduled task attempt | LM-03 | **no** | no network evidence (the RPC was refused before Zeek could log it) |

> WMI (LM-02) and the remote scheduled task (LM-03) are attempted against Samba, which refuses the DCOM / task-scheduler RPC before any operation is carried out, so Zeek has nothing to log. On Windows targets the bind and the call are logged and both hunts fire — these two are a limitation of the Samba lab, not of the detection.

## Ask the network: LLM answer quality

Answerer: `not available in this environment (run `docker compose up` locally, where Ollama is reachable)` · judge: `requires local Ollama` · gold hosts: DC01, FS01, WS-02, WS-04 · gold techniques: 8

| Question | Answered by | Judge (faith/rel/comp/act) | Verdict | Host F1 | Technique F1 | Semantic sim. | ROUGE-L |
|---|---|---|---|---|---|---|---|
| What abnormal behaviour happened on the network today? | template (no LLM) | -/-/-/- | n/a | 0.29 | 0.71 | 0.32 | 0.18 |
| Which hosts should I investigate first, and why did the model flag them? | template (no LLM) | -/-/-/- | n/a | 0.29 | 0.71 | 0.32 | 0.18 |
| Is there any sign of credential theft or lateral movement? | template (no LLM) | -/-/-/- | n/a | 0.29 | 0.71 | 0.32 | 0.18 |

Similarity method: TF-IDF cosine (no embedding model)

## Example answer

**Q:** What abnormal behaviour happened on the network today?

```
7 hosts scored, 16 hunt hits (6 suppressed as known admin behaviour).
[HUNT-001] critical WS-04: Beaconing (regular timing + same-size payloads) (T1071.001) WS-04 -> cdn-update-check.online; New domain + TLS client fingerprint (JA3) never seen (T1071.001) WS-04 -> cdn-update-check.online; Internal sweep of SMB/RPC/RDP ports (T1046) WS-04 -> 9 hosts; Long-lived external connection (T1572) WS-04 -> c2; DGA: burst of random-looking failed lookups (T1568.002) WS-04 -> 56 domains; Kerberoasting (RC4 service tickets for many SPNs) (T1558.003) WS-04 -> DC (KDC). Why: longest external connection (h) = 0.07 (this host usually 0.00); failed DNS names = 3 (this host usually 2).
[HUNT-002] medium WS-01: ML anomaly only. Why: failed DNS names = 3 (this host usually 1); longest external connection (h) = 0.00 (this host usually 0.00).
```
