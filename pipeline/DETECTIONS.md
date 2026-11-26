> Detection reference for the pipeline: the 12 hunts, the ML model, the explainability layer, and how a day is scored. The lab that produces the data and the full runnable system are described in the [top-level README](../README.md). The `synthetic/` folder regenerates the same detections on synthetic logs without Docker.

> **الخلاصة:** الـ prototype ده بيعمل threat hunting يومي على Zeek logs. فيه **12 hunt** (8 للـ lateral movement و4 للـ C2)، كل واحد عبارة عن hypothesis بيدوّر على سلوك معروف (PsExec، WMI، RDP غريب، pass-the-hash، Kerberoasting، DCSync، beaconing، DGA…). جنبهم **ML model** بيقارن كل host بنفسه (هو عادةً بيعمل إيه) ويطلع risk score، و**explainability layer** بيقول ليه. بعدين بيجمّع الـ hosts اللي بينهم lateral movement في **case واحدة** (attack path)، و**LLM open source** (Qwen3 على **Ollama**، self-hosted) بيكتب triage summary بالـ evidence. الـ analyst بيدوس TP/FP، والـ feedback بيدرّب XGBoost.
>
> على الداتا الـ synthetic: الـ intrusion كلها (11 technique على 3 hosts) طلعت في أول 2 cases، و15 hit من SCCM (شكلها زي PsExec بالظبط) اتشالت أوتوماتيك لأنها بتحصل كل يوم في الـ baseline.

![dashboard](examples/dashboard.png)

```
Zeek (conn, dns, ssl, kerberos, ntlm, smb_mapping, smb_files, dce_rpc, rdp)
   │
   ├─► hunts.py  ── 12 hunts (ATT&CK) ─────────────┐   known-bad behaviour
   │                                               ├─► hunt.py: score + group into cases (attack path)
   └─► hunts.py  ── per-host features ─► Isolation Forest vs the host's OWN baseline ─► Explainability
                                                   │
                                     out/cases.json ─► triage.py (open-source LLM, 1 call per case)
                                                   │
                                     build_dashboard.py ─► analyst TP/FP ─► train_feedback.py (XGBoost) ─┐
                                                   ▲                                                    │
                                                   └──────────────── next day ranks with --xgb ◄────────┘
```

## Quick start

```bash
pip install -r requirements.txt
bash run_demo.sh          # ~1 min: data, hunt, triage, dashboard, feedback, unseen day
open out/dashboard.html   # click cases, switch hosts in the explanation panel, press TP/FP, export labels.csv
```

Run it from a local copy (the shared project folder is a network drive; Python imports from it sometimes fail).

## Two layers, and why both

| | Hunts (rules) | ML (Isolation Forest + explainability) |
|---|---|---|
| Question it answers | "Is this host doing something attackers do?" | "Is this host doing something **it** doesn't normally do?" |
| Good at | Known techniques, even done once (one DCSync call is enough) | Things nobody wrote a rule for, volume/shape changes |
| Weak at | New techniques | Things that never vary in the baseline (a DCSync feature that is always 0 gives the forest nothing to split on) |
| Explanation | The finding itself + ATT&CK id + Zeek uids | Explainability: "RDP destinations = 2 (this host usually 0)" |

**Score per host** = max(hunt severity, 0.7 × ML risk) + 4 per extra distinct hunt + 8 if ML agrees (≥ 90) with a hunt. ML alone tops out at 70 ("medium: hunting lead"), so the queue is driven by evidence, and ML raises or adds leads.

**ML compares each host with itself** (UEBA style): features are "today minus this host's 5-day median", only the increase counts. The first version compared every host with every other host and put the servers on top every day (SCCM01 always talks to 15 hosts). Baseline rows are built leave-one-day-out so the model sees honest day-to-day noise.

**Cases:** hosts are joined into one case when code or a session moved between them (LM-01..04). WS-17 → PsExec → WS-22 → RDP → WS-30 becomes one case with an attack path, not 14 separate alerts. Auth-only hits (pass-the-hash, DCSync) list their targets as "touched hosts" without merging. A case with both C2 and lateral movement gets +5 (kill chain).

## Lateral movement hunts: how each one works

| ID | Hunt | Zeek logs | Logic | ATT&CK |
|---|---|---|---|---|
| LM-01 | Admin share + remote service (PsExec, Impacket smbexec, …) | smb_mapping, smb_files, dce_rpc | Same source→target: maps `\\host\ADMIN$` or `C$`, **writes an .exe/.dll/.bat/.ps1** there, then calls `svcctl::CreateServiceW/StartServiceW`. All three together = remote code execution as a service. | T1021.002, T1569.002 |
| LM-02 | Remote WMI / DCOM | dce_rpc | `IRemoteSCMActivator::RemoteCreateInstance` + `IWbemServices::ExecMethod` (wmiexec, `Invoke-WmiMethod`). Workstations rarely do this to each other. | T1047, T1021.003 |
| LM-03 | Remote scheduled task | dce_rpc | `ITaskSchedulerService::SchRpcRegisterTask` or `atsvc::JobAdd` to another host (`schtasks /s`, atexec). | T1053.005 |
| LM-04 | Unusual RDP | rdp, conn | Flags an RDP session when 2 of 3 are true: **off hours**, **workstation → workstation**, **pair never seen** in the baseline. Admin → server RDP in the daytime stays quiet. The `cookie` field gives the username. | T1021.001 |
| LM-05 | NTLM fan-out (pass-the-hash) | ntlm | One account authenticates with NTLM to ≥ 5 hosts within an hour. Pass-the-hash forces NTLM (no Kerberos ticket), and an attacker sprays the stolen hash across hosts. | T1550.002 |
| LM-06 | Kerberoasting | kerberos | ≥ 5 different service tickets (TGS) with **RC4** cipher within an hour. Attackers ask for RC4 because it cracks offline fast; normal clients get AES. | T1558.003 |
| LM-07 | DCSync | dce_rpc | `drsuapi::DRSGetNCChanges` from a host that is **not** a domain controller. Only DCs replicate; anyone else calling it is dumping password hashes (Mimikatz `lsadump::dcsync`). | T1003.006 |
| LM-08 | Internal sweep | conn | ≥ 20 internal hosts on 135/139/445/3389/5985 with ≥ 50% failed connections. The recon before lateral movement. | T1046, T1135 |

**Known admin behaviour is learned, not hand-written:** any (source, hunt) pair that fires on ≥ 3 of the 5 baseline days is suppressed and shown as "hidden" (SCCM01 deploying with ADMIN$ + a service every day). A new source doing the same thing still fires.

## C2 hunts: how each one works

| ID | Hunt | Zeek logs | Logic | ATT&CK |
|---|---|---|---|---|
| C2-01 | Beaconing | conn, ssl | Per (host, external IP) with ≥ 20 connections, four scores 0–1 averaged (RITA style): **timing** = 1 − MAD/median of the gaps (20% jitter still scores ~0.9; browsing ~0.1), **skew** of the gaps, **size** = same bytes sent each time, **coverage** = share of the 24 hours active (malware doesn't stop at 6 pm). Fires at ≥ 0.8. | T1071.001, T1573 |
| C2-02 | Long-lived connection | conn | One external connection ≥ 4h. Low bytes for that duration = an interactive tunnel/shell, not a download. | T1572, T1571 |
| C2-03 | DGA | dns | ≥ 30 distinct NXDOMAIN names from one host and the names look random (character-pair "surprise" ≥ 4.0; English-like names ≈ 3). | T1568.002 |
| C2-04 | New domain + unseen JA3 | ssl | First time anyone in the network reached the domain **and** the TLS client fingerprint (JA3) was never seen in the baseline. Malware TLS stacks (Cobalt Strike, Sliver defaults) have JA3s that browsers don't. | T1071.001 |

The older [`ml-scoring`](../ml-scoring/) prototype adds more C2/exfil detail per host→domain (DNS tunnelling, cousin domains, GameOver-Zeus-style DGA, exfil volume). The two can run side by side; `hunt.py` is host-centric, `ml-scoring` is connection-centric.

## The LLM part (open source, self-hosted)

The default backend is **Ollama** on your own machine or server, so no log data leaves the company:

```bash
# install Ollama (https://ollama.com), then once:
ollama pull qwen3:14b          # ~9 GB, runs on a 16 GB GPU (or slowly on CPU)
python3 triage.py              # defaults: http://localhost:11434/v1, model qwen3:14b

# bigger GPU (24 GB+): better summaries
ollama pull qwen3:32b
python3 triage.py --model qwen3:32b

# Ollama on another server:
LLM_URL=http://ollama-host:11434/v1 python3 triage.py
```

`triage.py` talks to Ollama through its OpenAI-compatible API, so you can swap in vLLM or llama.cpp later with `--llm-url` (e.g. `vllm serve Qwen/Qwen3-32B-AWQ` → `--llm-url http://gpu-host:8000/v1 --model Qwen/Qwen3-32B-AWQ`). Other open models that work the same way: `llama3.3:70b`, `mistral-small3.1`, `gemma3:27b`. If the LLM can't be reached, the case still gets a template card, so the queue keeps moving. **Pipeline mode:** the code collects all evidence first (Zeek rows by uid; in production fixed read-only KQL queries against Sentinel, see the end of `kql/hunts.kql`), then makes one call per case with **guided JSON** (schema in `triage.py`). The model never writes free KQL. The prompt tells it to cite a finding id or uid for every claim, list benign explanations, and not decide TP/FP.

**The summary in the screenshot is NOT from a real LLM.** It was made with `--offline`, which writes the same JSON from a template (the dashboard says so in small print). The HTTP call was tested against a mock OpenAI-compatible server, not a real Ollama yet.

## Sentinel

`kql/hunts.kql` has the same 12 hunts as KQL, plus the uid evidence lookup. **Not run against a real workspace**: table and column names are guesses (`Zeek_conn_CL`, …) and need adjusting to how your Zeek logs land in Sentinel.

## Files

| File | Does |
|---|---|
| `generate_lab.py` | Synthetic Zeek logs (9 log types, real field names) for a small Windows domain: 5 clean days + an intrusion day. `--variant 1` = same techniques on other hosts (unseen test day). |
| `hunts.py` | The 12 hunts, per-host features, baseline learning (known domains, JA3s, host pairs, known admin behaviour) |
| `hunt.py` | Isolation Forest vs own baseline, explainability, scoring, case grouping, attack path → `out/cases.json` |
| `triage.py` | LLM triage cards (Ollama by default, any OpenAI-compatible server, or `--offline`) → `out/triage.json` |
| `build_dashboard.py` | Self-contained `dashboard.html` (+ PNG with `--png` if Python Playwright is installed) |
| `simulate_feedback.py`, `train_feedback.py` | Analyst labels → XGBoost; `hunt.py --xgb` ranks with it |
| `kql/hunts.kql` | The hunts as Sentinel KQL |
| `examples/` | `cases.json`, `triage.json`, `dashboard.html`, `dashboard.png` from the demo run |

## Results on synthetic data (don't over-read them)

| | Result |
|---|---|
| Intrusion day: WS-17 (beacon, tunnel, sweep, Kerberoasting, PsExec ×2, WMI, DCSync), WS-22 (night RDP ×2, pass-the-hash, scheduled task), WS-33 (DGA) | All 11 techniques found. WS-17 + WS-22 in one critical case (#1) with the attack path; DGA host case #2. |
| False positives | 15 SCCM hits suppressed by the baseline. 2 "ML anomaly only" leads at #3/#4 (score ~69). One benign daytime RDP from WS-17 to a colleague shows up inside case #1. |
| Unseen day after 6 analyst labels (XGBoost) | Both attacked groups (other hosts, other C2 domain, 15-min beacon) #1 and #2; the two ML-only leads dropped out. |

The attacks are synthetic and loud, and the baseline is clean by construction. Real networks have backup jobs, vulnerability scanners and helpdesk tools that will trip LM-04/05/08 until the baseline learns them.

## Guesses (marked `GUESS:` in the code)

- Workstation subnet `10.10.1.0/24`, DC list, working hours 07–20 UTC: set yours in `hunts.py`.
- Host names come from a static map; in production use DHCP/DNS or the CMDB.
- 5 baseline days. 2–4 weeks is better, especially for RDP pairs and "known admin behaviour".
- Thresholds (beacon ≥ 0.8, ≥ 5 RC4 SPNs, ≥ 5 NTLM targets, ≥ 20 sweep targets, 4h connection, randomness ≥ 4.0) are tuned on synthetic data.
- Beaconing is per day; slow beacons (hours apart) need a multi-day window.
- Zeek needs the right analyzers for this: SMB, DCE-RPC, Kerberos, NTLM, RDP are on by default in recent Zeek; JA3 needs the `ja3` package (or JA4).
- Encrypted SMB3 / RPC hides file names and RPC operations from Zeek. Then LM-01..03 fall back to "new admin-port pair" features, and EDR becomes the main source.
