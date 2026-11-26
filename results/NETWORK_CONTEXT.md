# Network context: how it changes hunt ranking

The hunt engine scores every case from two signals it can compute on any network:
the per-host **Isolation Forest** risk (how far today is from that host's own baseline) and
the **hunt** hits (known attacker techniques with ATT&CK ids). That is the *base* score.

A network also has a shape the logs alone don't carry: which subnets are the domain
controllers, which are crown-jewel databases, which flows are normal, and which attack
scenarios the defender actually worries about. You give the platform that shape in a
`network_context.yaml` (zones + criticality, an allowed zone-to-zone flow policy, and a
threat model mapped to ATT&CK). The engine then **grounds** each case in it — this is
retrieval/grounding, **not** fine-tuning; no model is retrained, the context is read at
scoring time and injected into the LLM prompt.

For each case the engine:

1. labels every flow with its source/destination **zone** and whether it **breaks the
   zone policy** (e.g. a workstation reaching the domain zone);
2. maps policy-violating hunts onto the defender's **threat model** (TM-xx → ATT&CK);
3. adds an **explainable bonus** — driven by the criticality of the most critical zone a
   violation reaches, plus the number of distinct threat-model scenarios matched (capped at +14).

The bonus only fires on **policy violations**, so a loud-but-legitimate anomaly gets nothing,
while a quiet lateral-movement that crosses into a critical zone is pushed up.

## Synthetic lab — context OFF vs ON

Same scored day (`synthetic/run_demo.sh`), run with `--no-context` and with
`--netcontext synthetic/network_context.yaml`:

| Rank | Case | Host | Base (ML+hunt) | +Context | Why the context fired |
|------|------|------|----------------|----------|-----------------------|
| 1 | HUNT-001 | WS-17 | 100.0 | **100.0 (+14, capped)** | 12 policy violations reaching **domain, database, servers**; matches 8 threat-model scenarios (C2, Kerberoasting, PsExec, DCSync, PtH…) |
| 2 | HUNT-002 | WS-33 | 78.0 | **80.0 (+2)** | DGA beaconing to external — 1 threat-model match (TM-03), no critical zone crossed |
| 3 | HUNT-003 | WS-35 | 69.4 | 69.4 (+0) | ML-only anomaly, breaks no policy |
| 4 | HUNT-004 | WS-05 | 68.2 | 68.2 (+0) | ML-only anomaly, breaks no policy |

The real intrusions (WS-17, WS-33) take **all** of the bonus; the ML-only noise (WS-35, WS-05)
takes none. The margin between the last confirmed threat and the top noise widens from
**8.6 → 10.6 points**, and — more useful to an analyst — the lift is now *explained* in the
defender's own terms ("reaches your domain + database zones, matches your DCSync scenario")
instead of an opaque score bump.

## Docker lab — the published demo

The dashboard at [`docs/index.html`](../docs/index.html) is the Docker lab (real Zeek logs of
an Impacket attack), scored with [`network_context.yaml`](../network_context.yaml):

| Case | Host | Base | +Context | Why |
|------|------|------|----------|-----|
| HUNT-001 | WS-04 | 100.0 | **100.0 (+14, capped)** | 9 policy violations reaching **domain + servers**; 8 threat-model scenarios incl. DCSync (T1003.006), DGA C2 (T1568.002), PtH (T1550.002) |
| HUNT-002 | WS-01 | 70.0 | 70.0 (+0) | ML anomaly only — breaks no zone policy |

The compromised host stays #1, now with a **Zone map** tab that draws the attack as movement
across your criticality bands (red = breaks policy, blue = allowed, purple = external C2) and a
one-line rationale tying the bonus to your zones and threat model.

## Turning it on

- **Pipeline:** `hunt.py --netcontext network_context.yaml` (or set `$NSM_NETCONTEXT`); omit it,
  or pass `--no-context`, to fall back to the pure ML+hunt score.
- **Dashboard:** the **◇ Network context** button loads/updates the context in-browser, toggles
  context scoring on/off, and (live mode) posts it to the server for re-scoring. The static demo
  ships with the sample context preloaded.
- **LLM:** when context is present, the SOC assistant is told the zones, the policy and the
  threat model, and is instructed to call out policy violations into critical zones and name the
  matching threat-model scenario — so its triage reads in your network's terms.
