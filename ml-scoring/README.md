# NSM risk scoring prototype (Zeek → ML → SHAP)

> **الخلاصة:** الكود ده بياخد Zeek `conn.log` + `dns.log`، يجمّع الـ connections لـ alerts (host → domain/IP في اليوم)، يدّي كل alert risk score بـ Isolation Forest، ويشرح كل واحد بـ SHAP. لما الـ analyst يحط TP/FP، بيتدرب XGBoost على الـ feedback ويرتّب أحسن. وفيه كمان indicators واضحة (cousin domain، DGA، NXDOMAIN burst، DNS tunnel، beacon، scan) جنب الـ score. الناتج `top_alerts.json` هو اللي الـ LLM agent هياخده.

This is the "ML Scoring Model" and "SHAP" boxes of the pipeline:

```
Zeek JSON logs ─► features.py ─► score.py (Isolation Forest + rule indicators) ─► SHAP ─► top_alerts.json ─► LLM agent
                                        ▲                                                                  │
                                        └──── train_feedback.py (XGBoost) ◄────────────── analyst TP/FP ◄──┘
```

## Quick start

```bash
pip install -r requirements.txt
bash run_demo.sh        # ~45s: generate data, score, simulate analyst feedback, retrain, score an unseen day
```

Run it from a local copy of the folder. (The shared project folder is a network drive and Python sometimes fails to import from it.)

## What an "alert" is

Scoring single connections was the first attempt, and it didn't work well: big but normal SMB/HTTPS transfers out-ranked the attacks, and a single connection can't show beaconing or scanning. So connections are grouped into **alerts = (internal source host, target, 24h window)**, where target is the registered domain if known, else the destination IP. Failed connections from a host are grouped together (that's how scans show up), and so are its NXDOMAIN lookups (that's how a DGA burst shows up as one alert instead of 150). Each alert is one story for the analyst instead of 600 beacon rows.

## Features (per alert)

| Feature | Catches |
|---|---|
| `n_conn`, `bytes_out`, `bytes_in`, `out_in_ratio`, `max_duration` | exfiltration, long sessions |
| `beacon_regularity` (1 − CV of time gaps) | C2 beaconing (connections that recur on a fixed interval) |
| `new_domain` (not in baseline), `domain_host_count` | newly observed / rare domains (phishing, drive-by) |
| `domain_randomness` (character-pair frequency, the idea behind `freq.py`) | DGA / randomly named domains |
| `lookalike_score` (similarity to a popular domain after folding `rn→m`, `0→o`, `1→l/i`…) | cousin / typosquat domains (`rnicrosoft.com`, `g1thub.com`) |
| `nxdomain_ratio`, `n_unique_queries` | DGA bursts, unique queries per domain |
| `label_len_mean`, `label_len_std` (length of each distinct name with the TLD cut off) | DGAs whose names cluster in a narrow length band. This is how GameOver Zeus was found in the course example. |
| `dns_entropy`, `rare_qtype_ratio` (TXT/NULL/ANY) | DNS tunnelling, odd request types |
| `port_rarity` (vs baseline), `is_external` | odd ports (4444, 8443…) |
| `failed_ratio`, `n_dst_ips`, `n_dst_ports` | scanning |

DNS request/answer size and volume are covered by `bytes_out`, `bytes_in` and `n_conn` on DNS alerts.

### Indicators and pinned rules

Isolation Forest only learns from what varies in a clean baseline. A cousin domain almost never appears there, so the forest can't give it weight: the phishing alert looked like ordinary browsing to a new site and ranked around #100. Two fixes:

- Every alert carries plain **`indicators`** ("cousin/lookalike domain of 'microsoft'", "burst of 153 failed lookups (NXDOMAIN): possible DGA", "many long random subdomains: possible DNS tunnelling", "regular timing: possible C2 beacon", "390 ports with mostly failed connections: scanning", …). The LLM agent can quote them directly.
- **Strong rules** (now: lookalike ≥ 0.85) are pinned into the top N even when the model ranks them low. Once the analyst labels them, XGBoost learns the weight (after one round of feedback `lookalike_score` became its 2nd most important feature).

With XGBoost on, 5 of the top N slots stay reserved for the most anomalous alerts XGBoost didn't pick (`--novelty-slots`), so attack types nobody has labelled yet still surface.

## Results on synthetic data

5 days of clean baseline (with benign new domains and normal NXDOMAIN noise like WPAD and typos), then a day with **8 injected attacks**: exfil, beacon, port scan, rare-port shell, DNS tunnel, DGA burst, cousin domain, and a GameOver-Zeus-style DGA (~1,000 alphanumeric names of 20–30 characters a day across .com/.net/.org/.biz, spread over hours, almost all NXDOMAIN). Then an **unseen test day** where the same techniques run from other hosts, to other domains (`g1thub.com`, a `.net` DGA…), with different timing and ports.

| | Attacks caught | Where they ranked |
|---|---|---|
| Attack day, Isolation Forest + rules (~1,300 alerts) | 8/8 in top 20 | GameOver Zeus #3; others 1, 2, 4, 5, 6, 12, and 20 (the cousin domain, pinned by the rule) |
| Test day, XGBoost after 50 analyst labels (~1,270 alerts) | **8/8 in top 10** | GameOver Zeus #2 (names 24–34 chars this time); all 10 of the top 10 malicious |

**Don't over-read this.** The attacks are synthetic and loud, and XGBoost has seen only 11 true positives. Expect real Zeek data to be harder, with more false positives from Isolation Forest at first.

Example output: [`examples/top_alerts_isolation_forest.json`](examples/top_alerts_isolation_forest.json). The beacon alert reads:

> **indicators:** domain never seen before in this network; regular timing (regularity 0.97): possible C2 beacon
> **SHAP:** timing regularity = 0.97 (baseline median 0.00); upload/download ratio = 1.87x (baseline median 0.06x); number of connections = 600 (baseline median 26)

## Files

| File | Does |
|---|---|
| `generate_synthetic.py` | Zeek-format JSON logs (real field names, shared `uid` between conn and dns) + ground truth |
| `features.py` | Enrichment (domain from DNS, rcode/qtype, failed states, entropy, randomness, lookalike) and aggregation to alerts |
| `score.py` | Isolation Forest, risk 0–100 (percentile vs baseline), indicators, pinned rules, novelty slots, SHAP top-5 reasons, `top_alerts.json`, `alert_members.csv` (uid → alert, for pulling evidence from Sentinel) |
| `simulate_feedback.py` | Stand-in for the analyst: labels the top N from ground truth |
| `train_feedback.py` | Builds an accumulating labelled set, trains XGBoost on features + IF score |
| `evaluate.py` | Where did each injected attack rank |

## Plugging in real Zeek logs

1. Enable JSON in Zeek (`@load policy/tuning/json-logs.zeek`) and put a few days of `conn.log` + `dns.log` in `data/baseline/`, the day to score in `data/score/`.
2. `python3 score.py --baseline data/baseline --score data/score --top 20 --out out`
3. Have analysts fill `feedback/labels.csv` (`alert_id,window,label,analyst,note`, label = TP/FP), then `python3 train_feedback.py` and score with `--xgb feedback/model_xgb.joblib`.

## Guesses I made (marked `GUESS:` in the code)

- **Baseline is clean.** If an attack is already running during the baseline, it becomes "normal".
- **Domain mapping** uses the last DNS answer for the destination IP. On real data, `ssl.log` `server_name` and `http.log` `host` (joined by `uid`) are more accurate.
- **Registered domain = last two labels.** Wrong for `.com.eg`, `.co.uk`; swap in `tldextract`.
- **Beacon test** is simple (needs ≥10 connections, coefficient of variation). Jittered or sleeping beacons need something stronger, like an FFT or RITA-style scoring.
- **XGBoost uses baseline alerts as extra negatives** until there are enough real labels.
- 24h windows. Shorter windows (1h) catch things faster but are noisier.
- **Randomness model** is trained on a small built-in word list plus the baseline's domains. Train it on the Tranco top 1M (what `freq.py` does) for real use.
- **"Popular" domains** for the lookalike check = used by ≥ 20% of hosts in the baseline. Add your own company domain, banks and key partners: those are the ones attackers copy.
- **GameOver Zeus indicator** fires at ≥ 50 distinct names, ≥ 50% NXDOMAIN, average length ≥ 15 and spread ≤ 4 characters. A DGA with short or widely varying names is still caught by the randomness and NXDOMAIN-burst indicators instead.
- **Indicator thresholds** (randomness ≥ 4.8, lookalike ≥ 0.85, NXDOMAIN burst ≥ 20…) are tuned on synthetic data.

## v2: ideas from Zeek metadata not built yet

| Idea | Zeek log | Why not in v1 |
|---|---|---|
| WHOIS creation date of new domains (days old) | dns.log + WHOIS lookup (`domain_stats.py`) | Needs an external lookup service and caching. The list of new domains is small, so it's cheap once that exists. Plugs in as a `domain_age_days` feature. |
| Hostnames that break the naming standard, MACs not on the company asset list | dhcp.log | Needs your naming convention and asset/MAC list. |
| Vulnerable OS / app versions found passively | software.log | Needs a CVE/version feed. Better as a host-level context field than an alert feature. |
| Rare HTTP user agents | http.log | Easy add as `ua_host_count` once http.log is in the input. |
| Weak/rare TLS versions, ciphers, JA3/JA4, self-signed certs | ssl.log, x509.log | Same, plus `server_name` gives better domain mapping than DNS. |
| Long-term beaconing (crawl weeks back, jitter-tolerant) | conn.log | Needs multi-week storage; RITA-style scoring or FFT on the time series. |
| Learning what the org looks like (which systems talk to which, encryption in use) | all | A reporting/baseline job of its own, useful context for the LLM agent. |

## Open questions for you

1. Will the data come straight from Zeek files, or should scoring read from Sentinel (KQL query against the Zeek table)? That changes the input layer only.
2. Is an alert unit of host → domain per day right for how your analysts work, or do you want per-host risk too?
3. Roughly how many internal hosts and connections per day? This decides whether a single-machine Python job is enough.
