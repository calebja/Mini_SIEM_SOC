# Signal Deck - Mini SIEM + SOC Lab

![Python](https://img.shields.io/badge/python-3.x-3776AB?logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite&logoColor=white)
![Dashboard](https://img.shields.io/badge/dashboard-self--contained_HTML-E34F26?logo=html5&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-8_techniques_mapped-B91C1C)
![Detectors](https://img.shields.io/badge/detection_rules-8-6D28D9)
![Log Sources](https://img.shields.io/badge/log_sources-Windows%20%7C%20Linux%20%7C%20Firewall-183A61)
![Recall](https://img.shields.io/badge/recall-16%2F16_(100%25)-2EA44F)
![Precision](https://img.shields.io/badge/precision-0.97-2EA44F)
![F1](https://img.shields.io/badge/F1-0.98-2EA44F)
![Data](https://img.shields.io/badge/data-100%25_synthetic-orange)

A small, complete detection pipeline, including synthetic multi-source logs → a log
collector that normalizes them → a rule-based detection engine covering 8
attack classes → a scorecard that grades the engine against a hidden
red-team answer key → a dashboard.

```
Windows PC ──┐                                    ┌──> alerts.json
             │                                    │
Linux Server ├──> collector.py ──> siem.db ──> detect.py ──> evaluate.py
             │      (parses 3        (SQLite)      (8 rule-        │
Firewall ────┘       raw formats)                   based             ▼
                                                     detectors)   dashboard.html
```

## Files

| File | Role |
|---|---|
| `src/generate_logs.py` | Simulates 3 days of activity across 2 Windows PCs, 2 Linux servers and a firewall. Writes benign background traffic plus 16 labeled attack campaigns (2 of each of the 8 types). Labels go to `data/ground_truth.json` only — never into the detector's input. |
| `src/collector.py` | The "Log Collector" Parses the three raw formats (Windows EVTX-style pipe log, Linux syslog/auth.log, firewall CSV) with regex into one normalized `events` table in `data/siem.db`. |
| `src/detect.py` | The "Detection Engine" 8 independent detectors read `events` and write `alerts` with severity, MITRE ATT&CK technique + tactic, plain-language evidence, and a recommended response. |
| `src/evaluate.py` | Scores `alerts.json` against `ground_truth.json` to compute true/false-positive rates, per-campaign recall, and per-attack-type precision. |
| `src/build_dashboard.py` | Bakes the alerts + scorecard into `output/dashboard.html`, a self-contained analyst console. |

Run the whole pipeline:
```
cd src
python3 generate_logs.py   # synthetic logs + answer key
python3 collector.py       # normalize into SQLite
python3 detect.py          # run all 8 detectors
python3 evaluate.py        # score against the answer key
python3 build_dashboard.py # render the dashboard
```

## Detectors and MITRE ATT&CK mapping

| Detection | Logic | Technique |
|---|---|---|
| Brute-force authentication | ≥8 failed logons from one IP against one host inside a 5-min sliding window; escalates to Critical if a success follows within 2 min | T1110 |
| Suspicious PowerShell | ScriptBlock text matched against 9 patterns (`-enc`, `IEX(`, `DownloadString`, AMSI/Defender tampering, Mimikatz references, `-w hidden`, privilege enumeration, execution-policy bypass) | T1059.001 |
| Port scanning | ≥15 distinct destination ports from one source IP against one host inside a 2-min window; severity scales with deny ratio | T1046 |
| Impossible login | Same account authenticates successfully from two IPs mapped to different regions within 60 minutes | T1078 |
| Privilege escalation | Linux: sudo-to-root followed by sudoers/SUID tampering. Windows: `whoami /priv` followed by a special-privilege-assignment event within 5 min | T1548.003 / T1134 |
| New administrator accounts | Account creation immediately followed (≤2 min) by addition to an admin/sudo group; escalates outside business hours | T1136.001 |
| Persistence mechanisms | Scheduled tasks, services, cron jobs pointing at world-writable paths (`Public`, `ProgramData`, `/tmp`, hidden dirs); SSH `authorized_keys` edits | T1053.x / T1543.003 / T1098.004 |
| Large outbound transfers | Transfer size ≥ 3× the network's 95th-percentile baseline (floor 400 MB); escalates outside business hours | T1048 |

## Results on the synthetic lab (Sep 22–24, 2026)

16 attack campaigns were injected against ~1,150 benign background events.

- **Campaign-level recall: 16/16 (100%)** — every injected campaign produced at least one alert.
- **Alert-level precision: 0.97** — 28 of 29 fired alerts corresponded to a real campaign.
- **F1: 0.98**

The one false positive is an overlap. A
`whoami /priv` command that's part of a privilege-escalation campaign also matches the
suspicious-PowerShell detector's "privilege enumeration" pattern on its own, so two
independent detectors fire on the same underlying event. A production SIEM would
correlate these into a single incident rather than counting it as two; `evaluate.py`
intentionally does not paper over this, since alert-correlation across detectors is a
real tuning problem, not an edge case to hide.

Full per-type breakdown, false-positive list, and every raw alert are in
`data/metrics.json` / `data/alerts.json`, and are browsable in the dashboard.

## Notes on the design

- The generator tags
  attack-related log lines with a `GT=ATK-###` suffix; the collector strips it into its
  own `gt_id` column, and every detector function only ever reads operational fields
  (timestamps, users, IPs, ports, command text). `evaluate.py` is the only script that
  touches `ground_truth.json`.
- Two exfil campaigns landed
  under two minutes apart on the same host during generation; a naive "first ground-truth
  row that overlaps" rule misattributed one alert to the wrong campaign and manufactured
  a false negative. `evaluate.py` instead attributes each alert to whichever campaign's
  start time it's closest to — the kind of correlation-window bug worth catching in a
  real detection engine, not just this lab.
- All IPs, usernames, and hostnames are placeholders;
  nothing in this repo involves a real network.
