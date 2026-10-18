# Week 6 — ATT&CK Technique Study and SIEM Simulation

This week studies **MITRE ATT&CK T1046 — Network Service Discovery** and analyzes a safe synthetic connection-log dataset in Splunk.

## Contents

- `report/WEEK6_REPORT.md` — complete report, methodology, results, mapping, and limitations.
- `data/network_connections.csv` — synthetic connection events (17 rows: 3 baseline and 14 simulated discovery events).
- `queries/t1046_timeline.spl` — chronological event review.
- `queries/t1046_discovery.spl` — grouped multi-port detection query.
- `evidence/` — screenshots from Splunk and the ATT&CK reference page.

## Reproduction

Import the CSV into Splunk as a lookup named `network_connections.csv`, then run the SPL files in `queries/`. If importing as raw events instead, use the field extraction visible in the Splunk evidence screenshots before applying the filter and aggregation.

All records are synthetic. No actual network scan was performed and the sample does not represent activity on a real network.
