# Week 6 — ATT&CK Technique Study and SIEM Simulation

**Technique:** T1046 — Network Service Discovery  
**ATT&CK tactic:** Discovery  
**SIEM:** Splunk Enterprise  
**Dataset:** `data/network_connections.csv` (synthetic lab data)  
**Date:** 18 October 2026

## 1. Objective

Study one MITRE ATT&CK technique, examine a safe representation of its observable behavior, and use Splunk to identify and review that behavior. This exercise focuses on network service discovery and maps a repeated multi-port connection pattern to ATT&CK T1046.

## 2. Technique overview

MITRE ATT&CK defines **T1046, Network Service Discovery**, under the **Discovery** tactic. An adversary may probe network hosts to identify running or reachable services. In connection telemetry, one possible indicator is a single source contacting many distinct destination ports on the same host within a short period. This pattern is a hunting lead; it does not by itself establish malicious intent.

Official reference: [MITRE ATT&CK — T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/).

## 3. Safe simulation and dataset

The exercise uses a purpose-built CSV of 17 synthetic connection records. It contains three ordinary baseline connections and 14 records labeled `simulated_discovery`. The simulated sequence represents source `192.168.56.50` contacting destination `192.168.56.20` across 14 distinct ports from 10:10:00 to 10:10:39 on 17 October 2026. Outcomes include both `allowed` and `blocked` connections.

These are illustrative private lab addresses and generated records. No real port scan was run, and the CSV is not evidence of activity on an actual network. The activity was safely represented in data and analyzed in Splunk.

## 4. Splunk method

1. Uploaded the synthetic CSV into Splunk using **Add Data > Upload**. The search used `index=* source="network_connections.csv"` to retrieve the imported records.
2. Parsed the raw CSV fields with `rex`, since Splunk displayed the uploaded rows as raw events in this session.
3. Reviewed the simulated sequence in chronological order, displaying timestamp, source, destination, destination port, protocol, and action.
4. Grouped the simulated records by source and destination, calculated the total attempts and distinct destination ports, and applied an illustrative threshold of 10 unique ports.

The reproducible SPL is included in `queries/t1046_timeline.spl` and `queries/t1046_discovery.spl`. In the Splunk search used for the screenshots, the field extraction was performed from the raw CSV event using `rex` before the filter and aggregation.

## 5. Results

The uploaded dataset returned 17 records overall. The timeline search displayed the 14 simulated-discovery records. The detection search returned one source/destination group:

| Source | Destination | Attempts | Distinct destination ports | Threshold result |
|---|---|---:|---:|---|
| `192.168.56.50` | `192.168.56.20` | 14 | 14 | Flagged (threshold ≥ 10) |

The timeline shows the attempted destination ports and a mix of allowed and blocked outcomes. Three baseline connections use three distinct ports and do not meet the threshold. This confirms the expected behavior of the sample dataset and the query logic; it is not a finding about a real environment.

## 6. ATT&CK mapping and interpretation

The repeated attempts to reach multiple services on one destination are consistent with behavior associated with **Discovery — T1046 Network Service Discovery**. The mapping is based on the designed pattern in the synthetic records. A real investigation would need context such as asset role, approved vulnerability scans, monitoring tools, change windows, source ownership, surrounding DNS and network activity, and follow-on behavior before judging whether the activity is suspicious.

## 7. Limitations and next steps

- The data is synthetic and does not come from an endpoint, firewall, or packet capture.
- The threshold is illustrative. A slow scan may fall below it, while approved inventory or monitoring tools may exceed it.
- The sample has no user identity, service fingerprint, asset criticality, or broader network context.
- For a production hunt, tune the time window and threshold against authorized baseline telemetry, add asset context, and validate alerts with the network operations team.

## 8. Conclusion

This exercise studied T1046 and demonstrated how Splunk can surface a multi-port discovery pattern in connection records. The observed synthetic sequence produced 14 attempts across 14 destination ports and was correctly returned by the ≥10-port analytic threshold. The results meet the technique-study and SIEM-analysis objectives while remaining clearly limited to a controlled dataset.

## 9. Evidence

The accompanying genuine screenshots are in `evidence/`:

1. `01-t1046-detection.jpg` — Splunk grouped result showing 14 attempts and 14 unique ports.
2. `02-t1046-timeline.jpg` — Splunk event table showing the 14 simulated connection records.
3. `03-attack-reference.jpg` — ATT&CK page showing the T1046 title, ID, and Discovery tactic.

The screenshots substantiate the search results and technique reference. They do not show the initial upload configuration, so the report does not claim that an import-settings screenshot is included.
