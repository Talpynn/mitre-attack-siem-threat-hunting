# Week 7 — Using MITRE CAR (Cyber Analytics Repository) in Splunk

> **Lab report | SIEM detection engineering | Network reconnaissance**  
> **Analytic reference:** MITRE CAR-2021-01-001 — *Identifying Port Scanning Activity*  
> **SIEM:** Splunk Enterprise 10.6.0.5 on Windows  
> **ATT&CK mapping:** T1046 — Network Service Discovery  
> **Dataset type:** Synthetic, locally generated lab data

---

## 1. Executive Summary

This exercise implements a port-scanning detection workflow in Splunk using the MITRE Cyber Analytics Repository (CAR) analytic **CAR-2021-01-001 — Identifying Port Scanning Activity** as the reference model. A CSV lookup containing two deliberately constructed traffic patterns was uploaded to Splunk. A baseline search aggregated the data by one-minute time window, source IP, and destination IP. A second search applied a threshold of at least 10 distinct destination ports within a one-minute window.

The baseline search returned two groups: one with 3 distinct ports and one with 14. The detection search returned one group: source `192.168.56.60` connecting to destination `192.168.56.25` across 14 distinct ports. The result was mapped to ATT&CK T1046, Network Service Discovery, within the Discovery tactic.

**Scope limitation:** the CSV is synthetic and was created for this lab. The result demonstrates that the implemented query detects the constructed test case; it is not evidence of a real attack or of activity on a production network. The query is a simplified educational implementation inspired by the CAR analytic reference, not a claim of byte-for-byte reproduction of every upstream CAR implementation detail.

## 2. Learning Objectives

The exercise addresses the Week 7 syllabus task to select an analytic model from MITRE CAR, implement it in a SIEM, and map the analytic to related ATT&CK techniques.

By completing the exercise, the student should be able to:

1. Explain the role of MITRE CAR analytics in detection engineering.
2. Load a CSV lookup into Splunk.
3. Aggregate network events by time window and host pair.
4. Count distinct destination ports and apply a detection threshold.
5. Compare a baseline with a detection result.
6. Map the observed behavior to ATT&CK T1046.
7. Document evidence, false-positive considerations, and limitations.

## 3. Background and Concepts

### 3.1 MITRE CAR

MITRE Cyber Analytics Repository (CAR) publishes analytic models and related information that can support defensive detection development. In this lab, CAR-2021-01-001, *Identifying Port Scanning Activity*, is used as the reference analytic for a pattern consistent with a host checking multiple network ports on another host.

### 3.2 Port scanning

Port scanning is a form of network reconnaissance. A source host attempts connections to multiple destination ports to discover which services may be available. A high number of distinct destination ports targeted on one destination in a short period can be a useful detection signal.

This pattern is not automatically malicious. Vulnerability scanners, asset inventory tools, network monitoring systems, and authorized administrators can generate similar traffic. The result must be investigated in context.

### 3.3 SIEM detection versus an alert verdict

A SIEM query identifies records matching defined logic. A match is a lead for investigation, not a final verdict that a host is compromised. Analysts should validate the source, destination, timing, expected activity, and related telemetry before declaring an incident.

## 4. Environment and Prerequisites

| Component | Value used in this lab |
|---|---|
| Operating system | Windows |
| SIEM | Splunk Enterprise 10.6.0.5 |
| Splunk interface | Local browser interface |
| Lookup table | `car_network_scan.csv` |
| Baseline search | `car_baseline_check.spl` |
| Detection search | `car_2021_01_001_network_scan.spl` |
| Reference analytic | CAR-2021-01-001 |
| ATT&CK technique | T1046 — Network Service Discovery |

The Splunk interface was opened locally in a browser. The CSV was uploaded under **Settings → Lookups → Lookup table files**. Splunk confirmed that `car_network_scan.csv` was saved in the Search app context.

## 5. Dataset Description

The dataset contains 17 synthetic events: 3 baseline events and 14 simulated scan events. The fields are:

| Field | Meaning |
|---|---|
| `timestamp` | Event timestamp in `YYYY-MM-DD HH:MM:SS` format |
| `src_ip` | Source IP address |
| `dest_ip` | Destination IP address |
| `dest_port` | Destination port targeted by the event |
| `action` | Simulated connection outcome, such as `allowed` or `blocked` |
| `protocol` | Simulated transport protocol |

### 5.1 Test cases

| Test case | Source IP | Destination IP | Event count | Distinct ports | Expected outcome |
|---|---|---|---:|---:|---|
| Baseline traffic | `192.168.56.50` | `192.168.56.25` | 3 | 3 | Does not meet threshold |
| Simulated scan | `192.168.56.60` | `192.168.56.25` | 14 | 14 | Meets threshold |

The detection threshold used in this implementation is **10 distinct destination ports per source/destination pair within a one-minute bucket**. This threshold is a lab parameter chosen to make the two test cases distinguishable; it should not be treated as a universal production threshold.

## 6. Procedure: Upload the CSV Lookup

1. Open Splunk Enterprise in the browser and sign in.
2. Open **Settings**.
3. Navigate to **Lookups → Lookup table files**.
4. Select **New Lookup Table File**.
5. Upload `car_network_scan.csv`.
6. Save the file in the Search & Reporting app context using the filename `car_network_scan.csv`.
7. Verify the success message: `Successfully saved "car_network_scan.csv" in search`.

The lookup upload was successful. The file was then referenced in SPL with `inputlookup car_network_scan.csv`.

**Evidence to attach:** `evidence/week7_lookup_upload.png`

## 7. Baseline Validation

### 7.1 Purpose

Before applying the detection threshold, the baseline query verifies that Splunk can read the lookup, parse the timestamp, group events into one-minute buckets, and calculate the number of connections and distinct destination ports.

### 7.2 Baseline SPL

```spl
| inputlookup car_network_scan.csv
| eval event_time=strptime(timestamp, "%Y-%m-%d %H:%M:%S")
| bin event_time span=1m
| stats count as connections dc(dest_port) as unique_ports values(dest_port) as ports by event_time src_ip dest_ip
| sort event_time src_ip
```

### 7.3 Query explanation

- `inputlookup car_network_scan.csv` reads the uploaded lookup table.
- `eval event_time=strptime(...)` converts the timestamp string to Splunk epoch time.
- `bin event_time span=1m` groups events into one-minute intervals.
- `stats count` counts the events in each group.
- `dc(dest_port)` counts distinct destination ports.
- `values(dest_port)` lists the port values observed in each group.
- `by event_time src_ip dest_ip` keeps each time window and source/destination pair separate.
- `sort` orders the results for easier review.

### 7.4 Observed baseline result

Splunk returned **2 result rows**:

| Source IP | Destination IP | Connections | Distinct ports | Interpretation |
|---|---|---:|---:|---|
| `192.168.56.50` | `192.168.56.25` | 3 | 3 | Below threshold |
| `192.168.56.60` | `192.168.56.25` | 14 | 14 | Simulated scan test case |

This result confirms that the lookup was readable and that the aggregation produced the expected two groups. The second group is visible in the baseline output but is not yet filtered by the detection condition.

**Evidence to attach:** `evidence/week7_baseline.png`

## 8. Detection Implementation

### 8.1 Detection logic

The detection search uses the same aggregation as the baseline, then filters for groups with at least 10 distinct destination ports. It adds the CAR analytic identifier and ATT&CK mapping to the displayed output.

### 8.2 Detection SPL

```spl
| inputlookup car_network_scan.csv
| eval event_time=strptime(timestamp, "%Y-%m-%d %H:%M:%S")
| bin event_time span=1m
| stats count as connections dc(dest_port) as unique_ports values(dest_port) as ports values(action) as actions by event_time src_ip dest_ip
| where unique_ports >= 10
| eval analytic_id="CAR-2021-01-001", mitre_attack="T1046 - Network Service Discovery"
| table event_time analytic_id mitre_attack src_ip dest_ip connections unique_ports ports actions
| sort - unique_ports
```

### 8.3 Query explanation

- The first three commands read the lookup, parse the time, and create one-minute buckets.
- `stats` calculates the number of events, distinct destination ports, port values, and action values for each source/destination pair in each time bucket.
- `where unique_ports >= 10` retains only groups that meet the lab threshold.
- `eval` adds the analytic ID and ATT&CK mapping as output fields.
- `table` displays the fields relevant to analyst triage.
- `sort - unique_ports` places the largest distinct-port counts first.

### 8.4 Observed detection result

Splunk returned **1 result row**:

| Field | Observed value |
|---|---|
| Analytic ID | `CAR-2021-01-001` |
| ATT&CK mapping | `T1046 - Network Service Discovery` |
| Source IP | `192.168.56.60` |
| Destination IP | `192.168.56.25` |
| Connections | 14 |
| Distinct destination ports | 14 |
| Actions represented | `allowed`, `blocked` |

The detection query returned the simulated scan group and excluded the baseline group with only 3 distinct ports. This matches the expected behavior of the threshold-based test.

**Evidence to attach:** `evidence/week7_car_detection.png`

## 9. Mapping to MITRE ATT&CK

| Element | Mapping |
|---|---|
| MITRE CAR analytic | CAR-2021-01-001 — Identifying Port Scanning Activity |
| ATT&CK technique | T1046 — Network Service Discovery |
| Tactic | Discovery |
| Relevant behavior | A source host contacts multiple destination ports on a target host within a short time window |

The relationship is based on the behavior represented by the test data: a source connects to a large number of destination ports on one target in a short interval. This is consistent with network service discovery.

The official CAR page lists the technique as Network Service Discovery and the tactic as Discovery. The page also describes the data subtype as Flow. The current exercise uses a CSV with synthetic flow-like records, rather than a live network-flow sensor.

**Official CAR reference:** <https://car.mitre.org/analytics/CAR-2021-01-001/>

**ATT&CK reference:** <https://attack.mitre.org/techniques/T1046/>

**Evidence to attach:** `evidence/week7_mitre_car.png`

## 10. Analysis and Findings

### 10.1 What worked

1. The CSV lookup was uploaded successfully into Splunk.
2. The baseline query returned two groups with the expected event counts and distinct-port counts.
3. The detection query returned one group satisfying the threshold.
4. The output included the analytic ID and the ATT&CK mapping.
5. The result was consistent with the expected synthetic test case.

### 10.2 Why the baseline group was not detected

The baseline source `192.168.56.50` generated 3 connections to 3 distinct ports. Since the detection threshold is 10 distinct ports, the group does not satisfy `where unique_ports >= 10`.

### 10.3 Why the simulated scan group was detected

The source `192.168.56.60` generated 14 connections to 14 distinct destination ports for the same destination within one one-minute bucket. Since 14 is greater than or equal to 10, the group satisfies the condition and is returned.

### 10.4 Analyst interpretation

The output should be described as **a successful detection of a simulated port-scanning pattern**. It should not be described as a confirmed real attack, compromise, or malicious actor. Additional telemetry and context would be required for an operational incident assessment.

## 11. Limitations and False-Positive Considerations

1. **Synthetic dataset:** the events were created for the exercise, not collected from a real network.
2. **Simplified implementation:** the SPL query is a compact educational implementation based on the selected CAR analytic reference. It is not claimed to reproduce every upstream analytic detail exactly.
3. **Threshold tuning:** the threshold of 10 ports per minute is a lab setting. Real environments require baselining and tuning.
4. **False positives:** approved vulnerability scanners, inventory tools, and administrators may legitimately connect to many ports.
5. **False negatives:** a slow scan, a scan distributed across multiple time windows, or a scan spread across multiple source addresses may not meet this rule.
6. **Limited context:** the dataset has no asset criticality, user identity, process lineage, firewall policy, or business authorization context.
7. **No attribution:** the source IP alone does not identify a person or prove compromise.
8. **Timestamp assumptions:** the query assumes the timestamp field matches `%Y-%m-%d %H:%M:%S`. Other formats require parsing changes.

### Recommended production improvements

- Tune the threshold against normal network behavior.
- Add allowlists for approved scanners only when justified and documented.
- Enrich results with asset ownership, host role, and network zone.
- Correlate with firewall, endpoint, authentication, and DNS telemetry.
- Preserve the raw events and investigate adjacent activity before escalating.
- Track both the number of distinct ports and the timing/rate of attempts.

## 12. Evidence Checklist

Place actual screenshots in the `evidence/` folder. Use these filenames to keep the submission organized.

| Filename | Required content |
|---|---|
| `week7_lookup_upload.png` | Splunk success message for `car_network_scan.csv` |
| `week7_baseline.png` | Baseline query and both result rows |
| `week7_car_detection.png` | Detection query and its one result row |
| `week7_mitre_car.png` | Official CAR page showing CAR-2021-01-001 and ATT&CK mapping |

The evidence folder contains a README placeholder only. The screenshots must be captured from the actual lab environment; they are not fabricated or automatically included in this report package.

## 13. Conclusion

This exercise completed the core Week 7 workflow described in the course syllabus: select a MITRE CAR analytic, implement detection logic in a SIEM, validate the logic, and map the analytic to an ATT&CK technique.

The CSV was uploaded successfully. The baseline query returned two groups: one with 3 distinct ports and one with 14. The detection query returned one group with 14 connections across 14 distinct ports, matching the configured threshold. The simulated behavior was mapped to ATT&CK T1046 — Network Service Discovery, under the Discovery tactic.

The exercise demonstrates a repeatable workflow for basic detection engineering in Splunk. Its conclusion is limited to the synthetic dataset used for validation. A production deployment would require real telemetry, threshold tuning, contextual enrichment, and investigation of potential false positives.

## References

1. MITRE Cyber Analytics Repository. **CAR-2021-01-001: Identifying Port Scanning Activity.** <https://car.mitre.org/analytics/CAR-2021-01-001/>
2. MITRE ATT&CK. **T1046: Network Service Discovery.** <https://attack.mitre.org/techniques/T1046/>
3. Course syllabus, Week 7: **Using MITRE CAR (Cyber Analytics Repository)** — select an analytic model from CAR, implement it in a SIEM, and map it to related ATT&CK techniques.

---

**Submission note:** Before submitting, add your actual screenshots to `evidence/` and review any instructor-specific formatting requirements. This report records the lab steps and the results observed in the Splunk screenshots.
