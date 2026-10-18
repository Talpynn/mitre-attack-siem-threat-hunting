# Week 6 — ATT&CK Technique Study and Simulation

## Objective
Study one ATT&CK technique, create controlled evidence of its observable behavior, and map that behavior to ATT&CK. The chosen technique is **T1046 — Network Service Discovery**.

## Technique background
T1046 describes adversary discovery of services running on networked systems. In a real incident, an actor may probe a host or network to learn which ports/services are reachable. A series of connections to many destination ports in a short interval is one possible observable pattern. A single connection or a list of ports alone is not proof of malicious intent.

**Tactic:** Discovery. **Technique:** T1046, Network Service Discovery. Official reference: https://attack.mitre.org/techniques/T1046/

## Safe simulation and data
`data/network_connections.csv` is a synthetic firewall/connection-log dataset. It contains three baseline connections and a labeled simulated-discovery sequence from `192.168.56.50` to the lab-only example host `192.168.56.20`, covering 14 distinct destination ports in under one minute. It is sample data and is not a record of a real scan or real network. No scan command is required: the activity is represented in the dataset so it can be safely analyzed in Splunk.

## SIEM procedure
1. In Splunk, upload `data/network_connections.csv` and set the sourcetype to CSV (or create a lookup named `network_connections.csv`).
2. Run `queries/t1046_timeline.spl` to inspect the event sequence.
3. Run `queries/t1046_discovery.spl` to group attempts by source and destination and flag groups with at least 10 distinct destination ports.
4. Confirm the simulated source/destination pair, 14 distinct ports, and the observed allowed/blocked outcomes.
5. Capture genuine screenshots as described in `evidence/README.md`.

## Observations
Expected from the supplied synthetic records: one flagged source/destination pair (`192.168.56.50` → `192.168.56.20`), 14 connection attempts, and 14 unique destination ports. The baseline host generates only three ports and should not meet the threshold. Some attempts are marked blocked, illustrating that prevention outcomes do not erase the value of detection telemetry.

## ATT&CK mapping and interpretation
The repeated port checks are consistent with behavior that may map to Discovery / T1046. The mapping is based on a controlled synthetic pattern, not attribution or proof of compromise. In a production hunt, validate the device role, expected scanner/admin activity, time window, firewall action, DNS and asset context, and any follow-on connections.

## Limitations and improvements
- Input is synthetic, not collected from an endpoint or firewall.
- The threshold is illustrative and may miss slow scans or flag approved monitoring tools.
- The event schema omits service names, user identity, asset criticality, and packet-level context.
- Improve by testing thresholds against authorized baseline data and correlating with asset inventory and change windows.

## Conclusion
This exercise connects a recognizable network behavior to an ATT&CK technique and demonstrates a reproducible SIEM search. It supports the technique-mapping objective while keeping the exercise inside supplied sample data.

## Evidence
See `evidence/README.md`; attach screenshots from the actual Splunk run before submission.
