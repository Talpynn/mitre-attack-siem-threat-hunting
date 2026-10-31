# Results to complete after the lab run

Status: NOT EXECUTED ON WINDOWS OR WAZUH. Empty entries are not successful results.

## Run details

- Student and group: TO COMPLETE
- Run date, UTC start and UTC end: TO COMPLETE
- Windows name, version, IP and Wazuh agent ID: TO COMPLETE
- Wazuh manager version and IP: TO COMPLETE
- Sysmon version and configuration applied: TO COMPLETE
- Source IP and receiver IP/port: TO COMPLETE
- Test account (no password): TO COMPLETE
- Dashboard timezone and offset from UTC: TO COMPLETE
- Script run ID: TO COMPLETE

## Observed results

| Test | Actual UTC time | Result | Rule ID and event record | Evidence file | Explanation |
| --- | --- | --- | --- | --- | --- |
| A1 Logon | — | NOT TESTED | — | — | — |
| A2 Task creation | — | NOT TESTED | — | — | — |
| A3 Manual task run | — | NOT TESTED | — | — | — |
| A4 Task on next logon | — | NOT TESTED | — | — | — |
| A5 Dummy transfer | — | NOT TESTED | — | — | — |
| A6 Hash equality | — | NOT TESTED | — | — | — |
| N1 Other account | — | NOT TESTED | — | — | — |
| N2 Other task | — | NOT TESTED | — | — | — |
| N3 curl version | — | NOT TESTED | — | — | — |
| N4 Receiver stopped | — | NOT TESTED | — | — | — |
| N5 Invalid payload | — | NOT TESTED | — | — | — |
| C1 Cleanup | — | NOT TESTED | — | — | — |

Use PASS, FAIL or INCONCLUSIVE only after observing the test. Explain missing telemetry separately from missing alerts.

## Required screenshots and exports

- 01-lab-topology.png — VM names, roles and connectivity.
- 02-logon-alert.png + corresponding JSON — 4624, account, source IP and timestamp.
- 03-task-alert.png + JSON — 4698 and task details.
- 04-task-relogon.png — logon trigger, last result and two marker timestamps.
- 05-upload-process.png + JSON — Sysmon 1 with curl command line.
- 06-upload-network.png + JSON — Sysmon 3 with destination and process GUID.
- 07-receiver-hash.png — receiver 201, size and sender/receiver SHA256.
- 08-timeline.png — ordered lab events on the same Windows agent.
- 09-cleanup.png — absence of the lab task.
- run-metadata.json, receiver-response.json, task.xml, task-result.txt, task-marker.txt and received/receiver.jsonl.

## Hash verification

Sender SHA256: TO COMPLETE

Receiver SHA256: TO COMPLETE

Sender and receiver size: TO COMPLETE

Same process GUID for Sysmon 1 and 3: TO COMPLETE

## Analysis

Which stages were detected: TO COMPLETE

Which stages were missed and why: TO COMPLETE

Control-test outcomes and rule changes: TO COMPLETE

Cleanup and configuration restoration: TO COMPLETE

Conclusion supported by the evidence: TO COMPLETE
