# Week 8 Adversary Emulation Plan

Initial access → persistence → data exfiltration

> **Status:** Emulation plan and supporting files prepared. Windows/Wazuh execution and detection results are pending. No successful attack detection is claimed.

This folder extends the [MITRE ATT&CK SIEM Threat Hunting project](https://github.com/Talpynn/mitre-attack-siem-threat-hunting) with the Week 8 assignment: a simple adversary emulation plan covering initial access, persistence and data exfiltration.

## Repository contents

| File | Purpose |
| --- | --- |
| [Russian lab guide](README_RU.md) | Setup, commands, evidence collection and cleanup |
| [Lab stages](scripts/Invoke-LabStages.ps1) | Benign scheduled task and fixed dummy-file upload |
| [HTTP receiver](scripts/receiver.py) | Accept only the predefined dummy payload |
| [Cleanup](scripts/Remove-LabTask.ps1) | Remove the lab task and retain evidence |
| [Wazuh rules](detection-rules/week8_rules.xml) | Four lab detection signatures |
| [Windows agent collection](config/windows-agent-snippet.xml) | Security and Sysmon event collection snippets |
| [Sysmon configuration](config/sysmon-lab.xml) | Lab process and network telemetry |
| [Hunting queries](HUNTING_QUERIES.md) | Search and manually correlate events |
| [Test plan](TEST_PLAN.md) | Acceptance and control cases |
| [Results ledger](evidence/RESULTS.md) | Record actual outcomes after execution |
| [Package verification](VALIDATION.md) | Checks completed and verification limits |
| [Sources](SOURCES.md) | Official technique and tool references |

## Quick start

1. Read the [lab guide](README_RU.md), prepare an isolated Windows/Wazuh environment and replace example addresses and the test username.
2. Enable the required audit and Sysmon events; merge the agent configuration and validate the custom Wazuh rules.
3. Start the receiver on the lab machine:

```bash
python3 scripts/receiver.py --bind 192.168.56.20 --port 8080 --output evidence/received
```

4. Log on to the Windows target over RDP as the test account, then run in Windows PowerShell with suitable task-creation rights:

```powershell
.\scripts\Invoke-LabStages.ps1 -ReceiverIP 192.168.56.20
```

5. Sign out and log on again to verify the task trigger. Complete the [test plan](TEST_PLAN.md), collect alerts and hashes, and fill in the [results](evidence/RESULTS.md).
6. Remove the lab task after saving evidence:

```powershell
.\scripts\Remove-LabTask.ps1
```

The scripts do not install Wazuh/Sysmon, create accounts or configure firewall access. Full prerequisites and commands are in the guide.

## Purpose and laboratory scope

This plan emulates initial access, persistence and data exfiltration in an isolated Windows laboratory. It specifies the actions, ATT&CK mappings, telemetry and evidence needed to assess whether Wazuh observes each stage. The accompanying scripts perform only a timestamp task and a fixed dummy-file transfer.

### Relationship to the existing project

The linked project README describes a SIEM threat-hunting workflow involving controlled simulations, log collection, detection and investigation [1]. This Week 8 addition follows that workflow. The laboratory addresses and implementation below are proposed; the repository README does not establish that this infrastructure is deployed.

### Objective and assumptions

The scenario assumes that the adversary already knows a dedicated lab account password. Credential theft and brute force are outside scope. The lab user signs in remotely, creates a recurring task and sends a synthetic file to a controlled receiver. No command-and-control channel or external internet destination is used.

| Role | Example address | Required capability |
| --- | --- | --- |
| Windows target | 192.168.56.10 | RDP, Wazuh agent, Sysmon and PowerShell |
| Source and receiver | 192.168.56.20 | RDP client, Python HTTP receiver on TCP 8080 |
| Wazuh manager | 192.168.56.30 | Rule administration and searchable alerts |

Data flow: source → Windows target → lab receiver. Windows event logs → Wazuh agent → manager → dashboard. Replace example addresses with actual lab values before execution.

### Boundaries

Use a VM snapshot, a temporary account and synthetic data. Restrict RDP and receiver access to the lab hosts. Preserve evidence before removing the task and restoring temporary configuration changes. CALDERA is optional recommended reading; this plan uses direct benign actions for a reproducible small scenario.

## Scenario and ATT&CK mapping

### Initial access through valid credentials

Technique T1078, Valid Accounts, covers use of an existing account for access [2]. From the designated source, sign in to Windows over RDP as labstudent. Treat the password as already known. The observable is a successful remote interactive logon, normally Security event 4624 with logon type 10. This emulates credential abuse without stealing credentials.

### Persistence through a scheduled task

Technique T1053.005, Scheduled Task, covers scheduled execution that may maintain persistence [3]. Register Lab_Emulation_Test with a logon trigger for the current lab account and an action that appends a UTC timestamp to task-marker.txt. Run it manually once, then sign out and sign in again. A second timestamp establishes that the recurring trigger worked.

### Dummy data transfer over HTTP

Technique T1048.003 covers exfiltration over an unencrypted protocol outside a command-and-control channel [4]. Use curl.exe to POST only dummy-data.txt to the lab receiver on /upload. The receiver accepts only the exact predefined dummy bytes. This tests observability of the transfer pattern; it does not send real sensitive data or cross a real organizational boundary.

| Stage | ATT&CK ID | Completion evidence |
| --- | --- | --- |
| Initial access | T1078 | 4624 type 10, expected account and source |
| Persistence | T1053.005 | 4698, task XML and second-logon marker |
| Exfiltration | T1048.003 | Sysmon process/network events plus receiver 201 and matching SHA256 |

PowerShell is a support tool in this implementation. Its presence alone is not treated as malicious or counted as a separate required attack stage. The scenario does not represent a specific named threat actor.

## Execution procedure

### Prepare telemetry

Record machine names, actual IPs, software versions, agent ID and timezones in evidence/RESULTS.md. Synchronize time and use UTC for the timeline. Enable successful logon auditing and Audit Other Object Access Events. The latter is required for task-creation event 4698 [7].

Install or configure Sysmon to capture process creation and curl network connections [8]. Merge config/sysmon-lab.xml with any existing policy. Merge the Security and Sysmon EventChannel entries from config/windows-agent-snippet.xml into the existing agent configuration [6]. Preserve backups and restart the agent after validation.

### Apply the detection rules

Edit the lab username, source address and receiver address in detection-rules/week8_rules.xml. Confirm that IDs 100810 through 100813 are unused. Copy the custom file to the manager rules directory, validate the manager configuration and restart only after a successful check. Confirm actual decoded fields and test representative events on the deployed version [5].

### Perform the controlled actions

- Start scripts/receiver.py on the receiver, binding explicitly to its lab IP and TCP 8080.
- Connect from the source to the Windows target over RDP as the dedicated account and record the logon time.
- In that session, run scripts/Invoke-LabStages.ps1 with the actual receiver IP. The script creates a benign task, checks its marker and sends the fixed dummy file.
- Record the evidence directory printed by the script. Sign out of Windows and sign back in as the same user; confirm a second marker timestamp.
- Inspect the Wazuh alerts, correlate the process and network records, and compare sender and receiver SHA256 values.
- Complete the control tests, save screenshots/exports, then run scripts/Remove-LabTask.ps1 and restore temporary settings.

The [Russian guide](README_RU.md) provides the exact commands, audit settings and troubleshooting steps. Scripts do not create accounts, change firewall rules or install monitoring software. Task registration requires suitable rights; failure must be resolved before claiming persistence was exercised.

## Detection and investigation design

| Rule ID | Required signal | Interpretation |
| --- | --- | --- |
| 100810 | 4624, type 10, labstudent and source IP | Selected lab RDP logon |
| 100811 | 4698 with exact lab task name | Selected task was created |
| 100812 | Sysmon 1, curl.exe and dummy filename | Dummy upload command attempted |
| 100813 | Sysmon 3, curl.exe and receiver endpoint | Connection to the lab receiver |

### Investigation hypothesis

A selected account logging on from the designated source, followed by creation of a recurring task and a dummy-file upload on the same Windows host, should form a reconstructable sequence. Search within an initial 15-minute run window and expand only when the recorded timestamps require it.

Use the [hunting queries](HUNTING_QUERIES.md) to find the records. Correlate the logon account, task creator and process user with the run metadata. For Sysmon process and network events, compare processGuid. Do not infer that every action shares a process or logon ID: the scheduled task and curl command may execute separately.

### Telemetry and proof limits

A process-creation alert establishes an attempted command, and a network event establishes a connection. Neither establishes delivery. Confirm transfer with receiver.jsonl, a 201 response, the saved dummy file, equal byte counts and equal sender/receiver SHA256. Task creation similarly requires a separate execution check and a second-logon marker.

These are deterministic lab signatures, not general anomaly rules. A legitimate matching action can trigger them; actions using other accounts, task names or destinations may evade these signatures. The package does not implement automatic multi-stage correlation. A missing dashboard alert must be investigated at the event-generation, collection, decoding/rule and indexing layers.

### Improvement after the experiment

Use the observed results to identify absent audit categories, collection filters, mismatched field names or rule exceptions. Broader production detections would require baselines for remote logons, task actions and destinations, tested against representative legitimate activity. This single lab cannot establish a production false-positive rate.

## Acceptance criteria and results

### Required successful observations

- A1: The designated remote account logon is present in Windows and generates rule 100810.
- A2 and A3: Task creation generates rule 100811, and a manual task execution writes its timestamp marker.
- A4: A fresh logon of the same account adds a new timestamp through the task trigger.
- A5 and A6: The curl process and connection produce rules 100812 and 100813, and the receiver confirms the exact dummy file by SHA256 and size.
- C1: Cleanup removes the task; evidence is retained and temporary access changes are restored.

### Control cases

The [test plan](TEST_PLAN.md) defines alternative-account and alternative-task tests, curl --version, an unavailable receiver and an invalid payload. A failed upload may still generate command or connection alerts. Record the result of each control and retain failed or inconclusive observations rather than treating them as successful detections.

### Execution status

| Item | Current status | Evidence needed |
| --- | --- | --- |
| Plan and package | Prepared | Files in this Week 8 folder |
| Windows actions | Not executed | Run metadata and task evidence |
| Wazuh rules | Not validated on manager | Configuration test and real alerts |
| Lab delivery | Not executed | Receiver record and equal hashes |
| Detection coverage | Not measured | Completed results and control tests |

The complete results ledger is [evidence/RESULTS.md](evidence/RESULTS.md). Record UTC times, rule/event IDs, filenames, outcomes and limitations. Do not replace these execution statuses with a success claim until the corresponding evidence exists.

### Estimated remaining effort

With a working Windows/Wazuh lab, allow approximately 2–4 hours for configuration, execution, evidence collection and final editing. Building a new environment may take 1–2 days. These are planning estimates rather than measured durations.

## References and handover

### References

[1] Talpynn. MITRE ATT&CK SIEM Threat Hunting. https://github.com/Talpynn/mitre-attack-siem-threat-hunting
[2] MITRE ATT&CK. T1078 Valid Accounts. https://attack.mitre.org/techniques/T1078/
[3] MITRE ATT&CK. T1053.005 Scheduled Task. https://attack.mitre.org/techniques/T1053/005/
[4] MITRE ATT&CK. T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol. https://attack.mitre.org/techniques/T1048/003/
[5] Wazuh. Custom rules. https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
[6] Wazuh. Localfile configuration. https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
[7] Microsoft. Event 4698 and Audit Other Object Access Events. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
[8] Microsoft. Sysmon. https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

### Handover

The report and scripts are ready to copy into week-8-adversary-emulation in the project repository. Add the actual environment details and collected evidence before presenting this as an executed experiment. README_RU.md contains an optional root README entry and the upload procedure.

Source review date: 31 October 2026. The assignment screenshot asks for a plan; a completed practical demonstration additionally requires the evidence described above.
