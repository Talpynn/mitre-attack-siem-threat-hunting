# Detection Rules

## 1. Overview

This directory contains detection rules used to investigate activities during the Week 8 adversary emulation exercise.

Splunk Enterprise was used to search Windows Security Event Logs and identify relevant system activities.

## 2. Detection Rules

### Rule 1: Process Creation

- **Event ID:** 4688
- **Purpose:** Detect the creation of new processes.
- **MITRE ATT&CK:** T1566.001 – Spearphishing Attachment (limited local simulation)

**Splunk Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search "notepad.exe"
| table _time host EventCode Message
| sort -_time
```

**Observed Result:**

The event logs recorded Notepad process creation when the harmless training file was opened.

### Rule 2: Scheduled Task Creation

- **Event ID:** 4698
- **Purpose:** Detect the creation of a scheduled task.
- **MITRE ATT&CK:** T1053.005 – Scheduled Task

**Splunk Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4698
| search "Week8-BenignTask"
| table _time host EventCode Message
| sort -_time
```

**Observed Result:**

Splunk identified the creation of the scheduled task named `Week8-BenignTask`.

### Rule 3: Scheduled Task Deletion

- **Event ID:** 4699
- **Purpose:** Detect the deletion of a scheduled task.
- **MITRE ATT&CK:** T1053.005 – Scheduled Task

**Splunk Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4699
| search "Week8-BenignTask"
| table _time host EventCode Message
| sort -_time
```

**Observed Result:**

Splunk recorded the deletion of `Week8-BenignTask`, confirming that the temporary task was removed after testing.

## 3. Data Exfiltration Monitoring

A harmless test file was transferred from Windows to Kali Linux through the Host-only network.

The transfer was verified using:
- HTTP Status Code 200 (OK) on Windows PowerShell.
- Successful receipt of 68 bytes on Kali Linux.

**MITRE ATT&CK:** T1048.003 – Exfiltration Over Unencrypted Non-C2 Protocol.

Note: The HTTP transfer was verified using endpoint and receiver output. It is not claimed as a Splunk-detected network event.

## 4. Summary

The detection rules demonstrate how Splunk can investigate process creation and scheduled task activities through Windows Security Event Logs.

The exercise also verified a controlled local HTTP file transfer using harmless test data.

All activities were performed in a controlled laboratory environment.
