# Week 8: Creating a Plan to Emulate an Attacker's Action

## 1. Introduction

The objective of this practical assignment is to develop and implement a simple adversary emulation plan based on the MITRE ATT&CK framework.

The exercise covers three stages of an attack lifecycle:

1. Initial Access
2. Persistence
3. Data Exfiltration

The practical work was conducted in a controlled laboratory environment using harmless test files, Windows 11, Kali Linux, and Splunk Enterprise.

The main goal was to simulate selected attacker behaviors, generate security events, and investigate these events using a SIEM platform.

## 2. Lab Environment and Tools

| Component | Description |
|---|---|
| Host Operating System | Windows 11 |
| Linux Environment | Kali Linux |
| SIEM Platform | Splunk Enterprise |
| Virtualization | Oracle VirtualBox |
| Network Configuration | NAT and Host-only Network |
| Test Data | Harmless fictional training files |

Windows 11 was used as the monitored host. Kali Linux was used as a local HTTP receiving server during the data transfer simulation.

The Host-only network allowed communication between Windows and Kali Linux without sending test data to an external network.

## 3. Adversary Emulation Plan

Three MITRE ATT&CK techniques were selected for this exercise.

| Attack Stage | Technique ID | Technique Name |
|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment |
| Persistence | T1053.005 | Scheduled Task |
| Data Exfiltration | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |

The selected techniques represent different stages of an attack. Each stage was simulated using safe actions and harmless test data.

## 4. Practical Implementation

### 4.1 Initial Access — T1566.001

**Technique:** Spearphishing Attachment

A harmless text file named `training_attachment.txt` was created in the Windows laboratory directory:

`C:\Week8-Lab\training_attachment.txt`

The file was opened using Notepad to simulate a user opening an attachment.

Windows process creation activity was generated during this operation. Event ID 4688 was used to investigate the creation of new processes.

**Results:**

- The training file was opened successfully.
- Windows generated process creation events.
- Splunk collected and displayed Event ID 4688 records.

**Limitation:** This was a local file-opening simulation. No phishing email was sent, and no malicious attachment was used. Therefore, it represents only a limited approximation of the selected technique.

### 4.2 Persistence — T1053.005

**Technique:** Scheduled Task

A harmless scheduled task named `Week8-BenignTask` was created using Windows Task Scheduler.

The task was configured to open the training text file with Notepad.

The following command was used:

```powershell
schtasks /Create /SC ONLOGON /TN "Week8-BenignTask" /TR "notepad.exe C:\Week8-Lab\training_attachment.txt" /F
```

The task was queried and executed to verify its configuration and behavior.

After the test, the task was stopped and deleted:

```powershell
schtasks /End /TN "\Week8-BenignTask"
schtasks /Delete /TN "\Week8-BenignTask" /F
```

**Splunk Detection:**

The following Windows Security events were investigated:

| Event ID | Description |
|---|---|
| 4688 | A new process has been created |
| 4698 | A scheduled task was created |
| 4699 | A scheduled task was deleted |

Splunk successfully identified Event ID 4698 and Event ID 4699 records associated with `Week8-BenignTask`.

The deletion search returned two matching records.

**Results:**

- The scheduled task was created successfully.
- The task was executed and subsequently stopped.
- The task was successfully deleted.
- Splunk detected task creation and deletion events.

This demonstrated how scheduled task activity can be monitored through Windows Security logs.

### 4.3 Data Exfiltration — T1048.003

**Technique:** Exfiltration Over Unencrypted Non-C2 Protocol

A harmless test file named `exfil_test.txt` was created on Windows.

The file contained fictional training data:

```text
CONFIDENTIAL TEST DATA - Week 8 Lab - No Real Personal Information
```

A simple Python HTTP receiver was configured on Kali Linux.

The receiver listened on the Host-only network address:

`192.168.56.101:8000`

The Windows host transferred the test file to Kali Linux using an HTTP POST request.

The request returned the following response:

| Parameter | Result |
|---|---|
| HTTP Status Code | 200 |
| Status Description | OK |
| Received File Size | 68 bytes |

The Kali receiver confirmed that it received 68 bytes from the Windows host.

The received file was then inspected using:

```bash
cat /tmp/week8-received.txt
```

The displayed content matched the original test data.

**Results:**

- The HTTP receiver started successfully.
- Windows transferred the test file to Kali Linux.
- The HTTP request returned status code 200.
- Kali Linux received 68 bytes.
- The received file content was verified.

**Limitation:** This was a controlled transfer over a private Host-only network using fictional data. No external system or real personal information was involved.

## 5. Splunk Detection and Analysis

Splunk Enterprise was used to collect and investigate Windows Security logs.

The following event IDs were relevant to the practical exercise:

| Event ID | Event Description | Purpose |
|---|---|---|
| 4688 | Process creation | Monitor newly created processes |
| 4698 | Scheduled task creation | Detect persistence-related activity |
| 4699 | Scheduled task deletion | Monitor scheduled task removal |

Splunk searches confirmed that the Windows Security events were successfully collected and could be investigated.

The results demonstrate the importance of centralized log collection and event analysis when monitoring suspicious system activity.

## 6. Results and Limitations

The practical exercise successfully demonstrated three selected attacker behaviors in a controlled environment.

**Main Results:**

1. Process creation activity was investigated using Windows Event ID 4688.
2. Scheduled task creation was detected using Event ID 4698.
3. Scheduled task deletion was detected using Event ID 4699.
4. A harmless test file was transferred from Windows to Kali Linux over HTTP.
5. The HTTP transfer returned status code 200.
6. Kali Linux successfully received and verified the 68-byte test file.

**Limitations:**

- Initial Access was represented by a local file-opening simulation rather than an actual phishing email.
- Persistence was implemented using a benign scheduled task.
- Data transfer was limited to a private Host-only network.
- The exercise did not reproduce a complete real-world cyberattack.

## 7. Conclusion

This practical assignment provided experience in developing and implementing an adversary emulation plan using the MITRE ATT&CK framework.

The exercise demonstrated how selected attacker behaviors can generate observable system events and how Splunk Enterprise can be used to investigate Windows Security logs.

It also provided practical experience with process monitoring, scheduled task detection, and controlled HTTP file transfers.

Overall, the assignment improved understanding of adversary emulation, persistence techniques, data transfer monitoring, and SIEM-based security analysis.

## 8. Evidence Screenshots

The screenshots documenting the practical implementation will be added to the `screenshots` directory.

The evidence includes:

- Windows process creation events (Event ID 4688).
- Scheduled task creation events (Event ID 4698).
- Scheduled task deletion events (Event ID 4699).
- Successful HTTP transfer response from Windows.
- Kali Linux receiving 68 bytes.
- Verification of the received test file.
