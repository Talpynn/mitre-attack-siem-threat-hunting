# APT29 – MITRE ATT&CK Technique Mapping

## 1. Purpose

This document maps selected techniques publicly associated with APT29 and the SolarWinds Compromise to the MITRE ATT&CK Enterprise framework.

The mapping helps identify which behaviors a SOC should monitor and which data sources are required.

## 2. Technique Mapping

| Tactic | Technique ID | Technique | Publicly documented behavior | Potential defensive data source |
|---|---|---|---|---|
| Initial Access | T1195.002 | Compromise Software Supply Chain | Trojanized SolarWinds Orion updates | Software integrity records, EDR, application logs |
| Defense Evasion | T1553.002 | Subvert Trust Controls: Code Signing | Malicious code signed through the compromised software lifecycle | Code-signing and software integrity logs |
| Command and Control | T1071.001 | Web Protocols | HTTP-based command-and-control communication | Proxy, DNS, firewall, network telemetry |
| Discovery | T1087.002 | Domain Account | Domain account enumeration | Windows Security logs, Active Directory logs |
| Discovery | T1018 | Remote System Discovery | Enumeration of remote systems | EDR, endpoint process telemetry, network logs |
| Execution | T1059.001 | PowerShell | PowerShell used for commands and post-compromise activity | PowerShell operational logs, Event ID 4688, EDR |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` used to execute commands | Event ID 4688, EDR |
| Persistence | T1053.005 | Scheduled Task | Scheduled tasks used for persistence and execution | Event IDs 4698 and 4699, Task Scheduler logs |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | Remote access through RDP | Event IDs 4624 and 4625, Terminal Services logs |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | Remote access through SMB administrative shares | Network logs, Windows logon and share auditing |
| Credential Access | T1003.006 | DCSync | Replication of directory service data | Domain Controller Security logs, directory service auditing |
| Collection | T1114.002 | Remote Email Collection | Collection of targeted mailbox data | Microsoft 365 Unified Audit Log, Exchange audit logs |
| Exfiltration | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration through HTTPS requests | Proxy, firewall, network flow, DLP logs |

## 3. Mapping to Our Laboratory

Our laboratory currently collects Windows Security events in Splunk.

| Technique | Relevant event | Current laboratory visibility |
|---|---|---|
| T1059.003 – Windows Command Shell | 4688 | Available for process creation investigation |
| T1059.001 – PowerShell | 4688, PowerShell logs if configured | Partial; 4688 alone may not contain complete script content |
| T1053.005 – Scheduled Task | 4698, 4699 | Available when task auditing is enabled |
| Authentication-related investigation | 4624, 4625 | Available |
| T1195.002 – Software Supply Chain | Software integrity and update telemetry | Not available in current lab |
| T1071.001 – Web Protocols | DNS, proxy, firewall, network logs | Not available in current lab |
| T1003.006 – DCSync | Domain Controller Security logs | Not available in current lab |

## 4. Important Interpretation

A technique-to-event mapping does not mean that a single Windows event can conclusively detect the technique.

For example:

- Event ID 4688 records process creation, but a `cmd.exe` process is not automatically malicious.
- Event ID 4624 records successful logons, but most successful logons are legitimate.
- Event ID 4698 records scheduled task creation, but scheduled tasks are also used by normal software.

Detection requires contextual analysis, baselines, parent-child process relationships, account context, timestamps, and additional telemetry.

## 5. Conclusion

The mapping identifies three practical monitoring areas that are supported by the current laboratory:

1. Process creation and command execution.
2. Authentication activity.
3. Scheduled task creation and deletion.

Other APT29 behaviors require additional data sources, particularly network, cloud identity, Active Directory, and software integrity telemetry.

## 6. Reference

MITRE ATT&CK – APT29 (G0016): https://attack.mitre.org/groups/G0016/

MITRE ATT&CK – SolarWinds Compromise (C0024): https://attack.mitre.org/campaigns/C0024/
