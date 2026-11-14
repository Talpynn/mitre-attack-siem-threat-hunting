# SolarWinds Compromise – Case Study

## 1. Overview

The SolarWinds Compromise was a major software supply-chain cyber operation attributed by the United States and United Kingdom to Russia's Foreign Intelligence Service (SVR).

The operation was discovered in December 2020. APT29 compromised the software build process of SolarWinds Orion and inserted malicious code into legitimate software updates.

The campaign is tracked by MITRE ATT&CK as **C0024 – SolarWinds Compromise**.

The incident demonstrated that attackers can abuse trusted software distribution channels to gain access to organizations without relying exclusively on traditional phishing or direct exploitation.

## 2. Attack Process

### Stage 1: Supply-chain compromise

The attackers compromised the SolarWinds Orion software build environment and inserted malicious code into the software development and build process.

The trojanized software update was digitally signed and distributed through the legitimate update mechanism.

**MITRE ATT&CK techniques:**

- T1195.002 – Supply Chain Compromise: Compromise Software Supply Chain
- T1553.002 – Subvert Trust Controls: Code Signing

**Security significance:**

A trusted software update can bypass security assumptions based on software reputation. Organizations should monitor software integrity, update provenance, and unexpected behavior following software updates.

### Stage 2: Initial execution and command and control

After installation, the SUNBURST backdoor performed checks and communicated with attacker-controlled infrastructure using web protocols.

The attackers attempted to make malicious communications resemble legitimate network activity.

**MITRE ATT&CK techniques:**

- T1071.001 – Application Layer Protocol: Web Protocols
- T1568 – Dynamic Resolution
- T1016.001 – System Network Configuration Discovery: Internet Connection Discovery

**Security significance:**

Network monitoring should examine unusual DNS resolution, unexpected outbound connections, and abnormal HTTP or HTTPS communication from trusted applications.

### Stage 3: Discovery and execution

After obtaining access to victim environments, the attackers performed reconnaissance and used command interpreters and administrative tools.

Public reporting describes the use of PowerShell, Windows Command Shell, and tools such as AdFind to discover accounts and remote systems.

**MITRE ATT&CK techniques:**

- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1059.003 – Command and Scripting Interpreter: Windows Command Shell
- T1087.002 – Account Discovery: Domain Account
- T1018 – Remote System Discovery

**Security significance:**

SOC analysts should investigate unusual command-line activity, unexpected administrative tool execution, and discovery commands launched by unusual parent processes.

### Stage 4: Persistence and lateral movement

APT29 used scheduled tasks and remote services in parts of the campaign to maintain access and move between systems.

The attackers also used legitimate-looking task names to make malicious activity appear normal.

**MITRE ATT&CK techniques:**

- T1053.005 – Scheduled Task/Job: Scheduled Task
- T1021.001 – Remote Services: Remote Desktop Protocol
- T1021.002 – Remote Services: SMB/Windows Admin Shares
- T1021.006 – Remote Services: Windows Remote Management

**Security significance:**

Unexpected scheduled tasks, unusual remote logons, and administrative connections between systems should be investigated together rather than as isolated events.

### Stage 5: Credential and identity abuse

The campaign included credential theft and abuse of identity infrastructure. Attackers used forged authentication material in some environments to access cloud resources and bypass normal authentication controls.

**MITRE ATT&CK techniques:**

- T1003.006 – OS Credential Dumping: DCSync
- T1550.001 – Use Alternate Authentication Material: Application Access Token
- T1550.002 – Use Alternate Authentication Material: Pass the Hash
- T1606.002 – Forge Web Credentials: SAML Tokens

**Security significance:**

Monitoring should include privileged account activity, domain controller replication events, suspicious token use, and unexpected changes to identity federation configuration.

Note: The exact technique mapping should be interpreted using the current MITRE ATT&CK campaign page. Not every technique applies to every victim.

### Stage 6: Collection and exfiltration

The attackers collected information from compromised environments, including email data, and used web-based communication to transfer information.

**MITRE ATT&CK techniques:**

- T1114.002 – Email Collection: Remote Email Collection
- T1560.001 – Archive Collected Data: Archive via Utility
- T1048.002 – Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

**Security significance:**

Organizations should monitor unusual mailbox export activity, unexpected archive creation, and outbound data transfers that do not match normal business behavior.

## 3. Main Lessons for SOC Analysts

1. Trusted software can become an initial access vector.
2. Digital signatures do not guarantee that software is safe if the build or signing process is compromised.
3. Attackers may use legitimate administrative tools to blend into normal activity.
4. Identity infrastructure is a critical part of enterprise security.
5. Detection requires correlation across endpoint, identity, cloud, DNS, and network telemetry.

## 4. Relevance to Our Laboratory

Our laboratory uses Windows 11 and Splunk Enterprise to collect Windows Security events.

The following event types are relevant to selected behaviors discussed in this case study:

| Windows Event ID | Meaning | Relevance |
|---|---|---|
| 4688 | Process creation | Investigating command interpreter and process execution |
| 4624 | Successful logon | Investigating authentication activity |
| 4625 | Failed logon | Investigating failed authentication attempts |
| 4698 | Scheduled task created | Investigating task-based persistence |
| 4699 | Scheduled task deleted | Investigating task removal |

These events provide partial visibility into endpoint activity. They do not independently prove that an APT29 technique occurred.

## 5. Conclusion

The SolarWinds incident illustrates how a sophisticated adversary can compromise trusted software, use legitimate administrative tools, abuse identity systems, and move through enterprise environments.

For defenders, the most important response is to combine software integrity monitoring, endpoint telemetry, identity monitoring, and network visibility.

## 6. Sources

- MITRE ATT&CK – SolarWinds Compromise (C0024): https://attack.mitre.org/campaigns/C0024/
- CISA Alert AA20-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- Mandiant – SUNBURST Backdoor: https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
