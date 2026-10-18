# MITRE ATT&CK-Based SIEM Threat Hunting and Detection

## Project Overview

This project focuses on practical threat hunting and attack detection using a Security Information and Event Management (SIEM) environment and the MITRE ATT&CK framework.

The project will simulate controlled attack scenarios, collect and analyze security logs, develop detection rules, map detected activities to MITRE ATT&CK techniques, and investigate security incidents.

## Objectives

- Build and configure a practical SIEM environment
- Collect and analyze security logs
- Simulate controlled cyber attack scenarios
- Develop and test detection rules
- Perform threat hunting activities
- Map detected activities to MITRE ATT&CK techniques
- Investigate and document security incidents
- Develop scripts and security analysis tools
- Create dashboards for security monitoring and analysis

## Research Questions

1. How effectively can a SIEM detect common attack techniques?
2. How can MITRE ATT&CK improve threat hunting and detection?
3. What security logs and indicators are useful for identifying attacks?
4. How can detection rules be improved to reduce false positives?
5. How can SIEM data support incident investigation and response?

## Technologies

- Wazuh
- Elasticsearch
- Kibana
- MITRE ATT&CK
- Wireshark
- Python
- Kali Linux
- Windows Server

## Planned Attack Scenarios

The project will investigate several controlled attack scenarios, including:

- Brute-force attacks
- Network scanning
- Suspicious PowerShell activity
- Web-based attacks
- Suspicious authentication activity
- Other techniques selected according to the course syllabus

All attack simulations will be performed in controlled laboratory environments.

## MITRE ATT&CK Mapping

Detected activities will be mapped to relevant MITRE ATT&CK techniques and tactics.

Example techniques may include:

| Technique | Description |
|---|---|
| T1110 | Brute Force |
| T1059.001 | PowerShell |
| T1046 | Network Service Scanning |
| T1087 | Account Discovery |
| T1053 | Scheduled Task/Job |

The final mapping will be updated as the project develops.

## Threat Hunting Methodology

The general investigation process will follow:

1. Attack Simulation
2. Log Collection
3. Log Analysis
4. Detection
5. Threat Hunting
6. MITRE ATT&CK Mapping
7. Incident Investigation
8. Documentation
9. Detection Improvement

## Project Structure

```text
mitre-attack-siem-threat-hunting/
│
├── README.md
├── attack-scenarios/
├── detection-rules/
├── threat-hunting/
├── mitre-attack-mapping/
├── incident-investigations/
├── scripts/
├── dashboards/
└── reports/
```

## AI Usage Disclosure

Artificial Intelligence tools were used as an assisting tool during the development of this project.

AI was used for:

- Improving the clarity, grammar, and organization of technical explanations.
- Explaining cybersecurity concepts, including CTI, OSINT, Cyber Kill Chain, MITRE ATT&CK, SIEM, and threat hunting.
- Assisting with the interpretation and organization of information collected from official cybersecurity sources.
- Supporting troubleshooting of development tools, scripts, Git, Docker, and project configuration.

AI was not treated as an authoritative source. Technical information, MITRE ATT&CK mappings, cybersecurity facts, and references were reviewed against official or reliable sources where applicable.

The final project content, tool usage, practical work, evidence, screenshots, and repository organization were reviewed and validated by the project team.
