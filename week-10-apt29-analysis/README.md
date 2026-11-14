# Week 10 – APT29 Threat Intelligence and MITRE ATT&CK Analysis

## 1. Introduction

This week's task focuses on analyzing the APT29 threat group, studying the SolarWinds supply-chain compromise, and mapping publicly documented adversary behaviors to the MITRE ATT&CK framework.

The purpose is to understand how a sophisticated threat actor conducts operations, identify relevant techniques, and evaluate how a Security Information and Event Management (SIEM) system can support detection and investigation.

**Selected threat group:** APT29  
**MITRE ATT&CK Group ID:** G0016  
**Case study:** SolarWinds Compromise (C0024)  
**SIEM platform:** Splunk Enterprise  
**Operating system:** Windows 11

## 2. Objectives

- Research APT29 and its publicly documented activities.
- Examine the SolarWinds supply-chain compromise.
- Identify relevant tactics and techniques in MITRE ATT&CK.
- Map selected techniques to Windows Security Event Logs.
- Evaluate existing Splunk detection capabilities.
- Identify detection gaps and propose improvements.

## 3. Project Structure

| Directory / File | Description |
|---|---|
| `threat-intelligence/apt29-profile.md` | APT29 group profile |
| `threat-intelligence/solarwinds-case-study.md` | SolarWinds incident analysis |
| `attack-mapping/apt29-attack-mapping.md` | ATT&CK technique mapping |
| `detection-analysis/splunk-detection-coverage.md` | Splunk queries and verified lab capabilities |
| `detection-analysis/detection-gaps.md` | Limitations and improvement recommendations |
| `evidence/screenshots/` | Screenshots supporting the laboratory analysis |
| `references/SOURCES.md` | Research references |

## 4. Methodology

The work follows four stages:

1. **Threat intelligence research:** Review MITRE ATT&CK, CISA, and Mandiant publications.
2. **Technique mapping:** Identify APT29 techniques documented in the SolarWinds campaign.
3. **SIEM analysis:** Review Windows Security events collected by Splunk and assess which behaviors can be investigated.
4. **Gap assessment:** Compare the available telemetry with the visibility required to detect the documented techniques.

This is a threat intelligence and defensive detection analysis. No real APT29 activity was executed or emulated.

## 5. Laboratory Environment

| Component | Configuration |
|---|---|
| Host operating system | Windows 11 Pro, x64 |
| SIEM | Splunk Enterprise |
| Hostname | LEGION |
| Log source | Windows Security Event Log |
| Splunk index | `main` |
| Sourcetype | `WinEventLog:Security` |
| Search language | SPL |

The laboratory collected Windows Security events and used Splunk searches to investigate authentication, process creation, and scheduled-task-related activity.

## 6. Key Findings

- APT29 is associated with Russia's Foreign Intelligence Service (SVR), according to public government attribution.
- The SolarWinds campaign demonstrated the impact of a compromised software supply chain.
- Windows Security Event ID 4688 provides process creation telemetry.
- Event IDs 4624 and 4625 provide successful and failed logon telemetry.
- Event IDs 4698 and 4699 can support investigation of scheduled-task creation and deletion when the relevant auditing is enabled.
- Windows endpoint logs alone are insufficient to reconstruct the full SolarWinds campaign.

## 7. Conclusion

This analysis demonstrates how threat intelligence can be translated into practical SIEM monitoring priorities.

The laboratory confirmed that Splunk can collect and search selected Windows Security events. However, the environment does not contain the complete endpoint, identity, cloud, and network telemetry required to detect every technique associated with APT29.

The main lesson is that effective threat hunting requires both knowledge of adversary behavior and sufficient telemetry to observe that behavior.

## 8. References

See [`references/SOURCES.md`](references/SOURCES.md) for the complete list of sources.
