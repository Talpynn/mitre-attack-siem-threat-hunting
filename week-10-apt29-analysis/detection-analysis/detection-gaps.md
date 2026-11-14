# Detection Gaps and Improvement Recommendations

## 1. Purpose

This document evaluates the limitations of the current Splunk laboratory when investigating techniques associated with APT29 and the SolarWinds Compromise.

The objective is to identify missing telemetry and recommend realistic improvements.

## 2. Current Limitations

### 2.1 Limited endpoint visibility

The laboratory collects Windows Security events, including process creation and authentication events.

However, Event ID 4688 does not necessarily provide complete command-line information unless the corresponding audit policy is configured. It also does not provide all the behavioral context available from an Endpoint Detection and Response (EDR) platform.

**Impact:** Some suspicious process activity may be difficult to investigate.

**Recommendation:**
- Enable and verify process creation auditing.
- Enable command-line inclusion in process creation events where appropriate.
- Consider an EDR solution for richer process and behavioral telemetry.

### 2.2 Limited PowerShell visibility

Process creation events may show that PowerShell started, but they do not necessarily contain the full script content or all commands executed.

**Impact:** PowerShell-based behavior associated with T1059.001 may not be fully visible.

**Recommendation:**
- Enable PowerShell Script Block Logging where permitted.
- Collect the relevant PowerShell Operational event logs.
- Correlate PowerShell activity with process creation and account information.

### 2.3 No network telemetry

The current Splunk index does not provide verified DNS, proxy, firewall, or network-flow records for this analysis.

**Impact:** The laboratory cannot directly investigate web-based command-and-control or network exfiltration behavior associated with T1071.001 and T1048.002.

**Recommendation:**
- Collect DNS query logs.
- Integrate firewall and proxy logs.
- Consider Zeek or another network monitoring platform.
- Correlate endpoint processes with outbound network connections.

### 2.4 No centralized Active Directory or cloud identity logs

The laboratory is a Windows 11 endpoint and does not contain a fully monitored enterprise Active Directory or Microsoft 365 environment.

**Impact:** It cannot adequately investigate DCSync, forged SAML tokens, cloud account manipulation, or other identity-related techniques.

**Recommendation:**
- Collect Domain Controller Security logs in an appropriate lab environment.
- Monitor privileged account changes.
- Integrate Microsoft Entra ID and Microsoft 365 audit logs when available.
- Monitor unusual authentication and token activity.

### 2.5 No software supply-chain integrity monitoring

The current laboratory does not monitor a software build pipeline or verify software update integrity.

**Impact:** It cannot directly detect a compromised software build or malicious update similar to the SolarWinds incident.

**Recommendation:**
- Verify software signatures and update provenance.
- Monitor changes to software build pipelines.
- Maintain software inventories and integrity baselines.
- Investigate unexpected behavior following software updates.

## 3. Improvement Roadmap

| Priority | Improvement | Expected benefit |
|---|---|---|
| High | Verify process creation auditing and command-line logging | Better visibility into command execution |
| High | Collect PowerShell Operational logs | Improved script execution investigation |
| High | Improve scheduled task monitoring | Better persistence investigation |
| Medium | Integrate DNS, proxy, and firewall logs | Better command-and-control visibility |
| Medium | Collect Active Directory security logs | Better identity and credential attack investigation |
| Medium | Add EDR telemetry | Richer endpoint behavior analysis |
| Low | Add software integrity monitoring | Better supply-chain compromise investigation |

## 4. Practical Constraints

The laboratory is based on a Windows 11 host with 16 GB RAM and a local Splunk Enterprise installation.

The improvement roadmap therefore prioritizes configuration changes and data sources that can be added incrementally. Deploying a complete enterprise SOC environment is outside the scope of this week's exercise.

No credential dumping, real malware execution, or APT29 emulation was performed.

## 5. Conclusion

The current Splunk laboratory can investigate selected Windows endpoint events, but it cannot provide complete visibility into the multi-stage operations associated with APT29.

A more effective detection strategy requires correlation across endpoint, network, identity, cloud, and software integrity data.

The key lesson is that SIEM detection quality depends not only on search queries but also on the completeness and quality of collected telemetry.
