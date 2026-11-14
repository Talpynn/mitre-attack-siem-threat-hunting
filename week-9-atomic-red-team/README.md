# Week 9 · Atomic Red Team on macOS

## Introduction

This lab explores how Unix shell execution can be documented and reviewed in a SIEM. The exercise used Atomic Red Team on macOS to run a Bash script that checked loopback connectivity, then ran a reviewed local script that created a marker file. The two outcomes were recorded in Elasticsearch and examined in Kibana Discover.

## Lab environment

| Component | Configuration |
| --- | --- |
| Host | macOS |
| PowerShell | 7.7.0 |
| Invoke-AtomicRedTeam | 2.3.0 |
| Elasticsearch and Kibana | 8.12.0 on Docker Desktop |
| Elasticsearch index | `atomic-red-team-week9` |

## MITRE ATT&CK mapping

Both scenarios map to [T1059.004 · Unix Shell](https://attack.mitre.org/techniques/T1059/004/), a sub-technique of T1059 · Command and Scripting Interpreter under the Execution tactic (TA0002). The behavior under review was Bash script execution. PowerShell served as the Atomic Red Team runner. T1003 · OS Credential Dumping was outside the scope of this lab.

## Test execution and results

| Scenario | What ran | Result |
| --- | --- | --- |
| T1059.004-1 | Atomic Red Team test with the host set to `127.0.0.1` | Exit code `0`. All four loopback pings received replies. |
| T1059.004-2 local variant | The reviewed local script `echo-art-fish.sh` | The script ran on macOS and wrote `/tmp/art-fish.txt`. The upstream remote download-and-execute command was inspected only. |

The following PowerShell commands show module verification, test inspection, and the prerequisite checks.

```powershell
$PSVersionTable.PSVersion
Get-Module -ListAvailable Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.004 -ShowDetailsBrief
Invoke-AtomicTest T1059.004 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.004 -TestNumbers 2 -ShowDetails
Invoke-AtomicTest T1059.004 -TestNumbers 2 -CheckPrereqs
```

The following command uses the test's documented host input to reproduce the reported loopback run. [Atomic Red Team test definition](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.yaml)

```powershell
Invoke-AtomicTest T1059.004 -TestNumbers 1 -InputArgs @{ host = '127.0.0.1' }
```

Run the reviewed local script from its directory and check for the resulting file.

```bash
bash ./echo-art-fish.sh
ls -l /tmp/art-fish.txt
```

## SIEM ingestion and analysis

Two execution records were manually submitted with HTTP POST to the Elasticsearch endpoint `/atomic-red-team-week9/_doc`, one for each scenario. Kibana Discover showed two hits. The expanded first record showed the ATT&CK technique, event metadata, host information, and execution timestamps.

| Execution record | Result recorded for review |
| --- | --- |
| T1059.004-1 | The script reached the loopback address. Four of four pings received replies and the test returned exit code 0. |
| T1059.004-2 local variant | The reviewed script ran locally and created the marker file `/tmp/art-fish.txt`. |

The two records share the same ATT&CK technique. The test identifier distinguishes the network check from the file creation outcome.

The Discover results verify that Elasticsearch stored the manually submitted records and that Kibana could retrieve them. Automatic endpoint collection and detection were outside the scope of this exercise.

## Screenshot evidence

![Figure 1. Successful installation and verification of the Invoke-AtomicRedTeam PowerShell module (version 2.3.0) on macOS.](screenshots/figure-01.jpg)

*Figure 1. Successful installation and verification of the Invoke-AtomicRedTeam PowerShell module (version 2.3.0) on macOS.*

![Figure 2. Available Atomic Red Team tests for MITRE ATT&CK technique T1059.004 (Unix Shell) on macOS.](screenshots/figure-02.jpg)

*Figure 2. Available Atomic Red Team tests for MITRE ATT&CK technique T1059.004 (Unix Shell) on macOS.*

![Figure 3. Successful prerequisite verification for Atomic Red Team test T1059.004-1 on macOS.](screenshots/figure-03.jpg)

*Figure 3. Successful prerequisite verification for Atomic Red Team test T1059.004-1 on macOS.*

![Figure 4. Successful execution of Atomic Red Team test T1059.004-1 on macOS, demonstrating Bash script execution and localhost connectivity.](screenshots/figure-04.jpg)

*Figure 4. Successful execution of Atomic Red Team test T1059.004-1 on macOS, demonstrating Bash script execution and localhost connectivity.*

![Figure 5. Successful deployment of Kibana 8.12.0 on macOS using Docker Desktop.](screenshots/figure-05.jpg)

*Figure 5. Successful deployment of Kibana 8.12.0 on macOS using Docker Desktop.*

![Figure 6. Successful ingestion and analysis of Atomic Red Team test T1059.004 execution results in Kibana Discover.](screenshots/figure-06.jpg)

*Figure 6. Successful ingestion and analysis of Atomic Red Team test T1059.004 execution results in Kibana Discover.*

![Figure 7. Detailed analysis of the Atomic Red Team T1059.004 execution record in Kibana, showing the MITRE ATT&CK technique, event metadata, host information, and execution timestamps.](screenshots/figure-07.jpg)

*Figure 7. Detailed analysis of the Atomic Red Team T1059.004 execution record in Kibana, showing the MITRE ATT&CK technique, event metadata, host information, and execution timestamps.*

![Figure 8. Command inspection and successful prerequisite verification for Atomic Red Team test T1059.004-2.](screenshots/figure-08.jpg)

*Figure 8. Command inspection and successful prerequisite verification for Atomic Red Team test T1059.004-2.*

![Figure 9. Successful local execution of the verified T1059.004-2 test payload on macOS.](screenshots/figure-09.jpg)

*Figure 9. Successful local execution of the verified T1059.004-2 test payload on macOS.*

![Figure 10. Two Atomic Red Team T1059.004 test execution records successfully stored and analyzed in Kibana Discover.](screenshots/figure-10.jpg)

*Figure 10. Two Atomic Red Team T1059.004 test execution records successfully stored and analyzed in Kibana Discover.*


Figure 9 documents the reviewed local variant. Figures 6, 7, and 10 show manually ingested records.

## Conclusion

The loopback test completed with exit code `0` and received four replies from `127.0.0.1`. The reviewed local variant of the second test created `/tmp/art-fish.txt`. Together, the scenarios demonstrate two observable outcomes of Unix shell execution under MITRE ATT&CK T1059.004.

Kibana Discover returned both manually submitted execution records. Comparing the records by test identifier made it possible to distinguish the loopback connectivity check from the marker-file creation. The SIEM exercise validated record storage and retrieval. Automatic endpoint collection and detection were outside the scope of the lab.
