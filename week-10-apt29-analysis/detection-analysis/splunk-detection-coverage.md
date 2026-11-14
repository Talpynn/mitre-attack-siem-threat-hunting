# Splunk Detection Coverage – APT29 Analysis

## 1. Environment

The laboratory uses Splunk Enterprise on a Windows 11 host.

Windows Security events are collected in:

- Index: `main`
- Sourcetype: `WinEventLog:Security`
- Host: `LEGION`

The following searches were used to examine the available telemetry.

## 2. Authentication Monitoring

### 2.1 Failed logons – Event ID 4625

```spl
index=main EventCode=4625
| stats count by host
```

**Purpose:** Count failed logon events by host.

A more detailed search can extract logon type, source IP, and status information from the raw Windows event:

```spl
index=main EventCode=4625
| rex field=_raw "Тип входа:\s+(?<LogonType>\d+)"
| rex field=_raw "Имя процесса вызывающей стороны:\s+(?<ProcessPath>[^\r\n]+)"
| rex field=_raw "Сетевой адрес источника:\s+(?<SourceIP>[^\r\n]+)"
| rex field=_raw "Подсостояние:\s+(?<SubStatus>0x[0-9a-fA-F]+)"
| table _time host LogonType ProcessPath SourceIP SubStatus
| sort - _time
```

### 2.2 Successful logons – Event ID 4624

```spl
index=main EventCode=4624
| rex field=_raw "Тип входа:\s+(?<LogonType>\d+)"
| stats count by LogonType
| sort - count
```

**Purpose:** Identify the distribution of successful logon types.

A search for interactive and remote-interactive logons:

```spl
index=main EventCode=4624
| rex field=_raw "Тип входа:\s+(?<LogonType>\d+)"
| search LogonType=2 OR LogonType=10
| table _time host LogonType _raw
| sort - _time
```

Logon Type 2 represents an interactive logon. Logon Type 10 represents a remote interactive logon.

These values should be interpreted in context and are not malicious indicators by themselves.

## 3. Process Creation Monitoring – Event ID 4688

```spl
index=main EventCode=4688
| table _time host _raw
| sort - _time
```

**Purpose:** Review process creation events.

The following search extracts the new process and its creator process from the Russian-language event fields collected in this environment:

```spl
index=main EventCode=4688
| rex field=_raw "Имя нового процесса:\s+(?<NewProcess>[^\r\n]+)"
| rex field=_raw "Имя процесса-создателя:\s+(?<ParentProcess>[^\r\n]+)"
| table _time host NewProcess ParentProcess
| sort - _time
```

To investigate command shell execution:

```spl
index=main EventCode=4688
| rex field=_raw "Имя нового процесса:\s+(?<NewProcess>[^\r\n]+)"
| rex field=_raw "Командная строка процесса:\s*(?<CommandLine>[^\r\n]*)"
| search NewProcess="*\\cmd.exe"
| table _time NewProcess CommandLine
| sort - _time
```

This search can help investigate command interpreter activity. It does not establish that the command was malicious.

## 4. Scheduled Task Monitoring

### 4.1 Task creation – Event ID 4698

```spl
index=main EventCode=4698
| table _time host _raw
| sort - _time
```

### 4.2 Task deletion – Event ID 4699

```spl
index=main EventCode=4699
| table _time host _raw
| sort - _time
```

**Purpose:** Investigate scheduled task creation and deletion.

These events are relevant to T1053.005 – Scheduled Task. A task's name, creator, action, execution account, and timing should be reviewed before determining whether it is suspicious.

## 5. Relationship to APT29 Techniques

| Technique | Splunk data | Coverage |
|---|---|---|
| T1059.003 – Windows Command Shell | Event ID 4688 | Partial |
| T1059.001 – PowerShell | Event ID 4688; PowerShell logs if enabled | Partial |
| T1053.005 – Scheduled Task | Event IDs 4698 and 4699 | Partial |
| Authentication investigation | Event IDs 4624 and 4625 | Available |
| T1071.001 – Web Protocols | Proxy, DNS, firewall logs | Not available |
| T1195.002 – Software Supply Chain | Software integrity and update logs | Not available |
| T1003.006 – DCSync | Domain Controller Security logs | Not available |

## 6. Observed Laboratory Results

The Splunk searches returned Windows Security events from host `LEGION`.

The screenshots collected during the laboratory work demonstrate:

- Event ID 4625 records were searchable.
- Event ID 4624 records were searchable.
- Event ID 4688 process creation records were searchable.
- Process and parent-process fields could be extracted from raw event text.
- Event IDs 4698 and 4699 were used in the earlier scheduled-task investigation.

The process creation search also returned many normal Windows and Splunk service processes. This demonstrates why process creation data needs filtering and contextual analysis.

**Important:** These results demonstrate log collection and investigation capability. They do not demonstrate that APT29 or SUNBURST was present in the laboratory.

## 7. Conclusion

Splunk provides a useful foundation for investigating Windows endpoint activity.

The current configuration supports basic authentication, process creation, and scheduled-task investigations. However, full APT29 detection requires additional endpoint, network, Active Directory, and cloud identity telemetry.
