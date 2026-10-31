# Wazuh hunting queries

These queries use the Wazuh Dashboard search bar with DQL. Select the Windows agent and the actual run interval first. Field names below assume the standard Wazuh Windows EventChannel structure; inspect one actual alert before using them. They apply to `wazuh-alerts-*`, where only generated alerts are visible. A missing alert does not establish that Windows did not generate an event; check Windows Event Viewer and manager archives if configured.

## All lab alerts

```text
rule.id: ("100810" or "100811" or "100812" or "100813")
```

## Initial access

```text
data.win.system.eventID: "4624" and data.win.eventdata.targetUserName: "labstudent" and data.win.eventdata.logonType: "10"
```

Inspect `data.win.eventdata.ipAddress`, target domain, logon ID, agent and event timestamp. Compare the source with the designated lab IP; do not classify all successful logons as attacks.

## Scheduled task

```text
data.win.system.eventID: "4698" and data.win.eventdata.taskName: *Lab_Emulation_Test*
```

Inspect the creator, task name and task XML. Verify a logon trigger, current-user principal and benign timestamp action. Creation alone does not prove execution after a second logon.

## Dummy transfer command

```text
data.win.system.channel: "Microsoft-Windows-Sysmon/Operational" and data.win.system.eventID: "1" and data.win.eventdata.commandLine: *dummy-data.txt*
```

Inspect image, command line, user, parent process and process GUID. A command is evidence of an attempt only.

## Connection to receiver

```text
data.win.system.channel: "Microsoft-Windows-Sysmon/Operational" and data.win.system.eventID: "3" and data.win.eventdata.destinationIp: "192.168.56.20" and data.win.eventdata.destinationPort: "8080"
```

Replace the receiver IP and port to match the lab. Correlate event 1 and event 3 using `processGuid`, not just the process name. Use the receiver's 201 record, byte count and SHA256 to establish completed transfer.

## Timeline

Search the four rule IDs, sort by `data.win.system.systemTime` ascending and add columns `agent.name`, `rule.id`, `data.win.system.eventID`, `data.win.eventdata.targetUserName`, `data.win.eventdata.user`, `data.win.eventdata.subjectUserName`, `data.win.eventdata.processGuid`.

Use the same agent and a 15-minute initial window around the run. User fields differ by event type; task execution and upload may run in separate processes. Link the logon, task creator and process user with the recorded account and task/run metadata. If available, use logon IDs as supporting evidence. This is a manual investigation workflow, not an implemented automatic multi-stage correlation rule.
