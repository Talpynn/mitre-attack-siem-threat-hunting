# Acceptance and control tests

Run these only on the lab. Record actual results in `evidence/RESULTS.md`.

| Test | Action | Expected observation | What it establishes |
| --- | --- | --- | --- |
| A1 | RDP as labstudent from designated source | 4624 type 10 and rule 100810 | Selected lab logon is observable |
| A2 | Create Lab_Emulation_Test | 4698 and rule 100811 | Creation of selected task is detected |
| A3 | Run task once | Marker and successful task result | Action executes |
| A4 | Sign out and log on again as the same user | Another marker timestamp | Logon persistence trigger works |
| A5 | Upload fixed dummy payload | Sysmon 1 and 3, rules 100812/100813, receiver 201 | Command and connection observed |
| A6 | Compare sender and receiver SHA256 and size | Both hashes and sizes equal | Exact dummy bytes arrived |
| N1 | Log in with a different lab account | No 100810; other normal rules may fire | Username filter works |
| N2 | Create a benign task named Lab_Control_Test | No 100811; generic rules may fire | Task-name filter works |
| N3 | Run curl.exe --version | No 100812 or 100813 | Bare tool execution is not the signature |
| N4 | Stop receiver, repeat the same dummy upload from the original script command line | Upload fails; command/connection alerts may still occur | Alerts do not prove successful transfer |
| N5 | POST a different tiny test string to /upload | HTTP 400 and no saved payload | Receiver rejects non-dummy data |
| C1 | Run Remove-LabTask.ps1 | Lab task absent | Task cleanup completed |

The full Invoke-LabStages.ps1 intentionally refuses an existing task; for N4 reuse the exact curl command shown in its source with the previously created dummy file. Record that negative test separately from the successful run. Never use the negative test to replace a successful transfer record.

For N2, use a timestamp-only action, save the task name and delete that control task afterwards. The cleanup script removes only Lab_Emulation_Test. For N1 an alternative source-IP check can be used if no second account exists; document the substitution.

A failed expected alert requires checking four layers: event generation on Windows; collection by the agent; actual decoded field names and rule configuration; indexing/dashboard time filters. Keep the event and result even if a rule needs tuning. The tests measure these lab signatures, not general detection coverage or a statistical false-positive rate.
