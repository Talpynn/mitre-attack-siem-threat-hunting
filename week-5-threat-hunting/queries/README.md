# Hunting query notes

The executable query for this simplified exercise is `../scripts/hunt_powershell.py`.

Example KQL for Kibana (not executed as part of this Python exercise; requires matching fields and mappings):

```kql
process.name : "powershell.exe" and
(process.command_line : "*-enc*" or
 process.command_line : "*-encodedcommand*" or
 process.command_line : "*DownloadString*" or
 process.command_line : "*Invoke-Expression*")
```

Field names depend on your data source. Validate the selected data view before using this query.
