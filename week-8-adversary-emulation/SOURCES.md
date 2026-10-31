# Sources

Checked on 31 October 2026. The supplied screenshot defines the assignment. The public repository README provides project context; folder contents and deployed infrastructure have not been independently inspected. Addresses, scripts, rules and lab design in this package are proposed additions, not extracted implementation from the repository.

1. [Talpynn MITRE ATT&CK SIEM Threat Hunting project](https://github.com/Talpynn/mitre-attack-siem-threat-hunting) — project context and workflow.
2. [MITRE ATT&CK T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) — initial-access mapping.
3. [MITRE ATT&CK T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) — Windows scheduled-task persistence mapping.
4. [MITRE ATT&CK T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/) — dummy HTTP transfer mapping. No C2 channel is implemented.
5. [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) — custom rule files, testing and application.
6. [Wazuh localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html) — Windows EventChannel collection.
7. [Microsoft Windows event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) — task creation and required audit subcategory.
8. [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — process/network telemetry and configuration.
9. [MITRE CALDERA documentation](https://caldera.readthedocs.io/en/latest/) — recommended reading from the assignment; CALDERA execution is not required by this plan and is not included.
