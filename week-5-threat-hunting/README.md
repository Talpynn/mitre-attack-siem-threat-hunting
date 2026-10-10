# Week 5 — Threat Hunting Concept

## Scope note
The course outline asks students to execute hunt queries in Splunk or ELK. This is a simplified Python-and-CSV alternative because the local Kibana/ELK environment is currently unavailable. Do not present this as a Splunk/ELK execution; if the instructor strictly requires Splunk or ELK, this alternative may not fully satisfy the practical requirement.

## Objectives
- Explain intelligence-driven and hypothesis-driven hunting.
- State a testable hunting hypothesis.
- Search process-event records for suspicious PowerShell indicators.
- Interpret findings cautiously and document limitations.

## Hunting models
**Intelligence-driven hunting:** threat intelligence informs what an analyst searches for.

**Hypothesis-driven hunting:** the analyst forms a testable statement about possible adversary behavior, then searches available telemetry to support or reject it.

## Hunting hypothesis
Some process events in the examined dataset may show PowerShell execution with command-line characteristics that warrant investigation, such as encoded-command flags. This is a hypothesis, not a claim that a real system was compromised.

## Required telemetry
Useful process telemetry includes timestamp, host, process name, command line, parent process, user, and process ID. The included CSV is simulated and is not collected from a real endpoint.

## Procedure
1. Inspect `data/sample_process_events.csv`.
2. Run `python scripts/hunt_powershell.py`.
3. Review the console output and `output/hunt_results.csv`.
4. Document what matched and what additional evidence would be needed.
5. Capture a screenshot of the actual terminal output.

## Detection logic
The script looks for PowerShell process events containing `-enc`, `-encodedcommand`, `downloadstring`, `invoke-expression`, or `iex`. These are investigation leads, not proof of malicious activity. Legitimate scripts may use PowerShell; contextual review is necessary.

## ATT&CK context
PowerShell activity may be relevant to MITRE ATT&CK **T1059.001 — PowerShell**, under the **Execution** tactic. A keyword match alone does not prove adversary activity.
Official reference: https://attack.mitre.org/techniques/T1059/001/

## Limitations
- Data is simulated, not real endpoint telemetry.
- Keyword matching can create false positives and miss obfuscated commands.
- This exercise does not establish that any real host is compromised.
- This exercise does not demonstrate execution in Splunk or ELK.

## Improvements
Collect authorized endpoint process telemetry; add parent process, user, host, and time context; correlate with DNS, proxy, authentication, and endpoint alerts; and test the logic in Splunk or ELK when available.

## Conclusion
The exercise demonstrates a repeatable hunting workflow: define a question, identify required telemetry, run a search, inspect matches, and document limitations.

## References
1. MITRE ATT&CK, T1059.001 — PowerShell: https://attack.mitre.org/techniques/T1059/001/
2. Microsoft Learn, PowerShell: https://learn.microsoft.com/powershell/
3. Course outline, Week 5 — Threat Hunting Concept.
