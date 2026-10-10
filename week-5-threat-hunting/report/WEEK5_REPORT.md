# Week 5 Report — Threat Hunting Concept

## 1. Objective
Demonstrate a repeatable, hypothesis-driven search for suspicious PowerShell process activity using a small simulated CSV dataset.

## 2. Hunting hypothesis
Some process events may show PowerShell command-line characteristics that warrant investigation, including encoded-command or download-related keywords.

## 3. Data and method
The input was `data/sample_process_events.csv`, a simulated dataset. The Python script checks PowerShell process records for configured keywords.

## 4. Results
Run `python scripts/hunt_powershell.py` and use the exact counts shown by your execution. The included dataset is designed to produce two matching events.

## 5. Interpretation
Matches are investigation leads, not proof of compromise. The strings were included for training and were not executed. A real investigation requires context such as parent process, user, host, timestamp, and related network events.

## 6. ATT&CK mapping
PowerShell activity may be relevant to MITRE ATT&CK T1059.001 — PowerShell (Execution). This is a potential mapping; simulated keyword matches do not independently establish adversary activity.

## 7. Limitations
- The dataset is simulated.
- Keyword matching may produce false positives and false negatives.
- This version uses Python and CSV, not Splunk or ELK.
- No conclusion about a real host compromise can be drawn.

## 8. Conclusion
The exercise demonstrates how a hunting hypothesis can be converted into a repeatable search. If Splunk/ELK execution is mandatory, run the query in that platform and include genuine screenshots.
