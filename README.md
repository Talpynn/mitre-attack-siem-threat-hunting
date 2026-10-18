# Weeks 6–7: ATT&CK and MITRE CAR in Splunk

This package extends the repository's Weeks 1–5 with two SIEM-focused exercises, using Splunk and synthetic data. It does not use PowerShell or run against public/third-party systems.

## Contents
- `week-6-attack-technique/`: ATT&CK technique study and controlled network-discovery simulation (T1046).
- `week-7-car-analytics/`: an implementable Splunk analytic based on MITRE CAR `CAR-2021-01-001` for port scanning activity.

## Important evidence rule
CSV data is explicitly synthetic. Screenshots must be captured from the student's actual Splunk session after importing the CSV and running the provided SPL. Do not claim Splunk execution until that has been done. Reports include an evidence checklist and screenshot placeholders.

## Suggested workflow
1. Read both reports.
2. Import each `data/*.csv` into Splunk as a CSV lookup (or upload through **Add Data > Upload**, choose CSV, enable timestamp parsing only if configured, and set a distinct sourcetype).
3. Run the corresponding SPL in `queries/` and verify the listed counts.
4. Capture screenshots of the search, result table, and detection output; place them in the `evidence/` folders.
5. Add these folders to the existing GitHub repository and update its main README.
