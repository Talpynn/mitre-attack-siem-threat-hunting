# Package verification

Checked on 31 October 2026. These checks validate package components, not the Windows/Wazuh experiment.

- PASS receiver HTTP handler: accepted fixed dummy bytes, wrote exact file, returned 201 and matching SHA256
- PASS receiver HTTP handler: rejected wrong payload contents/length, route and transfer encoding without extra saved files
- PASS receiver address checks: public and wildcard addresses rejected
- PASS XML: three files are well formed; this is not Wazuh or Sysmon runtime validation
- PASS rule definitions: unique custom-range IDs; regex syntax and task-name positive/negative checks using Python regex, not the Wazuh engine
- PASS Windows script encoding: ASCII-compatible for Windows PowerShell 5.1
- PASS report: six rendered pages visually inspected; no clipped text or split table rows
- NOT RUN: real socket/network transfer. Local socket binding is restricted on this host; HTTP tests used an in-memory socket substitute and temporary files
- NOT RUN: Windows PowerShell parser/execution, task permissions/triggers, Sysmon schema loading and Wazuh loading/alert matching. Those target tools are unavailable here

Complete TEST_PLAN.md on the actual lab before asserting successful detection.
