# Feedback Change Log

This file records structured analyst feedback that may influence future tuning behavior.

Feedback should not automatically become global behavior. Each item should include:
- decision
- scope
- affected fields
- intended behavior change
- overbias risk
- guardrail
- whether an eval is needed



---

## Feedback Change Candidate — TR-20260614-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Time: 2026-06-14T02:54:10.656226Z  
Reviewer: catman98  
Decision: REJECT  
Status: Rejected  

### Scope

- Alert Bucket: identity_privilege
- Rule ID: 999903
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

### Analyst Notes

too broad because PowerShell from Office parent should not be tuned

### Proposed Behavior Change

- Type: avoid_pattern
- Scope: identity_privilege
- Affected Fields: process, parent_process, command_line, user, path
- Avoid Pattern: Unsafe PowerShell tuning with insufficient context
- Required Future Constraints: exact parent process, full command line, user or service account, exact script path or signed script, known benign business context

### Overbias Control

- Overbias Risk: The agent may become too strict and reject all PowerShell tuning.
- Guardrail: Do not reject all PowerShell. Only reject cases with suspicious parent processes, EncodedCommand, missing command line, or broad path-only suppression.
- Needs Eval: True
- Promoted To Global KB: True

