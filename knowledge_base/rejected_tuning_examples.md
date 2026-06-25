# Rejected Tuning Examples

## Example 1 — Broad PowerShell suppression

Rejected recommendation:
Suppress all PowerShell alerts from the host.

Reason rejected:
PowerShell is commonly abused by attackers. A broad suppression would create a major blind spot.

Better recommendation:
Suppress only the exact known benign script path, approved user, approved host, and expected command-line pattern.

## Example 2 — Global CVE rule suppression

Rejected recommendation:
Suppress Wazuh rule 23506 globally.

Reason rejected:
This would hide new vulnerability detections across the environment.

Better recommendation:
Suppress duplicate case creation for the same host, same CVE, and same package for a limited time window.


---

## Rejected Tuning — TR-20260607-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-07T03:58:54.587384Z
Approver: catman98
Decision: Rejected

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 5
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Rejected Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    <rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">
      <if_matched_sid>999903</if_matched_sid>
      <same_agent />
      <!-- Match same benign path/process indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -->
      <description>Repeated benign activity on same agent suppressed for 24 hours</description>
    </rule>

### Risk

Medium-Low

### Rejection Notes

No rejection notes provided.


---

## Rejected Tuning — TR-20260607-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-07T04:14:58.939580Z
Approver: catman98
Decision: Rejected

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 10
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Rejected Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    <rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">
      <if_matched_sid>999903</if_matched_sid>
      <same_agent />
      <!-- Match same benign path/process indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -->
      <description>Repeated benign activity on same agent suppressed for 24 hours</description>
    </rule>

### Risk

Medium-Low

### Rejection Notes

No rejection notes provided.


---

## Rejected Tuning — TR-20260613-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-13T22:18:47.872123Z  
Reviewer: catman98  
Decision: Rejected  

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 15
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Original Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    Do not modify the disposition or suppress any alerts related to rule 999903 on agent 'test-windows-agent' involving PowerShell commands from parent process WINWORD.EXE with path C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.

### Risk

Medium-Low

### Rejection Reason / Reviewer Notes

Too broad because PowerShell itself should not be tuned

### Future Guidance

This tuning was rejected. Future recommendations should avoid repeating this logic unless new evidence changes the risk assessment. The agent should prefer narrower scope, better validation, or additional evidence before suggesting a similar tuning again.


---

## Rejected Tuning — TR-20260613-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-13T23:14:37.798702Z  
Reviewer: catman98  
Decision: Rejected  

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 15
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Original Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    N/A - Proposed logic is not applicable since the cases are labeled for review and do not represent real-world scenarios.

### Risk

Medium-Low

### Rejection Reason / Reviewer Notes

this is too broad of a tuning

### Future Guidance

This tuning was rejected. Future recommendations should avoid repeating this logic unless new evidence changes the risk assessment. The agent should prefer narrower scope, better validation, or additional evidence before suggesting a similar tuning again.


---

## Rejected Tuning — TR-20260613-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-13T23:20:46.441839Z  
Reviewer: catman98  
Decision: Rejected  

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 15
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Original Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    No specific tuning proposed; maintain current disposition settings for rule 999903 on agent 'test-windows-agent' with correlation indicator path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, process: powershell.exe, parent: WINWORD.EXE.

### Risk

Medium-Low

### Rejection Reason / Reviewer Notes

this tuning is too broad, we cannot just tune PowerShell, this would result in missing real threats

### Future Guidance

This tuning was rejected. Future recommendations should avoid repeating this logic unless new evidence changes the risk assessment. The agent should prefer narrower scope, better validation, or additional evidence before suggesting a similar tuning again.


---

## Rejected Tuning — TR-20260614-999903-test-windows-agent-path-c-windows-system32-windowspowershell-v1-0-powershell-exe-d782da

Rejected Time: 2026-06-14T02:54:10.481323Z  
Reviewer: catman98  
Decision: Rejected  

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CVE: 
- Case Count: 15
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Original Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    No tuning logic generated because the LLM recommended REJECT. This activity should remain under investigation or review.

### Risk

Medium-Low

### Rejection Reason / Reviewer Notes

too broad because PowerShell from Office parent should not be tuned

### Future Guidance

This tuning was rejected. Future recommendations should avoid repeating this logic unless new evidence changes the risk assessment. The agent should prefer narrower scope, better validation, or additional evidence before suggesting a similar tuning again.
