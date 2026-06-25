# Approved Tuning Examples

## Example 1 — Repeated vulnerability duplicate

Rule ID: 23506  
Pattern: Same host, same CVE, same package repeatedly closed as Duplicate.

Approved tuning:
Suppress repeated case creation for the same agent, same CVE, and same package for 24 hours.

Good reason:
The vulnerability remains visible in Wazuh inventory, but repeated duplicate cases are reduced.

Validation:
- Confirm new CVEs still generate alerts.
- Confirm different hosts still generate alerts.
- Confirm vulnerability inventory still shows the unresolved CVE.

## Example 2 — Benign Defender binary path

Rule ID: 999901  
Pattern: Same host and exact path `C:\Program Files\Microsoft Defender\MpCmdRun.exe` repeatedly closed as False Positive.

Approved tuning:
Suppress only when the rule ID, exact host, exact signed process path, and expected activity context match.

Good reason:
This avoids suppressing unrelated suspicious process execution.

Validation:
- Confirm the binary is signed by Microsoft.
- Confirm different paths still alert.
- Confirm suspicious parent processes still alert.
- Confirm unexpected users still alert.


---

## Approved Tuning — TR-20260605-999902-test-windows-agent-path-c-windows-system32-wuauclt-exe-336887

Approved Time: 2026-06-05T03:20:46.716435Z  
Approver: catman98  
Decision: Approved  

### Detection / Rule

- Rule ID: 999902
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-windows-agent
- Indicator: path:C:\Windows\System32\wuauclt.exe
- CVE: 
- Case Count: 5
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    <rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">
      <if_matched_sid>999902</if_matched_sid>
      <same_agent />
      <!-- Match same benign path/process indicator: path:C:\Windows\System32\wuauclt.exe -->
      <description>Repeated benign activity on same agent suppressed for 24 hours</description>
    </rule>

### Risk

Medium-Low

### Approval Notes

No approval notes provided.

### Future Guidance

This tuning was approved because multiple cases showed the same or similar activity and were closed as False Positive or Duplicate. Future recommendations should prefer similarly narrow tuning based on rule, host, and stable benign indicators instead of broad rule suppression.


---

## Approved Tuning — TR-20260607-999903-test-linux-backup-agent-path-usr-bin-rsync-523b18

Approved Time: 2026-06-07T03:37:29.930626Z  
Approver: catman98  
Decision: Approved  

### Detection / Rule

- Rule ID: 999903
- Rule Name: Repeated vulnerability detection / related activity
- Host / Agent: test-linux-backup-agent
- Indicator: path:/usr/bin/rsync
- CVE: 
- Case Count: 5
- Lookback Days: 14
- Disposition Pattern: False Positive / Duplicate

### Tuning Suggestion

Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.

### Proposed Logic

    <rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">
      <if_matched_sid>999903</if_matched_sid>
      <same_agent />
      <!-- Match same benign path/process indicator: path:/usr/bin/rsync -->
      <description>Repeated benign activity on same agent suppressed for 24 hours</description>
    </rule>

### Risk

Medium-Low

### Approval Notes

No approval notes provided.

### Future Guidance

This tuning was approved because multiple cases showed the same or similar activity and were closed as False Positive or Duplicate. Future recommendations should prefer similarly narrow tuning based on rule, host, and stable benign indicators instead of broad rule suppression.
