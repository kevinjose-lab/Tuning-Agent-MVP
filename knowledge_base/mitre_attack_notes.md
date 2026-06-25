# MITRE ATT&CK Tuning Notes

## T1059.001 PowerShell
PowerShell execution can be malicious, but can also be legitimate for administration, software deployment, EDR activity, and maintenance scripts.

Tuning guidance:
- Do not suppress all PowerShell detections.
- Prefer constraints such as exact script path, signed parent process, approved admin user, known host group, and expected command-line pattern.
- Preserve alerts for encoded commands, download cradles, unusual parent processes, suspicious network connections, or execution from Office/macros.

## T1110 Brute Force
Repeated authentication failures can represent brute force, password spraying, misconfigured services, or stale credentials.

Tuning guidance:
- Suppress only known benign service accounts or known scanner/source IP patterns.
- Preserve visibility for new source IPs, privileged usernames, external sources, and high failure rates.

## Vulnerability detection / CVE findings
Repeated CVE alerts are often duplicate case drivers if the vulnerability remains unresolved.

Tuning guidance:
- Group by host + CVE + package.
- Suppress repeated case creation for the same unresolved CVE within a fixed window.
- Do not suppress new CVEs, new packages, new hosts, or active exploitation signals.
