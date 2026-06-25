# SOC Tuning Ideology

## Goal

The tuning agent should recommend narrow, evidence-based tuning suggestions only after repeated false-positive or duplicate case patterns are observed.

## Minimum threshold

A tuning recommendation requires at least 5 similar cases within the configured lookback window.

Cases should generally be closed as:
- False Positive
- Duplicate
- Benign / Expected Activity

## Core principles

1. Do not suppress an entire rule globally unless explicitly approved.
2. Prefer narrow suppression logic based on stable benign traits.
3. Preserve detection coverage for nearby suspicious variants.
4. Always include risk and validation steps.
5. Do not auto-implement tuning without human approval.
6. A tuning suggestion should reduce noise without hiding materially different activity.

## Preferred tuning constraints

Use one or more of:

- Rule ID
- Agent / host
- Host group
- Exact process path
- Parent process
- Command line pattern
- User or service account
- Source IP
- Destination IP
- CVE
- Package name
- Asset role
- Known scanner or management tool

## Bad tuning recommendations

Avoid recommending:

- Suppress the entire rule globally
- Suppress all activity from a host without a reason
- Suppress all PowerShell
- Suppress all vulnerability detections
- Suppress based only on one case
- Suppress without explaining blind spots
- Suppress without validation steps

## Required output sections

Every tuning recommendation must include:

- Why these cases appear related
- Recommended tuning
- Proposed logic
- Expected impact
- Risk / possible blind spot
- Validation steps
