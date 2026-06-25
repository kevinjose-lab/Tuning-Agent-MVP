def interpret_feedback(decision: str, rec: dict, notes: str = "") -> dict:
    """
    Convert analyst feedback into structured behavior-change metadata.
    This does not automatically change global behavior. It creates an auditable candidate lesson.
    """
    decision = decision.upper()
    notes_l = notes.lower()

    bucket = rec.get("alert_bucket", "generic")
    indicator = rec.get("indicator", "")
    proposed_logic = rec.get("proposed_logic", "")
    rule_id = rec.get("rule_id", "")

    result = {
        "behavior_change_type": "case_note",
        "behavior_change_scope": bucket,
        "affected_fields": [],
        "avoid_pattern": "",
        "required_future_constraints": [],
        "overbias_risk": "",
        "overbias_guardrail": "",
        "promote_to_global_kb": False,
        "needs_eval": False,
        "feedback_summary": notes,
    }

    if decision == "APPROVE":
        result.update({
            "behavior_change_type": "positive_example",
            "behavior_change_scope": bucket,
            "affected_fields": ["rule_id", "host", "indicator"],
            "required_future_constraints": ["same rule", "same host", "same stable benign indicator"],
            "overbias_risk": "Could overgeneralize one approved tuning to unrelated alerts.",
            "overbias_guardrail": "Use approved examples only when core fields match or are explicitly validated.",
            "promote_to_global_kb": True,
            "needs_eval": False,
        })
        return result

    if decision == "REJECT":
        result.update({
            "behavior_change_type": "avoid_pattern",
            "behavior_change_scope": bucket,
            "promote_to_global_kb": True,
            "needs_eval": True,
        })

        if "powershell" in notes_l or "powershell" in indicator.lower() or "powershell" in proposed_logic.lower():
            result.update({
                "affected_fields": ["process", "parent_process", "command_line", "user", "path"],
                "avoid_pattern": "Unsafe PowerShell tuning with insufficient context",
                "required_future_constraints": [
                    "exact parent process",
                    "full command line",
                    "user or service account",
                    "exact script path or signed script",
                    "known benign business context"
                ],
                "overbias_risk": "The agent may become too strict and reject all PowerShell tuning.",
                "overbias_guardrail": (
                    "Do not reject all PowerShell. Only reject cases with suspicious parent processes, "
                    "EncodedCommand, missing command line, or broad path-only suppression."
                ),
            })

        elif bucket == "ioc":
            result.update({
                "affected_fields": ["indicator", "enrichment_result", "allowlist_status"],
                "avoid_pattern": "Tuning IOC alerts without confirmed benign or allowlisted status",
                "required_future_constraints": [
                    "indicator allowlisted",
                    "benign enrichment result",
                    "business justification",
                    "expiration or review date"
                ],
                "overbias_risk": "The agent may refuse all IOC tuning even for known benign test indicators.",
                "overbias_guardrail": "Allow IOC tuning only when the indicator is confirmed benign or allowlisted.",
            })

        elif bucket == "authentication":
            result.update({
                "affected_fields": ["username", "source_ip", "target", "auth_result"],
                "avoid_pattern": "Broad authentication tuning without user/source constraints",
                "required_future_constraints": [
                    "known user or service account",
                    "known source IP",
                    "expected target application",
                    "expected time window"
                ],
                "overbias_risk": "The agent may reject all authentication tuning.",
                "overbias_guardrail": "Permit narrow tuning for known scanners, test accounts, or approved service accounts.",
            })

        else:
            result.update({
                "affected_fields": ["rule_id", "host", "indicator"],
                "avoid_pattern": "Rejected tuning pattern",
                "required_future_constraints": ["narrow scope", "clear benign evidence", "validation steps"],
                "overbias_risk": "The agent may overfit to one rejection.",
                "overbias_guardrail": "Apply this lesson only to similar bucket and field patterns.",
            })

        return result

    if decision in ["DRIFT", "STALE"]:
        result.update({
            "behavior_change_type": "stale_or_drifted_context",
            "behavior_change_scope": bucket,
            "affected_fields": ["indicator", "path", "version", "resource", "user", "parent_process"],
            "avoid_pattern": "Blindly reusing old tuning after context changed",
            "required_future_constraints": [
                "compare current context to approved context",
                "flag changed version/path/resource/user",
                "route similar-but-changed matches to REVIEW"
            ],
            "overbias_risk": "The agent may mark all similar future alerts as drift.",
            "overbias_guardrail": "Only mark drift when core context is similar but a meaningful field changed.",
            "promote_to_global_kb": True,
            "needs_eval": True,
        })
        return result

    if decision == "REVIEW":
        result.update({
            "behavior_change_type": "case_specific_review",
            "behavior_change_scope": bucket,
            "promote_to_global_kb": False,
            "needs_eval": False,
            "overbias_risk": "Review notes should not automatically become global rules.",
            "overbias_guardrail": "Keep REVIEW as case-specific unless repeatedly seen or promoted manually.",
        })

    return result