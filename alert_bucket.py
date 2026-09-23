import json


def _case_analysis_text(cases: list[dict]) -> str:
    """Serialize only analyst-controlled fields, excluding TheHive metadata."""
    allowed_fields = ["title", "description", "summary", "tags"]
    relevant_cases = [
        {field: case.get(field) for field in allowed_fields if case.get(field)}
        for case in cases
    ]
    return json.dumps(relevant_cases, default=str).lower()


def classify_alert_bucket(cluster_key: str, cases: list[dict]) -> dict:
    """
    Classify a case cluster into an alert bucket.
    Returns bucket metadata used by the tuning agent.
    """

    combined_text = _case_analysis_text(cases)
    cluster_text = cluster_key.lower()
    text = f"{cluster_text} {combined_text}"

    if any(term in text for term in ["cve", "vulnerability", "package", "23506", "vuln"]):
        return {
            "bucket": "vulnerability",
            "label": "Vulnerability / CVE Alert",
            "preferred_grouping": "rule_id + agent + cve + package",
            "tuning_goal": "Reduce duplicate case creation while preserving vulnerability visibility.",
        }
    if any(term in text for term in [
    "privilege",
    "privileged",
    "admin group",
    "domain admins",
    "enterprise admins",
    "role assignment",
    "permission",
    "group membership",
    "escalation",
    "sudo",
    "target_group",
    "privilege_change",
        ]):
        return {
        "bucket": "identity_privilege",
        "label": "Identity / Privilege Alert",
        "preferred_grouping": "rule_id + user + privilege_change + target_group",
        "tuning_goal": "Preserve visibility for privilege changes; tune only approved recurring admin workflows.",
    }
    
    if any(term in text for term in [
    "ioc",
    "threat intel",
    "threat-intel",
    "indicator match",
    "hash:",
    "sha256:",
    "sha1:",
    "md5:",
    "domain:",
    "url:",
    "virustotal",
    "abuseipdb",
    "malicious ip",
    "known malicious",
    "threat feed",]):
        return {
            "bucket": "ioc",
            "label": "IOC / Threat Intel Alert",
            "preferred_grouping": "rule_id + indicator + host + enrichment result",
            "tuning_goal": "Avoid suppressing truly malicious indicators; only tune confirmed benign/allowlisted indicators.",
        }


    if any(term in text for term in ["powershell", "cmd.exe", "process", "parent", "commandline", "encodedcommand", "winword.exe", ".exe", "script"]):
        return {
            "bucket": "endpoint_process",
            "label": "Endpoint Process Alert",
            "preferred_grouping": "rule_id + host + process_path + parent_process + user",
            "tuning_goal": "Tune only exact known-benign process behavior; preserve nearby suspicious variants.",
        }
    
    if any(term in text for term in ["login", "logon", "authentication", "failed password", "bruteforce", "brute force", "mfa", "okta", "azuread"]):
        return {
            "bucket": "authentication",
            "label": "Authentication Alert",
            "preferred_grouping": "rule_id + source_ip + username + target_host",
            "tuning_goal": "Reduce known benign auth noise while preserving visibility for new users, privileged users, and new sources.",
        }

    if any(term in text for term in ["aws", "azure", "gcp", "cloudtrail", "guardduty", "iam", "service account", "s3", "ec2", "security hub"]):
        return {
            "bucket": "cloud",
            "label": "Cloud Alert",
            "preferred_grouping": "rule_id + cloud_account + principal + action + resource",
            "tuning_goal": "Reduce expected cloud admin/service activity while preserving unusual principals, regions, and sensitive actions.",
        }

    if any(term in text for term in ["firewall", "dns", "proxy", "connection", "netflow", "destination ip", "srcip", "dstip", "port"]):
        return {
            "bucket": "network",
            "label": "Network Alert",
            "preferred_grouping": "rule_id + source_ip + destination_ip + port + protocol",
            "tuning_goal": "Tune known benign network patterns while preserving new destinations and suspicious ports/protocols.",
        }

    if any(term in text for term in ["email", "phishing", "sender", "recipient", "subject", "attachment", "mimecast", "proofpoint"]):
        return {
            "bucket": "email",
            "label": "Email / Phishing Alert",
            "preferred_grouping": "rule_id + sender + subject pattern + attachment/hash/url",
            "tuning_goal": "Avoid suppressing phishing patterns broadly; tune only known benign sender/campaign patterns.",
        }

    return {
        "bucket": "generic",
        "label": "Generic / Unknown Alert",
        "preferred_grouping": "rule_id + agent + stable indicator",
        "tuning_goal": "Use conservative review-first logic because the alert type is unclear.",
    }
