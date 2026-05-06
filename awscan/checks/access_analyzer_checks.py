def check_access_analyzer_enabled(session, analyzer_module):
    analyzers = analyzer_module.list_analyzers(session)
    active = [
        a for a in analyzers
        if a.get("status") == "ACTIVE" and a.get("type") in {"ACCOUNT", "ORGANIZATION"}
    ]
    if active:
        return []

    return [{
        "type": "ACCESS_ANALYZER_DISABLED",
        "resource": "account",
        "severity": "MEDIUM",
        "message": "No active IAM Access Analyzer found",
        "evidence": f"Analyzers found: {len(analyzers)}",
    }]
