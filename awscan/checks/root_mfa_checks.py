def check_root_mfa_enabled(session, iam_module):
    summary = iam_module.get_account_summary(session)
    mfa_enabled = summary.get("AccountMFAEnabled", 0)
    if mfa_enabled == 1:
        return []

    return [{
        "type": "ROOT_MFA_DISABLED",
        "resource": "root-account",
        "severity": "CRITICAL",
        "message": "Root account MFA is disabled",
        "evidence": f"AccountMFAEnabled={mfa_enabled}",
    }]
