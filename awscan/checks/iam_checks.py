def check_admin_roles(session, iam_module):
    results = []

    for role in iam_module.list_roles(session):
        if iam_module.has_admin_policy(role):
            results.append({
                "type": "IAM_ADMIN",
                "resource": role["RoleName"],
                "severity": "CRITICAL",
                "message": "Role has overly permissive policy"
            })

    return results