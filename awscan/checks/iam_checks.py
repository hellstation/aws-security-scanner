def check_admin_roles(session, iam_module):
    results = []

    for role in iam_module.list_roles(session):
        role_name = role["RoleName"]
        if iam_module.is_service_linked_role(role):
            continue
        if iam_module.role_has_admin_permissions(session, role_name):
            results.append({
                "type": "IAM_ADMIN",
                "resource": role_name,
                "severity": "CRITICAL",
                "message": "Role has overly permissive policy"
            })

    return results
