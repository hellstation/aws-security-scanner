def list_roles(session):
    iam = session.client("iam")
    return iam.list_roles()["Roles"]

def has_admin_policy(role):
    for policy in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
        if policy.get("Action") == "*" or policy.get("Effect") == "Allow":
            return True
    return False