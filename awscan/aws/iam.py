from awscan.aws.session import get_client


def list_roles(session):
    iam = get_client(session, "iam")
    return iam.list_roles()["Roles"]


def has_admin_policy(role):
    for policy in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
        if policy.get("Action") == "*" or policy.get("Effect") == "Allow":
            return True
    return False
