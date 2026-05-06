from awscan.aws.session import get_client


def list_roles(session):
    iam = get_client(session, "iam")
    return iam.list_roles()["Roles"]


def get_account_summary(session):
    iam = get_client(session, "iam")
    return iam.get_account_summary().get("SummaryMap", {})


def is_service_linked_role(role):
    role_name = role.get("RoleName", "")
    role_path = role.get("Path", "")

    if role_name.startswith("AWSServiceRoleFor"):
        return True
    if role_path.startswith("/aws-service-role/"):
        return True

    return False


def role_has_admin_permissions(session, role_name):
    iam = get_client(session, "iam")

    for policy in _get_attached_policy_documents(iam, role_name):
        if _policy_grants_admin(policy):
            return True

    for policy in _get_inline_policy_documents(iam, role_name):
        if _policy_grants_admin(policy):
            return True

    return False


def _get_attached_policy_documents(iam_client, role_name):
    attached = iam_client.list_attached_role_policies(RoleName=role_name).get(
        "AttachedPolicies", []
    )
    for policy in attached:
        policy_arn = policy["PolicyArn"]
        policy_meta = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy_meta["DefaultVersionId"]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        yield version["PolicyVersion"]["Document"]


def _get_inline_policy_documents(iam_client, role_name):
    policy_names = iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    for policy_name in policy_names:
        policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        yield policy["PolicyDocument"]


def _policy_grants_admin(policy_document):
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if not _action_is_admin(statement.get("Action")):
            continue
        if _resource_is_all(statement.get("Resource")):
            return True

    return False


def _action_is_admin(action):
    return _contains_value(action, {"*", "*:*"})


def _resource_is_all(resource):
    return _contains_value(resource, {"*"})


def _contains_value(value, match_values):
    if isinstance(value, str):
        return value in match_values
    if isinstance(value, list):
        return any(item in match_values for item in value)
    return False
