import unittest
from unittest.mock import Mock, patch

from awscan.aws import iam


class IamModuleTests(unittest.TestCase):
    def test_is_service_linked_role_by_name(self):
        role = {"RoleName": "AWSServiceRoleForSupport", "Path": "/"}
        self.assertTrue(iam.is_service_linked_role(role))

    def test_is_service_linked_role_by_path(self):
        role = {"RoleName": "custom-role", "Path": "/aws-service-role/support.amazonaws.com/"}
        self.assertTrue(iam.is_service_linked_role(role))

    def test_is_not_service_linked_role(self):
        role = {"RoleName": "custom-role", "Path": "/"}
        self.assertFalse(iam.is_service_linked_role(role))

    @patch("awscan.aws.iam.get_client")
    def test_role_has_admin_permissions_in_attached_policy(self, get_client):
        iam_client = Mock()
        get_client.return_value = iam_client

        iam_client.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        }
        iam_client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        iam_client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }
        iam_client.list_role_policies.return_value = {"PolicyNames": []}

        result = iam.role_has_admin_permissions(object(), "admin-role")
        self.assertTrue(result)

    @patch("awscan.aws.iam.get_client")
    def test_role_has_admin_permissions_in_inline_policy(self, get_client):
        iam_client = Mock()
        get_client.return_value = iam_client

        iam_client.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        iam_client.list_role_policies.return_value = {"PolicyNames": ["InlineAdmin"]}
        iam_client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}]
            }
        }

        result = iam.role_has_admin_permissions(object(), "admin-role")
        self.assertTrue(result)

    @patch("awscan.aws.iam.get_client")
    def test_role_without_admin_permissions_returns_false(self, get_client):
        iam_client = Mock()
        get_client.return_value = iam_client

        iam_client.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        iam_client.list_role_policies.return_value = {"PolicyNames": ["ReadOnly"]}
        iam_client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"}]
            }
        }

        result = iam.role_has_admin_permissions(object(), "readonly-role")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
