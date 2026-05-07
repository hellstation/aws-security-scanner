import unittest
from unittest.mock import Mock, patch

from awscan.aws import iam


class IamModuleTests(unittest.TestCase):
    @staticmethod
    def _mock_paginator(iam_client, name, pages):
        paginator = Mock()
        paginator.paginate.return_value = pages
        iam_client.get_paginator.side_effect = (
            lambda paginator_name: paginator if paginator_name == name else Mock()
        )
        return paginator

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

        attached_paginator = Mock()
        attached_paginator.paginate.return_value = [{
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        }]
        inline_paginator = Mock()
        inline_paginator.paginate.return_value = [{"PolicyNames": []}]
        iam_client.get_paginator.side_effect = lambda name: (
            attached_paginator if name == "list_attached_role_policies" else inline_paginator
        )
        iam_client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        iam_client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }
        result = iam.role_has_admin_permissions(object(), "admin-role")
        self.assertTrue(result)

    @patch("awscan.aws.iam.get_client")
    def test_role_has_admin_permissions_in_inline_policy(self, get_client):
        iam_client = Mock()
        get_client.return_value = iam_client

        attached_paginator = Mock()
        attached_paginator.paginate.return_value = [{"AttachedPolicies": []}]
        inline_paginator = Mock()
        inline_paginator.paginate.return_value = [{"PolicyNames": ["InlineAdmin"]}]
        iam_client.get_paginator.side_effect = lambda name: (
            attached_paginator if name == "list_attached_role_policies" else inline_paginator
        )
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

        attached_paginator = Mock()
        attached_paginator.paginate.return_value = [{"AttachedPolicies": []}]
        inline_paginator = Mock()
        inline_paginator.paginate.return_value = [{"PolicyNames": ["ReadOnly"]}]
        iam_client.get_paginator.side_effect = lambda name: (
            attached_paginator if name == "list_attached_role_policies" else inline_paginator
        )
        iam_client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"}]
            }
        }

        result = iam.role_has_admin_permissions(object(), "readonly-role")
        self.assertFalse(result)

    @patch("awscan.aws.iam.get_client")
    def test_get_instance_profile_roles(self, get_client):
        iam_client = Mock()
        get_client.return_value = iam_client
        iam_client.get_instance_profile.return_value = {
            "InstanceProfile": {
                "Roles": [{"RoleName": "app-role", "Path": "/"}]
            }
        }

        roles = iam.get_instance_profile_roles(
            object(), "arn:aws:iam::123456789012:instance-profile/app-profile"
        )
        self.assertEqual(roles[0]["RoleName"], "app-role")


if __name__ == "__main__":
    unittest.main()
