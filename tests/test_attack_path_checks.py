import unittest

from awscan.checks import attack_path_checks


class FakeNetworkModule:
    @staticmethod
    def describe_subnets(_session):
        return [{"SubnetId": "subnet-1", "MapPublicIpOnLaunch": True}]


class FakeEc2Module:
    @staticmethod
    def list_security_groups(_session):
        return [{
            "GroupId": "sg-1",
            "IpPermissions": [{
                "FromPort": 0,
                "ToPort": 65535,
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }]

    @staticmethod
    def describe_instances(_session):
        return [
            {
                "InstanceId": "i-1",
                "SubnetId": "subnet-1",
                "SecurityGroups": [{"GroupId": "sg-1"}],
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/web"},
            }
        ]


class FakeIamModule:
    @staticmethod
    def is_service_linked_role(_role):
        return False

    @staticmethod
    def role_has_admin_permissions(_session, role_name):
        return role_name == "admin-role"

    @staticmethod
    def get_instance_profile_roles(_session, _profile_arn):
        return [{"RoleName": "admin-role", "Path": "/"}]


class SafeIamModule(FakeIamModule):
    @staticmethod
    def role_has_admin_permissions(_session, _role_name):
        return False


class AttackPathCheckTests(unittest.TestCase):
    def test_detects_public_to_admin_chain(self):
        results = attack_path_checks.check_public_to_admin_exploit_path(
            object(), FakeNetworkModule, FakeEc2Module, FakeIamModule
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "EXPLOIT_PATH_PUBLIC_TO_ADMIN")

    def test_returns_empty_when_chain_is_incomplete(self):
        results = attack_path_checks.check_public_to_admin_exploit_path(
            object(), FakeNetworkModule, FakeEc2Module, SafeIamModule
        )
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
