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


class FakeIamModule:
    @staticmethod
    def list_roles(_session):
        return [{"RoleName": "admin-role", "Path": "/"}]

    @staticmethod
    def is_service_linked_role(_role):
        return False

    @staticmethod
    def role_has_admin_permissions(_session, role_name):
        return role_name == "admin-role"


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
