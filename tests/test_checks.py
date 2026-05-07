import unittest

from awscan.checks import (
    iam_checks,
    igw_checks,
    route_checks,
    s3_checks,
    sg_checks,
    subnet_checks,
    vpc_checks,
)


class FakeS3Module:
    @staticmethod
    def list_buckets(_session):
        return [{"Name": "public-bucket"}, {"Name": "private-bucket"}]

    @staticmethod
    def is_bucket_public(_session, bucket_name):
        if bucket_name == "public-bucket":
            return True, "ACL grants access to public group.", 0.95
        return False, "No public signals detected.", 0.9


class FakeIamModule:
    @staticmethod
    def list_roles(_session):
        return [
            {"RoleName": "admin-role", "Path": "/"},
            {"RoleName": "AWSServiceRoleForSupport", "Path": "/aws-service-role/support.amazonaws.com/"},
            {"RoleName": "readonly-role", "Path": "/"},
        ]

    @staticmethod
    def is_service_linked_role(role):
        return role["RoleName"].startswith("AWSServiceRoleFor") or role["Path"].startswith(
            "/aws-service-role/"
        )

    @staticmethod
    def role_has_admin_permissions(_session, role_name):
        return role_name == "admin-role"


class FakeEc2Module:
    @staticmethod
    def list_security_groups(_session):
        return [
            {
                "GroupId": "sg-1",
                "IpPermissions": [
                    {
                        "FromPort": 0,
                        "ToPort": 65535,
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]


class FakeNetworkModule:
    @staticmethod
    def describe_vpcs(_session):
        return [{"VpcId": "vpc-1", "EnableDnsSupport": False, "EnableDnsHostnames": False}]

    @staticmethod
    def describe_subnets(_session):
        return [{"SubnetId": "subnet-1", "MapPublicIpOnLaunch": True}]

    @staticmethod
    def describe_route_tables(_session):
        return [
            {
                "RouteTableId": "rtb-1",
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
            }
        ]

    @staticmethod
    def describe_internet_gateways(_session):
        return [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}]


class ChecksTests(unittest.TestCase):
    def test_s3_check_finds_public_bucket(self):
        results = s3_checks.check_public_buckets(object(), FakeS3Module)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "S3_PUBLIC")

    def test_iam_check_finds_admin_role(self):
        results = iam_checks.check_admin_roles(object(), FakeIamModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resource"], "admin-role")
        self.assertEqual(results[0]["severity"], "CRITICAL")

    def test_security_group_check_finds_open_group(self):
        results = sg_checks.check_open_ports(object(), FakeEc2Module)
        finding_types = {entry["type"] for entry in results}
        self.assertEqual(finding_types, {"SG_ALL_PROTOCOLS", "SG_ALL_PORTS"})

    def test_vpc_check_finds_dns_issues(self):
        results = vpc_checks.check_vpc_dns(object(), FakeNetworkModule)
        finding_types = {entry["type"] for entry in results}
        self.assertEqual(finding_types, {"VPC_DNS_DISABLED", "VPC_HOSTNAMES_DISABLED"})

    def test_subnet_check_finds_public_subnet(self):
        results = subnet_checks.check_public_subnets(object(), FakeNetworkModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "SUBNET_PUBLIC_IP")

    def test_route_check_finds_public_route(self):
        results = route_checks.check_public_routes(object(), FakeNetworkModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "PUBLIC_ROUTE")

    def test_igw_check_finds_attached_gateway(self):
        results = igw_checks.check_internet_gateways(object(), FakeNetworkModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "IGW_ATTACHED")


if __name__ == "__main__":
    unittest.main()
