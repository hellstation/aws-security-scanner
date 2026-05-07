import unittest
from unittest.mock import Mock, patch

from awscan.aws import accessanalyzer, ec2, iam, network


class PaginationTests(unittest.TestCase):
    @patch("awscan.aws.iam.get_client")
    def test_iam_list_roles_uses_paginator(self, get_client):
        client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [{"Roles": [{"RoleName": "r1"}, {"RoleName": "r2"}]}]
        client.get_paginator.return_value = paginator
        get_client.return_value = client

        roles = iam.list_roles(object())
        self.assertEqual(len(roles), 2)

    @patch("awscan.aws.ec2.get_client")
    def test_ec2_describe_instances_uses_paginator(self, get_client):
        client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}]},
        ]
        client.get_paginator.return_value = paginator
        get_client.return_value = client

        instances = ec2.describe_instances(object())
        self.assertEqual({i["InstanceId"] for i in instances}, {"i-1", "i-2"})

    @patch("awscan.aws.network.get_client")
    def test_network_describe_subnets_uses_paginator(self, get_client):
        client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [{"Subnets": [{"SubnetId": "s-1"}]}]
        client.get_paginator.return_value = paginator
        get_client.return_value = client

        subnets = network.describe_subnets(object())
        self.assertEqual(subnets[0]["SubnetId"], "s-1")

    @patch("awscan.aws.accessanalyzer.get_client")
    def test_access_analyzer_list_uses_paginator(self, get_client):
        client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [{"analyzers": [{"name": "a1"}]}]
        client.get_paginator.return_value = paginator
        get_client.return_value = client

        analyzers = accessanalyzer.list_analyzers(object())
        self.assertEqual(analyzers[0]["name"], "a1")


if __name__ == "__main__":
    unittest.main()
