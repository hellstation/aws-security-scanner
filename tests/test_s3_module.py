import unittest
from unittest.mock import Mock, patch

from awscan.aws import s3


class S3ModuleTests(unittest.TestCase):
    @patch("awscan.aws.s3.get_client")
    def test_detects_public_bucket_via_acl(self, get_client):
        s3_client = Mock()
        get_client.return_value = s3_client
        s3_client.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
        }
        s3_client.get_bucket_policy_status.side_effect = Exception("No policy")
        s3_client.get_public_access_block.side_effect = Exception("No PAB")

        is_public, evidence, confidence = s3.is_bucket_public(object(), "bucket-a")
        self.assertTrue(is_public)
        self.assertIn("ACL grants access", evidence)
        self.assertGreaterEqual(confidence, 0.9)

    @patch("awscan.aws.s3.get_client")
    def test_public_signals_suppressed_when_bucket_pab_is_fully_enabled(self, get_client):
        s3_client = Mock()
        get_client.return_value = s3_client
        s3_client.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
        }
        s3_client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": True}}
        s3_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        is_public, evidence, confidence = s3.is_bucket_public(object(), "bucket-a")
        self.assertFalse(is_public)
        self.assertIn("Public Access Block", evidence)
        self.assertGreaterEqual(confidence, 0.8)


if __name__ == "__main__":
    unittest.main()
