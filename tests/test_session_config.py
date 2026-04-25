import unittest
from unittest.mock import Mock, patch

from awscan.aws.session import get_client, get_session
from awscan.config import AWS_CLIENT_CONFIG


class SessionConfigTests(unittest.TestCase):
    @patch("awscan.aws.session.boto3.Session")
    def test_get_session_uses_boto3_session(self, session_cls):
        get_session()
        session_cls.assert_called_once()

    def test_get_client_applies_aws_client_config(self):
        session = Mock()
        get_client(session, "s3")
        session.client.assert_called_once_with("s3", config=AWS_CLIENT_CONFIG)


if __name__ == "__main__":
    unittest.main()
