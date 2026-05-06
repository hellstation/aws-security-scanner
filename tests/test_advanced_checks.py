import unittest

from awscan.checks import (
    access_analyzer_checks,
    cloudtrail_checks,
    ebs_checks,
    imdsv2_checks,
    root_mfa_checks,
)


class CloudTrailModuleNoTrails:
    @staticmethod
    def describe_trails(_session):
        return []


class CloudTrailModuleWithTrails:
    @staticmethod
    def describe_trails(_session):
        return [{"Name": "org-trail"}]


class IamModuleNoRootMfa:
    @staticmethod
    def get_account_summary(_session):
        return {"AccountMFAEnabled": 0}


class IamModuleWithRootMfa:
    @staticmethod
    def get_account_summary(_session):
        return {"AccountMFAEnabled": 1}


class AccessAnalyzerInactive:
    @staticmethod
    def list_analyzers(_session):
        return [{"name": "a1", "status": "CREATING", "type": "ACCOUNT"}]


class AccessAnalyzerActive:
    @staticmethod
    def list_analyzers(_session):
        return [{"name": "a1", "status": "ACTIVE", "type": "ACCOUNT"}]


class Ec2VolumesModule:
    @staticmethod
    def describe_volumes(_session):
        return [
            {"VolumeId": "vol-1", "Encrypted": False},
            {"VolumeId": "vol-2", "Encrypted": True},
        ]


class Ec2InstancesModule:
    @staticmethod
    def describe_instances(_session):
        return [
            {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}},
            {"InstanceId": "i-2", "MetadataOptions": {"HttpTokens": "required"}},
        ]


class AdvancedChecksTests(unittest.TestCase):
    def test_cloudtrail_check_finds_missing_trail(self):
        results = cloudtrail_checks.check_cloudtrail_enabled(object(), CloudTrailModuleNoTrails)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "CLOUDTRAIL_DISABLED")

    def test_cloudtrail_check_passes_when_trail_exists(self):
        results = cloudtrail_checks.check_cloudtrail_enabled(object(), CloudTrailModuleWithTrails)
        self.assertEqual(results, [])

    def test_root_mfa_check_finds_disabled(self):
        results = root_mfa_checks.check_root_mfa_enabled(object(), IamModuleNoRootMfa)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "ROOT_MFA_DISABLED")

    def test_root_mfa_check_passes_when_enabled(self):
        results = root_mfa_checks.check_root_mfa_enabled(object(), IamModuleWithRootMfa)
        self.assertEqual(results, [])

    def test_access_analyzer_check_finds_missing_active_analyzer(self):
        results = access_analyzer_checks.check_access_analyzer_enabled(object(), AccessAnalyzerInactive)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "ACCESS_ANALYZER_DISABLED")

    def test_access_analyzer_check_passes_with_active_analyzer(self):
        results = access_analyzer_checks.check_access_analyzer_enabled(object(), AccessAnalyzerActive)
        self.assertEqual(results, [])

    def test_ebs_check_finds_unencrypted_volumes(self):
        results = ebs_checks.check_ebs_encryption(object(), Ec2VolumesModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resource"], "vol-1")

    def test_imdsv2_check_finds_optional_tokens(self):
        results = imdsv2_checks.check_imdsv2_required(object(), Ec2InstancesModule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resource"], "i-1")


if __name__ == "__main__":
    unittest.main()
