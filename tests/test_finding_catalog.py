import unittest

from awscan.core.finding_catalog import enrich_findings


class FindingCatalogTests(unittest.TestCase):
    def test_enrich_adds_framework_mapping_and_risk(self):
        findings = [{
            "type": "S3_PUBLIC",
            "resource": "bucket-a",
            "severity": "HIGH",
            "message": "S3 bucket is public",
        }]

        enriched = enrich_findings(findings)
        self.assertEqual(len(enriched), 1)
        finding = enriched[0]
        self.assertIn("cis", finding)
        self.assertIn("nist", finding)
        self.assertIn("mitre_attack", finding)
        self.assertIn("remediation", finding)
        self.assertIn("confidence", finding)
        self.assertIn("false_positive_notes", finding)
        self.assertIn("evidence", finding)
        self.assertGreater(finding.get("risk_score", 0), 0)

    def test_enrich_sorts_by_risk_desc(self):
        findings = [
            {"type": "IGW_ATTACHED", "resource": "igw-1", "severity": "INFO", "message": "x"},
            {"type": "IAM_ADMIN", "resource": "admin", "severity": "CRITICAL", "message": "y"},
        ]

        enriched = enrich_findings(findings)
        self.assertEqual(enriched[0]["type"], "IAM_ADMIN")


if __name__ == "__main__":
    unittest.main()
