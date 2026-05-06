SEVERITY_SCORES = {
    "INFO": 10,
    "LOW": 30,
    "MEDIUM": 55,
    "HIGH": 75,
    "CRITICAL": 95,
}


FINDING_CATALOG = {
    "S3_PUBLIC": {
        "cis": ["CIS AWS Foundations 2.1.1"],
        "nist": ["NIST SP 800-53 AC-3", "NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1530"],
        "impact": "Data exposure and unintended public object access.",
        "remediation": "Block public access at bucket/account level and tighten bucket policy/ACL.",
        "likelihood": 0.9,
    },
    "IAM_ADMIN": {
        "cis": ["CIS AWS Foundations 1.16"],
        "nist": ["NIST SP 800-53 AC-6"],
        "mitre_attack": ["T1098", "T1078"],
        "impact": "Privilege escalation and full-account compromise risk.",
        "remediation": "Replace wildcard permissions with least privilege and split duties.",
        "likelihood": 0.85,
    },
    "SG_ALL_PROTOCOLS": {
        "cis": ["CIS AWS Foundations 5.2"],
        "nist": ["NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190"],
        "impact": "Internet-reachable workloads with broad attack surface.",
        "remediation": "Restrict ingress by source CIDR, protocol, and explicit ports.",
        "likelihood": 0.95,
    },
    "SG_ALL_PORTS": {
        "cis": ["CIS AWS Foundations 5.2"],
        "nist": ["NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190"],
        "impact": "Service exposure across all ports from untrusted networks.",
        "remediation": "Limit to required ports and trusted source ranges only.",
        "likelihood": 0.92,
    },
    "VPC_DNS_DISABLED": {
        "cis": ["CIS AWS Foundations 3.6"],
        "nist": ["NIST SP 800-53 CM-2"],
        "mitre_attack": ["T1565"],
        "impact": "Operational blind spots and degraded control-plane integrations.",
        "remediation": "Enable VPC DNS support unless explicitly unsupported by design.",
        "likelihood": 0.45,
    },
    "VPC_HOSTNAMES_DISABLED": {
        "cis": ["CIS AWS Foundations 3.6"],
        "nist": ["NIST SP 800-53 CM-2"],
        "mitre_attack": ["T1565"],
        "impact": "Reduced traceability and hostname-based control friction.",
        "remediation": "Enable DNS hostnames for managed and monitored workloads.",
        "likelihood": 0.35,
    },
    "SUBNET_PUBLIC_IP": {
        "cis": ["CIS AWS Foundations 5.3"],
        "nist": ["NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190"],
        "impact": "Instances may become directly internet reachable by default.",
        "remediation": "Disable automatic public IP assignment and use controlled egress paths.",
        "likelihood": 0.75,
    },
    "PUBLIC_ROUTE": {
        "cis": ["CIS AWS Foundations 5.2"],
        "nist": ["NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190"],
        "impact": "Outbound/inbound internet path can bypass segmentation intent.",
        "remediation": "Review 0.0.0.0/0 routes and isolate sensitive workloads to private route tables.",
        "likelihood": 0.8,
    },
    "IGW_ATTACHED": {
        "cis": ["CIS AWS Foundations 5.2"],
        "nist": ["NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190"],
        "impact": "Public perimeter exists; risk depends on routing and filtering controls.",
        "remediation": "Verify only intended VPCs have IGW and enforce strict route/SG/NACL controls.",
        "likelihood": 0.3,
    },
    "EXPLOIT_PATH_PUBLIC_TO_ADMIN": {
        "cis": ["CIS AWS Foundations 1.16", "CIS AWS Foundations 5.2"],
        "nist": ["NIST SP 800-53 AC-6", "NIST SP 800-53 SC-7"],
        "mitre_attack": ["T1190", "T1078", "T1098"],
        "impact": "Chained misconfigurations can lead to internet-to-admin compromise path.",
        "remediation": "Break the chain: close public network exposure and remove admin wildcard IAM privileges.",
        "likelihood": 0.97,
    },
    "CLOUDTRAIL_DISABLED": {
        "cis": ["CIS AWS Foundations 3.1"],
        "nist": ["NIST SP 800-53 AU-2", "NIST SP 800-53 AU-12"],
        "mitre_attack": ["T1562.008"],
        "impact": "Reduced auditability and slower incident response.",
        "remediation": "Enable organization/account CloudTrail with multi-region and log protection.",
        "likelihood": 0.8,
    },
    "ROOT_MFA_DISABLED": {
        "cis": ["CIS AWS Foundations 1.5"],
        "nist": ["NIST SP 800-53 IA-2"],
        "mitre_attack": ["T1078"],
        "impact": "High-impact account takeover risk through root credential abuse.",
        "remediation": "Enable MFA on root immediately and lock away root credentials.",
        "likelihood": 0.95,
    },
    "ACCESS_ANALYZER_DISABLED": {
        "cis": ["CIS AWS Foundations 1.20"],
        "nist": ["NIST SP 800-53 AC-2", "NIST SP 800-53 CA-7"],
        "mitre_attack": ["T1069"],
        "impact": "Lower visibility into unintended external access paths.",
        "remediation": "Enable IAM Access Analyzer at account or organization scope.",
        "likelihood": 0.65,
    },
    "EBS_UNENCRYPTED": {
        "cis": ["CIS AWS Foundations 2.2.1"],
        "nist": ["NIST SP 800-53 SC-28"],
        "mitre_attack": ["T1005"],
        "impact": "Data-at-rest exposure risk from snapshot/volume compromise.",
        "remediation": "Enable EBS encryption by default and migrate unencrypted volumes.",
        "likelihood": 0.85,
    },
    "IMDSV2_NOT_REQUIRED": {
        "cis": ["CIS AWS Foundations 1.14"],
        "nist": ["NIST SP 800-53 SI-4"],
        "mitre_attack": ["T1552"],
        "impact": "Increased risk of metadata credential theft via SSRF-style abuse.",
        "remediation": "Set instance metadata HttpTokens to required and harden metadata access.",
        "likelihood": 0.88,
    },
}


def _score_from_severity(severity):
    return SEVERITY_SCORES.get(str(severity).upper(), SEVERITY_SCORES["INFO"])


def enrich_findings(findings):
    enriched = []

    for finding in findings:
        finding_type = finding.get("type", "UNKNOWN")
        meta = FINDING_CATALOG.get(finding_type, {})
        severity = finding.get("severity", "INFO")
        base_score = _score_from_severity(severity)
        likelihood = meta.get("likelihood", 0.5)
        risk_score = round(base_score * likelihood, 2)

        merged = {
            **finding,
            "cis": meta.get("cis", ["N/A"]),
            "nist": meta.get("nist", ["N/A"]),
            "mitre_attack": meta.get("mitre_attack", ["N/A"]),
            "impact": meta.get("impact", "No impact description available."),
            "remediation": meta.get("remediation", "No remediation guidance available."),
            "risk_score": risk_score,
        }

        if "evidence" not in merged:
            merged["evidence"] = "Derived from AWS API configuration state."

        enriched.append(merged)

    enriched.sort(key=lambda item: item.get("risk_score", 0), reverse=True)
    return enriched
