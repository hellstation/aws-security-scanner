def check_vpc_dns(session, network):
    results = []

    for vpc in network.describe_vpcs(session):
        vpc_id = vpc["VpcId"]

        if not vpc.get("EnableDnsSupport", True):
            results.append({
                "type": "VPC_DNS_DISABLED",
                "resource": vpc_id,
                "severity": "MEDIUM",
                "message": "DNS support is disabled"
            })

        if not vpc.get("EnableDnsHostnames", True):
            results.append({
                "type": "VPC_HOSTNAMES_DISABLED",
                "resource": vpc_id,
                "severity": "LOW",
                "message": "DNS hostnames disabled"
            })

    return results