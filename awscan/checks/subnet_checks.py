def check_public_subnets(session, network):
    results = []

    for subnet in network.describe_subnets(session):
        if subnet.get("MapPublicIpOnLaunch"):
            results.append({
                "type": "SUBNET_PUBLIC_IP",
                "resource": subnet["SubnetId"],
                "severity": "MEDIUM",
                "message": "Auto-assign public IP enabled"
            })

    return results