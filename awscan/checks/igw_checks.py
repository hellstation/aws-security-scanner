def check_internet_gateways(session, network):
    results = []

    for igw in network.describe_internet_gateways(session):
        if igw.get("Attachments"):
            results.append({
                "type": "IGW_ATTACHED",
                "resource": igw["InternetGatewayId"],
                "severity": "INFO",
                "message": "Internet Gateway attached to VPC"
            })

    return results