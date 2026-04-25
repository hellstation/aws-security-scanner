def check_public_routes(session, network):
    results = []

    for rt in network.describe_route_tables(session):
        for route in rt.get("Routes", []):
            if route.get("DestinationCidrBlock") == "0.0.0.0/0" and route.get("GatewayId", "").startswith("igw-"):
                results.append({
                    "type": "PUBLIC_ROUTE",
                    "resource": rt["RouteTableId"],
                    "severity": "HIGH",
                    "message": "Route to Internet Gateway (0.0.0.0/0)"
                })

    return results