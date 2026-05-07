from awscan.aws.session import get_client


def describe_vpcs(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_vpcs")
    vpcs = []
    for page in paginator.paginate():
        vpcs.extend(page.get("Vpcs", []))
    return vpcs


def describe_subnets(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_subnets")
    subnets = []
    for page in paginator.paginate():
        subnets.extend(page.get("Subnets", []))
    return subnets


def describe_route_tables(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_route_tables")
    route_tables = []
    for page in paginator.paginate():
        route_tables.extend(page.get("RouteTables", []))
    return route_tables


def describe_internet_gateways(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_internet_gateways")
    internet_gateways = []
    for page in paginator.paginate():
        internet_gateways.extend(page.get("InternetGateways", []))
    return internet_gateways
