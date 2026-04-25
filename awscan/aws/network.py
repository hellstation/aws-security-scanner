from awscan.aws.session import get_client


def describe_vpcs(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_vpcs()["Vpcs"]


def describe_subnets(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_subnets()["Subnets"]


def describe_route_tables(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_route_tables()["RouteTables"]


def describe_internet_gateways(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_internet_gateways()["InternetGateways"]
