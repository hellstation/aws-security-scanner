from awscan.aws.session import get_client


def list_security_groups(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_security_groups")
    groups = []
    for page in paginator.paginate():
        groups.extend(page.get("SecurityGroups", []))
    return groups


def describe_volumes(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_volumes")
    volumes = []
    for page in paginator.paginate():
        volumes.extend(page.get("Volumes", []))
    return volumes


def describe_instances(session):
    ec2 = get_client(session, "ec2")
    paginator = ec2.get_paginator("describe_instances")
    instances = []
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
    return instances
