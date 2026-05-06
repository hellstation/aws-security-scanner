from awscan.aws.session import get_client


def list_security_groups(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_security_groups()["SecurityGroups"]


def describe_volumes(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_volumes().get("Volumes", [])


def describe_instances(session):
    ec2 = get_client(session, "ec2")
    reservations = ec2.describe_instances().get("Reservations", [])
    instances = []
    for reservation in reservations:
        instances.extend(reservation.get("Instances", []))
    return instances
