from awscan.aws.session import get_client


def list_security_groups(session):
    ec2 = get_client(session, "ec2")
    return ec2.describe_security_groups()["SecurityGroups"]
