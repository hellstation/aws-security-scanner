def list_security_groups(session):
    ec2 = session.client("ec2")
    return ec2.describe_security_groups()["SecurityGroups"]