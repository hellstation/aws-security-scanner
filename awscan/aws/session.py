import boto3
from awscan.config import AWS_CONFIG, AWS_CLIENT_CONFIG

def get_session():
    return boto3.Session(**AWS_CONFIG)


def get_client(session, service_name):
    return session.client(service_name, config=AWS_CLIENT_CONFIG)
