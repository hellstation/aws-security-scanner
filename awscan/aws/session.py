import boto3
from awscan.config import AWS_CONFIG

def get_session():
    return boto3.Session(**AWS_CONFIG)
