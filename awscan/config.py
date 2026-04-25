import os
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

AWS_CONFIG = {
    "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
    "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
    "region_name": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
}

AWS_CLIENT_CONFIG = Config(
    retries={
        "max_attempts": int(os.getenv("AWSCAN_AWS_MAX_ATTEMPTS", "5")),
        "mode": os.getenv("AWSCAN_AWS_RETRY_MODE", "standard"),
    },
    connect_timeout=int(os.getenv("AWSCAN_AWS_CONNECT_TIMEOUT", "5")),
    read_timeout=int(os.getenv("AWSCAN_AWS_READ_TIMEOUT", "30")),
)
